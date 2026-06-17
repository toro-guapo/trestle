use std::cell::RefCell;

use tree_sitter::Node;

use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, SourceFileSpan, SourceSpan, check_assignment,
    check_value, offset_to_position, strip_build_config_quotes,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_groovy::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
}

struct GroovyContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl GroovyContext<'_> {
  fn already_emitted(&self, start: usize, end: usize) -> bool {
    self
      .emitted_value_ranges
      .iter()
      .any(|(rs, re)| *rs <= start && *re >= end)
  }

  fn record_emitted(&mut self, start: usize, end: usize) {
    self.emitted_value_ranges.push((start, end));
  }
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let Some(tree) = PARSER.with(|p| {
    let mut borrow = p.borrow_mut();
    let parser = borrow.as_mut()?;
    parser.parse(source, None)
  }) else {
    return false;
  };

  let mut ctx = GroovyContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
  };

  process_node(&mut ctx, tree.root_node(), source.as_bytes());
  scan_slashy_strings(&mut ctx, source);

  true
}

fn process_node(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  match node.kind() {
    "local_variable_declaration" | "field_declaration" => {
      process_declaration(ctx, node, source)
    }
    "assignment_expression" => process_assignment(ctx, node, source),
    "juxt_function_call" => process_setter(ctx, node, "args", source),
    "method_invocation" => process_invocation(ctx, node, source),
    "formal_parameter" => process_parameter(ctx, node, source),
    "map_item" => process_map_item(ctx, node, source),
    "string_literal" | "character_literal" => {
      process_value_only(ctx, node, source)
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

// -----------------------------------------------------------------------------
// Declarations, assignments
// -----------------------------------------------------------------------------

fn process_declaration(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  let assignment_type = if has_final(node, source) {
    AssignmentType::Constant
  } else {
    AssignmentType::Variable
  };

  let mut cursor = node.walk();
  for declarator in node
    .children(&mut cursor)
    .filter(|c| c.kind() == "variable_declarator")
  {
    let name = declarator
      .child_by_field_name("name")
      .and_then(|n| node_text(n, source));
    if let Some(value) = declarator.child_by_field_name("value") {
      check_value_node(ctx, name, value, assignment_type, source);
    }
  }
}

fn process_assignment(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  let (Some(left), Some(right)) = (
    node.child_by_field_name("left"),
    node.child_by_field_name("right"),
  ) else {
    return;
  };

  match left.kind() {
    "array_access" => {
      if let Some(key) = left
        .child_by_field_name("index")
        .and_then(|i| extract_string(i, source))
      {
        check_value_node(
          ctx,
          Some(&key),
          right,
          AssignmentType::Element,
          source,
        );
      }
    }
    "identifier" => {
      let name = node_text(left, source);
      check_value_node(ctx, name, right, AssignmentType::Variable, source);
    }
    "field_access" => {
      let name = left
        .child_by_field_name("field")
        .and_then(|f| node_text(f, source));
      check_value_node(ctx, name, right, AssignmentType::Variable, source);
    }
    _ => {}
  }
}

fn process_parameter(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  let name = node
    .child_by_field_name("name")
    .and_then(|n| node_text(n, source));

  let mut cursor = node.walk();
  let default = node.children(&mut cursor).find(|c| {
    matches!(
      c.kind(),
      "string_literal"
        | "character_literal"
        | "binary_expression"
        | "ternary_expression"
    )
  });

  if let Some(value) = default {
    check_value_node(ctx, name, value, AssignmentType::Parameter, source);
  }
}

// -----------------------------------------------------------------------------
// Gradle DSL setters: `storePassword "secret"`, `password("secret")`. The method
// name is the property, so a receiver-less call with one string argument is a
// name/value pair. Calls on a receiver (`obj.password(...)`) are not resolved.
// -----------------------------------------------------------------------------

fn process_invocation(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  if node.child_by_field_name("object").is_some() {
    return;
  }
  process_setter(ctx, node, "arguments", source);
}

fn process_setter(
  ctx: &mut GroovyContext,
  node: Node,
  args_field: &str,
  source: &[u8],
) {
  let Some(name) = node
    .child_by_field_name("name")
    .and_then(|n| node_text(n, source))
  else {
    return;
  };
  let Some(arguments) = node.child_by_field_name(args_field) else {
    return;
  };

  let mut cursor = arguments.walk();
  let strings: Vec<Node> = arguments
    .children(&mut cursor)
    .filter(|c| matches!(c.kind(), "string_literal" | "character_literal"))
    .collect();

  if name == "buildConfigField" {
    process_build_config_field(ctx, &strings, source);
    return;
  }

  if let [value] = strings.as_slice() {
    check_value_node(ctx, Some(name), *value, AssignmentType::Variable, source);
  }
}

fn process_build_config_field(
  ctx: &mut GroovyContext,
  strings: &[Node],
  source: &[u8],
) {
  let [_type, name_node, value_node] = strings else {
    return;
  };
  let (Some(field_name), Some(raw)) = (
    extract_string(*name_node, source),
    extract_string(*value_node, source),
  ) else {
    return;
  };

  emit_raw(
    ctx,
    Some(&field_name),
    strip_build_config_quotes(&raw),
    value_node.start_byte(),
    value_node.end_byte(),
    AssignmentType::Constant,
  );
}

fn process_map_item(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  let Some(key) = node.child_by_field_name("key") else {
    return;
  };
  let Some(value) = node.child_by_field_name("value") else {
    return;
  };

  let name = match key.kind() {
    "identifier" => node_text(key, source).map(str::to_owned),
    "string_literal" | "character_literal" => extract_string(key, source),
    _ => None,
  };

  if let Some(name) = name {
    check_value_node(ctx, Some(&name), value, AssignmentType::Element, source);
  }
}

// -----------------------------------------------------------------------------
// Value checking
// -----------------------------------------------------------------------------

fn process_value_only(ctx: &mut GroovyContext, node: Node, source: &[u8]) {
  check_value_node(ctx, None, node, AssignmentType::Variable, source);
}

fn check_value_node(
  ctx: &mut GroovyContext,
  name: Option<&str>,
  value_node: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  if let Some(value) = extract_string(value_node, source) {
    emit_raw(
      ctx,
      name,
      &value,
      value_node.start_byte(),
      value_node.end_byte(),
      assignment_type,
    );
    return;
  }

  match value_node.kind() {
    "ternary_expression" => {
      for field in ["consequence", "alternative"] {
        if let Some(child) = value_node.child_by_field_name(field) {
          check_value_node(ctx, name, child, assignment_type, source);
        }
      }
    }
    "binary_expression" => {
      if let Some(left) = value_node.child_by_field_name("left") {
        check_value_node(ctx, name, left, assignment_type, source);
      }
      if let Some(right) = value_node.child_by_field_name("right") {
        check_value_node(ctx, name, right, assignment_type, source);
      }
    }
    "array_literal" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor) {
        if child.is_named() {
          check_value_node(ctx, name, child, assignment_type, source);
        }
      }
    }
    _ => {}
  }
}

fn emit_raw(
  ctx: &mut GroovyContext,
  name: Option<&str>,
  value: &str,
  start: usize,
  end: usize,
  assignment_type: AssignmentType,
) {
  if ctx.already_emitted(start, end) {
    return;
  }

  let normalized = normalize_value(&value);
  let span = || SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, start),
      end: offset_to_position(ctx.source, end),
    }),
  };

  let diag: Option<Diagnostic> = match name {
    Some(n) => check_assignment(
      &normalize_name(&n),
      &normalized,
      assignment_type,
      ctx.source_context,
      span,
    ),
    None => check_value(&normalized, ctx.source_context, span),
  };

  if let Some(d) = diag {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}

// -----------------------------------------------------------------------------
// Slashy strings: `/.../` and dollar-slashy `$/.../$`
// -----------------------------------------------------------------------------

fn scan_slashy_strings(ctx: &mut GroovyContext, source: &str) {
  let bytes = source.as_bytes();
  let n = bytes.len();
  let mut i = 0;
  let mut prev: Option<u8> = None;

  while i < n {
    let Some(&b) = bytes.get(i) else {
      break;
    };

    if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
      while i < n && bytes.get(i) != Some(&b'\n') {
        i += 1;
      }
      prev = None;
      continue;
    }

    if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
      i += 2;
      while i < n
        && !(bytes.get(i) == Some(&b'*') && bytes.get(i + 1) == Some(&b'/'))
      {
        i += 1;
      }
      i = (i + 2).min(n);
      prev = None;
      continue;
    }

    if b == b'"' || b == b'\'' {
      i = skip_string(bytes, i, b);
      prev = Some(b'"');
      continue;
    }

    if b == b'$'
      && bytes.get(i + 1) == Some(&b'/')
      && let Some(close) = find_dollar_slashy_close(bytes, i + 2)
    {
      handle_slashy(ctx, source, bytes, i + 2, close, i);
      i = (close + 2).min(n);
      prev = Some(b')');
      continue;
    }

    if b == b'/'
      && is_expression_start(prev)
      && let Some(close) = find_slashy_close(bytes, i + 1)
    {
      handle_slashy(ctx, source, bytes, i + 1, close, i);
      i = (close + 1).min(n);
      prev = Some(b')');
      continue;
    }

    if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
      i += 1;
      continue;
    }

    prev = Some(b);
    i += 1;
  }
}

fn skip_string(bytes: &[u8], start: usize, quote: u8) -> usize {
  let n = bytes.len();
  let triple = bytes.get(start + 1) == Some(&quote)
    && bytes.get(start + 2) == Some(&quote);

  if triple {
    let mut i = start + 3;
    while i < n {
      match bytes.get(i) {
        Some(b'\\') => i += 2,
        Some(&c)
          if c == quote
            && bytes.get(i + 1) == Some(&quote)
            && bytes.get(i + 2) == Some(&quote) =>
        {
          return i + 3;
        }
        _ => i += 1,
      }
    }
    return n;
  }

  let mut i = start + 1;
  while i < n {
    match bytes.get(i) {
      Some(b'\\') => i += 2,
      Some(b'\n') => return i + 1,
      Some(&c) if c == quote => return i + 1,
      _ => i += 1,
    }
  }
  n
}

fn find_slashy_close(bytes: &[u8], from: usize) -> Option<usize> {
  let n = bytes.len();
  let mut i = from;
  while i < n {
    match bytes.get(i) {
      Some(b'\\') => i += 2,
      Some(b'\n') => return None,
      Some(b'/') => return Some(i),
      _ => i += 1,
    }
  }
  None
}

fn find_dollar_slashy_close(bytes: &[u8], from: usize) -> Option<usize> {
  let n = bytes.len();
  let mut i = from;
  while i < n {
    if bytes.get(i) == Some(&b'/') && bytes.get(i + 1) == Some(&b'$') {
      return Some(i);
    }
    i += 1;
  }
  None
}

fn is_expression_start(prev: Option<u8>) -> bool {
  match prev {
    None => true,
    Some(b) => matches!(
      b,
      b'='
        | b'('
        | b','
        | b'['
        | b'{'
        | b':'
        | b'?'
        | b'&'
        | b'|'
        | b'!'
        | b'~'
        | b';'
        | b'<'
        | b'>'
    ),
  }
}

fn handle_slashy(
  ctx: &mut GroovyContext,
  source: &str,
  bytes: &[u8],
  content_start: usize,
  content_end: usize,
  open: usize,
) {
  let Some(content) = source.get(content_start..content_end) else {
    return;
  };
  if has_interpolation(content) {
    return;
  }

  let name = assignment_name_before(source, bytes, open);
  emit_raw(
    ctx,
    name.as_deref(),
    content,
    content_start,
    content_end,
    AssignmentType::Variable,
  );
}

// The identifier on the left of `name = /.../`, or None when the slashy string
// is not the value of a plain assignment.
fn assignment_name_before(
  source: &str,
  bytes: &[u8],
  open: usize,
) -> Option<String> {
  let mut j = open;
  loop {
    j = j.checked_sub(1)?;
    match bytes.get(j) {
      Some(b' ' | b'\t') => continue,
      Some(b'=') => break,
      _ => return None,
    }
  }

  if let Some(prev) = j.checked_sub(1)
    && matches!(
      bytes.get(prev),
      Some(
        b'='
          | b'!'
          | b'<'
          | b'>'
          | b'+'
          | b'-'
          | b'*'
          | b'/'
          | b'%'
          | b'&'
          | b'|'
          | b'^'
          | b'~'
      )
    )
  {
    return None;
  }

  let mut end = j;
  while end > 0 && matches!(bytes.get(end - 1), Some(b' ' | b'\t')) {
    end -= 1;
  }

  let mut start = end;
  while start > 0
    && bytes
      .get(start - 1)
      .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.')
  {
    start -= 1;
  }

  source
    .get(start..end)
    .and_then(|s| s.rsplit('.').next())
    .filter(|s| !s.is_empty())
    .map(str::to_owned)
}

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "string_literal" => {
      let single = node_text(node, source)?.starts_with('\'');
      let mut result = String::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        match child.kind() {
          "string_fragment"
          | "multiline_string_fragment"
          | "escape_sequence" => {
            result.push_str(node_text(child, source)?);
          }
          _ => {}
        }
      }
      if !single && has_interpolation(&result) {
        return None;
      }
      Some(result)
    }
    "character_literal" => {
      let text = node_text(node, source)?;
      let inner = text.strip_prefix('\'')?.strip_suffix('\'')?;
      Some(inner.to_owned())
    }
    "binary_expression" => {
      let left = extract_string(node.child_by_field_name("left")?, source)?;
      let right = extract_string(node.child_by_field_name("right")?, source)?;
      Some(left + &right)
    }
    _ => None,
  }
}

// A double-quoted Groovy GString interpolates on `${...}` or `$identifier`.
fn has_interpolation(value: &str) -> bool {
  let bytes = value.as_bytes();
  bytes.iter().enumerate().any(|(i, &b)| {
    b == b'$'
      && bytes
        .get(i + 1)
        .is_some_and(|c| *c == b'{' || c.is_ascii_alphabetic() || *c == b'_')
  })
}

fn has_final(node: Node, source: &[u8]) -> bool {
  child_of_kind(node, "modifiers")
    .and_then(|m| node_text(m, source))
    .is_some_and(|text| text.contains("final"))
}

fn child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  node.children(&mut cursor).find(|c| c.kind() == kind)
}

fn node_text<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
  node.utf8_text(source).ok()
}
