use std::cell::RefCell;
use std::collections::HashMap;

use tree_sitter::Node;

use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, SourceFileSpan, SourceSpan, check_assignment,
    check_header_assignment, check_value, offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_swift::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
}

struct PendingCall {
  callee: String,
  arguments: Vec<(String, (usize, usize))>,
}

struct SwiftContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
  free_signatures: HashMap<String, Vec<String>>,
  pending_calls: Vec<PendingCall>,
}

impl SwiftContext<'_> {
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

  let mut ctx = SwiftContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
    free_signatures: HashMap::new(),
    pending_calls: Vec::new(),
  };

  let bytes = source.as_bytes();
  process_node(&mut ctx, tree.root_node(), bytes);
  resolve_pending_calls(&mut ctx);

  true
}

fn process_node(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  match node.kind() {
    "property_declaration" => process_property(ctx, node, source),
    "enum_entry" => process_enum_entry(ctx, node, source),
    "dictionary_literal" => process_dictionary(ctx, node, source),
    "tuple_expression" => process_tuple(ctx, node, source),
    "value_argument" => process_value_argument(ctx, node, source),
    "function_declaration" | "init_declaration" => {
      register_signature(ctx, node, source);
      process_default_params(ctx, node, source);
    }
    "call_expression" => process_call(ctx, node, source),
    "assignment" => process_assignment(ctx, node, source),
    "if_statement" | "guard_statement" | "while_statement" => {
      process_optional_binding(ctx, node, source);
    }
    "line_string_literal"
    | "multi_line_string_literal"
    | "raw_string_literal" => process_value_only(ctx, node, source),
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

// -----------------------------------------------------------------------------
// let / var declarations (top-level, properties, static, local)
// -----------------------------------------------------------------------------

fn process_property(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let assignment_type = if is_var_binding(node) {
    AssignmentType::Variable
  } else {
    AssignmentType::Constant
  };

  let mut cursor = node.walk();
  if !cursor.goto_first_child() {
    return;
  }

  let mut pending_name: Option<Node> = None;
  loop {
    let child = cursor.node();
    match cursor.field_name() {
      Some("name") => pending_name = Some(child),
      Some("value") => {
        if let Some(name_node) = pending_name.take() {
          process_binding(ctx, name_node, child, assignment_type, source);
        }
      }
      Some("computed_value") => {
        if let Some(name_node) = pending_name.take() {
          process_computed(ctx, name_node, child, assignment_type, source);
        }
      }
      _ => {}
    }
    if !cursor.goto_next_sibling() {
      break;
    }
  }
}

fn process_binding(
  ctx: &mut SwiftContext,
  name_node: Node,
  value_node: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  let inner: Vec<Node> = {
    let mut cursor = name_node.walk();
    name_node
      .children(&mut cursor)
      .filter(|c| c.kind() == "pattern")
      .collect()
  };

  if inner.is_empty() {
    if let Some(name) = pattern_name(name_node, source) {
      check_value_node(ctx, Some(&name), value_node, assignment_type, source);
    }
    return;
  }

  if value_node.kind() != "tuple_expression" {
    return;
  }
  for (pattern, value) in inner.iter().zip(tuple_values(value_node)) {
    if let Some(name) = pattern_name(*pattern, source) {
      check_value_node(ctx, Some(&name), value, assignment_type, source);
    }
  }
}

fn tuple_values(node: Node) -> Vec<Node> {
  let mut values = Vec::new();
  let mut cursor = node.walk();
  if cursor.goto_first_child() {
    loop {
      if cursor.field_name() == Some("value") {
        values.push(cursor.node());
      }
      if !cursor.goto_next_sibling() {
        break;
      }
    }
  }
  values
}

fn process_computed(
  ctx: &mut SwiftContext,
  name_node: Node,
  computed_node: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  let Some(name) = pattern_name(name_node, source) else {
    return;
  };
  let Some(value_node) = computed_return_value(computed_node) else {
    return;
  };
  check_value_node(ctx, Some(&name), value_node, assignment_type, source);
}

fn computed_return_value(node: Node) -> Option<Node> {
  let statements = direct_statements(node)?;

  let mut named = None;
  let mut count = 0;
  let mut cursor = statements.walk();
  for child in statements.children(&mut cursor) {
    if child.is_named() {
      named = Some(child);
      count += 1;
    }
  }

  if count != 1 {
    return None;
  }
  let only = named?;
  matches!(
    only.kind(),
    "line_string_literal" | "multi_line_string_literal" | "raw_string_literal"
  )
  .then_some(only)
}

fn direct_statements(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "statements" {
      return Some(child);
    }
    if child.kind() == "computed_getter" {
      let mut inner = child.walk();
      if let Some(statements) = child
        .children(&mut inner)
        .find(|c| c.kind() == "statements")
      {
        return Some(statements);
      }
    }
  }
  None
}

fn process_tuple(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  if !cursor.goto_first_child() {
    return;
  }

  let mut pending_label: Option<String> = None;
  loop {
    let child = cursor.node();
    match cursor.field_name() {
      Some("name") => {
        pending_label = child.utf8_text(source).ok().map(str::to_owned);
      }
      Some("value") => {
        if let Some(label) = pending_label.take() {
          check_value_node(
            ctx,
            Some(&label),
            child,
            AssignmentType::Element,
            source,
          );
        }
      }
      _ => {}
    }
    if !cursor.goto_next_sibling() {
      break;
    }
  }
}

fn pattern_name(node: Node, source: &[u8]) -> Option<String> {
  if node.kind() == "simple_identifier" {
    return node.utf8_text(source).ok().map(str::to_owned);
  }
  if let Some(bound) = node.child_by_field_name("bound_identifier") {
    return bound.utf8_text(source).ok().map(str::to_owned);
  }
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|c| c.kind() == "simple_identifier")
    .and_then(|c| c.utf8_text(source).ok())
    .map(str::to_owned)
}

fn is_var_binding(node: Node) -> bool {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "value_binding_pattern" {
      return child
        .child_by_field_name("mutability")
        .map(|m| m.kind() == "var")
        .unwrap_or(false);
    }
  }
  false
}

// -----------------------------------------------------------------------------
// enum cases with raw values: case primary = "secret"
// -----------------------------------------------------------------------------

fn process_enum_entry(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("raw_value") else {
    return;
  };
  let Some(name) = name_node.utf8_text(source).ok().map(str::to_owned) else {
    return;
  };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    AssignmentType::Constant,
    source,
  );
}

// -----------------------------------------------------------------------------
// Dictionary literals: ["password": "secret"]
// -----------------------------------------------------------------------------

fn process_dictionary(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  if !cursor.goto_first_child() {
    return;
  }

  let mut pending_key: Option<String> = None;
  loop {
    let field = cursor.field_name();
    let child = cursor.node();

    if field == Some("key") {
      pending_key = extract_string(child, source);
    } else if field == Some("value") {
      check_value_node(
        ctx,
        pending_key.as_deref(),
        child,
        AssignmentType::Element,
        source,
      );
      pending_key = None;
    }

    if !cursor.goto_next_sibling() {
      break;
    }
  }
}

// -----------------------------------------------------------------------------
// Labeled call arguments: connect(password: "secret")
// -----------------------------------------------------------------------------

fn process_value_argument(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("value") else {
    return;
  };
  let Some(name) = label_name(name_node, source) else {
    return;
  };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    AssignmentType::Argument,
    source,
  );
}

fn label_name(node: Node, source: &[u8]) -> Option<String> {
  if node.kind() == "simple_identifier" {
    return node.utf8_text(source).ok().map(str::to_owned);
  }
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|c| c.kind() == "simple_identifier")
    .and_then(|c| c.utf8_text(source).ok())
    .map(str::to_owned)
}

// -----------------------------------------------------------------------------
// Default parameter values: func connect(password: String = "secret")
// -----------------------------------------------------------------------------

fn process_default_params(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  if !cursor.goto_first_child() {
    return;
  }

  let mut last_param: Option<String> = None;
  loop {
    let child = cursor.node();
    if child.kind() == "parameter" {
      last_param = parameter_name(child, source);
    } else if cursor.field_name() == Some("default_value")
      && let Some(name) = last_param.as_deref()
    {
      check_value_node(
        ctx,
        Some(name),
        child,
        AssignmentType::Parameter,
        source,
      );
    }

    if !cursor.goto_next_sibling() {
      break;
    }
  }
}

fn parameter_name(node: Node, source: &[u8]) -> Option<String> {
  let name_node = node.child_by_field_name("name")?;
  if name_node.kind() == "simple_identifier" {
    return name_node.utf8_text(source).ok().map(str::to_owned);
  }
  None
}

// -----------------------------------------------------------------------------
// Function calls: resolve positional arguments against known signatures
// -----------------------------------------------------------------------------

fn register_signature(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  if is_method(node) {
    return;
  }

  let Some(name) = node
    .child_by_field_name("name")
    .and_then(|n| n.utf8_text(source).ok())
    .map(str::to_owned)
  else {
    return;
  };

  let mut parameter_names = Vec::new();
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "parameter"
      && let Some(param) = parameter_name(child, source)
    {
      parameter_names.push(param);
    }
  }

  ctx.free_signatures.insert(name, parameter_names);
}

fn is_method(node: Node) -> bool {
  let mut current = node.parent();
  while let Some(n) = current {
    match n.kind() {
      "class_body" | "enum_class_body" | "protocol_body" => return true,
      "function_body" | "source_file" => return false,
      _ => current = n.parent(),
    }
  }
  false
}

fn process_call(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  process_name_value_setter(ctx, node, source);

  let Some(callee) = call_callee(node, source) else {
    return;
  };
  let Some(args_node) = call_value_arguments(node) else {
    return;
  };

  let arguments = extract_positional_args(args_node, source);
  if arguments.is_empty() {
    return;
  }

  ctx.pending_calls.push(PendingCall { callee, arguments });
}

const SETTER_HEADER_LABELS: &[&str] = &["forHTTPHeaderField", "forHeader"];
const SETTER_KEY_LABELS: &[&str] = &["forKey", "key"];

fn process_name_value_setter(
  ctx: &mut SwiftContext,
  node: Node,
  source: &[u8],
) {
  let Some(args_node) = call_value_arguments(node) else {
    return;
  };

  let mut name: Option<String> = None;
  let mut is_header = false;
  let mut value_node: Option<Node> = None;

  let mut cursor = args_node.walk();
  for child in args_node.children(&mut cursor) {
    if child.kind() != "value_argument" {
      continue;
    }
    match child.child_by_field_name("name") {
      Some(label_node) => {
        if name.is_none()
          && let Some(label) = label_name(label_node, source)
        {
          let header = SETTER_HEADER_LABELS.contains(&label.as_str());
          let recognized =
            header || SETTER_KEY_LABELS.contains(&label.as_str());
          if recognized
            && let Some(value) = child.child_by_field_name("value")
            && let Some(extracted) = extract_string(value, source)
          {
            name = Some(extracted);
            is_header = header;
          }
        }
      }
      None => {
        if value_node.is_none() {
          value_node = child.child_by_field_name("value");
        }
      }
    }
  }

  let (Some(name), Some(value_node)) = (name, value_node) else {
    return;
  };

  if is_header {
    emit_header_setter(ctx, &name, value_node, source);
  } else {
    check_value_node(
      ctx,
      Some(&name),
      value_node,
      AssignmentType::Argument,
      source,
    );
  }
}

fn emit_header_setter(
  ctx: &mut SwiftContext,
  name: &str,
  value_node: Node,
  source: &[u8],
) {
  let Some(value) = extract_string(value_node, source) else {
    return;
  };

  let start = value_node.start_byte();
  let end = value_node.end_byte();
  if ctx.already_emitted(start, end) {
    return;
  }

  if let Some(d) =
    check_header_assignment(name, &value, ctx.source_context, || {
      compute_span(ctx, value_node)
    })
  {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}

fn resolve_pending_calls(ctx: &mut SwiftContext) {
  let calls = std::mem::take(&mut ctx.pending_calls);
  for call in calls {
    if let Some(parameter_names) =
      ctx.free_signatures.get(&call.callee).cloned()
    {
      resolve_arguments(ctx, &parameter_names, &call.arguments);
    }
  }
}

fn call_callee(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "simple_identifier" => {
        return child.utf8_text(source).ok().map(str::to_owned);
      }
      "call_suffix" => break,
      _ => {}
    }
  }
  None
}

fn call_value_arguments(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "call_suffix" {
      let mut inner = child.walk();
      return child
        .children(&mut inner)
        .find(|c| c.kind() == "value_arguments");
    }
  }
  None
}

fn extract_positional_args(
  args_node: Node,
  source: &[u8],
) -> Vec<(String, (usize, usize))> {
  let mut positional = Vec::new();
  let mut cursor = args_node.walk();
  for child in args_node.children(&mut cursor) {
    if child.kind() != "value_argument" {
      continue;
    }
    if child.child_by_field_name("name").is_some() {
      continue;
    }
    if let Some(value_node) = child.child_by_field_name("value")
      && let Some(value) = extract_string(value_node, source)
    {
      positional
        .push((value, (value_node.start_byte(), value_node.end_byte())));
    }
  }
  positional
}

fn resolve_arguments(
  ctx: &mut SwiftContext,
  parameter_names: &[String],
  arguments: &[(String, (usize, usize))],
) {
  for (i, (value, (start, end))) in arguments.iter().enumerate() {
    let Some(param_name) = parameter_names.get(i) else {
      break;
    };
    if ctx.already_emitted(*start, *end) {
      continue;
    }

    if let Some(d) = check_assignment(
      &normalize_name(param_name),
      &normalize_value(value),
      AssignmentType::Argument,
      ctx.source_context,
      || SourceFileSpan {
        file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
        file_span: Some(SourceSpan {
          start: offset_to_position(ctx.source, *start),
          end: offset_to_position(ctx.source, *end),
        }),
      },
    ) {
      ctx.record_emitted(*start, *end);
      ctx.source_context.emit_diagnostic(d);
    }
  }
}

// -----------------------------------------------------------------------------
// Optional bindings: if/guard/while let apiKey = "secret"
// -----------------------------------------------------------------------------

fn process_optional_binding(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  if !cursor.goto_first_child() {
    return;
  }

  let mut pending_name: Option<String> = None;
  let mut binding_type = AssignmentType::Constant;
  let mut saw_equals = false;

  loop {
    let child = cursor.node();
    let field = cursor.field_name();
    match child.kind() {
      "value_binding_pattern" => {
        binding_type = if child
          .child_by_field_name("mutability")
          .map(|m| m.kind() == "var")
          .unwrap_or(false)
        {
          AssignmentType::Variable
        } else {
          AssignmentType::Constant
        };
        saw_equals = false;
      }
      "=" => saw_equals = true,
      _ if field == Some("bound_identifier") => {
        pending_name = child.utf8_text(source).ok().map(str::to_owned);
      }
      _ if saw_equals && field == Some("condition") && child.is_named() => {
        if let Some(name) = pending_name.take() {
          check_value_node(ctx, Some(&name), child, binding_type, source);
        }
        saw_equals = false;
      }
      _ => {}
    }

    if !cursor.goto_next_sibling() {
      break;
    }
  }
}

// -----------------------------------------------------------------------------
// Reassignment: token = "secret", self.token = "secret"
// -----------------------------------------------------------------------------

fn process_assignment(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let Some(target) = node.child_by_field_name("target") else {
    return;
  };
  let Some(result) = node.child_by_field_name("result") else {
    return;
  };
  let Some(name) = assignable_name(target, source) else {
    return;
  };

  check_value_node(ctx, Some(&name), result, AssignmentType::Variable, source);
}

fn assignable_name(node: Node, source: &[u8]) -> Option<String> {
  if let Some(key) = subscript_key(node, source) {
    return Some(key);
  }
  last_simple_identifier(node, source)
}

fn subscript_key(node: Node, source: &[u8]) -> Option<String> {
  if node.kind() == "value_arguments" && is_subscript(node) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
      if child.kind() == "value_argument"
        && let Some(value) = child.child_by_field_name("value")
        && let Some(key) = extract_string(value, source)
      {
        return Some(key);
      }
    }
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if let Some(key) = subscript_key(child, source) {
      return Some(key);
    }
  }
  None
}

fn is_subscript(value_arguments: Node) -> bool {
  let mut cursor = value_arguments.walk();
  value_arguments
    .children(&mut cursor)
    .next()
    .map(|c| c.kind() == "[")
    .unwrap_or(false)
}

fn last_simple_identifier(node: Node, source: &[u8]) -> Option<String> {
  let mut found = None;
  collect_last_identifier(node, source, &mut found);
  found
}

fn collect_last_identifier(
  node: Node,
  source: &[u8],
  found: &mut Option<String>,
) {
  if node.kind() == "simple_identifier" {
    if let Ok(text) = node.utf8_text(source) {
      *found = Some(text.to_owned());
    }
    return;
  }
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    collect_last_identifier(child, source, found);
  }
}

// -----------------------------------------------------------------------------
// Bare value detection (signatures anywhere): array elements, returns, ...
// -----------------------------------------------------------------------------

fn process_value_only(ctx: &mut SwiftContext, node: Node, source: &[u8]) {
  let start = node.start_byte();
  let end = node.end_byte();
  if ctx.already_emitted(start, end) {
    return;
  }

  let Some(value) = extract_string(node, source) else {
    return;
  };

  if let Some(d) =
    check_value(&normalize_value(&value), ctx.source_context, || {
      compute_span(ctx, node)
    })
  {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}

// -----------------------------------------------------------------------------
// Value checking with conditional / nil-coalescing support
// -----------------------------------------------------------------------------

fn check_value_node(
  ctx: &mut SwiftContext,
  name: Option<&str>,
  value_node: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  if let Some(value) = extract_string(value_node, source) {
    let start = value_node.start_byte();
    let end = value_node.end_byte();
    if ctx.already_emitted(start, end) {
      return;
    }

    let normalized = normalize_value(&value);
    let diag: Option<Diagnostic> = match name {
      Some(n) => check_assignment(
        &normalize_name(&n.to_owned()),
        &normalized,
        assignment_type,
        ctx.source_context,
        || compute_span(ctx, value_node),
      ),
      None => check_value(&normalized, ctx.source_context, || {
        compute_span(ctx, value_node)
      }),
    };

    if let Some(d) = diag {
      ctx.record_emitted(start, end);
      ctx.source_context.emit_diagnostic(d);
    }
    return;
  }

  match value_node.kind() {
    "ternary_expression" => {
      if let Some(t) = value_node.child_by_field_name("if_true") {
        check_value_node(ctx, name, t, assignment_type, source);
      }
      if let Some(f) = value_node.child_by_field_name("if_false") {
        check_value_node(ctx, name, f, assignment_type, source);
      }
    }
    "nil_coalescing_expression" => {
      if let Some(v) = value_node.child_by_field_name("value") {
        check_value_node(ctx, name, v, assignment_type, source);
      }
      if let Some(n) = value_node.child_by_field_name("if_nil") {
        check_value_node(ctx, name, n, assignment_type, source);
      }
    }
    "array_literal" | "array_element" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor).filter(Node::is_named) {
        check_value_node(ctx, name, child, assignment_type, source);
      }
    }
    _ => {}
  }
}

// -----------------------------------------------------------------------------
// String extraction
// -----------------------------------------------------------------------------

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "line_string_literal" | "multi_line_string_literal" => {
      extract_quoted_string(node, source)
    }
    "raw_string_literal" => extract_raw_string(node, source),
    "additive_expression" => {
      let mut text = String::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if child.kind() == "+" {
          continue;
        }
        if child.is_named() {
          text.push_str(&extract_string(child, source)?);
        }
      }
      Some(text)
    }
    _ => None,
  }
}

fn extract_quoted_string(node: Node, source: &[u8]) -> Option<String> {
  let mut text = String::new();
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "line_str_text" | "multi_line_str_text" | "str_escaped_char" => {
        text.push_str(child.utf8_text(source).ok()?);
      }
      "interpolated_expression" => return None,
      _ => {}
    }
  }
  Some(text)
}

fn extract_raw_string(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind().contains("interpolation") {
      return None;
    }
  }

  let text = node.utf8_text(source).ok()?;
  let hashes = text.bytes().take_while(|&b| b == b'#').count();
  let inner = text.get(hashes..)?.strip_prefix('"')?;

  let mut closing = String::from("\"");
  for _ in 0..hashes {
    closing.push('#');
  }

  inner.strip_suffix(&closing).map(str::to_owned)
}

fn compute_span(ctx: &SwiftContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
