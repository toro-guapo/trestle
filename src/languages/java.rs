use std::cell::RefCell;

use tree_sitter::Node;

use crate::{
  analysis::{Analyzer, CallFrame, FunctionSignature},
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
    if parser.set_language(&tree_sitter_java::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
  static ANALYZER: RefCell<Analyzer<String, (usize, usize)>> =
    RefCell::new(Analyzer::new());
}

struct JavaContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> JavaContext<'a> {
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

  ANALYZER.with(|a| a.borrow_mut().clear());

  let mut ctx = JavaContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
  };

  let bytes = source.as_bytes();
  process_node(&mut ctx, tree.root_node(), bytes);

  ANALYZER.with(|a| {
    a.borrow().resolve_calls(|signature, arguments| {
      resolve_arguments(&mut ctx, signature, arguments);
    });
  });

  true
}

fn process_node(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  match node.kind() {
    "local_variable_declaration" | "field_declaration" => {
      process_variable_or_field(ctx, node, source);
    }
    "assignment_expression" => {
      process_assignment(ctx, node, source);
    }
    "method_invocation" => {
      process_method_invocation(ctx, node, source);
    }
    "object_creation_expression" => {
      process_object_creation(ctx, node, source);
    }
    "method_declaration" | "constructor_declaration" => {
      register_signature(node, source);
    }
    "annotation" | "marker_annotation" => {
      process_annotation(ctx, node, source);
    }
    "element_value_pair" => {
      process_annotation_pair(ctx, node, source);
    }
    "enum_constant" => {
      process_enum_constant(ctx, node, source);
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

// -----------------------------------------------------------------------------
// Local variables and field declarations
//
// `String password = "..."` (local var)
// `private String password = "..."` (field, Variable)
// `private static final String API_KEY = "..."` (field, Constant)
// -----------------------------------------------------------------------------

fn process_variable_or_field(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  let assignment_type =
    if node.kind() == "field_declaration" && is_static_final(node, source) {
      AssignmentType::Constant
    } else {
      AssignmentType::Variable
    };

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "variable_declarator" {
      process_variable_declarator(ctx, child, source, assignment_type);
    }
  }
}

fn process_variable_declarator(
  ctx: &mut JavaContext,
  declarator: Node,
  source: &[u8],
  assignment_type: AssignmentType,
) {
  let Some(name_node) = declarator.child_by_field_name("name") else {
    return;
  };

  let Some(value_node) = declarator.child_by_field_name("value") else {
    return;
  };

  let Some(name) = identifier_text(name_node, source) else {
    return;
  };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    value_node,
    source,
    assignment_type,
  );
}

fn is_static_final(node: Node, source: &[u8]) -> bool {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "modifiers" {
      let mut saw_static = false;
      let mut saw_final = false;
      let mut inner = child.walk();
      for modifier in child.children(&mut inner) {
        match modifier.utf8_text(source).unwrap_or("") {
          "static" => saw_static = true,
          "final" => saw_final = true,
          _ => {}
        }
      }
      return saw_static && saw_final;
    }
  }
  false
}

// -----------------------------------------------------------------------------
// Reassignment: `password = "..."`, `this.password = "..."`,
// `config.apiKey = "..."`, `headers["Authorization"] = "..."`.
// -----------------------------------------------------------------------------

fn process_assignment(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  let Some(left) = node.child_by_field_name("left") else {
    return;
  };

  let Some(right) = node.child_by_field_name("right") else {
    return;
  };

  let Some(name) = extract_assignee_name(left, source) else {
    return;
  };

  check_value_node(
    ctx,
    Some(&name),
    right,
    right,
    source,
    AssignmentType::Variable,
  );
}

fn extract_assignee_name(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" => identifier_text(node, source),
    // this.x or obj.x - take the rightmost field.
    "field_access" => {
      let field = node.child_by_field_name("field")?;
      identifier_text(field, source)
    }
    // map["key"] = ... - the bracket index, when string.
    "array_access" => {
      let index = node.child_by_field_name("index")?;
      extract_string(index, source)
    }
    _ => None,
  }
}

// -----------------------------------------------------------------------------
// Method calls
// -----------------------------------------------------------------------------

const HEADER_SETTERS: &[&str] = &[
  "addHeader",
  "addRequestProperty",
  "setHeader",
  "setRequestProperty",
];

const NAME_VALUE_SETTERS: &[&str] =
  &["addProperty", "put", "putIfAbsent", "set", "setProperty"];

const MAP_OF_NAMES: &[&str] = &["of", "ofEntries"];

fn process_method_invocation(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };

  let Some(args_node) = node.child_by_field_name("arguments") else {
    return;
  };

  let Some(method_name) = identifier_text(name_node, source) else {
    return;
  };

  let args = named_children(args_node);

  // Pattern 1: name+value setters take a string key as arg[0] and a
  // value as arg[1]. The first arg is the secret name; we use it as
  // such and let `check_assignment` decide.
  let setter_type = if HEADER_SETTERS.contains(&method_name.as_str()) {
    Some(AssignmentType::Header)
  } else if NAME_VALUE_SETTERS.contains(&method_name.as_str()) {
    Some(AssignmentType::Argument)
  } else {
    None
  };

  if let Some(setter_type) = setter_type
    && args.len() >= 2
    && let Some(key) = extract_string(args[0], source)
  {
    check_value_node(ctx, Some(&key), args[1], args[1], source, setter_type);
    return;
  }

  // Pattern 2: `Map.of("k1", "v1", "k2", "v2", ...)` - alternating
  // key/value pairs. Only fire when the receiver looks like Map / ImmutableMap.
  if MAP_OF_NAMES.contains(&method_name.as_str())
    && is_map_factory(node, source)
    && args.len() >= 2
  {
    let mut i = 0;
    while i + 1 < args.len() {
      if let Some(key) = extract_string(args[i], source) {
        check_value_node(
          ctx,
          Some(&key),
          args[i + 1],
          args[i + 1],
          source,
          AssignmentType::Element,
        );
      }
      i += 2;
    }
    return;
  }

  // Pattern 3: setX(value) - single string argument. The method name
  // (e.g. `setPassword`) carries the secret name; the normalizer
  // splits it on camelCase so a name like `setPassword` matches the
  // `password` keyword.
  if args.len() == 1 {
    check_value_node(
      ctx,
      Some(&method_name),
      args[0],
      args[0],
      source,
      AssignmentType::Argument,
    );
  }

  for arg in &args {
    check_value_node(ctx, None, *arg, *arg, source, AssignmentType::Argument);
  }

  // Pattern 4: cross-call resolution for unqualified calls only. A
  // qualified call like `obj.connect(...)` targets a method whose receiver
  // type we cannot determine, so a same-named signature must not be applied.
  if node.child_by_field_name("object").is_some() {
    return;
  }

  let extracted: Vec<(String, (usize, usize))> = args
    .iter()
    .filter_map(|arg| {
      let value = extract_string(*arg, source)?;
      Some((value, (arg.start_byte(), arg.end_byte())))
    })
    .collect();
  if extracted.is_empty() {
    return;
  }

  let resolved = ANALYZER.with(|a| {
    let analyzer = a.borrow();
    if let Some(signature) = analyzer.get_signature(&method_name) {
      resolve_arguments(ctx, signature, &extracted);
      true
    } else {
      false
    }
  });

  if !resolved {
    ANALYZER.with(|a| {
      a.borrow_mut().add_frame(CallFrame {
        callee: method_name,
        arguments: extracted,
      });
    });
  }
}

fn is_map_factory(node: Node, source: &[u8]) -> bool {
  let Some(object) = node.child_by_field_name("object") else {
    return false;
  };

  let Ok(text) = object.utf8_text(source) else {
    return false;
  };

  matches!(
    text,
    "Map" | "ImmutableMap" | "Maps" | "Collections" | "List" | "Set"
  )
}

// -----------------------------------------------------------------------------
// Constructor calls: `new Credentials("user", "secret")`
// -----------------------------------------------------------------------------

fn process_object_creation(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  let Some(type_node) = node.child_by_field_name("type") else {
    return;
  };

  let Some(args_node) = node.child_by_field_name("arguments") else {
    return;
  };

  let Some(class_name) = type_identifier_text(type_node, source) else {
    return;
  };

  let args = named_children(args_node);

  for arg in &args {
    check_value_node(ctx, None, *arg, *arg, source, AssignmentType::Argument);
  }

  let extracted: Vec<(String, (usize, usize))> = args
    .iter()
    .filter_map(|arg| {
      let value = extract_string(*arg, source)?;
      Some((value, (arg.start_byte(), arg.end_byte())))
    })
    .collect();

  if extracted.is_empty() {
    return;
  }

  let resolved = ANALYZER.with(|a| {
    let analyzer = a.borrow();
    if let Some(signature) = analyzer.get_signature(&class_name) {
      resolve_arguments(ctx, signature, &extracted);
      true
    } else {
      false
    }
  });

  if !resolved {
    ANALYZER.with(|a| {
      a.borrow_mut().add_frame(CallFrame {
        callee: class_name,
        arguments: extracted,
      });
    });
  }
}

fn resolve_arguments(
  ctx: &mut JavaContext,
  signature: &FunctionSignature,
  arguments: &[(String, (usize, usize))],
) {
  for (i, (value, (start, end))) in arguments.iter().enumerate() {
    let Some(param_name) = signature.parameter_names.get(i) else {
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
// Annotations
//
// `@ApiKey("...")` - marker / single-value: use annotation name.
// `@ApiKey(value = "...")` / `@Auth(token = "...")` - element_value_pair.
// -----------------------------------------------------------------------------

fn process_annotation(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  // Marker annotations have no arguments.
  if node.kind() == "marker_annotation" {
    return;
  }

  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };

  let Some(args_node) = node.child_by_field_name("arguments") else {
    return;
  };

  let Some(annotation_name) = type_identifier_text(name_node, source) else {
    return;
  };

  // Single-value annotation: `@ApiKey("...")`. Use the annotation
  // name as the key so the normalizer can match against secret-name
  // patterns (e.g. `@ApiKey` -> `api_key`).
  let mut single_value: Option<Node> = None;
  let mut has_pairs = false;
  let mut cursor = args_node.walk();

  for child in args_node.children(&mut cursor) {
    if !child.is_named() {
      continue;
    }
    if child.kind() == "element_value_pair" {
      has_pairs = true;
      break;
    }
    if single_value.is_none() {
      single_value = Some(child);
    }
  }

  if !has_pairs && let Some(value_node) = single_value {
    check_value_node(
      ctx,
      Some(&annotation_name),
      value_node,
      value_node,
      source,
      AssignmentType::Argument,
    );
  }
}

fn process_annotation_pair(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  let mut name: Option<String> = None;
  let mut value_node: Option<Node> = None;
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if !child.is_named() {
      continue;
    }
    if name.is_none() && child.kind() == "identifier" {
      name = identifier_text(child, source);
    } else if name.is_some() && value_node.is_none() {
      value_node = Some(child);
    }
  }

  let (Some(name), Some(value_node)) = (name, value_node) else {
    return;
  };
  check_value_node(
    ctx,
    Some(&name),
    value_node,
    value_node,
    source,
    AssignmentType::Argument,
  );
}

// -----------------------------------------------------------------------------
// Enum constants: `enum Service { USER_API("apikey"), PAYMENT_API("..."); }`
// -----------------------------------------------------------------------------

fn process_enum_constant(ctx: &mut JavaContext, node: Node, source: &[u8]) {
  let mut name: Option<String> = None;
  let mut args_node: Option<Node> = None;
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "identifier" if name.is_none() => {
        name = identifier_text(child, source);
      }
      "argument_list" if args_node.is_none() => {
        args_node = Some(child);
      }
      _ => {}
    }
  }

  let (Some(name), Some(args_node)) = (name, args_node) else {
    return;
  };
  let args = named_children(args_node);
  if args.len() == 1 {
    check_value_node(
      ctx,
      Some(&name),
      args[0],
      args[0],
      source,
      AssignmentType::Constant,
    );
  }
}

// -----------------------------------------------------------------------------
// Method/constructor signature registration
// -----------------------------------------------------------------------------

fn register_signature(node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };

  let Some(params_node) = node.child_by_field_name("parameters") else {
    return;
  };

  let Ok(name) = name_node.utf8_text(source) else {
    return;
  };

  let mut parameter_names = Vec::new();
  let mut cursor = params_node.walk();
  for child in params_node.children(&mut cursor) {
    if matches!(
      child.kind(),
      "formal_parameter" | "spread_parameter" | "receiver_parameter"
    ) && let Some(p_name_node) = child.child_by_field_name("name")
      && let Ok(p_name) = p_name_node.utf8_text(source)
    {
      parameter_names.push(p_name.to_owned());
    }
  }

  ANALYZER.with(|a| {
    a.borrow_mut()
      .add_signature(name.to_owned(), FunctionSignature { parameter_names });
  });
}

// -----------------------------------------------------------------------------
// Value checking with conditional/parens/cast unwrapping
// -----------------------------------------------------------------------------

fn check_value_node(
  ctx: &mut JavaContext,
  name: Option<&str>,
  value_node: Node,
  span_node: Node,
  source: &[u8],
  assignment_type: AssignmentType,
) {
  if let Some(value) = extract_string(value_node, source) {
    let start = value_node.start_byte();
    let end = value_node.end_byte();
    if ctx.already_emitted(start, end) {
      return;
    }

    let normalized = normalize_value(&value);
    let diag: Option<Diagnostic> = match name {
      Some(n) if assignment_type == AssignmentType::Header => {
        check_header_assignment(n, &value, ctx.source_context, || {
          compute_span(ctx, span_node)
        })
      }
      Some(n) => check_assignment(
        &normalize_name(&n.to_owned()),
        &normalized,
        assignment_type,
        ctx.source_context,
        || compute_span(ctx, span_node),
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
    // cond ? "a" : "b" - check both branches with the name preserved.
    "ternary_expression" => {
      if let Some(c) = value_node.child_by_field_name("consequence") {
        check_value_node(ctx, name, c, c, source, assignment_type);
      }
      if let Some(a) = value_node.child_by_field_name("alternative") {
        check_value_node(ctx, name, a, a, source, assignment_type);
      }
    }
    "parenthesized_expression" => {
      for child in named_children(value_node) {
        check_value_node(ctx, name, child, span_node, source, assignment_type);
      }
    }
    "cast_expression" => {
      if let Some(value) = value_node.child_by_field_name("value") {
        check_value_node(ctx, name, value, span_node, source, assignment_type);
      }
    }
    "binary_expression" => {
      if let Some(left) = value_node.child_by_field_name("left") {
        check_value_node(ctx, name, left, span_node, source, assignment_type);
      }
      if let Some(right) = value_node.child_by_field_name("right") {
        check_value_node(ctx, name, right, span_node, source, assignment_type);
      }
    }
    "method_invocation" | "object_creation_expression" => {
      if let Some(args) = value_node.child_by_field_name("arguments") {
        for arg in named_children(args) {
          check_value_node(ctx, name, arg, span_node, source, assignment_type);
        }
      }
    }
    "array_initializer" => {
      for child in named_children(value_node) {
        check_value_node(ctx, name, child, child, source, assignment_type);
      }
    }
    "array_creation_expression" => {
      if let Some(init) = value_node.child_by_field_name("value") {
        check_value_node(ctx, name, init, init, source, assignment_type);
      }
    }
    _ => {}
  }
}

// -----------------------------------------------------------------------------
// String extraction
//
// Java has:
//   - regular `"..."` string literals (with escape sequences and
//     `string_fragment` content children).
//   - text blocks `""" ... """` (Java 15+) under `string_literal` with
//     a `multiline_string_fragment` child.
//   - `+` concatenation across string literals.
//   - parenthesized expressions wrapping any of the above.
// -----------------------------------------------------------------------------

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "string_literal" => extract_string_literal(node, source),
    "binary_expression" => {
      let op = node.child_by_field_name("operator")?;
      if op.utf8_text(source).ok()? != "+" {
        return None;
      }
      let left = extract_string(node.child_by_field_name("left")?, source)?;
      let right = extract_string(node.child_by_field_name("right")?, source)?;
      Some(left + &right)
    }
    "parenthesized_expression" => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if child.is_named() {
          return extract_string(child, source);
        }
      }
      None
    }
    "cast_expression" => {
      extract_string(node.child_by_field_name("value")?, source)
    }
    _ => None,
  }
}

fn extract_string_literal(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  let mut out = String::new();
  let mut had_content = false;

  for child in node.children(&mut cursor) {
    match child.kind() {
      "string_fragment" | "multiline_string_fragment" => {
        if let Ok(text) = child.utf8_text(source) {
          out.push_str(text);
          had_content = true;
        }
      }
      "escape_sequence" => {
        let Ok(text) = child.utf8_text(source) else {
          return None;
        };
        match text {
          "\\n" => out.push('\n'),
          "\\r" => out.push('\r'),
          "\\t" => out.push('\t'),
          "\\\\" => out.push('\\'),
          "\\\"" => out.push('"'),
          "\\'" => out.push('\''),
          "\\0" => out.push('\0'),
          _ => return None,
        }
        had_content = true;
      }
      _ => {}
    }
  }

  if had_content && !out.is_empty() {
    Some(out)
  } else {
    None
  }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn identifier_text(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" | "type_identifier" => {
      node.utf8_text(source).ok().map(|s| s.to_owned())
    }
    _ => None,
  }
}

fn type_identifier_text(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" | "type_identifier" => {
      node.utf8_text(source).ok().map(|s| s.to_owned())
    }
    "scoped_type_identifier" => {
      let mut last = None;
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if child.kind() == "type_identifier" {
          last = child.utf8_text(source).ok().map(|s| s.to_owned());
        }
      }
      last
    }
    "generic_type" => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if matches!(child.kind(), "type_identifier" | "scoped_type_identifier")
        {
          return type_identifier_text(child, source);
        }
      }
      None
    }
    _ => None,
  }
}

fn named_children(node: Node) -> Vec<Node> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .filter(|n| n.is_named())
    .collect()
}

fn compute_span(ctx: &JavaContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
