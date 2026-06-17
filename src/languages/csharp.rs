use std::cell::RefCell;

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
    if parser.set_language(&tree_sitter_c_sharp::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
}

const HEADER_METHODS: &[&str] = &["Add", "Append", "TryAddWithoutValidation"];

struct CsharpContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl CsharpContext<'_> {
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

  scan(context, source, &[])
}

pub fn scan(
  context: &SourceContext,
  source: &str,
  output_spans: &[(usize, usize)],
) -> bool {
  let Some(tree) = PARSER.with(|p| {
    let mut borrow = p.borrow_mut();
    let parser = borrow.as_mut()?;
    parser.parse(source, None)
  }) else {
    return false;
  };

  let mut ctx = CsharpContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
  };

  process_node(&mut ctx, tree.root_node(), source.as_bytes());

  let _ = output_spans;

  true
}

fn process_node(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  match node.kind() {
    "field_declaration" => process_field(ctx, node, source),
    "property_declaration" => process_property(ctx, node, source),
    "local_declaration_statement" => process_local(ctx, node, source),
    "initializer_expression" => process_initializer(ctx, node, source),
    "argument" => process_argument(ctx, node, source),
    "parameter" => process_parameter(ctx, node, source),
    "invocation_expression" => process_invocation(ctx, node, source),
    "assignment_expression" => process_assignment(ctx, node, source),
    "string_literal"
    | "verbatim_string_literal"
    | "raw_string_literal"
    | "interpolated_string_expression" => process_value_only(ctx, node, source),
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

// -----------------------------------------------------------------------------
// Fields, properties, locals
// -----------------------------------------------------------------------------

fn process_field(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let assignment_type = if has_modifier(node, source, "const")
    || has_modifier(node, source, "readonly")
  {
    AssignmentType::Constant
  } else {
    AssignmentType::Variable
  };

  if let Some(declaration) = child_of_kind(node, "variable_declaration") {
    process_variable_declaration(ctx, declaration, assignment_type, source);
  }
}

fn process_local(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let assignment_type = if has_modifier(node, source, "const") {
    AssignmentType::Constant
  } else {
    AssignmentType::Variable
  };

  if let Some(declaration) = child_of_kind(node, "variable_declaration") {
    process_variable_declaration(ctx, declaration, assignment_type, source);
  }
}

fn process_variable_declaration(
  ctx: &mut CsharpContext,
  declaration: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  let mut cursor = declaration.walk();
  for declarator in declaration
    .children(&mut cursor)
    .filter(|c| c.kind() == "variable_declarator")
  {
    let name_node = declarator.child_by_field_name("name");
    let name = name_node.and_then(|n| node_text(n, source));

    if let Some(value) = value_child(declarator) {
      check_value_node(ctx, name, value, assignment_type, source);
    }
  }
}

fn process_property(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let name = node
    .child_by_field_name("name")
    .and_then(|n| node_text(n, source));

  let Some(value) = node.child_by_field_name("value") else {
    return;
  };

  let value = if value.kind() == "arrow_expression_clause" {
    value.named_child(0).unwrap_or(value)
  } else {
    value
  };

  check_value_node(ctx, name, value, AssignmentType::Property, source);
}

// -----------------------------------------------------------------------------
// Object and collection initializers
// -----------------------------------------------------------------------------

fn process_initializer(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "assignment_expression" => {
        let (Some(left), Some(right)) = (
          child.child_by_field_name("left"),
          child.child_by_field_name("right"),
        ) else {
          continue;
        };

        match left.kind() {
          "identifier" => check_value_node(
            ctx,
            node_text(left, source),
            right,
            AssignmentType::Property,
            source,
          ),
          "element_binding_expression" => {
            if let Some(key) = element_key(left, source) {
              check_value_node(
                ctx,
                Some(&key),
                right,
                AssignmentType::Element,
                source,
              );
            }
          }
          _ => {}
        }
      }
      "initializer_expression" => {
        let mut inner = child.walk();
        let entries: Vec<Node> = child
          .children(&mut inner)
          .filter(|c| is_value_expression(c.kind()))
          .collect();
        if let [key_node, value_node] = entries.as_slice()
          && let Some(key) = extract_string(*key_node, source)
        {
          check_value_node(
            ctx,
            Some(&key),
            *value_node,
            AssignmentType::Element,
            source,
          );
        }
      }
      _ => {}
    }
  }
}

// -----------------------------------------------------------------------------
// Named arguments, parameter defaults
// -----------------------------------------------------------------------------

fn process_argument(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let Some(name) = node
    .child_by_field_name("name")
    .and_then(|n| node_text(n, source))
  else {
    return;
  };

  if let Some(value) = value_child(node) {
    check_value_node(ctx, Some(name), value, AssignmentType::Argument, source);
  }
}

fn process_parameter(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let name = node
    .child_by_field_name("name")
    .and_then(|n| node_text(n, source));

  if let Some(value) = value_child(node) {
    check_value_node(ctx, name, value, AssignmentType::Parameter, source);
  }
}

// -----------------------------------------------------------------------------
// Header setters: Headers.Add / .Append / .TryAddWithoutValidation, indexers
// -----------------------------------------------------------------------------

fn process_invocation(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let Some(function) = node.child_by_field_name("function") else {
    return;
  };

  if function.kind() != "member_access_expression" {
    return;
  }

  let Some(method) = function
    .child_by_field_name("name")
    .and_then(|n| node_text(n, source))
  else {
    return;
  };

  let Some(arguments) = node.child_by_field_name("arguments") else {
    return;
  };
  let positional = positional_arguments(arguments);

  if method == "SetEnvironmentVariable" {
    if let [name_node, value_node, ..] = positional.as_slice()
      && let Some(name) = extract_string(*name_node, source)
    {
      check_value_node(
        ctx,
        Some(&name),
        *value_node,
        AssignmentType::EnvironmentVariable,
        source,
      );
    }
    return;
  }

  if HEADER_METHODS.contains(&method)
    && let Some(receiver) = function.child_by_field_name("expression")
    && receiver_is_headers(receiver, source)
    && let [name_node, value_node, ..] = positional.as_slice()
    && let (Some(name), Some(value)) = (
      extract_string(*name_node, source),
      extract_string(*value_node, source),
    )
  {
    emit_header(ctx, &name, &value, *value_node);
  }
}

fn process_assignment(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  let (Some(left), Some(right)) = (
    node.child_by_field_name("left"),
    node.child_by_field_name("right"),
  ) else {
    return;
  };

  match left.kind() {
    "identifier" => check_value_node(
      ctx,
      node_text(left, source),
      right,
      AssignmentType::Variable,
      source,
    ),
    "member_access_expression" => check_value_node(
      ctx,
      left
        .child_by_field_name("name")
        .and_then(|n| node_text(n, source)),
      right,
      AssignmentType::Variable,
      source,
    ),
    "element_access_expression" => {
      let Some(key) = element_access_key(left, source) else {
        return;
      };
      let on_headers = left
        .child_by_field_name("expression")
        .is_some_and(|receiver| receiver_is_headers(receiver, source));
      if on_headers {
        if let Some(value) = extract_string(right, source) {
          emit_header(ctx, &key, &value, right);
        }
      } else {
        check_value_node(
          ctx,
          Some(&key),
          right,
          AssignmentType::Element,
          source,
        );
      }
    }
    _ => {}
  }
}

fn receiver_is_headers(receiver: Node, source: &[u8]) -> bool {
  let name = match receiver.kind() {
    "member_access_expression" => receiver
      .child_by_field_name("name")
      .and_then(|n| node_text(n, source)),
    "identifier" => node_text(receiver, source),
    _ => None,
  };

  name.is_some_and(|n| n.to_ascii_lowercase().contains("header"))
}

fn positional_arguments(arguments: Node) -> Vec<Node> {
  let mut result = Vec::new();
  let mut cursor = arguments.walk();

  for argument in arguments
    .children(&mut cursor)
    .filter(|c| c.kind() == "argument")
  {
    if argument.child_by_field_name("name").is_some() {
      continue;
    }
    if let Some(value) = value_child(argument) {
      result.push(value);
    }
  }

  result
}

fn emit_header(
  ctx: &mut CsharpContext,
  name: &str,
  value: &str,
  value_node: Node,
) {
  let start = value_node.start_byte();
  let end = value_node.end_byte();
  if ctx.already_emitted(start, end) {
    return;
  }

  if let Some(d) =
    check_header_assignment(name, value, ctx.source_context, || {
      compute_span(ctx, value_node)
    })
  {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}

fn element_key(binding: Node, source: &[u8]) -> Option<String> {
  let argument = child_of_kind(binding, "argument")?;
  extract_string(value_child(argument)?, source)
}

fn element_access_key(access: Node, source: &[u8]) -> Option<String> {
  let subscript = access.child_by_field_name("subscript")?;
  let argument = child_of_kind(subscript, "argument")?;
  extract_string(value_child(argument)?, source)
}

// -----------------------------------------------------------------------------
// Value checking
// -----------------------------------------------------------------------------

fn process_value_only(ctx: &mut CsharpContext, node: Node, source: &[u8]) {
  check_value_node(ctx, None, node, AssignmentType::Variable, source);
}

fn check_value_node(
  ctx: &mut CsharpContext,
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
        &normalize_name(&n),
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
    "conditional_expression" => {
      let condition = value_node.child_by_field_name("condition");
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor) {
        if child.is_named() && Some(child) != condition {
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
    "switch_expression" => {
      let mut cursor = value_node.walk();
      for arm in value_node
        .children(&mut cursor)
        .filter(|c| c.kind() == "switch_expression_arm")
      {
        let mut inner = arm.walk();
        if let Some(arm_value) =
          arm.children(&mut inner).filter(Node::is_named).last()
        {
          check_value_node(ctx, name, arm_value, assignment_type, source);
        }
      }
    }
    "array_creation_expression" | "implicit_array_creation_expression" => {
      if let Some(init) = child_of_kind(value_node, "initializer_expression") {
        check_value_node(ctx, name, init, assignment_type, source);
      }
    }
    "initializer_expression"
    | "collection_expression"
    | "expression_element" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor).filter(Node::is_named) {
        check_value_node(ctx, name, child, assignment_type, source);
      }
    }
    _ => {}
  }
}

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "string_literal" => {
      let mut result = String::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        match child.kind() {
          "string_literal_content" | "escape_sequence" => {
            result.push_str(node_text(child, source)?);
          }
          _ => {}
        }
      }
      Some(result)
    }
    "raw_string_literal" => child_of_kind(node, "raw_string_content")
      .and_then(|c| node_text(c, source))
      .map(str::to_owned),
    "verbatim_string_literal" => {
      let text = node_text(node, source)?;
      let inner = text.strip_prefix("@\"")?.strip_suffix('"')?;
      Some(inner.replace("\"\"", "\""))
    }
    "interpolated_string_expression" => {
      let mut result = String::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        match child.kind() {
          "interpolation" => return None,
          "string_content" => result.push_str(node_text(child, source)?),
          _ => {}
        }
      }
      Some(result)
    }
    "binary_expression" => {
      let left = extract_string(node.child_by_field_name("left")?, source)?;
      let right = extract_string(node.child_by_field_name("right")?, source)?;
      Some(left + &right)
    }
    _ => None,
  }
}

fn is_value_expression(kind: &str) -> bool {
  matches!(
    kind,
    "string_literal"
      | "verbatim_string_literal"
      | "raw_string_literal"
      | "interpolated_string_expression"
      | "binary_expression"
      | "conditional_expression"
      | "switch_expression"
      | "array_creation_expression"
      | "implicit_array_creation_expression"
      | "collection_expression"
  )
}

fn value_child(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|c| is_value_expression(c.kind()))
}

fn has_modifier(node: Node, source: &[u8], keyword: &str) -> bool {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .any(|c| c.kind() == "modifier" && node_text(c, source) == Some(keyword))
}

fn child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  node.children(&mut cursor).find(|c| c.kind() == kind)
}

fn node_text<'a>(node: Node, source: &'a [u8]) -> Option<&'a str> {
  node.utf8_text(source).ok()
}

fn compute_span(ctx: &CsharpContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
