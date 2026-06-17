use std::cell::RefCell;
use std::collections::HashMap;

use tree_sitter::Node;

use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, SourceFileSpan, SourceSpan, check_assignment,
    check_header_assignment, check_value, offset_to_position,
    strip_build_config_quotes,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_kotlin_ng::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
}

const HEADER_SETTERS: &[&str] =
  &["addHeader", "header", "setHeader", "setRequestProperty"];

struct PendingCall {
  callee: String,
  arguments: Vec<(usize, String, (usize, usize))>,
}

struct KotlinContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
  free_signatures: HashMap<String, Vec<String>>,
  pending_calls: Vec<PendingCall>,
}

impl KotlinContext<'_> {
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

  let mut ctx = KotlinContext {
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

fn process_node(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  match node.kind() {
    "property_declaration" => process_property(ctx, node, source),
    "class_declaration" => process_enum_entries(ctx, node, source),
    "class_parameter" => process_class_parameter(ctx, node, source),
    "function_declaration" => {
      register_signature(ctx, node, source);
      process_default_params(ctx, node, source);
    }
    "secondary_constructor" => process_default_params(ctx, node, source),
    "call_expression" => process_call(ctx, node, source),
    "assignment" => process_assignment(ctx, node, source),
    "value_argument" => process_value_argument(ctx, node, source),
    "infix_expression" => process_infix(ctx, node, source),
    "annotation" => process_annotation(ctx, node, source),
    "string_literal" | "multiline_string_literal" => {
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
// val / var / const val declarations (top-level, class, object, companion)
// -----------------------------------------------------------------------------

fn process_property(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let assignment_type = if is_var(node) {
    AssignmentType::Variable
  } else {
    AssignmentType::Constant
  };

  let mut name: Option<String> = None;
  let mut value: Option<Node> = None;
  let mut getter: Option<Node> = None;
  let mut delegate: Option<Node> = None;

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "variable_declaration" => name = variable_name(child, source),
      "getter" => getter = Some(child),
      "property_delegate" => delegate = Some(child),
      "modifiers" | "setter" | "multi_variable_declaration" => {}
      _ if child.is_named() && name.is_some() && value.is_none() => {
        value = Some(child);
      }
      _ => {}
    }
  }

  if let Some(value) = value {
    check_value_node(ctx, name.as_deref(), value, assignment_type, source);
  } else if let Some(getter_value) = getter.and_then(getter_value) {
    check_value_node(
      ctx,
      name.as_deref(),
      getter_value,
      assignment_type,
      source,
    );
  } else if let Some(delegate_value) =
    delegate.and_then(|d| lazy_delegate_value(d, source))
  {
    check_value_node(
      ctx,
      name.as_deref(),
      delegate_value,
      assignment_type,
      source,
    );
  }
}

fn is_var(node: Node) -> bool {
  let mut cursor = node.walk();
  node.children(&mut cursor).any(|c| c.kind() == "var")
}

fn variable_name(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|c| c.kind() == "identifier")
    .and_then(|c| c.utf8_text(source).ok())
    .map(str::to_owned)
}

fn getter_value(getter: Node) -> Option<Node> {
  let mut cursor = getter.walk();
  let body = getter
    .children(&mut cursor)
    .find(|c| c.kind() == "function_body")?;

  let mut inner = body.walk();
  body
    .children(&mut inner)
    .find(|c| is_value_expression(c.kind()))
}

fn is_value_expression(kind: &str) -> bool {
  matches!(
    kind,
    "string_literal"
      | "multiline_string_literal"
      | "call_expression"
      | "if_expression"
      | "binary_expression"
      | "when_expression"
  )
}

// `val key by lazy { "..." }`: the lambda's tail expression is the property's
// value. Restricted to `lazy` because other delegates (`Delegates.observable`)
// pass a change handler lambda that is not the value.
fn lazy_delegate_value<'a>(
  delegate: Node<'a>,
  source: &[u8],
) -> Option<Node<'a>> {
  let mut cursor = delegate.walk();
  let call = delegate
    .children(&mut cursor)
    .find(|c| c.kind() == "call_expression")?;

  if call_head_identifier(call, source).as_deref() != Some("lazy") {
    return None;
  }

  let mut call_cursor = call.walk();
  let lambda = call
    .children(&mut call_cursor)
    .find(|c| c.kind() == "annotated_lambda")?;

  let mut lambda_cursor = lambda.walk();
  let body = lambda
    .children(&mut lambda_cursor)
    .find(|c| c.kind() == "lambda_literal")?;

  let mut body_cursor = body.walk();
  body
    .children(&mut body_cursor)
    .filter(|c| is_value_expression(c.kind()))
    .last()
}

fn call_head_identifier(call: Node, source: &[u8]) -> Option<String> {
  let mut cursor = call.walk();
  let head = call.children(&mut cursor).find(Node::is_named)?;
  match head.kind() {
    "identifier" => head.utf8_text(source).ok().map(str::to_owned),
    "call_expression" => call_head_identifier(head, source),
    _ => None,
  }
}

// Primary-constructor parameters, including `val`/`var` properties of data and
// regular classes: `data class C(val apiKey: String = "...")`.
fn process_class_parameter(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let assignment_type = class_parameter_type(node);
  let Some(name) = variable_name(node, source) else {
    return;
  };

  let mut cursor = node.walk();
  let value = node
    .children(&mut cursor)
    .filter(|c| c.is_named())
    .last()
    .filter(|c| is_value_expression(c.kind()));

  if let Some(value) = value {
    check_value_node(ctx, Some(&name), value, assignment_type, source);
  }
}

fn class_parameter_type(node: Node) -> AssignmentType {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "var" => return AssignmentType::Variable,
      "val" => return AssignmentType::Constant,
      _ => {}
    }
  }
  AssignmentType::Parameter
}

fn process_enum_entries(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let Some(body) = child_of_kind(node, "enum_class_body") else {
    return;
  };
  let parameter_names = primary_constructor_params(node, source);
  if parameter_names.is_empty() {
    return;
  }

  let mut cursor = body.walk();
  for entry in body
    .children(&mut cursor)
    .filter(|c| c.kind() == "enum_entry")
  {
    let Some(args) = child_of_kind(entry, "value_arguments") else {
      continue;
    };
    for (index, arg) in positional_args(args, source).iter().enumerate() {
      if let Some(name) = parameter_names.get(index) {
        check_value_node(
          ctx,
          Some(name),
          *arg,
          AssignmentType::Argument,
          source,
        );
      }
    }
  }
}

fn primary_constructor_params(node: Node, source: &[u8]) -> Vec<String> {
  let Some(constructor) = child_of_kind(node, "primary_constructor") else {
    return Vec::new();
  };
  let Some(params) = child_of_kind(constructor, "class_parameters") else {
    return Vec::new();
  };

  let mut names = Vec::new();
  let mut cursor = params.walk();
  for param in params
    .children(&mut cursor)
    .filter(|c| c.kind() == "class_parameter")
  {
    if let Some(name) = variable_name(param, source) {
      names.push(name);
    }
  }
  names
}

fn child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  node.children(&mut cursor).find(|c| c.kind() == kind)
}

// -----------------------------------------------------------------------------
// Function declarations: register free-function signatures, default params
// -----------------------------------------------------------------------------

fn register_signature(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
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

  let Some(params) = function_parameters(node) else {
    return;
  };

  let mut parameter_names = Vec::new();
  let mut cursor = params.walk();
  for child in params.children(&mut cursor) {
    if child.kind() == "parameter"
      && let Some(param) = variable_name(child, source)
    {
      parameter_names.push(param);
    }
  }

  ctx.free_signatures.insert(name, parameter_names);
}

fn process_default_params(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let Some(params) = function_parameters(node) else {
    return;
  };

  let mut pending_name: Option<String> = None;
  let mut cursor = params.walk();
  for child in params.children(&mut cursor) {
    if child.kind() == "parameter" {
      pending_name = variable_name(child, source);
    } else if child.is_named()
      && let Some(name) = pending_name.take()
    {
      check_value_node(
        ctx,
        Some(&name),
        child,
        AssignmentType::Parameter,
        source,
      );
    }
  }
}

fn function_parameters(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|c| c.kind() == "function_value_parameters")
}

fn is_method(node: Node) -> bool {
  let mut current = node.parent();
  while let Some(n) = current {
    match n.kind() {
      "class_body" | "enum_class_body" => return true,
      "function_body" | "source_file" => return false,
      _ => current = n.parent(),
    }
  }
  false
}

// -----------------------------------------------------------------------------
// Calls: header setters, then free-function signature resolution
// -----------------------------------------------------------------------------

fn process_call(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let Some((callee, is_free)) = call_callee(node, source) else {
    return;
  };
  let Some(args_node) = call_value_arguments(node) else {
    return;
  };

  let args = positional_args(args_node, source);

  if HEADER_SETTERS.contains(&callee.as_str()) && args.len() >= 2 {
    if let (Some(name), Some(value)) = (
      extract_string(args[0], source),
      extract_string(args[1], source),
    ) {
      emit_header(ctx, &name, &value, args[1]);
    }
    return;
  }

  if callee == "bearerAuth"
    && let Some(first) = args.first()
    && let Some(value) = extract_string(*first, source)
  {
    emit_header(ctx, "Authorization", &value, *first);
    return;
  }

  if callee == "basicAuth"
    && args.len() >= 2
    && let Some(value) = extract_string(args[1], source)
  {
    emit_header(ctx, "Authorization", &value, args[1]);
    return;
  }

  if callee == "buildConfigField" && args.len() == 3 {
    if let (Some(field_name), Some(raw)) = (
      extract_string(args[1], source),
      extract_string(args[2], source),
    ) {
      emit_secret(
        ctx,
        Some(&field_name),
        strip_build_config_quotes(&raw),
        args[2],
        AssignmentType::Constant,
      );
    }
    return;
  }

  if is_free {
    let arguments: Vec<(usize, String, (usize, usize))> = args
      .iter()
      .enumerate()
      .filter_map(|(i, arg)| {
        extract_string(*arg, source)
          .map(|v| (i, v, (arg.start_byte(), arg.end_byte())))
      })
      .collect();
    if !arguments.is_empty() {
      ctx.pending_calls.push(PendingCall { callee, arguments });
    }
  }
}

fn call_callee(node: Node, source: &[u8]) -> Option<(String, bool)> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "identifier" => {
        return child.utf8_text(source).ok().map(|n| (n.to_owned(), true));
      }
      "navigation_expression" => {
        return navigation_method(child, source).map(|n| (n, false));
      }
      "value_arguments" | "call_suffix" => break,
      _ => {}
    }
  }
  None
}

fn navigation_method(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .filter(|c| c.kind() == "identifier")
    .last()
    .and_then(|c| c.utf8_text(source).ok())
    .map(str::to_owned)
}

fn call_value_arguments(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|c| c.kind() == "value_arguments")
}

fn positional_args<'a>(args_node: Node<'a>, source: &[u8]) -> Vec<Node<'a>> {
  let mut result = Vec::new();
  let mut cursor = args_node.walk();
  for arg in args_node.children(&mut cursor) {
    if arg.kind() != "value_argument" || named_argument(arg, source).is_some() {
      continue;
    }
    let mut inner = arg.walk();
    if let Some(value) = arg.children(&mut inner).find(|c| c.is_named()) {
      result.push(value);
    }
  }
  result
}

fn named_argument<'a>(
  arg: Node<'a>,
  source: &[u8],
) -> Option<(String, Node<'a>)> {
  let mut cursor = arg.walk();
  let named: Vec<Node> =
    arg.children(&mut cursor).filter(Node::is_named).collect();
  if named.len() == 2 && named[0].kind() == "identifier" {
    let name = named[0].utf8_text(source).ok()?.to_owned();
    return Some((name, named[1]));
  }
  None
}

fn emit_header(
  ctx: &mut KotlinContext,
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

// -----------------------------------------------------------------------------
// Retrofit `@Headers("Name: Value")` static headers
// -----------------------------------------------------------------------------

fn process_annotation(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  let Some(invocation) = node
    .children(&mut cursor)
    .find(|c| c.kind() == "constructor_invocation")
  else {
    return;
  };

  if annotation_name(invocation, source).as_deref() != Some("Headers") {
    return;
  }

  let Some(args) = call_value_arguments(invocation) else {
    return;
  };

  for value_node in positional_args(args, source) {
    let Some(line) = extract_string(value_node, source) else {
      continue;
    };
    let Some((name, value)) = line.split_once(':') else {
      continue;
    };
    emit_header(ctx, name.trim(), value.trim(), value_node);
  }
}

fn annotation_name(invocation: Node, source: &[u8]) -> Option<String> {
  let mut cursor = invocation.walk();
  let user_type = invocation
    .children(&mut cursor)
    .find(|c| c.kind() == "user_type")?;

  let mut inner = user_type.walk();
  user_type
    .children(&mut inner)
    .filter(|c| c.kind() == "identifier")
    .last()
    .and_then(|c| c.utf8_text(source).ok())
    .map(str::to_owned)
}

fn resolve_pending_calls(ctx: &mut KotlinContext) {
  let calls = std::mem::take(&mut ctx.pending_calls);
  for call in calls {
    if let Some(parameter_names) =
      ctx.free_signatures.get(&call.callee).cloned()
    {
      for (index, value, (start, end)) in &call.arguments {
        let Some(param_name) = parameter_names.get(*index) else {
          continue;
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
  }
}

// -----------------------------------------------------------------------------
// Named arguments, map entries, reassignment
// -----------------------------------------------------------------------------

fn process_value_argument(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  if let Some((name, value)) = named_argument(node, source) {
    check_value_node(ctx, Some(&name), value, AssignmentType::Argument, source);
  }
}

fn process_infix(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  let parts: Vec<Node> =
    node.children(&mut cursor).filter(Node::is_named).collect();
  if parts.len() == 3
    && parts[1].kind() == "identifier"
    && parts[1].utf8_text(source).ok() == Some("to")
    && let Some(key) = extract_string(parts[0], source)
  {
    check_value_node(
      ctx,
      Some(&key),
      parts[2],
      AssignmentType::Element,
      source,
    );
  }
}

fn process_assignment(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  let Some(left) = node.child_by_field_name("left") else {
    return;
  };
  let Some(right) = node.child_by_field_name("right") else {
    return;
  };

  if left.kind() == "index_expression" {
    if let Some(key) = index_key(left, source) {
      check_value_node(ctx, Some(&key), right, AssignmentType::Element, source);
    }
    return;
  }

  let Some(name) = assignee_name(left, source) else {
    return;
  };

  check_value_node(ctx, Some(&name), right, AssignmentType::Variable, source);
}

fn assignee_name(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" => node.utf8_text(source).ok().map(str::to_owned),
    "navigation_expression" => navigation_method(node, source),
    _ => None,
  }
}

fn index_key(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  let string = node
    .children(&mut cursor)
    .find(|c| c.kind() == "string_literal")?;
  extract_string(string, source)
}

// -----------------------------------------------------------------------------
// Value checking
// -----------------------------------------------------------------------------

fn process_value_only(ctx: &mut KotlinContext, node: Node, source: &[u8]) {
  check_value_node(ctx, None, node, AssignmentType::Variable, source);
}

fn emit_secret(
  ctx: &mut KotlinContext,
  name: Option<&str>,
  value: &str,
  value_node: Node,
  assignment_type: AssignmentType,
) {
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
}

fn check_value_node(
  ctx: &mut KotlinContext,
  name: Option<&str>,
  value_node: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  if let Some(value) = extract_string(value_node, source) {
    emit_secret(ctx, name, &value, value_node, assignment_type);
    return;
  }

  match value_node.kind() {
    "if_expression" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor) {
        if child.is_named()
          && value_node.child_by_field_name("condition") != Some(child)
        {
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
    "when_expression" => {
      let mut cursor = value_node.walk();
      for entry in value_node.children(&mut cursor) {
        if entry.kind() != "when_entry" {
          continue;
        }

        let condition = entry.child_by_field_name("condition");
        let mut inner = entry.walk();
        for child in entry.children(&mut inner) {
          if child.is_named() && Some(child) != condition {
            check_value_node(ctx, name, child, assignment_type, source);
          }
        }
      }
    }
    // listOf("a", "b") and friends: each element inherits the assignment name.
    "call_expression"
      if call_head_identifier(value_node, source)
        .as_deref()
        .is_some_and(is_collection_builder) =>
    {
      if let Some(args) = call_value_arguments(value_node) {
        for arg in positional_args(args, source) {
          check_value_node(ctx, name, arg, assignment_type, source);
        }
      }
    }
    _ => {}
  }
}

fn is_collection_builder(name: &str) -> bool {
  matches!(
    name,
    "listOf"
      | "arrayOf"
      | "setOf"
      | "mutableListOf"
      | "mutableSetOf"
      | "listOfNotNull"
      | "arrayListOf"
      | "sortedSetOf"
      | "hashSetOf"
      | "linkedSetOf"
  )
}

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "string_literal" | "multiline_string_literal" => {
      let mut result = String::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        match child.kind() {
          "string_content" => {
            let text = child.utf8_text(source).ok()?;
            if text == "$" {
              return None;
            }
            result.push_str(text);
          }
          "escape_sequence" => result.push_str(child.utf8_text(source).ok()?),
          "interpolation" => return None,
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

fn compute_span(ctx: &KotlinContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
