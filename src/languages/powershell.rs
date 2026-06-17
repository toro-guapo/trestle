use std::cell::RefCell;
use std::collections::HashMap;

use tree_sitter::Node;

use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, SourceFileSpan, SourceSpan, check_assignment,
    check_value, offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_powershell::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
}

struct PendingCall {
  callee: String,
  named_used: Vec<String>,
  positional: Vec<(usize, String, (usize, usize))>,
}

struct PowerShellContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
  free_signatures: HashMap<String, Vec<String>>,
  pending_calls: Vec<PendingCall>,
}

impl PowerShellContext<'_> {
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

  let mut ctx = PowerShellContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
    free_signatures: HashMap::new(),
    pending_calls: Vec::new(),
  };

  process_node(&mut ctx, tree.root_node(), source.as_bytes());
  resolve_pending_calls(&mut ctx);

  true
}

fn process_node(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  match node.kind() {
    "function_statement" => register_signature(ctx, node, source),
    "assignment_expression" => process_assignment(ctx, node, source),
    "hash_entry" => process_hash_entry(ctx, node, source),
    "command" => process_command(ctx, node, source),
    "script_parameter" => process_parameter(ctx, node, source),
    "expandable_string_literal"
    | "verbatim_string_characters"
    | "expandable_here_string_literal"
    | "verbatim_here_string_characters" => {
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
// Variable assignment: `$password = "..."`, `$env:API_KEY = "..."`
// -----------------------------------------------------------------------------

fn process_assignment(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  let Some(left) = child_of_kind(node, "left_assignment_expression") else {
    return;
  };
  let Some(value) = node.child_by_field_name("value") else {
    return;
  };
  let Some((name, assignment_type)) = assignment_target(left, source) else {
    return;
  };

  if let Some(leaf) = string_node(value) {
    check_value_node(ctx, Some(&name), leaf, assignment_type, source);
  } else if is_array_value(value) {
    // `$apiKeys = @("a", "b")` / `"a", "b"`: elements inherit the name.
    let mut leaves = Vec::new();
    collect_array_strings(value, &mut leaves);
    for leaf in leaves {
      check_value_node(ctx, Some(&name), leaf, assignment_type, source);
    }
  }
}

fn is_array_value(node: Node) -> bool {
  match node.kind() {
    "array_expression" => true,
    "array_literal_expression" if node.named_child_count() >= 2 => true,
    _ if node.named_child_count() == 1 => {
      node.named_child(0).is_some_and(is_array_value)
    }
    _ => false,
  }
}

fn collect_array_strings<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
  match node.kind() {
    "expandable_string_literal"
    | "verbatim_string_characters"
    | "expandable_here_string_literal"
    | "verbatim_here_string_characters" => out.push(node),
    // Nested data structures carry their own names; don't reattribute them.
    "hash_literal_expression" | "script_block_expression" => {}
    _ => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        collect_array_strings(child, out);
      }
    }
  }
}

fn assignment_target(
  left: Node,
  source: &[u8],
) -> Option<(String, AssignmentType)> {
  if let Some(element) = first_descendant(left, "element_access")
    && let Some(key) =
      first_string(element).and_then(|n| extract_string(n, source))
  {
    return Some((key, AssignmentType::Element));
  }

  if let Some(member) = first_descendant(left, "member_access")
    && let Some(name) = member_target(member, source)
  {
    return Some((name, AssignmentType::Property));
  }

  let variable = first_descendant(left, "variable")?;
  variable_name(variable, source)
}

fn member_target(member: Node, source: &[u8]) -> Option<String> {
  let member_name = child_of_kind(member, "member_name")?;
  first_descendant(member_name, "simple_name")
    .and_then(|n| n.utf8_text(source).ok())
    .map(str::to_owned)
}

fn first_string(node: Node) -> Option<Node> {
  match node.kind() {
    "expandable_string_literal"
    | "verbatim_string_characters"
    | "expandable_here_string_literal"
    | "verbatim_here_string_characters" => Some(node),
    _ => {
      let mut cursor = node.walk();
      node.children(&mut cursor).find_map(first_string)
    }
  }
}

fn variable_name(
  node: Node,
  source: &[u8],
) -> Option<(String, AssignmentType)> {
  let text = node.utf8_text(source).ok()?;
  let bare = text
    .strip_prefix('$')?
    .trim_matches(|c| c == '{' || c == '}');

  if let Some((scope, rest)) = bare.split_once(':') {
    let scope = scope.to_ascii_lowercase();
    if scope == "env" {
      return Some((rest.to_owned(), AssignmentType::EnvironmentVariable));
    }
    if matches!(
      scope.as_str(),
      "script" | "global" | "local" | "private" | "using" | "variable"
    ) {
      return Some((rest.to_owned(), AssignmentType::Variable));
    }
  }

  Some((bare.to_owned(), AssignmentType::Variable))
}

// -----------------------------------------------------------------------------
// Hashtable entries: `@{ Password = "..."; ApiKey = "..." }`
// -----------------------------------------------------------------------------

fn process_hash_entry(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  let children: Vec<Node> =
    node.children(&mut cursor).filter(Node::is_named).collect();
  let (Some(key_node), Some(value_node)) = (children.first(), children.last())
  else {
    return;
  };

  let Some(key) = hash_key(*key_node, source) else {
    return;
  };
  if let Some(leaf) = string_node(*value_node) {
    check_value_node(ctx, Some(&key), leaf, AssignmentType::Element, source);
  }
}

fn hash_key(node: Node, source: &[u8]) -> Option<String> {
  if let Some(leaf) = string_node(node) {
    return extract_string(leaf, source);
  }
  first_descendant(node, "simple_name")
    .and_then(|n| n.utf8_text(source).ok())
    .map(str::to_owned)
}

// -----------------------------------------------------------------------------
// Commands: named parameters (`-Password "..."`) and ConvertTo-SecureString
// `-AsPlainText`.
// -----------------------------------------------------------------------------

fn process_command(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  let Some(elements) = node.child_by_field_name("command_elements") else {
    return;
  };

  let command = node
    .child_by_field_name("command_name")
    .and_then(|n| n.utf8_text(source).ok())
    .map(str::to_ascii_lowercase)
    .unwrap_or_default();

  if command.ends_with("convertto-securestring")
    && has_parameter(elements, "asplaintext", source)
  {
    let mut cursor = elements.walk();
    for child in elements.children(&mut cursor) {
      if let Some(leaf) = string_node(child) {
        check_value_node(
          ctx,
          Some("password"),
          leaf,
          AssignmentType::Variable,
          source,
        );
      }
    }
    return;
  }

  let mut pending: Option<String> = None;
  let mut named_used: Vec<String> = Vec::new();
  let mut positional: Vec<(usize, String, (usize, usize))> = Vec::new();
  let mut slot = 0;

  let mut cursor = elements.walk();
  for child in elements.children(&mut cursor) {
    match child.kind() {
      "command_parameter" => pending = parameter_name(child, source),
      "command_argument_sep" => {}
      _ => {
        if let Some(name) = pending.take() {
          if let Some(leaf) = string_node(child) {
            check_value_node(
              ctx,
              Some(&name),
              leaf,
              AssignmentType::Argument,
              source,
            );
          }
          named_used.push(name.to_ascii_lowercase());
        } else {
          if let Some(value) =
            string_node(child).and_then(|leaf| extract_string(leaf, source))
          {
            let leaf = string_node(child).unwrap_or(child);
            positional.push((
              slot,
              value,
              (leaf.start_byte(), leaf.end_byte()),
            ));
          }
          slot += 1;
        }
      }
    }
  }

  if !positional.is_empty() {
    ctx.pending_calls.push(PendingCall {
      callee: command,
      named_used,
      positional,
    });
  }
}

fn parameter_name(node: Node, source: &[u8]) -> Option<String> {
  let text = node.utf8_text(source).ok()?;
  let name = text
    .trim_start_matches('-')
    .trim_end_matches(':')
    .to_owned();
  (!name.is_empty()).then_some(name)
}

fn has_parameter(elements: Node, name: &str, source: &[u8]) -> bool {
  let mut cursor = elements.walk();
  elements
    .children(&mut cursor)
    .filter(|c| c.kind() == "command_parameter")
    .filter_map(|c| parameter_name(c, source))
    .any(|p| p.eq_ignore_ascii_case(name))
}

fn register_signature(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  let Some(name) = child_of_kind(node, "function_name")
    .and_then(|n| n.utf8_text(source).ok())
    .map(str::to_ascii_lowercase)
  else {
    return;
  };

  let names = function_parameter_names(node, source);
  if !names.is_empty() {
    ctx.free_signatures.insert(name, names);
  }
}

fn function_parameter_names(node: Node, source: &[u8]) -> Vec<String> {
  let container = child_of_kind(node, "function_parameter_declaration")
    .or_else(|| {
      child_of_kind(node, "script_block")
        .and_then(|block| child_of_kind(block, "param_block"))
    });
  let Some(list) = container.and_then(|c| child_of_kind(c, "parameter_list"))
  else {
    return Vec::new();
  };

  let mut names = Vec::new();
  let mut cursor = list.walk();
  for param in list
    .children(&mut cursor)
    .filter(|c| c.kind() == "script_parameter")
  {
    if let Some((name, _)) =
      child_of_kind(param, "variable").and_then(|v| variable_name(v, source))
    {
      names.push(name);
    }
  }
  names
}

fn resolve_pending_calls(ctx: &mut PowerShellContext) {
  let calls = std::mem::take(&mut ctx.pending_calls);
  for call in calls {
    let Some(params) = ctx.free_signatures.get(&call.callee).cloned() else {
      continue;
    };
    let available: Vec<String> = params
      .into_iter()
      .filter(|p| !call.named_used.contains(&p.to_ascii_lowercase()))
      .collect();

    for (index, value, (start, end)) in &call.positional {
      let Some(param_name) = available.get(*index) else {
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

// -----------------------------------------------------------------------------
// Parameter defaults: `param([string]$Password = "...")`
// -----------------------------------------------------------------------------

fn process_parameter(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  // Direct children only: the parameter's own `$name`, not a `$_` buried in a
  // `[ValidateScript({ $_ ... })]` attribute.
  let Some(variable) = child_of_kind(node, "variable") else {
    return;
  };
  let Some((name, _)) = variable_name(variable, source) else {
    return;
  };

  let Some(default) = child_of_kind(node, "script_parameter_default") else {
    return;
  };
  if let Some(leaf) = string_node(default) {
    check_value_node(ctx, Some(&name), leaf, AssignmentType::Parameter, source);
  }
}

fn child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  node.children(&mut cursor).find(|c| c.kind() == kind)
}

// -----------------------------------------------------------------------------
// Value checking
// -----------------------------------------------------------------------------

fn process_value_only(ctx: &mut PowerShellContext, node: Node, source: &[u8]) {
  check_value_node(ctx, None, node, AssignmentType::Variable, source);
}

fn check_value_node(
  ctx: &mut PowerShellContext,
  name: Option<&str>,
  leaf: Node,
  assignment_type: AssignmentType,
  source: &[u8],
) {
  let Some(value) = extract_string(leaf, source) else {
    return;
  };

  let start = leaf.start_byte();
  let end = leaf.end_byte();
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
      || compute_span(ctx, leaf),
    ),
    None => {
      check_value(&normalized, ctx.source_context, || compute_span(ctx, leaf))
    }
  };

  if let Some(d) = diag {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}

fn string_node(node: Node) -> Option<Node> {
  match node.kind() {
    "expandable_string_literal"
    | "verbatim_string_characters"
    | "expandable_here_string_literal"
    | "verbatim_here_string_characters" => Some(node),
    "array_expression" | "sub_expression" | "script_block_expression" => None,
    _ if node.named_child_count() == 1 => string_node(node.named_child(0)?),
    _ => None,
  }
}

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  let text = node.utf8_text(source).ok()?;
  let inner = match node.kind() {
    "expandable_string_literal" | "expandable_here_string_literal"
      if node.named_child_count() > 0 =>
    {
      return None;
    }
    "expandable_string_literal" | "verbatim_string_characters" => {
      text.get(1..text.len().checked_sub(1)?)?
    }
    "expandable_here_string_literal" | "verbatim_here_string_characters" => {
      text
        .get(2..text.len().checked_sub(2)?)?
        .trim_matches(|c| c == '\n' || c == '\r')
    }
    _ => return None,
  };

  Some(inner.to_owned())
}

fn first_descendant<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  if node.kind() == kind {
    return Some(node);
  }
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if let Some(found) = first_descendant(child, kind) {
      return Some(found);
    }
  }
  None
}

fn compute_span(ctx: &PowerShellContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
