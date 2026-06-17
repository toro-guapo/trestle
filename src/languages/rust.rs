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
    if parser.set_language(&tree_sitter_rust::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
  static ANALYZER: RefCell<Analyzer<String, (usize, usize)>> =
    RefCell::new(Analyzer::new());
}

struct RustContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> RustContext<'a> {
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

  let mut ctx = RustContext {
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

fn process_node(ctx: &mut RustContext, node: Node, source: &[u8]) {
  match node.kind() {
    "let_declaration" => process_let(ctx, node, source),
    "let_condition" => process_let_condition(ctx, node, source),
    "const_item" => process_const_item(ctx, node, source),
    "static_item" => process_static_item(ctx, node, source),
    "assignment_expression" => process_assignment(ctx, node, source),
    "compound_assignment_expr" => {
      process_compound_assignment(ctx, node, source)
    }
    "call_expression" => process_call(ctx, node, source),
    "macro_invocation" => process_macro(ctx, node, source),
    "field_initializer" => process_field_initializer(ctx, node, source),
    "tuple_expression" => process_tuple_expression(ctx, node, source),
    "function_item" => register_signature(node, source),
    "attribute_item" | "inner_attribute_item" => {
      process_attribute_item(ctx, node, source);
    }
    "string_literal" | "raw_string_literal" => {
      process_string_literal_value_only(ctx, node, source);
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

fn process_string_literal_value_only(
  ctx: &mut RustContext,
  node: Node,
  source: &[u8],
) {
  let start = node.start_byte();
  let end = node.end_byte();
  if ctx.already_emitted(start, end) {
    return;
  }
  let Some(value) = extract_string(node, source) else {
    return;
  };

  let normalized = normalize_value(&value);
  if let Some(d) =
    check_value(&normalized, ctx.source_context, || compute_span(ctx, node))
  {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}

// -----------------------------------------------------------------------------
// let declarations
//
// `let x = "..."`, `let mut x = "..."`, `let x: T = "..."`,
// `let (a, b) = ("...", "...")`, `let Some(x) = ... else { ... }`.
// -----------------------------------------------------------------------------

fn process_let(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let Some(pattern) = node.child_by_field_name("pattern") else {
    return;
  };
  let Some(value) = node.child_by_field_name("value") else {
    return;
  };

  process_pattern_value(ctx, pattern, value, source, AssignmentType::Variable);
}

fn process_let_condition(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let Some(pattern) = node.child_by_field_name("pattern") else {
    return;
  };
  let Some(value) = node.child_by_field_name("value") else {
    return;
  };

  process_pattern_value(ctx, pattern, value, source, AssignmentType::Variable);
}

fn process_pattern_value(
  ctx: &mut RustContext,
  pattern: Node,
  value: Node,
  source: &[u8],
  assignment_type: AssignmentType,
) {
  match pattern.kind() {
    "identifier" => {
      let Some(name) = node_text(pattern, source) else {
        check_expression_value(
          ctx,
          None,
          value,
          value,
          source,
          assignment_type,
        );
        return;
      };
      check_expression_value(
        ctx,
        Some(&name),
        value,
        value,
        source,
        assignment_type,
      );
    }
    "mut_pattern" | "ref_pattern" => {
      if let Some(inner) = first_named_child(pattern) {
        process_pattern_value(ctx, inner, value, source, assignment_type);
      } else {
        check_expression_value(
          ctx,
          None,
          value,
          value,
          source,
          assignment_type,
        );
      }
    }
    "tuple_pattern" => {
      let names = named_children(pattern);
      let values_node_kind = value.kind();

      if values_node_kind == "tuple_expression" {
        let values = named_children(value);
        for (name_pattern, value_node) in names.iter().zip(values.iter()) {
          process_pattern_value(
            ctx,
            *name_pattern,
            *value_node,
            source,
            assignment_type,
          );
        }
      } else {
        check_expression_value(
          ctx,
          None,
          value,
          value,
          source,
          assignment_type,
        );
      }
    }
    _ => {
      check_expression_value(ctx, None, value, value, source, assignment_type);
    }
  }
}

// -----------------------------------------------------------------------------
// const / static items
//
// `const NAME: T = "..."`, `static NAME: T = "..."`, `static mut NAME: T = ...`.
// -----------------------------------------------------------------------------

fn process_const_item(ctx: &mut RustContext, node: Node, source: &[u8]) {
  process_named_item(ctx, node, source, AssignmentType::Constant);
}

fn process_static_item(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  let mut is_mut = false;

  for child in node.children(&mut cursor) {
    if child.kind() == "mutable_specifier" {
      is_mut = true;
      break;
    }
  }

  let assignment_type = if is_mut {
    AssignmentType::Variable
  } else {
    AssignmentType::Constant
  };

  process_named_item(ctx, node, source, assignment_type);
}

fn process_named_item(
  ctx: &mut RustContext,
  node: Node,
  source: &[u8],
  assignment_type: AssignmentType,
) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("value") else {
    return;
  };
  let Some(name) = node_text(name_node, source) else {
    return;
  };

  check_expression_value(
    ctx,
    Some(&name),
    value_node,
    value_node,
    source,
    assignment_type,
  );
}

// -----------------------------------------------------------------------------
// Reassignment: `x = "..."`, `self.password = "..."`,
// `config.api_key = "..."`, `map["key"] = "..."`.
// -----------------------------------------------------------------------------

fn process_assignment(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let Some(left) = node.child_by_field_name("left") else {
    return;
  };
  let Some(right) = node.child_by_field_name("right") else {
    return;
  };

  let name = extract_assignee_name(left, source);
  check_expression_value(
    ctx,
    name.as_deref(),
    right,
    right,
    source,
    AssignmentType::Variable,
  );
}

fn process_compound_assignment(
  ctx: &mut RustContext,
  node: Node,
  source: &[u8],
) {
  let Some(left) = node.child_by_field_name("left") else {
    return;
  };
  let Some(right) = node.child_by_field_name("right") else {
    return;
  };

  let name = extract_assignee_name(left, source);
  check_expression_value(
    ctx,
    name.as_deref(),
    right,
    right,
    source,
    AssignmentType::Variable,
  );
}

fn extract_assignee_name(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" => node_text(node, source),
    // `self.x`, `obj.field`, `obj.field.nested` - take the rightmost field.
    "field_expression" => {
      let field = node.child_by_field_name("field")?;
      node_text(field, source)
    }
    // `map["key"] = ...` - the bracket index, when string.
    "index_expression" => {
      let mut cursor = node.walk();
      let named: Vec<Node> = node
        .children(&mut cursor)
        .filter(|n| n.is_named())
        .collect();
      let index = named.get(1).copied()?;
      extract_string(index, source)
    }
    // `*ptr = ...` - dereference, take inner name.
    "unary_expression" => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if child.is_named() {
          return extract_assignee_name(child, source);
        }
      }
      None
    }
    // `(x) = ...` - parens around assignee.
    "parenthesized_expression" => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if child.is_named() {
          return extract_assignee_name(child, source);
        }
      }
      None
    }
    "scoped_identifier" => {
      let name = node.child_by_field_name("name")?;
      node_text(name, source)
    }
    _ => None,
  }
}

// -----------------------------------------------------------------------------
// Struct expression fields: `Foo { password: "..." }`
// -----------------------------------------------------------------------------

fn process_field_initializer(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let Some(field) = node.child_by_field_name("field") else {
    return;
  };
  let Some(value) = node.child_by_field_name("value") else {
    return;
  };
  let Some(name) = node_text(field, source) else {
    return;
  };

  check_expression_value(
    ctx,
    Some(&name),
    value,
    value,
    source,
    AssignmentType::Property,
  );
}

// -----------------------------------------------------------------------------
// Tuple expressions as key-value pairs
// -----------------------------------------------------------------------------

fn process_tuple_expression(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let named = named_children(node);
  if named.len() != 2 {
    return;
  }
  let Some(key) = extract_string(named[0], source) else {
    return;
  };

  check_expression_value(
    ctx,
    Some(&key),
    named[1],
    named[1],
    source,
    AssignmentType::Property,
  );
}

// -----------------------------------------------------------------------------
// Function / method calls
// -----------------------------------------------------------------------------

const HEADER_SETTERS: &[&str] =
  &["add_header", "addheader", "header", "set_header"];

const NAME_VALUE_SETTERS: &[&str] =
  &["insert", "put", "set", "set_var", "setdefault", "setenv"];

fn process_call(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let Some(func_node) = node.child_by_field_name("function") else {
    return;
  };
  let Some(args_node) = node.child_by_field_name("arguments") else {
    return;
  };

  let args = named_children(args_node);

  let last_segment = call_last_segment(func_node, source);

  // Pattern 1: `Map::insert(...)`, `env::set_var(...)`, `client.put(...)`,
  // etc. The first arg is a string key, the second is the value.
  let setter_type = last_segment.as_deref().and_then(|name| {
    if HEADER_SETTERS.contains(&name) {
      Some(AssignmentType::Header)
    } else if NAME_VALUE_SETTERS.contains(&name) {
      Some(AssignmentType::Argument)
    } else {
      None
    }
  });

  if let Some(setter_type) = setter_type
    && args.len() >= 2
    && let Some(key) = extract_string(args[0], source)
  {
    check_expression_value(
      ctx,
      Some(&key),
      args[1],
      args[1],
      source,
      setter_type,
    );
    return;
  }

  // Pattern 2: method call with the receiver carrying meaning. For a
  // call like `client.set_password("secret")`, the field_identifier
  // (`set_password`) becomes the key. Only fire when:
  // - the function is a `field_expression` (i.e. method call), and
  // - there's exactly one argument.
  if let Some(method_name) =
    method_name_for_setter(func_node, source).filter(|_| args.len() == 1)
  {
    check_expression_value(
      ctx,
      Some(&method_name),
      args[0],
      args[0],
      source,
      AssignmentType::Argument,
    );
  }

  // Pattern 3: nameless value-only scan for every argument.
  for arg in &args {
    check_expression_value(
      ctx,
      None,
      *arg,
      *arg,
      source,
      AssignmentType::Argument,
    );
  }

  // Pattern 4: signature resolution. If we know the callee's parameter
  // names, pair each positional string arg with its parameter. A method
  // call on a value (`receiver.method(...)`) has an unknown receiver type.
  if is_method_call(func_node) {
    return;
  }

  let callee = match &last_segment {
    Some(name) => name.clone(),
    None => match node_text(func_node, source) {
      Some(s) => s,
      None => return,
    },
  };

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
    if let Some(signature) = analyzer.get_signature(&callee) {
      resolve_arguments(ctx, signature, &extracted);
      true
    } else {
      false
    }
  });

  if !resolved {
    ANALYZER.with(|a| {
      a.borrow_mut().add_frame(CallFrame {
        callee,
        arguments: extracted,
      });
    });
  }
}

fn call_last_segment(func: Node, source: &[u8]) -> Option<String> {
  match func.kind() {
    "identifier" => node_text(func, source),
    "field_expression" => {
      let field = func.child_by_field_name("field")?;
      node_text(field, source)
    }
    "scoped_identifier" => {
      let name = func.child_by_field_name("name")?;
      node_text(name, source)
    }
    "generic_function" => {
      let function = func.child_by_field_name("function")?;
      call_last_segment(function, source)
    }
    _ => None,
  }
}

fn method_name_for_setter(func: Node, source: &[u8]) -> Option<String> {
  if func.kind() != "field_expression" {
    return None;
  }
  let field = func.child_by_field_name("field")?;
  node_text(field, source)
}

fn is_method_call(func: Node) -> bool {
  match func.kind() {
    "field_expression" => true,
    "generic_function" => func
      .child_by_field_name("function")
      .is_some_and(is_method_call),
    _ => false,
  }
}

fn resolve_arguments(
  ctx: &mut RustContext,
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

    let name = param_name.to_owned();
    let value = value.to_owned();
    if let Some(d) = check_assignment(
      &normalize_name(&name),
      &normalize_value(&value),
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
// Macro invocations
// -----------------------------------------------------------------------------

fn process_macro(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let macro_name = node
    .child_by_field_name("macro")
    .and_then(|n| call_last_segment(n, source));

  let Some(token_tree) = find_child(node, "token_tree") else {
    return;
  };

  // `vec![("k1", "v1"), ("k2", "v2")]`, `hashmap!{ "k" => "v" }`, etc.
  process_token_tree_pairs(ctx, token_tree, source);

  // `format!("template", args...)`
  let _ = macro_name;
}

fn process_token_tree_pairs(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  let children: Vec<Node> = node.children(&mut cursor).collect();

  let mut i = 0;
  while i < children.len() {
    let child = children[i];

    if let Some(name) = token_to_name(child, source) {
      // Pattern 1: `name : type = value` - lazy_static!/thread_local!/
      // similar declarations. Skip the `: type` annotation so we
      // attribute the value to the actual binding name.
      if let Some(advance) =
        try_name_type_value(ctx, &name, &children, i, source)
      {
        i += advance;
        continue;
      }

      // Pattern 2: `name = value`, `name : value`, `name => value` -
      // simple two-token separator forms.
      if let Some(sep) = children.get(i + 1) {
        let sep_kind = sep.kind();
        let is_eq_or_colon = !sep.is_named() && matches!(sep_kind, "=" | ":");
        let is_fat_arrow = !sep.is_named() && sep_kind == "=>";
        if (is_eq_or_colon || is_fat_arrow)
          && let Some(value_node) = children.get(i + 2)
          && value_node.is_named()
        {
          check_expression_value(
            ctx,
            Some(&name),
            *value_node,
            *value_node,
            source,
            AssignmentType::Argument,
          );
          i += 3;
          continue;
        }
      }
    }

    if child.kind() == "token_tree" {
      process_token_tree_as_tuple(ctx, child, source);
    }

    i += 1;
  }
}

/// Recognizes `name : <type-tokens> = <value>` inside a macro token
/// stream. Type tokens may span multiple nodes (e.g. `Vec < String >`),
/// so we scan forward looking for a top-level `=` and grab the next
/// named child after it. Returns how many positions to advance past the
/// matched pattern (so the outer loop skips over what we consumed).
fn try_name_type_value(
  ctx: &mut RustContext,
  name: &str,
  children: &[Node],
  start: usize,
  source: &[u8],
) -> Option<usize> {
  let colon = children.get(start + 1)?;
  if colon.is_named() || colon.kind() != ":" {
    return None;
  }

  // Walk forward to find an `=` token at the same nesting level. Stop
  // if we hit a statement boundary (`;` or `,`).
  let mut equals_pos = None;
  for (j, child) in children.iter().enumerate().skip(start + 2) {
    let kind = child.kind();
    if !child.is_named() && kind == "=" {
      equals_pos = Some(j);
      break;
    }
    if !child.is_named() && matches!(kind, ";" | ",") {
      return None;
    }
  }
  let equals_pos = equals_pos?;

  // The value is the next named child after the `=`.
  let value_node = children[equals_pos + 1..]
    .iter()
    .find(|n| n.is_named())
    .copied()?;

  check_expression_value(
    ctx,
    Some(name),
    value_node,
    value_node,
    source,
    AssignmentType::Argument,
  );

  // Advance past the value.
  let value_idx = children
    .iter()
    .enumerate()
    .skip(equals_pos + 1)
    .find(|(_, n)| n.is_named())
    .map(|(idx, _)| idx)?;
  Some(value_idx - start + 1)
}

fn process_token_tree_as_tuple(
  ctx: &mut RustContext,
  node: Node,
  source: &[u8],
) {
  let mut cursor = node.walk();
  let named: Vec<Node> = node
    .children(&mut cursor)
    .filter(|n| n.is_named())
    .collect();
  if named.len() != 2 {
    process_token_tree_pairs(ctx, node, source);
    return;
  }

  let key_node = named[0];
  let value_node = named[1];
  let Some(key) = token_to_name(key_node, source) else {
    process_token_tree_pairs(ctx, node, source);
    return;
  };

  check_expression_value(
    ctx,
    Some(&key),
    value_node,
    value_node,
    source,
    AssignmentType::Argument,
  );
}

fn token_to_name(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" | "field_identifier" => node_text(node, source),
    "string_literal" | "raw_string_literal" => extract_string(node, source),
    _ => None,
  }
}

// -----------------------------------------------------------------------------
// Attributes
// -----------------------------------------------------------------------------

fn process_attribute_item(ctx: &mut RustContext, node: Node, source: &[u8]) {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "attribute" {
      process_attribute(ctx, child, source);
    }
  }
}

fn process_attribute(ctx: &mut RustContext, node: Node, source: &[u8]) {
  // `#[name = value]`
  if let Some(value) = node.child_by_field_name("value") {
    let name = attribute_name(node, source);
    if let Some(name) = name {
      check_expression_value(
        ctx,
        Some(&name),
        value,
        value,
        source,
        AssignmentType::Attribute,
      );
    }
  }

  // `#[name(arg = "value", other(...))]`
  if let Some(args) = node.child_by_field_name("arguments") {
    process_token_tree_pairs(ctx, args, source);
  }
}

fn attribute_name(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "identifier" => return node_text(child, source),
      "scoped_identifier" => {
        let name = child.child_by_field_name("name")?;
        return node_text(name, source);
      }
      _ => {}
    }
  }
  None
}

// -----------------------------------------------------------------------------
// Function signature registration
// -----------------------------------------------------------------------------

fn register_signature(node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(params_node) = node.child_by_field_name("parameters") else {
    return;
  };

  let Some(name) = node_text(name_node, source) else {
    return;
  };

  let mut parameter_names = Vec::new();
  let mut cursor = params_node.walk();
  for child in params_node.children(&mut cursor) {
    if child.kind() == "parameter"
      && let Some(pattern) = child.child_by_field_name("pattern")
      && let Some(param_name) = parameter_pattern_name(pattern, source)
    {
      parameter_names.push(param_name);
    }
  }

  ANALYZER.with(|a| {
    a.borrow_mut()
      .add_signature(name, FunctionSignature { parameter_names });
  });
}

fn parameter_pattern_name(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" => node_text(node, source),
    "mut_pattern" | "ref_pattern" => {
      let inner = first_named_child(node)?;
      parameter_pattern_name(inner, source)
    }
    "reference_pattern" => {
      let inner = first_named_child(node)?;
      parameter_pattern_name(inner, source)
    }
    _ => None,
  }
}

// -----------------------------------------------------------------------------
// Value checking with conditional / parens / ref / cast unwrapping
// -----------------------------------------------------------------------------

fn check_expression_value(
  ctx: &mut RustContext,
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
    "parenthesized_expression" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "reference_expression" => {
      // `&"hello"`, `&mut "hello"`
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "unary_expression" => {
      // `*x`, `-x`, `!x` etc.
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "type_cast_expression" => {
      // `"hello" as &str`
      let named = named_children(value_node);
      if let Some(value) = named.first() {
        check_expression_value(
          ctx,
          name,
          *value,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "binary_expression" => {
      // String + concat
      if let Some(left) = value_node.child_by_field_name("left") {
        check_expression_value(
          ctx,
          name,
          left,
          span_node,
          source,
          assignment_type,
        );
      }
      if let Some(right) = value_node.child_by_field_name("right") {
        check_expression_value(
          ctx,
          name,
          right,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "if_expression" => {
      if let Some(consequence) = value_node.child_by_field_name("consequence") {
        check_expression_value(
          ctx,
          name,
          consequence,
          span_node,
          source,
          assignment_type,
        );
      }
      if let Some(alternative) = value_node.child_by_field_name("alternative") {
        check_expression_value(
          ctx,
          name,
          alternative,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "else_clause" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "match_expression" => {
      if let Some(body) = value_node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for arm in body.children(&mut cursor) {
          if arm.kind() == "match_arm"
            && let Some(value) = arm.child_by_field_name("value")
          {
            check_expression_value(
              ctx,
              name,
              value,
              span_node,
              source,
              assignment_type,
            );
          }
        }
      }
    }
    "block" => {
      // A labelled block (`'lbl: { ... break 'lbl value; ... }`) takes
      // its value from any matching `break 'lbl <expr>` inside. Check
      // for the label and walk for matching breaks.
      if let Some(block_label) = block_label_name(value_node, source) {
        check_break_values_in_block(
          ctx,
          name,
          value_node,
          span_node,
          source,
          assignment_type,
          Some(block_label.as_str()),
        );
      }

      if let Some(tail) = block_tail_expression(value_node) {
        check_expression_value(
          ctx,
          name,
          tail,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "loop_expression" => {
      // `loop { ... break value; ... }`
      let target_label = loop_node_label(value_node, source);
      if let Some(body) = value_node.child_by_field_name("body") {
        check_break_values_in_block(
          ctx,
          name,
          body,
          span_node,
          source,
          assignment_type,
          target_label.as_deref(),
        );
      }
    }
    "while_expression" | "for_expression" => {
      let _ = loop_node_label(value_node, source);
    }
    "async_block" | "unsafe_block" | "try_block" | "const_block" => {
      if let Some(body) = value_node.child_by_field_name("body") {
        check_expression_value(
          ctx,
          name,
          body,
          span_node,
          source,
          assignment_type,
        );
      } else {
        for child in named_children(value_node) {
          if child.kind() == "block" {
            check_expression_value(
              ctx,
              name,
              child,
              span_node,
              source,
              assignment_type,
            );
          }
        }
      }
    }
    "await_expression" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "try_expression" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "return_expression" | "break_expression" | "yield_expression" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "call_expression" => {
      // Wrapper constructors: `String::from("x")`, `Cow::Borrowed("x")`,
      // `Box::new("x")`, `Some("x")`, ... Also `"x".to_string()`.
      if let Some(args_node) = value_node.child_by_field_name("arguments") {
        for arg in named_children(args_node) {
          check_expression_value(
            ctx,
            name,
            arg,
            span_node,
            source,
            assignment_type,
          );
        }
      }
      if let Some(func) = value_node.child_by_field_name("function") {
        match func.kind() {
          // `"x".to_string()`
          "field_expression" => {
            if let Some(receiver) = func.child_by_field_name("value") {
              check_expression_value(
                ctx,
                name,
                receiver,
                span_node,
                source,
                assignment_type,
              );
            }
          }
          // `(|| "x")()`
          "parenthesized_expression" => {
            for child in named_children(func) {
              check_expression_value(
                ctx,
                name,
                child,
                span_node,
                source,
                assignment_type,
              );
            }
          }
          // Direct closure call.
          "closure_expression" => {
            for child in named_children(func) {
              if child.kind() == "closure_parameters" {
                continue;
              }
              check_expression_value(
                ctx,
                name,
                child,
                span_node,
                source,
                assignment_type,
              );
            }
          }
          _ => {}
        }
      }
    }
    "closure_expression" => {
      // `let f = || "x";`
      for child in named_children(value_node) {
        if child.kind() == "closure_parameters" {
          continue;
        }
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "expression_statement" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    "macro_invocation" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor) {
        if child.kind() == "token_tree" {
          // For `concat!("a", "b")` resolve the concatenation.
          let mac_name = value_node
            .child_by_field_name("macro")
            .and_then(|n| call_last_segment(n, source));

          if mac_name.as_deref() == Some("concat")
            && let Some(concatenated) =
              extract_concat_macro_string(child, source)
          {
            let start = value_node.start_byte();
            let end = value_node.end_byte();
            if !ctx.already_emitted(start, end) {
              let normalized = normalize_value(&concatenated);
              let diag = match name {
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
            }
            continue;
          }

          // For other macros, look at the named string children directly
          // so the leading template (e.g. format!("Bearer {token}")) can
          // be checked as a value.
          let mut tt_cursor = child.walk();
          for tt_child in child.children(&mut tt_cursor) {
            if matches!(
              tt_child.kind(),
              "string_literal" | "raw_string_literal"
            ) {
              check_expression_value(
                ctx,
                name,
                tt_child,
                tt_child,
                source,
                assignment_type,
              );
            }
          }
        }
      }
    }
    "tuple_expression" | "array_expression" => {
      for child in named_children(value_node) {
        check_expression_value(
          ctx,
          name,
          child,
          span_node,
          source,
          assignment_type,
        );
      }
    }
    _ => {}
  }
}

fn check_break_values_in_block(
  ctx: &mut RustContext,
  name: Option<&str>,
  node: Node,
  span_node: Node,
  source: &[u8],
  assignment_type: AssignmentType,
  target_label: Option<&str>,
) {
  if node.kind() == "break_expression" {
    let br_label = break_expression_label(node, source);
    let matches = match (target_label, br_label.as_deref()) {
      (None, None) => true,
      (Some(want), Some(got)) => want == got,
      _ => false,
    };

    if matches && let Some(value) = break_value_node(node) {
      check_expression_value(
        ctx,
        name,
        value,
        span_node,
        source,
        assignment_type,
      );
    }

    return;
  }

  if matches!(
    node.kind(),
    "loop_expression" | "while_expression" | "for_expression"
  ) {
    if target_label.is_none() {
      return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
      check_break_values_in_block(
        ctx,
        name,
        child,
        span_node,
        source,
        assignment_type,
        target_label,
      );
    }

    return;
  }

  if node.kind() == "closure_expression" {
    return;
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    check_break_values_in_block(
      ctx,
      name,
      child,
      span_node,
      source,
      assignment_type,
      target_label,
    );
  }
}

fn break_expression_label(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "label" {
      return label_name(child, source);
    }
  }
  None
}

fn break_value_node(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if !child.is_named() {
      continue;
    }
    if child.kind() == "label" {
      continue;
    }
    return Some(child);
  }
  None
}

fn loop_node_label(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "label" {
      return label_name(child, source);
    }
    if matches!(child.kind(), "loop" | "while" | "for") {
      return None;
    }
  }
  None
}

fn label_name(label_node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = label_node.walk();
  for child in label_node.children(&mut cursor) {
    if child.kind() == "identifier" {
      return node_text(child, source);
    }
  }
  None
}

fn block_label_name(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "label" {
      return label_name(child, source);
    }
    if child.kind() == "{" {
      return None;
    }
  }
  None
}

fn block_tail_expression(block: Node) -> Option<Node> {
  let mut cursor = block.walk();
  let mut last_named: Option<Node> = None;

  for child in block.children(&mut cursor) {
    if !child.is_named() {
      continue;
    }
    last_named = Some(child);
  }

  let tail = last_named?;

  // `let x = ...;`, `use ...;` etc. don't produce a value.
  if matches!(
    tail.kind(),
    "let_declaration" | "use_declaration" | "empty_statement"
  ) {
    return None;
  }

  if tail.kind() == "expression_statement" {
    let mut c = tail.walk();
    let has_semi = tail.children(&mut c).any(|n| n.kind() == ";");
    if has_semi {
      return None;
    }

    let mut c = tail.walk();
    for child in tail.children(&mut c) {
      if child.is_named() {
        return Some(child);
      }
    }

    return None;
  }

  Some(tail)
}

// -----------------------------------------------------------------------------
// String extraction
//
//   - `"..."` - `string_literal`; mixed `string_content` and
//     `escape_sequence` children.
//   - `b"..."` (byte) and `c"..."` (C-string) - also `string_literal`,
//     the prefix sits in the opening quote token.
//   - `r"..."`, `r#"..."#`, `r##"..."##`, `br"..."`, `cr"..."` -
//     `raw_string_literal`; single `string_content` child, no escapes.
//   - `+` concatenation between two string-producing expressions.
//   - `&"..."`, `("...")`, `"..." as &str`, `unsafe { "..." }`,
//     `if x { "a" } else { "b" }`, `match x { _ => "..." }`,
//     block tail expression, etc. - all unwrap recursively.
//   - Wrapper calls: `String::from("...")`, `Cow::Borrowed("...")`,
//     `"...".to_string()`, `"...".to_owned()`, `"...".into()`,
//     `String::from("...").clone()`, etc.
//   - `concat!("a", "b")` macro - resolved as a single string here.
// -----------------------------------------------------------------------------

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "string_literal" => extract_quoted_string(node, source),
    "raw_string_literal" => extract_raw_string(node, source),
    "binary_expression" => {
      let op = node.child_by_field_name("operator")?;
      let op_text = node_text(op, source).unwrap_or_default();
      if op_text != "+" {
        return None;
      }
      let left = extract_string(node.child_by_field_name("left")?, source)?;
      let right = extract_string(node.child_by_field_name("right")?, source)?;
      Some(left + &right)
    }
    "parenthesized_expression" => {
      let inner = first_named_child(node)?;
      extract_string(inner, source)
    }
    "reference_expression" => {
      let inner = first_named_child(node)?;
      extract_string(inner, source)
    }
    "unary_expression" => {
      let inner = first_named_child(node)?;
      extract_string(inner, source)
    }
    "type_cast_expression" => {
      let named = named_children(node);
      let value = named.first().copied()?;
      extract_string(value, source)
    }
    "call_expression" => extract_string_from_call(node, source),
    "macro_invocation" => extract_string_from_macro(node, source),
    "block" => extract_string(block_tail_expression(node)?, source),
    "expression_statement" => {
      let mut c = node.walk();
      if node.children(&mut c).any(|n| n.kind() == ";") {
        return None;
      }
      extract_string(first_named_child(node)?, source)
    }
    "closure_expression" => {
      // `|| "x"`
      let mut c = node.walk();
      for child in node.children(&mut c) {
        if !child.is_named() {
          continue;
        }
        if child.kind() == "closure_parameters" {
          continue;
        }
        return extract_string(child, source);
      }
      None
    }
    "async_block" | "unsafe_block" | "try_block" | "const_block" => {
      let body = node.child_by_field_name("body").or_else(|| {
        named_children(node)
          .into_iter()
          .find(|n| n.kind() == "block")
      })?;
      extract_string(body, source)
    }
    "await_expression" | "try_expression" | "return_expression"
    | "break_expression" | "yield_expression" => {
      let inner = first_named_child(node)?;
      extract_string(inner, source)
    }
    "if_expression" => {
      let consequence = node.child_by_field_name("consequence")?;
      let alternative = node.child_by_field_name("alternative")?;
      let c = extract_string(consequence, source)?;
      let a = extract_string(alternative, source)?;
      if c == a { Some(c) } else { None }
    }
    _ => None,
  }
}

fn extract_quoted_string(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  let mut out = String::new();
  let mut had_content = false;

  for child in node.children(&mut cursor) {
    match child.kind() {
      "string_content" => {
        if let Ok(text) = child.utf8_text(source) {
          out.push_str(text);
          had_content = true;
        }
      }
      "escape_sequence" => {
        let Ok(text) = child.utf8_text(source) else {
          return None;
        };
        if let Some(decoded) = decode_escape(text) {
          out.push_str(&decoded);
          had_content = true;
        } else {
          out.push_str(text);
          had_content = true;
        }
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

fn extract_raw_string(node: Node, source: &[u8]) -> Option<String> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "string_content" {
      let text = child.utf8_text(source).ok()?;
      if text.is_empty() {
        return None;
      }
      return Some(text.to_owned());
    }
  }
  None
}

fn decode_escape(text: &str) -> Option<String> {
  match text {
    "\\n" => Some("\n".to_owned()),
    "\\r" => Some("\r".to_owned()),
    "\\t" => Some("\t".to_owned()),
    "\\\\" => Some("\\".to_owned()),
    "\\\"" => Some("\"".to_owned()),
    "\\'" => Some("'".to_owned()),
    "\\0" => Some("\0".to_owned()),
    _ => None,
  }
}

/// Wrapper-call extraction
fn extract_string_from_call(node: Node, source: &[u8]) -> Option<String> {
  let func = node.child_by_field_name("function")?;
  let args_node = node.child_by_field_name("arguments")?;
  let args = named_children(args_node);

  match func.kind() {
    "field_expression" => {
      let field = func.child_by_field_name("field")?;
      let field_name = node_text(field, source)?;
      if !WRAPPER_METHODS.contains(&field_name.as_str()) {
        return None;
      }
      if !args.is_empty() {
        return None;
      }
      let receiver = func.child_by_field_name("value")?;
      extract_string(receiver, source)
    }
    "scoped_identifier" | "generic_function" => {
      let last = call_last_segment(func, source)?;
      if !WRAPPER_PATH_TAILS.contains(&last.as_str()) {
        return None;
      }
      let arg = args.first().copied()?;
      extract_string(arg, source)
    }
    "identifier" => {
      let name = node_text(func, source)?;
      if !WRAPPER_PATH_TAILS.contains(&name.as_str()) {
        return None;
      }
      let arg = args.first().copied()?;
      extract_string(arg, source)
    }
    _ => None,
  }
}

const WRAPPER_METHODS: &[&str] = &[
  "as_bytes",
  "as_mut_str",
  "as_ref",
  "as_slice",
  "as_str",
  "clone",
  "deref",
  "into",
  "into_boxed_bytes",
  "into_boxed_str",
  "into_bytes",
  "into_inner",
  "into_string",
  "leak",
  "to_owned",
  "to_string",
];

const WRAPPER_PATH_TAILS: &[&str] = &[
  "Borrowed",
  "Err",
  "Lazy",
  "Ok",
  "Owned",
  "Pin",
  "Reverse",
  "Some",
  "Wrapping",
  "borrowed",
  "from",
  "from_str",
  "from_string",
  "into",
  "leak",
  "new",
  "new_unchecked",
  "of",
  "owned",
  "with_value",
];

fn extract_string_from_macro(node: Node, source: &[u8]) -> Option<String> {
  let macro_name = node
    .child_by_field_name("macro")
    .and_then(|n| call_last_segment(n, source))?;

  let token_tree = find_child(node, "token_tree")?;

  match macro_name.as_str() {
    "concat" => extract_concat_macro_string(token_tree, source),
    "format" | "println" | "eprintln" | "print" | "eprint" | "writeln"
    | "write" | "format_args" | "panic" | "unimplemented" | "todo"
    | "unreachable" | "assert" | "assert_eq" | "assert_ne" | "debug_assert"
    | "debug_assert_eq" | "debug_assert_ne" | "info" | "warn" | "error"
    | "debug" | "trace" => {
      // The first string literal in the token tree is the template.
      let mut cursor = token_tree.walk();
      for child in token_tree.children(&mut cursor) {
        if matches!(child.kind(), "string_literal" | "raw_string_literal") {
          return extract_string(child, source);
        }
      }
      None
    }
    _ => None,
  }
}

fn extract_concat_macro_string(
  token_tree: Node,
  source: &[u8],
) -> Option<String> {
  let mut cursor = token_tree.walk();
  let mut out = String::new();
  let mut had_any = false;
  for child in token_tree.children(&mut cursor) {
    if matches!(child.kind(), "string_literal" | "raw_string_literal") {
      let piece = extract_string(child, source)?;
      out.push_str(&piece);
      had_any = true;
    }
  }
  if had_any { Some(out) } else { None }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn node_text(node: Node, source: &[u8]) -> Option<String> {
  let raw = node.utf8_text(source).ok()?;
  if node.kind() == "identifier"
    && let Some(stripped) = raw.strip_prefix("r#")
  {
    return Some(stripped.to_owned());
  }
  Some(raw.to_owned())
}

fn named_children(node: Node) -> Vec<Node> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .filter(|n| n.is_named())
    .collect()
}

fn first_named_child(node: Node) -> Option<Node> {
  let mut cursor = node.walk();
  node.children(&mut cursor).find(|n| n.is_named())
}

fn find_child<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  node.children(&mut cursor).find(|n| n.kind() == kind)
}

fn compute_span(ctx: &RustContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
