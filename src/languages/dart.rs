use std::cell::RefCell;

use tree_sitter::Node;

use crate::{
  analysis::{Analyzer, CallFrame, FunctionSignature},
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
    if parser.set_language(&tree_sitter_dart::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
  static ANALYZER: RefCell<Analyzer<String, (usize, usize)>> =
    RefCell::new(Analyzer::new());
}

struct DartContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> DartContext<'a> {
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

  let mut ctx = DartContext {
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

fn process_node(ctx: &mut DartContext, node: Node, source: &[u8]) {
  match node.kind() {
    "static_final_declaration" => {
      process_static_final(ctx, node, source);
    }
    "initialized_identifier" => {
      process_initialized_identifier(ctx, node, source);
    }
    "initialized_variable_definition" => {
      process_initialized_variable(ctx, node, source);
    }
    "assignment_expression" => {
      process_assignment(ctx, node, source);
    }
    "pair" => process_pair(ctx, node, source),
    "named_argument" => process_named_argument(ctx, node, source),
    "function_signature" | "constructor_signature" => {
      register_signature(node, source);
    }
    "optional_formal_parameters" => {
      process_default_params(ctx, node, source);
    }
    "expression_statement" => {
      process_expression_statement(ctx, node, source);
    }
    "arguments" => {
      process_arguments_value_only(ctx, node, source);
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

fn process_arguments_value_only(
  ctx: &mut DartContext,
  args_node: Node,
  source: &[u8],
) {
  let enclosing = enclosing_name(args_node, source);

  let mut cursor = args_node.walk();
  for child in args_node.children(&mut cursor) {
    if child.kind() != "argument" {
      continue;
    }

    let mut inner = child.walk();
    let mut arg_expr: Option<Node> = None;
    let mut is_named = false;
    for arg_child in child.children(&mut inner) {
      if arg_child.kind() == "named_argument" {
        is_named = true;
        break;
      }
      if arg_child.is_named() {
        arg_expr = Some(arg_child);
      }
    }

    if is_named {
      continue;
    }

    if let Some(expr) = arg_expr {
      check_value_node(
        ctx,
        enclosing.as_deref(),
        expr,
        AssignmentType::Argument,
        expr,
        source,
      );
    }
  }
}

fn enclosing_name(start: Node, source: &[u8]) -> Option<String> {
  let mut current = start.parent()?;
  loop {
    match current.kind() {
      "assignment_expression" => {
        let left = current.child_by_field_name("left")?;
        return extract_assignee_name(left, source);
      }
      "initialized_variable_definition" | "initialized_identifier" => {
        let name_node = current.child_by_field_name("name")?;
        return name_node.utf8_text(source).ok().map(|s| s.to_owned());
      }
      "static_final_declaration" => {
        let name_node = current.child_by_field_name("name")?;
        return name_node.utf8_text(source).ok().map(|s| s.to_owned());
      }
      "pair" => {
        let key_node = current.child_by_field_name("key")?;
        return extract_string(key_node, source)
          .or_else(|| extract_name(key_node, source));
      }
      "named_argument" => {
        let mut cursor = current.walk();
        for child in current.children(&mut cursor) {
          if child.kind() == "label" {
            let mut inner = child.walk();
            for label_child in child.children(&mut inner) {
              if label_child.kind() == "identifier" {
                return label_child
                  .utf8_text(source)
                  .ok()
                  .map(|s| s.to_owned());
              }
            }
          }
        }
        return None;
      }
      _ => current = current.parent()?,
    }
  }
}

// -----------------------------------------------------------------------------
// const / final declarations
// -----------------------------------------------------------------------------

fn process_static_final(ctx: &mut DartContext, node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("value") else {
    return;
  };

  let Some(name) = name_node.utf8_text(source).ok().map(|s| s.to_owned())
  else {
    return;
  };

  let assignment_type = if is_const_declaration(node) {
    AssignmentType::Constant
  } else {
    AssignmentType::Variable
  };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    assignment_type,
    value_node,
    source,
  );
}

fn is_const_declaration(node: Node) -> bool {
  // const keyword is a sibling of static_final_declaration_list (our parent)
  // in the grandparent node (source_file, declaration, etc.)
  let Some(parent) = node.parent() else {
    return false;
  };
  let Some(grandparent) = parent.parent() else {
    return false;
  };

  let mut cursor = grandparent.walk();
  for child in grandparent.children(&mut cursor) {
    if child.kind() == "const" {
      return true;
    }
    if child.id() == parent.id() {
      break;
    }
  }
  false
}

// -----------------------------------------------------------------------------
// var / typed declarations (top-level and class-level)
// -----------------------------------------------------------------------------

fn process_initialized_identifier(
  ctx: &mut DartContext,
  node: Node,
  source: &[u8],
) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("value") else {
    return;
  };

  let Some(name) = name_node.utf8_text(source).ok().map(|s| s.to_owned())
  else {
    return;
  };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    AssignmentType::Variable,
    value_node,
    source,
  );
}

// -----------------------------------------------------------------------------
// Local variable declarations
// -----------------------------------------------------------------------------

fn process_initialized_variable(
  ctx: &mut DartContext,
  node: Node,
  source: &[u8],
) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("value") else {
    return;
  };

  let Some(name) = name_node.utf8_text(source).ok().map(|s| s.to_owned())
  else {
    return;
  };

  let assignment_type = if has_child_kind(node, "const") {
    AssignmentType::Constant
  } else {
    AssignmentType::Variable
  };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    assignment_type,
    value_node,
    source,
  );
}

// -----------------------------------------------------------------------------
// Reassignment: password = "secret"
// -----------------------------------------------------------------------------

fn process_assignment(ctx: &mut DartContext, node: Node, source: &[u8]) {
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
    AssignmentType::Variable,
    right,
    source,
  );
}

fn extract_assignee_name(node: Node, source: &[u8]) -> Option<String> {
  let mut last_ident = None;
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "identifier" => {
        last_ident = child.utf8_text(source).ok().map(|s| s.to_owned());
      }
      "unconditional_assignable_selector" => {
        let mut inner = child.walk();
        for inner_child in child.children(&mut inner) {
          match inner_child.kind() {
            // .field access
            "identifier" => {
              last_ident =
                inner_child.utf8_text(source).ok().map(|s| s.to_owned());
            }
            // ["key"] index access
            "string_literal" => {
              last_ident = extract_string(inner_child, source);
            }
            _ => {}
          }
        }
      }
      _ => {}
    }
  }
  last_ident
}

// -----------------------------------------------------------------------------
// Literal pairs: {"password": "secret"}
// -----------------------------------------------------------------------------

fn process_pair(ctx: &mut DartContext, node: Node, source: &[u8]) {
  let Some(key_node) = node.child_by_field_name("key") else {
    return;
  };
  let Some(value_node) = node.child_by_field_name("value") else {
    return;
  };

  let Some(key) =
    extract_string(key_node, source).or_else(|| extract_name(key_node, source))
  else {
    return;
  };

  check_value_node(
    ctx,
    Some(&key),
    value_node,
    AssignmentType::Element,
    value_node,
    source,
  );
}

// -----------------------------------------------------------------------------
// Named arguments: connect(password: "secret")
// -----------------------------------------------------------------------------

fn process_named_argument(ctx: &mut DartContext, node: Node, source: &[u8]) {
  let mut name: Option<String> = None;
  let mut value_node: Option<Node> = None;

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "label" => {
        let mut inner = child.walk();
        for label_child in child.children(&mut inner) {
          if label_child.kind() == "identifier" {
            name = label_child.utf8_text(source).ok().map(|s| s.to_owned());
          }
        }
      }
      _ if child.is_named() && name.is_some() && value_node.is_none() => {
        value_node = Some(child);
      }
      _ => {}
    }
  }

  let Some(name) = name else { return };
  let Some(value_node) = value_node else { return };

  check_value_node(
    ctx,
    Some(&name),
    value_node,
    AssignmentType::Argument,
    value_node,
    source,
  );
}

// -----------------------------------------------------------------------------
// Function calls (positional argument analysis)
// -----------------------------------------------------------------------------

fn process_expression_statement(
  ctx: &mut DartContext,
  node: Node,
  source: &[u8],
) {
  let mut callee: Option<String> = None;
  let mut arguments_node: Option<Node> = None;
  let mut is_method_call = false;

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "identifier" if callee.is_none() => {
        callee = child.utf8_text(source).ok().map(|s| s.to_owned());
      }
      "selector" => {
        let mut sel_cursor = child.walk();
        for sel_child in child.children(&mut sel_cursor) {
          match sel_child.kind() {
            "argument_part" => {
              let mut ap_cursor = sel_child.walk();
              for ap_child in sel_child.children(&mut ap_cursor) {
                if ap_child.kind() == "arguments" {
                  arguments_node = Some(ap_child);
                }
              }
            }
            "unconditional_assignable_selector" => {
              is_method_call = true;
              let mut us_cursor = sel_child.walk();
              for us_child in sel_child.children(&mut us_cursor) {
                if us_child.kind() == "identifier" {
                  callee =
                    us_child.utf8_text(source).ok().map(|s| s.to_owned());
                }
              }
            }
            _ => {}
          }
        }
      }
      _ => {}
    }
  }

  let Some(callee) = callee else { return };
  let Some(args_node) = arguments_node else {
    return;
  };

  let positional = extract_positional_args(args_node, source);
  if positional.is_empty() {
    return;
  }

  if is_method_call {
    return;
  }

  let resolved = ANALYZER.with(|a| {
    let analyzer = a.borrow();
    if let Some(signature) = analyzer.get_signature(&callee) {
      resolve_arguments(ctx, signature, &positional);
      true
    } else {
      false
    }
  });

  if !resolved {
    ANALYZER.with(|a| {
      a.borrow_mut().add_frame(CallFrame {
        callee,
        arguments: positional,
      });
    });
  }
}

fn extract_positional_args(
  args_node: Node,
  source: &[u8],
) -> Vec<(String, (usize, usize))> {
  let mut positional = Vec::new();
  let mut cursor = args_node.walk();

  for child in args_node.children(&mut cursor) {
    if child.kind() != "argument" {
      continue;
    }

    let has_named = {
      let mut inner = child.walk();
      child
        .children(&mut inner)
        .any(|c| c.kind() == "named_argument")
    };

    if has_named {
      continue;
    }

    let mut inner = child.walk();
    for arg_child in child.children(&mut inner) {
      if arg_child.is_named() {
        if let Some(value) = extract_string(arg_child, source) {
          positional
            .push((value, (arg_child.start_byte(), arg_child.end_byte())));
        }
        break;
      }
    }
  }

  positional
}

fn resolve_arguments(
  ctx: &mut DartContext,
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
// Function signature registration
// -----------------------------------------------------------------------------

fn register_signature(node: Node, source: &[u8]) {
  let Some(name_node) = node.child_by_field_name("name") else {
    return;
  };
  let Some(params_node) = node.child_by_field_name("parameters") else {
    return;
  };

  let Ok(func_name) = name_node.utf8_text(source) else {
    return;
  };

  let mut parameter_names = Vec::new();
  collect_params(params_node, source, &mut parameter_names);

  ANALYZER.with(|a| {
    a.borrow_mut().add_signature(
      func_name.to_owned(),
      FunctionSignature { parameter_names },
    );
  });
}

fn collect_params(node: Node, source: &[u8], names: &mut Vec<String>) {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "formal_parameter" => {
        if let Some(name_node) = child.child_by_field_name("name") {
          if let Ok(name) = name_node.utf8_text(source) {
            names.push(name.to_owned());
          }
        } else {
          // Constructor parameter: this.name
          let mut inner = child.walk();
          for param_child in child.children(&mut inner) {
            if param_child.kind() == "constructor_param" {
              let mut last_ident = None;
              let mut cp_cursor = param_child.walk();
              for cp_child in param_child.children(&mut cp_cursor) {
                if cp_child.kind() == "identifier" {
                  last_ident = cp_child.utf8_text(source).ok();
                }
              }
              if let Some(name) = last_ident {
                names.push(name.to_owned());
              }
            }
          }
        }
      }
      "optional_formal_parameters" | "formal_parameter_list" => {
        collect_params(child, source, names);
      }
      _ => {}
    }
  }
}

// -----------------------------------------------------------------------------
// Default parameter values: void connect({String password = "secret"})
// -----------------------------------------------------------------------------

fn process_default_params(ctx: &mut DartContext, node: Node, source: &[u8]) {
  let mut last_param_name: Option<String> = None;
  let mut saw_equals = false;

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "formal_parameter" => {
        if let Some(name_node) = child.child_by_field_name("name") {
          last_param_name =
            name_node.utf8_text(source).ok().map(|s| s.to_owned());
        } else {
          last_param_name = None;
        }
        saw_equals = false;
      }
      "=" => {
        saw_equals = true;
      }
      _ if saw_equals && child.is_named() => {
        if let Some(ref name) = last_param_name {
          check_value_node(
            ctx,
            Some(name),
            child,
            AssignmentType::Parameter,
            child,
            source,
          );
        }
        saw_equals = false;
        last_param_name = None;
      }
      _ => {
        saw_equals = false;
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Value checking with conditional expression support
// -----------------------------------------------------------------------------

fn check_value_node(
  ctx: &mut DartContext,
  name: Option<&str>,
  value_node: Node,
  assignment_type: AssignmentType,
  span_node: Node,
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
    "conditional_expression" => {
      if let Some(c) = value_node.child_by_field_name("consequence") {
        check_value_node(ctx, name, c, assignment_type, c, source);
      }
      if let Some(a) = value_node.child_by_field_name("alternative") {
        check_value_node(ctx, name, a, assignment_type, a, source);
      }
    }
    // x ?? "fallback" - each operand is its own value expression.
    "if_null_expression" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor) {
        if child.is_named() {
          check_value_node(ctx, name, child, assignment_type, child, source);
        }
      }
    }
    "list_literal" | "set_or_map_literal" => {
      let mut cursor = value_node.walk();
      for child in value_node.children(&mut cursor) {
        if child.is_named() {
          check_value_node(ctx, name, child, assignment_type, child, source);
        }
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
    "string_literal" => {
      // Adjacent string literals ("a" "b") produce multiple content
      // children - concatenate them all.
      let mut parts = Vec::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        match child.kind() {
          "string_literal_double_quotes"
          | "string_literal_single_quotes"
          | "string_literal_double_quotes_multiple"
          | "string_literal_single_quotes_multiple"
          | "raw_string_literal_double_quotes"
          | "raw_string_literal_single_quotes" => {
            parts.push(extract_string_content(child, source)?);
          }
          _ => {}
        }
      }
      if parts.is_empty() {
        None
      } else {
        Some(parts.join(""))
      }
    }
    "additive_expression" => {
      let mut parts = Vec::new();
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        if child.kind() == "+" {
          continue;
        }
        if child.is_named() {
          parts.push(extract_string(child, source)?);
        }
      }
      if parts.is_empty() {
        None
      } else {
        Some(parts.join(""))
      }
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
    _ => None,
  }
}

fn extract_string_content(node: Node, source: &[u8]) -> Option<String> {
  let is_raw = node.kind().starts_with("raw_");

  let mut cursor = node.walk();
  let mut text = String::new();
  let mut has_content = false;

  for child in node.children(&mut cursor) {
    match child.kind() {
      "template_substitution" => return None,
      "template_chars_double_single"
      | "template_chars_single_single"
      | "template_chars_double"
      | "template_chars_single" => {
        if let Ok(t) = child.utf8_text(source) {
          text.push_str(t);
          has_content = true;
        }
      }
      "$" if is_raw => {
        text.push('$');
        has_content = true;
      }
      _ => {}
    }
  }

  if has_content && !text.is_empty() {
    Some(text)
  } else {
    None
  }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn extract_name(node: Node, source: &[u8]) -> Option<String> {
  if node.kind() == "identifier" {
    return node.utf8_text(source).ok().map(|s| s.to_owned());
  }
  None
}

fn has_child_kind(node: Node, kind: &str) -> bool {
  let mut cursor = node.walk();
  node.children(&mut cursor).any(|c| c.kind() == kind)
}

fn compute_span(ctx: &DartContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
