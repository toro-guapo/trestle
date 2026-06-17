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
    if parser.set_language(&tree_sitter_go::LANGUAGE.into()).is_err() {
      None
    } else {
      Some(parser)
    }
  });
  static ANALYZER: RefCell<Analyzer<String, (usize, usize)>> =
    RefCell::new(Analyzer::new());
}

struct GoContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> GoContext<'a> {
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

  let mut ctx = GoContext {
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

fn process_node(ctx: &mut GoContext, node: Node, source: &[u8]) {
  match node.kind() {
    "short_var_declaration" | "assignment_statement" => {
      process_assignment(ctx, node, source);
    }
    "var_spec" | "const_spec" => {
      process_spec(ctx, node, source);
    }
    "call_expression" => {
      process_call(ctx, node, source);
    }
    "keyed_element" => {
      process_keyed_element(ctx, node, source);
    }
    "function_declaration" => {
      register_signature(node, source);
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    process_node(ctx, child, source);
  }
}

// -----------------------------------------------------------------------------
// Assignments: `:=` and `=`
// -----------------------------------------------------------------------------

fn process_assignment(ctx: &mut GoContext, node: Node, source: &[u8]) {
  let Some(left) = node.child_by_field_name("left") else {
    return;
  };
  let Some(right) = node.child_by_field_name("right") else {
    return;
  };

  let names = named_children(left);
  let values = named_children(right);

  for (name_node, value_node) in names.iter().zip(values.iter()) {
    let name = extract_name(*name_node, source);
    check_expression_value(
      ctx,
      name.as_deref(),
      *value_node,
      *value_node,
      source,
      AssignmentType::Variable,
    );
  }
}

// -----------------------------------------------------------------------------
// var / const specs
// -----------------------------------------------------------------------------

fn process_spec(ctx: &mut GoContext, node: Node, source: &[u8]) {
  let Some(values) = node.child_by_field_name("value") else {
    return;
  };

  let mut name_nodes = Vec::new();
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    if child.kind() == "identifier" && child.start_byte() < values.start_byte()
    {
      name_nodes.push(child);
    }
  }

  let value_nodes = named_children(values);

  for (name_node, value_node) in name_nodes.iter().zip(value_nodes.iter()) {
    let Some(name) = extract_name(*name_node, source) else {
      continue;
    };
    let assignment_type = if node.kind() == "const_spec" {
      AssignmentType::Constant
    } else {
      AssignmentType::Variable
    };
    check_expression_value(
      ctx,
      Some(&name),
      *value_node,
      *value_node,
      source,
      assignment_type,
    );
  }
}

// -----------------------------------------------------------------------------
// Function calls
// -----------------------------------------------------------------------------

fn process_call(ctx: &mut GoContext, node: Node, source: &[u8]) {
  let Some(func_node) = node.child_by_field_name("function") else {
    return;
  };
  let Some(args_node) = node.child_by_field_name("arguments") else {
    return;
  };

  let Some(callee) = extract_name(func_node, source) else {
    return;
  };

  let args = named_children(args_node);

  // Name-value correlation: arg 0 is the name, arg 1 is the value.
  // os.Setenv("KEY", value) sets an environment variable; (http.Header).Set /
  // .Add ("Header-Name", value) sets an HTTP header.
  let setter_type = if matches!(callee.as_str(), "Set" | "Add")
    && receiver_is_header(func_node, source)
  {
    Some(AssignmentType::Header)
  } else if callee == "Setenv" || callee == "Set" {
    Some(AssignmentType::Argument)
  } else {
    None
  };
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

  if func_node.kind() != "identifier" {
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

fn resolve_arguments(
  ctx: &mut GoContext,
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
// Map/struct literal keyed elements
// -----------------------------------------------------------------------------

fn process_keyed_element(ctx: &mut GoContext, node: Node, source: &[u8]) {
  let Some(key_wrapper) = node.child_by_field_name("key") else {
    return;
  };
  let Some(value_wrapper) = node.child_by_field_name("value") else {
    return;
  };

  // literal_element wraps the actual expression.
  let key_node = unwrap_literal_element(key_wrapper);
  let value_node = unwrap_literal_element(value_wrapper);

  let Some(key) =
    extract_string(key_node, source).or_else(|| extract_name(key_node, source))
  else {
    return;
  };
  check_expression_value(
    ctx,
    Some(&key),
    value_node,
    value_node,
    source,
    AssignmentType::Element,
  );
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
  let mut cursor = params_node.walk();
  for child in params_node.children(&mut cursor) {
    if child.kind() == "parameter_declaration" {
      let mut inner = child.walk();
      for param_child in child.children(&mut inner) {
        if param_child.kind() == "identifier"
          && let Ok(name) = param_child.utf8_text(source)
        {
          parameter_names.push(name.to_owned());
        }
      }
    }
  }

  ANALYZER.with(|a| {
    a.borrow_mut().add_signature(
      func_name.to_owned(),
      FunctionSignature { parameter_names },
    );
  });
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn unwrap_literal_element(node: Node) -> Node {
  if node.kind() == "literal_element" {
    node.child(0).unwrap_or(node)
  } else {
    node
  }
}

fn check_expression_value(
  ctx: &mut GoContext,
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
    "binary_expression" => {
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
    "call_expression" => {
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
    }
    // []string{"a", "b"}: positional elements inherit the name.
    "composite_literal" => {
      if let Some(body) = value_node.child_by_field_name("body") {
        for element in named_children(body) {
          if element.kind() == "literal_element" {
            for child in named_children(element) {
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
    }
    _ => {}
  }
}

fn extract_string(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "interpreted_string_literal" | "raw_string_literal" => {
      let text = node.utf8_text(source).ok()?;
      let inner = text.get(1..text.len().checked_sub(1)?)?;
      if inner.is_empty() {
        None
      } else {
        Some(inner.to_owned())
      }
    }
    "binary_expression" => {
      let op = node.child_by_field_name("operator")?;
      if op.utf8_text(source).ok()? != "+" {
        return None;
      }

      let left = extract_string(node.child_by_field_name("left")?, source)?;
      let right = extract_string(node.child_by_field_name("right")?, source)?;
      Some(left + &right)
    }
    "parenthesized_expression" => extract_string(node.child(1)?, source),
    _ => None,
  }
}

fn extract_name(node: Node, source: &[u8]) -> Option<String> {
  match node.kind() {
    "identifier" | "field_identifier" => {
      node.utf8_text(source).ok().map(|s| s.to_owned())
    }
    "selector_expression" => {
      let field = node.child_by_field_name("field")?;
      field.utf8_text(source).ok().map(|s| s.to_owned())
    }
    "index_expression" => {
      extract_string(node.child_by_field_name("index")?, source)
    }
    _ => None,
  }
}

fn receiver_is_header(func_node: Node, source: &[u8]) -> bool {
  func_node
    .child_by_field_name("operand")
    .is_some_and(|operand| selector_field_is_header(operand, source))
}

fn selector_field_is_header(node: Node, source: &[u8]) -> bool {
  match node.kind() {
    "selector_expression" => {
      node
        .child_by_field_name("field")
        .and_then(|f| f.utf8_text(source).ok())
        == Some("Header")
    }
    "call_expression" => node
      .child_by_field_name("function")
      .is_some_and(|f| selector_field_is_header(f, source)),
    _ => false,
  }
}

fn named_children(node: Node) -> Vec<Node> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .filter(|n| n.is_named())
    .collect()
}

fn compute_span(ctx: &GoContext, node: Node) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, node.start_byte()),
      end: offset_to_position(ctx.source, node.end_byte()),
    }),
  }
}
