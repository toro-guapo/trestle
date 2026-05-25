use ruby_prism::{Node, Visit};

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

struct RubyContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  analyzer: Analyzer<String, (usize, usize)>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> RubyContext<'a> {
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

  let result = ruby_prism::parse(source.as_bytes());

  if result.errors().count() > 0 {
    return false;
  }

  let mut ctx = RubyContext {
    source,
    source_context: context,
    analyzer: Analyzer::new(),
    emitted_value_ranges: Vec::new(),
  };

  ctx.visit(&result.node());

  let analyzer = std::mem::replace(&mut ctx.analyzer, Analyzer::new());
  analyzer.resolve_calls(|sig, args| {
    resolve_arguments(&mut ctx, sig, args);
  });
  ctx.analyzer = analyzer;

  true
}

impl ruby_prism::Visit<'_> for RubyContext<'_> {
  fn visit_local_variable_write_node(
    &mut self,
    node: &ruby_prism::LocalVariableWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_instance_variable_write_node(
    &mut self,
    node: &ruby_prism::InstanceVariableWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_class_variable_write_node(
    &mut self,
    node: &ruby_prism::ClassVariableWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_global_variable_write_node(
    &mut self,
    node: &ruby_prism::GlobalVariableWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('$').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_constant_write_node(
    &mut self,
    node: &ruby_prism::ConstantWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write_as(self, &name, &node.value(), AssignmentType::Constant);
    self.visit(&node.value());
  }

  fn visit_local_variable_or_write_node(
    &mut self,
    node: &ruby_prism::LocalVariableOrWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_local_variable_and_write_node(
    &mut self,
    node: &ruby_prism::LocalVariableAndWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_local_variable_operator_write_node(
    &mut self,
    node: &ruby_prism::LocalVariableOperatorWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_instance_variable_or_write_node(
    &mut self,
    node: &ruby_prism::InstanceVariableOrWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_instance_variable_and_write_node(
    &mut self,
    node: &ruby_prism::InstanceVariableAndWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_instance_variable_operator_write_node(
    &mut self,
    node: &ruby_prism::InstanceVariableOperatorWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_class_variable_or_write_node(
    &mut self,
    node: &ruby_prism::ClassVariableOrWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_class_variable_and_write_node(
    &mut self,
    node: &ruby_prism::ClassVariableAndWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_class_variable_operator_write_node(
    &mut self,
    node: &ruby_prism::ClassVariableOperatorWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('@').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_global_variable_or_write_node(
    &mut self,
    node: &ruby_prism::GlobalVariableOrWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('$').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_global_variable_and_write_node(
    &mut self,
    node: &ruby_prism::GlobalVariableAndWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('$').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_global_variable_operator_write_node(
    &mut self,
    node: &ruby_prism::GlobalVariableOperatorWriteNode<'_>,
  ) {
    let name = cid(node.name()).trim_start_matches('$').to_owned();
    check_write(self, &name, &node.value());
    self.visit(&node.value());
  }

  fn visit_constant_or_write_node(
    &mut self,
    node: &ruby_prism::ConstantOrWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write_as(self, &name, &node.value(), AssignmentType::Constant);
    self.visit(&node.value());
  }

  fn visit_constant_and_write_node(
    &mut self,
    node: &ruby_prism::ConstantAndWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write_as(self, &name, &node.value(), AssignmentType::Constant);
    self.visit(&node.value());
  }

  fn visit_constant_operator_write_node(
    &mut self,
    node: &ruby_prism::ConstantOperatorWriteNode<'_>,
  ) {
    let name = cid(node.name());
    check_write_as(self, &name, &node.value(), AssignmentType::Constant);
    self.visit(&node.value());
  }

  fn visit_call_node(&mut self, node: &ruby_prism::CallNode<'_>) {
    let method = cid(node.name());

    // ENV["KEY"] = value.
    if method == "[]=" && is_env_receiver(node) {
      if let Some(args_node) = node.arguments() {
        let args: Vec<_> = args_node.arguments().iter().collect();
        if args.len() >= 2
          && let Some(key) = extract_string(&args[0])
        {
          let v_loc = args[1].location();
          check_expression_value(
            self,
            Some(&key),
            &args[1],
            v_loc.start_offset(),
            v_loc.end_offset(),
            AssignmentType::Variable,
          );
        }
      }
    }

    // Keyword arguments: method(password: "secret")
    if let Some(args_node) = node.arguments() {
      for arg in args_node.arguments().iter() {
        if let Node::KeywordHashNode { .. } = &arg {
          process_keyword_hash(self, &arg);
        }
      }
    }

    // Positional argument analysis
    if let Some(args_node) = node.arguments() {
      let extracted: Vec<(String, (usize, usize))> = args_node
        .arguments()
        .iter()
        .filter_map(|arg| {
          let value = extract_string(&arg)?;
          let loc = arg.location();
          Some((value, (loc.start_offset(), loc.end_offset())))
        })
        .collect();

      if !extracted.is_empty() {
        let signature_clone = self.analyzer.get_signature(&method).cloned();
        if let Some(sig) = signature_clone {
          resolve_arguments(self, &sig, &extracted);
        } else {
          self.analyzer.add_frame(CallFrame {
            callee: method.clone(),
            arguments: extracted,
          });
        }
      }
    }

    if let Some(args_node) = node.arguments() {
      for arg in args_node.arguments().iter() {
        let loc = arg.location();
        let start = loc.start_offset();
        let end = loc.end_offset();
        check_expression_value(
          self,
          None,
          &arg,
          start,
          end,
          AssignmentType::Argument,
        );
      }
    }

    // Recurse
    if let Some(recv) = node.receiver() {
      self.visit(&recv);
    }
    if let Some(args) = node.arguments() {
      for arg in args.arguments().iter() {
        self.visit(&arg);
      }
    }
    if let Some(block) = node.block() {
      self.visit(&block);
    }
  }

  fn visit_hash_node(&mut self, node: &ruby_prism::HashNode<'_>) {
    for element in node.elements().iter() {
      process_hash_element(self, &element);
    }
    for element in node.elements().iter() {
      self.visit(&element);
    }
  }

  fn visit_def_node(&mut self, node: &ruby_prism::DefNode<'_>) {
    let func_name = cid(node.name());

    if let Some(params) = node.parameters() {
      let mut param_names = Vec::new();

      for req in params.requireds().iter() {
        if let Node::RequiredParameterNode { .. } = &req
          && let Some(name) = req_param_name(&req)
        {
          param_names.push(name);
        }
      }

      for opt in params.optionals().iter() {
        if let Some(name) = opt_param_name(&opt) {
          param_names.push(name.clone());
        }
      }

      self.analyzer.add_signature(
        func_name,
        FunctionSignature {
          parameter_names: param_names,
        },
      );

      for opt in params.optionals().iter() {
        if let Some((name, value)) = opt_param_name_and_value(&opt) {
          check_write_as(self, &name, &value, AssignmentType::Parameter);
        }
      }

      for kw in params.keywords().iter() {
        if let Some((name, value)) = kw_param_name_and_value(&kw) {
          check_write_as(self, &name, &value, AssignmentType::Parameter);
        }
      }
    }

    if let Some(body) = node.body() {
      self.visit(&body);
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn check_write(ctx: &mut RubyContext, name: &str, value: &Node) {
  check_write_as(ctx, name, value, AssignmentType::Variable);
}

fn check_branch(
  ctx: &mut RubyContext,
  name: Option<&str>,
  branch: &Node,
  assignment_type: AssignmentType,
) {
  let loc = branch.location();
  check_expression_value(
    ctx,
    name,
    branch,
    loc.start_offset(),
    loc.end_offset(),
    assignment_type,
  );
}

fn check_write_as(
  ctx: &mut RubyContext,
  name: &str,
  value: &Node,
  assignment_type: AssignmentType,
) {
  let v_loc = value.location();
  let start = v_loc.start_offset();
  let end = v_loc.end_offset();
  check_expression_value(ctx, Some(name), value, start, end, assignment_type);
}

fn check_expression_value(
  ctx: &mut RubyContext,
  name: Option<&str>,
  value: &Node,
  start: usize,
  end: usize,
  assignment_type: AssignmentType,
) {
  if let Some(value_str) = extract_string(value) {
    let v_loc = value.location();
    let v_start = v_loc.start_offset();
    let v_end = v_loc.end_offset();
    if ctx.already_emitted(v_start, v_end) {
      return;
    }

    let normalized = normalize_value(&value_str);
    let diag: Option<Diagnostic> = match name {
      Some(n) => {
        ctx.record_emitted(v_start, v_end);
        check_assignment(
          &normalize_name(&n.to_owned()),
          &normalized,
          assignment_type,
          ctx.source_context,
          || compute_span_offsets(ctx, start, end),
        )
      }
      None => check_value(&normalized, ctx.source_context, || {
        compute_span_offsets(ctx, v_start, v_end)
      }),
    };

    if let Some(d) = diag {
      if name.is_none() {
        ctx.record_emitted(v_start, v_end);
      }
      ctx.source_context.emit_diagnostic(d);
    }
    return;
  }

  match value {
    Node::OrNode { .. } => {
      if let Some(or) = value.as_or_node() {
        check_branch(ctx, name, &or.left(), assignment_type);
        check_branch(ctx, name, &or.right(), assignment_type);
      }
    }
    Node::AndNode { .. } => {
      if let Some(and) = value.as_and_node() {
        check_branch(ctx, name, &and.left(), assignment_type);
        check_branch(ctx, name, &and.right(), assignment_type);
      }
    }
    Node::IfNode { .. } => {
      if let Some(if_node) = value.as_if_node() {
        if let Some(stmts) = if_node.statements() {
          for body_node in stmts.body().iter() {
            check_branch(ctx, name, &body_node, assignment_type);
          }
        }
        if let Some(subsequent) = if_node.subsequent() {
          check_branch(ctx, name, &subsequent, assignment_type);
        }
      }
    }
    Node::ElseNode { .. } => {
      if let Some(else_node) = value.as_else_node()
        && let Some(stmts) = else_node.statements()
      {
        for body_node in stmts.body().iter() {
          check_branch(ctx, name, &body_node, assignment_type);
        }
      }
    }
    Node::CallNode { .. } => {
      if let Some(call) = value.as_call_node() {
        let method = cid(call.name());
        if method == "fetch" && is_env_receiver(&call) {
          // ENV.fetch('KEY', default)
          if let Some(args) = call.arguments() {
            let args_vec: Vec<_> = args.arguments().iter().collect();
            if let Some(default) = args_vec.get(1) {
              check_expression_value(
                ctx,
                name,
                default,
                start,
                end,
                assignment_type,
              );
            }
          }
          // ENV.fetch('KEY') { default }
          if let Some(block) = call.block() {
            if let Some(block_node) = block.as_block_node() {
              if let Some(body) = block_node.body() {
                check_expression_value(
                  ctx,
                  name,
                  &body,
                  start,
                  end,
                  assignment_type,
                );
              }
            }
          }
          return;
        }

        if call.arguments().is_none() && call.block().is_none() {
          if let Some(recv) = call.receiver() {
            check_expression_value(
              ctx,
              name,
              &recv,
              start,
              end,
              assignment_type,
            );
          }
          return;
        }

        if let Some(args) = call.arguments() {
          for arg in args.arguments().iter() {
            check_expression_value(
              ctx,
              name,
              &arg,
              start,
              end,
              assignment_type,
            );
          }
        }
      }
    }
    _ => {}
  }
}

fn process_hash_element(ctx: &mut RubyContext, element: &Node) {
  let Some(a) = element.as_assoc_node() else {
    return;
  };

  let Some(key) = extract_string(&a.key()).or_else(|| extract_symbol(&a.key()))
  else {
    return;
  };
  let v_loc = a.value().location();
  let start = v_loc.start_offset();
  let end = v_loc.end_offset();
  check_expression_value(
    ctx,
    Some(&key),
    &a.value(),
    start,
    end,
    AssignmentType::Element,
  );
}

fn process_keyword_hash(ctx: &mut RubyContext, node: &Node) {
  let Some(kh) = node.as_keyword_hash_node() else {
    return;
  };
  for element in kh.elements().iter() {
    let Some(assoc) = element.as_assoc_node() else {
      continue;
    };

    let Some(key) = extract_symbol(&assoc.key()) else {
      continue;
    };
    let v_loc = assoc.value().location();
    let start = v_loc.start_offset();
    let end = v_loc.end_offset();
    check_expression_value(
      ctx,
      Some(&key),
      &assoc.value(),
      start,
      end,
      AssignmentType::Argument,
    );
  }
}

fn resolve_arguments(
  ctx: &mut RubyContext,
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

fn extract_string(node: &Node) -> Option<String> {
  match node {
    Node::StringNode { .. } => {
      let s = node.as_string_node()?;
      let text = std::str::from_utf8(s.unescaped()).ok()?;
      if text.is_empty() {
        None
      } else {
        Some(text.to_owned())
      }
    }
    Node::ParenthesesNode { .. } => {
      let p = node.as_parentheses_node()?;
      extract_string(&p.body()?)
    }
    Node::StatementsNode { .. } => {
      let s = node.as_statements_node()?;
      let body: Vec<_> = s.body().iter().collect();
      if body.len() == 1 {
        extract_string(&body[0])
      } else {
        None
      }
    }
    Node::SymbolNode { .. } => extract_symbol(node),
    Node::CallNode { .. } => {
      // String concatenation: "a" + "b" is a method call in Ruby
      let c = node.as_call_node()?;
      if cid(c.name()) == "+" {
        let left = extract_string(&c.receiver()?)?;
        let args = c.arguments()?;
        let args_vec: Vec<_> = args.arguments().iter().collect();
        let right = extract_string(args_vec.first()?)?;
        Some(left + &right)
      } else {
        None
      }
    }
    _ => None,
  }
}

fn extract_symbol(node: &Node) -> Option<String> {
  let s = node.as_symbol_node()?;
  let text = std::str::from_utf8(s.unescaped()).ok()?;
  if text.is_empty() {
    None
  } else {
    Some(text.to_owned())
  }
}

fn req_param_name(node: &Node) -> Option<String> {
  let p = node.as_required_parameter_node()?;
  Some(cid(p.name()))
}

fn opt_param_name(node: &Node) -> Option<String> {
  let p = node.as_optional_parameter_node()?;
  Some(cid(p.name()))
}

fn opt_param_name_and_value<'a>(
  node: &'a Node<'a>,
) -> Option<(String, Node<'a>)> {
  let p = node.as_optional_parameter_node()?;
  Some((cid(p.name()), p.value()))
}

fn kw_param_name_and_value<'a>(
  node: &'a Node<'a>,
) -> Option<(String, Node<'a>)> {
  let p = node.as_optional_keyword_parameter_node()?;
  Some((cid(p.name()), p.value()))
}

fn is_env_receiver(node: &ruby_prism::CallNode<'_>) -> bool {
  node
    .receiver()
    .and_then(|recv| recv.as_constant_read_node().map(|c| cid(c.name())))
    .is_some_and(|name| name == "ENV")
}

fn cid(id: ruby_prism::ConstantId<'_>) -> String {
  std::str::from_utf8(id.as_slice())
    .unwrap_or_default()
    .to_owned()
}

fn compute_span_offsets(
  ctx: &RubyContext,
  start: usize,
  end: usize,
) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, start),
      end: offset_to_position(ctx.source, end),
    }),
  }
}
