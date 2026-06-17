use hcl_edit::{
  expr::Expression,
  structure::{Attribute, Block},
  template::{Element, StringTemplate},
  visit::{Visit, visit_attr, visit_block},
};

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_assignment,
    offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

struct HclVisitor<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  terraform_depth: u32,
  backend_depth: u32,
}

const SHELL_KEYS: &[&str] = &["command", "inline", "user_data", "provisioner"];

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let Ok(body) = hcl_edit::parser::parse_body(source) else {
    return false;
  };

  let mut visitor = HclVisitor {
    source,
    source_context: context,
    terraform_depth: 0,
    backend_depth: 0,
  };

  visitor.visit_body(&body);

  true
}

impl Visit for HclVisitor<'_> {
  fn visit_attr(&mut self, node: &Attribute) {
    let key = node.key.as_str();
    let span = hcl_edit::Span::span(&node.value);

    if SHELL_KEYS.contains(&key) {
      if let Some(value) = node.value.as_str()
        && !value.is_empty()
      {
        parse_shell_value(self, value, span.clone());
      }
    } else {
      let assignment_type = if self.backend_depth > 0 {
        AssignmentType::BackendConfig
      } else {
        AssignmentType::Property
      };
      check_expression_value(
        self,
        key,
        &node.value,
        span.clone(),
        assignment_type,
      );
    }

    visit_attr(self, node);
  }

  fn visit_block(&mut self, node: &Block) {
    // `variable "password" { default = "secret" }`
    if node.ident.as_str() == "variable" {
      if let Some(label) = node.labels.first() {
        let var_name = label.to_string();
        for attr in node.body.attributes() {
          if attr.key.as_str() == "default" {
            let span = hcl_edit::Span::span(&attr.value);
            check_expression_value(
              self,
              &var_name,
              &attr.value,
              span,
              AssignmentType::Variable,
            );
          }
        }
      }

      return;
    }

    // Track `terraform { ... }` and `backend "x" { ... }` blocks so
    // attributes inside `terraform { backend ... }` get marked as
    // BackendConfig. Backend config is loaded before Terraform's
    // variable system, so it cannot reference `var.X`.
    let ident = node.ident.as_str();
    let entering_terraform = ident == "terraform";
    let entering_backend = ident == "backend" && self.terraform_depth > 0;

    if entering_terraform {
      self.terraform_depth += 1;
    }
    if entering_backend {
      self.backend_depth += 1;
    }

    visit_block(self, node);

    if entering_backend {
      self.backend_depth -= 1;
    }
    if entering_terraform {
      self.terraform_depth -= 1;
    }
  }
}

fn check_expression_value(
  visitor: &mut HclVisitor,
  name: &str,
  expr: &Expression,
  span: Option<std::ops::Range<usize>>,
  assignment_type: AssignmentType,
) {
  if let Some(value) = expr.as_str() {
    if !value.is_empty() {
      let key = name.to_owned();
      let value = value.to_owned();
      if let Some(d) = check_assignment(
        &normalize_name(&key),
        &normalize_value(&value),
        assignment_type,
        visitor.source_context,
        || compute_span(visitor, span.clone()),
      ) {
        visitor.source_context.emit_diagnostic(d);
      }
    }
    return;
  }

  match expr {
    Expression::Conditional(cond) => {
      check_expression_value(
        visitor,
        name,
        &cond.true_expr,
        span.clone(),
        assignment_type,
      );
      check_expression_value(
        visitor,
        name,
        &cond.false_expr,
        span,
        assignment_type,
      );
    }
    Expression::FuncCall(call) => {
      let func_name = call.name.name.as_str();
      if matches!(func_name, "coalesce" | "try") {
        for arg in call.args.iter() {
          check_expression_value(
            visitor,
            name,
            arg,
            span.clone(),
            assignment_type,
          );
        }
      }
    }
    Expression::Parenthesis(p) => {
      check_expression_value(visitor, name, p.inner(), span, assignment_type);
    }
    Expression::StringTemplate(template) => {
      if let Some(literal) = template_single_literal(template) {
        let key = name.to_owned();
        if let Some(d) = check_assignment(
          &normalize_name(&key),
          &normalize_value(&literal),
          assignment_type,
          visitor.source_context,
          || compute_span(visitor, span.clone()),
        ) {
          visitor.source_context.emit_diagnostic(d);
        }
      }
    }
    _ => {}
  }
}

fn template_single_literal(template: &StringTemplate) -> Option<String> {
  let mut combined = String::new();
  for element in template.iter() {
    match element {
      Element::Literal(s) => combined.push_str(s.as_str()),
      Element::Interpolation(_) | Element::Directive(_) => return None,
    }
  }
  if combined.is_empty() {
    None
  } else {
    Some(combined)
  }
}

fn parse_shell_value(
  visitor: &HclVisitor,
  value: &str,
  span: Option<std::ops::Range<usize>>,
) {
  #[cfg(feature = "lang-shell")]
  {
    let (parent_line, parent_col) = match span {
      Some(range) => {
        let body_start = range.start
          + visitor
            .source
            .as_bytes()
            .get(range.start)
            .filter(|b| matches!(b, b'"' | b'\''))
            .map_or(0, |_| 1);
        let pos = offset_to_position(visitor.source, body_start);
        (
          visitor.source_context.parent_line + pos.line.saturating_sub(1),
          visitor.source_context.parent_col + pos.column.saturating_sub(1),
        )
      }
      None => (
        visitor.source_context.parent_line,
        visitor.source_context.parent_col,
      ),
    };
    let context = SourceContext {
      run: visitor.source_context.run,
      file_abs_path: visitor.source_context.file_abs_path,
      file_extension: None,
      body: Some(value),
      file_type: Some(crate::languages::FileType::Shell),
      parent_line,
      parent_col,
      #[cfg(feature = "services")]
      file_services: vec![],
      directives: std::cell::OnceCell::new(),
    };
    crate::languages::shell::parse(&context);
  }

  #[cfg(not(feature = "lang-shell"))]
  {
    let _ = (visitor, value, span);
  }
}

fn compute_span(
  visitor: &HclVisitor,
  range: Option<std::ops::Range<usize>>,
) -> SourceFileSpan {
  match range {
    Some(range) => SourceFileSpan {
      file_abs_path: visitor.source_context.file_abs_path.to_path_buf(),
      file_span: Some(SourceSpan {
        start: offset_to_position(visitor.source, range.start),
        end: offset_to_position(visitor.source, range.end),
      }),
    },
    None => SourceFileSpan {
      file_abs_path: visitor.source_context.file_abs_path.to_path_buf(),
      file_span: None,
    },
  }
}
