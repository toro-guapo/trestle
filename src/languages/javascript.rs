use std::cell::RefCell;

use oxc_ast::ast::{
  AssignmentTarget, BindingPattern, Class, ClassElement, Declaration,
  ExportDefaultDeclarationKind, Expression, ForStatementInit, FormalParameters,
  Function, JSXAttributeItem, JSXAttributeName, JSXAttributeValue,
  ObjectPropertyKind, PropertyKey, PropertyKind, Statement,
  VariableDeclaration, VariableDeclarationKind,
};
use oxc_span::{GetSpan, SourceType};
use oxc_syntax::operator::{
  AssignmentOperator, BinaryOperator, LogicalOperator,
};

use crate::{
  analysis::{Analyzer, CallFrame, FunctionSignature},
  diagnostic::{
    AssignmentType, SourceFileSpan, check_assignment, check_header_assignment,
    check_value, compute_file_span,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
  shared::MB,
};

thread_local! {
  static ALLOCATOR: RefCell<Option<oxc_allocator::Allocator>> = const { RefCell::new(
    None
  ) };
  static ANALYZER: RefCell<Analyzer<String, oxc_span::Span>> = RefCell::new(
    Analyzer::new()
  );
}

struct JsContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(u32, u32)>,
}

impl<'a> JsContext<'a> {
  fn already_emitted(&self, span: oxc_span::Span) -> bool {
    self
      .emitted_value_ranges
      .iter()
      .any(|(rs, re)| *rs <= span.start && *re >= span.end)
  }

  fn record_emitted(&mut self, span: oxc_span::Span) {
    self.emitted_value_ranges.push((span.start, span.end));
  }
}

pub fn parse(context: &SourceContext) -> bool {
  ANALYZER.with(|a| a.borrow_mut().clear());
  parse_with_source_type(context, None)
}

pub fn parse_with_source_type(
  context: &SourceContext,
  source_type: Option<SourceType>,
) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let source_type = source_type.unwrap_or_else(|| {
    SourceType::from_path(context.file_abs_path)
      .unwrap_or_else(|_| SourceType::tsx())
  });

  ALLOCATOR.with(|allocator| {
    let mut allocator = allocator.borrow_mut();

    let allocator = allocator
      .get_or_insert_with(|| oxc_allocator::Allocator::with_capacity(MB));

    let parser = oxc_parser::Parser::new(&*allocator, source, source_type)
      .with_options(oxc_parser::ParseOptions {
        allow_return_outside_function: true,
        ..Default::default()
      });

    let result = parser.parse();
    if !result.errors.is_empty() {
      return false;
    }

    ANALYZER.with(|a| a.borrow_mut().clear_frames());

    let mut js_context = JsContext {
      source,
      source_context: context,
      emitted_value_ranges: Vec::new(),
    };

    process_statements(&mut js_context, &result.program.body);

    ANALYZER.with(|a| {
      a.borrow().resolve_calls(|signature, arguments| {
        resolve_arguments(&mut js_context, signature, arguments);
      });
    });

    true
  })
}

pub fn scan_expression(context: &SourceContext) -> bool {
  scan_expression_inner(context, false)
}

pub fn scan_client_expression(context: &SourceContext) -> bool {
  scan_expression_inner(context, true)
}

fn scan_expression_inner(context: &SourceContext, client_sink: bool) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  ALLOCATOR.with(|allocator| {
    let mut allocator = allocator.borrow_mut();

    let allocator = allocator
      .get_or_insert_with(|| oxc_allocator::Allocator::with_capacity(MB));

    let parser = oxc_parser::Parser::new(&*allocator, source, SourceType::ts());

    let Ok(expression) = parser.parse_expression() else {
      return false;
    };

    ANALYZER.with(|a| a.borrow_mut().clear_frames());

    let mut js_context = JsContext {
      source,
      source_context: context,
      emitted_value_ranges: Vec::new(),
    };

    process_value(&mut js_context, &expression);
    process_expression(&mut js_context, &expression);

    let _ = client_sink;

    ANALYZER.with(|a| {
      a.borrow().resolve_calls(|signature, arguments| {
        resolve_arguments(&mut js_context, signature, arguments);
      });
    });

    true
  })
}

pub fn reset_analyzer() {
  ANALYZER.with(|a| a.borrow_mut().clear());
}

pub fn declare_signature(name: String, parameter_names: Vec<String>) {
  ANALYZER.with(|a| {
    a.borrow_mut()
      .add_signature(name, FunctionSignature { parameter_names });
  });
}

pub fn parameter_names(params_source: &str) -> Vec<String> {
  let wrapped = format!("({params_source}) => 0");

  ALLOCATOR.with(|allocator| {
    let mut allocator = allocator.borrow_mut();

    let allocator = allocator
      .get_or_insert_with(|| oxc_allocator::Allocator::with_capacity(MB));

    let parser =
      oxc_parser::Parser::new(&*allocator, &wrapped, SourceType::ts());

    let Ok(Expression::ArrowFunctionExpression(arrow)) =
      parser.parse_expression()
    else {
      return Vec::new();
    };

    identifier_param_names(&arrow.params)
  })
}

fn identifier_param_names(params: &FormalParameters) -> Vec<String> {
  params
    .items
    .iter()
    .map(|param| match &param.pattern {
      BindingPattern::BindingIdentifier(id) => id.name.to_string(),
      _ => String::new(),
    })
    .collect()
}

pub fn collect_signatures(source: &str) -> Vec<(String, Vec<String>)> {
  let mut signatures = Vec::new();

  ALLOCATOR.with(|allocator| {
    let mut allocator = allocator.borrow_mut();

    let allocator = allocator
      .get_or_insert_with(|| oxc_allocator::Allocator::with_capacity(MB));

    let parser = oxc_parser::Parser::new(&*allocator, source, SourceType::ts())
      .with_options(oxc_parser::ParseOptions {
        allow_return_outside_function: true,
        ..Default::default()
      });

    let result = parser.parse();
    if result.errors.is_empty() {
      for statement in &result.program.body {
        collect_signature(statement, &mut signatures);
      }
    }
  });

  signatures
}

fn collect_signature(
  statement: &Statement,
  signatures: &mut Vec<(String, Vec<String>)>,
) {
  match statement {
    Statement::FunctionDeclaration(function) => {
      push_function_signature(function, signatures);
    }
    Statement::VariableDeclaration(declaration) => {
      push_variable_signatures(declaration, signatures);
    }
    Statement::ExportNamedDeclaration(export) => match &export.declaration {
      Some(Declaration::FunctionDeclaration(function)) => {
        push_function_signature(function, signatures);
      }
      Some(Declaration::VariableDeclaration(declaration)) => {
        push_variable_signatures(declaration, signatures);
      }
      _ => {}
    },
    _ => {}
  }
}

fn push_function_signature(
  function: &Function,
  signatures: &mut Vec<(String, Vec<String>)>,
) {
  if let Some(id) = &function.id {
    signatures.push((
      id.name.to_string(),
      identifier_param_names(&function.params),
    ));
  }
}

fn push_variable_signatures(
  declaration: &VariableDeclaration,
  signatures: &mut Vec<(String, Vec<String>)>,
) {
  for declarator in &declaration.declarations {
    let BindingPattern::BindingIdentifier(id) = &declarator.id else {
      continue;
    };
    match &declarator.init {
      Some(Expression::ArrowFunctionExpression(arrow)) => {
        signatures
          .push((id.name.to_string(), identifier_param_names(&arrow.params)));
      }
      Some(Expression::FunctionExpression(function)) => {
        signatures.push((
          id.name.to_string(),
          identifier_param_names(&function.params),
        ));
      }
      _ => {}
    }
  }
}

fn process_statements(context: &mut JsContext<'_>, statements: &[Statement]) {
  for statement in statements {
    process_statement(context, statement);
  }
}

fn process_statement(context: &mut JsContext<'_>, statement: &Statement) {
  match statement {
    Statement::VariableDeclaration(decl) => {
      process_variable_declaration(context, decl);
    }
    Statement::FunctionDeclaration(f) => process_function(context, f),
    Statement::ClassDeclaration(c) => process_class(context, c),
    Statement::TSEnumDeclaration(e) => {
      process_enum_members(context, &e.body.members);
    }

    Statement::BlockStatement(block) => {
      process_statements(context, &block.body);
    }

    Statement::IfStatement(stmt) => {
      process_expression(context, &stmt.test);
      process_statement(context, &stmt.consequent);
      if let Some(alternate) = &stmt.alternate {
        process_statement(context, alternate);
      }
    }

    Statement::ForStatement(stmt) => {
      match &stmt.init {
        Some(ForStatementInit::VariableDeclaration(decl)) => {
          process_variable_declaration(context, decl);
        }
        Some(init) => {
          if let Some(expr) = init.as_expression() {
            process_expression(context, expr);
          }
        }
        None => {}
      }
      if let Some(update) = &stmt.update {
        process_expression(context, update);
      }
      process_statement(context, &stmt.body);
    }

    Statement::ForInStatement(stmt) => {
      process_statement(context, &stmt.body);
    }

    Statement::ForOfStatement(stmt) => {
      process_statement(context, &stmt.body);
    }

    Statement::WhileStatement(stmt) => {
      process_expression(context, &stmt.test);
      process_statement(context, &stmt.body);
    }

    Statement::DoWhileStatement(stmt) => {
      process_expression(context, &stmt.test);
      process_statement(context, &stmt.body);
    }

    Statement::SwitchStatement(stmt) => {
      process_expression(context, &stmt.discriminant);
      for case in &stmt.cases {
        if let Some(test) = &case.test {
          process_expression(context, test);
        }
        process_statements(context, &case.consequent);
      }
    }

    Statement::TryStatement(stmt) => {
      process_statements(context, &stmt.block.body);
      if let Some(handler) = &stmt.handler {
        process_statements(context, &handler.body.body);
      }
      if let Some(finalizer) = &stmt.finalizer {
        process_statements(context, &finalizer.body);
      }
    }

    Statement::LabeledStatement(stmt) => {
      process_statement(context, &stmt.body);
    }

    Statement::WithStatement(stmt) => {
      process_statement(context, &stmt.body);
    }

    Statement::ExpressionStatement(stmt) => {
      process_value(context, &stmt.expression);
      process_expression(context, &stmt.expression);
    }

    Statement::ReturnStatement(stmt) => {
      if let Some(arg) = &stmt.argument {
        process_value(context, arg);
        process_expression(context, arg);
      }
    }

    Statement::ThrowStatement(stmt) => {
      process_value(context, &stmt.argument);
      process_expression(context, &stmt.argument);
    }

    Statement::ExportNamedDeclaration(export) => {
      if let Some(decl) = &export.declaration {
        process_declaration(context, decl);
      }
    }

    Statement::ExportDefaultDeclaration(export) => match &export.declaration {
      ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
        process_function(context, f);
      }
      ExportDefaultDeclarationKind::ClassDeclaration(c) => {
        process_class(context, c);
      }
      _ => {
        if let Some(expr) = export.declaration.as_expression() {
          process_value(context, expr);
          process_expression(context, expr);
        }
      }
    },

    Statement::TSModuleDeclaration(decl) => {
      if let Some(body) = &decl.body {
        match body {
          oxc_ast::ast::TSModuleDeclarationBody::TSModuleDeclaration(inner) => {
            if let Some(inner_body) = &inner.body
              && let oxc_ast::ast::TSModuleDeclarationBody::TSModuleBlock(block) =
                inner_body
            {
              process_statements(context, &block.body);
            }
          }
          oxc_ast::ast::TSModuleDeclarationBody::TSModuleBlock(block) => {
            process_statements(context, &block.body);
          }
        }
      }
    }

    _ => {}
  }
}

fn process_declaration(context: &mut JsContext<'_>, decl: &Declaration) {
  match decl {
    Declaration::VariableDeclaration(d) => {
      process_variable_declaration(context, d);
    }
    Declaration::FunctionDeclaration(f) => process_function(context, f),
    Declaration::ClassDeclaration(c) => process_class(context, c),
    Declaration::TSEnumDeclaration(e) => {
      process_enum_members(context, &e.body.members);
    }
    _ => {}
  }
}

fn process_variable_declaration(
  context: &mut JsContext<'_>,
  decl: &VariableDeclaration,
) {
  let assignment_type = match decl.kind {
    VariableDeclarationKind::Const => AssignmentType::Constant,
    VariableDeclarationKind::Let | VariableDeclarationKind::Var => {
      AssignmentType::Variable
    }
    _ => return,
  };
  for declarator in &decl.declarations {
    let Some(init) = &declarator.init else {
      continue;
    };
    match &declarator.id {
      BindingPattern::BindingIdentifier(id) => {
        let name: &str = &id.name;
        match init {
          Expression::FunctionExpression(f) => {
            register_signature(name, &f.params);
          }
          Expression::ArrowFunctionExpression(a) => {
            register_signature(name, &a.params);
          }
          _ => {}
        }
        check_expression_value(
          context,
          name,
          init,
          init.span(),
          assignment_type,
        );
      }
      BindingPattern::ObjectPattern(_) | BindingPattern::ArrayPattern(_) => {
        process_binding_pattern_defaults(
          context,
          &declarator.id,
          AssignmentType::Variable,
        );
        process_expression(context, init);
      }
      _ => {
        process_expression(context, init);
      }
    }
  }
}

fn process_binding_pattern_defaults(
  context: &mut JsContext<'_>,
  pattern: &BindingPattern,
  assignment_type: AssignmentType,
) {
  match pattern {
    BindingPattern::AssignmentPattern(assign) => {
      let BindingPattern::BindingIdentifier(id) = &assign.left else {
        process_binding_pattern_defaults(
          context,
          &assign.left,
          assignment_type,
        );
        return;
      };
      let name: &str = &id.name;
      check_expression_value(
        context,
        name,
        &assign.right,
        assign.right.span(),
        assignment_type,
      );
    }
    BindingPattern::ObjectPattern(obj) => {
      for prop in &obj.properties {
        process_binding_pattern_defaults(context, &prop.value, assignment_type);
      }
    }
    BindingPattern::ArrayPattern(arr) => {
      for element in arr.elements.iter().flatten() {
        process_binding_pattern_defaults(context, element, assignment_type);
      }
    }
    _ => {}
  }
}

fn process_expression(context: &mut JsContext<'_>, expression: &Expression) {
  process_value(context, expression);

  match expression {
    Expression::AssignmentExpression(assign)
      if assign.operator == AssignmentOperator::Assign
        || assign.operator == AssignmentOperator::LogicalOr
        || assign.operator == AssignmentOperator::LogicalNullish =>
    {
      if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left {
        let name: &str = &id.name;
        check_expression_value(
          context,
          name,
          &assign.right,
          assign.right.span(),
          AssignmentType::Variable,
        );
      } else if let AssignmentTarget::StaticMemberExpression(member) =
        &assign.left
      {
        let name: &str = &member.property.name;
        check_expression_value(
          context,
          name,
          &assign.right,
          assign.right.span(),
          AssignmentType::Property,
        );
      } else if let AssignmentTarget::ComputedMemberExpression(member) =
        &assign.left
        && let Some(key) = string_literal(&member.expression)
      {
        check_expression_value(
          context,
          &key,
          &assign.right,
          assign.right.span(),
          AssignmentType::Element,
        );
      } else {
        process_expression(context, &assign.right);
      }
    }

    Expression::SequenceExpression(seq) => {
      if let Some(last) = seq.expressions.last() {
        process_expression(context, last);
      }
    }

    Expression::CallExpression(call) => {
      if let Some(callee_name) = free_function_callee(&call.callee) {
        process_call_arguments(context, &callee_name, &call.arguments, true);
      }

      process_header_setter_call(context, call);
      process_expression(context, &call.callee);

      for arg in &call.arguments {
        if let Some(expr) = arg.as_expression() {
          process_expression(context, expr);
        }
      }

      if auth_call_name(&call.callee)
        .as_deref()
        .is_some_and(is_auth_call)
      {
        for arg in &call.arguments {
          if let Some(expr) = arg.as_expression() {
            check_expression_value(
              context,
              "password",
              expr,
              expr.span(),
              AssignmentType::Argument,
            );
          }
        }
      }
    }

    Expression::NewExpression(new_expr) => {
      if let Some(callee_name) = constructed_type_name(&new_expr.callee) {
        process_call_arguments(
          context,
          &callee_name,
          &new_expr.arguments,
          true,
        );
      }

      process_expression(context, &new_expr.callee);
      for arg in &new_expr.arguments {
        if let Some(expr) = arg.as_expression() {
          process_expression(context, expr);
        }
      }
    }

    Expression::ArrowFunctionExpression(arrow) => {
      process_parameters(context, &arrow.params);
      process_statements(context, &arrow.body.statements);
    }

    Expression::FunctionExpression(function) => {
      process_function(context, function);
    }

    Expression::ClassExpression(class) => {
      process_class(context, class);
    }

    Expression::ObjectExpression(obj) => {
      for prop in &obj.properties {
        let ObjectPropertyKind::ObjectProperty(prop) = prop else {
          continue;
        };
        if prop.method {
          if let Expression::FunctionExpression(f) = &prop.value {
            process_function(context, f);
          }
          continue;
        }
        if prop.kind != PropertyKind::Init {
          if let Expression::FunctionExpression(f) = &prop.value {
            process_function(context, f);
          }
          continue;
        }
        if prop.shorthand {
          continue;
        }

        let Some(key_name) = property_key_name(&prop.key) else {
          process_expression(context, &prop.value);
          continue;
        };

        if key_name == "headers"
          && let Expression::ObjectExpression(headers) = &prop.value
        {
          process_header_object(context, headers);
          continue;
        }

        check_expression_value(
          context,
          &key_name,
          &prop.value,
          prop.value.span(),
          AssignmentType::Element,
        );
      }
    }

    Expression::ArrayExpression(arr) => {
      use oxc_ast::ast::ArrayExpressionElement;
      for element in &arr.elements {
        match element {
          ArrayExpressionElement::SpreadElement(spread) => {
            process_expression(context, &spread.argument);
          }
          ArrayExpressionElement::Elision(_) => {
            // Array hole like `[1, , 3]`; nothing to scan.
          }
          _ => {
            if !element.is_spread() && !element.is_elision() {
              process_expression(context, element.to_expression());
            }
          }
        }
      }
    }

    Expression::JSXElement(el) => {
      process_jsx_attributes(context, &el.opening_element.attributes);
      process_jsx_children(context, &el.children);
    }

    Expression::JSXFragment(frag) => {
      process_jsx_children(context, &frag.children);
    }

    Expression::ParenthesizedExpression(paren) => {
      process_expression(context, &paren.expression);
    }
    Expression::TSAsExpression(expr) => {
      process_expression(context, &expr.expression);
    }
    Expression::TSSatisfiesExpression(expr) => {
      process_expression(context, &expr.expression);
    }
    Expression::TSTypeAssertion(expr) => {
      process_expression(context, &expr.expression);
    }
    Expression::TSNonNullExpression(expr) => {
      process_expression(context, &expr.expression);
    }
    Expression::ConditionalExpression(cond) => {
      process_expression(context, &cond.consequent);
      process_expression(context, &cond.alternate);
    }
    Expression::LogicalExpression(logical) => {
      process_expression(context, &logical.left);
      process_expression(context, &logical.right);
    }

    Expression::TemplateLiteral(tpl) => {
      for expr in &tpl.expressions {
        process_expression(context, expr);
      }
    }

    Expression::TaggedTemplateExpression(tagged) => {
      process_expression(context, &tagged.tag);
      for quasi in &tagged.quasi.quasis {
        let value: String = quasi
          .value
          .cooked
          .as_ref()
          .map(ToString::to_string)
          .unwrap_or_else(|| quasi.value.raw.to_string());
        if value.is_empty() {
          continue;
        }
        if context.already_emitted(quasi.span) {
          continue;
        }
        if let Some(d) =
          check_value(&normalize_value(&value), context.source_context, || {
            compute_source_span(context, quasi.span)
          })
        {
          context.record_emitted(quasi.span);
          context.source_context.emit_diagnostic(d);
        }
      }
      for expr in &tagged.quasi.expressions {
        process_expression(context, expr);
      }
    }

    Expression::AwaitExpression(await_expr) => {
      process_expression(context, &await_expr.argument);
    }

    Expression::YieldExpression(yield_expr) => {
      if let Some(arg) = &yield_expr.argument {
        process_expression(context, arg);
      }
    }

    Expression::UnaryExpression(unary) => {
      process_expression(context, &unary.argument);
    }

    Expression::ImportExpression(import) => {
      process_expression(context, &import.source);
      if let Some(options) = &import.options {
        process_expression(context, options);
      }
    }

    Expression::BinaryExpression(bin) => {
      process_expression(context, &bin.left);
      process_expression(context, &bin.right);
    }

    Expression::ChainExpression(chain) => {
      use oxc_ast::ast::ChainElement;
      match &chain.expression {
        ChainElement::CallExpression(call) => {
          process_expression(context, &call.callee);
          for arg in &call.arguments {
            if let Some(expr) = arg.as_expression() {
              process_expression(context, expr);
            }
          }
        }
        ChainElement::TSNonNullExpression(tn) => {
          process_expression(context, &tn.expression);
        }
        ChainElement::ComputedMemberExpression(m) => {
          process_expression(context, &m.object);
          process_expression(context, &m.expression);
        }
        ChainElement::StaticMemberExpression(m) => {
          process_expression(context, &m.object);
        }
        ChainElement::PrivateFieldExpression(m) => {
          process_expression(context, &m.object);
        }
      }
    }

    _ => {}
  }
}

fn process_jsx_children(
  context: &mut JsContext<'_>,
  children: &[oxc_ast::ast::JSXChild],
) {
  use oxc_ast::ast::{JSXChild, JSXExpression};
  for child in children {
    match child {
      JSXChild::Element(el) => {
        process_jsx_attributes(context, &el.opening_element.attributes);
        process_jsx_children(context, &el.children);
      }
      JSXChild::Fragment(frag) => {
        process_jsx_children(context, &frag.children);
      }
      JSXChild::ExpressionContainer(container) => match &container.expression {
        JSXExpression::EmptyExpression(_) => {}
        expr => {
          process_expression(context, expr.to_expression());
        }
      },
      JSXChild::Spread(spread) => {
        process_expression(context, &spread.expression);
      }
      JSXChild::Text(_) => {}
    }
  }
}

fn process_jsx_attributes(
  context: &mut JsContext<'_>,
  attributes: &[JSXAttributeItem],
) {
  for attr in attributes {
    let attr = match attr {
      JSXAttributeItem::Attribute(a) => a,
      JSXAttributeItem::SpreadAttribute(spread) => {
        process_expression(context, &spread.argument);
        continue;
      }
    };
    let name: &str = match &attr.name {
      JSXAttributeName::Identifier(name_id) => &name_id.name,
      JSXAttributeName::NamespacedName(ns) => &ns.name.name,
    };
    match &attr.value {
      Some(JSXAttributeValue::StringLiteral(lit)) => {
        process_assignment(
          context,
          name,
          &lit.value,
          lit.span,
          AssignmentType::Attribute,
        );
      }
      Some(JSXAttributeValue::ExpressionContainer(container)) => {
        match &container.expression {
          oxc_ast::ast::JSXExpression::EmptyExpression(_) => {}
          expr => {
            check_expression_value(
              context,
              name,
              expr.to_expression(),
              expr.to_expression().span(),
              AssignmentType::Attribute,
            );
          }
        }
      }
      _ => {}
    }
  }
}

fn process_function(context: &mut JsContext<'_>, function: &Function) {
  if let Some(id) = &function.id {
    register_signature(&id.name, &function.params);
  }
  process_parameters(context, &function.params);
  if let Some(body) = &function.body {
    process_statements(context, &body.statements);
  }
}

fn process_parameters(context: &mut JsContext<'_>, params: &FormalParameters) {
  for param in &params.items {
    match &param.pattern {
      BindingPattern::BindingIdentifier(id) => {
        let Some(init) = &param.initializer else {
          continue;
        };
        let name: &str = &id.name;
        check_expression_value(
          context,
          name,
          init,
          init.span(),
          AssignmentType::Parameter,
        );
      }
      pattern => {
        process_binding_pattern_defaults(
          context,
          pattern,
          AssignmentType::Parameter,
        );
        if let Some(init) = &param.initializer {
          process_expression(context, init);
        }
      }
    }
  }
}

fn process_class(context: &mut JsContext<'_>, class: &Class) {
  let class_name = class.id.as_ref().map(|id| id.name.as_str());

  for element in &class.body.body {
    match element {
      ClassElement::MethodDefinition(method) => {
        if let Some(class_name) = class_name
          && let Some(name) = property_key_name(&method.key)
          && name == "constructor"
        {
          register_signature(class_name, &method.value.params);
        }
        process_function(context, &method.value);
      }
      ClassElement::PropertyDefinition(prop) => {
        if let Some(init) = &prop.value {
          let Some(name) = property_key_name(&prop.key) else {
            continue;
          };
          check_expression_value(
            context,
            &name,
            init,
            init.span(),
            AssignmentType::Property,
          );
        }
      }
      ClassElement::AccessorProperty(prop) => {
        if let Some(init) = &prop.value {
          let Some(name) = property_key_name(&prop.key) else {
            continue;
          };
          check_expression_value(
            context,
            &name,
            init,
            init.span(),
            AssignmentType::Property,
          );
        }
      }
      ClassElement::StaticBlock(block) => {
        process_statements(context, &block.body);
      }
      _ => {}
    }
  }
}

fn process_enum_members(
  context: &mut JsContext<'_>,
  members: &[oxc_ast::ast::TSEnumMember],
) {
  for member in members {
    let Some(init) = &member.initializer else {
      continue;
    };
    let Some(name) = enum_member_name(&member.id) else {
      continue;
    };
    check_expression_value(
      context,
      &name,
      init,
      init.span(),
      AssignmentType::Constant,
    );
  }
}

fn property_key_name(key: &PropertyKey) -> Option<String> {
  match key {
    PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
    PropertyKey::StringLiteral(lit) => Some(lit.value.to_string()),
    _ => None,
  }
}

fn enum_member_name(name: &oxc_ast::ast::TSEnumMemberName) -> Option<String> {
  match name {
    oxc_ast::ast::TSEnumMemberName::Identifier(id) => Some(id.name.to_string()),
    oxc_ast::ast::TSEnumMemberName::String(lit) => Some(lit.value.to_string()),
    _ => None,
  }
}

fn string_literal(expression: &Expression) -> Option<String> {
  match expression {
    Expression::StringLiteral(lit) => Some(lit.value.to_string()),
    Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
      let mut result = String::new();
      for quasi in &tpl.quasis {
        result.push_str(&quasi.value.raw);
      }
      Some(result)
    }
    Expression::ParenthesizedExpression(paren) => {
      string_literal(&paren.expression)
    }
    Expression::TSAsExpression(expr) => string_literal(&expr.expression),
    Expression::TSSatisfiesExpression(expr) => string_literal(&expr.expression),
    Expression::TSTypeAssertion(expr) => string_literal(&expr.expression),
    Expression::TSNonNullExpression(expr) => string_literal(&expr.expression),
    Expression::BinaryExpression(bin)
      if bin.operator == BinaryOperator::Addition =>
    {
      let left = string_literal(&bin.left)?;
      let right = string_literal(&bin.right)?;
      Some(left + &right)
    }
    _ => None,
  }
}

fn process_header_setter_call(
  context: &mut JsContext<'_>,
  call: &oxc_ast::ast::CallExpression<'_>,
) {
  let Expression::StaticMemberExpression(member) = &call.callee else {
    return;
  };

  if !matches!(
    member.property.name.as_str(),
    "setHeader" | "setRequestHeader"
  ) {
    return;
  }

  let exprs: Vec<&Expression> = call
    .arguments
    .iter()
    .filter_map(|a| a.as_expression())
    .collect();

  if exprs.len() >= 2
    && let Some(name) = string_literal(exprs[0])
  {
    check_expression_value(
      context,
      &name,
      exprs[1],
      exprs[1].span(),
      AssignmentType::Header,
    );
  }
}

fn process_header_object(
  context: &mut JsContext<'_>,
  obj: &oxc_ast::ast::ObjectExpression<'_>,
) {
  for prop in &obj.properties {
    let ObjectPropertyKind::ObjectProperty(prop) = prop else {
      continue;
    };
    if prop.method || prop.shorthand || prop.kind != PropertyKind::Init {
      continue;
    }
    let Some(key_name) = property_key_name(&prop.key) else {
      continue;
    };
    check_expression_value(
      context,
      &key_name,
      &prop.value,
      prop.value.span(),
      AssignmentType::Header,
    );
  }
}

fn check_expression_value(
  context: &mut JsContext<'_>,
  name: &str,
  expression: &Expression,
  span: oxc_span::Span,
  assignment_type: AssignmentType,
) {
  if let Some(value) = string_literal(expression) {
    let value_span = expression.span();
    if context.already_emitted(value_span) {
      return;
    }

    context.record_emitted(value_span);

    let diag = if assignment_type == AssignmentType::Header {
      check_header_assignment(name, &value, context.source_context, || {
        compute_source_span(context, span)
      })
    } else {
      check_assignment(
        &normalize_name(&name.to_owned()),
        &normalize_value(&value),
        assignment_type,
        context.source_context,
        || compute_source_span(context, span),
      )
    };

    if let Some(d) = diag {
      context.source_context.emit_diagnostic(d);
    }

    return;
  }
  match expression {
    Expression::ConditionalExpression(cond) => {
      check_expression_value(
        context,
        name,
        &cond.consequent,
        cond.consequent.span(),
        assignment_type,
      );
      check_expression_value(
        context,
        name,
        &cond.alternate,
        cond.alternate.span(),
        assignment_type,
      );
    }
    Expression::LogicalExpression(logical)
      if logical.operator == LogicalOperator::Or
        || logical.operator == LogicalOperator::Coalesce =>
    {
      check_expression_value(
        context,
        name,
        &logical.left,
        logical.left.span(),
        assignment_type,
      );
      check_expression_value(
        context,
        name,
        &logical.right,
        logical.right.span(),
        assignment_type,
      );
    }
    Expression::SequenceExpression(seq) => {
      if let Some(last) = seq.expressions.last() {
        check_expression_value(context, name, last, span, assignment_type);
      }
    }
    Expression::ParenthesizedExpression(paren) => {
      check_expression_value(
        context,
        name,
        &paren.expression,
        span,
        assignment_type,
      );
    }
    Expression::TSAsExpression(expr) => {
      check_expression_value(
        context,
        name,
        &expr.expression,
        span,
        assignment_type,
      );
    }
    Expression::TSSatisfiesExpression(expr) => {
      check_expression_value(
        context,
        name,
        &expr.expression,
        span,
        assignment_type,
      );
    }
    Expression::TSTypeAssertion(expr) => {
      check_expression_value(
        context,
        name,
        &expr.expression,
        span,
        assignment_type,
      );
    }
    Expression::TSNonNullExpression(expr) => {
      check_expression_value(
        context,
        name,
        &expr.expression,
        span,
        assignment_type,
      );
    }
    Expression::BinaryExpression(bin)
      if bin.operator == BinaryOperator::Addition =>
    {
      check_expression_value(context, name, &bin.left, span, assignment_type);
      check_expression_value(context, name, &bin.right, span, assignment_type);
    }
    Expression::TemplateLiteral(tpl) => {
      for quasi in &tpl.quasis {
        let value: String = quasi
          .value
          .cooked
          .as_ref()
          .map(ToString::to_string)
          .unwrap_or_else(|| quasi.value.raw.to_string());
        if value.is_empty() {
          continue;
        }
        if context.already_emitted(quasi.span) {
          continue;
        }

        if let Some(d) =
          check_value(&normalize_value(&value), context.source_context, || {
            compute_source_span(context, quasi.span)
          })
        {
          context.record_emitted(quasi.span);
          context.source_context.emit_diagnostic(d);
        }
      }
      for expr in &tpl.expressions {
        process_expression(context, expr);
      }
    }
    Expression::TaggedTemplateExpression(tagged) => {
      for quasi in &tagged.quasi.quasis {
        let value: String = quasi
          .value
          .cooked
          .as_ref()
          .map(ToString::to_string)
          .unwrap_or_else(|| quasi.value.raw.to_string());

        if value.is_empty() {
          continue;
        }

        if context.already_emitted(quasi.span) {
          continue;
        }

        if let Some(d) =
          check_value(&normalize_value(&value), context.source_context, || {
            compute_source_span(context, quasi.span)
          })
        {
          context.record_emitted(quasi.span);
          context.source_context.emit_diagnostic(d);
        }
      }

      for expr in &tagged.quasi.expressions {
        process_expression(context, expr);
      }

      process_expression(context, &tagged.tag);
    }
    Expression::CallExpression(call) => {
      for arg in &call.arguments {
        if let Some(expr) = arg.as_expression() {
          check_expression_value(context, name, expr, span, assignment_type);
        }
      }
      process_expression(context, expression);
    }
    Expression::NewExpression(new_expr) => {
      for arg in &new_expr.arguments {
        if let Some(expr) = arg.as_expression() {
          check_expression_value(context, name, expr, span, assignment_type);
        }
      }
      process_expression(context, expression);
    }
    Expression::ArrayExpression(array) => {
      use oxc_ast::ast::ArrayExpressionElement;
      for element in &array.elements {
        match element {
          ArrayExpressionElement::SpreadElement(spread) => {
            process_expression(context, &spread.argument);
          }
          ArrayExpressionElement::Elision(_) => {}
          _ => {
            let expr = element.to_expression();
            if string_literal(expr).is_some() {
              check_expression_value(
                context,
                name,
                expr,
                expr.span(),
                assignment_type,
              );
            } else {
              process_expression(context, expr);
            }
          }
        }
      }
    }
    _ => process_expression(context, expression),
  }
}

fn register_signature(name: &str, params: &FormalParameters) {
  let parameter_names: Vec<String> = params
    .items
    .iter()
    .filter_map(|p| {
      if let BindingPattern::BindingIdentifier(id) = &p.pattern {
        Some(id.name.to_string())
      } else {
        None
      }
    })
    .collect();

  ANALYZER.with(|a| {
    a.borrow_mut()
      .add_signature(name.to_owned(), FunctionSignature { parameter_names });
  });
}

fn free_function_callee(expression: &Expression) -> Option<String> {
  match expression {
    Expression::Identifier(id) => Some(id.name.to_string()),
    _ => None,
  }
}

fn auth_call_name(expression: &Expression) -> Option<String> {
  match expression {
    Expression::Identifier(id) => Some(id.name.to_string()),
    Expression::StaticMemberExpression(member) => {
      Some(member.property.name.to_string())
    }
    _ => None,
  }
}

fn is_auth_call(name: &str) -> bool {
  let lower = name.to_ascii_lowercase();
  lower.contains("login")
    || lower.contains("signin")
    || lower.contains("authenticate")
    || lower.contains("logon")
}

fn constructed_type_name(expression: &Expression) -> Option<String> {
  match expression {
    Expression::Identifier(id) => Some(id.name.to_string()),
    Expression::StaticMemberExpression(member) => {
      Some(member.property.name.to_string())
    }
    _ => None,
  }
}

fn process_call_arguments(
  context: &mut JsContext<'_>,
  callee_name: &str,
  arguments: &[oxc_ast::ast::Argument],
  save_call_frame: bool,
) {
  let extracted: Vec<(String, oxc_span::Span)> = arguments
    .iter()
    .filter_map(|arg| {
      let expr = arg.as_expression()?;
      let value = string_literal(expr)?;
      Some((value, expr.span()))
    })
    .collect();

  if extracted.is_empty() {
    return;
  }

  let resolved = ANALYZER.with(|a| {
    let analyzer = a.borrow();
    if let Some(signature) = analyzer.get_signature(callee_name) {
      resolve_arguments(context, signature, &extracted);
      true
    } else {
      false
    }
  });

  if !resolved && save_call_frame {
    ANALYZER.with(|a| {
      a.borrow_mut().add_frame(CallFrame {
        callee: callee_name.to_owned(),
        arguments: extracted,
      });
    });
  }
}

fn resolve_arguments(
  context: &mut JsContext<'_>,
  signature: &FunctionSignature,
  arguments: &[(String, oxc_span::Span)],
) {
  for (i, (value, span)) in arguments.iter().enumerate() {
    let Some(param_name) = signature.parameter_names.get(i) else {
      break;
    };
    process_assignment(
      context,
      param_name,
      value,
      *span,
      AssignmentType::Argument,
    );
  }
}

fn process_value(context: &mut JsContext<'_>, expression: &Expression) {
  if let Some(value) = string_literal(expression) {
    let span = expression.span();
    if context.already_emitted(span) {
      return;
    }

    if let Some(d) =
      check_value(&normalize_value(&value), context.source_context, || {
        compute_source_span(context, span)
      })
    {
      context.record_emitted(span);
      context.source_context.emit_diagnostic(d);
    }
    return;
  }

  if let Expression::TemplateLiteral(tpl) = expression {
    for quasi in &tpl.quasis {
      let value: String = quasi
        .value
        .cooked
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| quasi.value.raw.to_string());
      if value.is_empty() {
        continue;
      }
      if context.already_emitted(quasi.span) {
        continue;
      }
      if let Some(d) =
        check_value(&normalize_value(&value), context.source_context, || {
          compute_source_span(context, quasi.span)
        })
      {
        context.record_emitted(quasi.span);
        context.source_context.emit_diagnostic(d);
      }
    }
  }
}

fn process_assignment(
  context: &mut JsContext<'_>,
  name: &str,
  value: &str,
  span: oxc_span::Span,
  assignment_type: AssignmentType,
) {
  if context.already_emitted(span) {
    return;
  }

  let name = name.to_owned();
  let value = value.to_owned();

  if let Some(d) = check_assignment(
    &normalize_name(&name),
    &normalize_value(&value),
    assignment_type,
    context.source_context,
    || compute_source_span(context, span),
  ) {
    context.record_emitted(span);
    context.source_context.emit_diagnostic(d);
  }
}

fn compute_source_span(
  context: &JsContext<'_>,
  span: oxc_span::Span,
) -> SourceFileSpan {
  compute_file_span(
    context.source_context,
    context.source,
    span.start as usize,
    span.end as usize,
  )
}
