use std::cell::RefCell;

use mago_ast::{
  Access, Argument, ArgumentList, ArrayAccess, ArrayElement, Assignment,
  AssignmentOperator, Binary, BinaryOperator, Call, ClassLikeConstant,
  ClassLikeConstantItem, ClassLikeMember, ClassLikeMemberSelector,
  CompositeString, Conditional, Constant, ConstantItem, Construct, DeclareBody,
  Expression, ExpressionStatement, ForBody, ForeachBody,
  FunctionLikeParameterList, Identifier, IfBody, IfStatementBody,
  KeyValueArrayElement, LegacyArray, Literal, LiteralString, Match, MatchArm,
  MethodBody, NamedArgument, NamespaceBody, NullSafePropertyAccess,
  PlainProperty, PositionalArgument, Property, PropertyAccess,
  PropertyConcreteItem, PropertyItem, Sequence, Statement, StaticConcreteItem,
  StaticItem, StringPart, SwitchBody, SwitchCase, ValueArrayElement, Variable,
  WhileBody,
};
use mago_interner::ThreadedInterner;
use mago_parser::parse_source;
use mago_source::Source;
use mago_span::HasSpan;

use crate::{
  analysis::{Analyzer, CallFrame, FunctionSignature},
  diagnostic::{
    AssignmentType, SourceFileSpan, SourcePosition, SourceSpan,
    check_assignment, check_header_assignment, check_value,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
  source::compute_line_starts,
};

type E = Expression;

struct PhpContext<'a> {
  interner: &'a ThreadedInterner,
  source_context: &'a SourceContext<'a>,
  line_starts: RefCell<Option<Vec<usize>>>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> PhpContext<'a> {
  fn already_emitted(&self, span: &mago_span::Span) -> bool {
    let (s, e) = (span.start.offset, span.end.offset);
    self
      .emitted_value_ranges
      .iter()
      .any(|(rs, re)| *rs <= s && *re >= e)
  }

  fn record_emitted(&mut self, span: &mago_span::Span) {
    self
      .emitted_value_ranges
      .push((span.start.offset, span.end.offset));
  }
}

thread_local! {
  static ANALYZER: RefCell<Analyzer<String, mago_span::Span>> = RefCell::new(
    Analyzer::new()
  );
}

macro_rules! lookup_variable_name {
  ($context:expr, $variable:expr) => {
    $context.interner.lookup(&$variable.name).trim_start_matches('$')
  };
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(body) = context.body else {
    return false;
  };

  let markup = crate::languages::html::scan(context, &mask_php(body));

  scan(context, body) || markup
}

pub fn scan(context: &SourceContext, source: &str) -> bool {
  let path_str = context.file_abs_path.to_str().unwrap_or_default();

  let interner = ThreadedInterner::new();
  let parsed = Source::standalone(&interner, path_str, source);
  let (program, parse_error) = parse_source(&interner, &parsed);

  if parse_error.is_some() {
    return false;
  }

  ANALYZER.with(|a| a.borrow_mut().clear());

  let mut ctx = PhpContext {
    interner: &interner,
    source_context: context,
    line_starts: RefCell::new(None),
    emitted_value_ranges: Vec::new(),
  };

  process_statements(&mut ctx, &program.statements);

  ANALYZER.with(|a| {
    a.borrow().resolve_calls(|signature, arguments| {
      resolve_arguments(&mut ctx, signature, arguments);
    });
  });

  true
}

// Blanks every `<?php ... ?>` region (newlines kept) so the HTML markup pass
// sees only inline markup, never PHP code or the contents of PHP strings. Byte
// length and line breaks are preserved so reported spans stay accurate.
fn mask_php(source: &str) -> String {
  let bytes = source.as_bytes();
  let mut masked = Vec::with_capacity(bytes.len());
  let mut i = 0;

  while i < bytes.len() {
    if bytes[i] == b'<' && bytes.get(i + 1) == Some(&b'?') {
      let mut end = bytes.len();
      let mut j = i + 2;
      while j + 1 < bytes.len() {
        if bytes[j] == b'?' && bytes[j + 1] == b'>' {
          end = j + 2;
          break;
        }
        j += 1;
      }
      for &byte in &bytes[i..end] {
        masked.push(if byte == b'\n' { b'\n' } else { b' ' });
      }
      i = end;
    } else {
      masked.push(bytes[i]);
      i += 1;
    }
  }

  String::from_utf8(masked).unwrap_or_else(|_| source.to_owned())
}

fn process_statements(
  context: &mut PhpContext,
  statements: &Sequence<Statement>,
) {
  for statement in statements.iter() {
    process_statement(context, statement);
  }
}

fn process_statement(context: &mut PhpContext, statement: &Statement) {
  match statement {
    Statement::Block(block) => {
      process_statements(context, &block.statements);
    }
    Statement::Function(function) => {
      let name = context.interner.lookup(&function.name.value).to_owned();
      register_signature(context, &name, &function.parameter_list);
      process_parameters(context, &function.parameter_list);
      process_statements(context, &function.body.statements);
    }
    Statement::Constant(constant) => {
      process_constant(context, constant);
    }
    Statement::Class(class) => {
      process_members(context, &class.members);
    }
    Statement::Interface(interface) => {
      process_members(context, &interface.members);
    }
    Statement::Trait(r#trait) => {
      process_members(context, &r#trait.members);
    }
    Statement::Enum(r#enum) => {
      process_members(context, &r#enum.members);
    }
    Statement::Echo(echo) => {
      for value in echo.values.iter() {
        process_expression(context, value);
      }
    }
    Statement::Static(r#static) => {
      for item in r#static.items.iter() {
        let StaticItem::Concrete(StaticConcreteItem {
          variable, value, ..
        }) = item
        else {
          continue;
        };
        let name = lookup_variable_name!(context, &variable);
        check_expression_value(
          context,
          name,
          value,
          &value.span(),
          AssignmentType::Variable,
        );
      }
    }
    Statement::Return(r#return) => {
      if let Some(value) = &r#return.value {
        process_expression(context, value);
      }
    }
    Statement::Expression(ExpressionStatement { expression, .. }) => {
      process_expression(context, expression);
    }
    Statement::If(r#if) => match &r#if.body {
      IfBody::Statement(IfStatementBody {
        statement,
        else_if_clauses,
        else_clause,
      }) => {
        process_statement(context, statement);
        for clause in else_if_clauses.iter() {
          process_statement(context, &clause.statement);
        }
        if let Some(clause) = else_clause {
          process_statement(context, &clause.statement);
        }
      }
      IfBody::ColonDelimited(body) => {
        process_statements(context, &body.statements);
        for clause in body.else_if_clauses.iter() {
          process_statements(context, &clause.statements);
        }
        if let Some(clause) = &body.else_clause {
          process_statements(context, &clause.statements);
        }
      }
    },
    Statement::Foreach(foreach) => match &foreach.body {
      ForeachBody::Statement(stmt) => process_statement(context, stmt),
      ForeachBody::ColonDelimited(body) => {
        process_statements(context, &body.statements);
      }
    },
    Statement::For(r#for) => {
      for expr in r#for.initializations.iter() {
        process_expression(context, expr);
      }
      for expr in r#for.increments.iter() {
        process_expression(context, expr);
      }
      match &r#for.body {
        ForBody::Statement(stmt) => process_statement(context, stmt),
        ForBody::ColonDelimited(body) => {
          process_statements(context, &body.statements);
        }
      }
    }
    Statement::While(r#while) => match &r#while.body {
      WhileBody::Statement(stmt) => process_statement(context, stmt),
      WhileBody::ColonDelimited(body) => {
        process_statements(context, &body.statements);
      }
    },
    Statement::DoWhile(do_while) => {
      process_statement(context, &do_while.statement);
    }
    Statement::Switch(switch) => {
      let cases = match &switch.body {
        SwitchBody::BraceDelimited(body) => &body.cases,
        SwitchBody::ColonDelimited(body) => &body.cases,
      };
      for case in cases.iter() {
        match case {
          SwitchCase::Expression(c) => {
            process_expression(context, &c.expression);
            process_statements(context, &c.statements);
          }
          SwitchCase::Default(c) => {
            process_statements(context, &c.statements);
          }
        }
      }
    }
    Statement::Try(r#try) => {
      process_statements(context, &r#try.block.statements);
      for clause in r#try.catch_clauses.iter() {
        process_statements(context, &clause.block.statements);
      }
      if let Some(finally) = &r#try.finally_clause {
        process_statements(context, &finally.block.statements);
      }
    }
    Statement::Namespace(namespace) => match &namespace.body {
      NamespaceBody::Implicit(body) => {
        process_statements(context, &body.statements);
      }
      NamespaceBody::BraceDelimited(block) => {
        process_statements(context, &block.statements);
      }
    },
    Statement::Declare(declare) => {
      if let DeclareBody::ColonDelimited(body) = &declare.body {
        process_statements(context, &body.statements);
      } else if let DeclareBody::Statement(stmt) = &declare.body {
        process_statement(context, stmt);
      }
    }
    _ => {}
  }
}

fn process_expression(context: &mut PhpContext, expression: &Expression) {
  match expression {
    E::Call(call) => {
      #[derive(PartialEq)]
      enum CallType {
        Function,
        Method,
      }

      use CallType::*;

      let (callee_name, argument_list, call_type) = match call {
        Call::Function(c) => (
          callee_identifier(context, &c.function),
          &c.argument_list,
          Function,
        ),
        Call::Method(c) => {
          (callee_member(context, &c.method), &c.argument_list, Method)
        }
        Call::NullSafeMethod(c) => {
          (callee_member(context, &c.method), &c.argument_list, Method)
        }
        Call::StaticMethod(c) => {
          (callee_member(context, &c.method), &c.argument_list, Method)
        }
      };

      process_named_arguments(context, argument_list);

      if call_type == Function
        && let Some(callee_name) = &callee_name
      {
        if callee_name == "header" {
          process_header_function(context, argument_list);
        } else if callee_name == "setcookie" || callee_name == "setrawcookie" {
          process_setcookie(context, argument_list);
        } else if callee_name == "define" {
          process_define(context, argument_list);
        } else {
          process_positional_arguments(
            context,
            callee_name,
            argument_list,
            true,
          );
        }
      } else if call_type == Method
        && let Some(method) = &callee_name
        && HEADER_METHODS.contains(&method.as_str())
      {
        process_header_method(context, argument_list);
      }

      for argument in argument_list.arguments.iter() {
        if let Argument::Positional(PositionalArgument { value, .. }) = argument
        {
          process_expression(context, value);
        }
      }
    }

    E::Assignment(Assignment {
      lhs,
      operator: AssignmentOperator::Assign(_) | AssignmentOperator::Coalesce(_),
      rhs,
    }) => match lhs.as_ref() {
      E::Variable(Variable::Direct(variable)) => {
        let name = lookup_variable_name!(context, &variable);
        check_expression_value(
          context,
          name,
          rhs,
          &rhs.span(),
          AssignmentType::Variable,
        );
      }
      E::Access(
        Access::Property(PropertyAccess { property, .. })
        | Access::NullSafeProperty(NullSafePropertyAccess { property, .. }),
      ) => {
        if let Some(name) = callee_member(context, property) {
          check_expression_value(
            context,
            &name,
            rhs,
            &rhs.span(),
            AssignmentType::Property,
          );
        } else {
          process_expression(context, rhs);
        }
      }
      E::ArrayAccess(ArrayAccess { index, .. }) => {
        if let Some(key) = string_literal(context, index) {
          check_expression_value(
            context,
            &key,
            rhs,
            &rhs.span(),
            AssignmentType::Element,
          );
        } else {
          process_expression(context, rhs);
        }
      }
      _ => process_expression(context, rhs),
    },

    E::Array(array) => {
      process_array_elements(context, &array.elements);
    }

    E::LegacyArray(LegacyArray { elements, .. }) => {
      process_array_elements(context, elements);
    }

    E::Parenthesized(parenthesized) => {
      process_expression(context, &parenthesized.expression);
    }

    E::Conditional(Conditional { then, r#else, .. }) => {
      if let Some(then) = then {
        process_expression(context, then);
      }
      process_expression(context, r#else);
    }

    E::Match(Match { arms, .. }) => {
      for arm in arms.iter() {
        match arm {
          MatchArm::Expression(a) => {
            for condition in a.conditions.iter() {
              process_expression(context, condition);
            }
            process_expression(context, &a.expression);
          }
          MatchArm::Default(a) => process_expression(context, &a.expression),
        }
      }
    }

    E::Closure(closure) => {
      register_signature(
        context,
        &format!("closure@{}", closure.function.span.start.offset),
        &closure.parameter_list,
      );
      process_parameters(context, &closure.parameter_list);
      process_statements(context, &closure.body.statements);
    }

    E::ArrowFunction(arrow) => {
      process_parameters(context, &arrow.parameter_list);
      process_expression(context, &arrow.expression);
    }

    E::Construct(construct) => match construct {
      Construct::Print(c) => process_expression(context, &c.value),
      Construct::Exit(c) => {
        if let Some(args) = &c.arguments {
          process_argument_expressions(context, args);
        }
      }
      Construct::Die(c) => {
        if let Some(args) = &c.arguments {
          process_argument_expressions(context, args);
        }
      }
      Construct::Eval(c) => process_expression(context, &c.value),
      _ => {}
    },

    E::Throw(throw) => {
      process_expression(context, &throw.exception);
    }

    E::Instantiation(instantiation) => {
      if let Some(args) = &instantiation.arguments {
        process_named_arguments(context, args);
        for argument in args.arguments.iter() {
          if let Argument::Positional(PositionalArgument { value, .. }) =
            argument
          {
            process_expression(context, value);
          }
        }
      }
    }

    E::Literal(Literal::String(_))
    | E::CompositeString(_)
    | E::Binary(Binary {
      operator: BinaryOperator::StringConcat(_),
      ..
    }) => {
      process_value(context, expression);
    }

    _ => {}
  }
}

fn process_value(context: &mut PhpContext, expression: &Expression) {
  let Some(value) = string_literal(context, expression) else {
    return;
  };

  let span = expression.span();
  if context.already_emitted(&span) {
    return;
  }

  if let Some(d) =
    check_value(&normalize_value(&value), context.source_context, || {
      compute_source_span(context, &span)
    })
  {
    context.record_emitted(&span);
    context.source_context.emit_diagnostic(d);
  }
}

fn process_members(
  context: &mut PhpContext,
  members: &Sequence<ClassLikeMember>,
) {
  for member in members.iter() {
    match member {
      ClassLikeMember::Constant(constant) => {
        process_class_constant(context, constant);
      }
      ClassLikeMember::Property(Property::Plain(property)) => {
        process_property(context, property);
      }
      ClassLikeMember::Method(method) => {
        process_parameters(context, &method.parameter_list);
        if let MethodBody::Concrete(block) = &method.body {
          process_statements(context, &block.statements);
        }
      }
      _ => {}
    }
  }
}

fn register_signature(
  context: &PhpContext,
  name: &str,
  FunctionLikeParameterList { parameters, .. }: &FunctionLikeParameterList,
) {
  let parameter_names: Vec<String> = parameters
    .iter()
    .map(|p| lookup_variable_name!(context, &p.variable).to_owned())
    .collect();

  ANALYZER.with(|a| {
    a.borrow_mut()
      .add_signature(name.to_owned(), FunctionSignature { parameter_names });
  });
}

fn callee_identifier(
  context: &PhpContext,
  expression: &Expression,
) -> Option<String> {
  if let E::Identifier(Identifier::Local(identifier)) = expression {
    Some(context.interner.lookup(&identifier.value).to_owned())
  } else {
    None
  }
}

fn callee_member(
  context: &PhpContext,
  selector: &ClassLikeMemberSelector,
) -> Option<String> {
  if let ClassLikeMemberSelector::Identifier(identifier) = selector {
    Some(context.interner.lookup(&identifier.value).to_owned())
  } else {
    None
  }
}

fn process_positional_arguments(
  context: &mut PhpContext,
  callee_name: &str,
  ArgumentList { arguments, .. }: &ArgumentList,
  save_call_frame: bool,
) {
  let extracted: Vec<(String, mago_span::Span)> = arguments
    .iter()
    .filter_map(|argument| {
      let Argument::Positional(PositionalArgument { value, .. }) = argument
      else {
        return None;
      };
      let extracted_value = string_literal(context, value)?;
      Some((extracted_value, value.span()))
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

const HEADER_METHODS: &[&str] =
  &["addHeader", "setHeader", "withAddedHeader", "withHeader"];

fn process_header_function(
  context: &mut PhpContext,
  argument_list: &ArgumentList,
) {
  let Some(Argument::Positional(PositionalArgument { value, .. })) =
    argument_list.arguments.iter().next()
  else {
    return;
  };
  let Some(header) = string_literal(context, value) else {
    return;
  };
  let Some((name, header_value)) = header.split_once(':') else {
    return;
  };

  let name = name.trim();
  let header_value = header_value.trim();
  if name.is_empty() || header_value.is_empty() {
    return;
  }

  let span = value.span();
  if context.already_emitted(&span) {
    return;
  }

  context.record_emitted(&span);

  if let Some(d) =
    check_header_assignment(name, header_value, context.source_context, || {
      compute_source_span(context, &span)
    })
  {
    context.source_context.emit_diagnostic(d);
  }
}

fn process_setcookie(context: &mut PhpContext, argument_list: &ArgumentList) {
  // setcookie("name", "value", ...) / setrawcookie(...): arg 0 is the cookie
  // name (used as the secret name) and arg 1 is its value, both stored in a
  // Set-Cookie response header.
  let mut positionals = argument_list.arguments.iter().filter_map(|argument| {
    if let Argument::Positional(PositionalArgument { value, .. }) = argument {
      Some(value)
    } else {
      None
    }
  });

  let Some(name_expr) = positionals.next() else {
    return;
  };
  let Some(value_expr) = positionals.next() else {
    return;
  };
  let Some(name) = string_literal(context, name_expr) else {
    return;
  };

  check_expression_value(
    context,
    &name,
    value_expr,
    &value_expr.span(),
    AssignmentType::Header,
  );
}

fn process_header_method(
  context: &mut PhpContext,
  argument_list: &ArgumentList,
) {
  let mut positionals = argument_list.arguments.iter().filter_map(|argument| {
    if let Argument::Positional(PositionalArgument { value, .. }) = argument {
      Some(value)
    } else {
      None
    }
  });

  let Some(name_expr) = positionals.next() else {
    return;
  };
  let Some(value_expr) = positionals.next() else {
    return;
  };
  let Some(name) = string_literal(context, name_expr) else {
    return;
  };

  check_expression_value(
    context,
    &name,
    value_expr,
    &value_expr.span(),
    AssignmentType::Header,
  );
}

fn resolve_arguments(
  context: &mut PhpContext,
  signature: &FunctionSignature,
  arguments: &[(String, mago_span::Span)],
) {
  for (i, (value, span)) in arguments.iter().enumerate() {
    let Some(param_name) = signature.parameter_names.get(i) else {
      break;
    };
    process_assignment(
      context,
      param_name,
      value,
      span,
      AssignmentType::Argument,
    );
  }
}

fn process_named_arguments(
  context: &mut PhpContext,
  ArgumentList { arguments, .. }: &ArgumentList,
) {
  for argument in arguments.iter() {
    let Argument::Named(NamedArgument { name, value, .. }) = argument else {
      continue;
    };
    let name = context.interner.lookup(&name.value);
    check_expression_value(
      context,
      name,
      value,
      &value.span(),
      AssignmentType::Argument,
    );
  }
}

fn process_parameters(
  context: &mut PhpContext,
  FunctionLikeParameterList { parameters, .. }: &FunctionLikeParameterList,
) {
  for param in parameters.iter() {
    let Some(default) = &param.default_value else {
      continue;
    };
    let name_str = lookup_variable_name!(context, &param.variable);
    check_expression_value(
      context,
      name_str,
      &default.value,
      &default.value.span(),
      AssignmentType::Parameter,
    );
  }
}

fn process_property(
  context: &mut PhpContext,
  PlainProperty { items, .. }: &PlainProperty,
) {
  for item in items.iter() {
    let PropertyItem::Concrete(PropertyConcreteItem {
      variable, value, ..
    }) = item
    else {
      continue;
    };
    let name_str = lookup_variable_name!(context, &variable);
    check_expression_value(
      context,
      name_str,
      value,
      &value.span(),
      AssignmentType::Property,
    );
  }
}

fn process_class_constant(
  context: &mut PhpContext,
  ClassLikeConstant { items, .. }: &ClassLikeConstant,
) {
  for ClassLikeConstantItem { name, value, .. } in items.iter() {
    let name_str = context.interner.lookup(&name.value);
    check_expression_value(
      context,
      name_str,
      value,
      &value.span(),
      AssignmentType::Constant,
    );
  }
}

fn process_constant(
  context: &mut PhpContext,
  Constant { items, .. }: &Constant,
) {
  for ConstantItem { name, value, .. } in items.iter() {
    let name_str = context.interner.lookup(&name.value);
    check_expression_value(
      context,
      name_str,
      value,
      &value.span(),
      AssignmentType::Constant,
    );
  }
}

fn process_define(
  context: &mut PhpContext,
  ArgumentList { arguments, .. }: &ArgumentList,
) {
  if let [name, value] = arguments.nodes.as_slice() {
    let Some(name_str) = string_literal_positional(context, name) else {
      return;
    };
    let Argument::Positional(PositionalArgument {
      value: value_expr, ..
    }) = value
    else {
      return;
    };
    check_expression_value(
      context,
      &name_str,
      value_expr,
      &value_expr.span(),
      AssignmentType::Constant,
    );
  }
}

fn check_expression_value(
  context: &mut PhpContext,
  name: &str,
  expression: &Expression,
  span: &mago_span::Span,
  assignment_type: AssignmentType,
) {
  if let Some(value) = string_literal(context, expression) {
    let value_span = expression.span();
    if context.already_emitted(&value_span) {
      return;
    }

    context.record_emitted(&value_span);

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
    E::Conditional(Conditional { then, r#else, .. }) => {
      if let Some(then) = then {
        check_expression_value(
          context,
          name,
          then,
          &then.span(),
          assignment_type,
        );
      }
      check_expression_value(
        context,
        name,
        r#else,
        &r#else.span(),
        assignment_type,
      );
    }
    E::Binary(Binary {
      lhs,
      rhs,
      operator:
        BinaryOperator::Or(_)
        | BinaryOperator::LowOr(_)
        | BinaryOperator::NullCoalesce(_)
        | BinaryOperator::Elvis(_),
    }) => {
      check_expression_value(context, name, lhs, &lhs.span(), assignment_type);
      check_expression_value(context, name, rhs, &rhs.span(), assignment_type);
    }
    E::Binary(Binary {
      lhs,
      rhs,
      operator: BinaryOperator::StringConcat(_),
    }) => {
      check_expression_value(context, name, lhs, span, assignment_type);
      check_expression_value(context, name, rhs, span, assignment_type);
    }

    E::Call(call) => {
      let argument_list = match call {
        Call::Function(c) => &c.argument_list,
        Call::Method(c) => &c.argument_list,
        Call::NullSafeMethod(c) => &c.argument_list,
        Call::StaticMethod(c) => &c.argument_list,
      };
      for argument in argument_list.arguments.iter() {
        if let Argument::Positional(PositionalArgument { value, .. }) = argument
        {
          check_expression_value(context, name, value, span, assignment_type);
        }
      }
      process_expression(context, expression);
    }
    E::Instantiation(instantiation) => {
      if let Some(args) = &instantiation.arguments {
        for argument in args.arguments.iter() {
          if let Argument::Positional(PositionalArgument { value, .. }) =
            argument
          {
            check_expression_value(context, name, value, span, assignment_type);
          }
        }
      }
      process_expression(context, expression);
    }
    E::Array(array) => {
      process_named_array_elements(
        context,
        name,
        &array.elements,
        assignment_type,
      );
    }
    E::LegacyArray(LegacyArray { elements, .. }) => {
      process_named_array_elements(context, name, elements, assignment_type);
    }
    _ => process_expression(context, expression),
  }
}

fn process_named_array_elements(
  context: &mut PhpContext,
  name: &str,
  elements: &mago_ast::sequence::TokenSeparatedSequence<ArrayElement>,
  assignment_type: AssignmentType,
) {
  process_array_elements(context, elements);
  for element in elements.iter() {
    if let ArrayElement::Value(ValueArrayElement { value }) = element {
      check_expression_value(
        context,
        name,
        value,
        &value.span(),
        assignment_type,
      );
    }
  }
}

fn process_argument_expressions(
  context: &mut PhpContext,
  ArgumentList { arguments, .. }: &ArgumentList,
) {
  for argument in arguments.iter() {
    let value = match argument {
      Argument::Positional(a) => &a.value,
      Argument::Named(a) => &a.value,
    };
    process_expression(context, value);
  }
}

fn process_array_elements(
  context: &mut PhpContext,
  elements: &mago_ast::sequence::TokenSeparatedSequence<ArrayElement>,
) {
  for element in elements.iter() {
    let ArrayElement::KeyValue(KeyValueArrayElement { key, value, .. }) =
      element
    else {
      continue;
    };
    let Some(key_str) = string_literal(context, key) else {
      continue;
    };

    // ['headers' => ['Header-Name' => value]] (Guzzle/Symfony): each entry of
    // a nested `headers` array is an HTTP header.
    if key_str == "headers"
      && let E::Array(array) = &**value
    {
      for header in array.elements.iter() {
        let ArrayElement::KeyValue(KeyValueArrayElement { key, value, .. }) =
          header
        else {
          continue;
        };

        if let Some(name) = string_literal(context, key) {
          check_expression_value(
            context,
            &name,
            value,
            &value.span(),
            AssignmentType::Header,
          );
        }
      }

      continue;
    }

    check_expression_value(
      context,
      &key_str,
      value,
      &value.span(),
      AssignmentType::Element,
    );
  }
}

fn process_assignment(
  context: &mut PhpContext,
  name: &str,
  value: &str,
  span: &mago_span::Span,
  assignment_type: AssignmentType,
) {
  if context.already_emitted(span) {
    return;
  }

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

fn string_literal_positional(
  context: &PhpContext,
  argument: &Argument,
) -> Option<String> {
  if let Argument::Positional(PositionalArgument { value, .. }) = argument {
    string_literal(context, value)
  } else {
    None
  }
}

fn string_literal(
  context: &PhpContext,
  expression: &Expression,
) -> Option<String> {
  match expression {
    E::Literal(Literal::String(LiteralString { value, .. })) => {
      let raw = context.interner.lookup(value).trim_matches(['\'', '"']);
      Some(raw.to_owned())
    }
    E::CompositeString(composite) => {
      composite_string_literal(context, composite)
    }
    E::Binary(Binary {
      lhs,
      operator: BinaryOperator::StringConcat(_),
      rhs,
    }) => {
      let left = string_literal(context, lhs)?;
      let right = string_literal(context, rhs)?;
      Some(left + &right)
    }
    E::Parenthesized(p) => string_literal(context, &p.expression),
    _ => None,
  }
}

fn composite_string_literal(
  context: &PhpContext,
  composite: &CompositeString,
) -> Option<String> {
  let parts = composite.parts();
  let mut result = String::new();
  for part in parts.iter() {
    let StringPart::Literal(literal) = part else {
      return None;
    };
    result.push_str(context.interner.lookup(&literal.value));
  }
  Some(result)
}

fn compute_source_span(
  context: &PhpContext,
  span: &mago_span::Span,
) -> SourceFileSpan {
  let body = context.source_context.body.unwrap_or("");
  let mut cache = context.line_starts.borrow_mut();
  let starts = cache.get_or_insert_with(|| compute_line_starts(body));

  let mut start = position_from_line_starts(starts, span.start.offset);
  let mut end = position_from_line_starts(starts, span.end.offset);

  let parent_line = context.source_context.parent_line;
  let parent_col = context.source_context.parent_col;
  if start.line == 1 {
    start.column += parent_col;
  }
  if end.line == 1 {
    end.column += parent_col;
  }
  start.line += parent_line;
  end.line += parent_line;

  SourceFileSpan {
    file_abs_path: context.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan { start, end }),
  }
}

fn position_from_line_starts(
  line_starts: &[usize],
  offset: usize,
) -> SourcePosition {
  let line_idx = line_starts
    .partition_point(|&start| start <= offset)
    .saturating_sub(1);

  let line_start = line_starts.get(line_idx).copied().unwrap_or(0);

  SourcePosition {
    line: line_idx.saturating_add(1),
    column: offset.saturating_sub(line_start).saturating_add(1),
  }
}
