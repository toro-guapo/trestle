use std::cell::RefCell;

use ruff_python_ast::{
  Expr, ExprAttribute, ExprCall, ExprDict, ExprName, Operator, Stmt,
  StmtAnnAssign, StmtAssign, StmtClassDef, StmtFunctionDef, StmtIf, StmtMatch,
  StmtTry,
};
use ruff_text_size::{Ranged, TextRange};

use crate::{
  analysis::{Analyzer, CallFrame, FunctionSignature},
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_assignment, check_value,
    offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

thread_local! {
  static ANALYZER: RefCell<Analyzer<String, TextRange>> =
    RefCell::new(Analyzer::new());
}

struct PythonContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl<'a> PythonContext<'a> {
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

  let Ok(parsed) = ruff_python_parser::parse_module(source) else {
    return false;
  };

  ANALYZER.with(|a| a.borrow_mut().clear());

  let mut ctx = PythonContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
  };

  process_body(&mut ctx, parsed.suite());

  ANALYZER.with(|a| {
    a.borrow().resolve_calls(|signature, arguments| {
      resolve_arguments(&mut ctx, signature, arguments);
    });
  });

  true
}

// -----------------------------------------------------------------------------
// Statement processing
// -----------------------------------------------------------------------------

fn process_body(ctx: &mut PythonContext, body: &[Stmt]) {
  for stmt in body {
    process_statement(ctx, stmt);
  }
}

fn process_statement(ctx: &mut PythonContext, stmt: &Stmt) {
  match stmt {
    Stmt::Assign(s) => process_assign(ctx, s),
    Stmt::AnnAssign(s) => process_ann_assign(ctx, s),
    Stmt::FunctionDef(s) => process_function_def(ctx, s),
    Stmt::ClassDef(s) => process_class_def(ctx, s),
    Stmt::If(s) => process_if(ctx, s),
    Stmt::Match(s) => process_match(ctx, s),
    Stmt::For(s) => {
      process_body(ctx, &s.body);
      process_body(ctx, &s.orelse);
    }
    Stmt::While(s) => {
      process_body(ctx, &s.body);
      process_body(ctx, &s.orelse);
    }
    Stmt::With(s) => process_body(ctx, &s.body),
    Stmt::Try(s) => process_try(ctx, s),
    Stmt::Expr(s) => process_expr_value(ctx, &s.value),
    Stmt::Return(s) => {
      if let Some(value) = &s.value {
        process_expr_value(ctx, value);
      }
    }
    _ => {}
  }
}

fn process_assign(ctx: &mut PythonContext, assign: &StmtAssign) {
  for target in &assign.targets {
    if let Some(name) = extract_name(target) {
      check_expression_value(
        ctx,
        &name,
        &assign.value,
        assign.value.range(),
        AssignmentType::Variable,
      );
      return;
    }
  }

  process_expr_value(ctx, &assign.value);
}

fn process_ann_assign(ctx: &mut PythonContext, assign: &StmtAnnAssign) {
  let Some(value_expr) = &assign.value else {
    return;
  };

  if let Some(name) = extract_name(&assign.target) {
    check_expression_value(
      ctx,
      &name,
      value_expr,
      value_expr.range(),
      AssignmentType::Variable,
    );
  } else {
    process_expr_value(ctx, value_expr);
  }
}

fn process_function_def(ctx: &mut PythonContext, func: &StmtFunctionDef) {
  register_signature(func);

  for decorator in &func.decorator_list {
    process_expr_value(ctx, &decorator.expression);
  }

  for param in func.parameters.iter_non_variadic_params() {
    if let Some(default) = param.default() {
      let name = param.name().to_string();
      check_expression_value(
        ctx,
        &name,
        default,
        default.range(),
        AssignmentType::Parameter,
      );
    }
  }

  process_body(ctx, &func.body);
}

fn process_class_def(ctx: &mut PythonContext, class: &StmtClassDef) {
  for decorator in &class.decorator_list {
    process_expr_value(ctx, &decorator.expression);
  }

  process_body(ctx, &class.body);
}

fn process_if(ctx: &mut PythonContext, if_stmt: &StmtIf) {
  process_body(ctx, &if_stmt.body);
  for clause in &if_stmt.elif_else_clauses {
    process_body(ctx, &clause.body);
  }
}

fn process_match(ctx: &mut PythonContext, match_stmt: &StmtMatch) {
  for case in &match_stmt.cases {
    process_body(ctx, &case.body);
  }
}

fn process_try(ctx: &mut PythonContext, try_stmt: &StmtTry) {
  process_body(ctx, &try_stmt.body);
  for handler in &try_stmt.handlers {
    match handler {
      ruff_python_ast::ExceptHandler::ExceptHandler(h) => {
        process_body(ctx, &h.body);
      }
    }
  }
  process_body(ctx, &try_stmt.orelse);
  process_body(ctx, &try_stmt.finalbody);
}

// -----------------------------------------------------------------------------
// Expression value checking (with assignment context)
// -----------------------------------------------------------------------------

/// Checks an expression that is being assigned to `name`. Recurses through
/// conditional expressions and or-fallbacks to find string values.
fn check_expression_value(
  ctx: &mut PythonContext,
  name: &str,
  expr: &Expr,
  span: TextRange,
  assignment_type: AssignmentType,
) {
  if let Some(value) = extract_string_value(expr) {
    let range = expr.range();
    let start = range.start().to_u32() as usize;
    let end = range.end().to_u32() as usize;
    if ctx.already_emitted(start, end) {
      return;
    }
    let name = name.to_owned();
    if let Some(d) = check_assignment(
      &normalize_name(&name),
      &normalize_value(&value),
      assignment_type,
      ctx.source_context,
      || compute_span(ctx, span),
    ) {
      ctx.record_emitted(start, end);
      ctx.source_context.emit_diagnostic(d);
    }
    return;
  }

  match expr {
    // password = "secret" if prod else "dev"
    Expr::If(cond) => {
      check_expression_value(
        ctx,
        name,
        &cond.body,
        cond.body.range(),
        assignment_type,
      );
      check_expression_value(
        ctx,
        name,
        &cond.orelse,
        cond.orelse.range(),
        assignment_type,
      );
    }
    Expr::BoolOp(bool_op)
      if matches!(
        bool_op.op,
        ruff_python_ast::BoolOp::Or | ruff_python_ast::BoolOp::And
      ) =>
    {
      for value in bool_op.values.iter() {
        check_expression_value(
          ctx,
          name,
          value,
          value.range(),
          assignment_type,
        );
      }
    }

    Expr::BinOp(bin) if bin.op == Operator::Add => {
      check_expression_value(ctx, name, &bin.left, span, assignment_type);
      check_expression_value(ctx, name, &bin.right, span, assignment_type);
    }

    Expr::Call(call) => {
      for arg in call.arguments.args.iter() {
        check_expression_value(ctx, name, arg, span, assignment_type);
      }
      process_call(ctx, call);
    }
    _ => process_expr_value(ctx, expr),
  }
}

// -----------------------------------------------------------------------------
// Expression processing (no assignment context)
// -----------------------------------------------------------------------------

fn process_expr_value(ctx: &mut PythonContext, expr: &Expr) {
  if let Some(value) = extract_string_value(expr) {
    let range = expr.range();
    let start = range.start().to_u32() as usize;
    let end = range.end().to_u32() as usize;
    if !ctx.already_emitted(start, end) {
      let normalized = normalize_value(&value);
      if let Some(d) = check_value(&normalized, ctx.source_context, || {
        compute_span(ctx, range)
      }) {
        ctx.record_emitted(start, end);
        ctx.source_context.emit_diagnostic(d);
      }
    }
    return;
  }

  match expr {
    Expr::Call(call) => process_call(ctx, call),
    Expr::Dict(dict) => process_dict(ctx, dict),
    Expr::Named(named) => process_named(ctx, named),
    Expr::Lambda(lambda) => process_lambda(ctx, lambda),
    // x if cond else y - check both branches.
    Expr::If(cond) => {
      process_expr_value(ctx, &cond.body);
      process_expr_value(ctx, &cond.orelse);
    }
    // a or b, a and b - check each operand.
    Expr::BoolOp(bool_op) => {
      for v in bool_op.values.iter() {
        process_expr_value(ctx, v);
      }
    }
    _ => {}
  }
}

fn process_call(ctx: &mut PythonContext, call: &ExprCall) {
  // Keyword arguments (directly named)
  for keyword in call.arguments.keywords.iter() {
    let Some(arg) = &keyword.arg else {
      continue;
    };

    let name = arg.to_string();
    check_expression_value(
      ctx,
      &name,
      &keyword.value,
      keyword.value.range(),
      AssignmentType::Argument,
    );
  }

  // os.putenv("KEY", value) / os.environ.setdefault("KEY", value).
  if let Some(callee) = callee_name(&call.func) {
    if callee == "putenv" || callee == "setdefault" {
      let args = &call.arguments.args;
      if args.len() >= 2 {
        if let Some(key) = extract_string_value(&args[0]) {
          check_expression_value(
            ctx,
            &key,
            &args[1],
            args[1].range(),
            AssignmentType::Argument,
          );
          return;
        }
      }
    }
  }

  // Positional arguments (resolved via signature analysis)
  process_positional_arguments(ctx, call);

  // Recurse into positional args for nested patterns (walrus, etc.)
  for arg in call.arguments.args.iter() {
    process_expr_value(ctx, arg);
  }

  // Recurse into the function expression (decorator chains, etc.)
  process_expr_value(ctx, &call.func);
}

fn process_dict(ctx: &mut PythonContext, dict: &ExprDict) {
  for item in &dict.items {
    let Some(key_expr) = &item.key else {
      continue;
    };

    let Some(key) = extract_string_value(key_expr) else {
      continue;
    };

    check_expression_value(
      ctx,
      &key,
      &item.value,
      item.value.range(),
      AssignmentType::Element,
    );
  }
}

/// Walrus operator: `password := "secret"`
fn process_named(ctx: &mut PythonContext, named: &ruff_python_ast::ExprNamed) {
  if let Some(name) = extract_name(&named.target) {
    check_expression_value(
      ctx,
      &name,
      &named.value,
      named.value.range(),
      AssignmentType::Variable,
    );
  }
}

/// Lambda parameter defaults: `lambda password="secret": ...`
fn process_lambda(
  ctx: &mut PythonContext,
  lambda: &ruff_python_ast::ExprLambda,
) {
  let Some(parameters) = &lambda.parameters else {
    return;
  };

  for param in parameters.iter_non_variadic_params() {
    if let Some(default) = param.default() {
      let name = param.name().to_string();
      check_expression_value(
        ctx,
        &name,
        default,
        default.range(),
        AssignmentType::Parameter,
      );
    }
  }
}

// -----------------------------------------------------------------------------
// Positional argument analysis
// -----------------------------------------------------------------------------

/// Registers a function's positional parameter names for call resolution.
/// Strips `self`/`cls` so method calls align correctly.
fn register_signature(func: &StmtFunctionDef) {
  let parameter_names: Vec<String> = func
    .parameters
    .posonlyargs
    .iter()
    .chain(&func.parameters.args)
    .map(|p| p.name().to_string())
    .filter(|name| name != "self" && name != "cls")
    .collect();

  ANALYZER.with(|a| {
    a.borrow_mut().add_signature(
      func.name.to_string(),
      FunctionSignature { parameter_names },
    );
  });
}

/// Extracts positional string arguments from a call and either resolves
/// them immediately or defers resolution for a later pass.
fn process_positional_arguments(ctx: &mut PythonContext, call: &ExprCall) {
  let Some(callee) = callee_name(&call.func) else {
    return;
  };

  let extracted: Vec<(String, TextRange)> = call
    .arguments
    .args
    .iter()
    .filter_map(|arg| {
      let value = extract_string_value(arg)?;
      Some((value, arg.range()))
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
  ctx: &mut PythonContext,
  signature: &FunctionSignature,
  arguments: &[(String, TextRange)],
) {
  for (i, (value, range)) in arguments.iter().enumerate() {
    let Some(param_name) = signature.parameter_names.get(i) else {
      break;
    };

    let start = range.start().to_u32() as usize;
    let end = range.end().to_u32() as usize;
    if ctx.already_emitted(start, end) {
      continue;
    }

    let name = param_name.to_owned();
    let value = value.to_owned();
    if let Some(d) = check_assignment(
      &normalize_name(&name),
      &normalize_value(&value),
      AssignmentType::Argument,
      ctx.source_context,
      || compute_span(ctx, *range),
    ) {
      ctx.record_emitted(start, end);
      ctx.source_context.emit_diagnostic(d);
    }
  }
}

fn callee_name(expr: &Expr) -> Option<String> {
  match expr {
    Expr::Name(ExprName { id, .. }) => Some(id.to_string()),
    Expr::Attribute(ExprAttribute { attr, .. }) => Some(attr.to_string()),
    _ => None,
  }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Extracts a resolved string value from an expression, including
/// concatenation via `+`.
fn extract_string_value(expr: &Expr) -> Option<String> {
  match expr {
    Expr::StringLiteral(lit) => {
      let s = lit.value.to_str();
      if s.is_empty() {
        None
      } else {
        Some(s.to_owned())
      }
    }
    Expr::BinOp(bin) if bin.op == Operator::Add => {
      let left = extract_string_value(&bin.left)?;
      let right = extract_string_value(&bin.right)?;
      Some(left + &right)
    }
    _ => None,
  }
}

fn extract_name(expr: &Expr) -> Option<String> {
  match expr {
    Expr::Name(ExprName { id, .. }) => Some(id.to_string()),
    Expr::Attribute(ExprAttribute { attr, .. }) => Some(attr.to_string()),
    // os.environ["PASSWORD"] = "secret", dict["key"] = "value"
    Expr::Subscript(sub) => extract_string_value(&sub.slice),
    _ => None,
  }
}

fn compute_span(ctx: &PythonContext, range: TextRange) -> SourceFileSpan {
  let start = range.start().to_u32() as usize;
  let end = range.end().to_u32() as usize;

  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, start),
      end: offset_to_position(ctx.source, end),
    }),
  }
}
