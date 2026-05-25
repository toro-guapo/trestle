use brush_parser::{
  Parser, ParserOptions, SourceInfo,
  ast::{
    AndOr, Assignment, AssignmentName, AssignmentValue, Command,
    CommandPrefixOrSuffixItem, CompoundCommand, CompoundList, CompoundListItem,
    ForClauseCommand, IfClauseCommand, Pipeline, Program, SimpleCommand,
    WhileOrUntilClauseCommand, Word,
  },
};

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourcePosition, SourceSpan,
    check_assignment, check_value,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

struct ShellContext<'a> {
  source_context: &'a SourceContext<'a>,
}

fn apply_parent_offset(context: &SourceContext, pos: &mut SourcePosition) {
  if pos.line == 1 {
    pos.column += context.parent_col;
  }
  pos.line += context.parent_line;
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let mut parser = Parser::new(
    source.as_bytes(),
    &ParserOptions::default(),
    &SourceInfo {
      source: String::new(),
    },
  );

  let Ok(program) = parser.parse_program() else {
    return false;
  };

  let mut shell_context = ShellContext {
    source_context: context,
  };

  process_program(&mut shell_context, &program);

  true
}

fn process_program(context: &mut ShellContext, program: &Program) {
  for command in &program.complete_commands {
    process_compound_list(context, command);
  }
}

fn process_compound_list(context: &mut ShellContext, list: &CompoundList) {
  for CompoundListItem(and_or_list, _) in &list.0 {
    process_pipeline(context, &and_or_list.first);
    for and_or in &and_or_list.additional {
      match and_or {
        AndOr::And(pipeline) | AndOr::Or(pipeline) => {
          process_pipeline(context, pipeline);
        }
      }
    }
  }
}

fn process_pipeline(context: &mut ShellContext, pipeline: &Pipeline) {
  for command in &pipeline.seq {
    process_command(context, command);
  }
}

fn process_command(context: &mut ShellContext, command: &Command) {
  match command {
    Command::Simple(simple) => process_simple_command(context, simple),
    Command::Compound(compound, _) => {
      process_compound_command(context, compound);
    }
    Command::Function(func) => {
      process_compound_command(context, &func.body.0);
    }
    _ => {}
  }
}

fn process_compound_command(
  context: &mut ShellContext,
  command: &CompoundCommand,
) {
  match command {
    CompoundCommand::BraceGroup(group) => {
      process_compound_list(context, &group.list);
    }
    CompoundCommand::Subshell(subshell) => {
      process_compound_list(context, &subshell.list);
    }
    CompoundCommand::ForClause(ForClauseCommand { body, .. }) => {
      process_compound_list(context, &body.list);
    }
    CompoundCommand::ArithmeticForClause(clause) => {
      process_compound_list(context, &clause.body.list);
    }
    CompoundCommand::CaseClause(case) => {
      for item in &case.cases {
        if let Some(cmd) = &item.cmd {
          process_compound_list(context, cmd);
        }
      }
    }
    CompoundCommand::IfClause(IfClauseCommand {
      condition,
      then,
      elses,
      ..
    }) => {
      process_compound_list(context, condition);
      process_compound_list(context, then);
      if let Some(else_clauses) = elses {
        for clause in else_clauses {
          if let Some(cond) = &clause.condition {
            process_compound_list(context, cond);
          }
          process_compound_list(context, &clause.body);
        }
      }
    }
    CompoundCommand::WhileClause(WhileOrUntilClauseCommand(
      condition,
      body,
      _,
    ))
    | CompoundCommand::UntilClause(WhileOrUntilClauseCommand(
      condition,
      body,
      _,
    )) => {
      process_compound_list(context, condition);
      process_compound_list(context, &body.list);
    }
    _ => {}
  }
}

fn process_simple_command(context: &mut ShellContext, command: &SimpleCommand) {
  if let Some(prefix) = &command.prefix {
    for item in &prefix.0 {
      process_prefix_suffix_item(context, item);
    }
  }
  if let Some(suffix) = &command.suffix {
    for item in &suffix.0 {
      process_prefix_suffix_item(context, item);
    }
  }
}

fn process_prefix_suffix_item(
  context: &mut ShellContext,
  item: &CommandPrefixOrSuffixItem,
) {
  match item {
    CommandPrefixOrSuffixItem::AssignmentWord(assignment, _) => {
      process_assignment(context, assignment);
    }
    CommandPrefixOrSuffixItem::Word(word) => {
      process_word_value(context, word);
    }
    _ => {}
  }
}

fn process_word_value(context: &mut ShellContext, word: &Word) {
  let Some(value) = unquote_string(&word.value) else {
    return;
  };
  let location = word.loc.clone();
  if let Some(d) =
    check_value(&normalize_value(&value), context.source_context, || {
      if let Some(loc) = &location {
        compute_source_span(context, loc)
      } else {
        SourceFileSpan {
          file_abs_path: context.source_context.file_abs_path.to_path_buf(),
          file_span: None,
        }
      }
    })
  {
    context.source_context.emit_diagnostic(d);
  }
}

fn process_assignment(context: &mut ShellContext, assignment: &Assignment) {
  let AssignmentName::VariableName(name) = &assignment.name else {
    return;
  };

  match &assignment.value {
    AssignmentValue::Scalar(word) => {
      let Some(value) = unquote_string(&word.value) else {
        return;
      };
      let name_str = name.to_owned();
      if let Some(d) = check_assignment(
        &normalize_name(&name_str),
        &normalize_value(&value),
        AssignmentType::Variable,
        context.source_context,
        || compute_scalar_value_span(context, assignment, &name_str, word),
      ) {
        context.source_context.emit_diagnostic(d);
      }
    }
    AssignmentValue::Array(elements) => {
      for (_, word) in elements {
        let Some(value) = unquote_string(&word.value) else {
          continue;
        };
        let value = value.to_owned();
        if let Some(d) =
          check_value(&normalize_value(&value), context.source_context, || {
            if let Some(loc) = &word.loc {
              compute_source_span(context, loc)
            } else {
              compute_source_span(context, &assignment.loc)
            }
          })
        {
          context.source_context.emit_diagnostic(d);
        }
      }
    }
  }
}

fn unquote_string(raw: &str) -> Option<String> {
  let s = raw.trim();
  if s.is_empty() {
    return None;
  }

  if is_parameter_expansion(s) {
    return parameter_expansion_default(s);
  }

  if (s.starts_with('"') && s.ends_with('"'))
    || (s.starts_with('\'') && s.ends_with('\''))
  {
    let inner = s.get(1..s.len() - 1)?;
    return Some(inner.to_owned());
  }

  if s.starts_with("$'") && s.ends_with('\'') {
    let inner = s.get(2..s.len() - 1)?;
    return Some(inner.to_owned());
  }

  Some(s.to_owned())
}

fn is_parameter_expansion(s: &str) -> bool {
  let body = strip_outer_double_quotes(s).unwrap_or(s);
  body.starts_with("${") && body.ends_with('}')
}

/// Parses a `${NAME<op>default}` parameter expansion and returns
/// the default literal. brush_parser hands us the raw token text
/// for the value side of an assignment, so detecting the dev-
/// fallback inside `password=${PASSWORD:-secret}` requires parsing
/// the expansion.
///
/// Operators recognized:
///   - `:-` and `-`   - use default if VAR is unset (or unset/null)
///   - `:=` and `=`   - use default and assign back to VAR
///   - `:+` and `+`   - use the alternate value if VAR is set
///
/// `:?` and `?` are deliberately NOT included: those produce an
/// error message rather than a runtime value, so the string in that
/// position isn't a candidate-runtime secret.
///
/// Optionally tolerates an outer pair of double quotes
/// (`"${VAR:-secret}"`). Nested expansions inside the default are
/// not unwrapped - V1 scope.
fn parameter_expansion_default(s: &str) -> Option<String> {
  let body = strip_outer_double_quotes(s).unwrap_or(s);

  let inner = body
    .strip_prefix("${")
    .and_then(|rest| rest.strip_suffix('}'))?;

  // Read the parameter name (must start with letter or `_`).
  let mut chars = inner.char_indices();
  let (_, first) = chars.next()?;
  if !(first.is_ascii_alphabetic() || first == '_' || first.is_ascii_digit()) {
    return None;
  }
  let mut name_end = first.len_utf8();
  for (i, c) in chars {
    if c.is_ascii_alphanumeric() || c == '_' {
      name_end = i + c.len_utf8();
    } else {
      break;
    }
  }

  let rest = inner.get(name_end..)?;

  // Match the longest valid operator prefix.
  let default = if let Some(rest) = rest.strip_prefix(":-") {
    rest
  } else if let Some(rest) = rest.strip_prefix(":=") {
    rest
  } else if let Some(rest) = rest.strip_prefix(":+") {
    rest
  } else if let Some(rest) = rest.strip_prefix('-') {
    rest
  } else if let Some(rest) = rest.strip_prefix('=') {
    rest
  } else if let Some(rest) = rest.strip_prefix('+') {
    rest
  } else {
    // Unrecognized operator (including `:?`/`?`, which produce an
    // error not a value), or no operator at all.
    return None;
  };

  let default = default.trim();
  if default.is_empty() {
    return None;
  }

  // Strip surrounding quotes if the default is itself quoted.
  if (default.starts_with('"') && default.ends_with('"'))
    || (default.starts_with('\'') && default.ends_with('\''))
  {
    let inner = default.get(1..default.len() - 1)?;
    return Some(inner.to_owned());
  }

  Some(default.to_owned())
}

fn strip_outer_double_quotes(s: &str) -> Option<&str> {
  if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
    s.get(1..s.len() - 1)
  } else {
    None
  }
}

fn compute_scalar_value_span(
  context: &ShellContext,
  assignment: &Assignment,
  name: &str,
  word: &Word,
) -> SourceFileSpan {
  if let Some(loc) = &word.loc {
    return compute_source_span(context, loc);
  }

  let start_line = assignment.loc.start.line;
  let start_column = assignment.loc.start.column + name.chars().count() + 1;
  let value_chars = word.value.chars().count();

  let mut start = SourcePosition {
    line: start_line,
    column: start_column,
  };
  let mut end = SourcePosition {
    line: start_line,
    column: start_column + value_chars,
  };
  apply_parent_offset(context.source_context, &mut start);
  apply_parent_offset(context.source_context, &mut end);

  SourceFileSpan {
    file_abs_path: context.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan { start, end }),
  }
}

fn compute_source_span(
  context: &ShellContext,
  loc: &brush_parser::TokenLocation,
) -> SourceFileSpan {
  let mut start = SourcePosition {
    line: loc.start.line,
    column: loc.start.column,
  };

  let mut end = SourcePosition {
    line: loc.end.line,
    column: loc.end.column,
  };

  apply_parent_offset(context.source_context, &mut start);
  apply_parent_offset(context.source_context, &mut end);

  SourceFileSpan {
    file_abs_path: context.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan { start, end }),
  }
}
