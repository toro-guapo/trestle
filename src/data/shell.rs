use brush_parser::{
  Parser, ParserOptions, SourceInfo,
  ast::{
    AndOr, Command, CommandPrefixOrSuffixItem, CompoundCommand, CompoundList,
    CompoundListItem, ForClauseCommand, IfClauseCommand, Pipeline, Program,
    SimpleCommand, WhileOrUntilClauseCommand,
  },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
  pub name: String,
  pub args: Vec<String>,
}

impl Invocation {
  pub fn matches(&self, name: &str, subcommand: Option<&str>) -> bool {
    if self.name != name {
      return false;
    }
    match subcommand {
      None => true,
      Some(sub) => self.args.first().map(|s| s.as_str()) == Some(sub),
    }
  }
}

pub fn parse_shell(script: &str) -> Vec<Invocation> {
  let mut parser = Parser::new(
    script.as_bytes(),
    &ParserOptions::default(),
    &SourceInfo {
      source: String::new(),
    },
  );

  let Ok(program) = parser.parse_program() else {
    return Vec::new();
  };

  let mut invocations = Vec::new();
  collect_program(&program, &mut invocations);
  invocations
}

pub fn find_invocations<'a>(
  invocations: &'a [Invocation],
  name: &str,
  subcommand: Option<&str>,
) -> Vec<&'a Invocation> {
  invocations
    .iter()
    .filter(|inv| inv.matches(name, subcommand))
    .collect()
}

pub fn has_invocation(
  invocations: &[Invocation],
  name: &str,
  subcommand: Option<&str>,
) -> bool {
  invocations.iter().any(|inv| inv.matches(name, subcommand))
}

fn collect_program(program: &Program, out: &mut Vec<Invocation>) {
  for list in &program.complete_commands {
    collect_compound_list(list, out);
  }
}

fn collect_compound_list(list: &CompoundList, out: &mut Vec<Invocation>) {
  for CompoundListItem(and_or_list, _) in &list.0 {
    collect_pipeline(&and_or_list.first, out);
    for and_or in &and_or_list.additional {
      match and_or {
        AndOr::And(pipeline) | AndOr::Or(pipeline) => {
          collect_pipeline(pipeline, out);
        }
      }
    }
  }
}

fn collect_pipeline(pipeline: &Pipeline, out: &mut Vec<Invocation>) {
  for command in &pipeline.seq {
    collect_command(command, out);
  }
}

fn collect_command(command: &Command, out: &mut Vec<Invocation>) {
  match command {
    Command::Simple(simple) => {
      if let Some(invocation) = invocation_from_simple(simple) {
        out.push(invocation);
      }
    }
    Command::Compound(compound, _) => collect_compound_command(compound, out),
    Command::Function(func) => {
      collect_compound_command(&func.body.0, out);
    }
    _ => {}
  }
}

fn collect_compound_command(
  command: &CompoundCommand,
  out: &mut Vec<Invocation>,
) {
  match command {
    CompoundCommand::BraceGroup(group) => {
      collect_compound_list(&group.list, out);
    }
    CompoundCommand::Subshell(subshell) => {
      collect_compound_list(&subshell.list, out);
    }
    CompoundCommand::ForClause(ForClauseCommand { body, .. }) => {
      collect_compound_list(&body.list, out);
    }
    CompoundCommand::ArithmeticForClause(clause) => {
      collect_compound_list(&clause.body.list, out);
    }
    CompoundCommand::CaseClause(case) => {
      for item in &case.cases {
        if let Some(cmd) = &item.cmd {
          collect_compound_list(cmd, out);
        }
      }
    }
    CompoundCommand::IfClause(IfClauseCommand {
      condition,
      then,
      elses,
      ..
    }) => {
      collect_compound_list(condition, out);
      collect_compound_list(then, out);
      if let Some(else_clauses) = elses {
        for clause in else_clauses {
          if let Some(cond) = &clause.condition {
            collect_compound_list(cond, out);
          }
          collect_compound_list(&clause.body, out);
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
      collect_compound_list(condition, out);
      collect_compound_list(&body.list, out);
    }
    _ => {}
  }
}

fn invocation_from_simple(simple: &SimpleCommand) -> Option<Invocation> {
  let name_word = simple.word_or_name.as_ref()?;
  let name = unquote(&name_word.value)?;
  if name.is_empty() {
    return None;
  }

  let mut args = Vec::new();
  if let Some(suffix) = &simple.suffix {
    for item in &suffix.0 {
      if let CommandPrefixOrSuffixItem::Word(word) = item {
        if let Some(arg) = unquote(&word.value) {
          args.push(arg);
        }
      }
    }
  }

  Some(Invocation { name, args })
}

fn unquote(raw: &str) -> Option<String> {
  let s = raw.trim();
  if s.is_empty() {
    return None;
  }
  if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
    || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
  {
    let inner = s.get(1..s.len() - 1)?;
    return Some(inner.to_owned());
  }
  if s.starts_with("$'") && s.ends_with('\'') && s.len() >= 3 {
    let inner = s.get(2..s.len() - 1)?;
    return Some(inner.to_owned());
  }
  Some(s.to_owned())
}
