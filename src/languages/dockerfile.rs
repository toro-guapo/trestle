use std::collections::HashMap;

use dockerfile_parser::{Dockerfile, Instruction};

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

struct DockerContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let Ok(dockerfile) = Dockerfile::parse(source) else {
    return false;
  };

  let mut ctx = DockerContext {
    source,
    source_context: context,
  };

  // Each `FROM` opens a fresh stage with its own variable scope: ARG
  // and ENV declarations from previous stages are not visible. Reset
  // the scope per stage to mirror Docker's build-time evaluator.
  for stage in dockerfile.iter_stages() {
    let mut scope = Scope::new();
    for instruction in &stage.instructions {
      process_instruction(&mut ctx, instruction, &mut scope);
    }
  }

  true
}

fn process_instruction(
  ctx: &mut DockerContext,
  instruction: &Instruction,
  scope: &mut Scope,
) {
  match instruction {
    Instruction::Env(env) => {
      for var in &env.vars {
        let key = var.key.content.clone();
        let raw = var.value.to_string();
        let resolved = scope.substitute(&raw);

        // Record in scope so later instructions can reference this
        // ENV by name, just like Docker's evaluator does.
        scope.set(key.clone(), resolved.clone());

        if resolved.is_empty() {
          continue;
        }

        if let Some(d) = check_assignment(
          &normalize_name(&key),
          &normalize_value(&resolved),
          AssignmentType::EnvironmentVariable,
          ctx.source_context,
          || compute_span(ctx, var.value.span),
        ) {
          ctx.source_context.emit_diagnostic(d);
        } else {
          // The value is not a hardcoded secret, but a secret-named ENV fed by
          // a build argument (`ENV API_KEY=$ARG`) still bakes it into the image.
        }
      }
    }
    Instruction::Arg(arg) => {
      let key = arg.name.content.clone();

      let Some(value_spanned) = &arg.value else {
        // ARG without a default has its value supplied at build time
        // via `--build-arg`. We can't see that, so don't add it to
        // the scope: leaving the name unset means later `$NAME`
        // references stay literal rather than resolving to an empty
        // string, which would lose information about the unknown.
        return;
      };

      let raw = value_spanned.content.clone();
      let resolved = scope.substitute(&raw);
      scope.set(key.clone(), resolved.clone());
      if resolved.is_empty() {
        return;
      }

      if let Some(d) = check_assignment(
        &normalize_name(&key),
        &normalize_value(&resolved),
        AssignmentType::BuildArgument,
        ctx.source_context,
        || compute_span(ctx, value_spanned.span),
      ) {
        ctx.source_context.emit_diagnostic(d);
      } else {
      }
    }
    Instruction::Run(run) => {
      if let Some(shell_cmd) = run.as_shell() {
        let value = shell_cmd.to_string();
        parse_shell_value(ctx, &value, shell_cmd.span);
      }
    }
    Instruction::Label(label) => {
      for l in &label.labels {
        let key = l.name.content.clone();
        let raw = l.value.content.clone();

        let resolved = scope.substitute(&raw);
        if resolved.is_empty() {
          continue;
        }

        if let Some(d) = check_assignment(
          &normalize_name(&key),
          &normalize_value(&resolved),
          AssignmentType::Property,
          ctx.source_context,
          || compute_span(ctx, l.value.span),
        ) {
          ctx.source_context.emit_diagnostic(d);
        }
      }
    }
    _ => {}
  }
}

fn parse_shell_value(
  ctx: &mut DockerContext,
  value: &str,
  span: dockerfile_parser::Span,
) {
  #[cfg(feature = "lang-shell")]
  {
    let pos = offset_to_position(ctx.source, span.start);
    let shell_context = crate::processing::SourceContext {
      run: ctx.source_context.run,
      file_abs_path: ctx.source_context.file_abs_path,
      file_extension: None,
      body: Some(value),
      file_type: Some(crate::languages::FileType::Shell),
      parent_line: ctx.source_context.parent_line + pos.line.saturating_sub(1),
      parent_col: ctx.source_context.parent_col + pos.column.saturating_sub(1),
      #[cfg(feature = "services")]
      file_services: vec![],
      directives: std::cell::OnceCell::new(),
    };
    crate::languages::shell::parse(&shell_context);
  }

  #[cfg(not(feature = "lang-shell"))]
  {
    let _ = (ctx, value, span);
  }
}

fn compute_span(
  ctx: &DockerContext,
  span: dockerfile_parser::Span,
) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, span.start),
      end: offset_to_position(ctx.source, span.end),
    }),
  }
}

// -----------------------------------------------------------------------------
// Variable substitution
// -----------------------------------------------------------------------------

const MAX_SUBSTITUTION_DEPTH: usize = 16;

struct Scope {
  vars: HashMap<String, String>,
}

impl Scope {
  fn new() -> Self {
    Self {
      vars: HashMap::new(),
    }
  }

  fn set(&mut self, name: String, value: String) {
    self.vars.insert(name, value);
  }

  fn lookup(&self, name: &str) -> Option<&str> {
    self.vars.get(name).map(String::as_str)
  }

  fn substitute(&self, raw: &str) -> String {
    self.substitute_with_depth(raw, 0)
  }

  fn substitute_with_depth(&self, raw: &str, depth: usize) -> String {
    if depth >= MAX_SUBSTITUTION_DEPTH {
      return raw.to_owned();
    }

    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
      if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'$' {
        out.push('$');
        i += 2;
        continue;
      }

      if bytes[i] == b'$' {
        match self.parse_ref(raw, i, depth) {
          RefParse::Resolved(value, end) => {
            out.push_str(&value);
            i = end;
            continue;
          }
          RefParse::Unresolved(end) => {
            // Keep the original `$VAR` / `${VAR...}` text so the
            // classifier sees a literal placeholder rather than a
            // fabricated empty string.
            if let Some(slice) = raw.get(i..end) {
              out.push_str(slice);
            }
            i = end;
            continue;
          }
          RefParse::NotARef => {
            // Bare `$` followed by something that isn't a valid
            // identifier - emit it as literal and move on.
          }
        }
      }

      // Walk by character to stay UTF-8 safe.
      if let Some(ch) = raw.get(i..).and_then(|s| s.chars().next()) {
        out.push(ch);
        i += ch.len_utf8();
      } else {
        break;
      }
    }
    out
  }

  fn parse_ref(&self, raw: &str, dollar_pos: usize, depth: usize) -> RefParse {
    let bytes = raw.as_bytes();
    let Some(&next) = bytes.get(dollar_pos + 1) else {
      return RefParse::NotARef;
    };

    if next == b'{' {
      self.parse_braced(raw, dollar_pos, depth)
    } else if is_identifier_start(next) {
      self.parse_unbraced(raw, dollar_pos, depth)
    } else {
      RefParse::NotARef
    }
  }

  fn parse_unbraced(
    &self,
    raw: &str,
    dollar_pos: usize,
    depth: usize,
  ) -> RefParse {
    let bytes = raw.as_bytes();
    let mut end = dollar_pos + 1;
    while end < bytes.len() && is_identifier_continue(bytes[end]) {
      end += 1;
    }

    let Some(name) = raw.get(dollar_pos + 1..end) else {
      return RefParse::NotARef;
    };

    match self.lookup(name) {
      Some(value) => {
        let resolved = self.substitute_with_depth(value, depth + 1);
        RefParse::Resolved(resolved, end)
      }
      None => RefParse::Unresolved(end),
    }
  }

  fn parse_braced(
    &self,
    raw: &str,
    dollar_pos: usize,
    depth: usize,
  ) -> RefParse {
    let bytes = raw.as_bytes();
    let body_start = dollar_pos + 2;
    let Some(close) = bytes
      .get(body_start..)
      .and_then(|tail| tail.iter().position(|&b| b == b'}'))
    else {
      return RefParse::NotARef;
    };

    let end = body_start + close + 1;
    let Some(inner) = raw.get(body_start..body_start + close) else {
      return RefParse::NotARef;
    };

    let parsed = parse_braced_body(inner);
    let value = self.lookup(&parsed.name);

    let resolved = match (parsed.op, value) {
      // ${VAR}
      (BraceOp::Plain, Some(v)) => v.to_owned(),
      (BraceOp::Plain, None) => return RefParse::Unresolved(end),

      // ${VAR:-default} - use default if unset OR empty.
      (BraceOp::DefaultIfUnsetOrEmpty, Some(v)) if !v.is_empty() => {
        v.to_owned()
      }
      (BraceOp::DefaultIfUnsetOrEmpty, _) => parsed.argument.into_owned(),

      // ${VAR-default} - use default if unset; empty value still wins.
      (BraceOp::DefaultIfUnset, Some(v)) => v.to_owned(),
      (BraceOp::DefaultIfUnset, None) => parsed.argument.into_owned(),

      // ${VAR:+alt} - use alt if set AND non-empty.
      (BraceOp::AltIfSetAndNonEmpty, Some(v)) if !v.is_empty() => {
        parsed.argument.into_owned()
      }
      (BraceOp::AltIfSetAndNonEmpty, _) => String::new(),

      // ${VAR+alt} - use alt if set (even when empty).
      (BraceOp::AltIfSet, Some(_)) => parsed.argument.into_owned(),
      (BraceOp::AltIfSet, None) => String::new(),
    };

    let recursed = self.substitute_with_depth(&resolved, depth + 1);
    RefParse::Resolved(recursed, end)
  }
}

enum RefParse {
  Resolved(String, usize),
  Unresolved(usize),
  NotARef,
}

#[derive(Clone, Copy)]
enum BraceOp {
  Plain,
  DefaultIfUnsetOrEmpty, // :-
  DefaultIfUnset,        // -
  AltIfSetAndNonEmpty,   // :+
  AltIfSet,              // +
}

struct BracedRef<'a> {
  name: std::borrow::Cow<'a, str>,
  op: BraceOp,
  argument: std::borrow::Cow<'a, str>,
}

fn parse_braced_body(inner: &str) -> BracedRef<'_> {
  let bytes = inner.as_bytes();

  let mut i = 0;
  while i < bytes.len() {
    let b = bytes[i];
    if i == 0 && !is_identifier_start(b) {
      break;
    }
    if i > 0 && !is_identifier_continue(b) {
      break;
    }
    i += 1;
  }

  let name = inner.get(..i).unwrap_or("");
  let rest = inner.get(i..).unwrap_or("");

  let (op, argument) = if let Some(arg) = rest.strip_prefix(":-") {
    (BraceOp::DefaultIfUnsetOrEmpty, arg)
  } else if let Some(arg) = rest.strip_prefix(":+") {
    (BraceOp::AltIfSetAndNonEmpty, arg)
  } else if let Some(arg) = rest.strip_prefix('-') {
    (BraceOp::DefaultIfUnset, arg)
  } else if let Some(arg) = rest.strip_prefix('+') {
    (BraceOp::AltIfSet, arg)
  } else {
    (BraceOp::Plain, "")
  };

  BracedRef {
    name: std::borrow::Cow::Borrowed(name),
    op,
    argument: std::borrow::Cow::Borrowed(argument),
  }
}

fn is_identifier_start(b: u8) -> bool {
  b.is_ascii_alphabetic() || b == b'_'
}

fn is_identifier_continue(b: u8) -> bool {
  b.is_ascii_alphanumeric() || b == b'_'
}
