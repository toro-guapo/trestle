#[derive(Debug, Clone)]
pub struct Directive {
  pub kind: DirectiveKind,
  pub scope_start: usize,
  pub scope_end: usize,
  pub next_non_blank: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum DirectiveKind {
  Skip,
}

#[derive(Debug, Default)]
pub struct DirectiveMap {
  directives: Vec<Directive>,
}

const PREFIX: &str = "trestle:";
const SKIP_VERB: &str = "skip";
const MAX_SCOPE_LINES: usize = 20;

impl DirectiveMap {
  pub fn scan(source: &str) -> Self {
    let lines: Vec<&str> = source.lines().collect();
    let mut directives = Vec::new();

    for (i, line) in lines.iter().enumerate() {
      let line_no = i + 1;
      let Some((kind, is_leading)) = parse_directive_line(line) else {
        continue;
      };

      let (start, end) = if is_leading {
        let scope_end = compute_leading_scope(&lines, i);
        (line_no + 1, scope_end)
      } else {
        (line_no, line_no)
      };

      let next_non_blank = (i + 1..lines.len())
        .find(|&j| !lines[j].trim().is_empty())
        .map(|j| j + 1);

      if start > end && next_non_blank.is_none() {
        continue;
      }

      directives.push(Directive {
        kind,
        scope_start: start,
        scope_end: end,
        next_non_blank,
      });
    }

    Self { directives }
  }

  pub fn skip_covering(&self, line: usize) -> Option<&Directive> {
    self.directives.iter().find(|d| {
      if !matches!(d.kind, DirectiveKind::Skip) {
        return false;
      }
      let in_scope = d.scope_start <= d.scope_end
        && line >= d.scope_start
        && line <= d.scope_end;
      let is_next_non_blank = d.next_non_blank == Some(line);
      in_scope || is_next_non_blank
    })
  }
}

fn parse_directive_line(line: &str) -> Option<(DirectiveKind, bool)> {
  let prefix_pos = line.find(PREFIX)?;
  let before = line.get(..prefix_pos)?;
  let trimmed_before = before.trim_end();

  let delim_len = if trimmed_before.ends_with("<!--") {
    4
  } else if trimmed_before.ends_with("//") {
    2
  } else if trimmed_before.ends_with("/*") {
    2
  } else if trimmed_before.ends_with("--") {
    2
  } else if trimmed_before.ends_with('#') {
    1
  } else if trimmed_before.ends_with(';') {
    1
  } else {
    return None;
  };

  let prefix_before_delim =
    trimmed_before.get(..trimmed_before.len() - delim_len)?;

  let is_leading = prefix_before_delim
    .chars()
    .all(|c| c.is_whitespace() || matches!(c, '{' | '(' | '['));

  let after_prefix = line.get(prefix_pos + PREFIX.len()..)?;
  let (verb, _payload) = split_verb(after_prefix);

  let kind = match verb {
    SKIP_VERB => DirectiveKind::Skip,
    _ => return None,
  };

  Some((kind, is_leading))
}

fn split_verb(after_prefix: &str) -> (&str, &str) {
  let end = after_prefix
    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .unwrap_or(after_prefix.len());
  (
    after_prefix.get(..end).unwrap_or(""),
    after_prefix.get(end..).unwrap_or(""),
  )
}

fn compute_leading_scope(lines: &[&str], directive_idx: usize) -> usize {
  let next_idx = directive_idx + 1;
  let Some(next_line) = lines.get(next_idx).copied() else {
    return directive_idx + 1;
  };
  if next_line.trim().is_empty() {
    return next_idx;
  }

  let baseline_indent = indent_of(next_line);
  let mut end = next_idx + 1;

  for offset in 2..=MAX_SCOPE_LINES {
    let idx = directive_idx + offset;
    let Some(line) = lines.get(idx).copied() else {
      break;
    };
    if line.trim().is_empty() {
      break;
    }
    if indent_of(line) <= baseline_indent {
      break;
    }
    end = idx + 1;
  }

  end
}

fn indent_of(line: &str) -> usize {
  line.chars().take_while(|c| c.is_whitespace()).count()
}
