use std::borrow::Cow;

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, check_assignment, check_password_field,
    check_value, compute_file_span,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

struct ConfigContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  assignment_type: AssignmentType,
  is_npmrc: bool,
}

/// Parses .env, .ini, .properties, .cfg, and .conf files.
///
/// Handles `=` and `:` separators, `#` / `!` / `;` comments, `[section]`
/// headers, `export` prefix, quoted values, and `\`-continuation lines.
pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let is_npmrc = super::file_type_from_path(context.file_abs_path)
    == Some(super::FileType::Npmrc);

  let mut ctx = ConfigContext {
    source,
    source_context: context,
    assignment_type: assignment_type_for(context),
    is_npmrc,
  };

  let mut pos: usize = 0;

  while pos < source.len() {
    let remaining = source.get(pos..).unwrap_or_default();
    let line_len = remaining.find('\n').unwrap_or(remaining.len());
    let line = remaining
      .get(..line_len)
      .unwrap_or_default()
      .trim_end_matches('\r');

    let line_start = pos;
    pos += line_len + 1;

    // Join continuation lines (trailing odd `\`).
    let (logical, end_pos) = if has_continuation(line) {
      join_continuation(line, source, &mut pos)
    } else {
      (Cow::Borrowed(line), line_start + line.len())
    };

    process_line(&mut ctx, &logical, line_start, end_pos);
  }

  true
}

fn process_line(
  ctx: &mut ConfigContext,
  line: &str,
  line_start: usize,
  line_end: usize,
) {
  let trimmed = line.trim_start();

  if trimmed.is_empty()
    || trimmed.starts_with('#')
    || trimmed.starts_with('!')
    || trimmed.starts_with(';')
    || trimmed.starts_with('[')
  {
    return;
  }

  // Strip optional `export ` prefix (.env convention).
  let content = trimmed
    .strip_prefix("export ")
    .or_else(|| trimmed.strip_prefix("export\t"))
    .unwrap_or(trimmed);

  let Some(sep) = find_separator(content, !ctx.is_npmrc) else {
    return;
  };

  let key = content.get(..sep).unwrap_or_default().trim_end();
  let after_sep = content.get(sep + 1..).unwrap_or_default();
  let trimmed_after_sep = after_sep.trim_start();
  let raw_value = strip_inline_comment(trimmed_after_sep);
  let value = unquote(raw_value);

  if key.is_empty() || value.is_empty() {
    return;
  }

  let leading_ws_after_sep = after_sep.len() - trimmed_after_sep.len();
  let (value_start, value_end) = value_span(
    line,
    line_start,
    line_end,
    content,
    sep,
    leading_ws_after_sep,
    raw_value.len(),
  );

  let key = key.to_owned();
  if let Some(d) = check_assignment(
    &normalize_name(&key),
    &normalize_value(&value),
    ctx.assignment_type,
    ctx.source_context,
    || compute_span(ctx, value_start, value_end),
  ) {
    ctx.source_context.emit_diagnostic(d);
  }
}

fn value_span(
  line: &str,
  line_start: usize,
  line_end: usize,
  content: &str,
  sep: usize,
  leading_ws_after_sep: usize,
  raw_value_len: usize,
) -> (usize, usize) {
  let is_continuation = line_end - line_start != line.len();
  if is_continuation {
    return (line_start, line_end);
  }

  let leading_ws_in_line = line.len() - line.trim_start().len();
  let trimmed_len = line.len() - leading_ws_in_line;
  let export_len = trimmed_len - content.len();
  let start = line_start
    + leading_ws_in_line
    + export_len
    + sep
    + 1
    + leading_ws_after_sep;

  (start, start + raw_value_len)
}

fn assignment_type_for(context: &SourceContext) -> AssignmentType {
  if super::is_env_file(context.file_abs_path) {
    AssignmentType::EnvironmentVariable
  } else if super::is_user_database_file(context.file_abs_path) {
    AssignmentType::User
  } else {
    AssignmentType::Property
  }
}

/// Finds the first unescaped `=` separator, or `:` when `allow_colon` is set.
fn find_separator(line: &str, allow_colon: bool) -> Option<usize> {
  let mut escaped = false;
  for (i, b) in line.bytes().enumerate() {
    if escaped {
      escaped = false;
      continue;
    }
    if b == b'\\' {
      escaped = true;
      continue;
    }
    if b == b'=' || (allow_colon && b == b':') {
      return Some(i);
    }
  }
  None
}

fn strip_inline_comment(value: &str) -> &str {
  if value.starts_with('"') || value.starts_with('\'') {
    return value;
  }

  let bytes = value.as_bytes();
  let mut i = 0;

  while i < bytes.len() {
    let b = bytes.get(i).copied().unwrap_or(0);
    if (b == b'#' || b == b';')
      && i > 0
      && matches!(bytes.get(i - 1).copied(), Some(b' ' | b'\t'))
    {
      return value.get(..i).unwrap_or(value).trim_end();
    }
    i += 1;
  }

  value.trim_end()
}

/// Strips matching surrounding quotes (double or single).
fn unquote(value: &str) -> String {
  let v = value.trim();
  if v.len() >= 2
    && ((v.starts_with('"') && v.ends_with('"'))
      || (v.starts_with('\'') && v.ends_with('\'')))
  {
    v.get(1..v.len() - 1).unwrap_or_default().to_owned()
  } else {
    v.to_owned()
  }
}

/// Joins continuation lines (lines ending with an odd number of `\`).
fn join_continuation<'a>(
  first_line: &str,
  source: &'a str,
  pos: &mut usize,
) -> (Cow<'a, str>, usize) {
  let mut buf = strip_trailing_backslash(first_line).to_owned();

  loop {
    let remaining = source.get(*pos..).unwrap_or_default();
    if remaining.is_empty() {
      break;
    }

    let line_len = remaining.find('\n').unwrap_or(remaining.len());
    let line = remaining
      .get(..line_len)
      .unwrap_or_default()
      .trim_end_matches('\r');

    *pos += line_len + 1;

    if has_continuation(line) {
      buf.push_str(strip_trailing_backslash(line.trim_start()));
    } else {
      buf.push_str(line.trim_start());
      break;
    }
  }

  let end = (*pos).min(source.len());
  (Cow::Owned(buf), end)
}

fn has_continuation(line: &str) -> bool {
  let count = line.bytes().rev().take_while(|&b| b == b'\\').count();
  count % 2 == 1
}

fn strip_trailing_backslash(line: &str) -> &str {
  line.get(..line.len() - 1).unwrap_or(line)
}

fn compute_span(
  ctx: &ConfigContext,
  start: usize,
  end: usize,
) -> SourceFileSpan {
  compute_file_span(ctx.source_context, ctx.source, start, end)
}

fn emit_password_field(
  context: &SourceContext,
  source: &str,
  value: &str,
  start: usize,
  end: usize,
) {
  if let Some(d) = check_password_field(
    "password",
    value,
    AssignmentType::Property,
    context,
    || compute_file_span(context, source, start, end),
  ) {
    context.emit_diagnostic(d);
  }
}

pub fn parse_netrc(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let tokens = whitespace_tokens(source);
  let mut i = 0;

  while i < tokens.len() {
    if tokens[i].0.eq_ignore_ascii_case("password") {
      if let Some(&(value, start, end)) = tokens.get(i + 1) {
        emit_password_field(context, source, value, start, end);
      }
      i += 2;
    } else {
      i += 1;
    }
  }

  true
}

fn whitespace_tokens(source: &str) -> Vec<(&str, usize, usize)> {
  let bytes = source.as_bytes();
  let mut tokens = Vec::new();
  let mut i = 0;

  while i < bytes.len() {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
      i += 1;
    }
    let start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
      i += 1;
    }
    if i > start
      && let Some(tok) = source.get(start..i)
    {
      tokens.push((tok, start, i));
    }
  }

  tokens
}

pub fn parse_pgpass(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  for_each_line(source, |line, line_start| {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
      return;
    }

    let Some(field_start) = pgpass_password_offset(line) else {
      return;
    };

    let raw = line.get(field_start..).unwrap_or_default();
    if raw.is_empty() {
      return;
    }

    emit_password_field(
      context,
      source,
      &pgpass_unescape(raw),
      line_start + field_start,
      line_start + line.len(),
    );
  });

  true
}

fn pgpass_password_offset(line: &str) -> Option<usize> {
  let bytes = line.as_bytes();
  let mut colons = 0;
  let mut i = 0;

  while i < bytes.len() {
    match bytes[i] {
      b'\\' => i += 2,
      b':' => {
        colons += 1;
        i += 1;
        if colons == 4 {
          return Some(i);
        }
      }
      _ => i += 1,
    }
  }

  None
}

fn pgpass_unescape(value: &str) -> String {
  let mut out = String::with_capacity(value.len());
  let mut chars = value.chars();

  while let Some(c) = chars.next() {
    if c == '\\' {
      if let Some(next) = chars.next() {
        out.push(next);
      }
    } else {
      out.push(c);
    }
  }

  out
}

pub fn parse_esmtprc(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  for_each_line(source, |line, line_start| {
    let lead = line.len() - line.trim_start().len();
    let content = line.trim_start();
    if content.is_empty() || content.starts_with('#') {
      return;
    }

    let Some(sep) = content.find(|c: char| c.is_ascii_whitespace()) else {
      return;
    };
    let key = content.get(..sep).unwrap_or_default();
    if !matches!(
      key.to_ascii_lowercase().as_str(),
      "password" | "passwd" | "pwd"
    ) {
      return;
    }

    let after_key = content.get(sep..).unwrap_or_default();
    let value_lead = after_key.len() - after_key.trim_start().len();
    let raw_value = after_key.trim_start();
    if raw_value.is_empty() {
      return;
    }

    emit_password_field(
      context,
      source,
      &unquote(raw_value),
      line_start + lead + sep + value_lead,
      line_start + line.len(),
    );
  });

  true
}

fn for_each_line(source: &str, mut handle: impl FnMut(&str, usize)) {
  let mut pos = 0;
  while pos < source.len() {
    let remaining = source.get(pos..).unwrap_or_default();
    let line_len = remaining.find('\n').unwrap_or(remaining.len());
    let line = remaining
      .get(..line_len)
      .unwrap_or_default()
      .trim_end_matches('\r');
    let line_start = pos;
    pos += line_len + 1;

    handle(line, line_start);
  }
}

pub fn parse_git_credentials(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  for_each_line(source, |line, line_start| {
    let lead = line.len() - line.trim_start().len();
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
      return;
    }

    let start = line_start + lead;
    let end = start + trimmed.len();

    if let Some(d) = check_value(&normalize_value(&trimmed), context, || {
      compute_file_span(context, source, start, end)
    }) {
      context.emit_diagnostic(d);
    }
  });

  true
}
