use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_credential_assignment,
    offset_to_position,
  },
  processing::SourceContext,
  secrets::values::normalize::normalize_value,
};

const PASSWORD_DIRECTIVES: &[&str] = &[
  "requirepass",
  "masterauth",
  "tls-key-file-pass",
  "tls-replication-key-file-pass",
];

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let mut line_start: usize = 0;
  while line_start < source.len() {
    let remaining = source.get(line_start..).unwrap_or_default();
    let line_len = remaining.find('\n').unwrap_or(remaining.len());
    let line = remaining
      .get(..line_len)
      .unwrap_or_default()
      .trim_end_matches('\r');

    process_line(context, source, line, line_start);

    line_start += line_len + 1;
  }

  true
}

fn process_line(
  context: &SourceContext,
  source: &str,
  line: &str,
  line_offset: usize,
) {
  let leading_ws = line.len() - line.trim_start().len();
  let content = line.trim_start();
  if content.is_empty() || content.starts_with('#') {
    return;
  }

  let tokens = tokenize(content, line_offset + leading_ws);
  let Some(directive) = tokens.first() else {
    return;
  };
  let directive_text = directive.text.to_ascii_lowercase();

  if PASSWORD_DIRECTIVES.contains(&directive_text.as_str()) {
    if let Some(value) = tokens.get(1) {
      emit(
        context,
        source,
        &directive_text,
        value.text,
        value.start,
        value.end,
        AssignmentType::Directive,
      );
    }
    return;
  }

  if directive_text == "user" {
    let Some(username) = tokens.get(1) else {
      return;
    };
    for token in tokens.iter().skip(2) {
      let Some(first) = token.text.as_bytes().first().copied() else {
        continue;
      };

      if !matches!(first, b'>' | b'<' | b'#' | b'!') {
        continue;
      }

      let value = token.text.get(1..).unwrap_or_default();
      if value.is_empty() {
        continue;
      }

      emit(
        context,
        source,
        username.text,
        value,
        token.start + 1,
        token.end,
        AssignmentType::User,
      );
    }
  }
}

fn emit(
  context: &SourceContext,
  source: &str,
  display_name: &str,
  value: &str,
  start: usize,
  end: usize,
  assignment_type: AssignmentType,
) {
  let value = strip_quotes(value);
  if value.is_empty() {
    return;
  }
  if let Some(d) = check_credential_assignment(
    display_name,
    &normalize_value(&value.to_owned()),
    assignment_type,
    context,
    || SourceFileSpan {
      file_abs_path: context.file_abs_path.to_path_buf(),
      file_span: Some(SourceSpan {
        start: offset_to_position(source, start),
        end: offset_to_position(source, end),
      }),
    },
  ) {
    context.emit_diagnostic(d);
  }
}

struct Token<'a> {
  text: &'a str,
  start: usize,
  end: usize,
}

fn tokenize(line: &str, line_offset: usize) -> Vec<Token<'_>> {
  let mut tokens = Vec::new();
  let bytes = line.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    let b = bytes[i];
    if b.is_ascii_whitespace() {
      i += 1;
      continue;
    }
    let start = i;
    if b == b'"' || b == b'\'' {
      let quote = b;
      i += 1;
      while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
          i += 2;
          continue;
        }
        if c == quote {
          i += 1;
          break;
        }
        i += 1;
      }
    } else {
      while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
      }
    }
    let end = i;
    if let Some(text) = line.get(start..end) {
      tokens.push(Token {
        text,
        start: line_offset + start,
        end: line_offset + end,
      });
    }
  }
  tokens
}

fn strip_quotes(value: &str) -> &str {
  let bytes = value.as_bytes();
  if bytes.len() >= 2 {
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
      return value.get(1..value.len() - 1).unwrap_or(value);
    }
  }
  value
}
