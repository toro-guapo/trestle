use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, SourceFileSpan, SourceSpan, check_assignment,
    check_value, offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

struct SqlContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted_value_ranges: Vec<(usize, usize)>,
}

impl SqlContext<'_> {
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

enum Token {
  Word(usize, usize),
  Assign,
  ColonAssign,
  Open,
  Close,
  Stop,
}

const MAX_BODY_DEPTH: usize = 4;

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let mut ctx = SqlContext {
    source,
    source_context: context,
    emitted_value_ranges: Vec::new(),
  };

  scan(&mut ctx, source);

  true
}

fn scan(ctx: &mut SqlContext, source: &str) {
  scan_range(ctx, source, 0, source.len(), 0);
}

fn scan_range(
  ctx: &mut SqlContext,
  source: &str,
  lo: usize,
  hi: usize,
  depth: usize,
) {
  let bytes = source.as_bytes();
  let n = bytes.len();
  let mut i = lo;
  let mut recent: Vec<Token> = Vec::new();

  while i < hi {
    let Some(&b) = bytes.get(i) else {
      break;
    };

    if b == b'-' && bytes.get(i + 1) == Some(&b'-') {
      i += 2;
      while i < n && bytes.get(i) != Some(&b'\n') {
        i += 1;
      }
      continue;
    }

    if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
      i += 2;
      while i < n
        && !(bytes.get(i) == Some(&b'*') && bytes.get(i + 1) == Some(&b'/'))
      {
        i += 1;
      }
      i = (i + 2).min(n);
      continue;
    }

    // MySQL `#` line comment. T-SQL temp tables (`#temp`) attach an identifier
    // with no space, so only a `#` followed by whitespace begins a comment.
    if b == b'#' && bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace) {
      while i < n && bytes.get(i) != Some(&b'\n') {
        i += 1;
      }
      continue;
    }

    if b.is_ascii_whitespace() {
      i += 1;
      continue;
    }

    if b == b'\'' || b == b'"' {
      let (start, end, next) = lex_quoted(bytes, i, b);
      classify_string(ctx, source, &recent, start, end);
      push(&mut recent, Token::Stop);
      i = next;
      continue;
    }

    if b == b'`' {
      let (start, end, next) = lex_quoted(bytes, i, b'`');
      push(&mut recent, Token::Word(start, end));
      i = next;
      continue;
    }

    if b == b'$' {
      if let Some((start, end, next)) = lex_dollar(bytes, i) {
        classify_string(ctx, source, &recent, start, end);
        if depth < MAX_BODY_DEPTH {
          scan_range(ctx, source, start, end, depth + 1);
        }
        push(&mut recent, Token::Stop);
        i = next;
      } else {
        push(&mut recent, Token::Stop);
        i += 1;
      }
      continue;
    }

    if b.is_ascii_alphabetic() || b == b'_' || b == b'@' || b == b'#' {
      let start = i;
      i += 1;
      while i < n && bytes.get(i).is_some_and(is_word_continue) {
        i += 1;
      }
      if i - start == 1 && bytes.get(i) == Some(&b'\'') {
        let prefix = b.to_ascii_lowercase();

        if prefix == b'q' {
          let (cstart, cend, next) = lex_q_quote(bytes, i);
          classify_string(ctx, source, &recent, cstart, cend);
          push(&mut recent, Token::Stop);
          i = next;
          continue;
        }

        if matches!(prefix, b'e' | b'n' | b'b' | b'x') {
          let (cstart, cend, next) = lex_quoted(bytes, i, b'\'');
          classify_string(ctx, source, &recent, cstart, cend);
          push(&mut recent, Token::Stop);
          i = next;
          continue;
        }
      }
      push(&mut recent, Token::Word(start, i));

      continue;
    }

    if b == b':' {
      if bytes.get(i + 1) == Some(&b'=') {
        push(&mut recent, Token::ColonAssign);
        i += 2;
        continue;
      }
      if bytes
        .get(i + 1)
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
      {
        let start = i;
        i += 1;
        while i < n && bytes.get(i).is_some_and(is_word_continue) {
          i += 1;
        }
        push(&mut recent, Token::Word(start, i));

        continue;
      }
      push(&mut recent, Token::Stop);
      i += 1;
      continue;
    }

    if b.is_ascii_digit() {
      i += 1;
      while i < n && bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
      }
      push(&mut recent, Token::Stop);
      continue;
    }

    match b {
      b'=' => push(&mut recent, Token::Assign),
      b'(' => push(&mut recent, Token::Open),
      b')' => push(&mut recent, Token::Close),
      b';' => {
        push(&mut recent, Token::Stop);
      }
      _ => push(&mut recent, Token::Stop),
    }
    i += 1;
  }
}

fn is_word_continue(c: &u8) -> bool {
  c.is_ascii_alphanumeric() || *c == b'_' || *c == b'@' || *c == b'#'
}

fn push(recent: &mut Vec<Token>, token: Token) {
  recent.push(token);
  if recent.len() > 16 {
    recent.remove(0);
  }
}

fn lex_quoted(bytes: &[u8], start: usize, quote: u8) -> (usize, usize, usize) {
  let n = bytes.len();
  let content = start + 1;
  let mut i = content;
  while i < n {
    match bytes.get(i) {
      Some(&c) if c == quote => {
        if bytes.get(i + 1) == Some(&quote) {
          i += 2;
          continue;
        }
        return (content, i, i + 1);
      }
      Some(b'\\') if quote == b'\'' => i += 2,
      _ => i += 1,
    }
  }
  (content, n, n)
}

// Oracle alternative quoting: `q'<d>...<d>'`, where the delimiter is the
// character after the quote (brackets pair, anything else closes with itself).
fn lex_q_quote(bytes: &[u8], quote: usize) -> (usize, usize, usize) {
  let n = bytes.len();
  let close = match bytes.get(quote + 1) {
    Some(b'[') => b']',
    Some(b'(') => b')',
    Some(b'{') => b'}',
    Some(b'<') => b'>',
    Some(&c) => c,
    None => return (quote + 1, n, n),
  };

  let content = quote + 2;
  let mut i = content;

  while i < n {
    if bytes.get(i) == Some(&close) && bytes.get(i + 1) == Some(&b'\'') {
      return (content, i, i + 2);
    }
    i += 1;
  }

  (content, n, n)
}

// PostgreSQL dollar-quoting: `$tag$ ... $tag$`, tag empty or an identifier. A
// leading digit (`$1`) is a positional parameter, not a string.
fn lex_dollar(bytes: &[u8], start: usize) -> Option<(usize, usize, usize)> {
  let n = bytes.len();
  let mut tag_end = start + 1;
  while tag_end < n
    && bytes
      .get(tag_end)
      .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
  {
    tag_end += 1;
  }
  if bytes.get(tag_end) != Some(&b'$') {
    return None;
  }
  if bytes.get(start + 1).is_some_and(|c| c.is_ascii_digit()) {
    return None;
  }

  let opener = bytes.get(start..tag_end + 1)?;
  let content = tag_end + 1;
  let mut i = content;
  while i < n {
    if bytes.get(i) == Some(&b'$')
      && bytes.get(i..i + opener.len()) == Some(opener)
    {
      return Some((content, i, i + opener.len()));
    }
    i += 1;
  }
  Some((content, n, n))
}

fn classify_string(
  ctx: &mut SqlContext,
  source: &str,
  recent: &[Token],
  content_start: usize,
  content_end: usize,
) {
  let Some(value) = source.get(content_start..content_end) else {
    return;
  };

  match credential_name(source, recent) {
    Some((name, assignment_type)) => emit_raw(
      ctx,
      Some(&name),
      value,
      content_start,
      content_end,
      assignment_type,
    ),
    None => emit_raw(
      ctx,
      None,
      value,
      content_start,
      content_end,
      AssignmentType::Variable,
    ),
  }
}

// Names a string from the tokens before it: a credential keyword
// (`PASSWORD '...'`, `IDENTIFIED BY '...'`, `SECRET = '...'`) or an assignment
// target, including typed declarations (`@pw NVARCHAR(50) = '...'`). Otherwise
// the string is unnamed.
fn credential_name(
  source: &str,
  recent: &[Token],
) -> Option<(String, AssignmentType)> {
  if !matches!(recent.last(), Some(Token::ColonAssign))
    && let Some(canonical) = find_credential(recent, source)
  {
    return Some((canonical.to_owned(), AssignmentType::Property));
  }

  if matches!(recent.last(), Some(Token::Assign | Token::ColonAssign)) {
    let before = recent.len().checked_sub(2)?;
    if let Some(name) = assignment_target(source, recent, before) {
      return Some((name, AssignmentType::Variable));
    }
  }

  None
}

fn find_credential(recent: &[Token], source: &str) -> Option<&'static str> {
  for token in recent.iter().rev().take(6) {
    match token {
      Token::Assign | Token::ColonAssign | Token::Open => continue,
      Token::Word(start, end) => {
        let word = source
          .get(*start..*end)
          .map(str::to_ascii_lowercase)
          .unwrap_or_default();
        if let Some(canonical) = credential_keyword(&word) {
          return Some(canonical);
        }
      }
      Token::Close | Token::Stop => return None,
    }
  }
  None
}

// The token before `=` is usually the target. When it is a type (`@pw INT =`)
// or the close of a size spec (`@pw NVARCHAR(50) =`), step back over the type
// to the variable it declares.
fn assignment_target(
  source: &str,
  recent: &[Token],
  before: usize,
) -> Option<String> {
  let mut index = before;

  if matches!(recent.get(index), Some(Token::Close)) {
    let mut depth = 1;
    loop {
      index = index.checked_sub(1)?;
      match recent.get(index) {
        Some(Token::Close) => depth += 1,
        Some(Token::Open) => {
          depth -= 1;
          if depth == 0 {
            break;
          }
        }
        _ => {}
      }
    }
    index = index.checked_sub(1)?;
  }

  if let Some(Token::Word(start, end)) = recent.get(index) {
    let word = source.get(*start..*end)?;
    if index == before && !is_type_keyword(&word.to_ascii_lowercase()) {
      return non_empty(strip_sigils(word));
    }
    if is_type_keyword(&word.to_ascii_lowercase()) {
      index = index.checked_sub(1)?;
      if let Some(Token::Word(s, e)) = recent.get(index)
        && source.get(*s..*e).map(str::to_ascii_lowercase).as_deref()
          == Some("as")
      {
        index = index.checked_sub(1)?;
      }
      if let Some(Token::Word(vstart, vend)) = recent.get(index) {
        return non_empty(strip_sigils(source.get(*vstart..*vend)?));
      }
    }
  }

  None
}

fn non_empty(name: &str) -> Option<String> {
  (!name.is_empty()).then(|| name.to_owned())
}

fn credential_keyword(word: &str) -> Option<&'static str> {
  match word {
    "password" => Some("password"),
    "passwd" => Some("passwd"),
    "pwd" => Some("pwd"),
    "secret" => Some("secret"),
    "identified" => Some("password"),
    _ => None,
  }
}

fn is_type_keyword(word: &str) -> bool {
  matches!(
    word,
    "int"
      | "integer"
      | "bigint"
      | "smallint"
      | "tinyint"
      | "bit"
      | "decimal"
      | "numeric"
      | "dec"
      | "float"
      | "real"
      | "double"
      | "money"
      | "smallmoney"
      | "char"
      | "character"
      | "varchar"
      | "varchar2"
      | "nchar"
      | "nvarchar"
      | "text"
      | "ntext"
      | "string"
      | "binary"
      | "varbinary"
      | "bytea"
      | "blob"
      | "clob"
      | "date"
      | "datetime"
      | "datetime2"
      | "smalldatetime"
      | "time"
      | "timestamp"
      | "year"
      | "bool"
      | "boolean"
      | "uuid"
      | "uniqueidentifier"
      | "xml"
      | "json"
      | "jsonb"
  )
}

fn strip_sigils(word: &str) -> &str {
  word.trim_matches(|c| matches!(c, '@' | ':' | '#' | '"' | '`'))
}

fn emit_raw(
  ctx: &mut SqlContext,
  name: Option<&str>,
  value: &str,
  start: usize,
  end: usize,
  assignment_type: AssignmentType,
) {
  if ctx.already_emitted(start, end) {
    return;
  }

  let normalized = normalize_value(&value);
  let span = || SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, start),
      end: offset_to_position(ctx.source, end),
    }),
  };

  let diag: Option<Diagnostic> = match name {
    Some(n) => check_assignment(
      &normalize_name(&n),
      &normalized,
      assignment_type,
      ctx.source_context,
      span,
    ),
    None => check_value(&normalized, ctx.source_context, span),
  };

  if let Some(d) = diag {
    ctx.record_emitted(start, end);
    ctx.source_context.emit_diagnostic(d);
  }
}
