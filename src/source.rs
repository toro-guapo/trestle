use std::path::PathBuf;

pub fn compute_line_starts(source: &str) -> Vec<usize> {
  let mut starts = vec![0];
  for (i, &b) in source.as_bytes().iter().enumerate() {
    if b == b'\n' {
      starts.push(i + 1);
    }
  }
  starts
}

#[derive(Debug)]
pub struct SourcePosition {
  pub line: usize,
  pub column: usize,
}

impl std::fmt::Display for SourcePosition {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", self.line, self.column)
  }
}

#[derive(Debug)]
pub struct SourceSpan {
  pub start: SourcePosition,
  pub end: SourcePosition,
}

impl std::fmt::Display for SourceSpan {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}-{}", self.start, self.end)
  }
}

#[derive(Debug)]
pub struct SourceFileSpan {
  pub file_abs_path: PathBuf,
  pub file_span: Option<SourceSpan>,
}

impl SourceFileSpan {
  pub fn display_path(&self) -> String {
    self.file_abs_path.display().to_string()
  }

  pub fn display(&self) -> String {
    match &self.file_span {
      Some(span) => format!("{}:{}", self.display_path(), span),
      None => self.display_path(),
    }
  }

  pub fn display_start(&self) -> String {
    match &self.file_span {
      Some(span) => format!("{}:{}", self.display_path(), span.start),
      None => self.display_path(),
    }
  }

  pub fn display_end(&self) -> String {
    match &self.file_span {
      Some(span) => format!("{}:{}", self.display_path(), span.end),
      None => self.display_path(),
    }
  }
}

impl std::fmt::Display for SourceFileSpan {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.display())
  }
}

pub fn offset_to_position(source: &str, offset: usize) -> SourcePosition {
  let slice = source.get(..offset).unwrap_or(source);
  let line = slice.bytes().filter(|&b| b == b'\n').count() + 1;
  let last_newline = slice.rfind('\n').map_or(0, |pos| pos + 1);
  let column = source
    .get(last_newline..offset)
    .unwrap_or("")
    .chars()
    .count()
    + 1;

  SourcePosition { line, column }
}
