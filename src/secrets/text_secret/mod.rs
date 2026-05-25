use std::ops::Range;

#[cfg(feature = "pem")]
pub mod pem;
#[cfg(feature = "putty")]
pub mod putty;

#[cfg(feature = "pem")]
use crate::secrets::pem::PrivateKey;
#[cfg(feature = "putty")]
use crate::secrets::putty::PuttyKey;

#[derive(Debug)]
pub enum TextSecret {
  #[cfg(feature = "pem")]
  Pem(Vec<PrivateKey>),
  #[cfg(feature = "putty")]
  Putty(Vec<PuttyKey>),
}

impl std::fmt::Display for TextSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    #[cfg(feature = "pem")]
    #[allow(irrefutable_let_patterns)]
    if let Self::Pem(keys) = self
      && let Some(first) = keys.first()
    {
      return write!(f, "{first}");
    }

    #[cfg(feature = "putty")]
    #[allow(irrefutable_let_patterns)]
    if let Self::Putty(keys) = self
      && let Some(first) = keys.first()
    {
      return write!(f, "{first}");
    }

    let _ = f;
    Ok(())
  }
}

#[cfg(any(feature = "pem", feature = "putty"))]
fn is_only_filler_around(content: &str, ranges: &[Range<usize>]) -> bool {
  let mut sorted: Vec<Range<usize>> = ranges.to_vec();
  sorted.sort_by_key(|r| r.start);

  let mut cursor = 0;
  for r in &sorted {
    let Some(filler) = content.get(cursor..r.start) else {
      return false;
    };
    if !is_acceptable_filler(filler) {
      return false;
    }
    cursor = r.end;
  }

  let Some(trailing) = content.get(cursor..) else {
    return false;
  };

  is_acceptable_filler(trailing)
}

#[cfg(any(feature = "pem", feature = "putty"))]
fn is_acceptable_filler(s: &str) -> bool {
  s.lines().all(is_acceptable_line)
}

#[cfg(any(feature = "pem", feature = "putty"))]
fn is_acceptable_line(line: &str) -> bool {
  let trimmed = line.trim();
  trimmed.is_empty() || is_comment_line(trimmed) || is_header_line(trimmed)
}

#[cfg(any(feature = "pem", feature = "putty"))]
fn is_comment_line(line: &str) -> bool {
  line.starts_with('#')
}

#[cfg(any(feature = "pem", feature = "putty"))]
fn is_header_line(line: &str) -> bool {
  if let Some(separator) = line.find(|c: char| c == ':' || c == '=') {
    let Some(prefix) = line.get(..separator) else {
      return false;
    };
    !prefix.is_empty()
      && prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
  } else {
    false
  }
}
