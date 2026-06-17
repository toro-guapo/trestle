pub struct Region {
  pub full_start: usize,
  pub full_end: usize,
  pub code: Option<CodeInner>,
}

pub struct CodeInner {
  pub start: usize,
  pub end: usize,
  // A byte (inside the blanked delimiter) to set to `;` so the fragment is a
  // statement once fragments are concatenated in the code buffer.
  pub semicolon_at: Option<usize>,
}

impl Region {
  pub fn code(
    full_start: usize,
    full_end: usize,
    start: usize,
    end: usize,
    semicolon_at: Option<usize>,
  ) -> Self {
    Region {
      full_start,
      full_end,
      code: Some(CodeInner {
        start,
        end,
        semicolon_at,
      }),
    }
  }

  pub fn mask(full_start: usize, full_end: usize) -> Self {
    Region {
      full_start,
      full_end,
      code: None,
    }
  }
}

pub fn mask_markup(source: &str, regions: &[Region]) -> String {
  let mut buf = source.as_bytes().to_vec();
  for region in regions {
    for byte in &mut buf[region.full_start..region.full_end] {
      if *byte != b'\n' {
        *byte = b' ';
      }
    }
  }
  String::from_utf8(buf).unwrap_or_else(|_| source.to_owned())
}

pub fn build_code(source: &str, regions: &[Region], open: &[u8]) -> String {
  let bytes = source.as_bytes();
  let mut buf: Vec<u8> = bytes
    .iter()
    .map(|&b| if b == b'\n' { b'\n' } else { b' ' })
    .collect();

  for region in regions {
    if let Some(code) = &region.code {
      buf[code.start..code.end].copy_from_slice(&bytes[code.start..code.end]);
      if let Some(pos) = code.semicolon_at
        && let Some(slot) = buf.get_mut(pos)
      {
        *slot = b';';
      }
    }
  }

  for (k, &b) in open.iter().enumerate() {
    if let Some(slot) = buf.get_mut(k) {
      *slot = b;
    }
  }

  String::from_utf8(buf).unwrap_or_else(|_| source.to_owned())
}

pub fn matches_at(bytes: &[u8], i: usize, needle: &[u8]) -> bool {
  bytes.get(i..i + needle.len()) == Some(needle)
}

pub fn contains_html_markup(source: &str) -> bool {
  let bytes = source.as_bytes();
  bytes.iter().enumerate().any(|(offset, &byte)| {
    byte == b'<'
      && crate::secrets::values::classify::is_html_tag_at(bytes, offset)
  })
}

pub fn find_from(source: &str, from: usize, needle: &str) -> Option<usize> {
  source
    .get(from..)
    .and_then(|s| s.find(needle))
    .map(|p| from + p)
}

// The zero-based line of a byte offset (the number of newlines before it).
pub fn line_at(source: &str, offset: usize) -> usize {
  source
    .get(..offset)
    .map_or(0, |prefix| prefix.bytes().filter(|&b| b == b'\n').count())
}

// The zero-based character column of a byte offset on its line.
pub fn char_column(source: &str, offset: usize) -> usize {
  let prefix = source.get(..offset).unwrap_or("");
  match prefix.rfind('\n') {
    Some(newline) => prefix
      .get(newline + 1..)
      .map_or(0, |rest| rest.chars().count()),
    None => prefix.chars().count(),
  }
}
