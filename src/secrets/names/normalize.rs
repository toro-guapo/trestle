use crate::formatting::normalize_camel_case_and_lower;

pub struct NormalizedName<'a> {
  original: &'a str,
  segments: Vec<String>,
}

impl<'a> NormalizedName<'a> {
  pub fn segments(&self) -> &[String] {
    &self.segments
  }

  pub fn original(&self) -> &'a str {
    self.original
  }
}

pub fn normalize_name<'a>(name: &'a impl AsRef<str>) -> NormalizedName<'a> {
  let name = name.as_ref();
  let mut normalized = Vec::new();

  for segment in name
    .trim()
    .trim_matches(['_', '-', '.', '/'])
    .split(['_', '-', '.', '/'])
  {
    if !segment.is_empty() {
      for normalized_segment in normalize_camel_case_and_lower(segment) {
        normalized.push(normalized_segment);
      }
    }
  }

  NormalizedName {
    original: name,
    segments: normalized,
  }
}
