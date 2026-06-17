pub struct NormalizedValue {
  original: String,
  lower: String,
}

impl NormalizedValue {
  pub fn as_str(&self) -> &str {
    &self.lower
  }

  pub fn original(&self) -> &str {
    &self.original
  }

  pub fn len(&self) -> usize {
    self.lower.len()
  }

  pub fn is_empty(&self) -> bool {
    self.lower.is_empty()
  }
}

pub fn normalize_value(value: &impl AsRef<str>) -> NormalizedValue {
  let original = value.as_ref().trim_ascii().to_string();
  let lower = original.to_ascii_lowercase();
  NormalizedValue { original, lower }
}
