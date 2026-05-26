pub fn indefinite_article(text: &str) -> &'static str {
  let first_word = text
    .trim_start()
    .split_whitespace()
    .next()
    .unwrap_or_default();

  if let Some(article) = phonetic_letter_override(first_word) {
    return article;
  }

  match in_definite::is_an(first_word) {
    in_definite::Is::An => "an",
    in_definite::Is::A | in_definite::Is::None => "a",
  }
}

fn phonetic_letter_override(word: &str) -> Option<&'static str> {
  let first_letter = word.chars().next()?;

  if is_letter_plus_digits(word) {
    Some(phonetic_letter_article(first_letter))
  } else {
    None
  }
}

fn is_letter_plus_digits(word: &str) -> bool {
  let mut chars = word.chars();

  let Some(first) = chars.next() else {
    return false;
  };

  if !first.is_ascii_uppercase() {
    return false;
  }

  let mut has_digit = false;

  for c in chars {
    if c.is_ascii_digit() {
      has_digit = true;
    } else if !c.is_ascii_uppercase() {
      return false;
    }
  }

  has_digit
}

fn phonetic_letter_article(letter: char) -> &'static str {
  match letter.to_ascii_lowercase() {
    'a' | 'e' | 'f' | 'h' | 'i' | 'l' | 'm' | 'n' | 'o' | 'r' | 's' | 'x' => {
      "an"
    }
    _ => "a",
  }
}

pub fn articulate(text: &str) -> String {
  format!("{} {}", indefinite_article(text), text)
}

pub fn articulate_capitalize(text: &str) -> String {
  format!("{} {}", uppercase_first(&indefinite_article(text)), text)
}

pub fn lowercase_first(s: &str) -> String {
  let mut chars = s.chars();
  match chars.next() {
    Some(c) => {
      let lower: String = c.to_lowercase().collect();
      format!("{lower}{}", chars.as_str())
    }
    None => String::new(),
  }
}

pub fn uppercase_first(s: &str) -> String {
  let mut chars = s.chars();
  match chars.next() {
    Some(c) => {
      let upper: String = c.to_uppercase().collect();
      format!("{upper}{}", chars.as_str())
    }
    None => String::new(),
  }
}

pub fn format_count(count: usize, singular: &str, plural: &str) -> String {
  if count == 1 {
    format!("1 {singular}")
  } else {
    format!("{count} {plural}")
  }
}

pub fn pluralize<'a>(
  count: usize,
  singular: &'a str,
  plural: &'a str,
) -> &'a str {
  if count == 1 { singular } else { plural }
}

pub fn trim_in_place(s: &mut String) {
  let start = s.len() - s.trim_start().len();
  let new_len = s.trim().len();

  s.replace_range(..start, "");
  s.truncate(new_len);
}

pub fn wrap(text: &str, width: usize, hang: &str) -> Vec<String> {
  let mut lines = Vec::new();
  let mut line = String::new();

  for word in text.split_whitespace() {
    if line.is_empty() {
      line.push_str(word);
    } else if line.chars().count() + 1 + word.chars().count() <= width {
      line.push(' ');
      line.push_str(word);
    } else {
      lines.push(line);
      line = word.to_string();
    }
  }

  if !line.is_empty() {
    lines.push(line);
  }

  for line in lines.iter_mut().skip(1) {
    line.insert_str(0, hang);
  }

  lines
}

pub fn is_js_identifier(name: &str) -> bool {
  let mut chars = name.chars();
  let Some(first) = chars.next() else {
    return false;
  };
  if !is_js_identifier_start(first) {
    return false;
  }
  chars.all(is_js_identifier_continue)
}

fn is_js_identifier_start(c: char) -> bool {
  c.is_ascii_alphabetic() || c == '_' || c == '$'
}

fn is_js_identifier_continue(c: char) -> bool {
  c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

pub fn js_string_literal(s: &str) -> String {
  serde_json::Value::String(s.to_string()).to_string()
}

pub fn js_property_access(object: &str, name: &str) -> String {
  if is_js_identifier(name) {
    format!("{object}.{name}")
  } else {
    format!("{object}[{}]", js_string_literal(name))
  }
}

pub fn is_context_word(s: &str) -> bool {
  s.len() >= 5 && s.bytes().all(|b| b.is_ascii_alphabetic())
}

pub fn normalize_camel_case_and_lower(name: &str) -> Vec<String> {
  let bytes = name.as_bytes();
  if bytes.is_empty() {
    return Vec::new();
  }

  const MAX_DIGIT_BOUNDARIES_FOR_SPLIT: usize = 2;
  let digit_boundary_count = bytes
    .windows(2)
    .filter(|w| {
      (w[0].is_ascii_alphabetic() && w[1].is_ascii_digit())
        || (w[0].is_ascii_digit() && w[1].is_ascii_alphabetic())
    })
    .count();

  let split_digits = digit_boundary_count <= MAX_DIGIT_BOUNDARIES_FOR_SPLIT;

  let mut out = Vec::with_capacity(4);
  let mut start = 0;

  for i in 1..bytes.len() {
    let prev = bytes[i - 1];
    let curr = bytes[i];
    let next = bytes.get(i + 1).copied();

    let boundary =
      // abcDef -> abc | Def
      (prev.is_ascii_lowercase() && curr.is_ascii_uppercase())
      ||
      // ABCDef -> ABC | Def
      (prev.is_ascii_uppercase()
        && curr.is_ascii_uppercase()
        && next.is_some_and(|n| n.is_ascii_lowercase()))
      ||
      // abcd2 -> abcd | 2 (only when the transition pattern is clean)
      (split_digits
        && prev.is_ascii_alphabetic()
        && curr.is_ascii_digit())
      ||
      // 2abcd -> 2 | abcd (only when the transition pattern is clean)
      (split_digits
        && prev.is_ascii_digit()
        && curr.is_ascii_alphabetic());

    if boundary {
      out.push(name[start..i].to_ascii_lowercase());
      start = i;
    }
  }

  out.push(name[start..].to_ascii_lowercase());
  out
}
