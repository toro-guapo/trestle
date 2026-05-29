use blake3::Hasher;

const GROUP_SIZE: usize = 4;
const GROUP_COUNT: usize = 4;
const RAW_LEN: usize = GROUP_SIZE * GROUP_COUNT;
const FINGERPRINT_BYTES: usize = 10;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
  pub fn compute(rule_id: &str, secret: &[u8]) -> Self {
    let mut hasher = Hasher::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(secret);
    let mut bytes = [0u8; FINGERPRINT_BYTES];
    hasher.finalize_xof().fill(&mut bytes);
    Self(group(&encode_base32(&bytes)))
  }

  pub fn parse(text: &str) -> Option<Self> {
    let mut raw = String::with_capacity(RAW_LEN);
    for ch in text.trim().chars() {
      if ch == '-' {
        continue;
      }
      if !ch.is_ascii() {
        return None;
      }
      let symbol = ch.to_ascii_uppercase();
      if !BASE32_ALPHABET.contains(&(symbol as u8)) {
        return None;
      }
      raw.push(symbol);
      if raw.len() > RAW_LEN {
        return None;
      }
    }
    if raw.len() != RAW_LEN {
      return None;
    }
    Some(Self(group(&raw)))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl std::fmt::Display for Fingerprint {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

fn encode_base32(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(RAW_LEN);
  let mut acc: u32 = 0;
  let mut bits: u32 = 0;
  for &byte in bytes {
    acc = (acc << 8) | byte as u32;
    bits += 8;
    while bits >= 5 {
      bits -= 5;
      let index = ((acc >> bits) & 0x1f) as usize;
      if let Some(&symbol) = BASE32_ALPHABET.get(index) {
        out.push(symbol as char);
      }
    }
  }
  out
}

fn group(raw: &str) -> String {
  let mut out = String::with_capacity(RAW_LEN + GROUP_COUNT - 1);
  for (i, ch) in raw.chars().enumerate() {
    if i > 0 && i % GROUP_SIZE == 0 {
      out.push('-');
    }
    out.push(ch);
  }
  out
}
