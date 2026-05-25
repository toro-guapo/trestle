use std::{ops::Range, sync::LazyLock};

use regex::Regex;

static TOKEN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
  Regex::new(concat!(
    r"PuTTY-User-Key-File-([23]):[ \t]*([\w-]+)[ \t]*\n",
    r"(?:.*\n)*?",
    r"Private-Lines:[ \t]*[0-9]+[ \t]*\n",
    r"[A-Za-z0-9+/]{20}[A-Za-z0-9+/=]*\n",
    r"(?:.*\n)*?",
    r"Private-MAC:[ \t]*[a-fA-F0-9]+",
  ))
  .ok()
});

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PuttyKey {
  Generic,
  Rsa,
  Dsa,
  Ecdsa,
  Ed25519,
  Ed448,
}

impl std::fmt::Display for PuttyKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Generic => write!(f, "PuTTY private key"),
      Self::Rsa => write!(f, "PuTTY RSA private key"),
      Self::Dsa => write!(f, "PuTTY DSA private key"),
      Self::Ecdsa => write!(f, "PuTTY ECDSA private key"),
      Self::Ed25519 => write!(f, "PuTTY Ed25519 private key"),
      Self::Ed448 => write!(f, "PuTTY Ed448 private key"),
    }
  }
}

fn classify(algorithm: &str) -> PuttyKey {
  match algorithm {
    "ssh-rsa" => PuttyKey::Rsa,
    "ssh-dss" | "ssh-dsa" => PuttyKey::Dsa,
    "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
      PuttyKey::Ecdsa
    }
    "ssh-ed25519" => PuttyKey::Ed25519,
    "ssh-ed448" => PuttyKey::Ed448,
    _ => PuttyKey::Generic,
  }
}

pub struct Finding {
  pub key_type: PuttyKey,
  pub byte_range: Range<usize>,
}

pub fn scan(content: &str) -> Vec<Finding> {
  let Some(re) = TOKEN_RE.as_ref() else {
    return Vec::new();
  };

  re.captures_iter(content)
    .filter_map(|caps| {
      let algorithm = caps.get(2)?.as_str();
      let m = caps.get(0)?;
      Some(Finding {
        key_type: classify(algorithm),
        byte_range: m.start()..m.end(),
      })
    })
    .collect()
}
