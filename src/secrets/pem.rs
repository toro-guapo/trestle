// PEM and RFC 4716 encoded private key block detection.
//
// Matches the full structure: header, at least one line of base64 content (20+
// chars), and footer. This avoids false positives from code that merely
// references the markers.
//
// https://www.rfc-editor.org/rfc/rfc7468 (PEM)
// https://www.rfc-editor.org/rfc/rfc4716 (SSH2)

use std::{io::Cursor, ops::Range, sync::LazyLock};

use ::pgp::composed::{Deserializable, SignedSecretKey};
use ::pgp::types::KeyDetails;
use regex::Regex;

static TOKEN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
  Regex::new(concat!(
    r"(?m)-{4,5} ?BEGIN ",
    r"([ A-Z0-9]*PRIVATE KEY(?:[ A-Z]* BLOCK)?)",
    r" ?-{4,5}[ \t]*\n",
    r"(?:.*\n)*?",
    r"[A-Za-z0-9+/]{20}[A-Za-z0-9+/=]*\n",
    r"(?:.*\n)*?",
    r"-{4,5} ?END ",
    r"([ A-Z0-9]*PRIVATE KEY(?:[ A-Z]* BLOCK)?)",
    r" ?-{4,5}",
  ))
  .ok()
});

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PrivateKey {
  Generic,
  Rsa,
  Ec,
  Dsa,
  Ecdsa,
  Ed25519,
  Ed448,
  X25519,
  X448,
  Dh,
  OpenSsh,
  Encrypted,
  Pgp { key_id: Option<String> },
  Ssh2Encrypted,
}

impl std::fmt::Display for PrivateKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Generic => write!(f, "private key"),
      Self::Rsa => write!(f, "RSA private key"),
      Self::Ec => write!(f, "EC private key"),
      Self::Dsa => write!(f, "DSA private key"),
      Self::Ecdsa => write!(f, "ECDSA private key"),
      Self::Ed25519 => write!(f, "Ed25519 private key"),
      Self::Ed448 => write!(f, "Ed448 private key"),
      Self::X25519 => write!(f, "X25519 private key"),
      Self::X448 => write!(f, "X448 private key"),
      Self::Dh => write!(f, "DH private key"),
      Self::OpenSsh => write!(f, "OpenSSH private key"),
      Self::Encrypted => write!(f, "encrypted private key"),
      Self::Pgp { .. } => write!(f, "PGP private key block"),
      Self::Ssh2Encrypted => write!(f, "SSH2 encrypted private key"),
    }
  }
}

fn classify(label: &str) -> PrivateKey {
  match label {
    "PRIVATE KEY" => PrivateKey::Generic,
    "RSA PRIVATE KEY" => PrivateKey::Rsa,
    "EC PRIVATE KEY" => PrivateKey::Ec,
    "DSA PRIVATE KEY" => PrivateKey::Dsa,
    "ECDSA PRIVATE KEY" => PrivateKey::Ecdsa,
    "ED25519 PRIVATE KEY" => PrivateKey::Ed25519,
    "ED448 PRIVATE KEY" => PrivateKey::Ed448,
    "X25519 PRIVATE KEY" => PrivateKey::X25519,
    "X448 PRIVATE KEY" => PrivateKey::X448,
    "DH PRIVATE KEY" => PrivateKey::Dh,
    "OPENSSH PRIVATE KEY" => PrivateKey::OpenSsh,
    "ENCRYPTED PRIVATE KEY" => PrivateKey::Encrypted,
    "PGP PRIVATE KEY BLOCK" => PrivateKey::Pgp { key_id: None },
    "SSH2 ENCRYPTED PRIVATE KEY" => PrivateKey::Ssh2Encrypted,
    _ => PrivateKey::Generic,
  }
}

pub struct Finding {
  pub key_type: PrivateKey,
  pub byte_range: Range<usize>,
}

pub fn scan(content: &str) -> Vec<Finding> {
  let Some(re) = TOKEN_RE.as_ref() else {
    return Vec::new();
  };

  re.captures_iter(content)
    .filter_map(|caps| {
      let begin_label = caps.get(1)?.as_str();
      let end_label = caps.get(2)?.as_str();
      if begin_label != end_label {
        return None;
      }
      let m = caps.get(0)?;
      let key_type = match begin_label {
        "PGP PRIVATE KEY BLOCK" => PrivateKey::Pgp {
          key_id: extract_pgp_key_id(content.get(m.start()..m.end())?),
        },
        _ => classify(begin_label),
      };
      Some(Finding {
        key_type,
        byte_range: m.start()..m.end(),
      })
    })
    .collect()
}

fn extract_pgp_key_id(armored: &str) -> Option<String> {
  let cursor = Cursor::new(armored.as_bytes());
  let (key, _headers) = SignedSecretKey::from_armor_single(cursor).ok()?;
  Some(format!("{:X}", key.fingerprint()))
}
