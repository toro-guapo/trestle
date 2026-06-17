// GPG/PGP binary secret key packet detection.
//
// Every OpenPGP packet starts with a tag byte followed by a length
// field and then the packet body:
//
//   [tag byte] [length field ...] [body ...]
//
// The tag byte identifies the packet type and format. We only care
// about tag 5 (Secret-Key) and tag 7 (Secret-Subkey). Once the tag
// is recognized, we advance past the length field (we don't need the
// length value itself) to reach the body, where we validate:
//
//   - Version byte (4 or 5).
//   - Creation timestamp (4 bytes, reasonable range).
//   - Algorithm byte (known public-key algorithm ID).
//
// Tag byte encoding
// -----------------
// RFC 9580 S4.2  https://www.rfc-editor.org/rfc/rfc9580#section-4.2
//
// Old format (bit 6 = 0): bits 5-2 = tag, bits 1-0 = length type.
//   Length type 0 = 1-byte length, 1 = 2-byte, 2 = 4-byte.
//   Tag 5: 0x94 (1-byte len), 0x95 (2-byte), 0x96 (4-byte).
//   Tag 7: 0x9C (1-byte len), 0x9D (2-byte), 0x9E (4-byte).
//
// New format (bit 6 = 1): bits 5-0 = tag, length is encoded
//   separately in the next 1, 2, or 5 bytes.
//   Tag 5: 0xC5.
//   Tag 7: 0xC7.
//
// Body layout
// -----------
// RFC 9580 S5.5.2  https://www.rfc-editor.org/rfc/rfc9580#section-5.5.2
// RFC 4880 S5.5.2  https://www.rfc-editor.org/rfc/rfc4880#section-5.5.2

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GpgAlgorithm {
  Rsa,
  Elgamal,
  Dsa,
  Ecdh,
  Ecdsa,
  EdDsa,
  X25519,
  X448,
  Ed25519,
  Ed448,
  MlDsa65Ed25519,
  MlDsa87Ed448,
  SlhDsaShake128s,
  SlhDsaShake128f,
  SlhDsaShake256s,
  MlKem768X25519,
  MlKem1024X448,
}

impl std::fmt::Display for GpgAlgorithm {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Rsa => write!(f, "RSA"),
      Self::Elgamal => write!(f, "Elgamal"),
      Self::Dsa => write!(f, "DSA"),
      Self::Ecdh => write!(f, "ECDH"),
      Self::Ecdsa => write!(f, "ECDSA"),
      Self::EdDsa => write!(f, "EdDSA"),
      Self::X25519 => write!(f, "X25519"),
      Self::X448 => write!(f, "X448"),
      Self::Ed25519 => write!(f, "Ed25519"),
      Self::Ed448 => write!(f, "Ed448"),
      Self::MlDsa65Ed25519 => write!(f, "ML-DSA-65+Ed25519"),
      Self::MlDsa87Ed448 => write!(f, "ML-DSA-87+Ed448"),
      Self::SlhDsaShake128s => write!(f, "SLH-DSA-SHAKE-128s"),
      Self::SlhDsaShake128f => write!(f, "SLH-DSA-SHAKE-128f"),
      Self::SlhDsaShake256s => write!(f, "SLH-DSA-SHAKE-256s"),
      Self::MlKem768X25519 => write!(f, "ML-KEM-768+X25519"),
      Self::MlKem1024X448 => write!(f, "ML-KEM-1024+X448"),
    }
  }
}

fn parse_algorithm(id: u8) -> Option<GpgAlgorithm> {
  // See:
  // https://www.iana.org/assignments/openpgp/openpgp.xhtml#openpgp-public-key-algorithms
  match id {
    1..=3 => Some(GpgAlgorithm::Rsa),
    16 => Some(GpgAlgorithm::Elgamal),
    17 => Some(GpgAlgorithm::Dsa),
    18 => Some(GpgAlgorithm::Ecdh),
    19 => Some(GpgAlgorithm::Ecdsa),
    22 => Some(GpgAlgorithm::EdDsa),
    25 => Some(GpgAlgorithm::X25519),
    26 => Some(GpgAlgorithm::X448),
    27 => Some(GpgAlgorithm::Ed25519),
    28 => Some(GpgAlgorithm::Ed448),
    30 => Some(GpgAlgorithm::MlDsa65Ed25519),
    31 => Some(GpgAlgorithm::MlDsa87Ed448),
    32 => Some(GpgAlgorithm::SlhDsaShake128s),
    33 => Some(GpgAlgorithm::SlhDsaShake128f),
    34 => Some(GpgAlgorithm::SlhDsaShake256s),
    35 => Some(GpgAlgorithm::MlKem768X25519),
    36 => Some(GpgAlgorithm::MlKem1024X448),
    _ => None,
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GpgSecret {
  pub algorithm: GpgAlgorithm,
  pub kind: GpgKind,
  pub key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GpgKind {
  SecretKey,
  SecretSubkey,
}

impl std::fmt::Display for GpgSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let kind = match self.kind {
      GpgKind::SecretKey => "secret key",
      GpgKind::SecretSubkey => "secret subkey",
    };
    write!(f, "GPG/PGP {} {kind}", self.algorithm)
  }
}

const MIN_TIMESTAMP: u32 = 662680799; // December 31st, 1990
const MAX_TIMESTAMP: u32 = 4102444800; // January 1st, 2100

pub fn scan_bytes(source: &[u8]) -> Option<GpgSecret> {
  // See:
  // https://www.iana.org/assignments/openpgp/openpgp.xhtml#openpgp-packet-types
  let first = *source.first()?;

  let (is_secret_key, body_start) = match first {
    // Old format, tag 5 (secret key).
    0x94 => (true, skip_old_length(1, 1)),
    0x95 => (true, skip_old_length(1, 2)),
    0x96 => (true, skip_old_length(1, 4)),
    // Old format, tag 7 (secret subkey).
    0x9C => (false, skip_old_length(1, 1)),
    0x9D => (false, skip_old_length(1, 2)),
    0x9E => (false, skip_old_length(1, 4)),
    // New format, tag 5.
    0xC5 => (true, skip_new_length(source, 1)?),
    // New format, tag 7.
    0xC7 => (false, skip_new_length(source, 1)?),
    _ => return None,
  };

  validate_body(source, body_start, is_secret_key)
}

fn validate_body(
  source: &[u8],
  offset: usize,
  is_secret_key: bool,
) -> Option<GpgSecret> {
  // Version byte.
  let version = *source.get(offset)?;
  if version != 4 && version != 5 {
    return None;
  }

  // Creation timestamp (4 bytes, big-endian).
  let ts = u32::from_be_bytes([
    *source.get(offset + 1)?,
    *source.get(offset + 2)?,
    *source.get(offset + 3)?,
    *source.get(offset + 4)?,
  ]);
  if !(MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&ts) {
    return None;
  }

  // Algorithm byte position depends on version.
  let algo_offset = if version == 4 {
    offset + 5
  } else {
    // v5 has 4 extra bytes (key material octet count).
    offset + 9
  };
  let algo_id = *source.get(algo_offset)?;
  let algo = parse_algorithm(algo_id)?;

  Some(GpgSecret {
    algorithm: algo,
    kind: if is_secret_key {
      GpgKind::SecretKey
    } else {
      GpgKind::SecretSubkey
    },
    key_id: extract_key_id(source),
  })
}

fn extract_key_id(source: &[u8]) -> Option<String> {
  use ::pgp::composed::{Deserializable, SignedSecretKey};
  use ::pgp::types::KeyDetails;
  let cursor = std::io::Cursor::new(source);
  let key = SignedSecretKey::from_bytes(cursor).ok()?;
  Some(format!("{:X}", key.fingerprint()))
}

// Returns the body offset past an old-format length field. The tag
// byte's low 2 bits already told us how wide it is (1, 2, or 4
// bytes), so we just advance by that amount.
// RFC 4880 S4.2.1  https://www.rfc-editor.org/rfc/rfc4880#section-4.2.1
fn skip_old_length(offset: usize, len_bytes: usize) -> usize {
  offset + len_bytes
}

// Returns the body offset past a new-format length field. The width
// depends on the first byte of the length encoding:
//   0-191   -> 1 byte
//   192-223 -> 2 bytes
//   255     -> 5 bytes (1 marker + 4 length)
//   224-254 -> partial body length (not used by key packets)
// RFC 9580 S4.2.1  https://www.rfc-editor.org/rfc/rfc9580#section-4.2.1
fn skip_new_length(source: &[u8], offset: usize) -> Option<usize> {
  let first = *source.get(offset)?;
  if first < 192 {
    Some(offset + 1)
  } else if first < 224 {
    Some(offset + 2)
  } else if first == 255 {
    Some(offset + 5)
  } else {
    // Partial body length.
    None
  }
}
