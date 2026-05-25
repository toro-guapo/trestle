// KeePass password database detection.
//
// KDB (v1) header:
//   Bytes 0-3:  Primary signature (03 D9 A2 9A).
//   Bytes 4-7:  Secondary signature (65 FB 4B B5).
//   Bytes 8-11: Flags.
//
// KDBX (v2+) header:
//   Bytes 0-3:   Primary signature (03 D9 A2 9A).
//   Bytes 4-7:   Secondary signature (67 FB 4B B5).
//   Bytes 8-9:   Minor version (little-endian u16).
//   Bytes 10-11: Major version (little-endian u16, 3 or 4).
//
// https://keepass.info/help/kb/kdbx.html

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeePassSecret {
  Kdb,
  Kdbx3,
  Kdbx4,
}

impl std::fmt::Display for KeePassSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Kdb => write!(f, "KeePass database (KDB v1)"),
      Self::Kdbx3 => write!(f, "KeePass database (KDBX v3)"),
      Self::Kdbx4 => write!(f, "KeePass database (KDBX v4)"),
    }
  }
}

const PRIMARY_SIG: &[u8] = &[0x03, 0xD9, 0xA2, 0x9A];
const KDB_SECONDARY: &[u8] = &[0x65, 0xFB, 0x4B, 0xB5];
const KDBX_SECONDARY: &[u8] = &[0x67, 0xFB, 0x4B, 0xB5];

pub fn scan_bytes(source: &[u8]) -> Option<KeePassSecret> {
  if source.len() < 12 {
    return None;
  }
  if source.get(0..4)? != PRIMARY_SIG {
    return None;
  }

  let secondary = source.get(4..8)?;

  if secondary == KDB_SECONDARY {
    return Some(KeePassSecret::Kdb);
  }

  if secondary == KDBX_SECONDARY {
    let major = u16::from_le_bytes([*source.get(10)?, *source.get(11)?]);
    return match major {
      3 => Some(KeePassSecret::Kdbx3),
      4 => Some(KeePassSecret::Kdbx4),
      _ => None,
    };
  }

  None
}
