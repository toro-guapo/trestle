// Java KeyStore (JKS) file detection.
//
// Header structure (12 bytes):
//   Bytes 0-3:  Magic (FE ED FE ED).
//   Bytes 4-7:  Version (00 00 00 01 or 00 00 00 02).
//   Bytes 8-11: Entry count (big-endian u32).
//
// We validate the magic, version, and that the entry count is at least 1
// (an empty keystore is not a secret).
//
// https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/provider/JavaKeyStore.java

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum JksSecret {
  KeyStore,
}

impl std::fmt::Display for JksSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::KeyStore => write!(f, "Java KeyStore (JKS)"),
    }
  }
}

const MAGIC: &[u8] = &[0xFE, 0xED, 0xFE, 0xED];

pub fn scan_bytes(source: &[u8]) -> Option<JksSecret> {
  if source.len() < 12 {
    return None;
  }
  if source.get(0..4)? != MAGIC {
    return None;
  }
  let version = u32::from_be_bytes([
    *source.get(4)?,
    *source.get(5)?,
    *source.get(6)?,
    *source.get(7)?,
  ]);
  if version != 1 && version != 2 {
    return None;
  }
  let entry_count = u32::from_be_bytes([
    *source.get(8)?,
    *source.get(9)?,
    *source.get(10)?,
    *source.get(11)?,
  ]);
  if entry_count == 0 {
    return None;
  }
  Some(JksSecret::KeyStore)
}
