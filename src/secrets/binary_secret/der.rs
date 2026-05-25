// DER-encoded binary private key and PKCS#12 container detection.
//
// Uses a fast two-byte pre-check (0x30 + length encoding) to skip non-DER
// files, then progressively validates using the RustCrypto `der`, `pkcs8`,
// and `pkcs1` crates.
//
// Detected formats:
//   PKCS#12 / PFX          - Certificate/key container (version 3).
//   PKCS#8 private key     - Generic private key with algorithm ID.
//   PKCS#1 RSA private key - RSA-specific DER format.
//
// https://www.rfc-editor.org/rfc/rfc7292 (PKCS#12)
// https://www.rfc-editor.org/rfc/rfc5958 (PKCS#8)
// https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.2 (PKCS#1)

use ::der::Decode;
use ::der::Encode;
use ::der::asn1::{ContextSpecific, OctetString};
use ::der::oid::ObjectIdentifier;
use ::der::oid::db::{rfc4519, rfc5911, rfc5912, rfc8410};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DerSecret {
  Pkcs12 { common_name: Option<String> },
  Pkcs8(Pkcs8Algorithm),
  Pkcs1Rsa,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Pkcs8Algorithm {
  Rsa,
  RsaPss,
  Ec,
  Ed25519,
  Ed448,
  X25519,
  X448,
  Dh,
  Dsa,
  Other(ObjectIdentifier),
}

impl Pkcs8Algorithm {
  pub fn name(&self) -> Option<&'static str> {
    match self {
      Self::Rsa => Some("RSA"),
      Self::RsaPss => Some("RSA-PSS"),
      Self::Ec => Some("EC"),
      Self::Ed25519 => Some("ED25519"),
      Self::Ed448 => Some("ED448"),
      Self::X25519 => Some("X25519"),
      Self::X448 => Some("X448"),
      Self::Dh => Some("DH"),
      Self::Dsa => Some("DSA"),
      Self::Other(_) => None,
    }
  }
}

impl std::fmt::Display for DerSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Pkcs12 { .. } => write!(f, "PKCS#12 / PFX container"),
      Self::Pkcs8(Pkcs8Algorithm::Other(oid)) => {
        write!(f, "PKCS#8 private key (DER, OID {oid})")
      }
      Self::Pkcs8(algorithm) => match algorithm.name() {
        Some(name) => write!(f, "PKCS#8 {name} private key (DER)"),
        None => write!(f, "PKCS#8 private key (DER)"),
      },
      Self::Pkcs1Rsa => write!(f, "PKCS#1 RSA private key (DER)"),
    }
  }
}

// PKCS#3 dhKeyAgreement is not in const-oid's database, so it stays here.
// https://oid-base.com/cgi-bin/display?oid=1.2.840.113549.1.3.1
const DH_OID: ObjectIdentifier =
  ObjectIdentifier::new_unwrap("1.2.840.113549.1.3.1");

fn pkcs8_algorithm(oid: &ObjectIdentifier) -> Pkcs8Algorithm {
  if *oid == rfc5912::RSA_ENCRYPTION {
    Pkcs8Algorithm::Rsa
  } else if *oid == rfc5912::ID_RSASSA_PSS {
    Pkcs8Algorithm::RsaPss
  } else if *oid == rfc5912::ID_EC_PUBLIC_KEY {
    Pkcs8Algorithm::Ec
  } else if *oid == rfc8410::ID_ED_25519 {
    Pkcs8Algorithm::Ed25519
  } else if *oid == rfc8410::ID_ED_448 {
    Pkcs8Algorithm::Ed448
  } else if *oid == rfc8410::ID_X_25519 {
    Pkcs8Algorithm::X25519
  } else if *oid == rfc8410::ID_X_448 {
    Pkcs8Algorithm::X448
  } else if *oid == DH_OID {
    Pkcs8Algorithm::Dh
  } else if *oid == rfc5912::ID_DSA {
    Pkcs8Algorithm::Dsa
  } else {
    Pkcs8Algorithm::Other(*oid)
  }
}

pub fn scan_bytes(source: &[u8]) -> Option<DerSecret> {
  if source.len() < 12 {
    return None;
  }

  if *source.first()? != 0x30 {
    return None;
  }

  // Reject indefinite length (0x80) and reserved (0xFF).
  let len_byte = *source.get(1)?;
  if len_byte == 0x80 || len_byte == 0xFF {
    return None;
  }

  // Read the version: first INTEGER inside the SEQUENCE.
  let version = read_first_integer(source)?;

  match version {
    3 => try_pkcs12(source),
    // Version 0: PKCS#8 or PKCS#1.
    // Version 1: SEC 1 EC keys also start this way, and PKCS#8 wraps them,
    //            so try PKCS#8 first.
    0 | 1 => try_private_key(source),
    _ => None,
  }
}

fn read_first_integer(source: &[u8]) -> Option<u8> {
  // Skip SEQUENCE tag (1 byte) + length encoding.
  let pos = skip_length(source, 1)?;

  // Expect INTEGER tag (0x02), length 1, then the value.
  if *source.get(pos)? != 0x02 {
    return None;
  }
  if *source.get(pos + 1)? != 0x01 {
    return None;
  }
  source.get(pos + 2).copied()
}

fn skip_length(source: &[u8], offset: usize) -> Option<usize> {
  let len_byte = *source.get(offset)?;
  if len_byte < 0x80 {
    Some(offset + 1)
  } else {
    let count = (len_byte & 0x7F) as usize;
    if count == 0 || count > 4 {
      return None;
    }
    Some(offset + 1 + count)
  }
}

fn try_pkcs12(source: &[u8]) -> Option<DerSecret> {
  // After confirming version 3 via read_first_integer, verify the element
  // following the version INTEGER is a SEQUENCE (the contentInfo field). This
  // distinguishes PKCS#12 from other DER structures with version 3.
  let content_start = skip_length(source, 1)?;

  // Skip past INTEGER(3): tag(1) + length(1) + value(1) = 3.
  let after_version = content_start + 3;

  if *source.get(after_version)? != 0x30 {
    return None;
  }

  Some(DerSecret::Pkcs12 {
    common_name: extract_pkcs12_common_name(source),
  })
}

// Walks an unencrypted PKCS#12 to find a certificate's CN. Many PKCS#12 files
// encrypt the cert bag with the export password; in that case we get None and
// callers fall back to a generic placeholder.
//
// PFX -> AuthenticatedSafe -> SafeContents -> SafeBag (CertBag) -> X.509 cert.
fn extract_pkcs12_common_name(source: &[u8]) -> Option<String> {
  let pfx = pkcs12::pfx::Pfx::from_der(source).ok()?;
  if pfx.auth_safe.content_type != rfc5911::ID_DATA {
    return None;
  }

  let auth_safe_outer = pfx.auth_safe.content.to_der().ok()?;
  let auth_safe_octets = OctetString::from_der(&auth_safe_outer).ok()?;
  let auth_safes = Vec::<cms::content_info::ContentInfo>::from_der(
    auth_safe_octets.as_bytes(),
  )
  .ok()?;

  for content_info in auth_safes {
    if content_info.content_type != rfc5911::ID_DATA {
      continue;
    }
    let safe_contents_outer = content_info.content.to_der().ok()?;
    let safe_contents_octets =
      OctetString::from_der(&safe_contents_outer).ok()?;
    let safe_bags =
      pkcs12::safe_bag::SafeContents::from_der(safe_contents_octets.as_bytes())
        .ok()?;

    for safe_bag in safe_bags {
      if safe_bag.bag_id != pkcs12::PKCS_12_CERT_BAG_OID {
        continue;
      }
      let cs = ContextSpecific::<pkcs12::cert_type::CertBag>::from_der(
        &safe_bag.bag_value,
      )
      .ok()?;
      let cert_bag = cs.value;
      if cert_bag.cert_id != pkcs12::PKCS_12_X509_CERT_OID {
        continue;
      }
      let cert =
        x509_cert::Certificate::from_der(cert_bag.cert_value.as_bytes())
          .ok()?;
      for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
          if atv.oid == rfc4519::COMMON_NAME {
            // AttributeTypeAndValue's Display impl decodes the value's string
            // tag (UTF8 / Printable / IA5 / Teletex) and emits "CN=value" with
            // RFC 4514 escapes for special characters.
            if let Some(cn) = atv.to_string().strip_prefix("CN=") {
              return Some(cn.to_string());
            }
          }
        }
      }
    }
  }
  None
}

fn try_private_key(source: &[u8]) -> Option<DerSecret> {
  // Try PKCS#8 first (most common DER private key format). This also catches EC
  // keys wrapped in PKCS#8.
  if let Ok(info) = pkcs8::PrivateKeyInfo::from_der(source) {
    return Some(DerSecret::Pkcs8(pkcs8_algorithm(&info.algorithm.oid)));
  }

  // Try PKCS#1 RSA.
  if pkcs1::RsaPrivateKey::from_der(source).is_ok() {
    return Some(DerSecret::Pkcs1Rsa);
  }

  None
}
