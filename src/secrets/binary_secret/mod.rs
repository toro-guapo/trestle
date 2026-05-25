#[cfg(feature = "binary-der")]
pub mod der;
#[cfg(feature = "binary-gpg")]
pub mod gpg;
#[cfg(feature = "binary-jceks")]
pub mod jceks;
#[cfg(feature = "binary-jks")]
pub mod jks;
#[cfg(feature = "binary-keepass")]
pub mod keepass;

#[derive(Debug, Clone)]
pub enum BinarySecret {
  #[cfg(feature = "binary-der")]
  Der(der::DerSecret),
  #[cfg(feature = "binary-gpg")]
  Gpg(gpg::GpgSecret),
  #[cfg(feature = "binary-jceks")]
  Jceks(jceks::JceksSecret),
  #[cfg(feature = "binary-jks")]
  Jks(jks::JksSecret),
  #[cfg(feature = "binary-keepass")]
  KeePass(keepass::KeePassSecret),
}

impl std::fmt::Display for BinarySecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    #[cfg(feature = "binary-der")]
    if let Self::Der(v) = self {
      return write!(f, "{v}");
    }
    #[cfg(feature = "binary-gpg")]
    if let Self::Gpg(v) = self {
      return write!(f, "{v}");
    }
    #[cfg(feature = "binary-jceks")]
    if let Self::Jceks(v) = self {
      return write!(f, "{v}");
    }
    #[cfg(feature = "binary-jks")]
    if let Self::Jks(v) = self {
      return write!(f, "{v}");
    }
    #[cfg(feature = "binary-keepass")]
    if let Self::KeePass(v) = self {
      return write!(f, "{v}");
    }
    let _ = f;
    Ok(())
  }
}
