use crate::diagnostic::AnnotatedDiagnostic;
use crate::secrets::values::classify::ValueClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationStatus {
  Live,
  Inactive,
  Unknown,
}

impl ValidationStatus {
  pub fn as_str(&self) -> &'static str {
    match self {
      ValidationStatus::Live => "live",
      ValidationStatus::Inactive => "inactive",
      ValidationStatus::Unknown => "unknown",
    }
  }
}

pub trait SecretValidator: Send + Sync {
  fn handles(&self, value_class: &ValueClass) -> bool;

  fn submit(&self, finding: AnnotatedDiagnostic, secret: &str);

  fn finish(&self);
}
