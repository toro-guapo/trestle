use std::path::{Path, PathBuf};

use crate::formatting::uppercase_first;
use crate::languages::FileType;
use crate::processing::SourceContext;
use crate::secrets::binary_secret::BinarySecret;
pub use crate::secrets::headers::check_header;
use crate::secrets::text_secret::TextSecret;
use crate::secrets::{
  names::{
    classify::{NameClass, NameKind, classify_normalized_name},
    normalize::NormalizedName,
  },
  values::{
    classify::{NamedSecret, ValueClass, classify_named_value, classify_value},
    normalize::NormalizedValue,
  },
};
pub use crate::source::{
  SourceFileSpan, SourcePosition, SourceSpan, offset_to_position,
};

include!(concat!(env!("OUT_DIR"), "/rule_ids.rs"));

#[derive(Debug, PartialEq)]
pub enum Severity {
  Critical,
  Warning,
}

impl std::fmt::Display for Severity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let severity = match self {
      Severity::Critical => "Critical",
      Severity::Warning => "Warning",
    };
    write!(f, "{}", severity)
  }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AssignmentType {
  Argument,
  Attribute,
  BackendConfig,
  BuildArgument,
  Constant,
  Directive,
  Element,
  EnvironmentVariable,
  Header,
  Parameter,
  Property,
  User,
  Variable,
}

impl std::fmt::Display for AssignmentType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let assignment_type = match self {
      AssignmentType::Argument => "argument",
      AssignmentType::Attribute => "attribute",
      AssignmentType::BackendConfig => "backend configuration",
      AssignmentType::BuildArgument => "build argument",
      AssignmentType::Constant => "constant",
      AssignmentType::Directive => "directive",
      AssignmentType::Element => "element",
      AssignmentType::EnvironmentVariable => "environment variable",
      AssignmentType::Header => "header",
      AssignmentType::Parameter => "parameter",
      AssignmentType::Property => "property",
      AssignmentType::User => "user",
      AssignmentType::Variable => "variable",
    };
    write!(f, "{}", assignment_type)
  }
}

pub fn compute_file_span(
  context: &SourceContext,
  source: &str,
  start: usize,
  end: usize,
) -> SourceFileSpan {
  let mut start_pos = offset_to_position(source, start);
  let mut end_pos = offset_to_position(source, end);

  if start_pos.line == 1 {
    start_pos.column += context.parent_col;
  }
  if end_pos.line == 1 {
    end_pos.column += context.parent_col;
  }
  start_pos.line += context.parent_line;
  end_pos.line += context.parent_line;

  SourceFileSpan {
    file_abs_path: context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: start_pos,
      end: end_pos,
    }),
  }
}

#[derive(Debug)]
pub enum Diagnostic {
  SecretAssignment {
    name: String,
    assignment_type: AssignmentType,
    value_class: ValueClass,
    source_span: SourceFileSpan,
    severity: Severity,
    file_type: Option<FileType>,
  },
  SecretValue {
    source_span: SourceFileSpan,
    value_class: ValueClass,
    severity: Severity,
    file_type: Option<FileType>,
  },
  BinarySecret {
    secret: BinarySecret,
    severity: Severity,
    file_type: Option<FileType>,
    file_abs_path: PathBuf,
  },
  TextSecret {
    secret: TextSecret,
    severity: Severity,
    file_type: Option<FileType>,
    file_abs_path: PathBuf,
  },
}

impl Diagnostic {
  pub fn source_span(&self) -> Option<&SourceFileSpan> {
    match self {
      Diagnostic::SecretAssignment { source_span, .. }
      | Diagnostic::SecretValue { source_span, .. } => Some(source_span),
      Diagnostic::BinarySecret { .. } | Diagnostic::TextSecret { .. } => None,
    }
  }

  pub fn file_abs_path(&self) -> &Path {
    match self {
      Diagnostic::SecretAssignment { source_span, .. }
      | Diagnostic::SecretValue { source_span, .. } => {
        source_span.file_abs_path.as_path()
      }
      Diagnostic::BinarySecret { file_abs_path, .. }
      | Diagnostic::TextSecret { file_abs_path, .. } => file_abs_path.as_path(),
    }
  }

  pub fn message(&self) -> String {
    match self {
      Diagnostic::SecretAssignment {
        name,
        assignment_type,
        value_class,
        ..
      } => {
        let subject = uppercase_first(&value_class.to_string());
        format!("{subject} assigned to {assignment_type} \"{name}\".")
      }
      Diagnostic::SecretValue { value_class, .. } => {
        let subject = uppercase_first(&value_class.to_string());
        format!("{subject} found.")
      }
      Diagnostic::BinarySecret { secret, .. } => {
        let subject = uppercase_first(&secret.to_string());
        format!("{subject} found.")
      }
      Diagnostic::TextSecret { secret, .. } => {
        let subject = uppercase_first(&secret.to_string());
        format!("{subject} found.")
      }
    }
  }

  pub fn id(&self) -> &'static str {
    match self {
      Diagnostic::SecretAssignment { .. } => RULES[0].0,
      Diagnostic::SecretValue { .. } => RULES[1].0,
      Diagnostic::BinarySecret { .. } => RULES[2].0,
      Diagnostic::TextSecret { .. } => RULES[3].0,
    }
  }

  pub fn description(&self) -> &'static str {
    match self {
      Diagnostic::SecretAssignment { .. } => RULES[0].1,
      Diagnostic::SecretValue { .. } => RULES[1].1,
      Diagnostic::BinarySecret { .. } => RULES[2].1,
      Diagnostic::TextSecret { .. } => RULES[3].1,
    }
  }

  pub fn severity(&self) -> &Severity {
    match self {
      Diagnostic::SecretAssignment { severity, .. }
      | Diagnostic::SecretValue { severity, .. }
      | Diagnostic::BinarySecret { severity, .. }
      | Diagnostic::TextSecret { severity, .. } => severity,
    }
  }
}

impl std::fmt::Display for Diagnostic {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Diagnostic::SecretAssignment { source_span, .. }
      | Diagnostic::SecretValue { source_span, .. } => {
        write!(
          f,
          "{} {}: {}",
          source_span.display_start(),
          self.severity(),
          self.message()
        )
      }
      Diagnostic::BinarySecret { file_abs_path, .. }
      | Diagnostic::TextSecret { file_abs_path, .. } => write!(
        f,
        "{} {}: {}",
        file_abs_path.display(),
        self.severity(),
        self.message()
      ),
    }
  }
}

pub fn check_assignment(
  name: &NormalizedName,
  value: &NormalizedValue,
  assignment_type: AssignmentType,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  type K = NameKind;
  type V = ValueClass;

  let name_class = classify_normalized_name(name);
  let value_class = match &name_class {
    Some(nc) => classify_named_value(nc, value, context)?,
    None => classify_value(value, context)?,
  };

  let name_kind = name_class.as_ref().map(|nc| &nc.kind);

  let severity = match (name_kind, &value_class) {
    (_, V::Public) => return None,
    #[cfg(feature = "pem")]
    (_, V::Secret(NamedSecret::PrivateKey(_))) => Severity::Critical,
    #[cfg(feature = "putty")]
    (_, V::Secret(NamedSecret::PuttyKey(_))) => Severity::Critical,
    #[cfg(feature = "signatures")]
    (_, V::Secret(NamedSecret::Signature(_))) => Severity::Critical,
    #[cfg(feature = "services")]
    (_, V::Secret(NamedSecret::Service(_))) => Severity::Warning,
    #[cfg(feature = "url")]
    (_, V::Secret(NamedSecret::Url(_))) => Severity::Warning,
    (_, V::Secret(NamedSecret::CreditCard)) => Severity::Critical,
    (Some(K::Mnemonic), V::Secret(NamedSecret::Mnemonic)) => Severity::Warning,
    (Some(K::Mnemonic), _) => return None,
    (Some(K::Sensitive), _) => Severity::Warning,
    (Some(K::Key { .. } | K::Token { .. }), _) => Severity::Warning,
    (None, _) => return None,
  };

  Some(Diagnostic::SecretAssignment {
    name: name.original().to_string(),
    assignment_type,
    value_class,
    source_span: resolve_span(),
    severity,
    file_type: context.file_type,
  })
}

pub fn check_credential_assignment(
  display_name: &str,
  value: &NormalizedValue,
  assignment_type: AssignmentType,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let synthetic = NameClass {
    #[cfg(feature = "services")]
    service: None,
    kind: NameKind::Sensitive,
    name_words: Vec::new(),
  };
  let value_class = classify_named_value(&synthetic, value, context)?;

  let severity = match &value_class {
    ValueClass::Public => return None,
    #[cfg(feature = "pem")]
    ValueClass::Secret(NamedSecret::PrivateKey(_)) => Severity::Critical,
    #[cfg(feature = "putty")]
    ValueClass::Secret(NamedSecret::PuttyKey(_)) => Severity::Critical,
    #[cfg(feature = "signatures")]
    ValueClass::Secret(NamedSecret::Signature(_)) => Severity::Critical,
    _ => Severity::Warning,
  };

  Some(Diagnostic::SecretAssignment {
    name: display_name.to_string(),
    assignment_type,
    value_class,
    source_span: resolve_span(),
    severity,
    file_type: context.file_type,
  })
}

pub fn check_value(
  value: &NormalizedValue,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let value_class = classify_value(value, context)?;

  let severity = match &value_class {
    ValueClass::Public => return None,
    #[cfg(feature = "pem")]
    ValueClass::Secret(NamedSecret::PrivateKey(_)) => Severity::Critical,
    #[cfg(feature = "putty")]
    ValueClass::Secret(NamedSecret::PuttyKey(_)) => Severity::Critical,
    #[cfg(feature = "signatures")]
    ValueClass::Secret(NamedSecret::Signature(_)) => Severity::Critical,
    ValueClass::Secret(NamedSecret::Mnemonic) => Severity::Warning,
    #[cfg(feature = "url")]
    ValueClass::Secret(NamedSecret::Url(_)) => Severity::Warning,
    _ => return None,
  };

  Some(Diagnostic::SecretValue {
    source_span: resolve_span(),
    value_class,
    severity,
    file_type: context.file_type,
  })
}
