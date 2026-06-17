use std::path::{Path, PathBuf};

use crate::fingerprint::Fingerprint;
use crate::formatting::uppercase_first;
use crate::languages::FileType;
use crate::processing::SourceContext;
use crate::secrets::binary_secret::BinarySecret;
pub use crate::secrets::headers::check_header;
use crate::secrets::text_secret::TextSecret;
use crate::secrets::{
  names::{
    classify::{
      NameClass, NameKind, classify_normalized_name, is_password_name,
    },
    normalize::{NormalizedName, normalize_name},
  },
  values::{
    classify::{
      NamedSecret, ValueClass, classify_named_value, classify_value,
      value_is_password_literal, value_is_weak_password,
    },
    normalize::{NormalizedValue, normalize_value},
  },
};
pub use crate::source::{
  SourceFileSpan, SourcePosition, SourceSpan, offset_to_position,
};

include!(concat!(env!("OUT_DIR"), "/rule_ids.rs"));

#[derive(Clone, Copy, Debug, PartialEq)]
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
    fingerprint: Fingerprint,
  },
  SecretValue {
    source_span: SourceFileSpan,
    value_class: ValueClass,
    severity: Severity,
    file_type: Option<FileType>,
    fingerprint: Fingerprint,
    from_content_scan: bool,
  },
  BinarySecret {
    secret: BinarySecret,
    severity: Severity,
    file_type: Option<FileType>,
    file_abs_path: PathBuf,
    fingerprint: Fingerprint,
  },
  TextSecret {
    secret: TextSecret,
    severity: Severity,
    file_type: Option<FileType>,
    file_abs_path: PathBuf,
    fingerprint: Fingerprint,
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

  pub fn value_class(&self) -> Option<&ValueClass> {
    match self {
      Diagnostic::SecretAssignment { value_class, .. }
      | Diagnostic::SecretValue { value_class, .. } => Some(value_class),
      _ => None,
    }
  }

  pub fn fingerprint(&self) -> &Fingerprint {
    match self {
      Diagnostic::SecretAssignment { fingerprint, .. }
      | Diagnostic::SecretValue { fingerprint, .. }
      | Diagnostic::BinarySecret { fingerprint, .. }
      | Diagnostic::TextSecret { fingerprint, .. } => fingerprint,
    }
  }

  /// Lowercase noun phrase describing what kind of secret this is, suitable
  /// for mid-sentence use ("can read the {kind}").
  pub fn secret_kind(&self) -> String {
    match self {
      Diagnostic::SecretAssignment { value_class, .. }
      | Diagnostic::SecretValue { value_class, .. } => value_class.to_string(),
      Diagnostic::BinarySecret { secret, .. } => secret.to_string(),
      Diagnostic::TextSecret { secret, .. } => secret.to_string(),
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

pub fn assignment_fingerprint(secret: &[u8]) -> Fingerprint {
  Fingerprint::compute(RULES[0].0, secret)
}

pub fn value_fingerprint(secret: &[u8]) -> Fingerprint {
  Fingerprint::compute(RULES[1].0, secret)
}

pub fn binary_fingerprint(secret: &[u8]) -> Fingerprint {
  Fingerprint::compute(RULES[2].0, secret)
}

pub fn text_fingerprint(secret: &[u8]) -> Fingerprint {
  Fingerprint::compute(RULES[3].0, secret)
}

pub fn check_assignment(
  name: &NormalizedName,
  value: &NormalizedValue,
  assignment_type: AssignmentType,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  classify_assignment(name, value, assignment_type, context, &resolve_span)
    .or_else(|| {
      check_connection_string(
        value.original(),
        assignment_type,
        context,
        &resolve_span,
      )
    })
}

pub fn check_assignment_in_scope(
  scope: &[&str],
  name: &NormalizedName,
  value: &NormalizedValue,
  assignment_type: AssignmentType,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  if scope.is_empty() {
    return check_assignment(
      name,
      value,
      assignment_type,
      context,
      resolve_span,
    );
  }

  let mut folded = scope.join(".");
  folded.push('.');
  folded.push_str(name.original());

  check_assignment(
    &normalize_name(&folded),
    value,
    assignment_type,
    context,
    resolve_span,
  )
}

fn classify_assignment(
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
    Some(nc) => classify_named_value(nc, value, context),
    None => classify_value(value, context),
  };

  let password_field = is_password_name(name)
    && crate::languages::is_declarative_config_file(context.file_abs_path);

  if let Some(value_class) = value_class {
    let name_kind = name_class.as_ref().map(|nc| &nc.kind);

    let severity = match (name_kind, &value_class) {
      (_, V::Public) => return None,
      (_, V::Placeholder) => return None,
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
      (Some(K::Mnemonic), V::Secret(NamedSecret::Mnemonic)) => {
        Severity::Warning
      }
      (Some(K::Mnemonic), _) => return None,
      (Some(K::Sensitive { .. }), _) => Severity::Warning,
      (Some(K::Key { .. } | K::Token { .. }), _) => Severity::Warning,
      // A `pass`-style key (not a strong keyword) with a secret-looking value.
      (None, _) if password_field => Severity::Warning,
      (None, _) => return None,
    };

    return Some(Diagnostic::SecretAssignment {
      name: name.original().to_string(),
      assignment_type,
      value_class,
      source_span: resolve_span(),
      severity,
      file_type: context.file_type,
      fingerprint: assignment_fingerprint(value.original().as_bytes()),
    });
  }

  if password_field && value_is_weak_password(value) {
    return Some(Diagnostic::SecretAssignment {
      name: name.original().to_string(),
      assignment_type,
      value_class: ValueClass::PossibleSecret,
      source_span: resolve_span(),
      severity: Severity::Warning,
      file_type: context.file_type,
      fingerprint: assignment_fingerprint(value.original().as_bytes()),
    });
  }

  None
}

pub(crate) fn secret_value_severity(
  value_class: &ValueClass,
) -> Option<Severity> {
  match value_class {
    ValueClass::Public => None,
    ValueClass::Placeholder => None,
    #[cfg(feature = "pem")]
    ValueClass::Secret(NamedSecret::PrivateKey(_)) => Some(Severity::Critical),
    #[cfg(feature = "putty")]
    ValueClass::Secret(NamedSecret::PuttyKey(_)) => Some(Severity::Critical),
    #[cfg(feature = "signatures")]
    ValueClass::Secret(NamedSecret::Signature(_)) => Some(Severity::Critical),
    _ => Some(Severity::Warning),
  }
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
    kind: NameKind::Sensitive { weak: false },
    name_words: Vec::new(),
  };
  let value_class = classify_named_value(&synthetic, value, context)?;
  let severity = secret_value_severity(&value_class)?;

  Some(Diagnostic::SecretAssignment {
    name: display_name.to_string(),
    assignment_type,
    value_class,
    source_span: resolve_span(),
    severity,
    file_type: context.file_type,
    fingerprint: assignment_fingerprint(value.original().as_bytes()),
  })
}

pub fn check_password_field(
  display_name: &str,
  value: &str,
  assignment_type: AssignmentType,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  if !value_is_password_literal(&normalize_value(&value)) {
    return None;
  }

  Some(Diagnostic::SecretAssignment {
    name: display_name.to_string(),
    assignment_type,
    value_class: ValueClass::PossibleSecret,
    source_span: resolve_span(),
    severity: Severity::Warning,
    file_type: context.file_type,
    fingerprint: assignment_fingerprint(value.as_bytes()),
  })
}

const CONNECTION_SECRET_KEYS: &[&str] = &[
  "accesskey",
  "accountkey",
  "awssecretaccesskey",
  "awssecretkey",
  "clientsecret",
  "password",
  "pwd",
  "secret",
  "secretaccesskey",
  "sharedaccesskey",
  "sharedaccesssignature",
];

pub fn check_connection_string(
  value: &str,
  assignment_type: AssignmentType,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  if value.split(';').filter(|pair| pair.contains('=')).count() < 2 {
    return None;
  }

  for pair in value.split(';') {
    let Some((key, component)) = pair.split_once('=') else {
      continue;
    };
    let normalized_key = key
      .chars()
      .filter(|c| c.is_ascii_alphanumeric())
      .collect::<String>()
      .to_ascii_lowercase();
    if !CONNECTION_SECRET_KEYS.contains(&normalized_key.as_str()) {
      continue;
    }

    let component = component.trim().trim_matches(|c| c == '"' || c == '\'');
    if component.is_empty() {
      continue;
    }

    if let Some(diagnostic) = check_credential_assignment(
      key.trim(),
      &normalize_value(&component),
      assignment_type,
      context,
      &resolve_span,
    ) {
      return Some(diagnostic);
    }
  }

  None
}

pub fn strip_build_config_quotes(raw: &str) -> &str {
  let trimmed = raw.trim();

  let trimmed = trimmed
    .strip_prefix("\\\"")
    .or_else(|| trimmed.strip_prefix('"'))
    .unwrap_or(trimmed);

  trimmed
    .strip_suffix("\\\"")
    .or_else(|| trimmed.strip_suffix('"'))
    .unwrap_or(trimmed)
}

pub fn check_header_assignment(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  check_header(name, value, context, &resolve_span).or_else(|| {
    check_assignment(
      &normalize_name(&name),
      &normalize_value(&value),
      AssignmentType::Header,
      context,
      resolve_span,
    )
  })
}

pub fn check_value(
  value: &NormalizedValue,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  classify_value_only(value, context, &resolve_span).or_else(|| {
    check_connection_string(
      value.original(),
      AssignmentType::Variable,
      context,
      &resolve_span,
    )
  })
}

fn classify_value_only(
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
    fingerprint: value_fingerprint(value.original().as_bytes()),
    from_content_scan: false,
  })
}

#[cfg(feature = "git-history")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryLocation {
  Branch { name: String, current: bool },
  RemoteRef(String),
  Tag(String),
  Stash,
  Dangling,
}

#[cfg(feature = "git-history")]
impl HistoryLocation {
  pub fn qualifier(&self) -> Option<String> {
    match self {
      Self::Branch { current: true, .. } => None,
      Self::Branch {
        name,
        current: false,
      } => Some(format!("on {name}")),
      Self::RemoteRef(name) => Some(format!("on {name}")),
      Self::Tag(name) => Some(format!("on tag {name}")),
      Self::Stash => Some("in stash".to_owned()),
      Self::Dangling => Some("dangling".to_owned()),
    }
  }
}

#[cfg(feature = "git-history")]
pub const SHORT_COMMIT_LEN: usize = 12;

#[cfg(feature = "git-history")]
#[derive(Debug, Clone)]
pub struct HistoryCommit {
  pub commit: String,
  pub author_time: chrono::DateTime<chrono::FixedOffset>,
  pub subject: String,
}

#[cfg(feature = "git-history")]
impl HistoryCommit {
  pub fn short_commit(&self) -> &str {
    self.commit.get(..SHORT_COMMIT_LEN).unwrap_or(&self.commit)
  }
}

#[cfg(feature = "git-history")]
#[derive(Debug, Clone)]
pub struct HistoryAttribution {
  pub commit: String,
  pub author_date: chrono::NaiveDate,
  pub location: HistoryLocation,
  pub also_in_working_tree: bool,
  pub commits: Vec<HistoryCommit>,
}

#[cfg(feature = "git-history")]
impl HistoryAttribution {
  pub fn short_commit(&self) -> &str {
    self.commit.get(..SHORT_COMMIT_LEN).unwrap_or(&self.commit)
  }
}

#[cfg(feature = "git-history")]
impl std::fmt::Display for HistoryAttribution {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let prefix = if self.also_in_working_tree {
      "also "
    } else {
      ""
    };

    let short = self.short_commit();
    let date = self.author_date;

    if let HistoryLocation::Dangling = self.location {
      return write!(f, "({prefix}in a dangling commit since {short}, {date})");
    }

    match self.location.qualifier() {
      Some(loc) => {
        write!(f, "({prefix}in history since {short} {loc}, {date})")
      }
      None => write!(f, "({prefix}in history since {short}, {date})"),
    }
  }
}

#[derive(Debug)]
pub struct AnnotatedDiagnostic {
  pub diagnostic: Diagnostic,
  #[cfg(feature = "git-history")]
  pub history: Option<HistoryAttribution>,
  #[cfg(feature = "validation")]
  pub validation: Option<crate::validation::ValidationStatus>,
}

impl AnnotatedDiagnostic {
  pub fn bare(diagnostic: Diagnostic) -> Self {
    Self {
      diagnostic,
      #[cfg(feature = "git-history")]
      history: None,
      #[cfg(feature = "validation")]
      validation: None,
    }
  }

  #[cfg(feature = "validation")]
  pub fn validation(&self) -> Option<crate::validation::ValidationStatus> {
    self.validation
  }

  pub fn severity(&self) -> &Severity {
    self.diagnostic.severity()
  }

  pub fn source_span(&self) -> Option<&SourceFileSpan> {
    self.diagnostic.source_span()
  }

  pub fn file_abs_path(&self) -> &Path {
    self.diagnostic.file_abs_path()
  }

  pub fn message(&self) -> String {
    self.diagnostic.message()
  }

  pub fn id(&self) -> &'static str {
    self.diagnostic.id()
  }

  pub fn fingerprint(&self) -> &Fingerprint {
    self.diagnostic.fingerprint()
  }

  pub fn description(&self) -> &'static str {
    self.diagnostic.description()
  }

  pub fn secret_kind(&self) -> String {
    self.diagnostic.secret_kind()
  }

  #[cfg(feature = "git-history")]
  pub fn display_history(&self) -> Option<String> {
    self.history.as_ref().map(|h| h.to_string())
  }
}

impl std::fmt::Display for AnnotatedDiagnostic {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.diagnostic)?;
    #[cfg(feature = "git-history")]
    if let Some(marker) = self.display_history() {
      write!(f, " {marker}")?;
    }
    Ok(())
  }
}
