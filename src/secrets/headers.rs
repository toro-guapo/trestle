use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, Severity, SourceFileSpan,
    assignment_fingerprint,
  },
  processing::SourceContext,
  secrets::values::{
    classify::{NamedSecret, ValueClass, classify_value},
    normalize::normalize_value,
  },
};

pub fn check_header(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let lower_name = name.to_ascii_lowercase();

  if lower_name == "authorization" || lower_name == "proxy-authorization" {
    return check_authorization(name, value, context, &resolve_span);
  }

  if is_sensitive_header(&lower_name) {
    return check_header_value(name, value, context, &resolve_span);
  }

  None
}

fn check_authorization(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: &dyn Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let trimmed = value.trim();

  if let Some(encoded) = trimmed
    .strip_prefix("Basic ")
    .or_else(|| trimmed.strip_prefix("basic "))
  {
    return check_basic_auth(name, encoded.trim(), context, resolve_span);
  }

  if let Some(token) = trimmed
    .strip_prefix("Bearer ")
    .or_else(|| trimmed.strip_prefix("bearer "))
  {
    return check_token_value(name, token.trim(), context, resolve_span);
  }

  // Other auth schemes (Token, Digest, etc.) - strip the scheme prefix.
  let token = trimmed
    .find(' ')
    .map(|pos| trimmed.get(pos + 1..).unwrap_or("").trim())
    .unwrap_or(trimmed);
  check_token_value(name, token, context, resolve_span)
}

fn check_basic_auth(
  name: &str,
  encoded: &str,
  context: &SourceContext,
  resolve_span: &dyn Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  use base64::Engine;

  let decoded = base64::engine::general_purpose::STANDARD
    .decode(encoded)
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok());

  let Some(decoded) = decoded else {
    return check_token_value(name, encoded, context, resolve_span);
  };

  let parts: Vec<&str> = decoded.splitn(2, ':').collect();
  if parts.len() != 2 {
    return check_token_value(name, encoded, context, resolve_span);
  }

  let password = parts[1];
  if password.is_empty() {
    return None;
  }

  let normalized = normalize_value(&password.to_owned());
  if classify_value(&normalized, context).is_some() {
    return Some(Diagnostic::SecretAssignment {
      name: name.to_owned(),
      assignment_type: AssignmentType::Header,
      value_class: ValueClass::Secret(NamedSecret::Header),
      source_span: resolve_span(),
      severity: Severity::Warning,
      file_type: context.file_type,
      fingerprint: assignment_fingerprint(normalized.original().as_bytes()),
    });
  }

  None
}

fn check_token_value(
  name: &str,
  token: &str,
  context: &SourceContext,
  resolve_span: &dyn Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let token = token.trim();
  if token.is_empty() {
    return None;
  }

  let normalized = normalize_value(&token.to_owned());
  if classify_value(&normalized, context).is_some() {
    return Some(Diagnostic::SecretAssignment {
      name: name.to_owned(),
      assignment_type: AssignmentType::Header,
      value_class: ValueClass::Secret(NamedSecret::Header),
      source_span: resolve_span(),
      severity: Severity::Warning,
      file_type: context.file_type,
      fingerprint: assignment_fingerprint(normalized.original().as_bytes()),
    });
  }

  None
}

fn check_header_value(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: &dyn Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let value = value.trim();
  if value.is_empty() {
    return None;
  }

  let normalized = normalize_value(&value.to_owned());
  if classify_value(&normalized, context).is_some() {
    return Some(Diagnostic::SecretAssignment {
      name: name.to_owned(),
      assignment_type: AssignmentType::Header,
      value_class: ValueClass::Secret(NamedSecret::Header),
      source_span: resolve_span(),
      severity: Severity::Warning,
      file_type: context.file_type,
      fingerprint: assignment_fingerprint(normalized.original().as_bytes()),
    });
  }

  None
}

fn is_sensitive_header(lower_name: &str) -> bool {
  matches!(
    lower_name,
    "authorization"
      | "proxy-authorization"
      | "cookie"
      | "set-cookie"
      | "x-api-key"
      | "x-auth-token"
      | "x-csrf-token"
      | "x-xsrf-token"
      | "x-access-token"
      | "x-secret"
      | "x-token"
  )
}
