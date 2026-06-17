use crate::{
  diagnostic::{
    AssignmentType, Diagnostic, SourceFileSpan, assignment_fingerprint,
    secret_value_severity,
  },
  processing::SourceContext,
  secrets::values::{classify::classify_value, normalize::normalize_value},
};

pub fn is_sensitive_header(lower_name: &str) -> bool {
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

const COOKIE_ATTRIBUTES: &[&str] = &[
  "comment",
  "domain",
  "expires",
  "httponly",
  "max-age",
  "partitioned",
  "path",
  "priority",
  "samesite",
  "secure",
  "version",
];

pub fn check_header(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let lower_name = name.to_ascii_lowercase();

  if lower_name == "cookie" || lower_name == "set-cookie" {
    return cookie_header_secret(name, value, context, resolve_span);
  }

  let credential =
    if lower_name == "authorization" || lower_name == "proxy-authorization" {
      authorization_credential(value)?
    } else if is_sensitive_header(&lower_name) {
      value.to_owned()
    } else {
      return None;
    };

  classify_header_value(name, &credential, context, resolve_span)
}

fn classify_header_value(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  let normalized = normalize_value(&value.to_owned());
  let value_class = classify_value(&normalized, context)?;
  let severity = secret_value_severity(&value_class)?;

  Some(Diagnostic::SecretAssignment {
    name: name.to_owned(),
    assignment_type: AssignmentType::Header,
    value_class,
    source_span: resolve_span(),
    severity,
    file_type: context.file_type,
    fingerprint: assignment_fingerprint(normalized.original().as_bytes()),
  })
}

fn cookie_header_secret(
  name: &str,
  value: &str,
  context: &SourceContext,
  resolve_span: impl Fn() -> SourceFileSpan,
) -> Option<Diagnostic> {
  for pair in value.split(';') {
    let Some((cookie_name, cookie_value)) = pair.split_once('=') else {
      continue;
    };

    if COOKIE_ATTRIBUTES
      .contains(&cookie_name.trim().to_ascii_lowercase().as_str())
    {
      continue;
    }

    let cookie_value = cookie_value.trim();
    if cookie_value.is_empty() {
      continue;
    }

    if let Some(diagnostic) =
      classify_header_value(name, cookie_value, context, &resolve_span)
    {
      return Some(diagnostic);
    }
  }

  None
}

fn authorization_credential(value: &str) -> Option<String> {
  let trimmed = value.trim();

  if let Some(encoded) = trimmed
    .strip_prefix("Basic ")
    .or_else(|| trimmed.strip_prefix("basic "))
  {
    return basic_auth_password(encoded.trim());
  }

  if let Some(token) = trimmed
    .strip_prefix("Bearer ")
    .or_else(|| trimmed.strip_prefix("bearer "))
  {
    return Some(token.trim().to_owned());
  }

  let token = trimmed
    .find(' ')
    .map(|pos| trimmed.get(pos + 1..).unwrap_or("").trim())
    .unwrap_or(trimmed);
  Some(token.to_owned())
}

fn basic_auth_password(encoded: &str) -> Option<String> {
  use base64::Engine;

  let Some(decoded) = base64::engine::general_purpose::STANDARD
    .decode(encoded)
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok())
  else {
    return Some(encoded.to_owned());
  };

  let Some((_username, password)) = decoded.split_once(':') else {
    return Some(encoded.to_owned());
  };

  if password.is_empty() {
    return None;
  }
  Some(password.to_owned())
}
