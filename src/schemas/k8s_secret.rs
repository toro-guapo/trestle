use base64::Engine;

use crate::{
  diagnostic::{AssignmentType, SourceFileSpan, check_assignment},
  languages::FileType,
  processing::SourceContext,
  schemas::SchemaValue,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
  source::{SourcePosition, SourceSpan},
};

/// Returns true if the YAML body looks like a Kubernetes manifest. Every K8s
/// manifest has top-level `apiVersion:` and `kind:` keys, both unindented.
pub fn looks_like_k8s_manifest(yaml: &str) -> bool {
  let mut has_api_version = false;
  let mut has_kind = false;

  for line in yaml.lines() {
    if line.starts_with(' ') || line.starts_with('\t') {
      continue;
    }

    if line.starts_with("apiVersion:") {
      has_api_version = true;
    } else if line.starts_with("kind:") {
      has_kind = true;
    }

    if has_api_version && has_kind {
      return true;
    }
  }

  false
}

/// Intercepts `data.*` values in Kubernetes Secret manifests, base64-decodes
/// them, and runs the decoded content through the normal name + value
/// classification pipeline. This catches signature patterns (e.g. Stripe keys)
/// that are invisible in base64 form.
///
/// Registered as a fallback handler for all YAML files. The `path == ["data"]`
/// check returns false immediately for non-K8s files, so the overhead is
/// negligible. When this handler returns false, the YAML parser's normal
/// `check_assignment` runs on the raw value.
pub fn handle(info: &SchemaValue) -> bool {
  if info.path.len() != 1 || info.path.first() != Some(&"data") {
    return false;
  }

  let trimmed = info.value.trim();
  if trimmed.is_empty() {
    return false;
  }

  let Some(decoded) = base64::engine::general_purpose::STANDARD
    .decode(trimmed)
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok())
  else {
    return false;
  };

  if decoded.is_empty() {
    return true;
  }

  let source_context = SourceContext {
    run: info.run,
    file_abs_path: info.file_abs_path,
    file_extension: None,
    body: None,
    file_type: Some(FileType::K8sSecret),
    parent_line: info.parent_line,
    parent_col: info.parent_col,
    #[cfg(feature = "services")]
    file_services: vec![],
    directives: std::cell::OnceCell::new(),
  };
  if let Some(d) = check_assignment(
    &normalize_name(&info.key),
    &normalize_value(&decoded),
    AssignmentType::Property,
    &source_context,
    || SourceFileSpan {
      file_abs_path: info.file_abs_path.to_path_buf(),
      file_span: Some(SourceSpan {
        start: SourcePosition {
          line: info.parent_line + 1,
          column: info.parent_col + 1,
        },
        end: SourcePosition {
          line: info.parent_line + 1,
          column: info.parent_col + 1,
        },
      }),
    },
  ) {
    source_context.emit_diagnostic(d);
  }

  true
}
