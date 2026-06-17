use serde_json::json;

use crate::diagnostic::{AnnotatedDiagnostic, Diagnostic};
use crate::formatting::uppercase_first;
#[cfg(feature = "git-history")]
use crate::output::history_to_json;
use crate::output::{
  SUMMARY_FIELDS, ScanSummary, WriteContext, build_summary, count,
  write_indented_json,
};
use crate::source::SourceFileSpan;

pub fn write(ctx: WriteContext<'_>) -> ScanSummary {
  let mut summary = ScanSummary::default();

  writeln!(ctx.output_writer, "{{").ok();
  writeln!(ctx.output_writer, "  \"diagnostics\": [").ok();

  let mut first = true;
  for diagnostic in ctx.diagnostic_receiver {
    count(&mut summary, &diagnostic);

    if !first {
      writeln!(ctx.output_writer, ",").ok();
    }

    let obj = diagnostic_to_json(&diagnostic);
    write_indented_json(ctx.output_writer, &obj, 4);

    first = false;
  }

  writeln!(ctx.output_writer).ok();
  writeln!(ctx.output_writer, "  ]").ok();

  if ctx.options.show_summary
    && let Ok(stats) = ctx.scan_stats_receiver.recv()
  {
    let formatted = build_summary(stats, summary);
    writeln!(ctx.output_writer, ",").ok();
    write!(ctx.output_writer, "  \"summary\": ").ok();
    let value = build_summary_value(&formatted);
    write_indented_json(ctx.output_writer, &value, 2);
    writeln!(ctx.output_writer).ok();
  }

  writeln!(ctx.output_writer, "}}").ok();

  summary
}

fn build_summary_value(
  formatted: &crate::output::FormattedSummary,
) -> serde_json::Value {
  let mut map = serde_json::Map::new();
  for field in SUMMARY_FIELDS {
    map.insert(field.name.to_owned(), formatted.field_value(field.name));
  }
  serde_json::Value::Object(map)
}

fn diagnostic_to_json(annotated: &AnnotatedDiagnostic) -> serde_json::Value {
  let rule_id = annotated.id();
  let severity = annotated.severity().to_string().to_lowercase();
  let message = annotated.message();

  #[allow(unused_mut)]
  let mut obj = match &annotated.diagnostic {
    Diagnostic::SecretAssignment {
      name,
      assignment_type,
      value_class,
      source_span,
      ..
    } => {
      let mut obj = json!({
        "ruleId": rule_id,
        "severity": severity,
        "name": name,
        "assignmentType": assignment_type.to_string(),
        "description": uppercase_first(&value_class.to_string()),
        "message": message,
      });

      add_location(&mut obj, source_span);
      obj
    }
    Diagnostic::SecretValue {
      source_span,
      value_class,
      ..
    } => {
      let mut obj = json!({
        "ruleId": rule_id,
        "severity": severity,
        "description": uppercase_first(&value_class.to_string()),
        "message": message,
      });

      add_location(&mut obj, source_span);
      obj
    }
    Diagnostic::BinarySecret {
      secret,
      file_abs_path,
      ..
    } => {
      let mut obj = json!({
        "ruleId": rule_id,
        "severity": severity,
        "description": uppercase_first(&secret.to_string()),
        "message": message,
      });
      add_path(&mut obj, file_abs_path.as_path());
      obj
    }
    Diagnostic::TextSecret {
      secret,
      file_abs_path,
      ..
    } => {
      let mut obj = json!({
        "ruleId": rule_id,
        "severity": severity,
        "description": uppercase_first(&secret.to_string()),
        "message": message,
      });
      add_path(&mut obj, file_abs_path.as_path());
      obj
    }
  };

  obj["fingerprint"] = json!(annotated.fingerprint().as_str());

  #[cfg(feature = "git-history")]
  if let Some(history) = &annotated.history {
    obj["history"] = history_to_json(history);
  }

  #[cfg(feature = "validation")]
  if let Some(status) = annotated.validation() {
    obj["validation"] = json!(status.as_str());
  }

  obj
}

fn add_path(obj: &mut serde_json::Value, path: &std::path::Path) {
  obj["file"] = json!(path.display().to_string());
}

fn add_location(obj: &mut serde_json::Value, source_span: &SourceFileSpan) {
  obj["file"] = json!(source_span.file_abs_path.display().to_string());
  if let Some(span) = &source_span.file_span {
    obj["startLine"] = json!(span.start.line);
    obj["startColumn"] = json!(span.start.column);
    obj["endLine"] = json!(span.end.line);
    obj["endColumn"] = json!(span.end.column);
  }
}
