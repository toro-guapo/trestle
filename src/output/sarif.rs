use serde_json::json;

use crate::diagnostic::{Diagnostic, RULES, Severity};
use crate::output::{
  SUMMARY_FIELDS, ScanSummary, WriteContext, build_summary, count,
  write_indented_json,
};

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

pub fn write(ctx: WriteContext<'_>) -> ScanSummary {
  let mut summary = ScanSummary::default();

  write_header(ctx.output_writer);

  writeln!(ctx.output_writer, "    \"results\": [").ok();
  let mut first = true;
  for diagnostic in ctx.diagnostic_receiver {
    count(&mut summary, &diagnostic);
    if !first {
      writeln!(ctx.output_writer, ",").ok();
    }

    let value = diagnostic_to_result(&diagnostic);
    write_indented_json(ctx.output_writer, &value, 6);
    first = false;
  }
  writeln!(ctx.output_writer).ok();
  write!(ctx.output_writer, "    ]").ok();

  if ctx.options.show_summary {
    if let Ok(stats) = ctx.scan_stats_receiver.recv() {
      let formatted = build_summary(stats, summary);
      writeln!(ctx.output_writer, ",").ok();
      write!(ctx.output_writer, "    \"properties\": ").ok();
      write_indented_json(
        ctx.output_writer,
        &summary_properties(&formatted),
        4,
      );
      writeln!(ctx.output_writer).ok();
    }
  } else {
    writeln!(ctx.output_writer).ok();
  }

  writeln!(ctx.output_writer, "  }}]").ok();
  writeln!(ctx.output_writer, "}}").ok();

  summary
}

fn write_header(out: &mut dyn std::io::Write) {
  let tool = json!({
    "driver": {
      "name": "trestle",
      "rules": rules(),
    }
  });
  writeln!(out, "{{").ok();
  writeln!(out, "  \"$schema\": \"{SARIF_SCHEMA}\",").ok();
  writeln!(out, "  \"version\": \"2.1.0\",").ok();
  writeln!(out, "  \"runs\": [{{").ok();
  write!(out, "    \"tool\": ").ok();
  write_indented_json(out, &tool, 4);
  writeln!(out, ",").ok();
}

fn summary_properties(
  formatted: &crate::output::FormattedSummary,
) -> serde_json::Value {
  let mut map = serde_json::Map::new();
  for field in SUMMARY_FIELDS {
    map.insert(field.name.to_owned(), formatted.field_value(field.name));
  }
  json!({ "trestleSummary": serde_json::Value::Object(map) })
}

fn rules() -> Vec<serde_json::Value> {
  RULES
    .iter()
    .map(|(id, desc)| {
      json!({
        "id": id,
        "shortDescription": { "text": desc },
      })
    })
    .collect()
}

fn diagnostic_to_result(diagnostic: &Diagnostic) -> serde_json::Value {
  let message = diagnostic.message();
  let level = severity_to_level(diagnostic.severity());

  let rule_id = diagnostic.id();

  let mut result = json!({
    "ruleId": rule_id,
    "level": level,
    "message": { "text": message },
  });

  result["locations"] = match diagnostic {
    Diagnostic::SecretAssignment { source_span, .. }
    | Diagnostic::SecretValue { source_span, .. } => build_locations(
      source_span.file_abs_path.as_path(),
      source_span.file_span.as_ref(),
    ),
    Diagnostic::BinarySecret { file_abs_path, .. }
    | Diagnostic::TextSecret { file_abs_path, .. } => {
      build_locations(file_abs_path.as_path(), None)
    }
  };

  if let Diagnostic::SecretAssignment {
    assignment_type, ..
  } = diagnostic
  {
    result["properties"] = json!({
      "assignmentType": assignment_type.to_string(),
    });
  }

  result
}

fn build_locations(
  file_abs_path: &std::path::Path,
  file_span: Option<&crate::source::SourceSpan>,
) -> serde_json::Value {
  let uri = format!("file://{}", file_abs_path.display());

  let mut physical = json!({
    "artifactLocation": { "uri": uri },
  });

  if let Some(span) = file_span {
    physical["region"] = json!({
      "startLine": span.start.line,
      "startColumn": span.start.column,
      "endLine": span.end.line,
      "endColumn": span.end.column,
    });
  }

  json!([{ "physicalLocation": physical }])
}

fn severity_to_level(severity: &Severity) -> &'static str {
  match severity {
    Severity::Critical => "error",
    Severity::Warning => "warning",
  }
}
