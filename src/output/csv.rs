use crate::diagnostic::{AnnotatedDiagnostic, Diagnostic};
use crate::formatting::uppercase_first;
use crate::output::{ScanSummary, WriteContext, build_summary, count};

const HEADER: &[&str] = &[
  "Severity",
  "Rule ID",
  "Name",
  "Assignment Type",
  "Description",
  "Message",
  "File",
  "Start Line",
  "Start Column",
  "End Line",
  "End Column",
  "Fingerprint",
];

pub fn write(ctx: WriteContext<'_>) -> ScanSummary {
  let mut summary = ScanSummary::default();
  let mut writer = csv::Writer::from_writer(ctx.output_writer);
  writer.write_record(HEADER).ok();

  for diagnostic in ctx.diagnostic_receiver {
    count(&mut summary, &diagnostic);
    let row = build_row(&diagnostic);
    writer.write_record(&row).ok();
  }

  writer.flush().ok();

  if ctx.options.show_summary
    && let Ok(stats) = ctx.scan_stats_receiver.recv()
  {
    let formatted = build_summary(stats, summary);
    eprintln!("{}", formatted.message);
  }

  summary
}

fn build_row(annotated: &AnnotatedDiagnostic) -> Vec<String> {
  let severity = annotated.severity().to_string().to_lowercase();
  let rule_id = annotated.id();
  let message = annotated.message();

  let mut row = match &annotated.diagnostic {
    Diagnostic::SecretAssignment {
      name,
      assignment_type,
      value_class,
      source_span,
      ..
    } => {
      let (file, start_line, start_col, end_line, end_col) =
        extract_location(source_span);
      vec![
        severity,
        rule_id.into(),
        name.clone(),
        assignment_type.to_string(),
        uppercase_first(&value_class.to_string()),
        message,
        file,
        start_line,
        start_col,
        end_line,
        end_col,
      ]
    }
    Diagnostic::SecretValue {
      source_span,
      value_class,
      ..
    } => {
      let (file, start_line, start_col, end_line, end_col) =
        extract_location(source_span);
      vec![
        severity,
        rule_id.into(),
        String::new(),
        String::new(),
        uppercase_first(&value_class.to_string()),
        message,
        file,
        start_line,
        start_col,
        end_line,
        end_col,
      ]
    }
    Diagnostic::BinarySecret {
      secret,
      file_abs_path,
      ..
    } => vec![
      severity,
      rule_id.into(),
      String::new(),
      String::new(),
      uppercase_first(&secret.to_string()),
      message,
      file_abs_path.display().to_string(),
      String::new(),
      String::new(),
      String::new(),
      String::new(),
    ],
    Diagnostic::TextSecret {
      secret,
      file_abs_path,
      ..
    } => vec![
      severity,
      rule_id.into(),
      String::new(),
      String::new(),
      uppercase_first(&secret.to_string()),
      message,
      file_abs_path.display().to_string(),
      String::new(),
      String::new(),
      String::new(),
      String::new(),
    ],
  };

  row.push(annotated.fingerprint().as_str().to_owned());
  row
}

fn extract_location(
  source_span: &crate::source::SourceFileSpan,
) -> (String, String, String, String, String) {
  let file = source_span.file_abs_path.display().to_string();

  if let Some(span) = &source_span.file_span {
    (
      file,
      span.start.line.to_string(),
      span.start.column.to_string(),
      span.end.line.to_string(),
      span.end.column.to_string(),
    )
  } else {
    (
      file,
      String::new(),
      String::new(),
      String::new(),
      String::new(),
    )
  }
}
