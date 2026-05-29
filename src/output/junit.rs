use std::io;

use quick_xml::Writer;
use quick_xml::events::{
  BytesCData, BytesDecl, BytesEnd, BytesStart, BytesText, Event,
};

use crate::diagnostic::{AnnotatedDiagnostic, Diagnostic};
use crate::output::{
  SUMMARY_FIELDS, ScanStats, ScanSummary, WriteContext, build_summary, count,
};

pub fn write(ctx: WriteContext<'_>) -> ScanSummary {
  let mut summary = ScanSummary::default();

  let diagnostics: Vec<AnnotatedDiagnostic> = ctx
    .diagnostic_receiver
    .into_iter()
    .inspect(|d| count(&mut summary, d))
    .collect();

  let stats = ctx.scan_stats_receiver.recv().ok();

  emit_xml(
    ctx.output_writer,
    &diagnostics,
    summary,
    ctx.options.show_summary,
    stats,
  );

  summary
}

fn emit_xml(
  writer: &mut dyn io::Write,
  diagnostics: &[AnnotatedDiagnostic],
  summary: ScanSummary,
  show_summary: bool,
  stats: Option<ScanStats>,
) {
  let mut xml = Writer::new_with_indent(writer, b' ', 2);

  xml
    .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
    .ok();
  xml.write_event(Event::Text(BytesText::new("\n"))).ok();

  let total = summary.total();

  let mut suite = BytesStart::new("testsuite");
  suite.push_attribute(("name", "trestle"));
  suite.push_attribute(("tests", total.to_string().as_str()));
  suite.push_attribute(("failures", total.to_string().as_str()));
  suite.push_attribute(("errors", "0"));
  xml.write_event(Event::Start(suite)).ok();

  if show_summary {
    if let Some(stats) = stats {
      let formatted = build_summary(stats, summary);
      write_properties(&mut xml, &formatted);
    }
  }

  for diagnostic in diagnostics {
    write_testcase(&mut xml, diagnostic);
  }

  xml.write_event(Event::End(BytesEnd::new("testsuite"))).ok();
  xml.write_event(Event::Text(BytesText::new("\n"))).ok();
}

fn write_testcase(
  xml: &mut Writer<&mut dyn io::Write>,
  diagnostic: &AnnotatedDiagnostic,
) {
  let mut testcase = BytesStart::new("testcase");
  testcase.push_attribute(("name", diagnostic_name(diagnostic).as_str()));
  testcase.push_attribute(("classname", diagnostic.id()));
  testcase.push_attribute(("fingerprint", diagnostic.fingerprint().as_str()));
  if let Diagnostic::SecretAssignment {
    assignment_type, ..
  } = &diagnostic.diagnostic
  {
    testcase
      .push_attribute(("assignmentType", assignment_type.to_string().as_str()));
  }
  xml.write_event(Event::Start(testcase)).ok();

  let severity = diagnostic.severity().to_string().to_lowercase();
  let message = diagnostic.message();

  let mut failure = BytesStart::new("failure");
  failure.push_attribute(("message", message.as_str()));
  failure.push_attribute(("type", severity.as_str()));
  xml.write_event(Event::Start(failure)).ok();

  let body = format!("{diagnostic}");
  xml.write_event(Event::CData(BytesCData::new(body))).ok();

  xml.write_event(Event::End(BytesEnd::new("failure"))).ok();
  xml.write_event(Event::End(BytesEnd::new("testcase"))).ok();
}

fn write_properties(
  xml: &mut Writer<&mut dyn io::Write>,
  summary: &crate::output::FormattedSummary,
) {
  xml
    .write_event(Event::Start(BytesStart::new("properties")))
    .ok();

  for field in SUMMARY_FIELDS {
    write_property(xml, field.name, &summary.field_text(field.name));
  }

  xml
    .write_event(Event::End(BytesEnd::new("properties")))
    .ok();
}

fn write_property(
  xml: &mut Writer<&mut dyn io::Write>,
  name: &str,
  value: &str,
) {
  let mut tag = BytesStart::new("property");
  tag.push_attribute(("name", name));
  tag.push_attribute(("value", value));
  xml.write_event(Event::Empty(tag)).ok();
}

fn diagnostic_name(diagnostic: &AnnotatedDiagnostic) -> String {
  match &diagnostic.diagnostic {
    Diagnostic::SecretAssignment { source_span, .. }
    | Diagnostic::SecretValue { source_span, .. } => {
      source_span.display_start()
    }
    Diagnostic::BinarySecret { file_abs_path, .. }
    | Diagnostic::TextSecret { file_abs_path, .. } => {
      file_abs_path.display().to_string()
    }
  }
}
