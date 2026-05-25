use std::io;

use quick_xml::Writer;
use quick_xml::events::{
  BytesCData, BytesDecl, BytesEnd, BytesStart, BytesText, Event,
};

use crate::diagnostic::Diagnostic;
use crate::formatting::uppercase_first;
use crate::output::{
  SUMMARY_FIELDS, ScanStats, ScanSummary, WriteContext, build_summary, count,
};
use crate::source::SourceFileSpan;

pub fn write(ctx: WriteContext<'_>) -> ScanSummary {
  let mut summary = ScanSummary::default();

  let diagnostics: Vec<Diagnostic> = ctx
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
  diagnostics: &[Diagnostic],
  summary: ScanSummary,
  show_summary: bool,
  stats: Option<ScanStats>,
) {
  let mut xml = Writer::new_with_indent(writer, b' ', 2);

  xml
    .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
    .ok();
  xml.write_event(Event::Text(BytesText::new("\n"))).ok();

  xml
    .write_event(Event::Start(BytesStart::new("trestle")))
    .ok();

  xml
    .write_event(Event::Start(BytesStart::new("diagnostics")))
    .ok();

  for diagnostic in diagnostics {
    write_diagnostic(&mut xml, diagnostic);
  }

  xml
    .write_event(Event::End(BytesEnd::new("diagnostics")))
    .ok();

  if show_summary {
    if let Some(stats) = stats {
      write_summary(&mut xml, build_summary(stats, summary));
    }
  }

  xml.write_event(Event::End(BytesEnd::new("trestle"))).ok();
  xml.write_event(Event::Text(BytesText::new("\n"))).ok();
}

fn write_diagnostic(
  xml: &mut Writer<&mut dyn io::Write>,
  diagnostic: &Diagnostic,
) {
  let rule_id = diagnostic.id();
  let severity = diagnostic.severity().to_string().to_lowercase();
  let message = diagnostic.message();

  let mut tag = BytesStart::new("diagnostic");
  tag.push_attribute(("ruleId", rule_id));
  tag.push_attribute(("severity", severity.as_str()));

  match diagnostic {
    Diagnostic::SecretAssignment {
      name,
      assignment_type,
      value_class,
      source_span,
      ..
    } => {
      tag.push_attribute(("name", name.as_str()));
      tag.push_attribute((
        "assignmentType",
        assignment_type.to_string().as_str(),
      ));
      let description = uppercase_first(&value_class.to_string());
      tag.push_attribute(("description", description.as_str()));
      push_location_attrs(&mut tag, source_span);
    }
    Diagnostic::SecretValue {
      source_span,
      value_class,
      ..
    } => {
      let description = uppercase_first(&value_class.to_string());
      tag.push_attribute(("description", description.as_str()));
      push_location_attrs(&mut tag, source_span);
    }
    Diagnostic::BinarySecret {
      secret,
      file_abs_path,
      ..
    } => {
      let description = uppercase_first(&secret.to_string());
      tag.push_attribute(("description", description.as_str()));
      push_path_attr(&mut tag, file_abs_path.as_path());
    }
    Diagnostic::TextSecret {
      secret,
      file_abs_path,
      ..
    } => {
      let description = uppercase_first(&secret.to_string());
      tag.push_attribute(("description", description.as_str()));
      push_path_attr(&mut tag, file_abs_path.as_path());
    }
  }

  xml.write_event(Event::Start(tag)).ok();
  write_cdata_tag(xml, "message", &message);

  xml
    .write_event(Event::End(BytesEnd::new("diagnostic")))
    .ok();
}

fn push_path_attr(tag: &mut BytesStart, path: &std::path::Path) {
  tag.push_attribute(("file", path.display().to_string().as_str()));
}

fn push_location_attrs(tag: &mut BytesStart, source_span: &SourceFileSpan) {
  tag.push_attribute((
    "file",
    source_span.file_abs_path.display().to_string().as_str(),
  ));
  if let Some(span) = &source_span.file_span {
    tag.push_attribute(("startLine", span.start.line.to_string().as_str()));
    tag.push_attribute(("startColumn", span.start.column.to_string().as_str()));
    tag.push_attribute(("endLine", span.end.line.to_string().as_str()));
    tag.push_attribute(("endColumn", span.end.column.to_string().as_str()));
  }
}

fn write_summary(
  xml: &mut Writer<&mut dyn io::Write>,
  summary: crate::output::FormattedSummary,
) {
  xml
    .write_event(Event::Start(BytesStart::new("summary")))
    .ok();

  for field in SUMMARY_FIELDS {
    let value = summary.field_text(field.name);
    if field.name == "message" {
      write_cdata_tag(xml, field.name, &value);
    } else {
      write_text_tag(xml, field.name, &value);
    }
  }

  xml.write_event(Event::End(BytesEnd::new("summary"))).ok();
}

fn write_cdata_tag(
  xml: &mut Writer<&mut dyn io::Write>,
  name: &str,
  value: &str,
) {
  xml.write_event(Event::Start(BytesStart::new(name))).ok();
  xml.write_event(Event::CData(BytesCData::new(value))).ok();
  xml.write_event(Event::End(BytesEnd::new(name))).ok();
}

fn write_text_tag(
  xml: &mut Writer<&mut dyn io::Write>,
  name: &str,
  value: &str,
) {
  xml.write_event(Event::Start(BytesStart::new(name))).ok();
  xml.write_event(Event::Text(BytesText::new(value))).ok();
  xml.write_event(Event::End(BytesEnd::new(name))).ok();
}
