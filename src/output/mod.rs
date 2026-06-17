mod csv;
mod json;
mod junit;
mod sarif;
mod text;
mod xml;

use std::io;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::diagnostic::{AnnotatedDiagnostic, Severity};
#[cfg(feature = "git-history")]
use crate::diagnostic::{HistoryAttribution, HistoryLocation};
use crate::formatting::format_count;
use crate::options::{Options, OutputFormat};

pub struct SummaryFieldInfo {
  pub name: &'static str,
  pub description: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/summary_fields.rs"));

#[derive(Debug, Clone, Copy)]
pub struct ScanStats {
  pub scanned_file_count: usize,
  pub elapsed: Duration,
}

pub struct WriteContext<'a> {
  pub diagnostic_receiver: Receiver<AnnotatedDiagnostic>,
  pub options: Options,
  pub output_is_terminal: bool,
  pub output_writer: &'a mut dyn io::Write,
  pub scan_stats_receiver: Receiver<ScanStats>,
}

#[derive(Debug, Clone)]
pub struct FormattedSummary {
  pub scanned_file_count: usize,
  pub elapsed_milliseconds: u128,
  pub critical_count: usize,
  pub warning_count: usize,
  pub total_count: usize,
  pub message: String,
}

impl FormattedSummary {
  pub fn field_value(&self, name: &str) -> serde_json::Value {
    match name {
      "scannedFileCount" => serde_json::json!(self.scanned_file_count),
      "elapsedMilliseconds" => serde_json::json!(self.elapsed_milliseconds),
      "criticalCount" => serde_json::json!(self.critical_count),
      "warningCount" => serde_json::json!(self.warning_count),
      "totalCount" => serde_json::json!(self.total_count),
      "message" => serde_json::json!(self.message),
      _ => serde_json::Value::Null,
    }
  }

  pub fn field_text(&self, name: &str) -> String {
    match self.field_value(name) {
      serde_json::Value::String(s) => s,
      other => other.to_string(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanSummary {
  pub critical_count: usize,
  pub warning_count: usize,
}

impl ScanSummary {
  pub fn total(&self) -> usize {
    self.critical_count.saturating_add(self.warning_count)
  }
}

pub fn write(write_context: WriteContext<'_>) -> ScanSummary {
  match write_context.options.output_format.clone() {
    OutputFormat::Text => text::write(write_context),
    OutputFormat::Csv => csv::write(write_context),
    OutputFormat::Json => json::write(write_context),
    OutputFormat::Junit => junit::write(write_context),
    OutputFormat::Sarif => sarif::write(write_context),
    OutputFormat::Xml => xml::write(write_context),
  }
}

pub fn count(summary: &mut ScanSummary, diagnostic: &AnnotatedDiagnostic) {
  match diagnostic.severity() {
    Severity::Critical => {
      summary.critical_count = summary.critical_count.saturating_add(1);
    }
    Severity::Warning => {
      summary.warning_count = summary.warning_count.saturating_add(1);
    }
  }
}

pub fn build_summary(
  context: ScanStats,
  summary: ScanSummary,
) -> FormattedSummary {
  let files_str = format_count(context.scanned_file_count, "file", "files");

  let elapsed_str = if context.elapsed.as_secs() >= 1 {
    format!("{:.2}s", context.elapsed.as_secs_f64())
  } else {
    format!("{}ms", context.elapsed.as_millis())
  };

  let scanned_str = format!("Scanned {files_str} in {elapsed_str}");
  let total = summary.total();

  let message = if total == 0 {
    format!("{scanned_str}. No secrets found.")
  } else if summary.critical_count == total {
    format!(
      "{scanned_str}. Found {}.",
      format_count(total, "secret", "secrets")
    )
  } else if summary.warning_count == total {
    format!(
      "{scanned_str}. Found {}.",
      format_count(total, "warning", "warnings")
    )
  } else {
    let mut parts = Vec::new();

    if summary.critical_count > 0 {
      parts.push(format_count(summary.critical_count, "secret", "secrets"));
    }

    if summary.warning_count > 0 {
      parts.push(format_count(summary.warning_count, "warning", "warnings"));
    }

    format!("{scanned_str}. Found {}.", parts.join(" and "))
  };

  FormattedSummary {
    scanned_file_count: context.scanned_file_count,
    elapsed_milliseconds: context.elapsed.as_millis(),
    critical_count: summary.critical_count,
    warning_count: summary.warning_count,
    total_count: total,
    message,
  }
}

#[cfg(feature = "git-history")]
pub fn history_to_json(history: &HistoryAttribution) -> serde_json::Value {
  use serde_json::json;
  let location = match &history.location {
    HistoryLocation::Branch { name, current } => {
      json!({ "type": "branch", "current": current, "name": name })
    }
    HistoryLocation::RemoteRef(name) => {
      json!({ "type": "remoteRef", "name": name })
    }
    HistoryLocation::Tag(name) => json!({ "type": "tag", "name": name }),
    HistoryLocation::Stash => json!({ "type": "stash" }),
    HistoryLocation::Dangling => json!({ "type": "dangling" }),
  };
  let mut obj = json!({
    "commit": history.commit,
    "authorDate": history.author_date.to_string(),
    "alsoInWorkingTree": history.also_in_working_tree,
    "location": location,
  });

  if let (Some(oldest), Some(newest)) =
    (history.commits.first(), history.commits.last())
  {
    obj["commits"] = json!({
      "oldest": oldest.commit,
      "newest": newest.commit,
      "total": history.commits.len(),
    });
  }

  obj
}

pub fn write_indented_json(
  writer: &mut dyn io::Write,
  value: &serde_json::Value,
  indent: usize,
) {
  let pretty = serde_json::to_string_pretty(value).unwrap_or_default();
  let prefix = " ".repeat(indent);
  for (i, line) in pretty.lines().enumerate() {
    if i > 0 {
      writeln!(writer).ok();
    }
    write!(writer, "{prefix}{line}").ok();
  }
}
