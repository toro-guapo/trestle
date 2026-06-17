use crate::diagnostic::{AnnotatedDiagnostic, Severity};
use crate::formatting::format_count;
use crate::output::{ScanSummary, WriteContext, build_summary, count};
#[cfg(feature = "validation")]
use crate::validation::ValidationStatus;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_DARK_YELLOW: &str = "\x1b[33m";
const ANSI_DIM: &str = "\x1b[90m";

fn colorize_summary(summary: &ScanSummary, scanned_str: &str) -> String {
  let total = summary.total();

  if total == 0 {
    return format!("{scanned_str}. No secrets found.");
  }

  let label = |n: usize, singular: &str, plural: &str, color: &str| -> String {
    let word = if n == 1 { singular } else { plural };
    format!("{color}{n}{ANSI_RESET} {word}")
  };

  if summary.critical_count == total {
    let s = label(total, "secret", "secrets", ANSI_RED);
    return format!("{scanned_str}. Found {s}.");
  }

  if summary.warning_count == total {
    let s = label(total, "warning", "warnings", ANSI_DARK_YELLOW);
    return format!("{scanned_str}. Found {s}.");
  }

  let mut parts = Vec::new();

  if summary.critical_count > 0 {
    parts.push(label(summary.critical_count, "secret", "secrets", ANSI_RED));
  }

  if summary.warning_count > 0 {
    parts.push(label(
      summary.warning_count,
      "warning",
      "warnings",
      ANSI_DARK_YELLOW,
    ));
  }

  format!("{scanned_str}. Found {}.", parts.join(" and "))
}

fn split_line_column_suffix(location: &str) -> Option<(&str, &str)> {
  let (before_col, col) = location.rsplit_once(':')?;
  if col.is_empty() || !col.chars().all(|c| c.is_ascii_digit()) {
    return None;
  }

  let (path, line) = before_col.rsplit_once(':')?;
  if line.is_empty() || !line.chars().all(|c| c.is_ascii_digit()) {
    return None;
  }

  let suffix_start = path.len();
  Some((&location[..suffix_start], &location[suffix_start..]))
}

#[cfg(feature = "validation")]
fn validation_label(status: ValidationStatus) -> &'static str {
  match status {
    ValidationStatus::Live => "(active)",
    ValidationStatus::Inactive => "(inactive)",
    ValidationStatus::Unknown => "(could not verify)",
  }
}

fn render_diagnostic(
  diagnostic: &AnnotatedDiagnostic,
  use_color: bool,
) -> String {
  let severity_label = diagnostic.severity().to_string().to_uppercase();
  let severity = if use_color {
    match diagnostic.severity() {
      Severity::Critical => {
        format!("{ANSI_RED}{severity_label}{ANSI_RESET}")
      }
      Severity::Warning => {
        format!("{ANSI_DARK_YELLOW}{severity_label}{ANSI_RESET}")
      }
    }
  } else {
    severity_label
  };

  let message = diagnostic.message();

  let line = if let Some(source_span) = diagnostic.source_span() {
    let location = source_span.display_start();
    let location = if use_color {
      if let Some((path, suffix)) = split_line_column_suffix(&location) {
        format!("{path}{ANSI_DIM}{suffix}{ANSI_RESET}")
      } else {
        location
      }
    } else {
      location
    };
    format!("{severity} {location} {message}")
  } else {
    let location = diagnostic.file_abs_path().display().to_string();
    format!("{severity} {location}: {message}")
  };

  #[cfg(feature = "git-history")]
  let line = match diagnostic.display_history() {
    Some(marker) if use_color => {
      format!("{line} {ANSI_DIM}{marker}{ANSI_RESET}")
    }
    Some(marker) => format!("{line} {marker}"),
    None => line,
  };

  #[cfg(feature = "validation")]
  let line = match diagnostic.validation() {
    Some(status) if use_color => {
      let label = validation_label(status);
      match status {
        ValidationStatus::Live => {
          format!("{line} {ANSI_RED}{label}{ANSI_RESET}")
        }
        _ => format!("{line} {ANSI_DIM}{label}{ANSI_RESET}"),
      }
    }
    Some(status) => format!("{line} {}", validation_label(status)),
    None => line,
  };

  let fingerprint = diagnostic.fingerprint();
  if use_color {
    format!("{line} {ANSI_DIM}[{fingerprint}]{ANSI_RESET}")
  } else {
    format!("{line} [{fingerprint}]")
  }
}

pub fn write(ctx: WriteContext<'_>) -> ScanSummary {
  let mut summary = ScanSummary::default();
  let use_color = ctx.options.color.unwrap_or(ctx.output_is_terminal);

  let WriteContext {
    diagnostic_receiver,
    options,
    output_writer,
    scan_stats_receiver,
    ..
  } = ctx;

  for diagnostic in diagnostic_receiver {
    count(&mut summary, &diagnostic);
    let rendered = render_diagnostic(&diagnostic, use_color);
    writeln!(output_writer, "{rendered}").ok();
  }

  if options.show_summary
    && let Ok(stats) = scan_stats_receiver.recv()
  {
    let formatted = build_summary(stats, summary);
    let message = summary_message(&formatted, &summary, use_color);
    writeln!(output_writer, "{message}").ok();
  }

  summary
}

fn summary_message(
  formatted: &crate::output::FormattedSummary,
  summary: &ScanSummary,
  use_color: bool,
) -> String {
  if use_color {
    let files_str = format_count(formatted.scanned_file_count, "file", "files");
    let elapsed_str = if formatted.elapsed_milliseconds >= 1000 {
      format!("{:.2}s", formatted.elapsed_milliseconds as f64 / 1000.0)
    } else {
      format!("{}ms", formatted.elapsed_milliseconds)
    };
    let scanned_str = format!("Scanned {files_str} in {elapsed_str}");
    colorize_summary(summary, &scanned_str)
  } else {
    formatted.message.clone()
  }
}
