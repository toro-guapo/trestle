use std::path::Path;
use std::sync::mpsc::Receiver;


use crate::advice::{self, AdviceContext};
use crate::diagnostic::AnnotatedDiagnostic;
use crate::formatting::truncate_with_ellipsis;
use crate::git;
use crate::output::{ScanStats, ScanSummary, count};
use crate::text::{Text, TextSpan, plain};

#[cfg(feature = "git-history")]
use crate::advice::HistorySection;

pub fn explanation_for(
  diagnostic: &AnnotatedDiagnostic,
  scan_root: &Path,
  width: usize,
  detailed: bool,
) -> Text {
  let git = git::open(scan_root).and_then(|repo| repo.thread_handle());
  let mut context = AdviceContext {
    git,
  };
  let advice = advice::advise_annotated(&mut context, diagnostic);
  advice_to_text(&advice, width, detailed)
}

pub fn plain_explanation_for(
  diagnostic: &AnnotatedDiagnostic,
  scan_root: &Path,
  width: usize,
  detailed: bool,
) -> String {
  let text = explanation_for(
    diagnostic,
    scan_root,
    width,
    detailed,
  );
  plain::render(&text)
}

pub fn bare_explanation_for(
  diagnostic: &crate::diagnostic::Diagnostic,
  scan_root: &Path,
  width: usize,
  detailed: bool,
) -> Text {
  let git = git::open(scan_root).and_then(|repo| repo.thread_handle());

  let mut context = AdviceContext {
    git,
  };

  let advice = advice::advise(&mut context, diagnostic);
  advice_to_text(&advice, width, detailed)
}

pub fn drain_after_scan(
  diagnostic_receiver: Receiver<AnnotatedDiagnostic>,
  scan_stats_receiver: Receiver<ScanStats>,
  summary: &mut ScanSummary,
) -> (Vec<AnnotatedDiagnostic>, Option<ScanStats>) {
  let mut diagnostics: Vec<AnnotatedDiagnostic> = Vec::new();
  for diagnostic in diagnostic_receiver {
    count(summary, &diagnostic);
    diagnostics.push(diagnostic);
  }
  let stats = scan_stats_receiver.recv().ok();
  (diagnostics, stats)
}

fn advice_to_text(
  advice: &advice::Advice,
  width: usize,
  detailed: bool,
) -> Text {
  let mut spans: Vec<TextSpan> = Vec::new();

  spans.push(text_to_paragraph_span(&advice.summary));

  push_section(
    &mut spans,
    "Development",
    advice.development_summary.as_ref(),
    advice
      .development_steps
      .iter()
      .map(|s| s.render())
      .collect(),
  );

  push_section(
    &mut spans,
    "Deployment",
    advice.deployment_summary.as_ref(),
    advice.deployment_steps.iter().map(|s| s.render()).collect(),
  );

  #[cfg(feature = "git-history")]
  if let Some(history) = &advice.history {
    push_history_section(&mut spans, history, width, detailed);
  }

  let _ = (width, detailed);
  Text::Rich(spans)
}

#[cfg(feature = "git-history")]
fn push_history_section(
  spans: &mut Vec<TextSpan>,
  history: &HistorySection,
  width: usize,
  detailed: bool,
) {
  spans.push(TextSpan::Heading("History".to_owned()));

  for paragraph in &history.paragraphs {
    spans.push(text_to_paragraph_span(paragraph));
  }

  if !history.commands.is_empty() {
    spans.push(TextSpan::CodeBlock {
      language: Some("sh".to_owned()),
      lines: history.commands.clone(),
    });
  }

  if history.commits.is_empty() {
    return;
  }

  let count = history.total_commits;
  let count_phrase =
    crate::formatting::format_count(count, "commit", "commits");

  spans.push(TextSpan::Paragraph(vec![TextSpan::Plain(format!(
    "Found in {count_phrase}:"
  ))]));

  let displayed = pick_displayed_commits(&history.commits, detailed);
  let indent = 2;
  let lines: Vec<String> = displayed
    .iter()
    .map(|c| format_commit_line(c, width, indent))
    .collect();

  spans.push(TextSpan::CodeBlock {
    language: None,
    lines,
  });
}

#[cfg(feature = "git-history")]
fn pick_displayed_commits(
  commits: &[crate::diagnostic::HistoryCommit],
  detailed: bool,
) -> Vec<DisplayCommit<'_>> {
  if detailed || commits.len() <= 4 {
    return commits.iter().map(DisplayCommit::Commit).collect();
  }
  let n = commits.len();
  vec![
    DisplayCommit::Commit(&commits[0]),
    DisplayCommit::Commit(&commits[1]),
    DisplayCommit::Ellipsis,
    DisplayCommit::Commit(&commits[n - 2]),
    DisplayCommit::Commit(&commits[n - 1]),
  ]
}

#[cfg(feature = "git-history")]
enum DisplayCommit<'a> {
  Commit(&'a crate::diagnostic::HistoryCommit),
  Ellipsis,
}

#[cfg(feature = "git-history")]
fn format_commit_line(
  item: &DisplayCommit<'_>,
  width: usize,
  indent_cols: usize,
) -> String {
  match item {
    DisplayCommit::Ellipsis => "...".to_owned(),
    DisplayCommit::Commit(c) => {
      let local = c.author_time.with_timezone(&chrono::Local);
      let stamp = local.format("%Y-%m-%d %H:%M").to_string();
      let prefix = format!("{} {}", c.short_commit(), stamp);

      let subject_space =
        width.saturating_sub(indent_cols + prefix.chars().count() + 1);

      let subject = if c.subject.is_empty() {
        String::new()
      } else if subject_space == 0 {
        String::new()
      } else {
        truncate_with_ellipsis(&c.subject, subject_space)
      };

      if subject.is_empty() {
        prefix
      } else {
        format!("{prefix} {subject}")
      }
    }
  }
}

fn push_section(
  spans: &mut Vec<TextSpan>,
  label: &str,
  summary: Option<&Text>,
  steps: Vec<Text>,
) {
  if summary.is_none() && steps.is_empty() {
    return;
  }

  spans.push(TextSpan::Heading(label.to_string()));

  if let Some(s) = summary {
    spans.push(text_to_paragraph_span(s));
  }

  if !steps.is_empty() {
    spans.push(TextSpan::OrderedList(steps));
  }
}

fn text_to_paragraph_span(text: &Text) -> TextSpan {
  match text {
    Text::Plain(s) => TextSpan::Paragraph(vec![TextSpan::Plain(s.clone())]),
    Text::Rich(spans) => TextSpan::Paragraph(spans.clone()),
  }
}
