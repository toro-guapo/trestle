use std::path::Path;
use std::sync::mpsc::Receiver;


use crate::advice::{self, AdviceContext};
use crate::diagnostic::Diagnostic;
use crate::git;
use crate::output::{ScanStats, ScanSummary, count};
use crate::text::{Text, TextSpan, plain};

pub fn explanation_for(
  diagnostic: &Diagnostic,
  scan_root: &Path,
) -> Text {
  let git = git::open(scan_root).and_then(|repo| repo.thread_handle());
  let mut context = AdviceContext {
    git,
  };
  let advice = advice::advise(&mut context, diagnostic);
  advice_to_text(&advice)
}

pub fn plain_explanation_for(
  diagnostic: &Diagnostic,
  scan_root: &Path,
) -> String {
  let text = explanation_for(
    diagnostic,
    scan_root,
  );
  plain::render(&text)
}

pub fn drain_after_scan(
  diagnostic_receiver: Receiver<Diagnostic>,
  scan_stats_receiver: Receiver<ScanStats>,
  summary: &mut ScanSummary,
) -> (Vec<Diagnostic>, Option<ScanStats>) {
  let mut diagnostics: Vec<Diagnostic> = Vec::new();
  for diagnostic in diagnostic_receiver {
    count(summary, &diagnostic);
    diagnostics.push(diagnostic);
  }
  let stats = scan_stats_receiver.recv().ok();
  (diagnostics, stats)
}

fn advice_to_text(advice: &advice::Advice) -> Text {
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

  Text::Rich(spans)
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
