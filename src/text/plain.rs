use super::{RichText, Text, TextSpan};
use crate::formatting::wrap;

#[derive(Clone, Debug)]
pub struct RenderOptions {
  pub width: usize,
}

impl RenderOptions {
  pub fn new(width: usize) -> Self {
    Self { width }
  }
}

impl Default for RenderOptions {
  fn default() -> Self {
    Self { width: usize::MAX }
  }
}

pub fn render(text: &Text) -> String {
  render_with(text, &RenderOptions::default())
}

pub fn render_with(text: &Text, options: &RenderOptions) -> String {
  match text {
    Text::Plain(s) => render_plain(s, options),
    Text::Rich(spans) => render_spans_with(spans, options),
  }
}

pub fn render_spans(spans: &RichText) -> String {
  render_spans_with(spans, &RenderOptions::default())
}

pub fn render_spans_with(spans: &RichText, options: &RenderOptions) -> String {
  let mut out = String::new();
  write_spans(&mut out, spans, "", options);
  out.trim().to_string()
}

fn render_plain(s: &str, options: &RenderOptions) -> String {
  if options.width == usize::MAX {
    return s.to_string();
  }
  wrap(s, options.width, "").join("\n")
}

fn write_spans(
  out: &mut String,
  spans: &[TextSpan],
  indent: &str,
  options: &RenderOptions,
) {
  for span in spans {
    write_span(out, span, indent, options);
  }
}

fn write_span(
  out: &mut String,
  span: &TextSpan,
  indent: &str,
  options: &RenderOptions,
) {
  match span {
    TextSpan::Plain(s) => out.push_str(s),
    TextSpan::Code(s) => {
      out.push('`');
      out.push_str(s);
      out.push('`');
    }
    TextSpan::CodeBlock { lines, .. } => {
      for (i, line) in lines.iter().enumerate() {
        if i == 0 {
          out.push_str("\n\n");
        } else {
          out.push('\n');
        }

        out.push_str(indent);
        out.push_str(line);
      }
    }
    TextSpan::Filename(s) => out.push_str(s),
    TextSpan::Heading(s) => {
      out.push_str("\n\n");
      out.push_str(indent);
      out.push_str(s);
    }
    TextSpan::Link { url, text } => match text {
      Some(t) => {
        out.push_str(&render(t));
        out.push_str(" (");
        out.push_str(url);
        out.push(')');
      }
      None => out.push_str(url),
    },
    TextSpan::Paragraph(inner) => {
      out.push_str("\n\n");
      write_paragraph(out, inner, indent, options);
    }
    TextSpan::UnorderedList(items) => {
      let item_indent = format!("{indent}  ");
      for (index, item) in items.iter().enumerate() {
        if index == 0 {
          out.push_str("\n\n");
        } else {
          out.push('\n');
        }
        write_list_item(out, item, indent, "- ", &item_indent, options);
      }
    }
    TextSpan::OrderedList(items) => {
      let item_indent = format!("{indent}   ");
      for (i, item) in items.iter().enumerate() {
        if i == 0 {
          out.push_str("\n\n");
        } else {
          out.push('\n');
        }
        let marker = format!("{}. ", i + 1);
        write_list_item(out, item, indent, &marker, &item_indent, options);
      }
    }
  }
}

fn write_paragraph(
  out: &mut String,
  spans: &[TextSpan],
  indent: &str,
  options: &RenderOptions,
) {
  let mut buffer = String::new();
  write_spans(&mut buffer, spans, indent, options);
  push_wrapped(out, &buffer, indent, indent, options.width);
}

fn write_list_item(
  out: &mut String,
  item: &Text,
  indent: &str,
  marker: &str,
  body_indent: &str,
  options: &RenderOptions,
) {
  let first_prefix = format!("{indent}{marker}");

  match item {
    Text::Plain(s) => {
      push_wrapped(out, s, &first_prefix, body_indent, options.width);
    }
    Text::Rich(spans) if all_inline(spans) => {
      let mut buffer = String::new();
      write_spans(&mut buffer, spans, body_indent, options);
      push_wrapped(out, &buffer, &first_prefix, body_indent, options.width);
    }
    Text::Rich(spans) => {
      let appended_start = out.len();

      write_spans(out, spans, body_indent, options);

      let after_newlines = appended_start
        + out[appended_start..]
          .bytes()
          .take_while(|b| *b == b'\n')
          .count();

      let after_indent = after_newlines
        + out[after_newlines..]
          .bytes()
          .take_while(|b| *b == b' ')
          .count();

      out.replace_range(appended_start..after_indent, &first_prefix);
    }
  }
}

fn all_inline(spans: &[TextSpan]) -> bool {
  spans.iter().all(|s| {
    matches!(
      s,
      TextSpan::Plain(_)
        | TextSpan::Code(_)
        | TextSpan::Filename(_)
        | TextSpan::Link { .. }
    )
  })
}

fn push_wrapped(
  out: &mut String,
  text: &str,
  first_prefix: &str,
  cont_prefix: &str,
  width: usize,
) {
  if width == usize::MAX {
    out.push_str(first_prefix);
    out.push_str(text.trim_start());
    return;
  }
  let first_width = first_prefix.chars().count();
  let content_width = width.saturating_sub(first_width).max(1);
  let lines = wrap(text, content_width, cont_prefix);
  for (i, line) in lines.iter().enumerate() {
    if i == 0 {
      out.push_str(first_prefix);
    } else {
      out.push('\n');
    }
    out.push_str(line);
  }
}
