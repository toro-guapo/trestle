use super::{RichText, Text, TextSpan};

pub fn render(text: &Text) -> String {
  match text {
    Text::Plain(s) => escape(s),
    Text::Rich(spans) => render_spans(spans),
  }
}

pub fn render_spans(spans: &RichText) -> String {
  let mut out = String::new();
  write_spans(&mut out, spans, "");
  out.trim().to_string()
}

fn write_spans(out: &mut String, spans: &[TextSpan], indent: &str) {
  for span in spans {
    write_span(out, span, indent);
  }
}

fn write_span(out: &mut String, span: &TextSpan, indent: &str) {
  match span {
    TextSpan::Plain(s) => out.push_str(&escape(s)),
    TextSpan::Code(s) => out.push_str(&render_code(s)),
    TextSpan::Filename(s) => out.push_str(&render_code(s)),
    TextSpan::Heading(s) => {
      out.push_str("\n\n");
      out.push_str(indent);
      out.push_str("## ");
      out.push_str(&escape(s));
    }
    TextSpan::Link { url, text } => write_link(out, url, text.as_ref()),
    TextSpan::Paragraph(inner) => {
      out.push_str("\n\n");
      out.push_str(indent);
      write_spans(out, inner, indent);
    }
    TextSpan::UnorderedList(items) => {
      let item_indent = format!("{indent}  ");
      for (i, item) in items.iter().enumerate() {
        out.push_str(if i == 0 { "\n\n" } else { "\n" });
        out.push_str(indent);
        out.push_str("- ");
        write_list_item(out, item, &item_indent);
      }
    }
    TextSpan::OrderedList(items) => {
      let item_indent = format!("{indent}   ");
      for (i, item) in items.iter().enumerate() {
        out.push_str(if i == 0 { "\n\n" } else { "\n" });
        out.push_str(indent);
        out.push_str(&format!("{}. ", i + 1));
        write_list_item(out, item, &item_indent);
      }
    }
  }
}

fn write_link(out: &mut String, url: &str, text: Option<&Text>) {
  match text {
    Some(t) => {
      let label = render(t);
      out.push('[');
      out.push_str(&label);
      out.push_str("](");
      out.push_str(url);
      out.push(')');
    }
    None => {
      out.push('<');
      out.push_str(url);
      out.push('>');
    }
  }
}

fn write_list_item(out: &mut String, item: &Text, body_indent: &str) {
  match item {
    Text::Plain(s) => out.push_str(&escape(s)),
    Text::Rich(spans) => write_spans(out, spans, body_indent),
  }
}

fn escape(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  for c in s.chars() {
    match c {
      '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '&' => {
        out.push('\\');
        out.push(c);
      }
      _ => out.push(c),
    }
  }
  out
}

fn render_code(content: &str) -> String {
  let max_run = max_backtick_run(content);
  let fence = "`".repeat(max_run + 1);
  let needs_padding = content.starts_with('`') || content.ends_with('`');
  if needs_padding {
    format!("{fence} {content} {fence}")
  } else {
    format!("{fence}{content}{fence}")
  }
}

fn max_backtick_run(s: &str) -> usize {
  let mut max = 0;
  let mut current = 0;
  for c in s.chars() {
    if c == '`' {
      current += 1;
      if current > max {
        max = current;
      }
    } else {
      current = 0;
    }
  }
  max
}
