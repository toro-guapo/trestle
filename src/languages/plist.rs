use std::io::Cursor;

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_assignment, check_value,
    offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  if source.as_bytes().starts_with(b"bplist") {
    return parse_binary(context, source.as_bytes());
  }

  parse_xml(context, source)
}

// ---------------------------------------------------------------------------
// XML plist parsing (with source spans)
// ---------------------------------------------------------------------------

struct XmlContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
}

fn parse_xml(context: &SourceContext, source: &str) -> bool {
  let options = roxmltree::ParsingOptions {
    allow_dtd: true,
    ..roxmltree::ParsingOptions::default()
  };

  let Ok(doc) = roxmltree::Document::parse_with_options(source, options) else {
    return false;
  };

  let mut ctx = XmlContext {
    source,
    source_context: context,
  };

  // The root element is <plist>; process its children as values.
  for child in doc.root_element().children().filter(|n| n.is_element()) {
    process_value(&mut ctx, &child);
  }

  true
}

fn process_value(ctx: &mut XmlContext, node: &roxmltree::Node) {
  match node.tag_name().name() {
    "dict" => process_dict(ctx, node),
    "array" => process_array(ctx, node),
    "string" => {
      if let Some(text) = trimmed_text(node) {
        let text = text.to_owned();
        if let Some(d) =
          check_value(&normalize_value(&text), ctx.source_context, || {
            compute_span(ctx, node.range())
          })
        {
          ctx.source_context.emit_diagnostic(d);
        }
      }
    }
    _ => {}
  }
}

fn process_dict(ctx: &mut XmlContext, node: &roxmltree::Node) {
  let mut children = node.children().filter(|n| n.is_element());

  while let Some(key_node) = children.next() {
    if key_node.tag_name().name() != "key" {
      continue;
    }

    let Some(value_node) = children.next() else {
      break;
    };

    let key_text = key_node.text().unwrap_or_default();

    match value_node.tag_name().name() {
      "string" => {
        if let Some(value_text) = trimmed_text(&value_node) {
          let key = key_text.to_owned();
          let value = value_text.to_owned();
          if let Some(d) = check_assignment(
            &normalize_name(&key),
            &normalize_value(&value),
            AssignmentType::Element,
            ctx.source_context,
            || compute_span(ctx, value_node.range()),
          ) {
            ctx.source_context.emit_diagnostic(d);
          }
        }
      }
      "dict" => process_dict(ctx, &value_node),
      "array" => process_array(ctx, &value_node),
      _ => {}
    }
  }
}

fn process_array(ctx: &mut XmlContext, node: &roxmltree::Node) {
  for child in node.children().filter(|n| n.is_element()) {
    process_value(ctx, &child);
  }
}

fn trimmed_text<'a>(node: &'a roxmltree::Node) -> Option<&'a str> {
  let text = node.text()?.trim();
  if text.is_empty() { None } else { Some(text) }
}

fn compute_span(
  ctx: &XmlContext,
  range: std::ops::Range<usize>,
) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, range.start),
      end: offset_to_position(ctx.source, range.end),
    }),
  }
}

// ---------------------------------------------------------------------------
// Binary plist parsing (no source text, file-level spans only)
// ---------------------------------------------------------------------------

struct BinaryContext<'a> {
  source_context: &'a SourceContext<'a>,
}

fn parse_binary(context: &SourceContext, bytes: &[u8]) -> bool {
  let Ok(value) = plist::Value::from_reader(Cursor::new(bytes)) else {
    return false;
  };

  let mut ctx = BinaryContext {
    source_context: context,
  };

  walk_value(&mut ctx, &value);

  true
}

fn walk_value(ctx: &mut BinaryContext, value: &plist::Value) {
  match value {
    plist::Value::Dictionary(dict) => {
      for (key, val) in dict.iter() {
        if let plist::Value::String(s) = val {
          let key = key.to_owned();
          if let Some(d) = check_assignment(
            &normalize_name(&key),
            &normalize_value(s),
            AssignmentType::Element,
            ctx.source_context,
            || make_binary_span(ctx),
          ) {
            ctx.source_context.emit_diagnostic(d);
          }
        } else {
          walk_value(ctx, val);
        }
      }
    }
    plist::Value::Array(array) => {
      for val in array {
        walk_value(ctx, val);
      }
    }
    plist::Value::String(s) => {
      if let Some(d) =
        check_value(&normalize_value(s), ctx.source_context, || {
          make_binary_span(ctx)
        })
      {
        ctx.source_context.emit_diagnostic(d);
      }
    }
    _ => {}
  }
}

fn make_binary_span(ctx: &BinaryContext) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: None,
  }
}
