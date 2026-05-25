use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_assignment,
    offset_to_position,
  },
  processing::SourceContext,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

struct XmlContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

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

  process_node(&mut ctx, &doc.root_element());

  true
}

fn process_node(ctx: &mut XmlContext, node: &roxmltree::Node) {
  let name_or_key = node.attribute("name").or_else(|| node.attribute("key"));

  // Check individual attributes
  for attr in node.attributes() {
    let key = attr.name().to_owned();
    let value = attr.value().to_owned();
    if let Some(d) = check_assignment(
      &normalize_name(&key),
      &normalize_value(&value),
      AssignmentType::Property,
      ctx.source_context,
      || compute_span(ctx, attr.range_value()),
    ) {
      ctx.source_context.emit_diagnostic(d);
    }
  }

  // Check key-value attribute pairs (name/key + value)
  if let Some(nk) = name_or_key {
    if let Some(v) = node.attribute("value") {
      let value_range = node
        .attributes()
        .find(|a| a.name() == "value")
        .map(|a| a.range_value())
        .unwrap_or_else(|| node.range());

      let key = nk.to_owned();
      let value = v.to_owned();
      if let Some(d) = check_assignment(
        &normalize_name(&key),
        &normalize_value(&value),
        AssignmentType::Property,
        ctx.source_context,
        || compute_span(ctx, value_range.clone()),
      ) {
        ctx.source_context.emit_diagnostic(d);
      }
    }
  }

  // Check text content
  if let Some(raw_text) = node.text() {
    let text = raw_text.trim();
    if !text.is_empty() {
      let text_range = node
        .children()
        .find(|c| c.is_text())
        .map(|c| c.range())
        .unwrap_or_else(|| node.range());

      let effective_name =
        name_or_key.unwrap_or(node.tag_name().name()).to_owned();

      let text = text.to_owned();

      if let Some(d) = check_assignment(
        &normalize_name(&effective_name),
        &normalize_value(&text),
        AssignmentType::Element,
        ctx.source_context,
        || compute_span(ctx, text_range.clone()),
      ) {
        ctx.source_context.emit_diagnostic(d);
      }
    }
  }

  // Recurse into child elements
  for child in node.children().filter(|n| n.is_element()) {
    process_node(ctx, &child);
  }
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
