use std::cell::OnceCell;

use oxc_span::SourceType;
use tree_sitter::Node;

use crate::diagnostic::{
  AssignmentType, check_assignment, check_header_assignment, check_value,
  compute_file_span,
};
use crate::languages::javascript;
use crate::processing::SourceContext;
use crate::secrets::names::normalize::normalize_name;
use crate::secrets::values::normalize::normalize_value;

pub enum RegionKind {
  Statements,
  Expression,
  Parameters,
}

pub struct JsRegion {
  pub start: usize,
  pub end: usize,
  pub parent_line: usize,
  pub parent_col: usize,
  pub kind: RegionKind,
}

pub fn region_at(
  start: usize,
  end: usize,
  source: &str,
  kind: RegionKind,
) -> JsRegion {
  let column = char_column(source, start);
  let parent_col = match kind {
    RegionKind::Parameters => column.saturating_sub(1),
    _ => column,
  };
  JsRegion {
    start,
    end,
    parent_line: line_at(source, start),
    parent_col,
    kind,
  }
}

pub fn scan_region(
  context: &SourceContext,
  source: &str,
  region: &JsRegion,
) -> bool {
  let Some(snippet) = source.get(region.start..region.end) else {
    return false;
  };
  if snippet.trim().is_empty() {
    return false;
  }

  match region.kind {
    RegionKind::Statements => {
      let js_context = child_context(context, snippet, region);
      javascript::parse_with_source_type(&js_context, Some(SourceType::ts()))
    }
    RegionKind::Expression => {
      let js_context = child_context(context, snippet, region);
      javascript::scan_client_expression(&js_context)
    }
    RegionKind::Parameters => {
      let wrapped = format!("({snippet}) => 0");
      let js_context = child_context(context, &wrapped, region);
      javascript::scan_expression(&js_context)
    }
  }
}

fn child_context<'a>(
  context: &'a SourceContext,
  body: &'a str,
  region: &JsRegion,
) -> SourceContext<'a> {
  SourceContext {
    run: context.run,
    file_abs_path: context.file_abs_path,
    file_extension: context.file_extension,
    body: Some(body),
    file_type: context.file_type,
    #[cfg(feature = "services")]
    file_services: context.file_services.clone(),
    parent_line: region.parent_line,
    parent_col: region.parent_col,
    directives: OnceCell::new(),
  }
}

pub fn check_literal_attribute(
  context: &SourceContext,
  source: &str,
  name: &str,
  value_node: Node,
) {
  let Some(value) = node_text(value_node, source) else {
    return;
  };
  if value.is_empty() {
    return;
  }

  let start = value_node.start_byte();
  let end = value_node.end_byte();

  if let Some(diagnostic) = check_assignment(
    &normalize_name(&name.to_owned()),
    &normalize_value(&value.to_owned()),
    AssignmentType::Attribute,
    context,
    || compute_file_span(context, source, start, end),
  ) {
    context.emit_diagnostic(diagnostic);
  }
}

pub fn is_meta_tag(tag: Node, source: &str) -> bool {
  find_child_of_kind(tag, "tag_name")
    .and_then(|name_node| node_text(name_node, source))
    .is_some_and(|name| name.eq_ignore_ascii_case("meta"))
}

pub fn process_meta_element(context: &SourceContext, source: &str, tag: Node) {
  let mut name: Option<&str> = None;
  let mut http_equiv: Option<&str> = None;
  let mut content: Option<Node> = None;

  let mut cursor = tag.walk();
  for attr in tag
    .children(&mut cursor)
    .filter(|c| c.kind() == "attribute")
  {
    let Some(attr_name) = attribute_name_text(attr, source) else {
      continue;
    };
    let Some(value_node) = attribute_value_node(attr) else {
      continue;
    };

    if attr_name.eq_ignore_ascii_case("content") {
      content = Some(value_node);
    } else if attr_name.eq_ignore_ascii_case("http-equiv") {
      http_equiv = node_text(value_node, source);
    } else if attr_name.eq_ignore_ascii_case("name")
      || attr_name.eq_ignore_ascii_case("property")
    {
      name = node_text(value_node, source);
    } else if !attr_name.eq_ignore_ascii_case("charset") {
      check_literal_attribute(context, source, attr_name, value_node);
    }
  }

  let Some(content) = content else {
    return;
  };

  if let Some(header) = http_equiv {
    check_header_attribute(context, source, header, content);
  } else if let Some(name) = name {
    check_literal_attribute(context, source, name, content);
  } else {
    check_value_attribute(context, source, content);
  }
}

pub fn attribute_name_text<'a>(attr: Node, source: &'a str) -> Option<&'a str> {
  find_child_of_kind(attr, "attribute_name").and_then(|n| node_text(n, source))
}

fn check_header_attribute(
  context: &SourceContext,
  source: &str,
  name: &str,
  value_node: Node,
) {
  let Some(value) = node_text(value_node, source) else {
    return;
  };
  if value.is_empty() {
    return;
  }

  let start = value_node.start_byte();
  let end = value_node.end_byte();

  if let Some(diagnostic) =
    check_header_assignment(name, value, context, || {
      compute_file_span(context, source, start, end)
    })
  {
    context.emit_diagnostic(diagnostic);
  }
}

fn check_value_attribute(
  context: &SourceContext,
  source: &str,
  value_node: Node,
) {
  let Some(value) = node_text(value_node, source) else {
    return;
  };
  if value.is_empty() {
    return;
  }

  let start = value_node.start_byte();
  let end = value_node.end_byte();

  if let Some(diagnostic) =
    check_value(&normalize_value(&value.to_owned()), context, || {
      compute_file_span(context, source, start, end)
    })
  {
    context.emit_diagnostic(diagnostic);
  }
}

#[cfg(any(feature = "lang-html", feature = "lang-astro"))]
pub fn script_is_javascript(script_element: Node, source: &str) -> bool {
  let Some(start_tag) = find_child_of_kind(script_element, "start_tag") else {
    return true;
  };

  let mut cursor = start_tag.walk();
  for attr in start_tag.children(&mut cursor) {
    if attr.kind() != "attribute" {
      continue;
    }
    if !attribute_name_text(attr, source)
      .is_some_and(|n| n.eq_ignore_ascii_case("type"))
    {
      continue;
    }
    return match attribute_value_node(attr).and_then(|v| node_text(v, source)) {
      Some(value) => is_javascript_type(value),
      None => true,
    };
  }

  true
}

#[cfg(any(feature = "lang-html", feature = "lang-astro"))]
fn is_javascript_type(value: &str) -> bool {
  let base = value
    .split(';')
    .next()
    .unwrap_or(value)
    .trim()
    .to_ascii_lowercase();

  !matches!(
    base.as_str(),
    "application/json"
      | "application/ld+json"
      | "importmap"
      | "speculationrules"
      | "text/html"
      | "text/template"
      | "text/x-template"
      | "text/x-handlebars-template"
      | "text/x-mustache"
      | "text/markdown"
  )
}

pub fn find_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  node
    .children(&mut cursor)
    .find(|child| child.kind() == kind)
}

pub fn attribute_value_node<'a>(node: Node<'a>) -> Option<Node<'a>> {
  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    match child.kind() {
      "attribute_value" => return Some(child),
      "quoted_attribute_value" => {
        return find_child_of_kind(child, "attribute_value");
      }
      _ => {}
    }
  }
  None
}

pub fn node_text<'a>(node: Node, source: &'a str) -> Option<&'a str> {
  source.get(node.start_byte()..node.end_byte())
}

fn char_column(source: &str, offset: usize) -> usize {
  let prefix = source.get(..offset).unwrap_or("");
  match prefix.rfind('\n') {
    Some(newline) => prefix
      .get(newline + 1..)
      .map_or(0, |rest| rest.chars().count()),
    None => prefix.chars().count(),
  }
}

fn line_at(source: &str, offset: usize) -> usize {
  source
    .get(..offset)
    .map_or(0, |prefix| prefix.bytes().filter(|&b| b == b'\n').count())
}
