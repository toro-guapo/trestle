use std::cell::RefCell;

use tree_sitter::Node;

use crate::languages::javascript;
use crate::languages::sfc::{
  JsRegion, RegionKind, attribute_name_text, attribute_value_node,
  check_literal_attribute, find_child_of_kind, is_meta_tag, node_text,
  process_meta_element, region_at, scan_region, script_is_javascript,
};
use crate::processing::SourceContext;

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser
      .set_language(&tree_sitter_astro_next::LANGUAGE.into())
      .is_err()
    {
      None
    } else {
      Some(parser)
    }
  });
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let Some(tree) = PARSER.with(|p| {
    let mut borrow = p.borrow_mut();
    let parser = borrow.as_mut()?;
    parser.parse(source, None)
  }) else {
    return false;
  };

  javascript::reset_analyzer();
  register_signatures(tree.root_node(), source);

  let mut regions = Vec::new();
  walk(tree.root_node(), context, source, &mut regions);

  let mut parsed_any = false;
  for region in &regions {
    if scan_region(context, source, region) {
      parsed_any = true;
    }
  }

  parsed_any
}

fn register_signatures(node: Node, source: &str) {
  match node.kind() {
    "frontmatter_js_block" => {
      if let Some(code) = node_text(node, source) {
        for (name, params) in javascript::collect_signatures(code) {
          javascript::declare_signature(name, params);
        }
      }
    }
    "raw_text" => {
      if let Some(parent) = node.parent()
        && parent.kind() == "script_element"
        && script_is_javascript(parent, source)
        && let Some(script) = node_text(node, source)
      {
        for (name, params) in javascript::collect_signatures(script) {
          javascript::declare_signature(name, params);
        }
      }
    }
    _ => {}
  }

  let mut cursor = node.walk();
  for child in node.children(&mut cursor) {
    register_signatures(child, source);
  }
}

fn walk(
  node: Node,
  context: &SourceContext,
  source: &str,
  regions: &mut Vec<JsRegion>,
) {
  match node.kind() {
    "start_tag" | "self_closing_tag" if is_meta_tag(node, source) => {
      process_meta_element(context, source, node);
    }
    "frontmatter_js_block" => {
      regions.push(region_at(
        node.start_byte(),
        node.end_byte(),
        source,
        RegionKind::Statements,
      ));
    }
    "raw_text" => {
      if let Some(parent) = node.parent()
        && parent.kind() == "script_element"
        && script_is_javascript(parent, source)
      {
        regions.push(region_at(
          node.start_byte(),
          node.end_byte(),
          source,
          RegionKind::Statements,
        ));
      }
    }
    "html_interpolation" => {
      regions.push(region_at(
        node.start_byte() + 1,
        node.end_byte().saturating_sub(1),
        source,
        RegionKind::Expression,
      ));

      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        walk(child, context, source, regions);
      }
    }
    "attribute" => process_attribute(node, context, source, regions),
    _ => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        walk(child, context, source, regions);
      }
    }
  }
}

fn process_attribute(
  attr: Node,
  context: &SourceContext,
  source: &str,
  regions: &mut Vec<JsRegion>,
) {
  let name = attribute_name_text(attr, source);

  if let (Some(name), Some(value_node)) = (name, attribute_value_node(attr)) {
    check_literal_attribute(context, source, name, value_node);
  }

  if let Some(interpolation) =
    find_child_of_kind(attr, "attribute_interpolation")
    && let Some(expr) = find_child_of_kind(interpolation, "attribute_js_expr")
  {
    regions.push(region_at(
      expr.start_byte(),
      expr.end_byte(),
      source,
      RegionKind::Expression,
    ));
  }

  if let Some(backtick) = find_child_of_kind(attr, "attribute_backtick_string")
  {
    regions.push(region_at(
      backtick.start_byte(),
      backtick.end_byte(),
      source,
      RegionKind::Expression,
    ));
  }
}
