use std::cell::RefCell;

use tree_sitter::Node;

use crate::languages::javascript;
use crate::languages::sfc::{
  JsRegion, RegionKind, check_literal_attribute, find_child_of_kind,
  is_meta_tag, node_text, process_meta_element, region_at, scan_region,
};
use crate::processing::SourceContext;

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser
      .set_language(&tree_sitter_svelte_ng::LANGUAGE.into())
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
  walk(tree.root_node(), context, source, None, &mut regions);

  let mut parsed_any = false;
  for region in &regions {
    if scan_region(context, source, region) {
      parsed_any = true;
    }
  }

  parsed_any
}

fn walk(
  node: Node,
  context: &SourceContext,
  source: &str,
  attribute_name: Option<&str>,
  regions: &mut Vec<JsRegion>,
) {
  match node.kind() {
    "start_tag" | "self_closing_tag" if is_meta_tag(node, source) => {
      process_meta_element(context, source, node);
    }
    "svelte_raw_text" => {
      let kind =
        if node.parent().map(|parent| parent.kind()) == Some("snippet_start") {
          RegionKind::Parameters
        } else {
          RegionKind::Expression
        };
      regions.push(region_at(node.start_byte(), node.end_byte(), source, kind));
    }
    "raw_text" => {
      if node.parent().map(|parent| parent.kind()) == Some("script_element") {
        regions.push(region_at(
          node.start_byte(),
          node.end_byte(),
          source,
          RegionKind::Statements,
        ));
      }
    }
    "attribute_value" => {
      if let Some(name) = attribute_name {
        check_literal_attribute(context, source, name, node);
      }
    }
    "attribute" => {
      let name = find_child_of_kind(node, "attribute_name")
        .and_then(|name_node| node_text(name_node, source));
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        walk(child, context, source, name, regions);
      }
    }
    _ => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        walk(child, context, source, attribute_name, regions);
      }
    }
  }
}

fn register_signatures(node: Node, source: &str) {
  match node.kind() {
    "snippet_start" => {
      if let Some(name) = find_child_of_kind(node, "snippet_name")
        .and_then(|n| node_text(n, source))
      {
        let params = find_child_of_kind(node, "svelte_raw_text")
          .and_then(|p| node_text(p, source))
          .unwrap_or("");
        javascript::declare_signature(
          name.to_owned(),
          javascript::parameter_names(params),
        );
      }
    }
    "raw_text" => {
      if node.parent().map(|parent| parent.kind()) == Some("script_element")
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
