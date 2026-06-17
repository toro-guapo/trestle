use std::cell::RefCell;

use tree_sitter::Node;

use crate::languages::javascript;
use crate::languages::sfc::{
  JsRegion, RegionKind, attribute_value_node, check_literal_attribute,
  find_child_of_kind, is_meta_tag, node_text, process_meta_element, region_at,
  scan_region,
};
use crate::processing::SourceContext;

thread_local! {
  static PARSER: RefCell<Option<tree_sitter::Parser>> = RefCell::new({
    let mut parser = tree_sitter::Parser::new();
    if parser
      .set_language(&tree_sitter_vue_next::LANGUAGE.into())
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
  if node.kind() == "raw_text"
    && node.parent().map(|parent| parent.kind()) == Some("script_element")
    && let Some(script) = node_text(node, source)
  {
    for (name, params) in javascript::collect_signatures(script) {
      javascript::declare_signature(name, params);
    }
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
    "raw_text" => match node.parent().map(|parent| parent.kind()) {
      Some("script_element") => regions.push(region_at(
        node.start_byte(),
        node.end_byte(),
        source,
        RegionKind::Statements,
      )),
      Some("interpolation") => regions.push(region_at(
        node.start_byte(),
        node.end_byte(),
        source,
        RegionKind::Expression,
      )),
      _ => {}
    },
    "attribute" => {
      if let (Some(name), Some(value_node)) = (
        find_child_of_kind(node, "attribute_name")
          .and_then(|name_node| node_text(name_node, source)),
        attribute_value_node(node),
      ) {
        check_literal_attribute(context, source, name, value_node);
      }
    }
    "directive_attribute" => handle_directive(node, source, regions),
    _ => {
      let mut cursor = node.walk();
      for child in node.children(&mut cursor) {
        walk(child, context, source, regions);
      }
    }
  }
}

enum DirectiveKind {
  Slot,
  For,
  Handler,
  Expression,
}

fn directive_kind(node: Node, source: &str) -> DirectiveKind {
  if let Some(name) = find_child_of_kind(node, "directive_name")
    .and_then(|name_node| node_text(name_node, source))
  {
    match name {
      "v-for" => DirectiveKind::For,
      "v-slot" => DirectiveKind::Slot,
      "v-on" => DirectiveKind::Handler,
      _ => DirectiveKind::Expression,
    }
  } else if find_child_of_kind(node, "#").is_some() {
    DirectiveKind::Slot
  } else if find_child_of_kind(node, "@").is_some() {
    DirectiveKind::Handler
  } else {
    DirectiveKind::Expression
  }
}

fn handle_directive(node: Node, source: &str, regions: &mut Vec<JsRegion>) {
  let Some(value_node) = attribute_value_node(node) else {
    return;
  };
  let start = value_node.start_byte();
  let end = value_node.end_byte();

  match directive_kind(node, source) {
    DirectiveKind::Slot => {
      regions.push(region_at(start, end, source, RegionKind::Parameters));
    }
    DirectiveKind::For => {
      if let Some(iterable_start) = v_for_iterable_start(source, start, end) {
        regions.push(region_at(
          iterable_start,
          end,
          source,
          RegionKind::Expression,
        ));
      }
    }
    DirectiveKind::Handler => {
      regions.push(region_at(start, end, source, RegionKind::Statements));
    }
    DirectiveKind::Expression => {
      regions.push(region_at(start, end, source, RegionKind::Expression));
    }
  }
}

fn v_for_iterable_start(
  source: &str,
  start: usize,
  end: usize,
) -> Option<usize> {
  let value = source.get(start..end)?;
  for separator in [" in ", " of "] {
    if let Some(position) = value.find(separator) {
      return Some(start + position + separator.len());
    }
  }
  None
}
