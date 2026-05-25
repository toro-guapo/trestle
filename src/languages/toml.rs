use toml_edit::{ImDocument, Item, Value};

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

struct TomlContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let Ok(doc) = source.parse::<ImDocument<String>>() else {
    return false;
  };

  let mut ctx = TomlContext {
    source,
    source_context: context,
  };

  process_table(&mut ctx, doc.as_table());

  true
}

fn process_table(ctx: &mut TomlContext, table: &toml_edit::Table) {
  for (key, item) in table.iter() {
    match item {
      Item::Value(value) => {
        process_value_with_key(ctx, key, value);
      }
      Item::Table(sub) => process_table(ctx, sub),
      Item::ArrayOfTables(aot) => {
        for sub in aot.iter() {
          process_table(ctx, sub);
        }
      }
      Item::None => {}
    }
  }
}

fn process_value_with_key(ctx: &mut TomlContext, key: &str, value: &Value) {
  match value {
    Value::String(s) => {
      let s = s.value();
      if !s.is_empty() {
        let span = value.span();
        let key = key.to_owned();
        let value = s.to_owned();
        if let Some(d) = check_assignment(
          &normalize_name(&key),
          &normalize_value(&value),
          AssignmentType::Element,
          ctx.source_context,
          || compute_span(ctx, span.clone()),
        ) {
          ctx.source_context.emit_diagnostic(d);
        }
      }
    }
    Value::InlineTable(inline) => {
      for (k, v) in inline.iter() {
        process_value_with_key(ctx, k, v);
      }
    }
    Value::Array(array) => {
      for v in array.iter() {
        process_standalone_value(ctx, v);
      }
    }
    _ => {}
  }
}

fn process_standalone_value(ctx: &mut TomlContext, value: &Value) {
  match value {
    Value::String(s) => {
      let s = s.value();
      if !s.is_empty() {
        let span = value.span();
        let val = s.to_owned();
        if let Some(d) =
          check_value(&normalize_value(&val), ctx.source_context, || {
            compute_span(ctx, span.clone())
          })
        {
          ctx.source_context.emit_diagnostic(d);
        }
      }
    }
    Value::InlineTable(inline) => {
      for (k, v) in inline.iter() {
        process_value_with_key(ctx, k, v);
      }
    }
    Value::Array(array) => {
      for v in array.iter() {
        process_standalone_value(ctx, v);
      }
    }
    _ => {}
  }
}

fn compute_span(
  ctx: &TomlContext,
  range: Option<std::ops::Range<usize>>,
) -> SourceFileSpan {
  match range {
    Some(range) => SourceFileSpan {
      file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
      file_span: Some(SourceSpan {
        start: offset_to_position(ctx.source, range.start),
        end: offset_to_position(ctx.source, range.end),
      }),
    },
    None => SourceFileSpan {
      file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
      file_span: None,
    },
  }
}
