use toml_edit::{ImDocument, Item, Value};

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_assignment_in_scope,
    check_value, offset_to_position,
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

  process_table(&mut ctx, &[], doc.as_table());

  true
}

fn process_table(
  ctx: &mut TomlContext,
  scope: &[&str],
  table: &toml_edit::Table,
) {
  for (key, item) in table.iter() {
    match item {
      Item::Value(value) => {
        process_value_with_key(ctx, scope, key, value);
      }
      Item::Table(sub) => {
        let mut child = scope.to_vec();
        child.push(key);
        process_table(ctx, &child, sub);
      }

      // An array of tables ([[x]]) is keyed like a YAML sequence: the key `x`
      // scopes the fields inside, while the repeated elements are anonymous.
      Item::ArrayOfTables(aot) => {
        let mut child = scope.to_vec();
        child.push(key);
        for sub in aot.iter() {
          process_table(ctx, &child, sub);
        }
      }
      Item::None => {}
    }
  }
}

fn process_value_with_key(
  ctx: &mut TomlContext,
  scope: &[&str],
  key: &str,
  value: &Value,
) {
  match value {
    Value::String(s) => {
      let s = s.value();
      if !s.is_empty() {
        let span = value.span();
        let key = key.to_owned();
        let value = s.to_owned();
        if let Some(d) = check_assignment_in_scope(
          scope,
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
      let mut child = scope.to_vec();
      child.push(key);
      for (k, v) in inline.iter() {
        process_value_with_key(ctx, &child, k, v);
      }
    }
    Value::Array(array) => {
      let mut child = scope.to_vec();
      child.push(key);
      for v in array.iter() {
        process_standalone_value(ctx, &child, v);
      }
    }
    _ => {}
  }
}

fn process_standalone_value(
  ctx: &mut TomlContext,
  scope: &[&str],
  value: &Value,
) {
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
        process_value_with_key(ctx, scope, k, v);
      }
    }
    Value::Array(array) => {
      for v in array.iter() {
        process_standalone_value(ctx, scope, v);
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
