use jsonc_parser::{
  CollectOptions, ParseOptions,
  ast::{Array, Object, Value},
  parse_to_ast,
};

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, SourceSpan, check_assignment, check_value,
    offset_to_position,
  },
  processing::SourceContext,
  schemas::SchemaValue,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

pub type SchemaHandler<'a> = &'a dyn Fn(&SchemaValue) -> bool;

pub struct JsonOptions<'a> {
  pub on_value: Option<SchemaHandler<'a>>,
}

struct JsonContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  on_value: Option<SchemaHandler<'a>>,
}

pub const PARSE_OPTIONS: ParseOptions = ParseOptions {
  allow_comments: true,
  allow_trailing_commas: true,
  allow_loose_object_property_names: false,
  allow_missing_commas: false,
  allow_single_quoted_strings: false,
  allow_hexadecimal_numbers: false,
  allow_unary_plus_numbers: false,
};

pub fn parse(context: &SourceContext) -> bool {
  parse_with_options(context, &JsonOptions { on_value: None })
}

pub fn parse_with_options(
  context: &SourceContext,
  options: &JsonOptions,
) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let collect_options = CollectOptions {
    comments: jsonc_parser::CommentCollectionStrategy::Off,
    tokens: false,
  };

  let Ok(result) = parse_to_ast(source, &collect_options, &PARSE_OPTIONS)
  else {
    return false;
  };

  let Some(value) = &result.value else {
    return false;
  };

  let mut json_context = JsonContext {
    source,
    source_context: context,
    on_value: options.on_value,
  };

  process_value(&mut json_context, &[], value);

  true
}

fn process_value(context: &mut JsonContext, path: &[&str], value: &Value) {
  match value {
    Value::Object(object) => process_object(context, path, object),
    Value::Array(array) => process_array(context, path, array),
    Value::StringLit(lit) => {
      let value = lit.value.to_string();
      if let Some(d) =
        check_value(&normalize_value(&value), context.source_context, || {
          compute_source_span(context, lit.range.start, lit.range.end)
        })
      {
        context.source_context.emit_diagnostic(d);
      }
    }
    _ => {}
  }
}

fn process_object(context: &mut JsonContext, path: &[&str], object: &Object) {
  for prop in &object.properties {
    let key = prop.name.as_str();

    if let Value::StringLit(lit) = &prop.value {
      let value = lit.value.to_string();

      let handled = if let Some(handler) = context.on_value {
        let value_pos = offset_to_position(context.source, lit.range.start);

        let parent_line =
          context.source_context.parent_line + value_pos.line.saturating_sub(1);

        let parent_col = context.source_context.parent_col
          + value_pos.column.saturating_sub(1);

        let info = SchemaValue {
          run: context.source_context.run,
          file_abs_path: context.source_context.file_abs_path,
          path,
          key,
          value: &value,
          parent_line,
          parent_col,
        };

        handler(&info)
      } else {
        false
      };

      if !handled {
        let key = key.to_owned();
        if let Some(d) = check_assignment(
          &normalize_name(&key),
          &normalize_value(&value),
          AssignmentType::Element,
          context.source_context,
          || compute_source_span(context, lit.range.start, lit.range.end),
        ) {
          context.source_context.emit_diagnostic(d);
        }
      }
    } else {
      let mut child_path = path.to_vec();
      child_path.push(key);
      process_value(context, &child_path, &prop.value);
    }
  }
}

fn process_array(context: &mut JsonContext, path: &[&str], array: &Array) {
  for element in &array.elements {
    process_value(context, path, element);
  }
}

fn compute_source_span(
  context: &JsonContext,
  start: usize,
  end: usize,
) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: context.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(context.source, start),
      end: offset_to_position(context.source, end),
    }),
  }
}
