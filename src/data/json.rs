use jsonc_parser::{
  CollectOptions, CommentCollectionStrategy, ParseOptions,
  ast::{Array, Object, Value as JsoncValue},
  parse_to_ast,
};

use super::Value;

const PARSE_OPTIONS: ParseOptions = ParseOptions {
  allow_comments: true,
  allow_trailing_commas: true,
  allow_loose_object_property_names: false,
  allow_missing_commas: false,
  allow_single_quoted_strings: false,
  allow_hexadecimal_numbers: false,
  allow_unary_plus_numbers: false,
};

pub fn parse_json(content: &str) -> Option<Value> {
  let collect_options = CollectOptions {
    comments: CommentCollectionStrategy::Off,
    tokens: false,
  };
  let result = parse_to_ast(content, &collect_options, &PARSE_OPTIONS).ok()?;
  result.value.as_ref().map(convert)
}

fn convert(value: &JsoncValue) -> Value {
  match value {
    JsoncValue::StringLit(s) => Value::String(s.value.to_string()),
    JsoncValue::NumberLit(n) => {
      n.value.parse::<f64>().map_or(Value::Null, Value::Number)
    }
    JsoncValue::BooleanLit(b) => Value::Bool(b.value),
    JsoncValue::NullKeyword(_) => Value::Null,
    JsoncValue::Array(arr) => convert_array(arr),
    JsoncValue::Object(obj) => convert_object(obj),
  }
}

fn convert_array(arr: &Array) -> Value {
  Value::Array(arr.elements.iter().map(convert).collect())
}

fn convert_object(obj: &Object) -> Value {
  let pairs = obj
    .properties
    .iter()
    .map(|prop| (prop.name.as_str().to_owned(), convert(&prop.value)))
    .collect();
  Value::Object(pairs)
}
