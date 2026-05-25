use toml_edit::{DocumentMut, Item, Value as TomlValue};

use super::Value;

pub fn parse_toml(content: &str) -> Option<Value> {
  let doc = content.parse::<DocumentMut>().ok()?;
  Some(convert_table(doc.as_table()))
}

fn convert_item(item: &Item) -> Value {
  match item {
    Item::None => Value::Null,
    Item::Value(value) => convert_value(value),
    Item::Table(table) => convert_table(table),
    Item::ArrayOfTables(aot) => {
      Value::Array(aot.iter().map(convert_table).collect())
    }
  }
}

fn convert_table(table: &toml_edit::Table) -> Value {
  let pairs = table
    .iter()
    .map(|(k, v)| (k.to_owned(), convert_item(v)))
    .collect();
  Value::Object(pairs)
}

fn convert_inline_table(table: &toml_edit::InlineTable) -> Value {
  let pairs = table
    .iter()
    .map(|(k, v)| (k.to_owned(), convert_value(v)))
    .collect();
  Value::Object(pairs)
}

fn convert_value(value: &TomlValue) -> Value {
  match value {
    TomlValue::String(s) => Value::String(s.value().to_owned()),
    TomlValue::Integer(i) => Value::Number(*i.value() as f64),
    TomlValue::Float(f) => Value::Number(*f.value()),
    TomlValue::Boolean(b) => Value::Bool(*b.value()),
    TomlValue::Datetime(dt) => Value::String(dt.to_string()),
    TomlValue::Array(arr) => {
      Value::Array(arr.iter().map(convert_value).collect())
    }
    TomlValue::InlineTable(table) => convert_inline_table(table),
  }
}
