use yaml_rust2::{Yaml, YamlLoader};

use super::Value;

pub fn parse_yaml(content: &str) -> Option<Value> {
  let docs = YamlLoader::load_from_str(content).ok()?;
  let first_doc = docs.into_iter().next()?;
  Some(convert(first_doc))
}

fn convert(yaml: Yaml) -> Value {
  match yaml {
    Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => Value::Null,
    Yaml::Boolean(b) => Value::Bool(b),
    Yaml::Integer(i) => Value::Number(i as f64),
    Yaml::Real(s) => s.parse::<f64>().map_or(Value::Null, Value::Number),
    Yaml::String(s) => Value::String(s),
    Yaml::Array(arr) => Value::Array(arr.into_iter().map(convert).collect()),
    Yaml::Hash(hash) => {
      let pairs = hash
        .into_iter()
        .filter_map(|(k, v)| match k {
          Yaml::String(key) => Some((key, convert(v))),
          _ => None,
        })
        .collect();
      Value::Object(pairs)
    }
  }
}
