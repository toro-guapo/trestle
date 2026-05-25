mod json;
mod shell;
mod toml;
mod yaml;

pub use json::parse_json;
pub use shell::{Invocation, find_invocations, has_invocation, parse_shell};
pub use toml::parse_toml;
pub use yaml::parse_yaml;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
  Null,
  Bool(bool),
  Number(f64),
  String(String),
  Array(Vec<Value>),
  Object(Vec<(String, Value)>),
}

impl Value {
  pub fn as_str(&self) -> Option<&str> {
    match self {
      Value::String(s) => Some(s.as_str()),
      _ => None,
    }
  }

  pub fn as_bool(&self) -> Option<bool> {
    match self {
      Value::Bool(b) => Some(*b),
      _ => None,
    }
  }

  pub fn as_number(&self) -> Option<f64> {
    match self {
      Value::Number(n) => Some(*n),
      _ => None,
    }
  }

  pub fn as_array(&self) -> Option<&[Value]> {
    match self {
      Value::Array(items) => Some(items),
      _ => None,
    }
  }

  pub fn as_object(&self) -> Option<&[(String, Value)]> {
    match self {
      Value::Object(pairs) => Some(pairs),
      _ => None,
    }
  }

  pub fn is_null(&self) -> bool {
    matches!(self, Value::Null)
  }
}

#[derive(Debug, Clone, Copy)]
pub enum PathPart<'a> {
  Key(&'a str),
  Any,
}

pub fn find_all<'a>(root: &'a Value, path: &[PathPart]) -> Vec<&'a Value> {
  let mut current: Vec<&'a Value> = vec![root];

  for part in path {
    let mut next: Vec<&'a Value> = Vec::new();
    for value in current {
      match (part, value) {
        (PathPart::Key(k), Value::Object(pairs)) => {
          for (pk, pv) in pairs {
            if pk == k {
              next.push(pv);
            }
          }
        }
        (PathPart::Any, Value::Object(pairs)) => {
          for (_, pv) in pairs {
            next.push(pv);
          }
        }
        (PathPart::Any, Value::Array(items)) => {
          for item in items {
            next.push(item);
          }
        }
        _ => {}
      }
    }
    current = next;
    if current.is_empty() {
      return Vec::new();
    }
  }

  current
}

pub fn find_first<'a>(root: &'a Value, path: &[PathPart]) -> Option<&'a Value> {
  find_all(root, path).into_iter().next()
}
