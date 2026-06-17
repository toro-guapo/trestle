use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use toml_edit::{Array, DocumentMut, ImDocument, Item};

use crate::options::{
  DefaultValue, OPTION_SPECS, OUTPUT_FORMATS, OptionSpec, Options,
  OutputFormat, SKIP_GLOB, output_format_names_csv,
};

pub const FILE_NAME: &str = ".trestlerc.toml";

pub fn is_trestlerc(path: &Path) -> bool {
  path.file_name().and_then(|n| n.to_str()) == Some(FILE_NAME)
}

pub struct OptionsResolver {
  cli_args: Vec<String>,
  cli_anchor: PathBuf,
  layered_cache: Mutex<HashMap<PathBuf, Arc<Options>>>,
  effective_cache: Mutex<HashMap<PathBuf, Arc<Options>>>,
}

impl OptionsResolver {
  pub fn new(cli_args: Vec<String>, cli_anchor: PathBuf) -> Self {
    Self {
      cli_args,
      cli_anchor,
      layered_cache: Mutex::new(HashMap::new()),
      effective_cache: Mutex::new(HashMap::new()),
    }
  }

  pub fn cli_args(&self) -> &[String] {
    &self.cli_args
  }

  pub fn cli_anchor(&self) -> &Path {
    &self.cli_anchor
  }

  pub fn resolve(&self, dir: &Path) -> Arc<Options> {
    if let Some(cached) = self
      .effective_cache
      .lock()
      .ok()
      .and_then(|c| c.get(dir).cloned())
    {
      return cached;
    }

    let layered = self.resolve_layered(dir);
    let mut options = (*layered).clone();
    options.apply_args(&self.cli_args, &self.cli_anchor);

    let result = Arc::new(options);
    if let Ok(mut cache) = self.effective_cache.lock() {
      cache.insert(dir.to_path_buf(), result.clone());
    }
    result
  }

  pub fn resolve_for_path(&self, path: &Path) -> Arc<Options> {
    let dir = if path.is_file() {
      path.parent().unwrap_or(path)
    } else {
      path
    };
    self.resolve(dir)
  }

  pub fn clear(&self) {
    if let Ok(mut cache) = self.layered_cache.lock() {
      cache.clear();
    }
    if let Ok(mut cache) = self.effective_cache.lock() {
      cache.clear();
    }
  }

  pub fn seed(&self, dir: PathBuf, options: Options) {
    if let Ok(mut cache) = self.effective_cache.lock() {
      cache.insert(dir, Arc::new(options));
    }
  }

  fn resolve_layered(&self, dir: &Path) -> Arc<Options> {
    if let Some(cached) = self
      .layered_cache
      .lock()
      .ok()
      .and_then(|c| c.get(dir).cloned())
    {
      return cached;
    }

    let parent_options = match dir.parent() {
      Some(parent) => self.resolve_layered(parent),
      None => Arc::new(Options::default()),
    };

    let mut options = (*parent_options).clone();

    let trestlerc_path = dir.join(FILE_NAME);
    if let Ok(text) = std::fs::read_to_string(&trestlerc_path) {
      options.apply_configuration_source(&text, dir, &trestlerc_path);
    }

    let result = Arc::new(options);
    if let Ok(mut cache) = self.layered_cache.lock() {
      cache.insert(dir.to_path_buf(), result.clone());
    }
    result
  }
}

pub fn add_skip_glob_entry(source: &str, entry: &str) -> Option<String> {
  let mut doc = if source.trim().is_empty() {
    DocumentMut::new()
  } else {
    source.parse::<DocumentMut>().ok()?
  };

  match doc.get_mut(SKIP_GLOB.name) {
    None => {
      let mut arr = Array::new();
      arr.push(entry);
      doc[SKIP_GLOB.name] = toml_edit::value(arr);
    }
    Some(item) => {
      let arr = item.as_array_mut()?;
      if !arr.iter().any(|v| v.as_str() == Some(entry)) {
        arr.push(entry);
      }
    }
  }

  Some(doc.to_string())
}

pub struct ByteSpan {
  pub start: usize,
  pub end: usize,
}

pub struct Issue {
  pub span: ByteSpan,
  pub message: String,
}

pub struct KeyHover {
  pub span: ByteSpan,
  pub markdown: String,
}

pub struct Report {
  pub issues: Vec<Issue>,
  pub hovers: Vec<KeyHover>,
}

pub fn analyze(source: &str) -> Report {
  let mut report = Report {
    issues: Vec::new(),
    hovers: Vec::new(),
  };

  let Ok(doc) = ImDocument::parse(source) else {
    return report;
  };

  let table = doc.as_table();
  let names: Vec<String> =
    table.iter().map(|(name, _)| name.to_owned()).collect();

  for name in names {
    let Some((key, item)) = table.get_key_value(&name) else {
      continue;
    };
    let Some(key_range) = key.span() else {
      continue;
    };
    let key_span = ByteSpan {
      start: key_range.start,
      end: key_range.end,
    };

    match OPTION_SPECS.iter().find(|s| s.name == name) {
      None => {
        report.issues.push(Issue {
          span: key_span,
          message: format!("Unknown option `{name}`."),
        });
      }
      Some(spec) => {
        if let Some(message) = check_value(spec, item) {
          let value_span = item
            .span()
            .map(|r| ByteSpan {
              start: r.start,
              end: r.end,
            })
            .unwrap_or(ByteSpan {
              start: key_span.start,
              end: key_span.end,
            });
          report.issues.push(Issue {
            span: value_span,
            message,
          });
        }
        report.hovers.push(KeyHover {
          span: key_span,
          markdown: spec_markdown(spec),
        });
      }
    }
  }

  report
}

fn check_value(spec: &OptionSpec, item: &Item) -> Option<String> {
  match spec.default_value {
    DefaultValue::Bool(_) | DefaultValue::AutoBool(_) => {
      if item.as_bool().is_none() {
        Some(format!("Option `{}` expects a boolean.", spec.name))
      } else {
        None
      }
    }
    DefaultValue::String(_) => match item.as_str() {
      None => Some(format!("Option `{}` expects a string.", spec.name)),
      Some(value) => {
        if spec.name == "output-format" && OutputFormat::parse(value).is_none()
        {
          Some(format!(
            "Option `{}` must be one of: {}.",
            spec.name,
            output_format_names_csv()
          ))
        } else {
          None
        }
      }
    },
    DefaultValue::StringList(_) => match item.as_array() {
      None => Some(format!(
        "Option `{}` expects an array of strings.",
        spec.name
      )),
      Some(arr) => {
        if arr.iter().any(|v| v.as_str().is_none()) {
          Some(format!(
            "Option `{}` expects an array of strings.",
            spec.name
          ))
        } else {
          None
        }
      }
    },
    #[cfg(feature = "git-history")]
    DefaultValue::Enum { values, .. } => {
      if item.as_bool().is_some() {
        None
      } else if let Some(value) = item.as_str() {
        if values.contains(&value) {
          None
        } else {
          Some(format!(
            "Option `{}` must be one of: {}.",
            spec.name,
            values.join(", ")
          ))
        }
      } else {
        Some(format!(
          "Option `{}` expects a string or boolean.",
          spec.name
        ))
      }
    }
  }
}

pub enum CompletionKind {
  Option,
  Value,
}

pub struct Completion {
  pub label: String,
  pub kind: CompletionKind,
  pub detail: String,
  pub documentation: String,
}

pub fn complete(source: &str, byte_offset: usize) -> Vec<Completion> {
  let prefix = source.get(..byte_offset).unwrap_or("");
  let line_start = prefix.rfind('\n').map(|i| i + 1).unwrap_or(0);
  let line_prefix = prefix.get(line_start..).unwrap_or("");

  match line_prefix.split_once('=') {
    Some((key_part, _)) => {
      let key = key_part.trim();
      OPTION_SPECS
        .iter()
        .find(|s| s.name == key)
        .map(value_completions)
        .unwrap_or_default()
    }
    None => OPTION_SPECS.iter().map(option_completion).collect(),
  }
}

fn option_completion(spec: &OptionSpec) -> Completion {
  Completion {
    label: spec.name.to_owned(),
    kind: CompletionKind::Option,
    detail: type_label(&spec.default_value).to_owned(),
    documentation: spec_markdown(spec),
  }
}

fn value_completions(spec: &OptionSpec) -> Vec<Completion> {
  match &spec.default_value {
    DefaultValue::Bool(_) | DefaultValue::AutoBool(_) => ["true", "false"]
      .iter()
      .map(|v| Completion {
        label: (*v).to_owned(),
        kind: CompletionKind::Value,
        detail: "boolean".to_owned(),
        documentation: String::new(),
      })
      .collect(),
    DefaultValue::String(_) if spec.name == "output-format" => OUTPUT_FORMATS
      .iter()
      .map(|f| Completion {
        label: format!("\"{}\"", f.name),
        kind: CompletionKind::Value,
        detail: "string".to_owned(),
        documentation: String::new(),
      })
      .collect(),
    #[cfg(feature = "git-history")]
    DefaultValue::Enum { values, .. } => values
      .iter()
      .map(|v| Completion {
        label: format!("\"{v}\""),
        kind: CompletionKind::Value,
        detail: "string".to_owned(),
        documentation: String::new(),
      })
      .collect(),
    _ => Vec::new(),
  }
}

fn type_label(default: &DefaultValue) -> &'static str {
  match default {
    DefaultValue::Bool(_) | DefaultValue::AutoBool(_) => "boolean",
    DefaultValue::String(_) => "string",
    DefaultValue::StringList(_) => "array of strings",
    #[cfg(feature = "git-history")]
    DefaultValue::Enum { .. } => "string",
  }
}

fn spec_markdown(spec: &OptionSpec) -> String {
  let type_label = type_label(&spec.default_value);

  let default = match &spec.default_value {
    DefaultValue::Bool(v) => v.to_string(),
    DefaultValue::AutoBool(v) => v.to_string(),
    DefaultValue::String(s) => format!("\"{s}\""),
    DefaultValue::StringList(list) => {
      let items: Vec<String> =
        list.iter().map(|s| format!("\"{s}\"")).collect();
      format!("[{}]", items.join(", "))
    }
    #[cfg(feature = "git-history")]
    DefaultValue::Enum { default, .. } => format!("\"{default}\""),
  };

  format!(
    "**`{name}`** · _{type_label}_\n\n{description}\n\n**Default:** `{default}`",
    name = spec.name,
    description = spec.description,
  )
}
