use jsonc_parser::ast::{Array, Object, Value};

use crate::languages::FileType;
use crate::processing::SourceContext;

pub fn parse(context: &SourceContext) -> Option<FileType> {
  let source = context.body?;
  let notebook_path = context.file_abs_path;

  let collect_options = jsonc_parser::CollectOptions {
    comments: jsonc_parser::CommentCollectionStrategy::Off,
    tokens: false,
  };

  let result = jsonc_parser::parse_to_ast(
    source,
    &collect_options,
    &crate::languages::json::PARSE_OPTIONS,
  )
  .ok()?;

  let root_obj = match result.value.as_ref()? {
    Value::Object(o) => o,
    _ => return None,
  };

  let language = detect_language(root_obj);
  let cells = get_array(root_obj, "cells")?;

  let mut any_parsed = false;

  for cell in &cells.elements {
    let Value::Object(cell_obj) = cell else {
      continue;
    };

    if get_string(cell_obj, "cell_type") != Some("code") {
      continue;
    }

    let Some(cell_source) = extract_source(cell_obj) else {
      continue;
    };
    if cell_source.trim().is_empty() {
      continue;
    }

    let cell_context = SourceContext {
      run: context.run,
      file_abs_path: notebook_path,
      file_extension: Some(language_extension(&language)),
      body: Some(&cell_source),
      file_type: Some(language_file_type(&language)),
      parent_line: 0,
      parent_col: 0,
      #[cfg(feature = "services")]
      file_services: vec![],
      directives: std::cell::OnceCell::new(),
    };

    if parse_cell(&cell_context, &language) {
      any_parsed = true;
    }
  }

  if any_parsed {
    Some(FileType::Jupyter)
  } else {
    None
  }
}

// -----------------------------------------------------------------------------
// Language dispatch
// -----------------------------------------------------------------------------

fn parse_cell(context: &SourceContext, language: &str) -> bool {
  match language {
    #[cfg(feature = "lang-python")]
    "python" | "python3" => crate::languages::python::parse(context),
    #[cfg(feature = "lang-javascript")]
    "javascript" | "node" | "typescript" => {
      crate::languages::javascript::parse(context)
    }
    #[cfg(feature = "lang-ruby")]
    "ruby" => crate::languages::ruby::parse(context),
    #[cfg(feature = "lang-go")]
    "go" | "golang" => crate::languages::go::parse(context),
    #[cfg(feature = "lang-php")]
    "php" => crate::languages::php::parse(context),
    #[cfg(feature = "lang-shell")]
    "shell" | "bash" => crate::languages::shell::parse(context),
    _ => {
      #[cfg(feature = "lang-python")]
      return crate::languages::python::parse(context);
      #[allow(unreachable_code)]
      false
    }
  }
}

fn language_extension(language: &str) -> &str {
  match language {
    "python" | "python3" => "py",
    "r" => "r",
    "julia" => "jl",
    "javascript" | "node" => "js",
    "typescript" => "ts",
    "ruby" => "rb",
    "go" | "golang" => "go",
    "shell" | "bash" => "sh",
    "php" => "php",
    _ => "py",
  }
}

fn language_file_type(language: &str) -> FileType {
  match language {
    "javascript" | "node" => FileType::JavaScript,
    "typescript" => FileType::TypeScript,
    "ruby" => FileType::Ruby,
    "go" | "golang" => FileType::Go,
    "shell" | "bash" => FileType::Shell,
    "php" => FileType::Php,
    _ => FileType::Python,
  }
}

// -----------------------------------------------------------------------------
// Notebook JSON helpers
// -----------------------------------------------------------------------------

fn detect_language(root: &Object) -> String {
  get_object(root, "metadata")
    .and_then(|m| get_object(m, "kernelspec"))
    .and_then(|k| get_string(k, "language"))
    .unwrap_or("python")
    .to_ascii_lowercase()
}

fn extract_source(cell: &Object) -> Option<String> {
  let prop = cell
    .properties
    .iter()
    .find(|p| p.name.as_str() == "source")?;

  match &prop.value {
    Value::StringLit(lit) => Some(lit.value.to_string()),
    Value::Array(arr) => {
      let mut joined = String::new();
      for elem in &arr.elements {
        if let Value::StringLit(lit) = elem {
          joined.push_str(&lit.value);
        }
      }
      if joined.is_empty() {
        None
      } else {
        Some(joined)
      }
    }
    _ => None,
  }
}

fn get_object<'a>(obj: &'a Object, key: &str) -> Option<&'a Object<'a>> {
  obj.properties.iter().find_map(|p| {
    if p.name.as_str() == key {
      match &p.value {
        Value::Object(o) => Some(o),
        _ => None,
      }
    } else {
      None
    }
  })
}

fn get_string<'a>(obj: &'a Object, key: &str) -> Option<&'a str> {
  obj.properties.iter().find_map(|p| {
    if p.name.as_str() == key {
      match &p.value {
        Value::StringLit(lit) => Some(lit.value.as_ref()),
        _ => None,
      }
    } else {
      None
    }
  })
}

fn get_array<'a>(obj: &'a Object, key: &str) -> Option<&'a Array<'a>> {
  obj.properties.iter().find_map(|p| {
    if p.name.as_str() == key {
      match &p.value {
        Value::Array(a) => Some(a),
        _ => None,
      }
    } else {
      None
    }
  })
}
