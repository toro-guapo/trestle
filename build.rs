use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

fn main() {
  println!("cargo:rerun-if-env-changed=TRESTLE_EDITION");

  let version = env!("CARGO_PKG_VERSION");
  let display = match std::env::var("TRESTLE_EDITION") {
    Ok(edition) if !edition.is_empty() => {
      format!("Trestle {edition} {version}")
    }
    _ => format!("Trestle {version}"),
  };

  println!("cargo:rustc-env=TRESTLE_VERSION_DISPLAY={display}");

  for table in tables() {
    println!("cargo:rerun-if-changed={}", table.input_path);
    generate_table(table);
  }
}

struct Table {
  input_path: &'static str,
  output_filename: &'static str,
  const_decl: &'static str,
  render_row: fn(&serde_json::Value, &str) -> String,
}

fn tables() -> &'static [Table] {
  &[
    Table {
      input_path: "data/output-formats.json",
      output_filename: "output_formats.rs",
      const_decl: "pub const OUTPUT_FORMATS: &[OutputFormatInfo] = &[",
      render_row: |entry, path| {
        let name = require_str(entry, "name", path);
        let description = require_str(entry, "description", path);
        format!(
          "OutputFormatInfo {{ name: {name:?}, description: {description:?} }},"
        )
      },
    },
    Table {
      input_path: "data/exit-codes.json",
      output_filename: "exit_codes.rs",
      const_decl: "pub const EXIT_CODES: &[ExitCodeInfo] = &[",
      render_row: |entry, path| {
        let code = require_i32(entry, "code", path);
        let description = require_str(entry, "description", path);
        format!(
          "ExitCodeInfo {{ code: {code}, description: {description:?} }},"
        )
      },
    },
    Table {
      input_path: "data/rule-ids.json",
      output_filename: "rule_ids.rs",
      const_decl: "pub const RULES: &[(&str, &str)] = &[",
      render_row: |entry, path| {
        let id = require_str(entry, "id", path);
        let description = require_str(entry, "description", path);
        format!("({id:?}, {description:?}),")
      },
    },
    Table {
      input_path: "data/summary-fields.json",
      output_filename: "summary_fields.rs",
      const_decl: "pub const SUMMARY_FIELDS: &[SummaryFieldInfo] = &[",
      render_row: |entry, path| {
        let name = require_str(entry, "name", path);
        let description = require_str(entry, "description", path);
        format!(
          "SummaryFieldInfo {{ name: {name:?}, description: {description:?} }},"
        )
      },
    },
  ]
}

fn generate_table(table: &Table) {
  let entries = read_json_array(table.input_path);
  let mut out = format!("{}\n", table.const_decl);
  for entry in &entries {
    writeln!(out, "  {}", (table.render_row)(entry, table.input_path))
      .expect("writing to String never fails");
  }
  out.push_str("];\n");

  fs::write(out_path(table.output_filename), out).unwrap_or_else(|err| {
    panic!("write {} to OUT_DIR: {err}", table.output_filename)
  });
}

fn out_path(name: &str) -> std::path::PathBuf {
  let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
  Path::new(&out_dir).join(name)
}

fn read_json_array(path: &str) -> Vec<serde_json::Value> {
  let json =
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {path}: {err}"));

  let value: serde_json::Value = serde_json::from_str(&json)
    .unwrap_or_else(|err| panic!("{path} is invalid JSON: {err}"));

  value
    .as_array()
    .unwrap_or_else(|| panic!("{path} must contain a JSON array"))
    .clone()
}

fn require_str<'a>(
  entry: &'a serde_json::Value,
  key: &str,
  path: &str,
) -> &'a str {
  entry
    .get(key)
    .and_then(|v| v.as_str())
    .unwrap_or_else(|| panic!("{path} entry missing string \"{key}\": {entry}"))
}

fn require_i32(entry: &serde_json::Value, key: &str, path: &str) -> i32 {
  let raw = entry.get(key).and_then(|v| v.as_i64()).unwrap_or_else(|| {
    panic!("{path} entry missing integer \"{key}\": {entry}")
  });

  i32::try_from(raw).unwrap_or_else(|_| {
    panic!("{path} value for \"{key}\" out of i32 range: {raw}")
  })
}
