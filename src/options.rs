use std::path::{Path, PathBuf};

use crate::exit::EXIT_CODES;

const DEFAULT_AUTO_EXCLUDES: bool = true;
#[cfg(feature = "cache")]
const DEFAULT_CACHE_DIRECTORY: &str = "";
const DEFAULT_OUTPUT_FILE: &str = "-";
const DEFAULT_OUTPUT_FORMAT: OutputFormat = OutputFormat::Text;
const DEFAULT_OUTPUT_FORMAT_STRING: &str = "text";
const DEFAULT_COLOR: Option<bool> = None;
const DEFAULT_COLOR_DESCRIPTION: &str =
  "true when output is a terminal, otherwise false";
const DEFAULT_SHOW_SUMMARY: bool = true;
const DEFAULT_SKIP_DIRECTORY_NAMES: &[&str] = &[];
const DEFAULT_SKIP_FILE_NAMES: &[&str] = &[];
const DEFAULT_SKIP_GLOB: &[&str] = &[];
const DEFAULT_SKIP_VCS_IGNORED: bool = true;
const DEFAULT_VERBOSE: bool = false;

/// A glob pattern paired with the directory it should be evaluated
/// against. The pattern matches files whose paths, taken relative to
/// `anchor`, satisfy the glob. `rc_file` is the path to the
/// `.trestlerc.toml` that declared the rule, or `None` if it came from
/// the command line.
#[derive(Clone, Debug)]
pub struct ScopedGlob {
  pub anchor: PathBuf,
  pub pattern: String,
  pub rc_file: Option<PathBuf>,
}

/// A bare file or directory name paired with the directory the rule
/// was declared in. `rc_file` is the path to the `.trestlerc.toml`
/// that declared the rule, or `None` if it came from the command line.
#[derive(Clone, Debug, PartialEq)]
pub struct ScopedName {
  pub anchor: PathBuf,
  pub name: String,
  pub rc_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
  Scan,
  Watch,
  #[cfg(feature = "lsp")]
  Lsp,
  #[cfg(feature = "mcp")]
  Mcp,
  Install,
  Uninstall,
}

const SCAN_COMMAND_NAME: &str = "scan";
const SCAN_COMMAND_DESCRIPTION: &str = "Scan paths for secrets (default).";

const WATCH_COMMAND_NAME: &str = "watch";
const WATCH_COMMAND_DESCRIPTION: &str =
  "Scan paths for secrets then watch for changes.";

#[cfg(feature = "lsp")]
const LSP_COMMAND_NAME: &str = "lsp";
#[cfg(feature = "lsp")]
const LSP_COMMAND_DESCRIPTION: &str = "Run as an LSP server.";

#[cfg(feature = "mcp")]
const MCP_COMMAND_NAME: &str = "mcp";
#[cfg(feature = "mcp")]
const MCP_COMMAND_DESCRIPTION: &str = "Run as an MCP server.";

const INSTALL_COMMAND_NAME: &str = "install";
const INSTALL_COMMAND_DESCRIPTION: &str =
  "Install trestle into the current project.";

const UNINSTALL_COMMAND_NAME: &str = "uninstall";
const UNINSTALL_COMMAND_DESCRIPTION: &str =
  "Uninstall trestle from the current project.";

impl Command {
  pub fn from_str(s: &str) -> Option<Self> {
    match s {
      SCAN_COMMAND_NAME => Some(Self::Scan),
      WATCH_COMMAND_NAME => Some(Self::Watch),
      #[cfg(feature = "lsp")]
      LSP_COMMAND_NAME => Some(Self::Lsp),
      #[cfg(feature = "mcp")]
      MCP_COMMAND_NAME => Some(Self::Mcp),
      INSTALL_COMMAND_NAME => Some(Self::Install),
      UNINSTALL_COMMAND_NAME => Some(Self::Uninstall),
      _ => None,
    }
  }

  pub fn name(&self) -> &'static str {
    match self {
      Self::Scan => SCAN_COMMAND_NAME,
      Self::Watch => WATCH_COMMAND_NAME,
      #[cfg(feature = "lsp")]
      Self::Lsp => LSP_COMMAND_NAME,
      #[cfg(feature = "mcp")]
      Self::Mcp => MCP_COMMAND_NAME,
      Self::Install => INSTALL_COMMAND_NAME,
      Self::Uninstall => UNINSTALL_COMMAND_NAME,
    }
  }
}

impl Default for Command {
  fn default() -> Self {
    Self::Scan
  }
}

const COMMANDS: &[(&str, &str)] = &[
  (SCAN_COMMAND_NAME, SCAN_COMMAND_DESCRIPTION),
  (WATCH_COMMAND_NAME, WATCH_COMMAND_DESCRIPTION),
  #[cfg(feature = "lsp")]
  (LSP_COMMAND_NAME, LSP_COMMAND_DESCRIPTION),
  #[cfg(feature = "mcp")]
  (MCP_COMMAND_NAME, MCP_COMMAND_DESCRIPTION),
  (INSTALL_COMMAND_NAME, INSTALL_COMMAND_DESCRIPTION),
  (UNINSTALL_COMMAND_NAME, UNINSTALL_COMMAND_DESCRIPTION),
];

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
  Text,
  Csv,
  Json,
  Junit,
  Sarif,
  Xml,
}

pub struct OutputFormatInfo {
  pub name: &'static str,
  pub description: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/output_formats.rs"));

impl OutputFormat {
  pub fn from_str(s: &str) -> Option<Self> {
    match s {
      "text" => Some(Self::Text),
      "csv" => Some(Self::Csv),
      "json" => Some(Self::Json),
      "junit" => Some(Self::Junit),
      "sarif" => Some(Self::Sarif),
      "xml" => Some(Self::Xml),
      _ => None,
    }
  }
}

pub fn output_format_names_csv() -> String {
  OUTPUT_FORMATS
    .iter()
    .map(|f| f.name)
    .collect::<Vec<_>>()
    .join(", ")
}

#[derive(Clone)]
pub struct Options {
  pub auto_excludes: bool,
  #[cfg(feature = "cache")]
  pub cache_directory: Option<String>,
  pub color: Option<bool>,
  pub output_file: String,
  pub output_format: OutputFormat,
  pub show_summary: bool,
  pub skip_directory_names: Vec<ScopedName>,
  pub skip_file_names: Vec<ScopedName>,
  pub skip_glob: Vec<ScopedGlob>,
  pub skip_vcs_ignored: bool,
  pub verbose: bool,
}

impl Default for Options {
  fn default() -> Self {
    Self {
      auto_excludes: DEFAULT_AUTO_EXCLUDES,
      #[cfg(feature = "cache")]
      cache_directory: None,
      color: DEFAULT_COLOR,
      output_file: DEFAULT_OUTPUT_FILE.to_owned(),
      output_format: DEFAULT_OUTPUT_FORMAT,
      show_summary: DEFAULT_SHOW_SUMMARY,
      skip_directory_names: Vec::new(),
      skip_file_names: Vec::new(),
      skip_glob: Vec::new(),
      skip_vcs_ignored: DEFAULT_SKIP_VCS_IGNORED,
      verbose: DEFAULT_VERBOSE,
    }
  }
}

impl Options {
  pub fn from_args(args: &[String]) -> ParseResult {
    let mut default = Self::default();
    let mut paths: Vec<String> = Vec::new();
    let mut cli_args: Vec<String> = Vec::new();

    let (command, rest) = match args.first() {
      Some(first) if !first.starts_with('-') => {
        match Command::from_str(first) {
          Some(cmd) => (cmd, &args[1..]),
          None => {
            if std::path::Path::new(first).exists() {
              (Command::default(), args)
            } else {
              eprintln!("Unknown command or path: \"{first}\".\n");
              return ParseResult::ErrorWithHelp;
            }
          }
        }
      }
      _ => (Command::default(), args),
    };

    let placeholder_anchor = PathBuf::new();

    for arg in rest {
      match default.apply_arg(arg, &placeholder_anchor) {
        ApplyArgOutcome::Applied => cli_args.push(arg.clone()),
        ApplyArgOutcome::NotAnOption => paths.push(arg.clone()),
        ApplyArgOutcome::Help => return ParseResult::Help,
        ApplyArgOutcome::Version => return ParseResult::Version,
        ApplyArgOutcome::Error => return ParseResult::Error,
        ApplyArgOutcome::Unknown(name) => {
          eprintln!("Unknown option: --{name}\n");
          return ParseResult::ErrorWithHelp;
        }
      }
    }

    ParseResult::Run {
      command,
      cli_args,
      cli_options: default,
      paths,
    }
  }

  pub fn apply_arg(&mut self, arg: &str, anchor: &Path) -> ApplyArgOutcome {
    let Some(rest) = arg.strip_prefix("--") else {
      return ApplyArgOutcome::NotAnOption;
    };
    if rest == "help" {
      return ApplyArgOutcome::Help;
    }
    if rest == "version" {
      return ApplyArgOutcome::Version;
    }

    for spec in OPTION_SPECS {
      if let Some(value) = rest
        .strip_prefix(spec.name)
        .and_then(|s| s.strip_prefix('='))
      {
        return match spec.default_value {
          DefaultValue::Bool(_) | DefaultValue::AutoBool(_) => {
            self.set_bool(spec.name, value == "true");
            ApplyArgOutcome::Applied
          }
          DefaultValue::String(_) => match self.set_string(spec.name, value) {
            None => ApplyArgOutcome::Applied,
            Some(ParseResult::Error) => ApplyArgOutcome::Error,
            Some(ParseResult::ErrorWithHelp) => ApplyArgOutcome::Error,
            Some(ParseResult::Help) => ApplyArgOutcome::Help,
            Some(ParseResult::Version) => ApplyArgOutcome::Version,
            Some(ParseResult::Run { .. }) => ApplyArgOutcome::Applied,
          },
          DefaultValue::StringList(_) => {
            self.set_string_list(
              spec.name,
              value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
              anchor,
              None,
            );
            ApplyArgOutcome::Applied
          }
        };
      }

      // Bare --flag (no =value) is valid for booleans, sets to true.
      if rest == spec.name {
        if let DefaultValue::Bool(_) | DefaultValue::AutoBool(_) =
          spec.default_value
        {
          self.set_bool(spec.name, true);
          return ApplyArgOutcome::Applied;
        }
      }
    }

    ApplyArgOutcome::Unknown(rest.to_owned())
  }

  pub fn apply_args(&mut self, args: &[String], anchor: &Path) {
    for arg in args {
      let _ = self.apply_arg(arg, anchor);
    }
  }

  fn set_bool(&mut self, name: &str, value: bool) {
    if name == AUTO_EXCLUDES.name {
      self.auto_excludes = value;
    } else if name == COLOR.name {
      self.color = Some(value);
    } else if name == SKIP_VCS_IGNORED.name {
      self.skip_vcs_ignored = value;
    } else if name == SHOW_SUMMARY.name {
      self.show_summary = value;
    } else if name == VERBOSE.name {
      self.verbose = value;
    }
  }

  fn set_string(&mut self, name: &str, value: &str) -> Option<ParseResult> {
    #[cfg(feature = "cache")]
    if name == CACHE_DIRECTORY.name {
      self.cache_directory = Some(value.to_owned());
      return None;
    }

    if name == OUTPUT_FILE.name {
      self.output_file = value.to_owned();
    } else if name == OUTPUT_FORMAT.name {
      if let Some(format) = OutputFormat::from_str(value) {
        self.output_format = format;
      } else {
        eprintln!(
          "Unknown output format: \"{value}\". Valid values: {}.",
          output_format_names_csv()
        );
        return Some(ParseResult::Error);
      }
    }
    None
  }

  fn set_string_list(
    &mut self,
    name: &str,
    value: Vec<String>,
    anchor: &Path,
    rc_file: Option<&Path>,
  ) {
    if name == SKIP_GLOB.name {
      let anchor = anchor.to_path_buf();
      for pattern in value {
        if !self
          .skip_glob
          .iter()
          .any(|s| s.anchor == anchor && s.pattern == pattern)
        {
          self.skip_glob.push(ScopedGlob {
            anchor: anchor.clone(),
            pattern,
            rc_file: rc_file.map(Path::to_path_buf),
          });
        }
      }
    } else if name == SKIP_DIRECTORY_NAMES.name {
      add_scoped_names(&mut self.skip_directory_names, anchor, value, rc_file);
    } else if name == SKIP_FILE_NAMES.name {
      add_scoped_names(&mut self.skip_file_names, anchor, value, rc_file);
    }
  }

  pub fn apply_configuration_source(
    &mut self,
    toml: &str,
    anchor: &Path,
    rc_file: &Path,
  ) {
    let Ok(doc) = toml.parse::<toml_edit::DocumentMut>() else {
      return;
    };

    for spec in OPTION_SPECS {
      let Some(item) = doc.get(spec.name) else {
        continue;
      };

      match spec.default_value {
        DefaultValue::Bool(_) | DefaultValue::AutoBool(_) => {
          if let Some(v) = item.as_bool() {
            self.set_bool(spec.name, v);
          }
        }
        DefaultValue::String(_) => {
          if let Some(v) = item.as_str() {
            self.set_string(spec.name, v);
          }
        }
        DefaultValue::StringList(_) => {
          if let Some(arr) = item.as_array() {
            let values: Vec<String> = arr
              .iter()
              .filter_map(|v| v.as_str().map(String::from))
              .collect();
            self.set_string_list(spec.name, values, anchor, Some(rc_file));
          }
        }
      }
    }
  }
}

fn add_scoped_names(
  target: &mut Vec<ScopedName>,
  anchor: &Path,
  values: Vec<String>,
  rc_file: Option<&Path>,
) {
  for name in values {
    if !target.iter().any(|s| s.anchor == anchor && s.name == name) {
      target.push(ScopedName {
        anchor: anchor.to_path_buf(),
        name,
        rc_file: rc_file.map(Path::to_path_buf),
      });
    }
  }
}

pub enum ParseResult {
  Run {
    command: Command,
    cli_args: Vec<String>,
    cli_options: Options,
    paths: Vec<String>,
  },
  Help,
  Version,
  ErrorWithHelp,
  Error,
}

pub enum ApplyArgOutcome {
  Applied,
  NotAnOption,
  Help,
  Version,
  Error,
  Unknown(String),
}

pub fn print_help() {
  let help_col = "  --help";
  let version_col = "  --version";
  let cols: Vec<String> = OPTION_SPECS
    .iter()
    .map(|spec| match spec.default_value {
      DefaultValue::Bool(_) | DefaultValue::AutoBool(_) => {
        format!("  --{}[=<value>]", spec.name)
      }
      _ => format!("  --{}=<value>", spec.name),
    })
    .collect();

  let indent = cols
    .iter()
    .map(|c| c.len())
    .chain(std::iter::once(help_col.len()))
    .chain(std::iter::once(version_col.len()))
    .max()
    .unwrap_or(0)
    + 2;

  let term_width = terminal_size::terminal_size()
    .map(|(w, _)| w.0 as usize)
    .unwrap_or(80);

  println!("Usage: trestle [command] [options] [path ...]\n");

  let command_indent = COMMANDS
    .iter()
    .map(|(name, _)| name.len() + 2)
    .max()
    .unwrap_or(0)
    + 2;

  println!("Commands:");
  for (name, description) in COMMANDS {
    let col = format!("  {name}");
    print_option(&col, description, command_indent, term_width);
  }
  println!();

  println!("Options:");
  for (spec, col) in OPTION_SPECS.iter().zip(&cols) {
    let description = spec.description;
    let text = match &spec.default_value {
      DefaultValue::Bool(v) => {
        format!("{description} Default: {v}.")
      }
      DefaultValue::AutoBool(v) => {
        format!("{description} Default: {v}.")
      }
      DefaultValue::String(v) => {
        if v.is_empty() {
          description.to_string()
        } else {
          format!("{description} Default: {v}.")
        }
      }
      DefaultValue::StringList(v) => {
        if v.is_empty() {
          description.to_string()
        } else {
          format!("{description} Default: {}.", v.join(","))
        }
      }
    };
    print_option(col, &text, indent, term_width);
  }
  print_option(help_col, "Show this help message.", indent, term_width);
  print_option(version_col, "Show version information.", indent, term_width);

  println!();
  println!("Output formats:");

  let format_cols: Vec<String> = OUTPUT_FORMATS
    .iter()
    .map(|f| format!("  {}", f.name))
    .collect();
  let format_indent =
    format_cols.iter().map(|c| c.len()).max().unwrap_or(0) + 2;

  for (info, col) in OUTPUT_FORMATS.iter().zip(&format_cols) {
    print_option(col, info.description, format_indent, term_width);
  }

  println!();
  println!("Exit codes:");
  let exit_cols: Vec<String> =
    EXIT_CODES.iter().map(|c| format!("  {}", c.code)).collect();
  let exit_indent = exit_cols.iter().map(|c| c.len()).max().unwrap_or(0) + 2;

  for (info, col) in EXIT_CODES.iter().zip(&exit_cols) {
    print_option(col, info.description, exit_indent, term_width);
  }
}

fn print_option(col: &str, text: &str, indent: usize, term_width: usize) {
  let max_text = if term_width > indent {
    term_width - indent
  } else {
    40
  };

  let lines = crate::formatting::wrap(text, max_text, "");
  for (i, line) in lines.iter().enumerate() {
    if i == 0 {
      println!("{col:<indent$}{line}");
    } else {
      println!("{:indent$}{line}", "");
    }
  }
}

pub struct OptionSpec {
  pub name: &'static str,
  pub description: &'static str,
  pub default_value: DefaultValue,
}

pub enum DefaultValue {
  Bool(bool),
  AutoBool(&'static str),
  String(&'static str),
  StringList(&'static [&'static str]),
}

#[cfg(feature = "cache")]
pub const CACHE_DIRECTORY: OptionSpec = OptionSpec {
  name: "cache-directory",
  description: "Directory for caching scan results.",
  default_value: DefaultValue::String(DEFAULT_CACHE_DIRECTORY),
};

pub const AUTO_EXCLUDES: OptionSpec = OptionSpec {
  name: "auto-excludes",
  description: "Skip known vendor, cache, build, and metadata paths.",
  default_value: DefaultValue::Bool(DEFAULT_AUTO_EXCLUDES),
};

pub const OUTPUT_FILE: OptionSpec = OptionSpec {
  name: "output-file",
  description: "Write output to a file. Use \"-\" for stdout.",
  default_value: DefaultValue::String(DEFAULT_OUTPUT_FILE),
};

pub const OUTPUT_FORMAT: OptionSpec = OptionSpec {
  name: "output-format",
  description: "Output format. See \"Output formats\" below.",
  default_value: DefaultValue::String(DEFAULT_OUTPUT_FORMAT_STRING),
};

pub const COLOR: OptionSpec = OptionSpec {
  name: "color",
  description: "Enable ANSI colors in text output.",
  default_value: DefaultValue::AutoBool(DEFAULT_COLOR_DESCRIPTION),
};

pub const SHOW_SUMMARY: OptionSpec = OptionSpec {
  name: "show-summary",
  description: "Include scan summary in output.",
  default_value: DefaultValue::Bool(DEFAULT_SHOW_SUMMARY),
};

pub const SKIP_DIRECTORY_NAMES: OptionSpec = OptionSpec {
  name: "skip-directory-names",
  description: "Skip directories with these names, relative to the current directory, comma-separated.",
  default_value: DefaultValue::StringList(DEFAULT_SKIP_DIRECTORY_NAMES),
};

pub const SKIP_FILE_NAMES: OptionSpec = OptionSpec {
  name: "skip-file-names",
  description: "Skip files with these names, relative to the current directory, comma-separated.",
  default_value: DefaultValue::StringList(DEFAULT_SKIP_FILE_NAMES),
};

pub const SKIP_GLOB: OptionSpec = OptionSpec {
  name: "skip-glob",
  description: "Skip files and directories matching these glob patterns, relative to the current directory, comma-separated.",
  default_value: DefaultValue::StringList(DEFAULT_SKIP_GLOB),
};

pub const SKIP_VCS_IGNORED: OptionSpec = OptionSpec {
  name: "skip-vcs-ignored",
  description: "Skip files and directories ignored by version control (.gitignore).",
  default_value: DefaultValue::Bool(DEFAULT_SKIP_VCS_IGNORED),
};

pub const VERBOSE: OptionSpec = OptionSpec {
  name: "verbose",
  description: "Print additional scan information.",
  default_value: DefaultValue::Bool(DEFAULT_VERBOSE),
};

pub const OPTION_SPECS: &[OptionSpec] = &[
  AUTO_EXCLUDES,
  #[cfg(feature = "cache")]
  CACHE_DIRECTORY,
  OUTPUT_FILE,
  OUTPUT_FORMAT,
  COLOR,
  SHOW_SUMMARY,
  SKIP_DIRECTORY_NAMES,
  SKIP_FILE_NAMES,
  SKIP_GLOB,
  SKIP_VCS_IGNORED,
  VERBOSE,
];
