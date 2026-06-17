use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "cache")]
const TRESTLERC_FILENAME: &str = ".trestlerc.toml";
#[cfg(feature = "cache")]
const TRESTLE_DIRNAME: &str = ".trestle";
#[cfg(feature = "cache")]
const GITIGNORE_FILENAME: &str = ".gitignore";
#[cfg(feature = "mcp")]
const MCP_CONFIG_FILENAME: &str = ".mcp.json";
#[cfg(feature = "mcp")]
const MCP_SERVER_KEY: &str = "trestle";
#[cfg(feature = "mcp")]
const CODEX_CONFIG_REL_PATH: &str = ".codex/config.toml";

#[cfg(feature = "cache")]
const TRESTLERC_CONTENT: &str = "cache-directory = \".trestle/cache\"\n";
#[cfg(feature = "cache")]
const GITIGNORE_LINE: &str = ".trestle/";

const HOOK_SHEBANG: &str = "#!/bin/sh";

const AGENT_FILE_DEFAULT: &str = "AGENTS.md";
const AGENT_FILE_CANDIDATES: &[&str] = &[
  "AGENTS.md",
  "CLAUDE.md",
  ".cursorrules",
  ".clinerules",
  ".windsurfrules",
];

const AGENT_MARKER_BEGIN: &str = "<!-- trestle (begin) -->";
const AGENT_MARKER_END: &str = "<!-- trestle (end) -->";

const AGENT_BLOCK_BODY: &str = r#"## Secret scanning with trestle

trestle detects secrets (API keys, tokens, passwords, private keys, etc.)
in source code. After every code change you make or suggest, no matter
how small, run trestle to verify the change is safe. This covers every
modification, not only full file writes: single-line edits, partial-line
tweaks, renames, comment changes, and whitespace adjustments all need a
scan.

Do not try to judge whether code is sensitive enough to warrant scanning.
Let trestle decide. **Scan unconditionally.**

**If trestle is configured as an MCP server** (see `.mcp.json`):

- Call `scan_proposed` **before** suggesting the change to the user. Pass
  the complete file content as it will look after the change is applied,
  not just the diff or snippet. Do this for every edit, however small.
- Call `scan_path` after writing to verify what is on disk.

**If you do not have MCP access**, run `trestle scan` from the project
root after every code change. Treat any reported finding as a blocker:
do not propose or commit the change until every finding is addressed.

A leaked credential cannot be unleaked. Always scan.
"#;

#[derive(Debug, Clone, PartialEq)]
pub enum InstallChange {
  #[cfg(feature = "cache")]
  CreatedTrestlerc,
  #[cfg(feature = "cache")]
  UpdatedGitignore,
  InstalledPreCommitHook,
  UpdatedAgentInstructions,
  #[cfg(feature = "mcp")]
  UpdatedMcpConfig,
}

impl InstallChange {
  pub fn description(&self) -> &'static str {
    match self {
      #[cfg(feature = "cache")]
      Self::CreatedTrestlerc => "Created .trestlerc.toml.",
      #[cfg(feature = "cache")]
      Self::UpdatedGitignore => "Added .trestle/ to .gitignore.",
      Self::InstalledPreCommitHook => "Installed git pre-commit hook.",
      Self::UpdatedAgentInstructions => {
        "Added trestle instructions to AI agent files."
      }
      #[cfg(feature = "mcp")]
      Self::UpdatedMcpConfig => "Added trestle to MCP server config.",
    }
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UninstallChange {
  #[cfg(feature = "cache")]
  RemovedTrestlerc,
  #[cfg(feature = "cache")]
  RemovedTrestleDirectory,
  #[cfg(feature = "cache")]
  UpdatedGitignore,
  RemovedPreCommitHook,
  UpdatedAgentInstructions,
  #[cfg(feature = "mcp")]
  UpdatedMcpConfig,
}

impl UninstallChange {
  pub fn description(&self) -> &'static str {
    match self {
      #[cfg(feature = "cache")]
      Self::RemovedTrestlerc => "Removed .trestlerc.toml.",
      #[cfg(feature = "cache")]
      Self::RemovedTrestleDirectory => "Removed .trestle directory.",
      #[cfg(feature = "cache")]
      Self::UpdatedGitignore => "Removed .trestle/ from .gitignore.",
      Self::RemovedPreCommitHook => "Removed git pre-commit hook.",
      Self::UpdatedAgentInstructions => {
        "Removed trestle instructions from AI agent files."
      }
      #[cfg(feature = "mcp")]
      Self::UpdatedMcpConfig => "Removed trestle from MCP server config.",
    }
  }
}

struct Targets {
  project_root: PathBuf,
  hook_path: Option<PathBuf>,
}

fn resolve_targets(start: &Path) -> Targets {
  let repo = gix::discover(start).ok();
  let project_root = repo
    .as_ref()
    .and_then(|r| r.workdir().map(Path::to_path_buf))
    .unwrap_or_else(|| start.to_path_buf());
  let hook_path = repo.as_ref().map(pre_commit_hook_path);
  Targets {
    project_root,
    hook_path,
  }
}

fn pre_commit_hook_path(repo: &gix::Repository) -> PathBuf {
  let hooks_dir = repo
    .config_snapshot()
    .string("core.hooksPath")
    .and_then(|bstr| {
      let path = gix::path::from_bstr(bstr.as_ref());
      if path.is_absolute() {
        Some(path.into_owned())
      } else {
        repo.workdir().map(|w| w.join(path.as_ref()))
      }
    })
    .unwrap_or_else(|| repo.path().join("hooks"));
  hooks_dir.join("pre-commit")
}

pub fn install_in(
  start: &Path,
  trestle_path: &Path,
) -> Result<Vec<InstallChange>, String> {
  let targets = resolve_targets(start);
  let mut changes = Vec::new();

  #[cfg(feature = "cache")]
  {
    let trestlerc_path = targets.project_root.join(TRESTLERC_FILENAME);
    if !trestlerc_path.exists() {
      fs::write(&trestlerc_path, TRESTLERC_CONTENT)
        .map_err(|e| format!("Failed to create {TRESTLERC_FILENAME}: {e}"))?;
      changes.push(InstallChange::CreatedTrestlerc);
    }

    let gitignore_path = targets.project_root.join(GITIGNORE_FILENAME);
    let gitignore = fs::read_to_string(&gitignore_path).unwrap_or_default();
    if !line_present(&gitignore, GITIGNORE_LINE) {
      let mut updated = gitignore;
      if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
      }
      updated.push_str(GITIGNORE_LINE);
      updated.push('\n');
      fs::write(&gitignore_path, updated)
        .map_err(|e| format!("Failed to update {GITIGNORE_FILENAME}: {e}"))?;
      changes.push(InstallChange::UpdatedGitignore);
    }
  }

  if let Some(hook_path) = targets.hook_path
    && install_hook(&hook_path, trestle_path)?
  {
    changes.push(InstallChange::InstalledPreCommitHook);
  }

  if install_agent_instructions(&targets.project_root)? {
    changes.push(InstallChange::UpdatedAgentInstructions);
  }

  #[cfg(feature = "mcp")]
  if install_mcp_configs(&targets.project_root)? {
    changes.push(InstallChange::UpdatedMcpConfig);
  }

  Ok(changes)
}

pub fn uninstall_in(start: &Path) -> Result<Vec<UninstallChange>, String> {
  let targets = resolve_targets(start);
  let mut changes = Vec::new();

  #[cfg(feature = "cache")]
  {
    let trestlerc_path = targets.project_root.join(TRESTLERC_FILENAME);
    if trestlerc_path.exists() {
      fs::remove_file(&trestlerc_path)
        .map_err(|e| format!("Failed to remove {TRESTLERC_FILENAME}: {e}"))?;
      changes.push(UninstallChange::RemovedTrestlerc);
    }

    let trestle_dir_path = targets.project_root.join(TRESTLE_DIRNAME);
    if trestle_dir_path.is_dir() {
      fs::remove_dir_all(&trestle_dir_path)
        .map_err(|e| format!("Failed to remove {TRESTLE_DIRNAME}: {e}"))?;
      changes.push(UninstallChange::RemovedTrestleDirectory);
    }

    let gitignore_path = targets.project_root.join(GITIGNORE_FILENAME);
    if let Ok(existing) = fs::read_to_string(&gitignore_path)
      && let Some(updated) = remove_line(&existing, GITIGNORE_LINE)
    {
      if updated.trim().is_empty() {
        fs::remove_file(&gitignore_path)
          .map_err(|e| format!("Failed to remove {GITIGNORE_FILENAME}: {e}"))?;
      } else {
        fs::write(&gitignore_path, updated)
          .map_err(|e| format!("Failed to update {GITIGNORE_FILENAME}: {e}"))?;
      }
      changes.push(UninstallChange::UpdatedGitignore);
    }
  }

  if let Some(hook_path) = targets.hook_path
    && let Ok(existing) = fs::read_to_string(&hook_path)
    && let Some(updated) = remove_trestle_lines(&existing)
  {
    if hook_is_essentially_empty(&updated) {
      fs::remove_file(&hook_path)
        .map_err(|e| format!("Failed to remove pre-commit hook: {e}"))?;
    } else {
      fs::write(&hook_path, updated)
        .map_err(|e| format!("Failed to update pre-commit hook: {e}"))?;
    }
    changes.push(UninstallChange::RemovedPreCommitHook);
  }

  if uninstall_agent_instructions(&targets.project_root)? {
    changes.push(UninstallChange::UpdatedAgentInstructions);
  }

  #[cfg(feature = "mcp")]
  if uninstall_mcp_configs(&targets.project_root)? {
    changes.push(UninstallChange::UpdatedMcpConfig);
  }

  Ok(changes)
}

#[cfg(feature = "mcp")]
fn install_mcp_configs(project_root: &Path) -> Result<bool, String> {
  let standard_changed = install_mcp_config(project_root)?;
  let codex_changed = install_codex_mcp_config(project_root)?;
  Ok(standard_changed || codex_changed)
}

#[cfg(feature = "mcp")]
fn uninstall_mcp_configs(project_root: &Path) -> Result<bool, String> {
  let standard_changed = uninstall_mcp_config(project_root)?;
  let codex_changed = uninstall_codex_mcp_config(project_root)?;
  Ok(standard_changed || codex_changed)
}

fn install_hook(hook_path: &Path, trestle_path: &Path) -> Result<bool, String> {
  if let Some(parent) = hook_path.parent() {
    fs::create_dir_all(parent)
      .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
  }

  let new_line = hook_line_for(trestle_path)?;
  let existing = fs::read_to_string(hook_path).unwrap_or_default();

  let kept: Vec<&str> =
    existing.lines().filter(|l| !is_trestle_line(l)).collect();

  let mut new_content = String::new();
  if kept.is_empty() {
    new_content.push_str(HOOK_SHEBANG);
    new_content.push('\n');
  } else {
    for line in &kept {
      new_content.push_str(line);
      new_content.push('\n');
    }
  }
  new_content.push_str(&new_line);
  new_content.push('\n');

  if new_content == existing {
    return Ok(false);
  }

  fs::write(hook_path, new_content)
    .map_err(|e| format!("Failed to write pre-commit hook: {e}"))?;
  make_executable(hook_path)
    .map_err(|e| format!("Failed to chmod pre-commit hook: {e}"))?;
  Ok(true)
}

fn hook_line_for(trestle_path: &Path) -> Result<String, String> {
  let path_str = resolved_trestle_executable(trestle_path)?;
  Ok(format!("\"{path_str}\" scan"))
}

fn resolved_trestle_executable(trestle_path: &Path) -> Result<String, String> {
  let canonical = trestle_path.canonicalize();
  let resolved = canonical.as_deref().unwrap_or(trestle_path);
  resolved.to_str().map(str::to_owned).ok_or_else(|| {
    format!(
      "trestle executable path is not valid UTF-8: {}",
      resolved.display()
    )
  })
}

fn is_trestle_line(line: &str) -> bool {
  let trimmed = line.trim_end();
  let Some(prefix) = trimmed.strip_suffix(" scan") else {
    return false;
  };

  let unquoted = prefix
    .strip_prefix('"')
    .and_then(|s| s.strip_suffix('"'))
    .unwrap_or(prefix);

  unquoted == "trestle"
    || unquoted.ends_with("/trestle")
    || unquoted.ends_with("\\trestle")
}

fn hook_is_essentially_empty(content: &str) -> bool {
  content.lines().all(|l| {
    let trimmed = l.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
  })
}

#[cfg(feature = "cache")]
fn line_present(content: &str, target: &str) -> bool {
  content.lines().any(|l| l.trim_end() == target)
}

#[cfg(feature = "cache")]
fn remove_line(content: &str, target: &str) -> Option<String> {
  if !line_present(content, target) {
    return None;
  }
  let kept: Vec<&str> =
    content.lines().filter(|l| l.trim_end() != target).collect();
  let mut out = kept.join("\n");
  if content.ends_with('\n') && !out.is_empty() {
    out.push('\n');
  }
  Some(out)
}

fn remove_trestle_lines(content: &str) -> Option<String> {
  let original = content.lines().count();
  let kept: Vec<&str> =
    content.lines().filter(|l| !is_trestle_line(l)).collect();
  if kept.len() == original {
    return None;
  }
  let mut out = kept.join("\n");
  if content.ends_with('\n') && !out.is_empty() {
    out.push('\n');
  }
  Some(out)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> std::io::Result<()> {
  use std::os::unix::fs::PermissionsExt;
  let mut perms = fs::metadata(path)?.permissions();
  perms.set_mode(0o755);
  fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> std::io::Result<()> {
  Ok(())
}

fn install_agent_instructions(project_root: &Path) -> Result<bool, String> {
  let block =
    format!("{AGENT_MARKER_BEGIN}\n{AGENT_BLOCK_BODY}{AGENT_MARKER_END}\n");

  let existing: Vec<PathBuf> = AGENT_FILE_CANDIDATES
    .iter()
    .map(|name| project_root.join(name))
    .filter(|p| p.is_file())
    .collect();

  if existing.is_empty() {
    let target = project_root.join(AGENT_FILE_DEFAULT);
    fs::write(&target, &block)
      .map_err(|e| format!("Failed to create {AGENT_FILE_DEFAULT}: {e}"))?;
    return Ok(true);
  }

  let mut any_changed = false;
  for path in existing {
    let content = fs::read_to_string(&path)
      .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let new_content = match replace_marked_block(
      &content,
      AGENT_MARKER_BEGIN,
      AGENT_MARKER_END,
      &block,
    ) {
      Some(replaced) => replaced,
      None => append_marked_block(&content, &block),
    };

    if new_content != content {
      fs::write(&path, new_content)
        .map_err(|e| format!("Failed to update {}: {e}", path.display()))?;
      any_changed = true;
    }
  }

  Ok(any_changed)
}

fn uninstall_agent_instructions(project_root: &Path) -> Result<bool, String> {
  let mut any_changed = false;

  for name in AGENT_FILE_CANDIDATES {
    let path = project_root.join(name);
    if !path.is_file() {
      continue;
    }

    let content = fs::read_to_string(&path)
      .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let Some(updated) =
      remove_marked_block(&content, AGENT_MARKER_BEGIN, AGENT_MARKER_END)
    else {
      continue;
    };

    if updated.trim().is_empty() {
      fs::remove_file(&path)
        .map_err(|e| format!("Failed to remove {}: {e}", path.display()))?;
    } else {
      fs::write(&path, updated)
        .map_err(|e| format!("Failed to update {}: {e}", path.display()))?;
    }

    any_changed = true;
  }

  Ok(any_changed)
}

fn append_marked_block(existing: &str, block: &str) -> String {
  let mut out = String::with_capacity(existing.len() + block.len() + 2);
  out.push_str(existing);

  if !out.is_empty() && !out.ends_with('\n') {
    out.push('\n');
  }

  if !out.is_empty() {
    out.push('\n');
  }

  out.push_str(block);
  out
}

struct BlockBounds {
  block_start: usize,
  block_end: usize,
}

fn locate_marked_block(
  content: &str,
  begin: &str,
  end: &str,
) -> Option<BlockBounds> {
  let begin_idx = content.find(begin)?;
  let after_begin = begin_idx.checked_add(begin.len())?;
  let tail = content.get(after_begin..)?;
  let end_offset = tail.find(end)?;
  let end_idx = after_begin.checked_add(end_offset)?;
  let after_end = end_idx.checked_add(end.len())?;

  let before = content.get(..begin_idx)?;
  let block_start = before.rfind('\n').map(|i| i + 1).unwrap_or(0);

  let tail_after = content.get(after_end..)?;
  let block_end = tail_after
    .find('\n')
    .and_then(|nl| after_end.checked_add(nl).and_then(|i| i.checked_add(1)))
    .unwrap_or(content.len());

  Some(BlockBounds {
    block_start,
    block_end,
  })
}

fn replace_marked_block(
  content: &str,
  begin: &str,
  end: &str,
  new_block: &str,
) -> Option<String> {
  let bounds = locate_marked_block(content, begin, end)?;
  let prefix = content.get(..bounds.block_start)?;
  let suffix = content.get(bounds.block_end..)?;

  let mut result = String::new();
  result.push_str(prefix);
  result.push_str(new_block);
  result.push_str(suffix);
  Some(result)
}

fn remove_marked_block(
  content: &str,
  begin: &str,
  end: &str,
) -> Option<String> {
  let bounds = locate_marked_block(content, begin, end)?;
  let prefix = content.get(..bounds.block_start)?;
  let suffix = content.get(bounds.block_end..)?;

  let mut result = String::new();
  result.push_str(prefix);
  result.push_str(suffix);

  while result.contains("\n\n\n") {
    result = result.replace("\n\n\n", "\n\n");
  }

  Some(result)
}

#[cfg(feature = "mcp")]
fn install_mcp_config(project_root: &Path) -> Result<bool, String> {
  let path = project_root.join(MCP_CONFIG_FILENAME);

  let mut value = if path.exists() {
    let content = fs::read_to_string(&path)
      .map_err(|e| format!("Failed to read {MCP_CONFIG_FILENAME}: {e}"))?;
    serde_json::from_str(&content)
      .map_err(|e| format!("Failed to parse {MCP_CONFIG_FILENAME}: {e}"))?
  } else {
    serde_json::json!({})
  };

  let trestle_entry = serde_json::json!({
    "command": "trestle",
    "args": ["mcp", "."],
  });

  let root = value.as_object_mut().ok_or_else(|| {
    format!("{MCP_CONFIG_FILENAME} root must be a JSON object.")
  })?;

  let servers_entry = root
    .entry("mcpServers".to_string())
    .or_insert_with(|| serde_json::json!({}));

  let servers = servers_entry.as_object_mut().ok_or_else(|| {
    format!("{MCP_CONFIG_FILENAME} mcpServers must be an object.")
  })?;

  if servers.get(MCP_SERVER_KEY) == Some(&trestle_entry) {
    return Ok(false);
  }

  servers.insert(MCP_SERVER_KEY.to_string(), trestle_entry);

  let mut serialized = serde_json::to_string_pretty(&value)
    .map_err(|e| format!("Failed to serialize {MCP_CONFIG_FILENAME}: {e}"))?;
  serialized.push('\n');
  fs::write(&path, serialized)
    .map_err(|e| format!("Failed to write {MCP_CONFIG_FILENAME}: {e}"))?;

  Ok(true)
}

#[cfg(feature = "mcp")]
fn uninstall_mcp_config(project_root: &Path) -> Result<bool, String> {
  let path = project_root.join(MCP_CONFIG_FILENAME);
  let Ok(content) = fs::read_to_string(&path) else {
    return Ok(false);
  };

  let mut value: serde_json::Value = serde_json::from_str(&content)
    .map_err(|e| format!("Failed to parse {MCP_CONFIG_FILENAME}: {e}"))?;

  let Some(root) = value.as_object_mut() else {
    return Ok(false);
  };

  let Some(servers) = root
    .get_mut("mcpServers")
    .and_then(serde_json::Value::as_object_mut)
  else {
    return Ok(false);
  };

  if servers.remove(MCP_SERVER_KEY).is_none() {
    return Ok(false);
  }

  let servers_empty = servers.is_empty();
  if servers_empty {
    root.remove("mcpServers");
  }

  if root.is_empty() {
    fs::remove_file(&path)
      .map_err(|e| format!("Failed to remove {MCP_CONFIG_FILENAME}: {e}"))?;
  } else {
    let mut serialized = serde_json::to_string_pretty(&value)
      .map_err(|e| format!("Failed to serialize {MCP_CONFIG_FILENAME}: {e}"))?;
    serialized.push('\n');
    fs::write(&path, serialized)
      .map_err(|e| format!("Failed to update {MCP_CONFIG_FILENAME}: {e}"))?;
  }

  Ok(true)
}

#[cfg(feature = "mcp")]
fn install_codex_mcp_config(project_root: &Path) -> Result<bool, String> {
  let path = project_root.join(CODEX_CONFIG_REL_PATH);

  let mut doc = if path.exists() {
    let content = fs::read_to_string(&path)
      .map_err(|e| format!("Failed to read {CODEX_CONFIG_REL_PATH}: {e}"))?;
    content
      .parse::<toml_edit::DocumentMut>()
      .map_err(|e| format!("Failed to parse {CODEX_CONFIG_REL_PATH}: {e}"))?
  } else {
    toml_edit::DocumentMut::new()
  };

  if codex_trestle_entry_matches(&doc) {
    return Ok(false);
  }

  let servers_item = doc
    .entry("mcp_servers")
    .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));

  let Some(servers) = servers_item.as_table_mut() else {
    return Err(format!(
      "{CODEX_CONFIG_REL_PATH} mcp_servers must be a table."
    ));
  };

  let mut trestle = toml_edit::Table::new();
  trestle["command"] = toml_edit::value("trestle");

  let mut args = toml_edit::Array::new();
  args.push("mcp");
  args.push(".");

  trestle["args"] = toml_edit::value(args);
  servers[MCP_SERVER_KEY] = toml_edit::Item::Table(trestle);

  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)
      .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
  }

  fs::write(&path, doc.to_string())
    .map_err(|e| format!("Failed to write {CODEX_CONFIG_REL_PATH}: {e}"))?;

  Ok(true)
}

#[cfg(feature = "mcp")]
fn codex_trestle_entry_matches(doc: &toml_edit::DocumentMut) -> bool {
  let Some(servers) = doc.get("mcp_servers").and_then(|v| v.as_table_like())
  else {
    return false;
  };
  let Some(trestle) =
    servers.get(MCP_SERVER_KEY).and_then(|v| v.as_table_like())
  else {
    return false;
  };
  let command_ok =
    trestle.get("command").and_then(|v| v.as_str()) == Some("trestle");
  let args_ok = trestle
    .get("args")
    .and_then(|v| v.as_array())
    .map(|arr| {
      let collected: Vec<&str> =
        arr.iter().filter_map(|v| v.as_str()).collect();
      collected == ["mcp", "."]
    })
    .unwrap_or(false);
  command_ok && args_ok
}

#[cfg(feature = "mcp")]
fn uninstall_codex_mcp_config(project_root: &Path) -> Result<bool, String> {
  let path = project_root.join(CODEX_CONFIG_REL_PATH);
  let Ok(content) = fs::read_to_string(&path) else {
    return Ok(false);
  };

  let mut doc: toml_edit::DocumentMut = content
    .parse()
    .map_err(|e| format!("Failed to parse {CODEX_CONFIG_REL_PATH}: {e}"))?;

  let Some(servers_item) = doc.get_mut("mcp_servers") else {
    return Ok(false);
  };
  let Some(servers) = servers_item.as_table_mut() else {
    return Ok(false);
  };

  if servers.remove(MCP_SERVER_KEY).is_none() {
    return Ok(false);
  }

  if servers.is_empty() {
    doc.as_table_mut().remove("mcp_servers");
  }

  if doc.as_table().is_empty() {
    fs::remove_file(&path)
      .map_err(|e| format!("Failed to remove {CODEX_CONFIG_REL_PATH}: {e}"))?;
    if let Some(parent) = path.parent() {
      remove_dir_if_empty(parent);
    }
  } else {
    fs::write(&path, doc.to_string())
      .map_err(|e| format!("Failed to update {CODEX_CONFIG_REL_PATH}: {e}"))?;
  }

  Ok(true)
}

#[cfg(feature = "mcp")]
fn remove_dir_if_empty(dir: &Path) {
  let Ok(mut entries) = fs::read_dir(dir) else {
    return;
  };
  if entries.next().is_some() {
    return;
  }
  if let Err(err) = fs::remove_dir(dir) {
    eprintln!(
      "trestle: failed to remove empty directory {}: {err}",
      dir.display()
    );
  }
}
