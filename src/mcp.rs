use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;

use rmcp::{
  ServerHandler, ServiceExt,
  handler::server::{router::tool::ToolRouter, wrapper::Parameters},
  model::{ServerCapabilities, ServerInfo},
  schemars, tool, tool_handler, tool_router,
  transport::stdio,
};

use crate::diagnostic::Diagnostic;
use crate::install;
use crate::processing::{
  ScanContext, process_dir, process_files_with_surrounding_context,
  process_text,
};
use crate::trestlerc::OptionsResolver;

// -----------------------------------------------------------------------------
// Stable response markers
// -----------------------------------------------------------------------------

pub const NO_SECRETS_FOUND: &str = "No secrets found.";
pub const ALREADY_INSTALLED: &str = "trestle is already installed.";
pub const NOT_INSTALLED: &str = "trestle is not installed.";

// -----------------------------------------------------------------------------
// Server instructions sent to the AI agent on connect.
// -----------------------------------------------------------------------------

const INSTRUCTIONS_HEADER: &str = "\
trestle detects secrets (API keys, passwords, tokens, private keys, \
certificates) in source code. A leaked credential cannot be unleaked.

Do not try to judge whether code is sensitive enough to warrant \
scanning. Let trestle decide. **Scan unconditionally.**";

fn instructions_tools() -> String {
  format!(
    "## When to use which tool\n\
     \n\
     **`scan_proposed`** scans content that is not yet on disk. Use \
     it before suggesting any code change, no matter how small. \
     This applies to every modification you make or recommend, not \
     only to full file writes. Single-line edits, partial-line \
     tweaks, renames, comment changes, whitespace adjustments, and \
     patches produced by other tools all require a scan. For every \
     such change, construct the complete file content as it will \
     look after the change is applied (the full post-change file, \
     not a diff or snippet) and pass it together with the file \
     name (relative to the workspace root, e.g. `src/api.ts`). \
     trestle scans the content as if it were that file. There is \
     no situation where this step should be skipped.\n\
     \n\
     **`scan_path`** scans an existing file or directory on disk. \
     Use it after writing a change, before suggesting commit or \
     push, or when the user asks you to audit a path.\n\
     \n\
     **`status`** returns version info and a short reminder of how \
     to use the other tools. Call it if you are unsure whether \
     trestle is working, or to reorient mid-session.\n\
     \n\
     **`install`** wires trestle into the workspace. Use it once \
     per project, the first time you connect to a workspace where \
     it has not been called before. After that, do not call \
     `install` again unless the user asks for it. `install` is \
     idempotent: calling it on an already-installed project prints \
     `{ALREADY_INSTALLED}` and is harmless.\n\
     \n\
     **`uninstall`** reverses what `install` did. Only call it \
     when the user asks for it."
  )
}

const INSTRUCTIONS_INPUT_FORMAT: &str = "\
## What to pass to `scan_proposed`

Pass the **full post-change file content** plus the **workspace-\
relative file name**. Do not pass a diff or patch, a snippet \
showing only the changed lines, or the text of your reply to the \
user. Always reconstruct the full file: a partial scan can miss \
secrets that depend on surrounding context.

The `file_name` is the only signal trestle has for language \
detection. Pass the same extension the file will have on disk \
(`api.ts`, `api.py`, `Dockerfile`, etc.).";

const INSTRUCTIONS_ERRORS: &str = "\
## If something goes wrong

Every error trestle returns begins with `trestle:` and explains the \
cause and the next step. Read the message and follow its \
instruction. Do **not** skip the scan because a single call failed: \
retry, fix the input, or fall back to the CLI as the message \
suggests.

CLI fallback (use only if the MCP server itself appears broken): \
write the file to disk and run `trestle scan <path>` on it. This \
runs the same scanner with the same output format.";

fn instructions_footer() -> String {
  format!(
    "## Success and failure markers\n\
     \n\
     If `scan_proposed` or `scan_path` returns the exact string \
     `{NO_SECRETS_FOUND}`, the input is clean and you may \
     proceed.\n\
     \n\
     If it returns findings, address every one before suggesting \
     the change to the user: apply code or filesystem fixes \
     directly, and surface to the user any steps that require \
     their action outside the codebase (invalidating leaked \
     secrets, rotating values in deployment systems, etc.). Wait \
     for the user before continuing.\n\
     \n\
     If it returns a message beginning with `trestle:`, that is a \
     recoverable error: follow the instruction in the message and \
     retry."
  )
}

pub fn server_instructions() -> String {
  format!(
    "{header}\n\n{tools}\n\n{input}\n\n{errors}\n\n{footer}",
    header = INSTRUCTIONS_HEADER,
    tools = instructions_tools(),
    input = INSTRUCTIONS_INPUT_FORMAT,
    errors = INSTRUCTIONS_ERRORS,
    footer = instructions_footer(),
  )
}

// -----------------------------------------------------------------------------
// Tool argument schemas
// -----------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanPathArgs {
  pub path: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ScanProposedArgs {
  pub content: String,
  pub file_name: String,
}

// -----------------------------------------------------------------------------
// Tool runner: synchronous core that each MCP tool wraps.
// -----------------------------------------------------------------------------

pub struct ToolRunner {
  workspace: PathBuf,
  options_resolver: Arc<OptionsResolver>,
}

impl ToolRunner {
  pub fn new(
    workspace: PathBuf,
    options_resolver: Arc<OptionsResolver>,
  ) -> Self {
    Self {
      workspace,
      options_resolver,
    }
  }

  pub fn initial_scan(&self) {
    initial_scan(self);
  }

  pub fn scan_path(&self, path: Option<&str>) -> String {
    run_scan_path_tool(self, path)
  }

  pub fn scan_proposed(&self, file_name: &str, content: &str) -> String {
    run_scan_proposed_tool(self, file_name, content)
  }

  pub fn install(&self) -> String {
    run_install_tool(&self.workspace)
  }

  pub fn uninstall(&self) -> String {
    run_uninstall_tool(&self.workspace)
  }

  pub fn status(&self) -> String {
    run_status_tool(&self.workspace)
  }
}

#[derive(Clone)]
pub struct McpServer {
  runner: Arc<ToolRunner>,
  #[allow(dead_code)]
  tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpServer {
  pub fn new(
    workspace: PathBuf,
    options_resolver: Arc<OptionsResolver>,
  ) -> Self {
    let runner = ToolRunner::new(workspace, options_resolver);
    runner.initial_scan();

    Self {
      runner: Arc::new(runner),
      tool_router: Self::tool_router(),
    }
  }

  #[tool(
    description = "Scan an existing file or directory on disk for secrets. For content not yet on disk, use scan_proposed instead. Errors begin with 'trestle:' and describe the next step."
  )]
  async fn scan_path(
    &self,
    Parameters(args): Parameters<ScanPathArgs>,
  ) -> String {
    let runner = self.runner.clone();
    tokio::task::spawn_blocking(move || runner.scan_path(args.path.as_deref()))
      .await
      .unwrap_or_else(|e| internal_error("scan_path", e))
  }

  #[tool(
    description = "Scan proposed file content (not yet on disk) for secrets. Pass the FULL post-change file content (not a diff or snippet) and the workspace-relative file name it will be saved as (e.g. `src/api.ts`). The file extension drives language detection. Errors begin with 'trestle:' and describe the next step."
  )]
  async fn scan_proposed(
    &self,
    Parameters(args): Parameters<ScanProposedArgs>,
  ) -> String {
    let runner = self.runner.clone();
    tokio::task::spawn_blocking(move || {
      runner.scan_proposed(&args.file_name, &args.content)
    })
    .await
    .unwrap_or_else(|e| internal_error("scan_proposed", e))
  }

  #[tool(
    description = "Install trestle into the current workspace (idempotent). Call once per project on first connection."
  )]
  async fn install(&self) -> String {
    let runner = self.runner.clone();
    tokio::task::spawn_blocking(move || runner.install())
      .await
      .unwrap_or_else(|e| internal_error("install", e))
  }

  #[tool(
    description = "Remove trestle from the current workspace. Only call when the user asks for it."
  )]
  async fn uninstall(&self) -> String {
    let runner = self.runner.clone();
    tokio::task::spawn_blocking(move || runner.uninstall())
      .await
      .unwrap_or_else(|e| internal_error("uninstall", e))
  }

  #[tool(
    description = "Return trestle version info, the workspace path, and a short reminder of how to call the other tools. Use to verify trestle is healthy or to reorient mid-session."
  )]
  async fn status(&self) -> String {
    let runner = self.runner.clone();
    tokio::task::spawn_blocking(move || runner.status())
      .await
      .unwrap_or_else(|e| internal_error("status", e))
  }
}

#[tool_handler]
impl ServerHandler for McpServer {
  fn get_info(&self) -> ServerInfo {
    ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
      .with_instructions(server_instructions())
  }
}

// -----------------------------------------------------------------------------
// Tool implementations
// -----------------------------------------------------------------------------

fn build_scan_context(runner: &ToolRunner) -> ScanContext {
  ScanContext::new(runner.options_resolver.clone(), runner.workspace.clone())
}

fn initial_scan(runner: &ToolRunner) {
  let scan = build_scan_context(runner);
  let (diag_tx, diag_rx) = mpsc::channel();
  let run = scan.make_run_context(
    diag_tx,
    #[cfg(feature = "git-history")]
    None,
  );
  process_dir(&run, &runner.workspace);
  drop(run);
  for _ in diag_rx {}
  scan.flush_cache();
}

fn run_scan_path_tool(runner: &ToolRunner, path: Option<&str>) -> String {
  let target = path
    .map(PathBuf::from)
    .unwrap_or_else(|| runner.workspace.clone());

  if !target.exists() {
    return format!(
      "trestle: the path \"{}\" does not exist on disk. If you \
       meant to scan content that has not been written yet, call \
       `scan_proposed` with the full file content and the file \
       name instead. Otherwise verify the path is correct and \
       retry. Do not skip the scan.",
      target.display()
    );
  }

  let scan = build_scan_context(runner);
  let (diag_tx, diag_rx) = mpsc::channel();
  let run = scan.make_run_context_no_cache(diag_tx);

  if target.is_dir() {
    process_dir(&run, &target);
  } else {
    process_files_with_surrounding_context(&run, &[target.clone()]);
  }
  drop(run);

  let diagnostics: Vec<Diagnostic> = diag_rx
    .into_iter()
    .map(|annotated| annotated.diagnostic)
    .collect();
  format_diagnostics(runner, &diagnostics)
}

pub fn empty_file_name_error() -> String {
  "trestle: scan_proposed needs a non-empty `file_name`. Pass the \
   workspace-relative path the content will be saved as (for \
   example `src/api.ts`). The file extension is the only signal \
   trestle has for language detection. Rebuild the call with a \
   real file name and retry. Do not skip the scan."
    .to_string()
}

fn run_scan_proposed_tool(
  runner: &ToolRunner,
  file_name: &str,
  content: &str,
) -> String {
  if file_name.trim().is_empty() {
    return empty_file_name_error();
  }

  let virtual_path = if Path::new(file_name).is_absolute() {
    PathBuf::from(file_name)
  } else {
    runner.workspace.join(file_name)
  };

  let scan = build_scan_context(runner);
  let (diag_tx, diag_rx) = mpsc::channel();
  let run = scan.make_run_context_no_cache(diag_tx);

  process_text(&run, &virtual_path, content);
  run.flush_file_diagnostics();
  drop(run);

  let diagnostics: Vec<Diagnostic> = diag_rx
    .into_iter()
    .map(|annotated| annotated.diagnostic)
    .collect();
  format_diagnostics(runner, &diagnostics)
}

fn format_diagnostics(
  _runner: &ToolRunner,
  diagnostics: &[Diagnostic],
) -> String {
  if diagnostics.is_empty() {
    return NO_SECRETS_FOUND.to_string();
  }

  diagnostics
    .iter()
    .map(|d| format!("{d}"))
    .collect::<Vec<_>>()
    .join("\n")
}

fn run_install_tool(workspace: &Path) -> String {
  let trestle_path = match std::env::current_exe() {
    Ok(p) => p,
    Err(err) => {
      eprintln!("trestle: install could not resolve binary path: {err}");
      return format!(
        "trestle: could not locate the trestle binary on this \
         system (\"{err}\"). The MCP server itself is running, but \
         `install` needs to record the path to the trestle \
         executable in the workspace config and cannot find it. \
         Check that the trestle executable still exists at the path \
         it was launched from, then retry."
      );
    }
  };
  match install::install_in(workspace, &trestle_path) {
    Ok(changes) if changes.is_empty() => ALREADY_INSTALLED.to_string(),
    Ok(changes) => changes
      .iter()
      .map(install::InstallChange::description)
      .collect::<Vec<_>>()
      .join("\n"),
    Err(err) => {
      eprintln!("trestle: install failed: {err}");
      format!(
        "trestle: install failed (\"{err}\"). The workspace was not \
         modified. Check directory permissions and that the \
         workspace path is writable, then retry."
      )
    }
  }
}

fn run_uninstall_tool(workspace: &Path) -> String {
  match install::uninstall_in(workspace) {
    Ok(changes) if changes.is_empty() => NOT_INSTALLED.to_string(),
    Ok(changes) => changes
      .iter()
      .map(install::UninstallChange::description)
      .collect::<Vec<_>>()
      .join("\n"),
    Err(err) => {
      eprintln!("trestle: uninstall failed: {err}");
      format!(
        "trestle: uninstall failed (\"{err}\"). Some files may have \
         been left in place. Check directory permissions and retry."
      )
    }
  }
}

fn run_status_tool(workspace: &Path) -> String {
  format!(
    "trestle {version} is running.\n\
     Workspace: {workspace}\n\n\
     Tools:\n\
     - scan_proposed(file_name, content): scan content not yet on disk.\n\
     - scan_path(path?): scan a file or directory on disk; omit `path` to scan the workspace.\n\
     - install(): install trestle into this workspace (idempotent).\n\
     - uninstall(): remove trestle from this workspace.\n\
     - status(): you are reading it.\n\n\
     Pass full file content to scan_proposed (not a diff or \
     snippet). Every error message begins with `trestle:` and \
     describes the next step. CLI fallback: write the file to disk \
     and run `trestle scan <path>` on it.",
    version = env!("CARGO_PKG_VERSION"),
    workspace = workspace.display(),
  )
}

fn internal_error(op: &str, err: impl std::fmt::Display) -> String {
  eprintln!("trestle: internal error in {op}: {err}");
  format!(
    "trestle: internal error in {op} (\"{err}\"). Retry the same \
     call. If the failure persists, fall back to the CLI: write the \
     file to disk and run `trestle scan <path>` on it. Do not skip \
     the scan."
  )
}

// -----------------------------------------------------------------------------
// Server entry point
// -----------------------------------------------------------------------------

pub fn run(
  options_resolver: Arc<OptionsResolver>,
  abs_dirs: Vec<PathBuf>,
) -> Result<(), String> {
  let workspace = abs_dirs.into_iter().next().ok_or_else(|| {
    "trestle: the mcp command needs a workspace directory. Run \
     `trestle mcp <path>` where <path> is the project root."
      .to_string()
  })?;

  let runtime = tokio::runtime::Runtime::new().map_err(|e| {
    format!(
      "trestle: could not start the async runtime (\"{e}\"). The \
       MCP server cannot run without it."
    )
  })?;

  runtime.block_on(async move {
    let server = McpServer::new(workspace, options_resolver);
    let (input, output) = stdio();
    let service = server.serve((input, output)).await.map_err(|e| {
      format!(
        "trestle: could not start the MCP server on stdio \
         (\"{e}\"). Check that no other process is using the same \
         channel."
      )
    })?;
    let _ = service.waiting().await;
    Ok::<_, String>(())
  })
}
