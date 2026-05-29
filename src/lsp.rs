use std::cell::{Ref, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crossbeam_channel::{Sender, select, unbounded};
use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::{
  CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams,
  CodeActionProviderCapability, CodeActionResponse, CompletionItem,
  CompletionItemKind, CompletionOptions, CompletionParams, CompletionResponse,
  CreateFile, CreateFileOptions, Diagnostic as LspDiagnostic,
  DiagnosticSeverity as LspDiagnosticSeverity, DidChangeTextDocumentParams,
  DidChangeWorkspaceFoldersParams, DidCloseTextDocumentParams,
  DidOpenTextDocumentParams, DocumentChangeOperation, DocumentChanges,
  Documentation, Hover, HoverContents, HoverParams, HoverProviderCapability,
  InitializeResult, LogMessageParams, MarkupContent, MarkupKind, MessageType,
  NumberOrString, OneOf, OptionalVersionedTextDocumentIdentifier,
  Position as LspPosition, PublishDiagnosticsParams, Range, ResourceOp,
  ServerCapabilities, ServerInfo, TextDocumentEdit, TextDocumentSyncCapability,
  TextDocumentSyncKind, TextEdit, Url, WorkspaceEdit,
  WorkspaceFoldersServerCapabilities, WorkspaceServerCapabilities,
};

use crate::config::DEBOUNCE_DURATION;
use crate::diagnostic::{Diagnostic, Severity};
use crate::processing::{
  ScanContext, is_path_skipped, is_path_statically_skipped, process_dir,
  process_text,
};
use crate::source::compute_line_starts;
use crate::trestlerc;

// -----------------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------------

pub fn run(
  options_resolver: Arc<trestlerc::OptionsResolver>,
  abs_dirs: Vec<PathBuf>,
) -> Result<(), String> {
  if abs_dirs.is_empty() {
    return Err(
      "Error: lsp command requires at least one directory path.".to_string(),
    );
  }

  let (connection, io_threads) = Connection::stdio();
  let (fs_tx, fs_rx) = unbounded::<PathBuf>();

  let initialize_value = serde_json::to_value(InitializeResult {
    server_info: Some(ServerInfo {
      name: "trestle".to_string(),
      version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }),
    capabilities: server_capabilities(),
  })
  .map_err(|err| format!("Error: could not build LSP capabilities. {err}"))?;

  let (initialize_id, initialize_params) = connection
    .initialize_start()
    .map_err(|err| format!("Error: LSP initialization failed. {err}"))?;

  let parent_pid = initialize_params
    .get("processId")
    .and_then(|v| v.as_u64())
    .and_then(|v| u32::try_from(v).ok());

  connection
    .initialize_finish(initialize_id, initialize_value)
    .map_err(|err| format!("Error: LSP initialization failed. {err}"))?;

  if let Some(pid) = parent_pid {
    spawn_parent_watcher(pid);
  }

  let workspace = Workspace::new(options_resolver, abs_dirs);
  let session = Session::new(workspace);
  let out = ConnectionOutput {
    sender: connection.sender.clone(),
  };

  out.log("trestle LSP server initialized");

  let mut watchers: HashMap<PathBuf, notify::RecommendedWatcher> =
    HashMap::new();

  let initial_dirs: Vec<PathBuf> = session
    .workspace
    .roots()
    .iter()
    .map(|r| r.abs_dir.clone())
    .collect();

  for dir in initial_dirs {
    match start_fs_watcher(&dir, fs_tx.clone()) {
      Ok(watcher) => {
        watchers.insert(dir, watcher);
      }
      Err(err) => log_recoverable("could not start file watcher", &err),
    }
  }

  session.initial_scan(&out);

  loop {
    let event =
      match wait_for_event(&connection, &fs_rx, session.next_deadline()) {
        LoopEvent::Lsp(message) => message,
        LoopEvent::FsPath(path) => {
          session.schedule_fs_event(Instant::now(), path);
          session.flush(&out, Instant::now());
          continue;
        }
        LoopEvent::Tick => {
          session.flush(&out, Instant::now());
          continue;
        }
        LoopEvent::Shutdown => break,
      };

    match event {
      Message::Request(request) => match connection.handle_shutdown(&request) {
        Ok(true) => break,
        Ok(false) => handle_request(&session, &connection.sender, request),
        Err(err) => log_recoverable("failed handling shutdown request", &err),
      },
      Message::Notification(notification) => {
        handle_notification(&session, &out, &fs_tx, &mut watchers, notification)
      }
      Message::Response(_) => {}
    }

    session.flush(&out, Instant::now());
  }

  drop(watchers);
  drop(connection);

  io_threads
    .join()
    .map_err(|err| format!("Error: LSP io threads failed. {err}"))?;

  Ok(())
}

fn server_capabilities() -> ServerCapabilities {
  ServerCapabilities {
    text_document_sync: Some(TextDocumentSyncCapability::Kind(
      TextDocumentSyncKind::FULL,
    )),
    hover_provider: Some(HoverProviderCapability::Simple(true)),
    completion_provider: Some(CompletionOptions::default()),
    code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
    workspace: Some(WorkspaceServerCapabilities {
      workspace_folders: Some(WorkspaceFoldersServerCapabilities {
        supported: Some(true),
        change_notifications: Some(OneOf::Left(true)),
      }),
      file_operations: None,
    }),
    ..ServerCapabilities::default()
  }
}

enum LoopEvent {
  Lsp(Message),
  FsPath(PathBuf),
  Tick,
  Shutdown,
}

fn wait_for_event(
  connection: &Connection,
  fs_rx: &crossbeam_channel::Receiver<PathBuf>,
  deadline: Option<Instant>,
) -> LoopEvent {
  match deadline {
    None => select! {
      recv(connection.receiver) -> msg => match msg {
        Ok(m) => LoopEvent::Lsp(m),
        Err(_) => LoopEvent::Shutdown,
      },
      recv(fs_rx) -> path => match path {
        Ok(p) => LoopEvent::FsPath(p),
        Err(_) => LoopEvent::Shutdown,
      },
    },
    Some(d) => {
      let timeout = d.saturating_duration_since(Instant::now());
      select! {
        recv(connection.receiver) -> msg => match msg {
          Ok(m) => LoopEvent::Lsp(m),
          Err(_) => LoopEvent::Shutdown,
        },
        recv(fs_rx) -> path => match path {
          Ok(p) => LoopEvent::FsPath(p),
          Err(_) => LoopEvent::Shutdown,
        },
        default(timeout) => LoopEvent::Tick,
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Output trait - abstracts what the client sees
// -----------------------------------------------------------------------------

pub trait Output {
  fn publish_diagnostics(
    &self,
    uri: Url,
    diagnostics: Vec<LspDiagnostic>,
    version: Option<i32>,
  );

  fn log(&self, message: &str);
}

struct ConnectionOutput {
  sender: Sender<Message>,
}

impl Output for ConnectionOutput {
  fn publish_diagnostics(
    &self,
    uri: Url,
    diagnostics: Vec<LspDiagnostic>,
    version: Option<i32>,
  ) {
    let params = PublishDiagnosticsParams {
      uri,
      diagnostics,
      version,
    };
    let notification =
      Notification::new("textDocument/publishDiagnostics".to_string(), params);
    if let Err(err) = self.sender.send(Message::Notification(notification)) {
      log_recoverable("failed publishing diagnostics", &err);
    }
  }

  fn log(&self, message: &str) {
    let params = LogMessageParams {
      typ: MessageType::INFO,
      message: message.to_string(),
    };
    let notification =
      Notification::new("window/logMessage".to_string(), params);
    if let Err(err) = self.sender.send(Message::Notification(notification)) {
      log_recoverable("failed sending log message", &err);
    }
  }
}

fn log_recoverable(context: &str, err: &dyn std::fmt::Display) {
  eprintln!("trestle lsp: {context}: {err}");
}

// -----------------------------------------------------------------------------
// Session - LSP state machine
//
// Per-URI state lives in `documents`. `buffer_pending` and `fs_pending`
// hold deferred rescan deadlines. All output goes through `Output`.
// -----------------------------------------------------------------------------

pub struct Session {
  workspace: Workspace,
  documents: RefCell<HashMap<Url, DocumentEntry>>,
  pending: RefCell<HashMap<RescanKey, Instant>>,
}

#[derive(Default)]
struct DocumentEntry {
  buffer_text: Option<String>,
  buffer_version: Option<i32>,
  published_diagnostics: Vec<LspDiagnostic>,
  published_hovers: Vec<HoverEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RescanKey {
  Buffer(Url),
  Disk(PathBuf),
}

impl Session {
  pub fn new(workspace: Workspace) -> Self {
    Self {
      workspace,
      documents: RefCell::new(HashMap::new()),
      pending: RefCell::new(HashMap::new()),
    }
  }

  pub fn initial_scan<O: Output>(&self, out: &O) {
    let dirs: Vec<PathBuf> = self
      .workspace
      .roots()
      .iter()
      .map(|r| r.abs_dir.clone())
      .collect();

    for dir in &dirs {
      self.scan_root(out, dir);
      self.publish_trestlerc(out, dir);
    }
  }

  pub fn next_deadline(&self) -> Option<Instant> {
    self.pending.borrow().values().copied().min()
  }

  pub fn flush<O: Output>(&self, out: &O, now: Instant) {
    let ready: Vec<RescanKey> = self
      .pending
      .borrow()
      .iter()
      .filter(|(_, deadline)| **deadline <= now)
      .map(|(key, _)| key.clone())
      .collect();

    for key in ready {
      self.pending.borrow_mut().remove(&key);
      match key {
        RescanKey::Buffer(uri) => self.rescan_buffer(out, &uri),
        RescanKey::Disk(path) => self.handle_fs_path(out, &path),
      }
    }
  }

  // -----------------------------------------------------------------------------
  // didOpen / didChange / didClose
  // -----------------------------------------------------------------------------

  pub fn open<O: Output>(&self, out: &O, uri: Url, text: String, version: i32) {
    {
      let mut docs = self.documents.borrow_mut();
      let entry = docs.entry(uri.clone()).or_default();
      entry.buffer_text = Some(text);
      entry.buffer_version = Some(version);
    }

    self.rescan_buffer(out, &uri);
  }

  pub fn change(&self, now: Instant, uri: Url, text: String, version: i32) {
    {
      let mut docs = self.documents.borrow_mut();
      let entry = docs.entry(uri.clone()).or_default();
      entry.buffer_text = Some(text);
      entry.buffer_version = Some(version);
    }

    self
      .pending
      .borrow_mut()
      .insert(RescanKey::Buffer(uri), now + DEBOUNCE_DURATION);
  }

  pub fn close(&self, uri: Url) {
    self
      .pending
      .borrow_mut()
      .remove(&RescanKey::Buffer(uri.clone()));
    let mut docs = self.documents.borrow_mut();
    if let Some(entry) = docs.get_mut(&uri) {
      entry.buffer_text = None;
      entry.buffer_version = None;

      // Keep the entry as long as it still has published findings;
      // editors expect the displayed diagnostics to persist after a
      // buffer is closed.
      if entry.published_diagnostics.is_empty() {
        docs.remove(&uri);
      }
    }
  }

  // -----------------------------------------------------------------------------
  // FS events - debounced, classified at flush time
  // -----------------------------------------------------------------------------

  pub fn schedule_fs_event(&self, now: Instant, path: PathBuf) {
    if self.workspace.is_path_statically_skipped(&path) {
      return;
    }

    self
      .pending
      .borrow_mut()
      .insert(RescanKey::Disk(path), now + DEBOUNCE_DURATION);
  }

  fn handle_fs_path<O: Output>(&self, out: &O, path: &Path) {
    if Url::from_file_path(path).is_err() {
      return;
    }

    if trestlerc::is_trestlerc(path) {
      self.refresh_trestlerc(out, path);
      return;
    }

    if is_gitignore_file(path) {
      self.refresh_gitignore(out, path);
      return;
    }

    self.handle_disk_file_change(out, path);
  }

  fn refresh_gitignore<O: Output>(&self, out: &O, path: &Path) {
    let Some(root_dir) = self.workspace.reload_root_git_for_path(path) else {
      return;
    };
    self.scan_root(out, &root_dir);
    self.rescan_open_buffers_under(out, &root_dir);
  }

  fn handle_disk_file_change<O: Output>(&self, out: &O, path: &Path) {
    let Ok(uri) = Url::from_file_path(path) else {
      return;
    };

    if self
      .documents
      .borrow()
      .get(&uri)
      .map(|e| e.buffer_text.is_some())
      .unwrap_or(false)
    {
      // The editor owns the buffer; disk events are stale relative to
      // the in-memory text. didChange will re-scan with the correct
      // content.
      return;
    }

    if !path.is_file() {
      // Deletion: if we'd previously published findings, clear them.
      self.publish(out, uri, Vec::new(), Vec::new(), None);
      return;
    }

    let Ok(text) = std::fs::read_to_string(path) else {
      return;
    };
    let (diagnostics, hovers) = self.workspace.scan_document(&uri, &text);
    self.publish(out, uri, diagnostics, hovers, None);
  }

  // -----------------------------------------------------------------------------
  // Workspace folder add / remove
  // -----------------------------------------------------------------------------

  pub fn add_root<O: Output>(&self, out: &O, dir: PathBuf) -> bool {
    if !self.workspace.add_root(dir.clone()) {
      return false;
    }
    self.publish_trestlerc(out, &dir);
    self.scan_root(out, &dir);
    true
  }

  pub fn remove_root<O: Output>(&self, out: &O, dir: &Path) -> bool {
    if !self.workspace.remove_root(dir) {
      return false;
    }
    self.clear_findings_under(out, dir);
    true
  }

  // ---------------------------------------------------------------------------
  // Hover / completion / code action - pure queries
  // ---------------------------------------------------------------------------

  pub fn hover(&self, uri: &Url, position: LspPosition) -> Option<Hover> {
    let docs = self.documents.borrow();
    let entry = docs.get(uri)?;
    let hover_entry = entry
      .published_hovers
      .iter()
      .find(|h| range_contains(h.range, position))?;
    Some(Hover {
      contents: HoverContents::Markup(MarkupContent {
        kind: MarkupKind::Markdown,
        value: hover_entry.markdown.clone(),
      }),
      range: Some(hover_entry.range),
    })
  }

  pub fn completion(
    &self,
    uri: &Url,
    position: LspPosition,
  ) -> Vec<CompletionItem> {
    let Ok(path) = uri.to_file_path() else {
      return Vec::new();
    };

    if !trestlerc::is_trestlerc(&path) {
      return Vec::new();
    }

    let docs = self.documents.borrow();
    let Some(entry) = docs.get(uri) else {
      return Vec::new();
    };

    let Some(text) = entry.buffer_text.as_deref() else {
      return Vec::new();
    };

    trestlerc_completions(text, position)
  }

  pub fn code_action(&self, params: &CodeActionParams) -> Vec<CodeAction> {
    let Ok(file_path) = params.text_document.uri.to_file_path() else {
      return Vec::new();
    };

    if trestlerc::is_trestlerc(&file_path) {
      return Vec::new();
    }

    let Some(root_dir) = self.workspace.root_dir_for_path(&file_path) else {
      return Vec::new();
    };

    let trestle_diagnostics: Vec<LspDiagnostic> = params
      .context
      .diagnostics
      .iter()
      .filter(|d| d.source.as_deref() == Some("trestle"))
      .cloned()
      .collect();

    if trestle_diagnostics.is_empty() {
      return Vec::new();
    }

    match build_ignore_file_action(&root_dir, &file_path, trestle_diagnostics) {
      Some(action) => vec![action],
      None => Vec::new(),
    }
  }

  // ---------------------------------------------------------------------------
  // Scan + publish helpers
  // ---------------------------------------------------------------------------

  fn rescan_buffer<O: Output>(&self, out: &O, uri: &Url) {
    let snapshot =
      self.documents.borrow().get(uri).and_then(|e| {
        e.buffer_text.clone().map(|text| (text, e.buffer_version))
      });

    let Some((text, version)) = snapshot else {
      return;
    };

    let (diagnostics, hovers) = self.workspace.scan_document(uri, &text);
    self.publish(out, uri.clone(), diagnostics, hovers, version);
  }

  fn scan_root<O: Output>(&self, out: &O, dir: &Path) {
    let findings = self.workspace.scan_root(dir);
    let prev_uris: Vec<Url> = self.published_uris_under(dir);

    let touched: std::collections::HashSet<Url> =
      findings.keys().cloned().collect();

    for (uri, (diagnostics, hovers)) in findings {
      self.publish(out, uri, diagnostics, hovers, None);
    }

    for uri in prev_uris {
      if !touched.contains(&uri) && !self.has_open_buffer(&uri) {
        self.publish(out, uri, Vec::new(), Vec::new(), None);
      }
    }
  }

  fn refresh_trestlerc<O: Output>(&self, out: &O, path: &Path) {
    let Some(root_dir) = self.workspace.reload_root_for_trestlerc_path(path)
    else {
      return;
    };
    self.publish_trestlerc(out, &root_dir);
    self.scan_root(out, &root_dir);
    self.rescan_open_buffers_under(out, &root_dir);
  }

  fn publish_trestlerc<O: Output>(&self, out: &O, dir: &Path) {
    let path = dir.join(trestlerc::FILE_NAME);
    let Ok(uri) = Url::from_file_path(&path) else {
      return;
    };

    if !path.is_file() {
      self.publish(out, uri, Vec::new(), Vec::new(), None);
      return;
    }

    let Ok(text) = std::fs::read_to_string(&path) else {
      return;
    };

    let (diagnostics, hovers) = analyze_trestlerc(&text);
    self.publish(out, uri, diagnostics, hovers, None);
  }

  fn rescan_open_buffers_under<O: Output>(&self, out: &O, dir: &Path) {
    let open: Vec<Url> = self
      .documents
      .borrow()
      .iter()
      .filter(|(uri, e)| e.buffer_text.is_some() && uri_under(uri, dir))
      .map(|(uri, _)| uri.clone())
      .collect();

    for uri in open {
      self.rescan_buffer(out, &uri);
    }
  }

  fn clear_findings_under<O: Output>(&self, out: &O, dir: &Path) {
    for uri in self.published_uris_under(dir) {
      self.publish(out, uri, Vec::new(), Vec::new(), None);
    }
  }

  fn published_uris_under(&self, dir: &Path) -> Vec<Url> {
    self
      .documents
      .borrow()
      .iter()
      .filter(|(uri, e)| {
        !e.published_diagnostics.is_empty() && uri_under(uri, dir)
      })
      .map(|(uri, _)| uri.clone())
      .collect()
  }

  fn has_open_buffer(&self, uri: &Url) -> bool {
    self
      .documents
      .borrow()
      .get(uri)
      .map(|e| e.buffer_text.is_some())
      .unwrap_or(false)
  }

  fn publish<O: Output>(
    &self,
    out: &O,
    uri: Url,
    diagnostics: Vec<LspDiagnostic>,
    hovers: Vec<HoverEntry>,
    version: Option<i32>,
  ) {
    let mut docs = self.documents.borrow_mut();
    let entry = docs.entry(uri.clone()).or_default();

    let was_empty = entry.published_diagnostics.is_empty();
    let is_empty = diagnostics.is_empty();

    if was_empty && is_empty {
      if entry.buffer_text.is_none() {
        docs.remove(&uri);
      }
      return;
    }

    out.publish_diagnostics(uri.clone(), diagnostics.clone(), version);
    entry.published_diagnostics = diagnostics;
    entry.published_hovers = hovers;

    if entry.published_diagnostics.is_empty() && entry.buffer_text.is_none() {
      docs.remove(&uri);
    }
  }
}

// -----------------------------------------------------------------------------
// Notification / request dispatch
// -----------------------------------------------------------------------------

fn handle_notification<O: Output>(
  session: &Session,
  out: &O,
  fs_tx: &Sender<PathBuf>,
  watchers: &mut HashMap<PathBuf, notify::RecommendedWatcher>,
  notification: Notification,
) {
  match notification.method.as_str() {
    "textDocument/didOpen" => {
      if let Some(p) = parse_params::<DidOpenTextDocumentParams>(
        notification.params,
        "didOpen",
      ) {
        let doc = p.text_document;
        session.open(out, doc.uri, doc.text, doc.version);
      }
    }
    "textDocument/didChange" => {
      if let Some(p) = parse_params::<DidChangeTextDocumentParams>(
        notification.params,
        "didChange",
      ) {
        let uri = p.text_document.uri;
        let version = p.text_document.version;

        if let Some(change) = p.content_changes.into_iter().last() {
          session.change(Instant::now(), uri, change.text, version);
        }
      }
    }
    "textDocument/didClose" => {
      if let Some(p) = parse_params::<DidCloseTextDocumentParams>(
        notification.params,
        "didClose",
      ) {
        session.close(p.text_document.uri);
      }
    }
    "workspace/didChangeWorkspaceFolders" => {
      if let Some(p) = parse_params::<DidChangeWorkspaceFoldersParams>(
        notification.params,
        "didChangeWorkspaceFolders",
      ) {
        for added in p.event.added {
          if let Ok(dir) = added.uri.to_file_path() {
            if session.add_root(out, dir.clone()) {
              match start_fs_watcher(&dir, fs_tx.clone()) {
                Ok(w) => {
                  watchers.insert(dir, w);
                }
                Err(err) => log_recoverable(
                  "could not start watcher for added workspace root",
                  &err,
                ),
              }
            }
          }
        }

        for removed in p.event.removed {
          if let Ok(dir) = removed.uri.to_file_path() {
            watchers.remove(&dir);
            session.remove_root(out, &dir);
          }
        }
      }
    }
    _ => {}
  }
}

fn handle_request(
  session: &Session,
  sender: &Sender<Message>,
  request: Request,
) {
  match request.method.as_str() {
    "textDocument/hover" => {
      if let Some(p) = parse_params::<HoverParams>(request.params, "hover") {
        let uri = p.text_document_position_params.text_document.uri;
        let position = p.text_document_position_params.position;
        respond(sender, request.id, &session.hover(&uri, position));
      }
    }
    "textDocument/completion" => {
      if let Some(p) =
        parse_params::<CompletionParams>(request.params, "completion")
      {
        let uri = p.text_document_position.text_document.uri;
        let position = p.text_document_position.position;
        let items = session.completion(&uri, position);
        let response: Option<CompletionResponse> = if items.is_empty() {
          None
        } else {
          Some(CompletionResponse::Array(items))
        };
        respond(sender, request.id, &response);
      }
    }
    "textDocument/codeAction" => {
      if let Some(p) =
        parse_params::<CodeActionParams>(request.params, "codeAction")
      {
        let actions: CodeActionResponse = session
          .code_action(&p)
          .into_iter()
          .map(CodeActionOrCommand::CodeAction)
          .collect();
        respond(sender, request.id, &actions);
      }
    }
    _ => {}
  }
}

fn respond<T: serde::Serialize>(
  sender: &Sender<Message>,
  id: lsp_server::RequestId,
  value: &T,
) {
  let result = match serde_json::to_value(value) {
    Ok(v) => v,
    Err(err) => {
      log_recoverable("could not serialize response", &err);
      return;
    }
  };

  let response = Response {
    id,
    result: Some(result),
    error: None,
  };

  if let Err(err) = sender.send(Message::Response(response)) {
    log_recoverable("failed sending response", &err);
  }
}

// -----------------------------------------------------------------------------
// Workspace
// -----------------------------------------------------------------------------

pub struct Workspace {
  roots: RefCell<Vec<RootContext>>,
  ephemeral_roots: RefCell<HashMap<PathBuf, RootContext>>,
  options_resolver: Arc<trestlerc::OptionsResolver>,
}

impl Workspace {
  pub fn new(
    options_resolver: Arc<trestlerc::OptionsResolver>,
    abs_dirs: Vec<PathBuf>,
  ) -> Self {
    let roots: Vec<RootContext> = abs_dirs
      .into_iter()
      .map(|dir| RootContext::new(options_resolver.clone(), dir))
      .collect();

    Self {
      roots: RefCell::new(roots),
      ephemeral_roots: RefCell::new(HashMap::new()),
      options_resolver,
    }
  }

  pub fn roots(&self) -> Ref<'_, Vec<RootContext>> {
    self.roots.borrow()
  }

  pub fn root_dir_for_path(&self, path: &Path) -> Option<PathBuf> {
    let roots = self.roots.borrow();
    roots
      .iter()
      .filter(|r| path.starts_with(&r.abs_dir))
      .max_by_key(|r| r.abs_dir.as_os_str().len())
      .map(|r| r.abs_dir.clone())
  }

  pub fn scan_document(
    &self,
    uri: &Url,
    text: &str,
  ) -> (Vec<LspDiagnostic>, Vec<HoverEntry>) {
    let Ok(path) = uri.to_file_path() else {
      return (Vec::new(), Vec::new());
    };
    if trestlerc::is_trestlerc(&path) {
      return analyze_trestlerc(text);
    }

    {
      let roots = self.roots.borrow();
      if let Some(root) = pick_root(&roots, &path) {
        return scan_in_root(root, &path, text);
      }
    }

    let Some(ephemeral_dir) = ephemeral_root_dir(&path) else {
      return (Vec::new(), Vec::new());
    };

    let resolver = self.options_resolver.clone();
    let mut ephemeral = self.ephemeral_roots.borrow_mut();
    let root = ephemeral
      .entry(ephemeral_dir.clone())
      .or_insert_with(|| RootContext::new(resolver, ephemeral_dir));

    scan_in_root(root, &path, text)
  }

  pub fn scan_root(
    &self,
    root_dir: &Path,
  ) -> HashMap<Url, (Vec<LspDiagnostic>, Vec<HoverEntry>)> {
    let (diag_tx, diag_rx) = mpsc::channel();

    let roots = self.roots.borrow();
    let Some(root) = roots.iter().find(|r| r.abs_dir == root_dir) else {
      return HashMap::new();
    };

    {
      let scan = root.scan.borrow();
      let run_context = scan.make_run_context(
        diag_tx,
        #[cfg(feature = "git-history")]
        None,
      );
      process_dir(&run_context, &root.abs_dir);
      drop(run_context);
      scan.flush_cache();
    }

    let mut by_uri: HashMap<Url, (Vec<LspDiagnostic>, Vec<HoverEntry>)> =
      HashMap::new();

    for annotated in diag_rx {
      let diagnostic = annotated.diagnostic;
      let path = diagnostic.file_abs_path().to_path_buf();
      let Ok(uri) = Url::from_file_path(&path) else {
        continue;
      };
      let range = diagnostic_range(&diagnostic);
      let lsp_diag = to_lsp_diagnostic(diagnostic, range);
      let entry = by_uri.entry(uri).or_default();
      entry.0.push(lsp_diag);
    }

    by_uri
  }

  pub fn reload_root_for_trestlerc_path(&self, path: &Path) -> Option<PathBuf> {
    self.options_resolver.clear();
    let root_dir = self.root_dir_for_path(path)?;
    let roots = self.roots.borrow();
    if let Some(root) = roots.iter().find(|r| r.abs_dir == root_dir) {
      root.reload();
    }

    self.invalidate_ephemeral_roots();

    Some(root_dir)
  }

  pub fn reload_root_git_for_path(&self, path: &Path) -> Option<PathBuf> {
    let root_dir = self.root_dir_for_path(path)?;
    let roots = self.roots.borrow();
    if let Some(root) = roots.iter().find(|r| r.abs_dir == root_dir) {
      root.reload();
    }

    self.invalidate_ephemeral_roots();

    Some(root_dir)
  }

  fn invalidate_ephemeral_roots(&self) {
    self.ephemeral_roots.borrow_mut().clear();
  }

  pub fn is_path_statically_skipped(&self, path: &Path) -> bool {
    let roots = self.roots.borrow();
    let Some(root) = pick_root(&roots, path) else {
      return true;
    };

    let scan = root.scan.borrow();

    let (diag_tx, _diag_rx) = mpsc::channel();

    let run_context = scan.make_run_context_no_cache(diag_tx);

    is_path_statically_skipped(&run_context, path)
  }

  fn add_root(&self, dir: PathBuf) -> bool {
    let mut roots = self.roots.borrow_mut();
    if roots.iter().any(|r| r.abs_dir == dir) {
      return false;
    }
    roots.push(RootContext::new(self.options_resolver.clone(), dir));
    true
  }

  fn remove_root(&self, dir: &Path) -> bool {
    let mut roots = self.roots.borrow_mut();
    let before = roots.len();
    roots.retain(|r| r.abs_dir != dir);
    roots.len() != before
  }
}

fn pick_root<'a>(
  roots: &'a [RootContext],
  path: &Path,
) -> Option<&'a RootContext> {
  roots
    .iter()
    .filter(|r| path.starts_with(&r.abs_dir))
    .max_by_key(|r| r.abs_dir.as_os_str().len())
}

fn scan_in_root(
  root: &RootContext,
  path: &Path,
  text: &str,
) -> (Vec<LspDiagnostic>, Vec<HoverEntry>) {
  let (diag_tx, diag_rx) = mpsc::channel();
  let scan = root.scan.borrow();

  let run_context = scan.make_run_context_no_cache(diag_tx);

  if is_path_skipped(&run_context, path) {
    drop(run_context);
    return (Vec::new(), Vec::new());
  }

  let path_buf = path.to_path_buf();

  process_text(&run_context, &path_buf, text);
  run_context.flush_file_diagnostics();

  drop(run_context);
  drop(scan);

  let mut diagnostics = Vec::new();
  let hovers = Vec::new();

  for annotated in diag_rx {
    let diagnostic = annotated.diagnostic;
    let range = diagnostic_range(&diagnostic);
    diagnostics.push(to_lsp_diagnostic(diagnostic, range));
  }

  (diagnostics, hovers)
}

fn ephemeral_root_dir(path: &Path) -> Option<PathBuf> {
  let parent = path.parent()?;

  if let Some(repo) = crate::git::open(parent) {
    return Some(repo.workdir().to_path_buf());
  }

  Some(parent.to_path_buf())
}

pub struct RootContext {
  pub abs_dir: PathBuf,
  options_resolver: Arc<trestlerc::OptionsResolver>,
  scan: RefCell<ScanContext>,
}

impl RootContext {
  pub fn new(
    options_resolver: Arc<trestlerc::OptionsResolver>,
    abs_dir: PathBuf,
  ) -> Self {
    let scan = ScanContext::new(options_resolver.clone(), abs_dir.clone());

    Self {
      abs_dir,
      options_resolver,
      scan: RefCell::new(scan),
    }
  }

  pub fn reload(&self) {
    let mut scan = self.scan.borrow_mut();
    scan.flush_cache();
    *scan =
      ScanContext::new(self.options_resolver.clone(), self.abs_dir.clone());
  }
}

#[derive(Debug, Clone)]
pub struct HoverEntry {
  pub range: Range,
  pub markdown: String,
}

// -----------------------------------------------------------------------------
// Parent process watcher
// -----------------------------------------------------------------------------

const PARENT_POLL_INTERVAL: Duration = Duration::from_secs(2);

fn spawn_parent_watcher(pid: u32) {
  std::thread::spawn(move || {
    loop {
      std::thread::sleep(PARENT_POLL_INTERVAL);
      if !parent_alive(pid) {
        std::process::exit(0);
      }
    }
  });
}

#[cfg(unix)]
fn parent_alive(pid: u32) -> bool {
  let Ok(pid) = libc::pid_t::try_from(pid) else {
    return false;
  };

  if unsafe { libc::kill(pid, 0) } == 0 {
    return true;
  }

  std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn parent_alive(pid: u32) -> bool {
  use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
  use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
  };

  unsafe {
    let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
    if handle.is_null() {
      return false;
    }
    let result = WaitForSingleObject(handle, 0);
    CloseHandle(handle);
    result == WAIT_TIMEOUT
  }
}

// -----------------------------------------------------------------------------
// FS watcher
// -----------------------------------------------------------------------------

fn start_fs_watcher(
  root: &Path,
  fs_tx: Sender<PathBuf>,
) -> Result<notify::RecommendedWatcher, String> {
  let mut watcher =
    notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
      if let Ok(event) = res {
        for path in event.paths {
          fs_tx.send(path).ok();
        }
      }
    })
    .map_err(|err| format!("Error: could not start file watcher. {err}"))?;

  notify::Watcher::watch(&mut watcher, root, notify::RecursiveMode::Recursive)
    .map_err(|err| format!("Error: could not watch directory. {err}"))?;

  Ok(watcher)
}

fn is_gitignore_file(path: &Path) -> bool {
  path.file_name().and_then(|n| n.to_str()) == Some(".gitignore")
}

// -----------------------------------------------------------------------------
// Trestlerc analysis + completion
// -----------------------------------------------------------------------------

pub fn analyze_trestlerc(text: &str) -> (Vec<LspDiagnostic>, Vec<HoverEntry>) {
  let report = trestlerc::analyze(text);
  let line_starts = compute_line_starts(text);

  let diagnostics: Vec<LspDiagnostic> = report
    .issues
    .into_iter()
    .map(|issue| LspDiagnostic {
      range: byte_span_to_range(&line_starts, &issue.span),
      severity: Some(LspDiagnosticSeverity::WARNING),
      code: None,
      code_description: None,
      source: Some("trestle".to_string()),
      message: issue.message,
      related_information: None,
      tags: None,
      data: None,
    })
    .collect();

  let hovers: Vec<HoverEntry> = report
    .hovers
    .into_iter()
    .map(|hover| HoverEntry {
      range: byte_span_to_range(&line_starts, &hover.span),
      markdown: hover.markdown,
    })
    .collect();

  (diagnostics, hovers)
}

pub fn trestlerc_completions(
  text: &str,
  position: LspPosition,
) -> Vec<CompletionItem> {
  let line_starts = compute_line_starts(text);
  let Some(byte_offset) = position_to_byte_offset(&line_starts, text, position)
  else {
    return Vec::new();
  };

  trestlerc::complete(text, byte_offset)
    .into_iter()
    .map(completion_to_item)
    .collect()
}

fn completion_to_item(completion: trestlerc::Completion) -> CompletionItem {
  let kind = match completion.kind {
    trestlerc::CompletionKind::Option => CompletionItemKind::PROPERTY,
    trestlerc::CompletionKind::Value => CompletionItemKind::VALUE,
  };
  let documentation = if completion.documentation.is_empty() {
    None
  } else {
    Some(Documentation::MarkupContent(MarkupContent {
      kind: MarkupKind::Markdown,
      value: completion.documentation,
    }))
  };

  CompletionItem {
    label: completion.label,
    kind: Some(kind),
    detail: Some(completion.detail),
    documentation,
    ..CompletionItem::default()
  }
}

// -----------------------------------------------------------------------------
// Code actions
// -----------------------------------------------------------------------------

pub fn build_ignore_file_action(
  root_dir: &Path,
  file_path: &Path,
  diagnostics: Vec<LspDiagnostic>,
) -> Option<CodeAction> {
  let entry = relative_glob_entry(root_dir, file_path)?;

  let trestlerc_path = root_dir.join(trestlerc::FILE_NAME);
  let trestlerc_uri = Url::from_file_path(&trestlerc_path).ok()?;
  let trestlerc_exists = trestlerc_path.is_file();
  let existing_text = if trestlerc_exists {
    std::fs::read_to_string(&trestlerc_path).unwrap_or_default()
  } else {
    String::new()
  };

  let new_text = trestlerc::add_skip_glob_entry(&existing_text, &entry)?;

  let edit = whole_file_edit(&existing_text, new_text);
  let text_doc_edit = TextDocumentEdit {
    text_document: OptionalVersionedTextDocumentIdentifier {
      uri: trestlerc_uri.clone(),
      version: None,
    },
    edits: vec![OneOf::Left(edit)],
  };

  let document_changes = if trestlerc_exists {
    DocumentChanges::Edits(vec![text_doc_edit])
  } else {
    DocumentChanges::Operations(vec![
      DocumentChangeOperation::Op(ResourceOp::Create(CreateFile {
        uri: trestlerc_uri,
        options: Some(CreateFileOptions {
          overwrite: Some(false),
          ignore_if_exists: Some(true),
        }),
        annotation_id: None,
      })),
      DocumentChangeOperation::Edit(text_doc_edit),
    ])
  };

  Some(CodeAction {
    title: format!("Ignore \"{entry}\""),
    kind: Some(CodeActionKind::QUICKFIX),
    diagnostics: Some(diagnostics),
    edit: Some(WorkspaceEdit {
      changes: None,
      document_changes: Some(document_changes),
      change_annotations: None,
    }),
    command: None,
    is_preferred: None,
    disabled: None,
    data: None,
  })
}

pub fn relative_glob_entry(
  root_dir: &Path,
  file_path: &Path,
) -> Option<String> {
  let rel = file_path.strip_prefix(root_dir).ok()?;
  let mut parts: Vec<String> = Vec::new();
  for component in rel.components() {
    let part = component.as_os_str().to_str()?;
    parts.push(part.to_owned());
  }
  if parts.is_empty() {
    return None;
  }
  Some(parts.join("/"))
}

fn whole_file_edit(existing: &str, new_text: String) -> TextEdit {
  let line_starts = compute_line_starts(existing);
  let last_line_idx = line_starts.len().saturating_sub(1);
  let last_line_start = line_starts.last().copied().unwrap_or(0);
  let last_line_len = existing.len().saturating_sub(last_line_start);
  let end = LspPosition::new(last_line_idx as u32, last_line_len as u32);

  TextEdit {
    range: Range::new(LspPosition::new(0, 0), end),
    new_text,
  }
}

// -----------------------------------------------------------------------------
// Diagnostic conversion
// -----------------------------------------------------------------------------

pub fn diagnostic_range(diagnostic: &Diagnostic) -> Range {
  match diagnostic {
    Diagnostic::SecretAssignment { source_span, .. }
    | Diagnostic::SecretValue { source_span, .. } => {
      if let Some(span) = &source_span.file_span {
        let start_line = (span.start.line.saturating_sub(1)) as u32;
        let start_col = (span.start.column.saturating_sub(1)) as u32;
        let end_line = (span.end.line.saturating_sub(1)) as u32;
        let end_col = (span.end.column.saturating_sub(1)) as u32;
        Range::new(
          LspPosition::new(start_line, start_col),
          LspPosition::new(end_line, end_col),
        )
      } else {
        Range::new(LspPosition::new(0, 0), LspPosition::new(0, 1))
      }
    }
    Diagnostic::BinarySecret { .. } | Diagnostic::TextSecret { .. } => {
      Range::new(LspPosition::new(0, 0), LspPosition::new(0, 1))
    }
  }
}

pub fn to_lsp_diagnostic(
  diagnostic: Diagnostic,
  range: Range,
) -> LspDiagnostic {
  let severity = match diagnostic.severity() {
    Severity::Critical => Some(LspDiagnosticSeverity::ERROR),
    Severity::Warning => Some(LspDiagnosticSeverity::WARNING),
  };
  let code = Some(NumberOrString::String(diagnostic.id().to_owned()));
  LspDiagnostic {
    range,
    severity,
    code,
    code_description: None,
    source: Some("trestle".to_string()),
    message: diagnostic.message(),
    related_information: None,
    tags: None,
    data: None,
  }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn byte_span_to_range(
  line_starts: &[usize],
  span: &trestlerc::ByteSpan,
) -> Range {
  Range::new(
    byte_offset_to_position(line_starts, span.start),
    byte_offset_to_position(line_starts, span.end),
  )
}

fn byte_offset_to_position(
  line_starts: &[usize],
  offset: usize,
) -> LspPosition {
  let line_idx = line_starts
    .partition_point(|&start| start <= offset)
    .saturating_sub(1);
  let line_start = line_starts.get(line_idx).copied().unwrap_or(0);
  LspPosition::new(line_idx as u32, (offset.saturating_sub(line_start)) as u32)
}

fn position_to_byte_offset(
  line_starts: &[usize],
  text: &str,
  position: LspPosition,
) -> Option<usize> {
  let line_start = line_starts.get(position.line as usize).copied()?;
  let line_end = line_starts
    .get(position.line as usize + 1)
    .copied()
    .unwrap_or(text.len());
  let column = position.character as usize;
  Some(line_start.saturating_add(column).min(line_end))
}

fn range_contains(range: Range, position: LspPosition) -> bool {
  let at_or_after_start = position.line > range.start.line
    || (position.line == range.start.line
      && position.character >= range.start.character);
  let before_end = position.line < range.end.line
    || (position.line == range.end.line
      && position.character < range.end.character);
  at_or_after_start && before_end
}

fn uri_under(uri: &Url, dir: &Path) -> bool {
  uri
    .to_file_path()
    .map(|p| p.starts_with(dir))
    .unwrap_or(false)
}

fn parse_params<T: serde::de::DeserializeOwned>(
  raw: serde_json::Value,
  what: &str,
) -> Option<T> {
  match serde_json::from_value(raw) {
    Ok(p) => Some(p),
    Err(err) => {
      log_recoverable(&format!("invalid {what} params"), &err);
      None
    }
  }
}
