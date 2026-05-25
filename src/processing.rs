use std::{
  cell::{Cell, OnceCell, RefCell},
  fs::{self, read_dir},
  path::{Path, PathBuf},
  sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc::Sender,
  },
};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::sync::Arc;

#[cfg(feature = "cache")]
use crate::caching::{self, Cache};
#[cfg(feature = "services")]
use crate::scanning::{SERVICE_KEYWORDS, Service};
use crate::{
  diagnostic::{Diagnostic, Severity},
  directives::DirectiveMap,
  git::{self, GitThreadHandle},
  languages::{self, FileType},
  options::{Options, ScopedGlob, ScopedName},
  secrets::binary_secret::{self, BinarySecret},
  source::SourcePosition,
  trestlerc,
};

pub struct RunContext {
  pub abs_dir: PathBuf,
  pub options: Arc<Options>,
  pub options_resolver: Arc<trestlerc::OptionsResolver>,
  pub git_handle: Option<Mutex<GitThreadHandle>>,
  pub diagnostic_sender: Sender<Diagnostic>,
  #[cfg(feature = "cache")]
  pub cache: Option<Arc<Cache>>,
  pub scanned_file_count: AtomicUsize,
  pub git_root: Option<PathBuf>,
  pub buffers_diagnostics: bool,
}

impl RunContext {
  pub fn resolve_options(&self, dir: &Path) -> Arc<Options> {
    self.options_resolver.resolve(dir)
  }
}

thread_local! {
  static GIT_HANDLE: RefCell<Option<Option<GitThreadHandle>>> =
    const { RefCell::new(None) };
  static HAD_FINDINGS: Cell<bool> = const { Cell::new(false) };
  static FILE_DIAGNOSTICS: RefCell<Vec<Diagnostic>> =
    const { RefCell::new(Vec::new()) };
}

impl RunContext {
  pub fn send_diagnostic(&self, diagnostic: Diagnostic) {
    HAD_FINDINGS.with(|c| c.set(true));
    if self.buffers_diagnostics {
      FILE_DIAGNOSTICS.with(|buf| buf.borrow_mut().push(diagnostic));
    } else {
      self.diagnostic_sender.send(diagnostic).ok();
    }
  }

  pub fn flush_file_diagnostics(&self) {
    let diagnostics: Vec<Diagnostic> =
      FILE_DIAGNOSTICS.with(|buf| buf.borrow_mut().drain(..).collect());

    let n = diagnostics.len();
    let mut keep = vec![true; n];
    for (i, outer) in diagnostics.iter().enumerate() {
      for (j, inner) in diagnostics.iter().enumerate() {
        if i == j || !keep[j] {
          continue;
        }
        if supersedes(outer, inner) {
          keep[j] = false;
        }
      }
    }

    for (i, diagnostic) in diagnostics.into_iter().enumerate() {
      if keep[i] {
        self.diagnostic_sender.send(diagnostic).ok();
      }
    }
  }
}

fn supersedes(outer: &Diagnostic, inner: &Diagnostic) -> bool {
  let Some(outer_file_span) =
    outer.source_span().and_then(|s| s.file_span.as_ref())
  else {
    return false;
  };
  let Some(inner_file_span) =
    inner.source_span().and_then(|s| s.file_span.as_ref())
  else {
    return false;
  };

  let encompasses = position_le(&outer_file_span.start, &inner_file_span.start)
    && position_ge(&outer_file_span.end, &inner_file_span.end);
  if !encompasses {
    return false;
  }

  severity_rank(outer.severity()) > severity_rank(inner.severity())
}

fn position_le(a: &SourcePosition, b: &SourcePosition) -> bool {
  a.line < b.line || (a.line == b.line && a.column <= b.column)
}

fn position_ge(a: &SourcePosition, b: &SourcePosition) -> bool {
  a.line > b.line || (a.line == b.line && a.column >= b.column)
}

fn severity_rank(severity: &Severity) -> u8 {
  match severity {
    Severity::Critical => 2,
    Severity::Warning => 1,
  }
}

pub struct SourceContext<'a> {
  pub run: &'a RunContext,
  pub file_abs_path: &'a Path,
  pub file_extension: Option<&'a str>,
  pub body: Option<&'a str>,
  pub file_type: Option<FileType>,
  #[cfg(feature = "services")]
  pub file_services: Vec<&'static Service>,
  pub parent_line: usize,
  pub parent_col: usize,
  pub directives: OnceCell<DirectiveMap>,
}

impl<'a> SourceContext<'a> {
  pub fn directives(&self) -> &DirectiveMap {
    self
      .directives
      .get_or_init(|| DirectiveMap::scan(self.body.unwrap_or("")))
  }

  pub fn emit_diagnostic(&self, diagnostic: Diagnostic) {
    if let Some(line) = diagnostic_line(&diagnostic) {
      if self.directives().skip_covering(line).is_some() {
        return;
      }
    }
    self.run.send_diagnostic(diagnostic);
  }
}

fn diagnostic_line(diagnostic: &Diagnostic) -> Option<usize> {
  diagnostic
    .source_span()
    .and_then(|s| s.file_span.as_ref())
    .map(|s| s.start.line)
}

pub struct ScanContext {
  pub abs_dir: PathBuf,
  pub options: Arc<Options>,
  pub options_resolver: Arc<trestlerc::OptionsResolver>,
  pub git_handle: Option<GitThreadHandle>,
  pub git_root: Option<PathBuf>,
  #[cfg(feature = "cache")]
  pub cache: Option<Arc<Cache>>,
}

impl ScanContext {
  pub fn new(
    options_resolver: Arc<trestlerc::OptionsResolver>,
    abs_dir: PathBuf,
  ) -> Self {
    let options = options_resolver.resolve(&abs_dir);

    let git_repo = git::open(&abs_dir);
    let git_root = git_repo.as_ref().map(|r| r.workdir().to_path_buf());
    let git_handle = if options.skip_vcs_ignored {
      git_repo.and_then(|repo| repo.thread_handle())
    } else {
      None
    };

    #[cfg(feature = "cache")]
    let cache = options.cache_directory.as_ref().and_then(|dir| {
      match caching::open(std::path::Path::new(dir)) {
        Ok(c) => Some(Arc::new(c)),
        Err(err) => {
          eprintln!("Warning: {err}");
          None
        }
      }
    });

    Self {
      abs_dir,
      options,
      options_resolver,
      git_handle,
      git_root,
      #[cfg(feature = "cache")]
      cache,
    }
  }

  pub fn make_run_context(
    &self,
    diagnostic_sender: Sender<Diagnostic>,
  ) -> RunContext {
    RunContext {
      abs_dir: self.abs_dir.clone(),
      options: self.options.clone(),
      options_resolver: self.options_resolver.clone(),
      git_handle: self.git_handle.as_ref().map(|h| Mutex::new(h.clone())),
      diagnostic_sender,
      #[cfg(feature = "cache")]
      cache: self.cache.clone(),
      scanned_file_count: AtomicUsize::new(0),
      git_root: self.git_root.clone(),
      buffers_diagnostics: true,
    }
  }

  pub fn make_run_context_no_cache(
    &self,
    diagnostic_sender: Sender<Diagnostic>,
  ) -> RunContext {
    RunContext {
      abs_dir: self.abs_dir.clone(),
      options: self.options.clone(),
      options_resolver: self.options_resolver.clone(),
      git_handle: self.git_handle.as_ref().map(|h| Mutex::new(h.clone())),
      diagnostic_sender,
      #[cfg(feature = "cache")]
      cache: None,
      scanned_file_count: AtomicUsize::new(0),
      git_root: self.git_root.clone(),
      buffers_diagnostics: true,
    }
  }

  pub fn flush_cache(&self) {
    #[cfg(feature = "cache")]
    if let Some(ref cache) = self.cache {
      cache.flush_all();
    }
  }
}

pub fn process_dir(run_context: &RunContext, abs_dir: &PathBuf) {
  let Ok(entries) = read_dir(abs_dir) else {
    return;
  };

  let options = run_context.resolve_options(abs_dir);
  let mut pending: Vec<(PathBuf, bool)> = Vec::new();

  for entry in entries.filter_map(Result::ok) {
    let path = entry.path();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
      continue;
    };

    if record_stack_metadata(run_context, &path, name) {
      // Stack files and deployment files are still scanned for secrets
      // unless they are lock files.
      if let Some(reason) =
        skipped_file_reason(run_context, &options, &path, true)
      {
        report_verbose_ignored(run_context, &path, reason);
      } else if is_lock_file(name) {
        report_verbose_ignored(run_context, &path, SkipReason::LockFile);
      } else {
        report_verbose_scanned(run_context, &path);
        pending.push((path, false));
      }
      continue;
    }

    if path.is_dir() {
      if let Some(reason) =
        skipped_dir_reason(run_context, &options, &path, true)
      {
        report_verbose_ignored(run_context, &path, reason);
      } else {
        pending.push((path, true));
      }
    } else if let Some(reason) =
      skipped_file_reason(run_context, &options, &path, true)
    {
      report_verbose_ignored(run_context, &path, reason);
    } else {
      report_verbose_scanned(run_context, &path);
      pending.push((path, false));
    }
  }

  pending.par_iter().for_each(|(path, is_dir)| {
    if *is_dir {
      process_dir(run_context, path);
    } else {
      process_file(run_context, path);
    }
  });
}

fn is_git_excluded(
  run_context: &RunContext,
  path: &PathBuf,
  is_dir: bool,
) -> bool {
  GIT_HANDLE.with(|cell| {
    let mut slot = cell.borrow_mut();
    let inner = slot.get_or_insert_with(|| {
      run_context
        .git_handle
        .as_ref()
        .and_then(|mtx| mtx.lock().ok().map(|guard| guard.clone()))
    });

    let Some(handle) = inner.as_mut() else {
      return false;
    };

    handle.is_excluded(path, is_dir)
  })
}

fn matching_skip_glob<'a>(
  options: &'a Options,
  path: &PathBuf,
) -> Option<&'a ScopedGlob> {
  for scoped in &options.skip_glob {
    let Ok(rel) = path.strip_prefix(&scoped.anchor) else {
      continue;
    };
    let Some(rel_str) = rel.to_str() else {
      continue;
    };
    if glob_match::glob_match(&scoped.pattern, rel_str) {
      return Some(scoped);
    }
  }
  None
}

fn matching_scoped_name<'a>(
  scoped_names: &'a [ScopedName],
  path: &Path,
  name: &str,
) -> Option<&'a ScopedName> {
  scoped_names
    .iter()
    .find(|scoped| scoped.name == name && path.starts_with(&scoped.anchor))
}

enum SkipReason {
  ScopedDirectoryName {
    name: String,
    rc_file: Option<PathBuf>,
  },
  ScopedFileName {
    name: String,
    rc_file: Option<PathBuf>,
  },
  Glob {
    pattern: String,
    rc_file: Option<PathBuf>,
  },
  VcsIgnored,
  AutoExcluded,
  LockFile,
}

impl SkipReason {
  fn description(&self) -> String {
    match self {
      Self::ScopedDirectoryName { name, rc_file } => format_rc_suffix(
        format!("matched skip-directory-names entry \"{name}\""),
        rc_file,
      ),
      Self::ScopedFileName { name, rc_file } => format_rc_suffix(
        format!("matched skip-file-names entry \"{name}\""),
        rc_file,
      ),
      Self::Glob { pattern, rc_file } => format_rc_suffix(
        format!("matched skip-glob pattern \"{pattern}\""),
        rc_file,
      ),
      Self::VcsIgnored => "ignored by version control".to_owned(),
      Self::AutoExcluded => "matched auto-excludes".to_owned(),
      Self::LockFile => "lock file".to_owned(),
    }
  }
}

fn format_rc_suffix(base: String, rc_file: &Option<PathBuf>) -> String {
  match rc_file {
    Some(path) => format!("{base} in {}", path.display()),
    None => base,
  }
}

fn verbose_path(run_context: &RunContext, path: &Path) -> String {
  match path.strip_prefix(&run_context.abs_dir) {
    Ok(rel) if !rel.as_os_str().is_empty() => rel.display().to_string(),
    _ => path.display().to_string(),
  }
}

fn report_verbose_scanned(run_context: &RunContext, path: &Path) {
  if !run_context.options.verbose {
    return;
  }
  eprintln!("scanned: {}", verbose_path(run_context, path));
}

fn report_verbose_ignored(
  run_context: &RunContext,
  path: &Path,
  reason: SkipReason,
) {
  if !run_context.options.verbose {
    return;
  }
  eprintln!(
    "ignored: {} ({})",
    verbose_path(run_context, path),
    reason.description()
  );
}

fn is_auto_excluded_dir(name: &str) -> bool {
  matches!(
    name,
    // Version control
    ".git"
    | ".hg"
    | ".svn"
    | ".jj"
    // Dependencies / vendor
    | "node_modules"
    | "bower_components"
    | "jspm_packages"
    | "vendor"
    | "vendors"
    | "third_party"
    | "third-party"
    | "extern"
    | "externals"
    | "deps"
    // Caches
    | ".cache"
    | ".ccache"
    | "__pycache__"
    | ".pytest_cache"
    | ".mypy_cache"
    | ".ruff_cache"
    | ".tox"
    | ".nox"
    | ".eggs"
    | "*.egg-info"
    | ".gradle"
    | ".maven"
    | ".m2"
    | ".ivy2"
    | ".sbt"
    | ".metals"
    | ".bloop"
    | ".dart_tool"
    // Package manager state
    | ".npm"
    | ".yarn"
    | ".pnpm-store"
    | ".cargo"
    | ".rustup"
    | ".bundle"
    | ".gem"
    | ".pub-cache"
    | "Pods"
    | "Carthage"
    // Generated / coverage
    | "coverage"
    | ".nyc_output"
    | "htmlcov"
    | ".coverage"
    | "__snapshots__"
    // Containers / infra
    | ".terraform"
    | ".serverless"
    | ".pulumi"
  )
}

fn skipped_dir_reason(
  run_context: &RunContext,
  options: &Options,
  path: &PathBuf,
  check_git: bool,
) -> Option<SkipReason> {
  let name = path.file_name().and_then(|n| n.to_str())?;

  if let Some(matched) =
    matching_scoped_name(&options.skip_directory_names, path, name)
  {
    return Some(SkipReason::ScopedDirectoryName {
      name: matched.name.clone(),
      rc_file: matched.rc_file.clone(),
    });
  }

  if let Some(scoped) = matching_skip_glob(options, path) {
    return Some(SkipReason::Glob {
      pattern: scoped.pattern.clone(),
      rc_file: scoped.rc_file.clone(),
    });
  }

  if check_git
    && options.skip_vcs_ignored
    && is_git_excluded(run_context, path, true)
  {
    return Some(SkipReason::VcsIgnored);
  }

  if options.auto_excludes && is_auto_excluded_dir(name) {
    return Some(SkipReason::AutoExcluded);
  }

  None
}

fn is_os_metadata_file(file_name: &str) -> bool {
  matches!(file_name, ".DS_Store" | "Thumbs.db" | "desktop.ini")
}

fn is_lock_file(file_name: &str) -> bool {
  matches!(
    file_name,
    "package-lock.json"
      | "yarn.lock"
      | "pnpm-lock.yaml"
      | "bun.lock"
      | "bun.lockb"
      | "Cargo.lock"
      | "Gemfile.lock"
      | "gems.locked"
      | "poetry.lock"
      | "composer.lock"
      | "Pipfile.lock"
      | "pubspec.lock"
      | "go.sum"
      | "flake.lock"
      | "deno.lock"
  )
}

pub fn is_path_skipped(run_context: &RunContext, path: &Path) -> bool {
  is_path_skipped_inner(run_context, path, true)
}

/// Like [`is_path_skipped`] but skips the gitignore check.
pub fn is_path_statically_skipped(
  run_context: &RunContext,
  path: &Path,
) -> bool {
  is_path_skipped_inner(run_context, path, false)
}

fn is_path_skipped_inner(
  run_context: &RunContext,
  path: &Path,
  check_git: bool,
) -> bool {
  let path_buf = path.to_path_buf();
  let parent = path.parent().unwrap_or(path);
  let options = run_context.resolve_options(parent);
  if skipped_file_reason(run_context, &options, &path_buf, check_git).is_some()
  {
    return true;
  }

  let Ok(rel) = path.strip_prefix(&run_context.abs_dir) else {
    return false;
  };

  let mut ancestor = run_context.abs_dir.clone();

  let mut components: Vec<_> = rel.components().collect();
  components.pop();

  for component in components {
    let ancestor_parent = ancestor.clone();
    ancestor.push(component.as_os_str());
    let ancestor_options = run_context.resolve_options(&ancestor_parent);
    if skipped_dir_reason(run_context, &ancestor_options, &ancestor, check_git)
      .is_some()
    {
      return true;
    }
  }

  false
}

fn skipped_file_reason(
  run_context: &RunContext,
  options: &Options,
  path: &PathBuf,
  check_git: bool,
) -> Option<SkipReason> {
  let name = path.file_name().and_then(|n| n.to_str())?;

  if let Some(matched) =
    matching_scoped_name(&options.skip_file_names, path, name)
  {
    return Some(SkipReason::ScopedFileName {
      name: matched.name.clone(),
      rc_file: matched.rc_file.clone(),
    });
  }

  if let Some(scoped) = matching_skip_glob(options, path) {
    return Some(SkipReason::Glob {
      pattern: scoped.pattern.clone(),
      rc_file: scoped.rc_file.clone(),
    });
  }

  if check_git
    && options.skip_vcs_ignored
    && is_git_excluded(run_context, path, false)
  {
    return Some(SkipReason::VcsIgnored);
  }

  if options.auto_excludes && is_os_metadata_file(name) {
    return Some(SkipReason::AutoExcluded);
  }

  None
}

pub fn process_files(run_context: &RunContext, paths: &[PathBuf]) {
  for path in paths {
    process_explicit_file(run_context, path);
  }
}

pub fn process_files_with_surrounding_context(
  run_context: &RunContext,
  paths: &[PathBuf],
) {
  for path in paths {
    record_surrounding_stack_metadata(run_context, path);
    process_explicit_file(run_context, path);
  }
}

fn process_explicit_file(run_context: &RunContext, path: &PathBuf) {
  let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
    return;
  };

  record_stack_metadata(run_context, path, name);
  report_verbose_scanned(run_context, path);
  process_file(run_context, path);
}

fn record_surrounding_stack_metadata(
  run_context: &RunContext,
  file_path: &Path,
) {
  let mut dir = file_path.parent();

  while let Some(current) = dir {
    record_stack_metadata_in_dir(run_context, current);
    dir = current.parent();
  }
}

fn record_stack_metadata_in_dir(run_context: &RunContext, dir: &Path) {
  let Ok(entries) = read_dir(dir) else {
    return;
  };

  for entry in entries.filter_map(Result::ok) {
    let path = entry.path();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
      continue;
    };

    record_stack_metadata(run_context, &path, name);
  }
}

fn record_stack_metadata(
  _run_context: &RunContext,
  _path: &PathBuf,
  _name: &str,
) -> bool {
  false
}

pub fn process_text(run_context: &RunContext, path: &PathBuf, text: &str) {
  let Some(first_byte) = text.as_bytes().first() else {
    return;
  };

  if matches!(first_byte, 0x00..=0x1A | 0x1C..=0x1F | 0x7F) {
    return;
  }

  let context = SourceContext {
    run: run_context,
    file_abs_path: path,
    file_extension: path.extension().and_then(|ext| ext.to_str()),
    body: Some(text),
    file_type: None,
    parent_line: 0,
    parent_col: 0,
    #[cfg(feature = "services")]
    file_services: services_from_path(path),
    directives: OnceCell::new(),
  };

  if languages::parse(&context).is_none() {
    #[cfg(feature = "pem")]
    send_pem_diagnostics(run_context, path, text);
    #[cfg(feature = "putty")]
    send_putty_diagnostics(run_context, path, text);
  }
}

#[cfg(feature = "services")]
fn services_from_path(path: &PathBuf) -> Vec<&'static Service> {
  let path_str = path.to_string_lossy().to_ascii_lowercase();
  let mut found = Vec::new();

  for keyword in SERVICE_KEYWORDS {
    if path_str.contains(keyword) {
      if let Some(service) = Service::by_keyword(keyword) {
        found.push(service);
      }
    }
  }

  found
}

pub fn process_file(run_context: &RunContext, path: &PathBuf) {
  if cfg!(debug_assertions) {
    process_file_inner(run_context, path);
    return;
  }

  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    process_file_inner(run_context, path);
  }));

  if result.is_err() {
    eprintln!("trestle: could not scan \"{}\".", path.display());
  }
}

fn process_file_inner(run_context: &RunContext, path: &PathBuf) {
  let mtime = fs::metadata(path).and_then(|m| m.modified()).ok();

  #[cfg(feature = "cache")]
  if let (Some(cache), Some(mtime)) = (&run_context.cache, &mtime) {
    if matches!(cache.check(path, *mtime), crate::caching::CacheCheck::Clean) {
      run_context
        .scanned_file_count
        .fetch_add(1, Ordering::Relaxed);
      return;
    }
  }

  let Ok(body) = fs::read_to_string(path) else {
    return;
  };

  run_context
    .scanned_file_count
    .fetch_add(1, Ordering::Relaxed);

  let body_bytes = body.as_bytes();

  let Some(first_byte) = body_bytes.first() else {
    return;
  };

  HAD_FINDINGS.with(|c| c.set(false));
  FILE_DIAGNOSTICS.with(|buf| buf.borrow_mut().clear());

  match first_byte {
    #[cfg(feature = "binary-gpg")]
    0x94 | 0x95 | 0x96 | 0x9C | 0x9D | 0x9E | 0xC5 | 0xC7 => {
      if let Some(secret) = binary_secret::gpg::scan_bytes(body_bytes) {
        run_context.send_diagnostic(Diagnostic::BinarySecret {
          secret: BinarySecret::Gpg(secret),
          severity: Severity::Critical,
          file_type: Some(FileType::Gpg),
          file_abs_path: path.clone(),
        });
      }
    }
    #[cfg(feature = "binary-der")]
    0x30 => {
      if let Some(secret) = binary_secret::der::scan_bytes(body_bytes) {
        run_context.send_diagnostic(Diagnostic::BinarySecret {
          secret: BinarySecret::Der(secret),
          severity: Severity::Critical,
          file_type: Some(FileType::Der),
          file_abs_path: path.clone(),
        });
      }
    }
    #[cfg(feature = "binary-keepass")]
    0x03 => {
      if let Some(secret) = binary_secret::keepass::scan_bytes(body_bytes) {
        run_context.send_diagnostic(Diagnostic::BinarySecret {
          secret: BinarySecret::KeePass(secret),
          severity: Severity::Critical,
          file_type: Some(FileType::KeePass),
          file_abs_path: path.clone(),
        });
      }
    }
    #[cfg(feature = "binary-jceks")]
    0xCE => {
      if let Some(secret) = binary_secret::jceks::scan_bytes(body_bytes) {
        run_context.send_diagnostic(Diagnostic::BinarySecret {
          secret: BinarySecret::Jceks(secret),
          severity: Severity::Critical,
          file_type: Some(FileType::Jceks),
          file_abs_path: path.clone(),
        });
      }
    }
    #[cfg(feature = "binary-jks")]
    0xFE => {
      if let Some(secret) = binary_secret::jks::scan_bytes(body_bytes) {
        run_context.send_diagnostic(Diagnostic::BinarySecret {
          secret: BinarySecret::Jks(secret),
          severity: Severity::Critical,
          file_type: Some(FileType::Jks),
          file_abs_path: path.clone(),
        });
      }
    }
    _ => {
      process_text(run_context, path, &body);
    }
  }

  run_context.flush_file_diagnostics();

  #[cfg(feature = "cache")]
  if let (Some(cache), Some(mtime)) = (&run_context.cache, &mtime) {
    if HAD_FINDINGS.with(|c| c.get()) {
      cache.mark_findings(path, *mtime);
    } else {
      cache.mark_clean(path, *mtime);
    }
  }

  #[cfg(not(feature = "cache"))]
  let _ = mtime;
}

#[cfg(feature = "pem")]
fn send_pem_diagnostics(
  run_context: &RunContext,
  path: &PathBuf,
  content: &str,
) {
  use crate::{
    secrets::{
      pem,
      text_secret::{self, TextSecret},
      values::classify::{NamedSecret::PrivateKey, ValueClass::Secret},
    },
    source::{self, SourceFileSpan, SourceSpan},
  };

  let findings = pem::scan(content);
  if findings.is_empty() {
    return;
  }

  if text_secret::pem::is_whole_file(content, &findings) {
    let keys = findings.into_iter().map(|f| f.key_type).collect();
    run_context.send_diagnostic(Diagnostic::TextSecret {
      secret: TextSecret::Pem(keys),
      severity: Severity::Critical,
      file_type: Some(FileType::Pem),
      file_abs_path: path.clone(),
    });
    return;
  }

  for finding in findings {
    let start = source::offset_to_position(content, finding.byte_range.start);
    let end = source::offset_to_position(content, finding.byte_range.end);
    run_context.send_diagnostic(Diagnostic::SecretValue {
      source_span: SourceFileSpan {
        file_abs_path: path.clone(),
        file_span: Some(SourceSpan { start, end }),
      },
      value_class: Secret(PrivateKey(finding.key_type)),
      severity: Severity::Critical,
      file_type: None,
    });
  }
}

#[cfg(feature = "putty")]
fn send_putty_diagnostics(
  run_context: &RunContext,
  path: &PathBuf,
  content: &str,
) {
  use crate::{
    secrets::{
      putty,
      text_secret::{self, TextSecret},
      values::classify::{NamedSecret::PuttyKey, ValueClass::Secret},
    },
    source::{self, SourceFileSpan, SourceSpan},
  };

  let findings = putty::scan(content);
  if findings.is_empty() {
    return;
  }

  if text_secret::putty::is_whole_file(content, &findings) {
    let keys = findings.into_iter().map(|f| f.key_type).collect();
    run_context.send_diagnostic(Diagnostic::TextSecret {
      secret: TextSecret::Putty(keys),
      severity: Severity::Critical,
      file_type: Some(FileType::Putty),
      file_abs_path: path.clone(),
    });
    return;
  }

  for finding in findings {
    let start = source::offset_to_position(content, finding.byte_range.start);
    let end = source::offset_to_position(content, finding.byte_range.end);
    run_context.send_diagnostic(Diagnostic::SecretValue {
      source_span: SourceFileSpan {
        file_abs_path: path.clone(),
        file_span: Some(SourceSpan { start, end }),
      },
      value_class: Secret(PuttyKey(finding.key_type)),
      severity: Severity::Critical,
      file_type: None,
    });
  }
}
