use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc;

use notify::{RecursiveMode, Watcher};

use crate::config::DEBOUNCE_DURATION;
use crate::exit::exit_with_error;
use crate::processing::ScanContext;

pub fn run(base: &ScanContext, on_change: impl Fn(&ScanContext, Vec<PathBuf>)) {
  let (event_tx, event_rx) = mpsc::channel();

  let mut watcher = notify::recommended_watcher(move |res| {
    if let Ok(event) = res {
      event_tx.send(event).ok();
    }
  })
  .unwrap_or_else(|err| {
    exit_with_error(format!("Error: could not start file watcher. {err}"));
  });

  if let Err(err) =
    watcher.watch(base.abs_dir.as_ref(), RecursiveMode::Recursive)
  {
    exit_with_error(format!("Error: could not watch directory. {err}"));
  }

  eprintln!("Watching for changes...");

  while let Ok(first) = event_rx.recv() {
    let mut paths = BTreeSet::new();
    collect_paths(&first, &mut paths);

    while let Ok(event) = event_rx.recv_timeout(DEBOUNCE_DURATION) {
      collect_paths(&event, &mut paths);
    }

    let files: Vec<PathBuf> =
      paths.into_iter().filter(|p| p.is_file()).collect();

    if files.is_empty() {
      continue;
    }

    on_change(base, files);
  }
}

fn collect_paths(event: &notify::Event, paths: &mut BTreeSet<PathBuf>) {
  for path in &event.paths {
    paths.insert(path.clone());
  }
}
