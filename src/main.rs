use std::fs::File;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Sender};
use std::{env::args, fs::canonicalize};

use trestle::diagnostic::Diagnostic;
use trestle::exit::{EXIT_CODE_ERROR, exit_with_error, exit_with_findings};
#[cfg(feature = "lsp")]
use trestle::lsp;
#[cfg(feature = "mcp")]
use trestle::mcp;
use trestle::options::{Command, Options, ParseResult, print_help};
use trestle::output::{ScanStats, ScanSummary, WriteContext, write};
use trestle::processing::{
  RunContext, ScanContext, process_dir, process_files,
  process_files_with_surrounding_context,
};
use trestle::trestlerc::OptionsResolver;
use trestle::watch;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

struct ScanTarget {
  explicit_file: Option<PathBuf>,
  scan_root: PathBuf,
}

fn main() {
  let args: Vec<String> = args().skip(1).collect();
  let parse_result = Options::from_args(&args);

  let (command, cli_args, paths) = match parse_result {
    ParseResult::Run {
      command,
      cli_args,
      paths,
      ..
    } => (command, cli_args, paths),
    ParseResult::Help => {
      print_help();
      return;
    }
    ParseResult::Version => {
      println!("{}", env!("TRESTLE_VERSION_DISPLAY"));
      return;
    }
    ParseResult::ErrorWithHelp => {
      print_help();
      process::exit(EXIT_CODE_ERROR);
    }
    ParseResult::Error => process::exit(EXIT_CODE_ERROR),
  };

  match command {
    Command::Install => {
      run_install();
      return;
    }
    Command::Uninstall => {
      run_uninstall();
      return;
    }
    _ => {}
  }

  let paths = if paths.is_empty() {
    vec![".".to_string()]
  } else {
    paths
  };

  let targets: Vec<ScanTarget> =
    paths.iter().map(|path| resolve_path(path)).collect();

  let cli_anchor = std::env::current_dir().unwrap_or_else(|err| {
    exit_with_error(format!("Error: could not read current directory. {err}"));
  });

  let options_resolver = Arc::new(OptionsResolver::new(cli_args, cli_anchor));

  let watch = match command {
    Command::Scan => false,
    Command::Watch => true,
    #[cfg(feature = "lsp")]
    Command::Lsp => {
      if targets.iter().any(|t| t.explicit_file.is_some()) {
        exit_with_error("Error: lsp command requires directory paths.");
      }
      let roots: Vec<PathBuf> =
        targets.into_iter().map(|t| t.scan_root).collect();
      if let Err(err) = lsp::run(options_resolver, roots) {
        exit_with_error(err);
      }
      return;
    }
    #[cfg(feature = "mcp")]
    Command::Mcp => {
      if targets.iter().any(|t| t.explicit_file.is_some()) {
        exit_with_error("Error: mcp command requires directory paths.");
      }
      let roots: Vec<PathBuf> =
        targets.into_iter().map(|t| t.scan_root).collect();
      if let Err(err) = mcp::run(options_resolver, roots) {
        exit_with_error(err);
      }
      return;
    }
    Command::Install | Command::Uninstall => false,
  };

  let thread_count = std::thread::available_parallelism()
    .map(|n| (n.get() as f64 * 1.4).round() as usize)
    .ok();

  if let Some(num_threads) = thread_count {
    rayon::ThreadPoolBuilder::new()
      .num_threads(num_threads)
      .build_global()
      .ok();
  }

  let bases: Vec<ScanContext> = targets
    .iter()
    .map(|t| ScanContext::new(options_resolver.clone(), t.scan_root.clone()))
    .collect();

  let summary = run_scans(&bases, &targets);

  if !watch && summary.total() > 0 {
    exit_with_findings();
  }

  if watch {
    for (base, target) in bases.iter().zip(targets.iter()) {
      let explicit_file = target.explicit_file.clone();

      watch::run(base, |base, files| {
        let files = if let Some(file) = &explicit_file {
          files
            .into_iter()
            .filter(|path| canonicalize(path).is_ok_and(|path| path == *file))
            .collect()
        } else {
          files
        };

        if files.is_empty() {
          return;
        }

        run_scans_on_files(
          std::slice::from_ref(base),
          &files,
          explicit_file.is_some(),
        );
      });
    }
  }
}

fn resolve_path(path: &str) -> ScanTarget {
  let path_buf = PathBuf::from(path);

  if !path_buf.exists() {
    exit_with_error(format!(r#"Error: Path "{path}" does not exist."#));
  }

  let Ok(abs_path) = std::path::absolute(&path_buf) else {
    exit_with_error(format!(r#"Error: could not resolve path "{path}"."#));
  };

  let explicit_file = abs_path.is_file().then_some(abs_path.clone());

  let scan_root = explicit_file
    .as_ref()
    .and_then(|file| file.parent().map(|parent| parent.to_path_buf()))
    .unwrap_or(abs_path);

  ScanTarget {
    explicit_file,
    scan_root,
  }
}

fn run_scans(bases: &[ScanContext], targets: &[ScanTarget]) -> ScanSummary {
  with_writer(bases, move |sender| {
    let mut total = 0;

    for (base, target) in bases.iter().zip(targets.iter()) {
      total += scan_one(base, sender.clone(), |ctx| {
        if let Some(file) = &target.explicit_file {
          process_files_with_surrounding_context(ctx, &[file.clone()]);
        } else {
          process_dir(ctx, &base.abs_dir);
        }
      });
    }

    total
  })
}

fn run_scans_on_files(
  bases: &[ScanContext],
  files: &[PathBuf],
  with_context: bool,
) {
  with_writer(bases, move |sender| {
    let mut total = 0;

    for base in bases {
      total += scan_one(base, sender.clone(), |ctx| {
        if with_context {
          process_files_with_surrounding_context(ctx, files);
        } else {
          process_files(ctx, files);
        }
      });
    }

    total
  });
}

fn with_writer(
  bases: &[ScanContext],
  f: impl FnOnce(&Sender<Diagnostic>) -> usize,
) -> ScanSummary {
  let (diagnostic_sender, diagnostic_receiver) = mpsc::channel();
  let (scan_stats_sender, scan_stats_receiver) = mpsc::channel();

  let first = &bases[0];
  let options: Options = (*first.options).clone();
  let output_file = expand_tilde(&options.output_file);
  let output_is_terminal = output_file == "-" && io::stdout().is_terminal();

  let writer_thread = std::thread::spawn(move || {
    if output_file == "-" {
      let mut stdout = io::stdout().lock();
      write(WriteContext {
        diagnostic_receiver,
        options,
        output_is_terminal,
        output_writer: &mut stdout,
        scan_stats_receiver,
      })
    } else {
      match File::create(&output_file) {
        Ok(mut file) => write(WriteContext {
          diagnostic_receiver,
          options,
          output_is_terminal,
          output_writer: &mut file,
          scan_stats_receiver,
        }),
        Err(err) => {
          exit_with_error(format!(
            "Error: could not create output file \"{output_file}\". {err}"
          ));
        }
      }
    }
  });

  let start = std::time::Instant::now();
  let total = f(&diagnostic_sender);
  drop(diagnostic_sender);

  for base in bases {
    base.flush_cache();
  }

  scan_stats_sender
    .send(ScanStats {
      scanned_file_count: total,
      elapsed: start.elapsed(),
    })
    .ok();

  match writer_thread.join() {
    Ok(summary) => summary,
    Err(_) => exit_with_error("Error: writer thread failed."),
  }
}

fn scan_one(
  base: &ScanContext,
  sender: Sender<Diagnostic>,
  scan: impl FnOnce(&RunContext),
) -> usize {
  let run_context = base.make_run_context(sender);

  scan(&run_context);

  let count = run_context.scanned_file_count.load(Ordering::Relaxed);

  drop(run_context);

  count
}

fn run_install() {
  let cwd = std::env::current_dir().unwrap_or_else(|err| {
    exit_with_error(format!("Error: could not read current directory. {err}"));
  });

  let trestle_path = std::env::current_exe().unwrap_or_else(|err| {
    exit_with_error(format!("Error: could not resolve trestle path. {err}"));
  });

  match trestle::install::install_in(&cwd, &trestle_path) {
    Ok(changes) => {
      if changes.is_empty() {
        println!("trestle is already installed.");
      } else {
        for change in changes {
          println!("{}", change.description());
        }
      }
    }
    Err(err) => exit_with_error(format!("Error: {err}")),
  }
}

fn run_uninstall() {
  let cwd = std::env::current_dir().unwrap_or_else(|err| {
    exit_with_error(format!("Error: could not read current directory. {err}"));
  });

  match trestle::install::uninstall_in(&cwd) {
    Ok(changes) => {
      if changes.is_empty() {
        println!("trestle is not installed.");
      } else {
        for change in changes {
          println!("{}", change.description());
        }
      }
    }
    Err(err) => exit_with_error(format!("Error: {err}")),
  }
}

fn expand_tilde(path: &str) -> String {
  if path == "~" || path.starts_with("~/") {
    if let Some(home) = dirs::home_dir() {
      return home.display().to_string() + &path[1..];
    }
  }
  path.to_owned()
}
