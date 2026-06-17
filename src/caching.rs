use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

use rusqlite::Connection;

fn db_version() -> &'static str {
  static VERSION: OnceLock<String> = OnceLock::new();
  VERSION.get_or_init(|| {
    let Ok(exe_path) = std::env::current_exe() else {
      return "unknown".to_string();
    };
    let Ok(bytes) = std::fs::read(&exe_path) else {
      return "unknown".to_string();
    };
    let hash = xxhash_rust::xxh3::xxh3_64(&bytes);
    format!("{hash:016x}")
  })
}

const STATUS_CLEAN: i64 = 0;
const STATUS_HAS_FINDINGS: i64 = 1;

const CACHE_DIR_NAME: &str = "trestle-cache";
const DB_FILE_NAME: &str = "cache.db";

const WRITE_BATCH_SIZE: usize = 500;

pub enum CacheCheck {
  Clean,
  Scan,
}

struct CacheConn {
  conn: Connection,
  buf: Vec<(i64, i64, i64, i64)>,
}

thread_local! {
  static CACHE_CONN: RefCell<Option<CacheConn>> = const { RefCell::new(None) };
}

pub struct Cache {
  db_path: PathBuf,
}

pub fn open(cache_path: &Path) -> Result<Cache, String> {
  let cache_dir = cache_path.join(CACHE_DIR_NAME);
  let db_path = cache_dir.join(DB_FILE_NAME);

  if db_path.exists()
    && let Err(()) | Ok(false) = check_version(&db_path)
  {
    let _ = std::fs::remove_dir_all(&cache_dir);
  }

  if !cache_dir.exists() {
    std::fs::create_dir_all(&cache_dir).map_err(|err| {
      format!(
        "Cannot create cache directory \"{}\". {err}",
        cache_dir.display()
      )
    })?;
  }

  let conn = Connection::open(&db_path).map_err(|err| {
    format!(
      "Cannot open cache database \"{}\". {err}",
      db_path.display()
    )
  })?;

  conn
    .execute_batch(
      "PRAGMA journal_mode=WAL;
       CREATE TABLE IF NOT EXISTS meta (
         key TEXT PRIMARY KEY,
         value TEXT NOT NULL
       );
       CREATE TABLE IF NOT EXISTS files (
         path_hash INTEGER PRIMARY KEY,
         mtime_sec INTEGER NOT NULL,
         mtime_nano INTEGER NOT NULL,
         status INTEGER NOT NULL
       );",
    )
    .map_err(|err| {
      format!(
        "Cannot initialize cache database \"{}\". {err}",
        db_path.display()
      )
    })?;

  conn
    .execute(
      "INSERT OR REPLACE INTO meta (key, value) VALUES ('version', ?1)",
      rusqlite::params![db_version()],
    )
    .map_err(|err| {
      format!(
        "Cannot write cache version \"{}\". {err}",
        db_path.display()
      )
    })?;

  drop(conn);

  Ok(Cache { db_path })
}

impl Cache {
  fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> T) -> Option<T> {
    CACHE_CONN.with(|cell| {
      let mut cached_conn = cell.borrow_mut();
      if cached_conn.is_none()
        && let Ok(conn) = Connection::open(&self.db_path)
      {
        let _ = conn.execute("PRAGMA journal_mode=WAL", []);
        *cached_conn = Some(CacheConn {
          conn,
          buf: Vec::new(),
        });
      }
      cached_conn.as_ref().map(|cache_conn| f(&cache_conn.conn))
    })
  }

  pub fn check(&self, path: &Path, mtime: SystemTime) -> CacheCheck {
    let hash = path_hash(path);
    let (sec, nano) = system_time_to_parts(mtime);

    let result = self.with_conn(|conn| {
      let mut stmt = match conn.prepare_cached(
        "SELECT mtime_sec, mtime_nano, status FROM files WHERE path_hash = ?1",
      ) {
        Ok(s) => s,
        Err(_) => return CacheCheck::Scan,
      };

      match stmt.query_row(rusqlite::params![hash], |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, i64>(1)?,
          row.get::<_, i64>(2)?,
        ))
      }) {
        Ok((cached_sec, cached_nano, status)) => {
          if cached_sec == sec && cached_nano == nano && status == STATUS_CLEAN
          {
            CacheCheck::Clean
          } else {
            CacheCheck::Scan
          }
        }
        Err(_) => CacheCheck::Scan,
      }
    });

    result.unwrap_or(CacheCheck::Scan)
  }

  pub fn mark_clean(&self, path: &Path, mtime: SystemTime) {
    self.buffer_upsert(path, mtime, STATUS_CLEAN);
  }

  pub fn mark_findings(&self, path: &Path, mtime: SystemTime) {
    self.buffer_upsert(path, mtime, STATUS_HAS_FINDINGS);
  }

  fn buffer_upsert(&self, path: &Path, mtime: SystemTime, status: i64) {
    let hash = path_hash(path);
    let (sec, nano) = system_time_to_parts(mtime);

    CACHE_CONN.with(|cell| {
      let mut cached_conn = cell.borrow_mut();
      if cached_conn.is_none()
        && let Ok(conn) = Connection::open(&self.db_path)
      {
        let _ = conn.execute("PRAGMA journal_mode=WAL", []);
        *cached_conn = Some(CacheConn {
          conn,
          buf: Vec::new(),
        });
      }
      if let Some(cached_conn) = cached_conn.as_mut() {
        cached_conn.buf.push((hash, sec, nano, status));
        if cached_conn.buf.len() >= WRITE_BATCH_SIZE {
          flush_buf(cached_conn);
        }
      }
    });
  }

  pub fn flush_all(&self) {
    rayon::broadcast(|_| {
      flush_thread_local();
    });
    flush_thread_local();
  }
}

fn flush_thread_local() {
  CACHE_CONN.with(|cell| {
    let mut slot = cell.borrow_mut();
    if let Some(cc) = slot.as_mut() {
      flush_buf(cc);
    }
  });
}

fn flush_buf(cached_conn: &mut CacheConn) {
  if cached_conn.buf.is_empty() {
    return;
  }

  if cached_conn.conn.execute_batch("BEGIN").is_err() {
    cached_conn.buf.clear();
    return;
  }

  let result = cached_conn.conn.prepare_cached(
    "INSERT OR REPLACE INTO files (path_hash, mtime_sec, mtime_nano, status) \
     VALUES (?1, ?2, ?3, ?4)",
  );

  match result {
    Ok(mut stmt) => {
      for &(hash, sec, nano, status) in &cached_conn.buf {
        let _ = stmt.execute(rusqlite::params![hash, sec, nano, status]);
      }
    }
    Err(_) => {
      let _ = cached_conn.conn.execute_batch("ROLLBACK");
      cached_conn.buf.clear();
      return;
    }
  }

  let _ = cached_conn.conn.execute_batch("COMMIT");
  cached_conn.buf.clear();
}

fn path_hash(path: &Path) -> i64 {
  use xxhash_rust::xxh3::xxh3_64;
  xxh3_64(path.as_os_str().as_encoded_bytes()) as i64
}

fn system_time_to_parts(time: SystemTime) -> (i64, i64) {
  match time.duration_since(SystemTime::UNIX_EPOCH) {
    Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos() as i64),
    Err(_) => (0, 0),
  }
}

fn check_version(db_path: &Path) -> Result<bool, ()> {
  let conn = Connection::open(db_path).map_err(|_| ())?;
  let version: String = conn
    .query_row("SELECT value FROM meta WHERE key = 'version'", [], |row| {
      row.get(0)
    })
    .map_err(|_| ())?;
  Ok(version == db_version())
}
