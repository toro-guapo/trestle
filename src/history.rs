#![cfg(feature = "git-history")]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, NaiveDate};
use gix::{ObjectId, Repository};

use crate::diagnostic::{HistoryAttribution, HistoryCommit, HistoryLocation};
use crate::options::Options;

#[derive(Clone)]
pub struct BlobOccurrence {
  pub oid: ObjectId,
  pub path: PathBuf,
  pub attribution: HistoryAttribution,
}

pub struct HistoryWalker {
  repo: Repository,
  current_branch: Option<String>,
}

impl HistoryWalker {
  pub fn open(path: &Path) -> Option<Self> {
    let repo = gix::discover(path).ok()?;

    let current_branch = repo
      .head_name()
      .ok()
      .flatten()
      .and_then(|name| short_branch_name(name.as_bstr().as_ref()));

    Some(Self {
      repo,
      current_branch,
    })
  }

  pub fn workdir(&self) -> Option<&Path> {
    self.repo.workdir()
  }

  pub fn collect_blobs(&self) -> Vec<BlobOccurrence> {
    self.collect_blobs_filtered(&SkipFilter::default())
  }

  pub fn collect_blobs_with_options(
    &self,
    options: &Options,
  ) -> Result<Vec<BlobOccurrence>, String> {
    let filter = self.build_skip_filter(options)?;
    Ok(self.collect_blobs_filtered(&filter))
  }

  fn collect_blobs_filtered(&self, filter: &SkipFilter) -> Vec<BlobOccurrence> {
    let mut blobs: HashMap<ObjectId, BlobInfo> = HashMap::new();
    let mut reachable_commits: HashSet<ObjectId> = HashSet::new();

    let refs = match self.repo.references() {
      Ok(r) => r,
      Err(_) => return Vec::new(),
    };

    if let Ok(iter) = refs.prefixed("refs/heads/") {
      for reference in iter.flatten() {
        let name = reference.name().as_bstr().to_string();
        let short = strip_prefix(&name, "refs/heads/");
        let current = self.current_branch.as_deref() == Some(short);
        let location = HistoryLocation::Branch {
          name: short.to_owned(),
          current,
        };
        self.walk_ref(
          reference,
          location,
          &mut blobs,
          &mut reachable_commits,
          filter,
        );
      }
    }

    if let Ok(iter) = refs.prefixed("refs/remotes/") {
      for reference in iter.flatten() {
        let name = reference.name().as_bstr().to_string();
        let short = strip_prefix(&name, "refs/remotes/");
        let location = HistoryLocation::RemoteRef(short.to_owned());
        self.walk_ref(
          reference,
          location,
          &mut blobs,
          &mut reachable_commits,
          filter,
        );
      }
    }

    if let Ok(iter) = refs.prefixed("refs/tags/") {
      for reference in iter.flatten() {
        let name = reference.name().as_bstr().to_string();
        let short = strip_prefix(&name, "refs/tags/");
        let location = HistoryLocation::Tag(short.to_owned());
        self.walk_ref(
          reference,
          location,
          &mut blobs,
          &mut reachable_commits,
          filter,
        );
      }
    }

    if let Ok(stash) = self.repo.try_find_reference("refs/stash") {
      if let Some(reference) = stash {
        self.walk_ref(
          reference,
          HistoryLocation::Stash,
          &mut blobs,
          &mut reachable_commits,
          filter,
        );
      }
    }

    self.walk_dangling(&reachable_commits, &mut blobs, filter);

    blobs
      .into_iter()
      .filter_map(|(oid, info)| info.into_occurrence(oid))
      .collect()
  }

  pub fn read_blob(&self, oid: ObjectId) -> Option<Vec<u8>> {
    let object = self.repo.find_object(oid).ok()?;
    let blob = object.try_into_blob().ok()?;
    Some(blob.data.clone())
  }

  fn build_skip_filter(&self, options: &Options) -> Result<SkipFilter, String> {
    let mut filter = SkipFilter::default();

    if let Some(raw) = options.skip_commits_up_to.as_deref() {
      if raw.contains(',') {
        return Err(format!(
          "--skip-commits-up-to takes a single date or commit, not a list: {raw:?}."
        ));
      }

      if let Some(secs) = parse_cutoff_time(raw) {
        filter.time_cutoff = Some(secs);
      } else {
        match resolve_hex_commit(&self.repo, raw) {
          HexResolution::Commit(oid) => {
            filter.up_to_ancestors = self.ancestors_of(oid);
          }
          HexResolution::NotCommit => {
            return Err(format!(
              "--skip-commits-up-to value {raw:?} does not refer to a commit object."
            ));
          }
          HexResolution::NotFound => {
            return Err(format!(
              "--skip-commits-up-to value {raw:?} does not resolve to a known commit."
            ));
          }
          HexResolution::NotHex => {
            return Err(format!(
              "--skip-commits-up-to value {raw:?} is neither a valid date/time nor a commit hex."
            ));
          }
        }
      }
    }

    for entry in &options.skip_commits {
      match resolve_hex_commit(&self.repo, entry) {
        HexResolution::Commit(oid) => {
          filter.exact.insert(oid);
        }
        HexResolution::NotCommit => {
          return Err(format!(
            "--skip-commits value {entry:?} does not refer to a commit object."
          ));
        }
        HexResolution::NotFound => {
          return Err(format!(
            "--skip-commits value {entry:?} does not resolve to a known commit."
          ));
        }
        HexResolution::NotHex => {
          return Err(format!(
            "--skip-commits value {entry:?} is not a commit hex."
          ));
        }
      }
    }

    Ok(filter)
  }

  fn ancestors_of(&self, tip: ObjectId) -> HashSet<ObjectId> {
    let mut set = HashSet::new();
    if let Ok(walk) = self.repo.rev_walk([tip]).all() {
      for info in walk.flatten() {
        set.insert(info.id);
      }
    }
    set
  }

  fn walk_ref(
    &self,
    reference: gix::Reference<'_>,
    location: HistoryLocation,
    blobs: &mut HashMap<ObjectId, BlobInfo>,
    reachable_commits: &mut HashSet<ObjectId>,
    filter: &SkipFilter,
  ) {
    let priority = location_priority(&location);

    let tip = match reference.into_fully_peeled_id() {
      Ok(id) => id.detach(),
      Err(_) => return,
    };

    let walk = match self.repo.rev_walk([tip]).all() {
      Ok(w) => w,
      Err(_) => return,
    };

    for info in walk.flatten() {
      let commit_id = info.id;
      reachable_commits.insert(commit_id);
      self.absorb_commit(commit_id, &location, priority, blobs, filter);
    }
  }

  fn walk_dangling(
    &self,
    reachable: &HashSet<ObjectId>,
    blobs: &mut HashMap<ObjectId, BlobInfo>,
    filter: &SkipFilter,
  ) {
    let priority = location_priority(&HistoryLocation::Dangling);
    let Ok(iter) = self.repo.objects.iter() else {
      return;
    };

    for oid_result in iter {
      let Ok(oid) = oid_result else {
        continue;
      };
      if reachable.contains(&oid) {
        continue;
      }
      let Ok(object) = self.repo.find_object(oid) else {
        continue;
      };
      if !matches!(object.kind, gix::object::Kind::Commit) {
        continue;
      }

      self.absorb_commit(
        oid,
        &HistoryLocation::Dangling,
        priority,
        blobs,
        filter,
      );
    }
  }

  fn absorb_commit(
    &self,
    commit_id: ObjectId,
    location: &HistoryLocation,
    priority: u8,
    blobs: &mut HashMap<ObjectId, BlobInfo>,
    filter: &SkipFilter,
  ) {
    let Ok(commit) = self.repo.find_object(commit_id) else {
      return;
    };
    let Ok(commit) = commit.try_into_commit() else {
      return;
    };
    let Some(history_commit) = commit_to_history_commit(commit_id, &commit)
    else {
      return;
    };
    let author_secs = history_commit.author_time.timestamp();
    if filter.should_skip(&commit_id, author_secs) {
      return;
    }
    let Ok(tree) = commit.tree() else {
      return;
    };

    let mut recorder = gix::traverse::tree::Recorder::default();
    if tree.traverse().breadthfirst(&mut recorder).is_err() {
      return;
    }

    for entry in recorder.records {
      if !entry.mode.is_blob() {
        continue;
      }
      let Some(path) = bstring_to_pathbuf(&entry.filepath) else {
        continue;
      };

      let entry_oid = entry.oid;

      blobs
        .entry(entry_oid)
        .and_modify(|info| {
          info.consider(
            commit_id,
            author_secs,
            &path,
            location,
            priority,
            &history_commit,
          );
        })
        .or_insert_with(|| {
          let mut seen_commits = HashSet::new();
          seen_commits.insert(commit_id);
          BlobInfo {
            introducing_commit: commit_id,
            introducing_secs: author_secs,
            introducing_path: path.clone(),
            location: location.clone(),
            location_priority: priority,
            commits: vec![history_commit.clone()],
            seen_commits,
          }
        });
    }
  }
}

#[derive(Default)]
struct SkipFilter {
  time_cutoff: Option<i64>,
  up_to_ancestors: HashSet<ObjectId>,
  exact: HashSet<ObjectId>,
}

impl SkipFilter {
  fn should_skip(&self, commit_id: &ObjectId, author_secs: i64) -> bool {
    if self.exact.contains(commit_id) {
      return true;
    }
    if self.up_to_ancestors.contains(commit_id) {
      return true;
    }
    matches!(self.time_cutoff, Some(cutoff) if author_secs <= cutoff)
  }
}

enum HexResolution {
  Commit(ObjectId),
  NotCommit,
  NotFound,
  NotHex,
}

fn parse_cutoff_time(value: &str) -> Option<i64> {
  if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
    return Some(dt.timestamp());
  }

  if let Ok(dt) = DateTime::parse_from_str(value, "%a %b %e %H:%M:%S %Y %z") {
    return Some(dt.timestamp());
  }

  if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
    let next = date.succ_opt()?;
    let midnight = next.and_hms_opt(0, 0, 0)?;
    return Some(midnight.and_utc().timestamp() - 1);
  }

  None
}

fn resolve_hex_commit(repo: &Repository, value: &str) -> HexResolution {
  let Ok(prefix) = gix::hash::Prefix::from_hex(value) else {
    return HexResolution::NotHex;
  };

  let mut candidates = HashSet::new();
  let oid = match repo.objects.lookup_prefix(prefix, Some(&mut candidates)) {
    Ok(Some(Ok(oid))) => oid,
    _ => return HexResolution::NotFound,
  };

  match repo.find_object(oid) {
    Ok(object) if object.kind == gix::object::Kind::Commit => {
      HexResolution::Commit(oid)
    }
    Ok(_) => HexResolution::NotCommit,
    Err(_) => HexResolution::NotFound,
  }
}

fn commit_to_history_commit(
  commit_id: ObjectId,
  commit: &gix::Commit<'_>,
) -> Option<HistoryCommit> {
  let author = commit.author().ok()?;
  let time = author.time().ok()?;
  let offset = FixedOffset::east_opt(time.offset)?;
  let utc = DateTime::from_timestamp(time.seconds, 0)?;
  let author_time = utc.with_timezone(&offset);

  let title = commit
    .message()
    .ok()
    .map(|m| m.title.to_string())
    .unwrap_or_default();
  let subject = crate::formatting::sanitize_subject(&title);

  Some(HistoryCommit {
    commit: oid_hex(commit_id),
    author_time,
    subject,
  })
}

struct BlobInfo {
  introducing_commit: ObjectId,
  introducing_secs: i64,
  introducing_path: PathBuf,
  location: HistoryLocation,
  location_priority: u8,
  commits: Vec<HistoryCommit>,
  seen_commits: HashSet<ObjectId>,
}

impl BlobInfo {
  fn consider(
    &mut self,
    commit: ObjectId,
    secs: i64,
    path: &Path,
    location: &HistoryLocation,
    priority: u8,
    history_commit: &HistoryCommit,
  ) {
    if secs < self.introducing_secs {
      self.introducing_commit = commit;
      self.introducing_secs = secs;
      self.introducing_path = path.to_path_buf();
    }
    if priority > self.location_priority {
      self.location = location.clone();
      self.location_priority = priority;
    }
    if self.seen_commits.insert(commit) {
      self.commits.push(history_commit.clone());
    }
  }

  fn into_occurrence(mut self, oid: ObjectId) -> Option<BlobOccurrence> {
    let author_date =
      DateTime::from_timestamp(self.introducing_secs, 0)?.date_naive();

    self
      .commits
      .sort_by(|a, b| a.author_time.cmp(&b.author_time));

    Some(BlobOccurrence {
      oid,
      path: self.introducing_path,
      attribution: HistoryAttribution {
        commit: oid_hex(self.introducing_commit),
        author_date,
        location: self.location,
        also_in_working_tree: false,
        commits: self.commits,
      },
    })
  }
}

fn location_priority(location: &HistoryLocation) -> u8 {
  match location {
    HistoryLocation::Branch { current: true, .. } => 6,
    HistoryLocation::Branch { current: false, .. } => 5,
    HistoryLocation::RemoteRef(_) => 4,
    HistoryLocation::Tag(_) => 3,
    HistoryLocation::Stash => 2,
    HistoryLocation::Dangling => 1,
  }
}

fn strip_prefix<'a>(s: &'a str, prefix: &str) -> &'a str {
  s.strip_prefix(prefix).unwrap_or(s)
}

fn short_branch_name(full: &[u8]) -> Option<String> {
  let s = std::str::from_utf8(full).ok()?;
  Some(strip_prefix(s, "refs/heads/").to_owned())
}

fn bstring_to_pathbuf(bs: &gix::bstr::BString) -> Option<PathBuf> {
  let bytes: &[u8] = bs.as_ref();
  std::str::from_utf8(bytes).ok().map(PathBuf::from)
}

fn oid_hex(oid: ObjectId) -> String {
  oid.to_hex().to_string()
}
