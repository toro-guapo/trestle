use std::path::{Path, PathBuf};

use gix::{
  Repository,
  index::entry::Mode,
  path::os_str_into_bstr,
  prelude::Find,
  worktree::{IndexPersistedOrInMemory, Stack},
};

// -----------------------------------------------------------------------------
// File state
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitFileState {
  pub in_head: bool,
  pub staged: bool,
  pub ignored: bool,
}

// -----------------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------------

pub struct GitRepository {
  excludes: Stack,
  workdir: PathBuf,
  repo: Repository,
}

pub fn open(path: &Path) -> Option<GitRepository> {
  let repo = gix::discover(path).ok()?;
  let worktree = repo.worktree()?;
  let workdir = worktree.base().to_path_buf();

  let index = repo.index_or_load_from_head_or_empty().ok()?;
  let excludes = repo
    .excludes(
      &index,
      None,
      gix::worktree::stack::state::ignore::Source::WorktreeThenIdMappingIfNotSkipped,
    )
    .ok()?
    .detach();

  Some(GitRepository {
    excludes,
    workdir,
    repo,
  })
}

impl GitRepository {
  pub fn workdir(&self) -> &Path {
    &self.workdir
  }

  pub fn thread_handle(&self) -> Option<GitThreadHandle> {
    Some(GitThreadHandle {
      excludes: self.excludes.clone(),
      objects: self.repo.objects.clone().into_arc().ok()?,
      workdir: self.workdir.clone(),
      head_index: head_tree_index(&self.repo),
      staging_index: staging_tree_index(&self.repo),
    })
  }
}

fn head_tree_index(repo: &Repository) -> IndexPersistedOrInMemory {
  try_head_tree_index(repo).unwrap_or_else(|| empty_index(repo))
}

fn try_head_tree_index(repo: &Repository) -> Option<IndexPersistedOrInMemory> {
  let commit = repo.head_commit().ok()?;
  let tree_id = commit.tree_id().ok()?;
  let index = repo.index_from_tree(&tree_id).ok()?;
  Some(IndexPersistedOrInMemory::InMemory(index))
}

fn staging_tree_index(repo: &Repository) -> IndexPersistedOrInMemory {
  match repo.try_index().ok().flatten() {
    Some(idx) => IndexPersistedOrInMemory::Persisted(idx),
    None => empty_index(repo),
  }
}

fn empty_index(repo: &Repository) -> IndexPersistedOrInMemory {
  let state = gix::index::State::new(repo.object_hash());
  let file = gix::index::File::from_state(state, repo.index_path());
  IndexPersistedOrInMemory::InMemory(file)
}

// -----------------------------------------------------------------------------
// Thread-local handle
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct GitThreadHandle {
  excludes: Stack,
  objects: gix::OdbHandleArc,
  workdir: PathBuf,
  head_index: IndexPersistedOrInMemory,
  staging_index: IndexPersistedOrInMemory,
}

fn check_excluded(
  excludes: &mut Stack,
  objects: &dyn Find,
  workdir: &Path,
  path: &Path,
  is_dir: bool,
) -> Option<bool> {
  let relative = path.strip_prefix(workdir).ok()?;
  let mode = if is_dir { Mode::DIR } else { Mode::FILE };
  let platform = excludes.at_path(relative, Some(mode), objects).ok()?;
  Some(platform.is_excluded())
}

impl GitThreadHandle {
  pub fn workdir(&self) -> &Path {
    &self.workdir
  }

  pub fn is_excluded(&mut self, path: &Path, is_dir: bool) -> bool {
    check_excluded(
      &mut self.excludes,
      &self.objects,
      &self.workdir,
      path,
      is_dir,
    )
    .unwrap_or(false)
  }

  pub fn file_state(&mut self, path: &Path) -> Option<GitFileState> {
    let relative = path.strip_prefix(&self.workdir).ok()?;
    let bstr = os_str_into_bstr(relative.as_os_str()).ok()?;

    let platform = self
      .excludes
      .at_path(relative, Some(Mode::FILE), &self.objects)
      .ok()?;

    Some(GitFileState {
      in_head: self.head_index.entry_by_path(bstr).is_some(),
      staged: self.staging_index.entry_by_path(bstr).is_some(),
      ignored: platform.is_excluded(),
    })
  }
}
