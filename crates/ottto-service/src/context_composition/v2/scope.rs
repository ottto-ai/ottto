//! Repository scopes and their state.
//!
//! A scope is a repository (its shared git folder) or, outside git, one
//! folder. Its upload key (`workspace_hash`) is the hash of the main
//! checkout folder, saved the first time the scope is seen and never
//! recomputed, so worktrees coming and going never change it. Each file is
//! pinned to the scope it was first read in, even after its folder is gone.

use super::aggregate::{Aggregate, StoredAggregate};
use super::checkpoint::{read_json, write_json, Checkpoint};
use super::file::Source;
use super::STATE_SCHEMA;
use crate::context_footprint::{
    repository_main_checkout, resolve_repository_identity, sha256_hex, workspace_label,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Identity fields uploaded with the scope (labels resolved with consent
/// and sent only while it holds).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct SavedIdentity {
    pub(super) repository_hash: Option<String>,
    pub(super) repository_label: Option<String>,
    pub(super) repository_label_source: Option<String>,
    pub(super) repository_identity_source: Option<String>,
    pub(super) workspace_kind: Option<String>,
    pub(super) workspace_label: Option<String>,
}

/// A scope as first seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ScopeInfo {
    pub(super) workspace_hash: String,
    /// Local only (labels and repo-relative file names); never uploaded.
    pub(super) workspace_path: String,
    pub(super) identity: SavedIdentity,
    /// The repository's shared git folder (local only): its linked
    /// worktrees are mapped to this scope while they exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) common_dir: Option<String>,
}

pub(super) trait ScopeResolver {
    /// The scope id and first-sight info of a transcript folder; `None`
    /// when the folder cannot be resolved now.
    fn resolve(&mut self, cwd: &Path) -> Option<(String, ScopeInfo)>;
}

/// Resolves scopes with git, as the footprint collector does.
pub(super) struct GitScopeResolver;

impl ScopeResolver for GitScopeResolver {
    fn resolve(&mut self, cwd: &Path) -> Option<(String, ScopeInfo)> {
        let identity = resolve_repository_identity(cwd, true);
        let Some(repository_hash) = identity.repository_hash.clone() else {
            let text = cwd.to_string_lossy();
            let scope = sha256_hex(&[text.as_ref()]);
            return Some((
                scope.clone(),
                ScopeInfo {
                    workspace_hash: scope,
                    workspace_path: text.into_owned(),
                    identity: SavedIdentity {
                        repository_hash: None,
                        repository_label: identity.repository_label,
                        repository_label_source: identity.repository_label_source,
                        repository_identity_source: None,
                        workspace_kind: identity.workspace_kind,
                        workspace_label: workspace_label(cwd),
                    },
                    common_dir: None,
                },
            ));
        };
        // The main checkout, when it still exists and is the same
        // repository; else the folder itself.
        let main = repository_main_checkout(cwd)
            .filter(|main| main.is_dir())
            .map(|main| {
                let main_identity = resolve_repository_identity(&main, true);
                (main, main_identity)
            })
            .filter(|(_, main_identity)| {
                main_identity.repository_hash.as_deref() == Some(repository_hash.as_str())
            });
        // The usual layout keeps the shared git folder in the main checkout.
        let common_dir = main
            .as_ref()
            .map(|(main, _)| main.join(".git"))
            .filter(|dir| dir.is_dir())
            .map(|dir| dir.to_string_lossy().into_owned());
        let (path, identity) = main.unwrap_or_else(|| (cwd.to_path_buf(), identity));
        let text = path.to_string_lossy().into_owned();
        Some((
            repository_hash,
            ScopeInfo {
                workspace_hash: sha256_hex(&[text.as_str()]),
                identity: SavedIdentity {
                    workspace_label: identity
                        .repository_label
                        .clone()
                        .or_else(|| workspace_label(&path)),
                    repository_hash: identity.repository_hash,
                    repository_label: identity.repository_label,
                    repository_label_source: identity.repository_label_source,
                    repository_identity_source: identity.repository_identity_source,
                    workspace_kind: identity.workspace_kind,
                },
                workspace_path: text,
                common_dir,
            },
        ))
    }
}

/// One scope's state on disk.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StoredScope {
    schema: u32,
    agent: String,
    scope_id: String,
    info: ScopeInfo,
    generation: u64,
    files: BTreeMap<String, Checkpoint>,
    aggregate: StoredAggregate,
}

/// The same layout, borrowed for writing.
#[derive(Serialize)]
struct StoredScopeRef<'a> {
    schema: u32,
    agent: &'a str,
    scope_id: &'a str,
    info: &'a ScopeInfo,
    generation: u64,
    files: &'a BTreeMap<String, Checkpoint>,
    aggregate: StoredAggregate,
}

/// One scope's state in memory.
#[derive(Debug)]
pub(super) struct Scope {
    pub(super) scope_id: String,
    pub(super) info: ScopeInfo,
    /// Bumped by each commit that changed totals.
    pub(super) generation: u64,
    pub(super) files: BTreeMap<String, Checkpoint>,
    pub(super) agg: Aggregate,
}

impl Scope {
    /// Bytes held in memory, approximately: totals and checkpoints.
    pub(super) fn accounted_bytes(&self) -> usize {
        self.agg.accounted_bytes()
            + self
                .files
                .iter()
                .map(|(key, checkpoint)| key.len() + checkpoint.accounted_bytes())
                .sum::<usize>()
    }

    pub(super) fn new(scope_id: &str, info: ScopeInfo) -> Self {
        Self {
            scope_id: scope_id.to_string(),
            info,
            generation: 0,
            files: BTreeMap::new(),
            agg: Aggregate::default(),
        }
    }
}

/// Linked worktrees are capped per repository, so a runaway folder never
/// grows the pins.
const MAX_WORKTREES: usize = 4096;

/// The linked worktrees a shared git folder knows, read from its
/// `worktrees/*/gitdir` files (no git process).
pub(super) fn linked_worktrees(common_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(common_dir.join("worktrees")) else {
        return Vec::new();
    };
    let mut worktrees = Vec::new();
    for entry in entries.flatten().take(MAX_WORKTREES) {
        let mut text = String::new();
        let read = std::fs::File::open(entry.path().join("gitdir")).and_then(|file| {
            std::io::Read::read_to_string(&mut std::io::Read::take(file, 4096), &mut text)
        });
        if read.is_err() {
            continue;
        }
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let gitdir = Path::new(text);
        let gitdir = if gitdir.is_absolute() {
            gitdir.to_path_buf()
        } else {
            lexical_join(&entry.path(), gitdir)
        };
        if let Some(worktree) = gitdir.parent() {
            worktrees.push(worktree.to_path_buf());
        }
    }
    worktrees
}

/// `base` joined with a relative `path`, with `.` and `..` resolved by name.
fn lexical_join(base: &Path, path: &Path) -> PathBuf {
    let mut out = base.to_path_buf();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A folder that no longer exists, written with its nearest existing parent
/// resolved (symbolic links followed), the way git records worktree paths.
/// `None` when that changes nothing.
pub(super) fn resolved_missing(path: &Path) -> Option<PathBuf> {
    let mut rest = Vec::new();
    let mut current = path;
    loop {
        if let Ok(resolved) = current.canonicalize() {
            let mut out = resolved;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return (out != path).then_some(out);
        }
        rest.push(current.file_name()?.to_os_string());
        current = current.parent()?;
    }
}

pub(super) fn scope_file_stem(source: Source, scope_id: &str) -> String {
    format!("{}-{scope_id}", source.label())
}

pub(super) fn scope_path(state_dir: &Path, source: Source, scope_id: &str) -> PathBuf {
    state_dir
        .join("scopes")
        .join(format!("{}.json", scope_file_stem(source, scope_id)))
}

/// Load a scope. `Err` = the file exists but cannot be used (bad state).
pub(super) fn load_scope(path: &Path, source: Source, scope_id: &str) -> Result<Option<Scope>, ()> {
    let Some(stored) = read_json::<StoredScope>(path)? else {
        return Ok(None);
    };
    if stored.schema != STATE_SCHEMA
        || stored.agent != source.label()
        || stored.scope_id != scope_id
    {
        return Err(());
    }
    let agg = stored.aggregate.into_aggregate().ok_or(())?;
    Ok(Some(Scope {
        scope_id: stored.scope_id,
        info: stored.info,
        generation: stored.generation,
        files: stored.files,
        agg,
    }))
}

/// Write a scope atomically; returns its size in bytes.
pub(super) fn save_scope(path: &Path, source: Source, scope: &Scope) -> std::io::Result<u64> {
    write_json(
        path,
        &StoredScopeRef {
            schema: STATE_SCHEMA,
            agent: source.label(),
            scope_id: &scope.scope_id,
            info: &scope.info,
            generation: scope.generation,
            files: &scope.files,
            aggregate: StoredAggregate::from_aggregate(&scope.agg),
        },
    )
}
