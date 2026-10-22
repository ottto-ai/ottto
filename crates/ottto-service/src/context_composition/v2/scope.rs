//! Repository scopes and their state.
//!
//! A scope is a repository (its shared git folder) or, outside git, one
//! folder. Its upload key (`workspace_hash`) is the hash of the main
//! checkout folder, saved the first time the scope is seen and never
//! recomputed, so worktrees coming and going never change it. Each file is
//! pinned to the scope it was first read in, even after its folder is gone.

use super::aggregate::{Aggregate, Day, StoredAggregate};
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
                },
            ));
        };
        // The main checkout, when it still exists and is the same
        // repository; else the folder itself.
        let (path, identity) = repository_main_checkout(cwd)
            .filter(|main| main.is_dir())
            .map(|main| {
                let main_identity = resolve_repository_identity(&main, true);
                (main, main_identity)
            })
            .filter(|(_, main_identity)| {
                main_identity.repository_hash.as_deref() == Some(repository_hash.as_str())
            })
            .unwrap_or_else(|| (cwd.to_path_buf(), identity));
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
    next_file_id: u32,
    files: BTreeMap<String, Checkpoint>,
    aggregate: StoredAggregate,
    ownership_logs: Vec<(Day, u64)>,
}

/// The same layout, borrowed for writing.
#[derive(Serialize)]
struct StoredScopeRef<'a> {
    schema: u32,
    agent: &'a str,
    scope_id: &'a str,
    info: &'a ScopeInfo,
    generation: u64,
    next_file_id: u32,
    files: &'a BTreeMap<String, Checkpoint>,
    aggregate: StoredAggregate,
    ownership_logs: Vec<(Day, u64)>,
}

/// One scope's state in memory.
#[derive(Debug)]
pub(super) struct Scope {
    pub(super) scope_id: String,
    pub(super) info: ScopeInfo,
    /// Bumped by each commit that changed totals.
    pub(super) generation: u64,
    pub(super) next_file_id: u32,
    pub(super) files: BTreeMap<String, Checkpoint>,
    pub(super) agg: Aggregate,
    pub(super) ownership_logs: BTreeMap<Day, u64>,
}

impl Scope {
    pub(super) fn new(scope_id: &str, info: ScopeInfo) -> Self {
        Self {
            scope_id: scope_id.to_string(),
            info,
            generation: 0,
            next_file_id: 1,
            files: BTreeMap::new(),
            agg: Aggregate::default(),
            ownership_logs: BTreeMap::new(),
        }
    }

    pub(super) fn allocate_file_id(&mut self) -> u32 {
        let id = self.next_file_id;
        self.next_file_id = self.next_file_id.wrapping_add(1).max(1);
        id
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

pub(super) fn ownership_dir(state_dir: &Path, source: Source, scope_id: &str) -> PathBuf {
    state_dir
        .join("uuids")
        .join(scope_file_stem(source, scope_id))
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
        next_file_id: stored.next_file_id.max(1),
        files: stored.files,
        agg,
        ownership_logs: stored.ownership_logs.into_iter().collect(),
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
            next_file_id: scope.next_file_id,
            files: &scope.files,
            aggregate: StoredAggregate::from_aggregate(&scope.agg),
            ownership_logs: scope
                .ownership_logs
                .iter()
                .map(|(day, length)| (*day, *length))
                .collect(),
        },
    )
}
