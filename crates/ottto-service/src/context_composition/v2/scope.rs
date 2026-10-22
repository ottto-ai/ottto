//! Repository scopes and their state.
//!
//! A scope is a repository (its shared git folder) or, outside git, one
//! folder. Its upload key (`workspace_hash`) is the hash of the main
//! checkout folder, saved the first time the scope is seen and never
//! recomputed, so worktrees coming and going never change it. Each file is
//! pinned to the scope it was first read in, even after its folder is gone.

use super::aggregate::{stable_hash, Day};
use super::aggregate::{Aggregate, AggregateRef, StoredAggregate};
use super::checkpoint::{
    create_dir_durable, read_json, sync_dir, write_atomic, write_json, write_packed, Checkpoint,
};
use super::file::Source;
use super::STATE_SCHEMA;
use crate::context_footprint::{
    repository_main_checkout, resolve_repository_identity, sha256_hex, workspace_label,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

/// Immutable generation files keep the previous manifest valid until commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ShardRef {
    generation: u64,
    sha: String,
}

pub(super) const SHARDS: u16 = 256;
pub(super) fn shard_id(key: &str) -> u16 {
    (stable_hash(key.as_bytes()) % u64::from(SHARDS)) as u16
}

#[derive(Debug, Serialize, Deserialize)]
struct Shard {
    schema: u32,
    generation: u64,
    files: BTreeMap<String, Checkpoint>,
}

/// A compact membership multiset. One row per transcript/name at its last
/// access day. Duplicate sessions are collapsed only when building top rows.
pub(super) type FileSession = (u32, u64, Day);

/// One scope's state on disk.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StoredScope {
    schema: u32,
    agent: String,
    scope_id: String,
    info: ScopeInfo,
    generation: u64,
    #[serde(default)]
    files: BTreeMap<String, Checkpoint>,
    #[serde(default)]
    aggregate: StoredAggregate,
    #[serde(default)]
    shards: BTreeMap<u16, ShardRef>,
    #[serde(default)]
    file_sessions: Vec<FileSession>,
    #[serde(default)]
    totals: Option<ShardRef>,
}

/// The same layout, borrowed for writing.
#[derive(Serialize)]
struct StoredScopeRef<'a> {
    schema: u32,
    agent: &'a str,
    scope_id: &'a str,
    info: &'a ScopeInfo,
    generation: u64,
    shards: &'a BTreeMap<u16, ShardRef>,
    totals: ShardRef,
}

#[derive(Deserialize)]
struct StoredTotals {
    aggregate: StoredAggregate,
    file_sessions: Vec<FileSession>,
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
    pub(super) shards: BTreeMap<u16, ShardRef>,
    pub(super) file_sessions: Vec<FileSession>,
    /// Shards whose file was checked against its reference in this run.
    verified: BTreeSet<u16>,
}

/// The files one committed generation references: its totals and shards.
#[derive(Debug, Clone, Default)]
pub(super) struct Refs {
    totals: Option<u64>,
    shards: BTreeMap<u16, u64>,
}

impl Scope {
    /// Bytes held in memory, approximately: totals and checkpoints.
    pub(super) fn accounted_bytes(&self) -> usize {
        self.agg.accounted_bytes()
            + self.file_sessions.capacity() * std::mem::size_of::<FileSession>()
            + self.shards.len() * 128
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
            shards: BTreeMap::new(),
            file_sessions: Vec::new(),
            verified: BTreeSet::new(),
        }
    }

    /// The files this state references (kept by the next commit's cleanup).
    pub(super) fn refs(&self) -> Refs {
        Refs {
            totals: Some(self.generation),
            shards: self
                .shards
                .iter()
                .map(|(id, reference)| (*id, reference.generation))
                .collect(),
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

/// The previous committed manifest, kept until a newer commit is verified.
/// A commit keeps it as the fallback; its files stay until the next
/// verified commit replaces it.
pub(super) fn prev_path(path: &Path) -> PathBuf {
    path.with_extension("prev.json")
}

/// Keep the manifest now committed as the previous generation, before a new
/// one replaces it.
pub(super) fn keep_previous(path: &Path) -> std::io::Result<()> {
    let mut current = std::fs::File::open(path)?;
    write_atomic(&prev_path(path), |file| {
        std::io::copy(&mut current, file).map(|_| ())
    })
}

/// Load a scope. `Err` = the file exists but cannot be used (bad state).
pub(super) fn load_scope(path: &Path, source: Source, scope_id: &str) -> Result<Option<Scope>, ()> {
    load_manifest(path, path, source, scope_id)
}

/// Load the previous generation (`None` when there is none or it cannot
/// be used either). Its files are named after the scope's manifest.
pub(super) fn load_previous(path: &Path, source: Source, scope_id: &str) -> Option<Scope> {
    load_manifest(&prev_path(path), path, source, scope_id)
        .ok()
        .flatten()
}

fn load_manifest(
    manifest: &Path,
    path: &Path,
    source: Source,
    scope_id: &str,
) -> Result<Option<Scope>, ()> {
    let Some(stored) = read_json::<StoredScope>(manifest)? else {
        return Ok(None);
    };
    if stored.schema != STATE_SCHEMA
        || stored.agent != source.label()
        || stored.scope_id != scope_id
    {
        return Err(());
    }
    let (agg, file_sessions) = if let Some(reference) = stored.totals {
        let file = path.with_extension(format!("totals.{}.zst", reference.generation));
        if file_sha(&file).map_err(|_| ())? != reference.sha {
            return Err(());
        }
        let totals: StoredTotals = read_json(&file)?.ok_or(())?;
        (totals.aggregate.into_aggregate(), totals.file_sessions)
    } else {
        (stored.aggregate.into_aggregate(), stored.file_sessions)
    };
    Ok(Some(Scope {
        scope_id: stored.scope_id,
        info: stored.info,
        generation: stored.generation,
        files: stored.files,
        agg,
        shards: stored.shards,
        file_sessions,
        verified: BTreeSet::new(),
    }))
}

/// Read a just-written manifest back and check the totals and the shards it
/// wrote against their hashes. Only a verified commit lets the cleanup drop
/// the previous generation.
pub(super) fn verify_commit(path: &Path, source: Source, scope: &Scope) -> bool {
    let Ok(Some(stored)) = read_json::<StoredScope>(path) else {
        return false;
    };
    if stored.schema != STATE_SCHEMA
        || stored.agent != source.label()
        || stored.scope_id != scope.scope_id
        || stored.generation != scope.generation
    {
        return false;
    }
    let Some(totals) = stored.totals else {
        return false;
    };
    let file = path.with_extension(format!("totals.{}.zst", totals.generation));
    if totals.generation != scope.generation || file_sha(&file).ok() != Some(totals.sha) {
        return false;
    }
    stored.shards.iter().all(|(id, reference)| {
        reference.generation != scope.generation
            || file_sha(&shard_path(path, *id, reference.generation)).ok()
                == Some(reference.sha.clone())
    })
}

/// Write a scope atomically; returns its size in bytes.
pub(super) fn save_scope(path: &Path, source: Source, scope: &Scope) -> std::io::Result<u64> {
    #[derive(Serialize)]
    struct Totals<'a> {
        aggregate: AggregateRef<'a>,
        file_sessions: &'a [FileSession],
    }
    let file = path.with_extension(format!("totals.{}.zst", scope.generation));
    let bytes = write_packed(
        &file,
        &Totals {
            aggregate: AggregateRef {
                agg: &scope.agg,
                generations: true,
            },
            file_sessions: &scope.file_sessions,
        },
    )?;
    let sha = file_sha(&file)?;
    let manifest = StoredScopeRef {
        schema: STATE_SCHEMA,
        agent: source.label(),
        scope_id: &scope.scope_id,
        info: &scope.info,
        generation: scope.generation,
        shards: &scope.shards,
        totals: ShardRef {
            generation: scope.generation,
            sha,
        },
    };
    Ok(bytes + write_json(path, &manifest)?)
}

fn shard_path(path: &Path, id: u16, generation: u64) -> PathBuf {
    path.with_extension(format!("s{id:03}.{generation}.zst"))
}

impl Scope {
    /// Only the shard selected by changed bytes is read. Legacy unpublished
    /// state is migrated on its first commit without reading transcripts.
    pub(super) fn load_shard(&mut self, path: &Path, id: u16) -> Result<(), ()> {
        if let Some(reference) = self.shards.get(&id) {
            let file = shard_path(path, id, reference.generation);
            if !self.verified.contains(&id) && file_sha(&file).map_err(|_| ())? != reference.sha {
                return Err(());
            }
            let shard: Shard = read_json(&file)?.ok_or(())?;
            if shard.schema != STATE_SCHEMA
                || shard.generation != reference.generation
                || shard.files.keys().any(|key| shard_id(key) != id)
            {
                return Err(());
            }
            self.files = shard.files;
        }
        Ok(())
    }

    pub(super) fn save_shard(
        &mut self,
        path: &Path,
        id: u16,
        generation: u64,
    ) -> std::io::Result<u64> {
        let file = shard_path(path, id, generation);
        #[derive(Serialize)]
        struct ShardRef<'a> {
            schema: u32,
            generation: u64,
            files: &'a BTreeMap<String, Checkpoint>,
        }
        let bytes = write_packed(
            &file,
            &ShardRef {
                schema: STATE_SCHEMA,
                generation,
                files: &self.files,
            },
        )?;
        let sha = file_sha(&file)?;
        self.shards.insert(id, self::ShardRef { generation, sha });
        Ok(bytes)
    }

    /// Check the referenced files of these shards (missing, partial or a
    /// different hash) before anything is read; returns the damaged ones.
    pub(super) fn verify_shards(
        &mut self,
        path: &Path,
        ids: impl IntoIterator<Item = u16>,
    ) -> BTreeSet<u16> {
        let mut damaged = BTreeSet::new();
        for id in ids {
            let Some(reference) = self.shards.get(&id) else {
                continue;
            };
            if file_sha(&shard_path(path, id, reference.generation)).ok()
                == Some(reference.sha.clone())
            {
                self.verified.insert(id);
            } else {
                damaged.insert(id);
            }
        }
        damaged
    }

    /// Stop referencing a damaged shard; returns its file (to set aside).
    pub(super) fn drop_shard(&mut self, path: &Path, id: u16) -> Option<PathBuf> {
        self.verified.remove(&id);
        let reference = self.shards.remove(&id)?;
        Some(shard_path(path, id, reference.generation))
    }

    /// Recovery and test inspection only. The daily path never hydrates all
    /// checkpoints; it holds one changed shard at a time.
    pub(super) fn load_all_shards(&mut self, path: &Path) -> Result<(), ()> {
        let mut all = std::mem::take(&mut self.files);
        for id in self.shards.keys().copied().collect::<Vec<_>>() {
            self.load_shard(path, id)?;
            all.append(&mut self.files);
        }
        self.files = all;
        Ok(())
    }

    /// Remove generations neither this state nor `previous` references, only
    /// after the new manifest is verified.
    pub(super) fn clean_shards(&self, path: &Path, previous: &Refs) {
        let Some(dir) = path.parent() else { return };
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            return;
        };
        let current = self.refs();
        let kept = |refs: &Refs, id: Option<u16>, generation: u64| match id {
            None => refs.totals == Some(generation),
            Some(id) => refs.shards.get(&id) == Some(&generation),
        };
        for (file, id, generation) in generation_files(dir, stem) {
            if !kept(&current, id, generation) && !kept(previous, id, generation) {
                let _ = std::fs::remove_file(file);
            }
        }
    }
}

/// Totals (`None`) and shard files of a scope, with their generations.
fn generation_files(dir: &Path, stem: &str) -> Vec<(PathBuf, Option<u16>, u64)> {
    let prefix = format!("{stem}.s");
    let totals = format!("{stem}.totals.");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(rest) = name.strip_prefix(&totals) {
            if let Some(generation) = rest
                .strip_suffix(".zst")
                .and_then(|n| n.parse::<u64>().ok())
            {
                out.push((entry.path(), None, generation));
            }
            continue;
        }
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let mut parts = rest.split('.');
        let (Some(id), Some(generation), Some("zst"), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if let (Ok(id), Ok(generation)) = (id.parse::<u16>(), generation.parse::<u64>()) {
            out.push((entry.path(), Some(id), generation));
        }
    }
    out
}

/// The highest generation any file of the scope carries: a commit after a
/// fallback must never reuse a name the failed generation wrote.
pub(super) fn highest_generation(path: &Path) -> u64 {
    let (Some(dir), Some(stem)) = (path.parent(), path.file_stem().and_then(|s| s.to_str())) else {
        return 0;
    };
    generation_files(dir, stem)
        .into_iter()
        .map(|(_, _, generation)| generation)
        .max()
        .unwrap_or(0)
}

/// Every state file of one scope (manifests, totals, shards, upload ack).
pub(super) fn scope_files(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (path.parent(), path.file_stem().and_then(|s| s.to_str())) else {
        return Vec::new();
    };
    let prefix = format!("{stem}.");
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .map(|entry| entry.path())
        .collect()
}

/// Move state files that cannot be used out of the way, under
/// `quarantine/<label>`, for inspection. Nothing reads them again.
pub(super) fn set_aside(state_dir: &Path, label: &str, files: &[PathBuf]) -> std::io::Result<()> {
    let target = state_dir.join("quarantine").join(label);
    create_dir_durable(&target)?;
    let mut sources = BTreeSet::new();
    for file in files {
        let Some(name) = file.file_name() else {
            continue;
        };
        match std::fs::rename(file, target.join(name)) {
            Ok(()) => {
                if let Some(dir) = file.parent() {
                    sources.insert(dir.to_path_buf());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    sync_dir(&target)?;
    for dir in sources {
        sync_dir(&dir)?;
    }
    Ok(())
}

fn file_sha(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    #[cfg(test)]
    super::checkpoint::record_read(file.metadata()?.len());
    let mut digest = Sha256::new();
    let mut buf = [0; 16 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn checkpoint_members(checkpoint: &Checkpoint) -> Vec<FileSession> {
    use super::checkpoint::name_hash;
    let Some(session) = checkpoint.contribution.session() else {
        return Vec::new();
    };
    let session = session.split(" (subagent:").next().unwrap_or(session);
    let session = stable_hash(session.as_bytes());
    let mut names = BTreeMap::new();
    for (hash, day) in checkpoint.cold.iter().flat_map(|c| c.files()).chain(
        checkpoint
            .contribution
            .file_days()
            .map(|(day, name)| (name_hash(name), day)),
    ) {
        let latest = names.entry(hash).or_insert(day);
        *latest = (*latest).max(day);
    }
    names
        .into_iter()
        .map(|(name, day)| (name, session, day))
        .collect()
}

/// Multiset subtraction/addition, once per scope, without loading unchanged shards.
pub(super) fn update_members(
    rows: &mut Vec<FileSession>,
    mut remove: Vec<FileSession>,
    add: Vec<FileSession>,
    floor: Day,
) {
    rows.sort_unstable();
    remove.sort_unstable();
    let mut remove = remove.into_iter().peekable();
    rows.retain(|row| {
        while remove.peek().is_some_and(|old| old < row) {
            remove.next();
        }
        if remove.peek() == Some(row) {
            remove.next();
            false
        } else {
            row.2 >= floor
        }
    });
    rows.extend(add.into_iter().filter(|row| row.2 >= floor));
    rows.sort_unstable();
}
