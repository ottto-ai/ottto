//! Workspace discovery: transcripts under the registered roots, grouped by
//! repository scope.

use super::cache::CompositionFilesSignature;
use super::{MAX_WORKSPACES_PER_CYCLE, SETTLE_WINDOW};
use crate::context_footprint::{
    collect_recent_jsonl_files, first_existing_cwd_from_jsonl, resolve_repository_identity,
    sha256_hex,
};
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

// -------------------------------------------------------------------------
// Discovery.
// -------------------------------------------------------------------------

#[derive(Clone)]
pub(super) struct WorkspaceScan {
    pub(super) workspace: PathBuf,
    pub(super) files: Vec<(PathBuf, SystemTime)>,
    pub(super) last_seen: SystemTime,
}

pub(super) fn discover_workspaces(
    roots: &[PathBuf],
    now: SystemTime,
    deadline: Instant,
) -> Result<Vec<WorkspaceScan>> {
    if Instant::now() >= deadline {
        return Err(anyhow!("workspace discovery budget expired"));
    }
    let mut files = Vec::new();
    for root in roots {
        collect_recent_jsonl_files(root, now, &mut files);
    }
    let files = newest_copy_per_file_name(files);

    // Map each transcript to a single workspace (its first resolvable cwd).
    let mut by_cwd: BTreeMap<String, WorkspaceScan> = BTreeMap::new();
    for (file, mtime) in files {
        let Some(cwd) = first_existing_cwd_from_jsonl(&file, deadline)? else {
            continue;
        };
        let entry = by_cwd.entry(cwd.clone()).or_insert_with(|| WorkspaceScan {
            workspace: PathBuf::from(&cwd),
            files: Vec::new(),
            last_seen: mtime,
        });
        entry.files.push((file, mtime));
        if entry.last_seen < mtime {
            entry.last_seen = mtime;
        }
    }

    // Collapse cwds that share a repository scope onto the most-recent
    // representative workspace, matching footprint's dedupe so identities line
    // up. All the scope's transcripts are aggregated into that one snapshot.
    let mut by_scope: BTreeMap<String, WorkspaceScan> = BTreeMap::new();
    for (_, scan) in by_cwd {
        if Instant::now() >= deadline {
            return Err(anyhow!("workspace discovery budget expired"));
        }
        let identity = resolve_repository_identity(&scan.workspace, false);
        let fallback = scan.workspace.to_string_lossy();
        let scope = identity
            .repository_hash
            .unwrap_or_else(|| sha256_hex(&[fallback.as_ref()]));
        match by_scope.get_mut(&scope) {
            Some(existing) => {
                existing.files.extend(scan.files.iter().cloned());
                if existing.last_seen < scan.last_seen {
                    existing.last_seen = scan.last_seen;
                    existing.workspace = scan.workspace.clone();
                }
            }
            None => {
                by_scope.insert(scope, scan);
            }
        }
    }

    let mut out: Vec<WorkspaceScan> = by_scope.into_values().collect();
    out.sort_by_key(|scan| std::cmp::Reverse(scan.last_seen));
    out.truncate(MAX_WORKSPACES_PER_CYCLE);
    if Instant::now() >= deadline {
        return Err(anyhow!("workspace discovery budget expired"));
    }
    Ok(out)
}

/// Registered roots can hold one transcript twice: a copied account folder, or
/// a rollout present in both `sessions` and `archived_sessions`. Transcript
/// file names carry the session id, so each counts once, keeping the newest
/// copy. Output is newest first, ties broken by path.
pub(super) fn newest_copy_per_file_name(
    mut files: Vec<(PathBuf, SystemTime)>,
) -> Vec<(PathBuf, SystemTime)> {
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut seen = std::collections::BTreeSet::new();
    files.retain(|(path, _)| seen.insert(transcript_copy_key(path)));
    files
}

/// Claude subagent ids are unique only within their parent session
/// (`<session>/subagents/agent-<id>.jsonl`), so that key keeps the parent.
pub(super) fn transcript_copy_key(path: &Path) -> Vec<std::ffi::OsString> {
    let name = path.file_name().map(|name| name.to_os_string());
    let session = path
        .parent()
        .filter(|dir| dir.file_name() == Some(std::ffi::OsStr::new("subagents")))
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .map(|session| session.to_os_string());
    session.into_iter().chain(name).collect()
}

/// Leaves out transcripts modified within `SETTLE_WINDOW` of `now` that the
/// last upload did not include; a later cycle picks them up. An uploaded
/// transcript stays even when recent, so a replacement never drops its history.
pub(super) fn retain_settled_files(
    files: &mut Vec<(PathBuf, SystemTime)>,
    now: SystemTime,
    uploaded: Option<&CompositionFilesSignature>,
) {
    files.retain(|(path, mtime)| {
        now.duration_since(*mtime)
            .is_ok_and(|age| age >= SETTLE_WINDOW)
            || uploaded.is_some_and(|files| files.contains_key(path.to_string_lossy().as_ref()))
    });
}
