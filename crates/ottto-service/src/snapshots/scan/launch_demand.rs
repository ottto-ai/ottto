//! Launch demand: which launcher workers a scan candidate or parsed file
//! asks launch facts for, and the held Claude family launch-context check.

use crate::snapshots::*;

pub(in crate::snapshots) fn launch_workers_for_candidate(
    source: SnapshotSource,
    candidate: &CandidateFile,
    inventory: Option<&codex_file_join::HeaderInventory>,
) -> Vec<String> {
    if source == SnapshotSource::Codex {
        if let Some(owner) =
            inventory.and_then(|inventory| inventory.owner_for_path(&candidate.path))
        {
            return vec![owner.to_owned()];
        }
    }
    launch_workers_for_path(source, &candidate.path)
}

// Path hints authorize only lookup demand, never transcript ownership or facts.
pub(in crate::snapshots) fn launch_workers_for_path(
    source: SnapshotSource,
    path: &Path,
) -> Vec<String> {
    if claude_subagent_has_no_launch_worker(source, path) {
        return Vec::new();
    }
    match source {
        SnapshotSource::Codex => codex_session_id_candidates_from_path(path),
        SnapshotSource::ClaudeCode | SnapshotSource::Pi => path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|stem| vec![stem.to_string()])
            .unwrap_or_default(),
    }
}

// Finish-time demand for the parsed file. A Claude subagent carries its
// parent's `sessionId`, but `into_items` re-keys it from the path before any
// launch fact lookup, so demanding that parent would only discard the prepared
// batch for a key no consumer reads.
pub(in crate::snapshots) fn launch_workers_for_parsed(
    source: SnapshotSource,
    parsed_session_id: Option<&str>,
    path: &Path,
) -> Vec<String> {
    match parsed_session_id {
        _ if claude_subagent_has_no_launch_worker(source, path) => Vec::new(),
        Some(id) if source == SnapshotSource::Codex => vec![resolve_codex_identity(id)],
        Some(id) => vec![id.to_owned()],
        None => launch_workers_for_path(source, path),
    }
}

// Same predicate as the `into_items` re-key: the re-keyed id is never a UUID,
// and launch workers are UUID-only, so no launch event can name this file.
fn claude_subagent_has_no_launch_worker(source: SnapshotSource, path: &Path) -> bool {
    source == SnapshotSource::ClaudeCode && claude_subagent_identity(path).is_some()
}

pub(in crate::snapshots) fn claude_held_family_matches_launch_context(
    index: &ScanIndex,
    root: &str,
    current: &CandidateFile,
    remaining: &VecDeque<CandidateFile>,
    events: &crate::launch_events::LaunchEventInventory,
) -> bool {
    let Some(record) = index.claude_usage_authority_quarantine.get(root) else {
        return false;
    };
    let mut members = BTreeSet::new();
    for member in std::iter::once(current).chain(remaining.iter()) {
        let Some((family, id)) = claude_index_path_family_member(&member.path) else {
            continue;
        };
        if family != root {
            continue;
        }
        members.insert(id);
        let mut semantic = member.clone();
        if member.path != current.path {
            let workers = launch_workers_for_path(SnapshotSource::ClaudeCode, &member.path);
            if !events.prepared(&workers) {
                return false;
            }
            if let Some(witness) = events.witness(&workers) {
                semantic.source_file_fingerprint = sha256_hex(&[
                    "launcher_worker_context:v1",
                    &semantic.source_file_fingerprint,
                    &witness,
                ]);
            }
        }
        if index
            .claude_usage_authority_candidate_requires_family_reparse(&semantic)
            .is_some()
        {
            return false;
        }
    }
    members
        == record
            .member_source_file_fingerprints
            .keys()
            .cloned()
            .collect()
}
