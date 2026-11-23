//! One report-only row per ordinary sync cycle, taken between passes: process
//! heap in use, SQLite's own heap, and entry counts of the process-lifetime
//! maps keyed by sessions, paths, fingerprints or pages. Counts only, never
//! keys. A busy map reports null instead of waiting for its lock.
use serde::Serialize;

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct RestHeap {
    malloc_in_use_bytes: Option<u64>,
    sqlite_memory_used_bytes: u64,
    sqlite_memory_highwater_bytes: u64,
    rearm_clear_tags: usize,
    rearm_open_pages: usize,
    counted_poison_scopes: Option<usize>,
    counted_poison_fingerprints: Option<usize>,
    telemetry_notice_dirs: Option<usize>,
    telemetry_notice_roots: Option<usize>,
    state_v2_routes: Option<usize>,
    grant_rebind_refusals: Option<usize>,
    claude_token_owners: usize,
    claude_spawn_admitted: Option<usize>,
    repository_identities: Option<usize>,
    otlp_relay_journal_kept_rows: Option<u64>,
    otlp_relay_journal_kept_bytes: Option<u64>,
}

pub(super) fn collect() -> RestHeap {
    let (rearm_clear_tags, rearm_open_pages) = super::rearm_cause::rest_entries();
    let poison = crate::snapshot_sync::counted_poison_entries();
    let notices = crate::claude_local_otel::telemetry_notices::rest_entries();
    let kept = crate::claude_local_otel::relay_journal_kept();
    // SAFETY: SQLite documents both as thread-safe reads of its global
    // memory counters; passing 0 leaves the high-water mark unchanged.
    let (used, highwater) = unsafe {
        (
            rusqlite::ffi::sqlite3_memory_used(),
            rusqlite::ffi::sqlite3_memory_highwater(0),
        )
    };
    RestHeap {
        malloc_in_use_bytes: super::footprint::malloc_in_use(),
        sqlite_memory_used_bytes: u64::try_from(used).unwrap_or(0),
        sqlite_memory_highwater_bytes: u64::try_from(highwater).unwrap_or(0),
        rearm_clear_tags,
        rearm_open_pages,
        counted_poison_scopes: poison.map(|(scopes, _)| scopes),
        counted_poison_fingerprints: poison.map(|(_, fingerprints)| fingerprints),
        telemetry_notice_dirs: notices.map(|(dirs, _)| dirs),
        telemetry_notice_roots: notices.map(|(_, roots)| roots),
        state_v2_routes: crate::snapshots::state_v2::route_entries(),
        grant_rebind_refusals: crate::grant_rebind::refusal_entries(),
        claude_token_owners: crate::agent_status::token_owner_entries(),
        claude_spawn_admitted: spawn_admitted(),
        repository_identities: crate::snapshots::repository_identity_entries(),
        otlp_relay_journal_kept_rows: kept.map(|(rows, _)| rows),
        otlp_relay_journal_kept_bytes: kept.map(|(_, bytes)| bytes),
    }
}

#[cfg(unix)]
fn spawn_admitted() -> Option<usize> {
    crate::claude_spawn_gate::probe::admitted_entries()
}
#[cfg(not(unix))]
fn spawn_admitted() -> Option<usize> {
    None
}

/// Emit the row. Called by the ordinary sync loop after a cycle, never inside a pass.
pub(crate) fn emit() {
    super::traversal_point("process_rest_heap", "unknown", &collect());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_heap_row_is_counts_only_and_reads_without_side_effects() {
        let first = collect();
        let second = collect();
        assert_eq!(first.rearm_clear_tags, second.rearm_clear_tags);
        assert_eq!(first.claude_token_owners, second.claude_token_owners);
        let row = serde_json::to_value(&first).unwrap();
        let fields = row.as_object().unwrap();
        assert_eq!(fields.len(), 16);
        assert!(fields.values().all(|v| v.is_null() || v.is_u64()));
        assert!(fields.contains_key("sqlite_memory_used_bytes"));
        assert!(fields.contains_key("repository_identities"));
    }
}
