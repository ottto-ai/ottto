//! Scan entry points: the `scan_source_roots*` drivers that run an
//! `OwnedSourceScan` to completion, the Codex parent-unresolvable reasons and
//! census-walk checks, and the test-only scan hooks.

use crate::snapshots::*;

#[cfg(test)]
pub fn scan_source_roots(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
) -> Result<SourceScanResult> {
    // Convenience entry used by tests and non-policy-aware callers: artifacts
    // are scraped unconditionally. Production sync uses
    // `scan_source_roots_before_policy` to honor the org upload policy.
    let mut result = scan_source_roots_before_policy(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
    )?;
    // This convenience entry has no later privacy/enrichment stage. Finalize
    // immediately so its incremental state has the same final semantic entity
    // sets as the production path, which explicitly finalizes after policy.
    finalize_scan_after_policy(source, &mut result, index);
    Ok(result)
}

/// Scan entry for callers that apply the upload policy themselves.
pub fn scan_source_roots_before_policy(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
    )
}

/// Dark-mode attribution-aware scan. It reuses the normal changed-file path;
/// the context only adds in-memory HMAC facts to sessions already selected for
/// parsing and never changes the filesystem polling cadence.
#[cfg(test)]
pub fn scan_source_roots_with_attribution(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        attribution_context,
        None,
        &[],
        false,
    )
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "test seam preserves the scanner attribution and watcher inputs"
)]
pub fn scan_source_roots_with_attribution_and_hints(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        attribution_context,
        None,
        hinted_paths,
        watcher_overflowed,
    )
}

/// Production scan entry that tracks both the local Claude OTLP sidecar and
/// bounded watcher hints. Keeping the support directory explicit preserves
/// the pure scan API for audits and backfills.
#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
pub fn scan_source_roots_with_attribution_and_claude_effort_and_hints(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    claude_effort_support_dir: Option<&Path>,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        attribution_context,
        claude_effort_support_dir,
        hinted_paths,
        watcher_overflowed,
    )
}

/// Compatibility entry retained for focused account-attribution and effort
/// sidecar tests that do not exercise watcher hints.
#[cfg(test)]
pub fn scan_source_roots_with_attribution_and_claude_effort(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    claude_effort_support_dir: Option<&Path>,
) -> Result<SourceScanResult> {
    scan_source_roots_with_attribution_and_claude_effort_and_hints(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        attribution_context,
        claude_effort_support_dir,
        &[],
        false,
    )
}

// Inner form with an injectable file cap so the cap-policy test can exercise
// truncation without materializing `MAX_BACKFILL_FILES_PER_SOURCE` files.
pub(in crate::snapshots) fn scan_source_roots_with_limit(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        file_limit,
        None,
        None,
        &[],
        false,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum CodexParentUnresolvable {
    // Identity evidence (L-5, PR-1).
    Absent,
    Duplicated,
    NotRegular,
    Oversize,
    // Ledger evidence. `NoLedger`: no session id, no session meta, or zero
    // signatures.
    NoLedger,
    LedgerCapped,
    // Parent debt: the parent itself is held or lossy. Transitive: cured when
    // the parent or one of its ancestors changes.
    ParentHeld,
    ParentLossy,
    /// PR-P: the parent rollout is outside the backfill window, so discovery
    /// never makes it a candidate.
    OutOfWindow,
    /// PR-P: the fork chain returns to itself.
    ForkCycle,
    // Scheduling: non-progressing held disclosure, never ownership proof.
    /// PR-P: the parent ref did not fit the interim 256-ref cap.
    DeferredRef,
    /// PR-P: the scope's restart budget is spent and the parent is still owed
    /// (derived, never a settling witness).
    DeferredRestart,
}
crate::durable_tail_codec::durable_enum!(CodexParentUnresolvable {
    0 => Absent,
    1 => Duplicated,
    2 => NotRegular,
    3 => Oversize,
    4 => NoLedger,
    5 => LedgerCapped,
    6 => ParentHeld,
    7 => ParentLossy,
    8 => OutOfWindow,
    9 => ForkCycle,
    10 => DeferredRef,
    11 => DeferredRestart,
});
crate::heap_layout_bound::no_heap!(true; CodexParentUnresolvable);

pub(in crate::snapshots) fn codex_census_walk_pending(traversal: &ScanTraversalCheckpoint) -> bool {
    traversal
        .pending_directories
        .iter()
        .any(|d| d.census_member)
}

/// The frozen-census validity filter: every census-member directory visited, nothing
/// capped, rejected, unreadable or vanished.
pub(in crate::snapshots) fn codex_frozen_census_valid(traversal: &ScanTraversalCheckpoint) -> bool {
    !codex_census_walk_pending(traversal)
        && traversal.counts.directory_entry_cap_exceeded_count == 0
        && traversal.counts.symlink_rejected_count == 0
        && traversal.counts.unreadable_path_count == 0
        && traversal.counts.disappeared_file_count == 0
}

#[cfg(test)]
thread_local! {
    /// Seam: runs after a Codex candidate's memo lookup (which probes
    /// its parent) and before its parse begins, so a test can change that
    /// parent between the two.
    pub(in crate::snapshots) static CODEX_BEFORE_PARSE: std::cell::RefCell<Option<CodexBeforeParseHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type CodexBeforeParseHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
pub(in crate::snapshots) fn with_codex_before_parse<T>(
    hook: impl FnMut(&Path) + 'static,
    run: impl FnOnce() -> T,
) -> T {
    CODEX_BEFORE_PARSE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    let value = run();
    CODEX_BEFORE_PARSE.with(|slot| *slot.borrow_mut() = None);
    value
}

#[cfg(test)]
thread_local! {
    /// Stage2-pre seam: runs once the active file's reader reports EOF and
    /// before its completion (EOF record, tier gate, revalidation, commit), so a test
    /// can change the file inside the window that `OwnedSourceScan::step`
    /// boundaries do not expose.
    pub(in crate::snapshots) static AFTER_READER_EOF: std::cell::RefCell<Option<AfterReaderEofHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    static TRANSCRIPT_IO_DENIED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn transcript_io_allowed() -> std::io::Result<()> {
    if TRANSCRIPT_IO_DENIED.with(|v| v.get()) {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "synthetic transcript I/O denial",
        ))
    } else {
        Ok(())
    }
}
#[cfg(test)]
pub(crate) fn with_transcript_io_denied<T>(run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TRANSCRIPT_IO_DENIED.with(|v| v.set(false));
        }
    }
    TRANSCRIPT_IO_DENIED.with(|v| assert!(!v.replace(true)));
    let _reset = Reset;
    assert!(transcript_io_allowed().is_err(), "denial seam is armed");
    run()
}

#[cfg(test)]
type AfterReaderEofHook = Box<dyn FnMut(&OwnedActiveFile)>;

#[cfg(test)]
pub(in crate::snapshots) fn with_after_reader_eof<T>(
    hook: impl FnMut(&OwnedActiveFile) + 'static,
    run: impl FnOnce() -> T,
) -> T {
    AFTER_READER_EOF.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    let value = run();
    AFTER_READER_EOF.with(|slot| *slot.borrow_mut() = None);
    value
}

#[cfg(test)]
pub(crate) fn scan_source_roots_with_test_limit(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        file_limit,
    )
}

/// Bounded fixture driver with real watcher input, using the service selector.
#[cfg(test)]
pub(crate) fn scan_source_roots_with_test_limit_and_hints(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
    hints: &[PathBuf],
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        source,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        file_limit,
        None,
        None,
        hints,
        false,
    )
}

/// A bounded Claude scan with an explicit local OTEL support directory, so
/// sidecar changes enter each family member's source fingerprint, and an
/// injectable page size.
#[cfg(test)]
pub(crate) fn scan_source_roots_with_test_limit_and_claude_support(
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
    claude_effort_support_dir: &Path,
) -> Result<SourceScanResult> {
    scan_source_roots_with_limit_and_attribution(
        SnapshotSource::ClaudeCode,
        roots,
        index,
        collected_at,
        requested_backfill_window_days,
        file_limit,
        None,
        Some(claude_effort_support_dir),
        &[],
        false,
    )
}

#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
pub(in crate::snapshots) fn scan_source_roots_with_limit_and_attribution(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
    file_limit: usize,
    attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    claude_effort_support_dir: Option<&Path>,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
) -> Result<SourceScanResult> {
    index.require_persistence_available()?;
    state_v2::before_collection(index)?;

    let mut state = OwnedSourceScan::new(
        source,
        roots,
        std::mem::take(index),
        collected_at,
        requested_backfill_window_days,
        file_limit,
        claude_effort_support_dir,
        hinted_paths,
        watcher_overflowed,
    );
    loop {
        // A refusal is terminal for this attempt, not cooperative progress.
        // Restore the resident graph before returning through the Result API.
        if let Err(error) = state_v2::before_collection(&state.index) {
            *index = state.index;
            return Err(error);
        }
        match state.step(attribution_context) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete {
                index: complete_index,
                scan,
                ..
            } => {
                *index = complete_index;
                return Ok(scan);
            }
        }
    }
}
