use self::finish::finish_sync_source;
use self::progress_rows::sync_progress_parent;
use self::progress_rows::HeadConflictChallenge;
use self::progress_rows::PendingCacheHeadFile;
use self::progress_rows::PermanentSnapshotRejection;
pub(crate) use self::progress_rows::SnapshotProgressLock;
use self::progress_rows::SnapshotUploadProgress;
#[cfg(test)]
use self::progress_rows::SnapshotUploadProgressCas;
#[cfg(test)]
use self::progress_rows::SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION;
mod finish;
#[cfg(test)]
use self::lane::collect_file_activity_with_retry;
#[cfg(test)]
use self::lane::cycle_heartbeat;
use self::lane::local_cadence_phase_offset;
#[cfg(test)]
pub(crate) use self::lane::retained_with_withheld;
use self::lane::retry_ordinary_owned;
pub use self::lane::spawn_claude_agent_status_refresh;
pub use self::lane::spawn_failed_verification_reverify;
pub use self::lane::spawn_local_health_projection_sync;
pub use self::lane::spawn_local_snapshot_sync;
pub use self::lane::spawn_one_shot_local_snapshot_sync;
pub use self::lane::spawn_startup_source_reverify;
#[cfg(test)]
use self::lane::ClaudeAccountSwitchProbe;
#[cfg(test)]
use self::lane::ReverifySchedule;
#[cfg(test)]
use self::lane::SnapshotCycleOwner;
#[cfg(test)]
use self::lane::FAILED_VERIFY_RETRY_INITIAL;
#[cfg(test)]
use self::lane::FAILED_VERIFY_RETRY_MAX;
use self::retry::cadence_phase_offset;
#[cfg(test)]
use self::retry::clear_cadence_state_for_test;
use self::retry::clear_shed_streak;
#[cfg(test)]
use self::retry::clear_source_upload_deadlines_for_test;
pub(crate) use self::retry::collection_health;
use self::retry::defer_source_uploads;
pub(crate) use self::retry::full_jitter_backoff;
#[cfg(test)]
use self::retry::negotiated_wait;
use self::retry::note_shed_and_backoff;
use self::retry::paced_scan_due;
use self::retry::record_server_scan_directive;
pub(crate) use self::retry::reset_collection_health;
pub(crate) use self::retry::shed_backoff;
pub(crate) use self::retry::small_source_upload;
use self::retry::source_cadence_wait;
#[cfg(test)]
use self::retry::source_cadences;
use self::retry::source_paced_due;
#[cfg(test)]
use self::retry::source_shed_streaks;
use self::retry::source_upload_backoff_remaining;
#[cfg(test)]
use self::retry::source_upload_deadlines;
pub(crate) use self::retry::start_collection_health;
use self::retry::with_source_cadence;
use self::retry::with_source_cadence_state;
use self::retry::CADENCE_WAIT_SLICE;
use self::retry::MAX_CYCLE_INTERVAL;
#[cfg(test)]
use self::retry::SHED_BACKOFF_BASE;
use self::upload::apply_bootstrapped_cache_heads;
use self::upload::attach_head_conflict_answers;
#[cfg(test)]
use self::upload::bootstrap_cache_heads;
use self::upload::bootstrap_cache_heads_with_budget;
use self::upload::cache_full_replacement_negotiated;
use self::upload::cache_head_file_groups;
use self::upload::cache_head_index_key;
use self::upload::cache_head_probe;
#[cfg(test)]
use self::upload::cache_head_probe_held;
use self::upload::cache_head_selection_witness;
pub(crate) use self::upload::cache_session_key;
use self::upload::capture_deferred_cache_head_identities;
use self::upload::effective_snapshot_upload_body_witness;
use self::upload::identity_cache_wire_reserve;
use self::upload::prepare_snapshot_cache_for_upload;
#[cfg(test)]
pub(crate) use self::upload::retained_refusal_settles_for_test;
pub(crate) use self::upload::snapshot_batch_request;
use self::upload::snapshot_upload_batch_class;
use self::upload::with_bootstrap_deferred;
use self::upload::with_retained_refusal_conflicts;
mod lane;
#[cfg(test)]
use self::upload::ack_usage_identical;
use self::upload::attempt_snapshot_page;
use self::upload::is_shed_failure;
#[cfg(test)]
use self::upload::is_snapshot_batch_split_failure;
use self::upload::is_upload_outage;
use self::upload::require_normal_write_ack_for_legacy_reconciliation;
use self::upload::snapshot_entity_deferred;
pub(crate) use self::upload::snapshot_packing_json_length;
use self::upload::snapshot_upload_error_class;
#[cfg(test)]
use self::upload::upload_resumable_batches;
#[cfg(test)]
use self::upload::upload_resumable_batches_with_body_witness;
use self::upload::upload_resumable_batches_with_literal_families;
use self::upload::ResumableUploadResult;
use self::upload::SnapshotBatchPreflightRejected;
use self::upload::SnapshotBatchResponseRejected;
use self::upload::SnapshotEntityDeferred;
use self::upload::SnapshotLocalStateRejected;
#[cfg(test)]
use self::upload::SnapshotPackingLength;
use self::upload::SnapshotPageOutcome;
use self::upload::SnapshotUploadErrorClass;
use self::upload::SourcesFailed;
mod upload;
use self::continuation::continuation_finish_inputs;
#[cfg(test)]
use self::continuation::prepare_continuation_source;
#[cfg(test)]
use self::continuation::take_continuation_inputs;
#[cfg(test)]
use self::continuation::ContinuationInputs;
#[cfg(test)]
use self::continuation::ContinuationRefusal;
#[cfg(test)]
use self::prepare::collect_preparation_with_rotation;
pub(crate) use self::prepare::copy_unproven_upload_context;
use self::prepare::cycle_replay_generation;
pub(crate) use self::prepare::cycle_sampled_scope;
use self::prepare::cycle_upload_context;
#[cfg(test)]
use self::prepare::load_source_checkpoints;
use self::prepare::prepare_sync_source;
pub(crate) use self::prepare::resumed_prefix_upload_context;
use self::prepare::SourcePreparation;
use self::prepare::SourcePreparationStep;
pub(crate) use self::telemetry_only::apply_claude_local_evidence_to_scan;
#[cfg(test)]
pub(crate) use self::telemetry_only::apply_claude_local_evidence_to_scan_with_accepted_for_test;
use self::telemetry_only::apply_claude_local_evidence_to_scan_with_ledger_and_budget;
use self::telemetry_only::claude_evidence_session_ids;
#[cfg(test)]
pub(crate) use self::telemetry_only::evidence_chunks_for_test;
use self::telemetry_only::reconciliation_agent_status;
pub use self::telemetry_only::ClaudeLocalEvidenceStats;
#[cfg(test)]
use self::telemetry_only::E2_AFTER_API_ATTACH;
#[cfg(test)]
use self::telemetry_only::ONE_EVIDENCE_CHUNK;
#[cfg(test)]
use self::telemetry_only::PAGE_END_RELEASE;
#[cfg(test)]
use self::telemetry_only::REFERENCE_ROOTS;
#[cfg(test)]
use self::telemetry_only::WHOLE_CORPUS_EVIDENCE;
mod prepare;
use self::continuation::PlatformGates;
#[cfg(test)]
use self::retry::with_inplace_retry_test_clock;
use self::retry::{
    inplace_retry_failed_after, inplace_retry_sleep, InplaceRetryBudget,
    SNAPSHOT_INPLACE_RETRY_LIMIT, SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET,
};
use crate::local_resource_diagnostics::StageWindow;
#[cfg(test)]
use crate::snapshots::snapshot_quarantine_witness;
#[cfg(test)]
pub(crate) mod upload_context_receipt_tests;
use crate::adaptive_collector::{CadenceConfig, SourceCadence};
use crate::agent_status::AgentStatusCollection;
#[cfg(test)]
use crate::backfill::save_backfill_state;
use crate::backfill::{
    apply_backfill_cutoff, current_historical_replay, load_backfill_state,
    mark_backfill_complete_for_destination, pending_backfill_sources_for_destination,
    update_backfill_state,
};
use crate::codex_scan_diagnostics::{self, CodexScanDiagnostics};
use crate::detected_uses::{
    aggregate_detected_uses, merge_detected_uses, DETECTED_USE_RETENTION_DAYS,
};
use crate::local_resource_diagnostics::claude_contract;
use crate::session_attribution::SessionAttributionContext;
use crate::snapshot_client::{
    load_snapshot_device_credentials, AgentStatusSnapshotUploadRequest,
    AgentStatusSnapshotUploadResponse, BatchAuthorizationRejected, BatchRejected, CensusBlockCause,
    LocalHealthAuthorizationRejected, LocalHealthProjectionRejected, RefusedSnapshotIndexes,
    RelayTokenAuthorizationRejected, ShedSnapshotIndexes, SnapshotAckRejected, SnapshotApiClient,
    SnapshotStatusReportKind, SnapshotStatusRequest, UploadFailureDiagnostics, UploadShed,
    CENSUS_RESIDUE_ERROR_CODE, CENSUS_RESIDUE_STATUS_CONTRACT,
};
#[cfg(test)]
use crate::snapshots::apply_upload_policy;
use crate::snapshots::validate_snapshot_batch_request;
use crate::snapshots::{
    collector_version, finalize_scan_after_policy_with_body_witness,
    prepare_codex_recovery_diagnostics, snapshot_quarantine_deadline_is_bounded,
    snapshot_upload_body_witness, ScanIndex, SnapshotBatchRequest, SnapshotItem,
    SnapshotQuarantineDisposition, SnapshotQuarantineRecord, SnapshotQuarantineWitness,
    SnapshotSource, SnapshotSourceManifest, SnapshotUploadPolicy, SourceScanResult,
    UnsettledUploadCause, MAX_BACKFILL_FILES_PER_SOURCE, MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
    SNAPSHOT_QUARANTINE_RETRY_SECONDS, SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_STATUS_SCHEMA_VERSION,
};
use crate::LocalDaemon;
use crate::LocalHealthUploadFailureKind;
use anyhow::{anyhow, Context, Result};
use ottto_core::{default_support_dir, FileConnectionStore, FileMachineStore, LocalDeviceBinding};
use ottto_protocol::{AgentStatusSnapshot, DetectedUse, SourceKind};
pub(crate) use rejection_log::SessionHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroize;

#[cfg(test)]
mod claude_cache_ack_tests;
pub(crate) mod continuation;
#[cfg(test)]
mod identity_bucket_progress_tests;
mod reason_reoffer;
mod rejection_log;
mod retry;
mod stale_owed;

// Direct API host; the apex `ottto.net/backend` proxy is retired in the marketing cutover.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const SNAPSHOT_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub(crate) fn copy_prefix_pacing_seconds() -> (u64, u64) {
    (
        SNAPSHOT_SYNC_INTERVAL.as_secs(),
        MAX_CYCLE_INTERVAL.as_secs(),
    )
}
// Both scan workers' stack. Headroom, not a fix: the release cycle fits the
// 2 MiB spawn default (scan_worker_stack_margin_receipt), and an overflow
// would abort the daemon.
const SNAPSHOT_SYNC_WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;
// Non-terminal collector check-in cadence. The sync loop sleeps a fixed
// SNAPSHOT_SYNC_INTERVAL AFTER a cycle completes, so terminal status receipts
// alone age by cycle_duration + interval; a long cycle (first onboarding scan,
// a post-restart backlog drain) makes an alive collector read as stale
// server-side even while uploads are progressing. The backend's sources.status
// freshness promise is a check-in within five minutes — beat well inside it so
// receipt age stays bounded no matter how long a cycle runs.
const COLLECTOR_CHECKIN_INTERVAL: Duration = Duration::from_secs(2 * 60);
// The backend status/manifest contract accepts a negotiated semantic evidence
// window of at most 183 days. Historical replay may traverse a wider local
// corpus, but it must never widen this receipt contract: the manifest is
// recomputed from semantic activity inside the negotiated window.
const MAX_SNAPSHOT_STATUS_WINDOW_DAYS: u64 = 183;
const LOCAL_HEALTH_PROJECTION_INTERVAL: Duration = Duration::from_secs(60);
const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: i64 = 15;
// Match the backend's accepted entity count while retaining a separate byte
// bound for pathological backfill batches. Normal incremental scans are
// usually a single small chunk; historical replay avoids count-only 50-item
// requests that could consume the backend's full wire budget.
const SNAPSHOT_BATCH_LIMIT: usize = 50;
// Leave half of the backend's 4 MiB uncompressed request cap for derived
// semantic envelopes and bounded request metadata. The exact request serializer
// is still checked immediately before network I/O by
// `validate_snapshot_batch_request`.
pub(crate) const SNAPSHOT_BATCH_MAX_BYTES: usize = 2 * 1024 * 1024;
// A 50-item page needs at most six binary splits to isolate one poison item.
// Cap there so broad schema drift cannot turn one five-minute cycle into dozens
// of doomed backend calls.
const SNAPSHOT_ADAPTIVE_SPLIT_LIMIT: usize = 6;
const SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT: usize = SNAPSHOT_BATCH_LIMIT + 4;
const SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE: usize = SNAPSHOT_BATCH_LIMIT;
// A pre-ledger checkpoint with ambiguous settlement is re-entered through the
// existing entity-ACK upload machine. Arm at most one normal 50-entity page per
// five-minute source cycle; the scan-index cursor and quarantine map resume the
// remaining identities across restarts.
const LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE: usize = SNAPSHOT_BATCH_LIMIT;
static ONE_SHOT_SYNC_IN_FLIGHT: OnceLock<Mutex<bool>> = OnceLock::new();
static SNAPSHOT_SYNC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
pub(crate) fn status_test_scan_lock() -> std::sync::MutexGuard<'static, ()> {
    SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// Pinned with the replay strings in `backfill.rs`: a compiled history revision never
// triggers a re-read of existing history; new meaning ships forward via a rule epoch.
// Changing a pinned value needs owner approval (pin test: `history_revisions_are_pinned`).
pub(crate) const fn effective_upload_body_witness_revision(source: SnapshotSource) -> u64 {
    match source {
        SnapshotSource::ClaudeCode => 3,
        SnapshotSource::Codex | SnapshotSource::Pi => 1,
    }
}

// A Claude revision the history gate is not complete for does not
// build. Raise `MAX_GATED_CLAUDE_REVISION` only with its complete policy row.
const _: () = assert!(
    effective_upload_body_witness_revision(SnapshotSource::ClaudeCode)
        <= crate::snapshots::MAX_GATED_CLAUDE_REVISION
);

/// The revision a sync cycle activates: the compiled one.
fn cycle_body_witness_revision(source: SnapshotSource) -> u64 {
    effective_upload_body_witness_revision(source)
}

/// Where this destination's Claude prior history comes from. A fresh install
/// is only a positively empty support state.
/// - `Unverified`: the backfill state is unreadable.
/// - `Here`: this destination's completed bootstrap; a server-attested record
///   in its upload ledger (an accepted, quarantined or refused body or
///   accepted cache evidence; a generation or replay claim alone is saved
///   before any upload, so it is not evidence); a quarantined (`.corrupt.`)
///   sibling of this index; or the re-emission seen-marker. Also, when the
///   history is not `Moved`, an unscoped pre-scoping `claude_code-scan-index*`
///   beside `destinations/`: it names no destination, so it
///   is not a move, but this Mac did index history, so a cutoff keeps that
///   history owed, list-gated and paced instead of resent ungated.
/// - `Moved`: only a Claude bootstrap completed for another destination or
///   recorded by a legacy state, or a Claude index, ledger or quarantined
///   copy another destination's directory holds (an interrupted bootstrap
///   before a re-pair). A leftover is another destination only when it sits
///   under a different namespace; unless a claim
///   recorded a different-user cutoff, which keeps that history excluded by
///   the cutoff, as before.
///
/// Read before scanning; none of it lives in the index, so it survives index
/// loss (fail closed).
fn claude_prior_history(
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
    upload_progress: &SnapshotUploadProgress,
    index_path: &Path,
    support_dir: &Path,
) -> crate::snapshots::PriorHistory {
    use crate::snapshots::PriorHistory;
    if backfill_state.prior_history_unverified {
        return PriorHistory::Unverified;
    }
    let slug = SnapshotSource::ClaudeCode.api_slug();
    // Only a different namespace's directory is another destination. An
    // unscoped legacy `claude_code-scan-index*` beside `destinations/` names
    // no destination; it is usually this Mac's own pre-scoping index, so it
    // must not hold history as a move (I-r3-1). It is `Here` evidence below.
    let other_destination = || {
        let prefix = format!("{slug}-scan-index");
        let own = index_path.parent();
        let holds_claude_state =
            |directory: &Path| Some(directory) != own && dir_holds_prefixed(directory, &prefix);
        match std::fs::read_dir(support_dir.join("snapshots").join("destinations")) {
            Ok(mut destinations) => destinations.any(|destination| match destination {
                Ok(destination) => holds_claude_state(&destination.path()),
                Err(_) => true,
            }),
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        }
    };
    // Fails closed: only a positively missing marker is absent.
    let seen_marker = || match std::fs::symlink_metadata(
        crate::snapshots::claude_reemission_seen_marker_path(support_dir),
    ) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    };
    if claude_destination_history_here(
        backfill_state,
        destination_namespace,
        upload_progress,
        index_path,
    ) || seen_marker()
    {
        return PriorHistory::Here;
    }
    // A claim that recorded a different-user cutoff keeps the other
    // destinations' history excluded by that cutoff, not by the gate, but
    // only on that claim's own destination: a later same-user re-claim keeps
    // the cutoff on a new destination.
    let other_user_cutoff = backfill_state.backfill_cutoff_at.is_some()
        && backfill_state
            .backfill_cutoff_destination_namespace
            .as_deref()
            == Some(destination_namespace);
    // Claude's own entries only: `last_completed_at` is stamped by any
    // source's bootstrap, so a Codex or Pi completion is not Claude history.
    let earlier_bootstrap = backfill_state
        .completed_destination_replays
        .contains_key(slug)
        || backfill_state
            .completed_destination_namespaces
            .contains_key(slug)
        || backfill_state.completed_parser_versions.contains_key(slug)
        || backfill_state.completed_replay_revisions.contains_key(slug);
    // A pre-scoping daemon's unscoped index.
    let unscoped_legacy_index = || {
        dir_holds_prefixed(
            &support_dir.join("snapshots"),
            &format!("{slug}-scan-index"),
        )
    };
    if !other_user_cutoff && (earlier_bootstrap || other_destination()) {
        PriorHistory::Moved
    } else if unscoped_legacy_index() {
        PriorHistory::Here
    } else {
        PriorHistory::None
    }
}

/// Evidence belongs to this destination, independent of the Mac-wide marker.
fn claude_destination_history_here(
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
    upload_progress: &SnapshotUploadProgress,
    index_path: &Path,
) -> bool {
    let slug = SnapshotSource::ClaudeCode.api_slug();
    let here = backfill_state.destination_completed(slug, destination_namespace);
    // A quarantined copy of this index, of a legacy index or of this
    // destination's ledger. An unreadable directory fails closed; a missing
    // one is empty.
    let quarantined_sibling = || {
        let own_stem = index_path.file_stem().and_then(|stem| stem.to_str());
        let claude_prefix = format!("{slug}-scan-index");
        let Some(parent) = index_path.parent() else {
            return false;
        };
        match std::fs::read_dir(parent) {
            Ok(mut entries) => entries.any(|entry| match entry {
                Ok(entry) => entry.file_name().to_str().is_some_and(|name| {
                    name.contains(".corrupt.")
                        && (own_stem.is_some_and(|stem| name.starts_with(stem))
                            || name.starts_with(&claude_prefix))
                }),
                Err(_) => true,
            }),
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        }
    };
    here || upload_progress.records_server_attested_upload() || quarantined_sibling()
}

/// Narrow the corruption stop to loss of this destination's own history.
fn note_claude_index_rebuild_for_destination(
    source: SnapshotSource,
    loaded_fresh: bool,
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
    upload_progress: &SnapshotUploadProgress,
    index_path: &Path,
    support_dir: &Path,
) {
    if source == SnapshotSource::ClaudeCode
        && loaded_fresh
        && claude_destination_history_here(
            backfill_state,
            destination_namespace,
            upload_progress,
            index_path,
        )
    {
        crate::snapshots::note_claude_index_rebuild_stop(support_dir);
    }
}

/// True when `directory` holds an entry named `{prefix}*`. An unreadable
/// directory or entry fails closed; a missing directory is empty.
fn dir_holds_prefixed(directory: &Path, prefix: &str) -> bool {
    match std::fs::read_dir(directory) {
        Ok(mut entries) => entries.any(|entry| match entry {
            Ok(entry) => entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(prefix)),
            Err(_) => true,
        }),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Claude only, before scanning: with prior history, a fresh index (missing
/// or quarantined), a replay that dropped entries or the first gated load of
/// an index without one records the history cutoff; see
/// `ScanIndex::note_claude_history_cutoff`.
fn note_claude_history_cutoff_for_cycle(
    index: &mut ScanIndex,
    source: SnapshotSource,
    prior_history: crate::snapshots::PriorHistory,
    backfill_state: &crate::backfill::BackfillState,
    entries_lost: bool,
) {
    if source != SnapshotSource::ClaudeCode {
        return;
    }
    index.note_claude_history_cutoff(
        prior_history,
        backfill_state.claim_backfill_policy_full,
        entries_lost,
    );
}

/// Whether the source's bootstrap for this destination is pending, which arms
/// its historical replay (StateMissing H1, N2).
fn backfill_replay_pending(
    source: SnapshotSource,
    backfill_state: &crate::backfill::BackfillState,
    destination_namespace: &str,
) -> bool {
    pending_backfill_sources_for_destination(backfill_state, destination_namespace)
        .contains(&source)
}

/// Claude only: the unreadable backfill state suppresses replays until a
/// Claude census under the history gate clears it (N2).
fn claude_replay_suppressed(
    source: SnapshotSource,
    backfill_state: &crate::backfill::BackfillState,
) -> bool {
    source == SnapshotSource::ClaudeCode && backfill_state.prior_history_unverified
}

fn exclude_held_effective_body_witness_revision(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
) {
    let held = disposition.quarantined_fingerprints(items);
    let source_files = items
        .iter()
        .filter(|item| held.contains(&item.snapshot_fingerprint))
        .filter_map(|item| item.source_file_fingerprint.clone())
        .collect();
    index.exclude_effective_upload_body_witness_revision_for_source_files(&source_files);
}

/// Commit a `Completed` upload that left local holds. Every uploaded entity was
/// accepted or unchanged; only the held revisions are unsettled.
///
/// A hold that owes a clean follow-up (`progress_blocking`) keeps the
/// conservative partial commit and marks the sweep unsettled, so the
/// generation needs one clean follow-up. Otherwise every hold is
/// non-progressing (account deferrals and bound authority holds, including
/// bound RetryPending families under the path-(a) bridge): held keys keep their
/// committed revision, every other key commits as the no-hold save would, and
/// the traversal may settle. The caller keeps backfill and replay completion
/// pending, and the durable hold disclosure keeps health red.
///
/// A non-progressing hold in a Claude family that retains authority evidence
/// but has no committed entry to restore, as after a historical replay reset,
/// still blocks: settling it would let a later page of the same traversal
/// treat the still-present family as vanished. A never-committed member bound
/// by its committed family's terminal quarantine settles with a delivery-free
/// membership entry instead, so the family census stays complete.
fn commit_completed_with_local_holds(
    index: ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    locally_held_fingerprints: &BTreeSet<String>,
    account_deferred_held_fingerprints: &BTreeSet<String>,
    progress_blocking: bool,
) -> ScanIndex {
    if !progress_blocking {
        if index.locally_held_keys_restorable(
            committed_index,
            locally_held_fingerprints,
            account_deferred_held_fingerprints,
        ) {
            return index.into_locally_held_keys_reverted(
                committed_index,
                locally_held_fingerprints,
                account_deferred_held_fingerprints,
            );
        }
        crate::local_resource_diagnostics::claude_reread::held_reason(
            crate::local_resource_diagnostics::claude_reread::HeldReason::NotRestorable,
        );
    }
    let mut index = index.committable_subset_for_upload(
        committed_index,
        &upload_progress.accepted_fingerprints,
        &upload_progress.quarantined_fingerprints,
        locally_held_fingerprints,
        true,
    );
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::CompletedBlockingHolds);
    index
}

/// Local holds classified once per page, after finalization and before upload.
/// Every upload outcome settles against this one classification.
struct LocalHoldSettlement {
    /// Sessions held locally on this page.
    held_entity_count: usize,
    /// RetryPending Claude authority families anywhere in the index. They keep
    /// full completion (backfill, replay) pending, but since the path-(a)
    /// bridge they no longer make an unrelated page progress-blocking.
    retry_pending_family_count: usize,
    held_fingerprints: BTreeSet<String>,
    account_deferred_fingerprints: BTreeSet<String>,
    progress_blocking: bool,
}

struct AccountAuditRelease<'a> {
    previous: &'a ScanIndex,
    roots: &'a [PathBuf],
    backfill_window_days: u64,
}

impl LocalHoldSettlement {
    /// Record the durable account-hold disclosure, classify which holds a
    /// later page could still change, and remove every held entity from the
    /// upload. The disclosure is durable before upload, so every checkpoint
    /// below carries it. Only Claude account deferrals are settled this way;
    /// other sources keep every account deferral progress-blocking.
    fn classify(
        source: SnapshotSource,
        index: &mut ScanIndex,
        scan_result: &mut crate::snapshots::SourceScanResult,
        disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
    ) -> Self {
        let held_entity_count = disposition.quarantined_entity_count();
        let held_fingerprints = disposition.quarantined_fingerprints(&scan_result.snapshots);
        let account_deferred_fingerprints =
            disposition.account_deferred_fingerprints(&scan_result.snapshots);
        let account_holds_recorded = source == SnapshotSource::ClaudeCode
            && index.record_claude_account_deferred_holds(
                scan_result.completed_parses(),
                &disposition.account_deferred_tokens(&scan_result.snapshots),
            );
        if held_entity_count > 0 {
            let counts = serde_json::json!({
                "request_owned": disposition.request_owned_hold_reasons,
                "account_binding": account_deferred_fingerprints.len(),
                "authority_demotion": disposition.context_file_birth.demotion_quarantined_session_count,
            });
            eprintln!(
                "local snapshot sync: hold disposition source={} held_entities={} counts={counts}",
                source.api_slug(),
                held_entity_count,
            );
        }
        scan_result.remember_withheld_content(index);
        let progress_blocking_held_fingerprints = disposition.progress_blocking_held_fingerprints(
            &scan_result.snapshots,
            index,
            account_holds_recorded,
        );
        disposition.retain_uploadable(&mut scan_result.snapshots);
        crate::snapshots::record_lineage_parentless_while_incomplete(
            source,
            &scan_result.snapshots,
            index,
        );
        let retry_pending_family_count = index.claude_usage_authority_pending_count();
        Self {
            held_entity_count,
            retry_pending_family_count,
            held_fingerprints,
            account_deferred_fingerprints,
            progress_blocking: !progress_blocking_held_fingerprints.is_empty(),
        }
    }

    fn any(&self) -> bool {
        self.retry_pending_family_count > 0 || self.held_entity_count > 0
    }

    /// Whether this page itself held any entity.
    fn page_held(&self) -> bool {
        self.held_entity_count > 0
    }
}

/// The index selected by an upload outcome, and its transport/local-hold
/// settlement. Authority corrections are finalized on that selected index.
struct UploadIndexSettlement {
    index: ScanIndex,
    fully_settled: bool,
}

#[cfg(test)]
pub(crate) mod withheld_support {
    use super::*;
    /// A re-paired destination's Claude prior history, read as its first cycle
    /// reads it: before any upload ledger record.
    pub(crate) fn claude_prior_history_for_new_destination(
        support_dir: &Path,
        destination_namespace: &str,
    ) -> crate::snapshots::PriorHistory {
        let stable = snapshot_index_path(support_dir, SnapshotSource::ClaudeCode);
        let scoped = snapshot_destination_scoped_index_path(&stable, destination_namespace);
        claude_prior_history(
            &load_backfill_state(support_dir),
            destination_namespace,
            &SnapshotUploadProgress::new(
                destination_namespace.to_string(),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            ),
            &snapshot_v3_index_path(&scoped),
            support_dir,
        )
    }

    pub(crate) fn source_erasure_failures_for_test(
        support_dir: &Path,
        source: SnapshotSource,
    ) -> u32 {
        let marker = source_marker_path(support_dir, source);
        source_erasure_turn().get(&marker).copied().unwrap_or(0)
    }

    pub(crate) fn settle_withheld(
        previous: &ScanIndex,
        mut index: ScanIndex,
        mut scan: crate::snapshots::SourceScanResult,
    ) -> ScanIndex {
        let mut previous = previous.clone();
        previous.rehome_withheld_baseline(&index);
        let mut disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
        disposition.defer_sessions(
            scan.snapshots
                .iter()
                .map(|item| item.source_session_id.clone())
                .collect(),
        );
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut index,
            &mut scan,
            &disposition,
        );
        assert!(
            scan.snapshots.is_empty(),
            "account-held bodies stay Unknown and never enter upload"
        );
        let progress = SnapshotUploadProgress::new(
            "withheld-fixture".into(),
            crate::snapshots::snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        );
        settle_completed_upload(index, &previous, &progress, &holds).index
    }

    pub(crate) fn withheld_settled(index: &ScanIndex) -> bool {
        upload_settled_without_account_holds(index, true)
    }

    pub(crate) fn deferred_tokens(
        scan: &crate::snapshots::SourceScanResult,
    ) -> BTreeMap<String, u64> {
        let mut disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
        disposition.defer_sessions(
            scan.snapshots
                .iter()
                .map(|item| item.source_session_id.clone())
                .collect(),
        );
        disposition.account_deferred_tokens(&scan.snapshots)
    }
}

/// A persisted account hold was never uploaded, so the backfill and replay it
/// belongs to stay pending even on a page that did not revisit it.
fn upload_settled_without_account_holds(index: &ScanIndex, settled: bool) -> bool {
    settled && index.claude_account_deferred_hold_count() == 0
}

/// Settle a `Completed` upload: every uploaded entity was accepted or
/// unchanged, and only local holds can remain unsettled.
fn settle_completed_upload(
    index: ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    holds: &LocalHoldSettlement,
) -> UploadIndexSettlement {
    if !holds.page_held() {
        // RetryPending debt elsewhere settles this page as a no-hold page
        // would, and only keeps full completion pending.
        let fully_settled = upload_settled_without_account_holds(&index, !holds.any());
        return UploadIndexSettlement {
            index,
            fully_settled,
        };
    }
    let index = commit_completed_with_local_holds(
        index,
        committed_index,
        upload_progress,
        &holds.held_fingerprints,
        &holds.account_deferred_fingerprints,
        holds.progress_blocking,
    );
    eprintln!(
        "local snapshot sync retained {} Claude usage family/families and {} revised \
         entity/entities with unproven authority or session ownership; healthy siblings settled \
         and the retained revisions remain pending for bounded retry",
        holds.retry_pending_family_count, holds.held_entity_count
    );
    UploadIndexSettlement {
        index,
        fully_settled: false,
    }
}

#[cfg(test)]
pub(crate) fn classify_holds_for_test(
    source: SnapshotSource,
    index: &mut ScanIndex,
    scan: &mut SourceScanResult,
) {
    LocalHoldSettlement::classify(
        source,
        index,
        scan,
        &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
    );
}

#[cfg(test)]
fn classify_account_release_for_test(
    index: &mut ScanIndex,
    scan: &mut SourceScanResult,
) -> (LocalHoldSettlement, SnapshotUploadProgress) {
    let source = SnapshotSource::ClaudeCode;
    let holds = LocalHoldSettlement::classify(
        source,
        index,
        scan,
        &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
    );
    assert!(!holds.page_held());
    let mut progress =
        SnapshotUploadProgress::new(format!("{:064x}", 99), snapshot_quarantine_witness(source));
    let groups = cache_head_file_groups(index);
    for item in &scan.snapshots {
        progress
            .record_pending_cache_head_identity(
                item.source_file_fingerprint.as_ref(),
                &item.snapshot_fingerprint,
                &cache_session_key(&item.source_session_id),
                &groups,
                true,
            )
            .unwrap();
    }
    assert!(
        !progress.pending_cache_heads.is_empty(),
        "required head bindings recorded"
    );
    (holds, progress)
}

#[cfg(test)]
pub(crate) fn accept_account_release_for_test(
    mut index: ScanIndex,
    previous: &ScanIndex,
    scan: &mut SourceScanResult,
    roots: &[PathBuf],
) -> ScanIndex {
    let (holds, mut progress) = classify_account_release_for_test(&mut index, scan);
    progress.accepted_fingerprints.extend(
        scan.snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone()),
    );
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    let mut settled = settle_completed_upload(index, previous, &progress, &holds);
    assert!(settled.fully_settled);
    scan.preserve_released_account_audits(
        &mut settled.index,
        previous,
        roots,
        crate::snapshots::BACKFILL_WINDOW_DAYS,
    );
    settled.index
}

#[cfg(test)]
pub(crate) fn checkpoint_account_release_for_test(
    mut index: ScanIndex,
    previous: &ScanIndex,
    scan: &mut SourceScanResult,
    roots: &[PathBuf],
    paths: (&Path, &Path),
) -> Result<ScanIndex> {
    let (holds, mut progress) = classify_account_release_for_test(&mut index, scan);
    // Actual no-ACK partial save restores the prior accepted entry before
    // transferring retry custody. Head binding above still had to succeed.
    progress.save(paths.1)?;
    checkpoint_partial_snapshot_index_with_audit_release(
        &index,
        previous,
        &progress,
        &scan.snapshots,
        Some(scan),
        &holds.held_fingerprints,
        paths.0,
        paths.1,
        || Ok(()),
        None,
        Some(UnsettledUploadCause::UploadError),
        Some(AccountAuditRelease {
            previous,
            roots,
            backfill_window_days: crate::snapshots::BACKFILL_WINDOW_DAYS,
        }),
        Default::default(),
    )
}

/// The page items a server answer names: an indexed validation rejection
/// (422), an identity-deferral shed (503) or ACK refs that echoed another
/// body witness. `None` when nothing is named or a location falls outside
/// this page; that failure keeps its own path (a shed stays a whole-pass shed).
fn server_named_items(error: &anyhow::Error, indices: &[usize]) -> Option<BTreeSet<usize>> {
    let named = if let Some(named) = error.downcast_ref::<ShedSnapshotIndexes>() {
        &named.0
    } else if let Some(named) = error.downcast_ref::<RefusedSnapshotIndexes>() {
        &named.0
    } else {
        error
            .downcast_ref::<BatchRejected>()?
            .snapshot_indexes
            .as_ref()?
    };
    named
        .iter()
        .map(|index| indices.get(*index).copied())
        .collect()
}

/// Process-local, content-free count of records the attempt-count ladder made
/// `UnprovenTerminal` (all sources), apart from server verdicts, so a later
/// `unproven_terminal` rise can be attributed.
static UNPROVEN_TERMINAL_ATTEMPT_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Process-local, content-free count of `Rejected` pages whose local holds
/// were all terminal-bound and settled through the `Completed` restore path.
static CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Settle a `Deferred` or `Rejected` upload. Retryable or locally unproven
/// entities keep replay pending and owe a clean follow-up. A validated
/// permanent refusal settles transport and traversal; its separate health
/// still discloses the rejected usage. Its holds settle exactly as on a
/// `Completed` page: when every hold on this page is non-progressing and
/// restorable, held keys keep their committed revision and the traversal may
/// settle; backfill and replay stay pending. A RetryPending family elsewhere
/// keeps only full completion pending (path-(a) bridge).
fn settle_checkpointed_upload(
    index: ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
    holds: &LocalHoldSettlement,
    resolved_permanent_rejections: bool,
) -> UploadIndexSettlement {
    let terminal_bound_holds = resolved_permanent_rejections
        && holds.page_held()
        && !holds.progress_blocking
        && index.locally_held_keys_restorable(
            committed_index,
            &holds.held_fingerprints,
            &holds.account_deferred_fingerprints,
        );
    let mut index = if terminal_bound_holds {
        CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        index.into_locally_held_keys_reverted(
            committed_index,
            &holds.held_fingerprints,
            &holds.account_deferred_fingerprints,
        )
    } else if holds.page_held() || !resolved_permanent_rejections {
        // Refusals already have quarantine custody. Every entity that is not
        // held settles as on a clean page, semantic no-ops not resent here
        // included.
        index.committable_subset_for_upload(
            committed_index,
            &upload_progress.accepted_fingerprints,
            &upload_progress.quarantined_fingerprints,
            &holds.held_fingerprints,
            true,
        )
    } else {
        index
    };
    let settled = resolved_permanent_rejections && (!holds.page_held() || terminal_bound_holds);
    if !settled {
        index.mark_bounded_sweep_unsettled_by(if resolved_permanent_rejections {
            UnsettledUploadCause::RejectedWithHolds
        } else {
            UnsettledUploadCause::DeferredConflict
        });
    }
    let fully_settled = upload_settled_without_account_holds(&index, settled && !holds.any());
    UploadIndexSettlement {
        index,
        fully_settled,
    }
}

/// Fold the upload ledger into the index after any outcome that reaches the
/// durable save.
fn settle_index_after_upload(
    index: &mut ScanIndex,
    committed_index: &ScanIndex,
    upload_progress: &SnapshotUploadProgress,
) {
    index.reconcile_codex_recovery_settlement(
        committed_index,
        &upload_progress.accepted_fingerprints,
    );
    index.retain_quarantined_fingerprints(&upload_progress.quarantined_fingerprints);
    index.record_accepted_snapshot_fingerprints(&upload_progress.accepted_fingerprints);
}

/// Correction completion depends on the final selected file/empty facts. In
/// particular, the last no-body drain must precede the completion decision.
#[expect(
    clippy::too_many_arguments,
    reason = "the selected index, page facts, correction candidates and drain ledger"
)]
fn settle_upload_corrections_after_selection(
    index: &mut ScanIndex,
    scan: &SourceScanResult,
    committed_index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    candidates: &[crate::snapshots::ClaudeProofCorrectionCandidate],
    cutoff_candidates: &[crate::snapshots::ClaudeCutoffCorrectionCandidate],
    transport_fully_settled: bool,
    body_drains: &mut crate::snapshots::ClaudeProofBodyDrains,
) -> bool {
    // This drain is deliberately unavailable to partial/deferred/shed/error outcomes.
    // Both existing durable refusal carriers must bind the exact current body.
    // It settles against the selected entries, but a later account-audit
    // release can still clear one; its drains join the finish restore.
    if transport_fully_settled {
        let drains = index.settle_claude_proof_corrections_with_permanent(
            committed_index,
            candidates,
            &progress.accepted_fingerprints,
            &progress.accepted_body_witnesses,
            |fingerprint, body| {
                progress
                    .permanent_rejections
                    .get(fingerprint)
                    .is_some_and(|rejection| rejection.body_witness == body)
                    && progress
                        .quarantined_fingerprints
                        .get(fingerprint)
                        .is_some_and(|record| {
                            record.disposition == SnapshotQuarantineDisposition::UnprovenTerminal
                                && record.upload_body_witness.as_deref() == Some(body)
                        })
            },
        );
        body_drains.append(drains);
    }
    index.settle_cutoff_claude_proof_corrections(cutoff_candidates);
    index.settle_empty_claude_proof_corrections(scan);
    // Correction members the history gate holds wait for it; they are counted,
    // not blocking.
    let (blocking, deferred) = index.claude_authority_proof_correction_blocking();
    if deferred > 0 {
        eprintln!(
            "local snapshot proof corrections deferred to the history gate for {}: members={deferred}",
            scan.source.api_slug()
        );
        crate::local_resource_diagnostics::claude_history_proof_correction_deferred(deferred);
    }
    transport_fully_settled && !blocking
}

struct SelectedSettlementInputs<'a> {
    scan: &'a SourceScanResult,
    committed_index: &'a ScanIndex,
    progress: &'a SnapshotUploadProgress,
    candidates: &'a [crate::snapshots::ClaudeProofCorrectionCandidate],
    cutoff_candidates: &'a [crate::snapshots::ClaudeCutoffCorrectionCandidate],
    transport_fully_settled: bool,
    body_drains: crate::snapshots::ClaudeProofBodyDrains,
    audit_release: Option<AccountAuditRelease<'a>>,
}

/// The finish order after save selection, shared with the proof-correction
/// pipeline harness so its regressions guard this order: correction settle,
/// account-audit release (which can clear a drained entry's revision), then the
/// body-drain restore. Returns whether the page is fully settled.
fn finish_selected_settlement(index: &mut ScanIndex, inputs: SelectedSettlementInputs<'_>) -> bool {
    let SelectedSettlementInputs {
        scan,
        committed_index,
        progress,
        candidates,
        cutoff_candidates,
        transport_fully_settled,
        mut body_drains,
        audit_release,
    } = inputs;
    let mut fully_settled = settle_upload_corrections_after_selection(
        index,
        scan,
        committed_index,
        progress,
        candidates,
        cutoff_candidates,
        transport_fully_settled,
        &mut body_drains,
    );
    if let Some(release) = audit_release {
        scan.preserve_released_account_audits(
            index,
            release.previous,
            release.roots,
            release.backfill_window_days,
        );
    }
    // After every selected-entry restore and the account-audit release, which
    // can clear a drained entry's revision: a drain (pre-selection or settlement)
    // whose entry this save does not keep stays owed.
    if index.restore_unselected_claude_proof_body_drains(body_drains) {
        fully_settled = false;
    }
    fully_settled
}

fn apply_backfill_cutoff_with_claude_corrections(
    scan: &mut SourceScanResult,
    index: &ScanIndex,
    disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
    state: &crate::backfill::BackfillState,
) -> (
    usize,
    Vec<crate::snapshots::ClaudeCutoffCorrectionCandidate>,
) {
    let mut candidates = index.capture_claude_cutoff_corrections(scan, disposition);
    let removed = apply_backfill_cutoff(&mut scan.snapshots, state);
    ScanIndex::retain_fully_cutoff_corrections(&mut candidates, &scan.snapshots);
    (removed, candidates)
}

mod ack_retention;
mod progress_rows;
mod telemetry_only;
mod upload_context_resend;

use crate::hex::is_sha256_any_case as is_snapshot_fingerprint;

fn current_unix_seconds() -> u64 {
    #[cfg(test)]
    if let Some(now) =
        tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::retry_clock()
    {
        return now;
    }

    crate::scan_clock::utc_seconds()
}

pub(crate) fn quarantine_retry_after(fingerprint: &str) -> u64 {
    jittered_retry_after(
        fingerprint,
        current_unix_seconds(),
        SNAPSHOT_QUARANTINE_RETRY_SECONDS,
    )
}

/// Base of a head-CAS conflict's probe. Jitter adds less than the base, so
/// every conflict probe and refused-answer hold ends within one hour.
const SNAPSHOT_CONFLICT_PROBE_SECONDS: u64 = 30 * 60;

/// A conflict's mandatory probe: `[30 min, 1 h)` after `from`, per body.
/// Backend state can change without a local change, so a conflict is never
/// left waiting for new input alone.
fn conflict_probe_after(fingerprint: &str, from: u64) -> u64 {
    jittered_retry_after(fingerprint, from, SNAPSHOT_CONFLICT_PROBE_SECONDS)
}

/// `[from + base, from + 2 * base)`, staggered deterministically by `key`.
fn jittered_retry_after(key: &str, from: u64, base: u64) -> u64 {
    let digest = Sha256::digest(key.as_bytes());
    let jitter = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix")) % base;
    from.saturating_add(base).saturating_add(jitter)
}

/// Last computed scan-index manifest per (upload destination, source).
///
/// The check-in heartbeat runs on its own clock and does not know which
/// policy/attribution/destination-scoped index path the sync cycle chose, so it
/// cannot load the index itself. The sync cycle publishes the manifest it
/// already computed from the index it already had open, and both receipt shapes
/// read it from here. Missing means "no scan has completed in this process yet
/// for this destination", which is reported as an absent manifest rather than a
/// zeroed one.
///
/// The destination is part of the key, not an afterthought: a setup or account
/// switch replaces the relay binding without restarting the daemon (which is why
/// `ensure_snapshot_destination_current` exists), and a manifest keyed by source
/// alone would report the previous account's entity count and rolling hash to the
/// new one — a wrong witness and a disclosure of the previous account's local
/// session set.
static SOURCE_MANIFESTS: OnceLock<Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>> =
    OnceLock::new();

type SourceManifestCache = Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>;

fn source_manifests() -> &'static SourceManifestCache {
    SOURCE_MANIFESTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn publish_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    manifest: SnapshotSourceManifest,
) {
    // These mutations preserve BTreeMap invariants even if an unrelated
    // consumer panics while holding the process-global cache. Recover poison
    // so one caught panic cannot permanently suppress every future manifest.
    let mut manifests = source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // One destination at a time: a machine that has moved is never coming
    // back to the old binding with the same secret, so retaining its
    // manifests would only risk reporting them.
    manifests.retain(|(namespace, _), _| namespace == destination_namespace);
    manifests.insert(
        (destination_namespace.to_string(), source.api_slug()),
        manifest,
    );
}

fn withdraw_source_manifest(destination_namespace: &str, source: SnapshotSource) {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&(destination_namespace.to_string(), source.api_slug()));
}

fn save_index_and_publish_manifest(
    index: &mut ScanIndex,
    index_path: &Path,
    destination_namespace: &str,
    source: SnapshotSource,
    census_complete: bool,
    window_start: &str,
    window_end: &str,
) -> Result<()> {
    // The server may already hold this pass's new entities. Keep the previous
    // process-cache witness withdrawn until the exact replacement index is
    // durable; a failed CAS/save or manifest derivation must not let a
    // concurrent heartbeat repeat stale agreement.
    withdraw_source_manifest(destination_namespace, source);
    crate::local_resource_diagnostics::state_save_start(source.api_slug());
    index.save(index_path)?;
    if census_complete {
        publish_source_manifest(
            destination_namespace,
            source,
            index.manifest_for_window(source, window_start, window_end)?,
        );
    }
    Ok(())
}

// Exercise the real durable-save/publication boundary from decoder rescans.
#[cfg(test)]
pub(crate) fn decode_hold_manifest_published_for_test(
    index: &mut ScanIndex,
    path: &Path,
    source: SnapshotSource,
    complete: bool,
) -> Result<bool> {
    let namespace = "lenient-decode-rescan";
    save_index_and_publish_manifest(
        index,
        path,
        namespace,
        source,
        complete,
        "2026-01-01T00:00:00Z",
        "2026-10-22T00:00:00Z",
    )?;
    Ok(cached_source_manifest(namespace, source).is_some())
}

/// Freshness fixtures exercise the real returning-quarantine and exact ACK path.
#[cfg(test)]
pub(crate) fn ack_current_again_quarantines_for_test(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
) -> BTreeMap<String, String> {
    use tests::claude_money_e2_pipeline_tests::{ack, upload_source_under};
    let source = SnapshotSource::ClaudeCode;
    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source));
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    assert!(progress.retain_current_quarantines(&index.current_snapshot_fingerprints(), index));
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    let (status, batches, _) = upload_source_under(
        source,
        SnapshotUploadPolicy::default(),
        items,
        &mut progress,
        ack,
    );
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 1);
    assert!(progress.quarantined_fingerprints.is_empty());
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    progress.fresh_context_body_acks
}

#[cfg(test)]
pub(crate) fn checkpoint_unselected_for_test(
    index: &ScanIndex,
    committed: &ScanIndex,
    scan: &SourceScanResult,
    index_path: &Path,
    progress_path: &Path,
) -> Result<ScanIndex> {
    checkpoint_page_for_test(index, committed, scan, index_path, progress_path, false)
}

#[cfg(test)]
pub(crate) fn checkpoint_page_for_test(
    index: &ScanIndex,
    committed: &ScanIndex,
    scan: &SourceScanResult,
    index_path: &Path,
    progress_path: &Path,
    accept: bool,
) -> Result<ScanIndex> {
    let mut progress = SnapshotUploadProgress::load(
        progress_path,
        &format!("{:064x}", 588),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )?;
    if accept {
        use tests::claude_money_e2_pipeline_tests::{ack, upload_source_under};
        let mut index = index.clone();
        let mut scan = scan.clone();
        let holds = LocalHoldSettlement::classify(
            scan.source,
            &mut index,
            &mut scan,
            &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
        );
        assert!(!holds.any(), "the completed fixture page has no holds");
        let (result, _, _) = upload_source_under(
            scan.source,
            SnapshotUploadPolicy::default(),
            &scan.snapshots,
            &mut progress,
            ack,
        );
        anyhow::ensure!(
            result? == ResumableUploadResult::Completed,
            "fixture exact ACK"
        );
        progress.save(progress_path)?;
        index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
            &mut index,
            &scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        index.save(index_path)?;
        return Ok(index);
    }
    progress.save(progress_path)?;
    checkpoint_partial_snapshot_index_with_audit_release(
        index,
        committed,
        &progress,
        &scan.snapshots,
        Some(scan),
        &BTreeSet::new(),
        index_path,
        progress_path,
        || Ok(()),
        None,
        None,
        None,
        Default::default(),
    )
}

/// Preserve only delivery-owned file checkpoints on an unfinished upload.
/// Hold the progress lock through index CAS: neither an unsaved ACK nor a
/// racing ledger generation may certify the scan's new file/body witnesses.
#[expect(clippy::too_many_arguments, reason = "test helper, 9 case inputs")]
#[cfg(test)]
fn checkpoint_partial_snapshot_index(
    index: &ScanIndex,
    committed_index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    snapshots: &[SnapshotItem],
    correction_scan: Option<&SourceScanResult>,
    locally_held: &BTreeSet<String>,
    index_path: &Path,
    progress_path: &Path,
    validate_destination: impl FnOnce() -> Result<()>,
) -> Result<ScanIndex> {
    checkpoint_partial_snapshot_index_with_audit_release(
        index,
        committed_index,
        progress,
        snapshots,
        correction_scan,
        locally_held,
        index_path,
        progress_path,
        validate_destination,
        None,
        None,
        None,
        Default::default(),
    )
}

/// Fixed labels for the partial-checkpoint steps whose own error carries no
/// phrase `safe_error` knows. The checkpoint's other failures already carry
/// fixed messages naming the partial checkpoint (listed in
/// `PARTIAL_CHECKPOINT_FAILURES`).
const CHECKPOINT_PROGRESS_LOCK: &str = "partial checkpoint: acquire progress lock";
const CHECKPOINT_ACK_HANDOFF: &str = "partial checkpoint: stage ACK retirement handoff";
const CHECKPOINT_VALIDATE_DESTINATION: &str = "partial checkpoint: validate destination";
const CHECKPOINT_INDEX_SAVE: &str = "partial checkpoint: save scan index";

/// Every partial-checkpoint failure label `safe_error` may print, so a failed
/// checkpoint names its step instead of the bare "sync failed".
const PARTIAL_CHECKPOINT_FAILURES: [&str; 9] = [
    CHECKPOINT_PROGRESS_LOCK,
    "read snapshot progress for partial checkpoint",
    "parse snapshot progress for partial checkpoint",
    "partial checkpoint lacks a source witness",
    "snapshot progress changed before partial checkpoint",
    "conflicting snapshot bodies before partial checkpoint",
    CHECKPOINT_ACK_HANDOFF,
    CHECKPOINT_VALIDATE_DESTINATION,
    CHECKPOINT_INDEX_SAVE,
];

#[allow(
    clippy::too_many_arguments,
    reason = "partial checkpoint keeps the selected body, audit and drain inputs together"
)]
fn checkpoint_partial_snapshot_index_with_audit_release(
    index: &ScanIndex,
    committed_index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    snapshots: &[SnapshotItem],
    correction_scan: Option<&SourceScanResult>,
    locally_held: &BTreeSet<String>,
    index_path: &Path,
    progress_path: &Path,
    validate_destination: impl FnOnce() -> Result<()>,
    read_limit: Option<usize>,
    cause: Option<UnsettledUploadCause>,
    audit_release: Option<AccountAuditRelease<'_>>,
    body_drains: crate::snapshots::ClaudeProofBodyDrains,
) -> Result<ScanIndex> {
    let progress_owner =
        SnapshotProgressLock::acquire(progress_path).context(CHECKPOINT_PROGRESS_LOCK)?;
    let progress_owner = if crate::snapshots::state_v2_growth_retention_active(index) {
        progress_owner.for_v2(progress_path)
    } else {
        progress_owner
    };
    let durable: SnapshotUploadProgress = if progress.rows.is_some() {
        progress.durable_rows(index_path, &progress_owner)?
    } else {
        match match read_limit {
            Some(cap) => crate::snapshot_retry::read_state(progress_path, cap),
            None => std::fs::read(progress_path),
        } {
            Ok(bytes) => (if read_limit.is_some() {
                crate::snapshot_retry::decode_state(&bytes)
            } else {
                serde_json::from_slice(&bytes).map_err(anyhow::Error::from)
            })
            .context("parse snapshot progress for partial checkpoint")?,
            Err(error) if error.kind() == ErrorKind::NotFound && progress.generation == 0 => {
                SnapshotUploadProgress::new(
                    progress.destination_namespace_hash.clone(),
                    progress
                        .active_quarantine_witness
                        .clone()
                        .ok_or_else(|| anyhow!("partial checkpoint lacks a source witness"))?,
                )
            }
            Err(error) => {
                return Err(error).context("read snapshot progress for partial checkpoint")
            }
        }
    };
    // Refuse only a real concurrent writer, as `save()` does. The accepted
    // and quarantined sets and the upload-context stamp read `durable`.
    if !progress.same_writer(durable.stamp()) {
        return Err(anyhow!(
            "snapshot progress changed before partial checkpoint"
        ));
    }
    let mut current_bodies = BTreeMap::new();
    for item in snapshots {
        let witness = snapshot_upload_body_witness(item);
        if current_bodies
            .insert(item.snapshot_fingerprint.as_str(), witness.clone())
            .is_some_and(|previous| previous != witness)
        {
            return Err(anyhow!(
                "conflicting snapshot bodies before partial checkpoint"
            ));
        }
    }
    let accepted = durable
        .accepted_fingerprints
        .iter()
        .filter(|fingerprint| {
            durable.accepted_body_witnesses.get(*fingerprint)
                == current_bodies.get(fingerprint.as_str())
                && current_bodies.contains_key(fingerprint.as_str())
        })
        .cloned()
        .collect();
    let quarantined = durable
        .quarantined_fingerprints
        .iter()
        .filter(|(fingerprint, record)| {
            record.upload_body_witness.as_ref() == current_bodies.get(fingerprint.as_str())
                && current_bodies.contains_key(fingerprint.as_str())
        })
        .map(|(fingerprint, record)| (fingerprint.clone(), record.clone()))
        .collect();
    let mut committable = index.committable_subset_for_upload(
        committed_index,
        &accepted,
        &quarantined,
        locally_held,
        false,
    );
    if let Some(scan) = correction_scan {
        committable.requeue_unkept_scanned_keys(scan.source, index, locally_held);
    }
    if let Some(scan) = correction_scan {
        // Settle no-body grants only against the file/empty/map facts
        // actually selected for this save, after any old-entry restoration.
        committable.settle_empty_claude_proof_corrections(scan);
    }
    if let (Some(scan), Some(release)) = (correction_scan, audit_release) {
        scan.preserve_released_account_audits(
            &mut committable,
            release.previous,
            release.roots,
            release.backfill_window_days,
        );
    }
    // After every selected-entry restore above: a drain whose entry this
    // save does not keep stays owed.
    committable.restore_unselected_claude_proof_body_drains(body_drains);
    committable
        .mark_bounded_sweep_unsettled_by(cause.unwrap_or(UnsettledUploadCause::Unattributed));
    let census_absent = progress.complete_census_ack_retirements(
        index,
        correction_scan.is_some_and(|scan| scan.census_complete),
    );
    let scan_referenced = progress.ack_retirement_scan_references(committed_index, index);
    progress
        .stage_ack_retirement_handoff_with_scan(
            committed_index,
            &mut committable,
            &scan_referenced,
            locally_held,
            &census_absent,
        )
        .context(CHECKPOINT_ACK_HANDOFF)?;
    let context_rearms = committable.accept_file_upload_context_acks(
        &progress.split_context_receipt_candidates(),
        &progress.fresh_context_body_acks,
        &progress.covered_stale_bodies(),
    );
    committable.stamp_entity_upload_context_acks(
        &durable.destination_namespace_hash,
        &durable.accepted_body_witnesses,
        &durable.accepted_body_contexts,
    );
    validate_destination().context(CHECKPOINT_VALIDATE_DESTINATION)?;
    committable
        .save_with_progress_owner(index_path, read_limit, &progress_owner)
        .context(CHECKPOINT_INDEX_SAVE)?;
    if let Some(scan) = correction_scan {
        scan.report_discovery_growth_after_save(&committable);
        context_rearms.emit(scan.source);
    }
    Ok(committable)
}

fn cached_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
) -> Option<SnapshotSourceManifest> {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(destination_namespace.to_string(), source.api_slug()))
        .cloned()
}

#[cfg(test)]
fn clear_source_manifests_for_test() {
    source_manifests()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

/// Entity fingerprints already counted as a client-report poison loss.
///
/// Legacy validation failures are re-attempted every cycle because they have no
/// durable per-entity settlement. Counting each attempt would make one broken
/// session look like an unbounded stream of losses — and if the source has no
/// valid sibling, no request ever succeeds, so nothing commits the report and
/// the number only grows. Entity-ACK rejections and local corruption are counted
/// through the same ledger after their quarantine checkpoint is durable.
///
/// Pruned to the current scan on every upload pass, exactly like the accepted
/// fingerprint ledger, so it stays O(current scan) rather than O(all history).
///
/// Keyed by upload scope (the source) because the prune is per scan: a Codex pass
/// must not prune Claude's ledger, or the next Claude cycle would count its
/// already-counted poison a second time.
static COUNTED_POISON_FINGERPRINTS: OnceLock<Mutex<BTreeMap<String, BTreeSet<String>>>> =
    OnceLock::new();

fn counted_poison_fingerprints() -> &'static Mutex<BTreeMap<String, BTreeSet<String>>> {
    COUNTED_POISON_FINGERPRINTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn retain_counted_poison_fingerprints(scope: &str, current: &BTreeSet<String>) {
    if let Ok(mut counted) = counted_poison_fingerprints().lock() {
        if let Some(ledger) = counted.get_mut(scope) {
            ledger.retain(|value| current.contains(value));
            if ledger.is_empty() {
                counted.remove(scope);
            }
        }
    }
}

/// Record one poison loss for `fingerprint`, at most once per entity per scope.
fn record_poison_loss_once(scope: &str, fingerprint: &str) {
    let first_time = match counted_poison_fingerprints().lock() {
        Ok(mut counted) => counted
            .entry(scope.to_string())
            .or_default()
            .insert(fingerprint.to_string()),
        // A poisoned lock must not silently stop the accounting; over-reporting
        // a loss is recoverable, losing the signal is not.
        Err(_) => true,
    };
    if first_time {
        crate::client_report::record(crate::client_report::ClientReportReason::Poisoned, 1);
    }
}

#[cfg(test)]
fn counted_poison_fingerprints_for_test(scope: &str) -> BTreeSet<String> {
    counted_poison_fingerprints()
        .lock()
        .expect("poison ledger")
        .get(scope)
        .cloned()
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Default)]
struct SyncCounts {
    census_status: crate::snapshots::CensusStatus,
    backfill_window_days: u64,
    backfill_file_limit: u64,
    discovered_file_count: u64,
    skipped_file_count_due_to_limit: u64,
    scan_cap_hit: bool,
    scanned_file_count: u64,
    scanned_session_count: u64,
    semantic_noop_count: u64,
    census_complete: bool,
    symlink_rejected_count: u64,
    unreadable_path_count: u64,
    oversized_file_count: u64,
    disappeared_file_count: u64,
    malformed_json_line_count: u64,
    invalid_utf8_line_count: u64,
    over_line_cap_count: u64,
    recognized_usage_drop_count: u64,
    ownership_incomplete_file_count: u64,
    causes: crate::snapshots::ownership_diagnostics::Summary,
    snapshot_unproven_terminal_count: u64,
    snapshot_superseded_terminal_count: u64,
    cooldown_conflict_deferred: usize,
    zero_snapshot_confirmed_count: u64,
    zero_snapshot_usage_evidence_count: u64,
    dropped_usage_record_count: u64,
    /// The scan's settled share of each public loss counter above; see
    /// `SourceScanResult`. `terminal <= public` in every class.
    terminal_ownership_incomplete_file_count: u64,
    terminal_zero_snapshot_usage_evidence_count: u64,
    terminal_recognized_usage_drop_count: u64,
    terminal_dropped_usage_record_count: u64,
    terminal_over_line_cap_count: u64,
    /// Residue witness cardinalities, counts only.
    census_residue_index_key_count: u64,
    census_residue_archived_rollout_count: u64,
    uploaded_count: u64,
    sidecar_reads: Option<CodexScanDiagnostics>,
}

/// How the loss a completed cycle discloses reads on its terminal receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisclosedLoss {
    /// No ownership-incomplete file, no usage evidence without an entity, no
    /// dropped usage record.
    None,
    /// The census completed, no retryable problem remains, and every loss
    /// class equals its terminal counterpart: the receipt can prove, class by
    /// class, that all the loss it discloses is loss no retry can change.
    Terminal,
    /// Loss the daemon has not proved non-progressing: an incomplete census,
    /// a retryable problem beside the residue, or a class it has not settled.
    Unsettled,
}

impl SyncCounts {
    /// Loss a later traversal can still change. Mirrors
    /// `ScanTraversalCounts::has_retryable_problems` on the receipt's own
    /// counters so the receipt can never claim a settled residue the scan did
    /// not: a walk that could not enter, open, read, or parse something may
    /// simply not have seen the file that would resolve a fork.
    fn has_retryable_problems(&self) -> bool {
        self.symlink_rejected_count > 0
            || self.unreadable_path_count > 0
            || self.oversized_file_count > 0
            || self.disappeared_file_count > 0
            || self.malformed_json_line_count > 0
            || self.invalid_utf8_line_count > 0
            || self.over_line_cap_count > self.terminal_over_line_cap_count
    }

    /// The loss classes that have always turned a successful cycle's receipt
    /// into a `parse_error`. Unchanged, so the legacy shape is byte-identical.
    fn has_disclosed_loss(&self) -> bool {
        self.ownership_incomplete_file_count > 0
            || self.zero_snapshot_usage_evidence_count > 0
            || self.dropped_usage_record_count > 0
    }

    fn disclosed_loss(&self) -> DisclosedLoss {
        // A partial census is itself unsettled evidence even when it has not
        // yet populated one of the public loss counters. In particular,
        // RetryPending Claude authority families deliberately lower
        // `census_complete` and raise the scan-cap latch without inventing a
        // per-file loss. Letting the zero-loss fast path win here would emit a
        // clean success that the backend classifies as terminal.
        if !self.census_complete {
            return DisclosedLoss::Unsettled;
        }
        if !self.has_disclosed_loss() {
            return DisclosedLoss::None;
        }
        let every_class_terminal = self.ownership_incomplete_file_count
            == self.terminal_ownership_incomplete_file_count
            && self.zero_snapshot_usage_evidence_count
                == self.terminal_zero_snapshot_usage_evidence_count
            && self.recognized_usage_drop_count == self.terminal_recognized_usage_drop_count
            && self.dropped_usage_record_count == self.terminal_dropped_usage_record_count
            && self.over_line_cap_count == self.terminal_over_line_cap_count;
        if !self.has_retryable_problems() && every_class_terminal {
            DisclosedLoss::Terminal
        } else {
            DisclosedLoss::Unsettled
        }
    }

    fn for_policy(backfill_window_days: u64) -> Self {
        Self {
            backfill_window_days,
            backfill_file_limit: MAX_BACKFILL_FILES_PER_SOURCE as u64,
            ..Self::default()
        }
    }

    fn from_scan_result(
        scan_result: &SourceScanResult,
        uploaded_count: u64,
        receipt_window_days: u64,
    ) -> Self {
        Self {
            // Scan coverage and receipt evidence are deliberately different
            // during replay. The counters below describe the wider traversal;
            // this field and the manifest describe only the server-negotiated
            // semantic activity window.
            backfill_window_days: receipt_window_days,
            census_status: scan_result.census_status,
            backfill_file_limit: scan_result.backfill_file_limit as u64,
            discovered_file_count: scan_result.discovered_file_count as u64,
            skipped_file_count_due_to_limit: scan_result.skipped_file_count_due_to_limit as u64,
            scan_cap_hit: scan_result.scan_cap_hit,
            scanned_file_count: scan_result.scanned_file_count as u64,
            scanned_session_count: scan_result.scanned_session_count as u64,
            semantic_noop_count: scan_result.semantic_noop_count as u64,
            census_complete: scan_result.census_complete,
            symlink_rejected_count: scan_result.symlink_rejected_count as u64,
            unreadable_path_count: scan_result.unreadable_path_count as u64,
            oversized_file_count: scan_result.oversized_file_count as u64,
            disappeared_file_count: scan_result.disappeared_file_count as u64,
            malformed_json_line_count: scan_result.malformed_json_line_count as u64,
            invalid_utf8_line_count: scan_result.invalid_utf8_line_count as u64,
            over_line_cap_count: scan_result.over_line_cap_count as u64,
            recognized_usage_drop_count: scan_result.recognized_usage_drop_count as u64,
            ownership_incomplete_file_count: scan_result.ownership_incomplete_file_count as u64,
            causes: scan_result
                .causes
                .summary(scan_result.ownership_incomplete_file_count),
            snapshot_unproven_terminal_count: 0,
            snapshot_superseded_terminal_count: 0,
            cooldown_conflict_deferred: 0,
            zero_snapshot_confirmed_count: scan_result.zero_snapshot_confirmed_count as u64,
            zero_snapshot_usage_evidence_count: scan_result.zero_snapshot_usage_evidence_count
                as u64,
            dropped_usage_record_count: scan_result.dropped_usage_record_count,
            terminal_ownership_incomplete_file_count: scan_result
                .terminal_ownership_incomplete_file_count
                as u64,
            terminal_zero_snapshot_usage_evidence_count: scan_result
                .terminal_zero_snapshot_usage_evidence_count
                as u64,
            terminal_recognized_usage_drop_count: scan_result.terminal_recognized_usage_drop_count
                as u64,
            terminal_dropped_usage_record_count: scan_result.terminal_dropped_usage_record_count,
            terminal_over_line_cap_count: scan_result.terminal_over_line_cap_count as u64,
            census_residue_index_key_count: scan_result.census_residue_index_key_count as u64,
            census_residue_archived_rollout_count: scan_result.census_residue_archived_rollout_count
                as u64,
            uploaded_count,
            sidecar_reads: scan_result.local_codex_diagnostics,
        }
    }

    fn terminal_census_line(&self, source: &str) -> String {
        let mut line = format!(
            "snapshot terminal_census source={source} census_complete={} scanned_files={} \
             uploaded={} unproven_terminal={} unproven_terminal_attempt_count={} superseded_terminal={} \
             ownership_incomplete_files={} zero_snapshot_usage_evidence_files={} \
             dropped_usage_records={} cooldown_conflict_deferred={} terminal_contract_retry={} terminal_contract_retry_exhausted={}",
            self.census_complete,
            self.scanned_file_count,
            self.uploaded_count,
            self.snapshot_unproven_terminal_count,
            UNPROVEN_TERMINAL_ATTEMPT_COUNT.load(std::sync::atomic::Ordering::Relaxed),
            self.snapshot_superseded_terminal_count,
            self.ownership_incomplete_file_count,
            self.zero_snapshot_usage_evidence_count,
            self.dropped_usage_record_count,
            self.cooldown_conflict_deferred,
            crate::snapshots::terminal_contract_retry::local_count(),
            crate::snapshots::terminal_contract_retry::exhausted_count(),
        );
        if source == "codex" {
            line.push_str(&crate::snapshots::ownership_diagnostics::line(self.causes));
            if let Some(d) = self.sidecar_reads {
                line.push_str(&format!(" state_5_reused={} state_5_reloaded={} thread_history_1_reused={} thread_history_1_reloaded={} session_index_reused={} session_index_reloaded={} absent_roots={} sidecar_facts_heap_bytes={}",
                    d.state_titles.reused_roots, d.state_titles.reloaded_roots,
                    d.rollout_extents.reused_roots, d.rollout_extents.reloaded_roots,
                    d.session_index.reused_roots, d.session_index.reloaded_roots,
                    d.state_titles.absent_roots, d.sidecar_facts_heap_bytes));
                let or_none = |cause: &'static str| if cause.is_empty() { "none" } else { cause };
                line.push_str(&format!(
                    " sidecar_reload_cause={} sidecar_keep_declined={}",
                    or_none(d.sidecar_reload_cause),
                    or_none(d.sidecar_keep_declined)
                ));
                for (input, homes) in ["state_5", "thread_history_1", "session_index"]
                    .iter()
                    .zip(d.sidecar_changed_homes)
                {
                    line.push_str(&format!(" {input}_changed={}", homes.count_ones()));
                    if homes != 0 {
                        let bits = (0..64u32).filter(|bit| homes & (1 << bit) != 0);
                        let bits = bits.map(|bit| bit.to_string()).collect::<Vec<_>>();
                        line.push_str(&format!(" {input}_changed_homes={}", bits.join(",")));
                    }
                }
            }
        }
        line
    }

    fn with_snapshot_terminal_counts(mut self, index: &ScanIndex) -> Self {
        self.cooldown_conflict_deferred = index.reason_reoffer_cooldown_deferred_count();
        self.snapshot_unproven_terminal_count = index.snapshot_unproven_terminal_count() as u64;
        self.snapshot_superseded_terminal_count = index.snapshot_superseded_terminal_count() as u64;
        // Mirror #389's disclosed-loss convention: terminal unproven entities
        // also contribute to the established incomplete-evidence health scalar.
        self.ownership_incomplete_file_count = self
            .ownership_incomplete_file_count
            .saturating_add(self.snapshot_unproven_terminal_count);
        // They are terminal by disposition (the bounded reconstruction ladder
        // is exhausted), so the settled share grows by exactly the same
        // number: the ownership-incomplete class stays matched, and the
        // receipt keeps `terminal <= public`.
        self.terminal_ownership_incomplete_file_count = self
            .terminal_ownership_incomplete_file_count
            .saturating_add(self.snapshot_unproven_terminal_count);
        // Account-deferred holds are retried every generation, so they are
        // disclosed as incomplete ownership but never as settled residue: the
        // public count exceeds the terminal share and the receipt stays
        // unsettled for as long as any hold persists.
        self.ownership_incomplete_file_count = self
            .ownership_incomplete_file_count
            .saturating_add(index.claude_account_deferred_hold_count() as u64);
        self
    }
}

fn validated_receipt_window_days(negotiated_window_days: u64) -> Result<u64> {
    if negotiated_window_days > MAX_SNAPSHOT_STATUS_WINDOW_DAYS {
        return Err(anyhow!(
            "snapshot status evidence window is outside the supported 0..={MAX_SNAPSHOT_STATUS_WINDOW_DAYS} day range"
        ));
    }
    Ok(negotiated_window_days)
}

fn scan_request_window_days(receipt_window_days: u64, backfill_pending: bool) -> u64 {
    if backfill_pending {
        // The scanner applies its own local safety ceiling. `u64::MAX` means
        // "walk the complete replay range", not "claim this width upstream".
        u64::MAX
    } else {
        receipt_window_days
    }
}

fn snapshot_manifest_window(
    census_window_end: &str,
    receipt_window_days: u64,
) -> Result<(String, String)> {
    let receipt_window_days = validated_receipt_window_days(receipt_window_days)?;
    if receipt_window_days == 0 {
        return Err(anyhow!(
            "zero-width snapshot status evidence must be manifest-free"
        ));
    }
    let window_end = OffsetDateTime::parse(census_window_end, &Rfc3339)
        .context("parse snapshot manifest window end")?;
    let window_start = window_end
        .checked_sub(TimeDuration::days(receipt_window_days as i64))
        .ok_or_else(|| anyhow!("snapshot manifest window overflow"))?;
    Ok((
        window_start
            .format(&Rfc3339)
            .context("format snapshot manifest window start")?,
        window_end
            .format(&Rfc3339)
            .context("format snapshot manifest window end")?,
    ))
}

fn snapshot_manifest_window_days(manifest: &SnapshotSourceManifest) -> Result<u64> {
    let window_start = OffsetDateTime::parse(&manifest.window_start, &Rfc3339)
        .context("parse cached snapshot manifest window start")?;
    let window_end = OffsetDateTime::parse(&manifest.window_end, &Rfc3339)
        .context("parse cached snapshot manifest window end")?;
    let window_seconds = (window_end - window_start).whole_seconds();
    let day_seconds = 24 * 60 * 60;
    if window_seconds <= 0 || window_seconds % day_seconds != 0 {
        return Err(anyhow!(
            "cached snapshot manifest window is not a positive whole-day interval"
        ));
    }
    let window_days = u64::try_from(window_seconds / day_seconds)
        .context("convert cached snapshot manifest window days")?;
    validated_receipt_window_days(window_days)
}

fn deferred_entity_state(permanent: bool) -> CollectorState<'static> {
    CollectorState::Error {
        code: if permanent {
            "backend_validation_error"
        } else {
            "server_error"
        },
        message: if permanent {
            "backend permanently rejected exact snapshot bodies; accepted siblings checkpointed"
        } else {
            "backend has unsettled snapshot entities; accepted siblings checkpointed"
        },
    }
}

/// Current permanent refusals in the upload ledger. Content-free: counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PermanentRefusalCounts {
    total: usize,
    /// Refusals the backend already dominates with an accepted record.
    dominated: usize,
    exposure: crate::local_resource_diagnostics::RefusalExposure,
}

impl PermanentRefusalCounts {
    /// A refusal counts as dominated only while its quarantine record is still
    /// the terminal record for the same refused body. A newer body of that
    /// entity with a pending outcome, such as a retryable conflict, owes its
    /// own result, so the older refusal then counts as other.
    fn of(progress: &SnapshotUploadProgress) -> Self {
        progress.permanent_rejections.iter().fold(
            Self {
                exposure: progress.refusal_exposure(current_unix_seconds()),
                ..Self::default()
            },
            |mut counts, (fingerprint, refusal)| {
                counts.total += 1;
                if Self::is_dominated(progress, fingerprint, refusal) {
                    counts.dominated += 1;
                }
                counts
            },
        )
    }

    /// Dominated refusals whose reason is an authority downgrade. That guard
    /// has refused real growth before, so the local log keeps their own count.
    fn authority_downgrades(progress: &SnapshotUploadProgress) -> usize {
        progress
            .permanent_rejections
            .iter()
            .filter(|(fingerprint, refusal)| {
                refusal.reason
                    == crate::upload_receipts::RejectedUsageReason::UsageAccountingAuthorityDowngrade
                    && Self::is_dominated(progress, fingerprint, refusal)
            })
            .count()
    }

    fn is_dominated(
        progress: &SnapshotUploadProgress,
        fingerprint: &str,
        refusal: &PermanentSnapshotRejection,
    ) -> bool {
        (refusal.reason.is_dominated() || (refusal.is_stale() && refusal.exposure.is_some()))
            && !refusal
                .revisions
                .values()
                .any(PermanentSnapshotRejection::owed)
            && progress
                .quarantined_fingerprints
                .get(fingerprint)
                .is_some_and(|record| {
                    matches!(
                        record.disposition,
                        SnapshotQuarantineDisposition::UnprovenTerminal
                            | SnapshotQuarantineDisposition::SupersededTerminal
                    ) && record.upload_body_witness.as_deref()
                        == Some(refusal.body_witness.as_str())
                })
    }
}

/// Last retained-refusal log line per source. A quiet cycle that re-discloses
/// the same list does not log it again.
static SOURCE_REFUSAL_LOGS: Mutex<[Option<RefusalLogLine>; 3]> = Mutex::new([None, None, None]);

/// Retained refusal counts, the authority-downgrade share of the dominated
/// ones, and whether they were reported as settled residue.
type RefusalLogLine = (PermanentRefusalCounts, usize, bool);

/// Content-free, local-only: counts of the refusals retained this cycle, with
/// the dominated ones split by reason, and whether the cycle reported them as
/// settled residue. Logs on change only; each refusal is also logged with its
/// reason when it arrives.
fn log_retained_permanent_refusals(
    source: SnapshotSource,
    retained: PermanentRefusalCounts,
    authority_downgrades: usize,
    settled_residue: bool,
) {
    let line = (retained, authority_downgrades, settled_residue);
    let Some(previous) = rejection_log::changed(&SOURCE_REFUSAL_LOGS, source, line) else {
        return;
    };
    if previous.is_some_and(|p| retained.exposure.owed_entities > p.0.exposure.owed_entities) {
        eprintln!("ottto-service: refusal exposure alarm source={} reason=accepted_log_stale_older_upload owed_entities={} oldest_age_seconds={}", source.api_slug(), retained.exposure.owed_entities, retained.exposure.oldest_age_seconds);
    }
    eprintln!(
        "local snapshot sync retains {} dominated ({} usage_accounting_authority_downgrade) \
         and {} other permanent refusal(s) for {}{}; reason=accepted_log_stale_older_upload \
         owed_entities={} known_requests={} known_tokens={} unknown_request_entities={} \
         unknown_token_entities={} unknown_age_entities={} oldest_age_seconds={}",
        retained.dominated,
        authority_downgrades,
        retained.total - retained.dominated,
        source.api_slug(),
        if settled_residue {
            "; reported as settled residue the backend already owns"
        } else {
            ""
        },
        retained.exposure.owed_entities,
        retained.exposure.known_requests,
        retained.exposure.known_tokens,
        retained.exposure.unknown_request_entities,
        retained.exposure.unknown_token_entities,
        retained.exposure.unknown_age_entities,
        retained.exposure.oldest_age_seconds,
    );
}

/// Status only: an otherwise settled cycle with dominated or stale-owed
/// refusals remains successful. Existing residue counters keep their receipt
/// shape; stale debt remains owed in custody and diagnostics, never accepted.
/// Other refusals and unsettled transport retain their existing status.
fn refused_entity_state(
    permanent: bool,
    refusals: PermanentRefusalCounts,
    upload_fully_settled: bool,
) -> CollectorState<'static> {
    if permanent
        && upload_fully_settled
        && refusals.total > 0
        && refusals.dominated + refusals.exposure.owed_entities == refusals.total
    {
        CollectorState::Success
    } else {
        deferred_entity_state(permanent)
    }
}

#[derive(Debug)]
enum CollectorState<'a> {
    Success,
    /// A server-authoritative zero-width policy withdraws the prior census
    /// without claiming either a successful scan or a collector failure.
    PolicyTombstone,
    Disabled(Option<String>),
    Error {
        code: &'a str,
        message: &'a str,
    },
}

#[derive(Debug)]
struct CollectorStatus<'a> {
    source: SnapshotSource,
    machine_id: &'a str,
    scan_started_at: &'a str,
    counts: SyncCounts,
    state: CollectorState<'a>,
}

#[derive(Clone, Copy)]
enum TerminalManifestSource<'a> {
    Withdraw,
    CompleteCensus(&'a ScanIndex),
}

#[allow(dead_code, reason = "preparation is compiled ahead of its activation")]
#[path = "bounded_snapshot_retry.rs"]
mod bounded_snapshot_retry;
#[path = "live_snapshot_retry.rs"]
mod live_snapshot_retry;

pub fn upload_local_health_projection_now(daemon: &LocalDaemon) -> Result<()> {
    let _stage = StageWindow::begin("unknown", "offpass_local_health");
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let Some(source) = heartbeat_source(&device) else {
        return Err(anyhow!("registered device has no enabled sources"));
    };
    let client = SnapshotApiClient::new(snapshot_api_base_url()?);
    upload_local_health_projection_reporting(
        &client,
        &device,
        &device_secret,
        source,
        &machine_id,
        daemon,
    )
}

fn upload_local_health_projection_reporting(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Result<()> {
    // The binding this pass's requests are for, captured before any of them.
    // A failure is recorded against it, never against a setup run attached
    // while a request was in flight.
    let binding = setup_run_refresh_binding(device, device_secret, source)?;
    let relay_binding = client.relay_auth_binding(device, device_secret, source);
    if let Some(held) = setup_run_refresh_hold_for(&binding) {
        // No request at all while held: the last `AuthRejected` upload event
        // stays the latest one, so local health keeps reporting the rejection.
        return Err(anyhow::Error::new(held));
    }
    match upload_local_health_projection_with(
        client,
        device,
        device_secret,
        source,
        machine_id,
        daemon,
    ) {
        Ok(()) => {
            clear_setup_run_refresh_hold();
            let _ = daemon.record_local_health_upload_succeeded();
            Ok(())
        }
        Err(error)
            if local_health_upload_should_refresh_setup_run(&error)
                && crate::relay_auth::take_setup_refresh(relay_binding) =>
        {
            if let Err(refresh_error) =
                crate::control::refresh_setup_run_token_for_persisted_connection()
            {
                // Terminal refresh failure indicating the bound account was
                // deleted server-side: transition the binding to the
                // unbound-equivalent `account_not_found` state so the next
                // sign-in (by any user) is a fresh first claim instead of a
                // reset-required dead end.
                if crate::control::backend_error_indicates_account_gone(&refresh_error) {
                    let _ = daemon.mark_account_not_found();
                }
                let _ = daemon
                    .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected);
                note_setup_run_refresh_failed(
                    &binding,
                    crate::control::terminal_refresh_rejection(&refresh_error).is_some(),
                );
                return Err(error.context(format!(
                    "refresh setup-run credentials after relay auth rejection failed: {refresh_error}"
                )));
            }
            crate::relay_auth::retry_after_setup_refresh(
                relay_binding,
                client.relay_auth_binding(device, device_secret, source),
            );
            match upload_local_health_projection_with(
                client,
                device,
                device_secret,
                source,
                machine_id,
                daemon,
            ) {
                Ok(()) => {
                    clear_setup_run_refresh_hold();
                    let _ = daemon.record_local_health_upload_succeeded();
                    Ok(())
                }
                Err(retry_error) => {
                    if local_health_upload_should_refresh_setup_run(&retry_error) {
                        note_setup_run_refresh_failed(&binding, false);
                    }
                    let _ = daemon.record_local_health_upload_failed(
                        local_health_upload_failure_kind(&retry_error),
                    );
                    Err(retry_error)
                }
            }
        }
        Err(error) => {
            let _ =
                daemon.record_local_health_upload_failed(local_health_upload_failure_kind(&error));
            Err(error)
        }
    }
}

/// First wait after a local health pass whose setup-run refresh did not
/// restore authorization; it doubles per further failure up to the cap.
const SETUP_RUN_REFRESH_HOLD_BASE: Duration = Duration::from_secs(120);
const SETUP_RUN_REFRESH_HOLD_CAP: Duration = Duration::from_secs(30 * 60);

/// A local health pass skipped because the previous pass for the same device
/// credential and setup-run binding was rejected and the refresh did not help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalHealthRefreshHeld {
    /// `None` while parked until this Mac reconnects.
    remaining: Option<Duration>,
}

impl std::fmt::Display for LocalHealthRefreshHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.remaining {
            Some(remaining) => write!(
                f,
                "local health upload held after setup-run refresh failed; next attempt in {}s",
                remaining.as_secs()
            ),
            None => write!(
                f,
                "local health upload held: Ottto ended this Mac's setup run or device credential; reconnect to resume"
            ),
        }
    }
}

impl std::error::Error for LocalHealthRefreshHeld {}

/// Rejected-refresh streak for one binding. An authoritative terminal refresh
/// answer ([`crate::control::terminal_refresh_rejection`]: the run ended, or
/// the device credential is rejected) parks the binding until it changes;
/// every other rejection backs off on a capped ladder and is never final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupRunRefreshHold {
    binding: [u8; 32],
    failures: u32,
    /// `None`: parked until the binding changes.
    until: Option<Instant>,
}

static SETUP_RUN_REFRESH_HOLD: OnceLock<Mutex<Option<SetupRunRefreshHold>>> = OnceLock::new();

fn setup_run_refresh_hold() -> &'static Mutex<Option<SetupRunRefreshHold>> {
    SETUP_RUN_REFRESH_HOLD.get_or_init(|| Mutex::new(None))
}

/// Digest of what a reattach or credential change replaces: the device id and
/// secret, and the persisted setup run and API base. Kept in memory only.
fn setup_run_refresh_binding(
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"ottto:setup-run-refresh-hold:v1\0");
    digest.update(device.device_id.as_bytes());
    digest.update(b"\0");
    digest.update(device_secret.as_bytes());
    digest.update(crate::relay_auth::binding_key(
        &snapshot_api_base_url()?,
        device,
        device_secret,
        source.api_slug(),
    ));
    if let Some(connection) = FileConnectionStore::default().load().ok().flatten() {
        digest.update(b"\0");
        digest.update(connection.setup_run_id.as_bytes());
        digest.update(b"\0");
        digest.update(connection.api_base_url.as_bytes());
    }
    Ok(digest.finalize().into())
}

fn setup_run_refresh_hold_duration(failures: u32) -> Duration {
    SETUP_RUN_REFRESH_HOLD_BASE
        .saturating_mul(1u32 << failures.saturating_sub(1).min(5))
        .min(SETUP_RUN_REFRESH_HOLD_CAP)
}

/// The hold on `binding`, or `None` when a pass may run. A hold for a
/// different binding is dropped: the user reattached or the credential changed.
fn setup_run_refresh_hold_at(
    hold: &mut Option<SetupRunRefreshHold>,
    binding: &[u8; 32],
    now: Instant,
) -> Option<LocalHealthRefreshHeld> {
    let current = (*hold)?;
    if &current.binding != binding {
        *hold = None;
        return None;
    }
    match current.until {
        None => Some(LocalHealthRefreshHeld { remaining: None }),
        Some(until) => until
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| LocalHealthRefreshHeld {
                remaining: Some(remaining),
            }),
    }
}

/// Record a failed refresh for `binding`; returns the wait, or `None` when the
/// failure was terminal and the binding is parked.
fn note_setup_run_refresh_failed_at(
    hold: &mut Option<SetupRunRefreshHold>,
    binding: &[u8; 32],
    now: Instant,
    terminal: bool,
) -> Option<Duration> {
    let failures = match *hold {
        Some(current) if &current.binding == binding => current.failures.saturating_add(1),
        _ => 1,
    };
    let wait = (!terminal).then(|| setup_run_refresh_hold_duration(failures));
    *hold = Some(SetupRunRefreshHold {
        binding: *binding,
        failures,
        until: wait.map(|wait| now + wait),
    });
    wait
}

fn setup_run_refresh_hold_for(binding: &[u8; 32]) -> Option<LocalHealthRefreshHeld> {
    let mut hold = setup_run_refresh_hold().lock().ok()?;
    setup_run_refresh_hold_at(&mut hold, binding, Instant::now())
}

fn note_setup_run_refresh_failed(binding: &[u8; 32], terminal: bool) {
    if let Ok(mut hold) = setup_run_refresh_hold().lock() {
        match note_setup_run_refresh_failed_at(&mut hold, binding, Instant::now(), terminal) {
            Some(wait) => eprintln!(
                "local health setup-run refresh rejected; next attempt in {}s",
                wait.as_secs()
            ),
            None => eprintln!(
                "local health setup-run refresh ended by Ottto; held until this Mac reconnects"
            ),
        }
    }
}

/// Explicit recovery only: also release the local-health terminal refresh hold.
pub(crate) fn reset_relay_authorization_backoff() {
    crate::relay_auth::reset();
    clear_setup_run_refresh_hold();
}

fn clear_setup_run_refresh_hold() {
    if let Ok(mut hold) = setup_run_refresh_hold().lock() {
        *hold = None;
    }
}

fn local_health_upload_should_refresh_setup_run(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<RelayTokenAuthorizationRejected>()
        .is_some()
        || error
            .downcast_ref::<LocalHealthAuthorizationRejected>()
            .is_some()
}

fn local_health_upload_failure_kind(error: &anyhow::Error) -> LocalHealthUploadFailureKind {
    if error
        .downcast_ref::<LocalHealthProjectionRejected>()
        .is_some()
    {
        LocalHealthUploadFailureKind::ContractRejected
    } else if local_health_upload_should_refresh_setup_run(error) {
        LocalHealthUploadFailureKind::AuthRejected
    } else {
        LocalHealthUploadFailureKind::BackendUnreachable
    }
}

fn local_health_upload_can_wait_quietly(error: &anyhow::Error) -> bool {
    if error
        .downcast_ref::<RelayTokenAuthorizationRejected>()
        .is_some_and(|held| held.suppressed)
    {
        return true;
    }
    if error.downcast_ref::<LocalHealthRefreshHeld>().is_some() {
        return true;
    }
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}

fn upload_local_health_projection_with(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let mut status = daemon
        .status_for_trusted_client()
        .map_err(|error| anyhow!("read local health status failed: {error}"))?;
    // Pairing can select a different machine from the durable local identity.
    // Both heartbeat and health must match the paired identity on the server.
    // Set it before reprojection, using this owned status copy only.
    // Keep daemon state, machine store and setup request authority unchanged.
    // Source-control replies continue to fence on the current device binding.
    status.machine.machine_id = machine_id.to_owned();
    crate::refresh_canonical_local_health(&mut status);
    let heartbeat = status
        .runtime_heartbeat
        .as_ref()
        .ok_or_else(|| anyhow!("runtime heartbeat projection is missing"))?;
    let health = status
        .canonical_health
        .as_ref()
        .ok_or_else(|| anyhow!("canonical local health projection is missing"))?;

    let reply = client.upload_local_health_heartbeat(&relay_token, heartbeat)?;
    apply_source_control(&default_support_dir(), &reply);
    let _ = daemon.record_source_grants(device);
    client.upload_local_health_projection(&relay_token, health)?;
    Ok(())
}

pub(crate) fn agent_status_source_enabled(source: &SourceKind) -> bool {
    load_snapshot_device_credentials().is_ok_and(|(device, _)| {
        agent_status_source_enabled_in(&device, &default_support_dir(), source)
    })
}

/// Granted and not paused: the source's automatic status passes run.
pub(crate) fn agent_status_source_enabled_in(
    device: &LocalDeviceBinding,
    support_dir: &Path,
    source: &SourceKind,
) -> bool {
    enabled_snapshot_sources_in(device, support_dir)
        .into_iter()
        .any(|item| &source_kind(item) == source)
}

pub fn upload_agent_status_snapshots(snapshots: &[AgentStatusSnapshot]) -> Result<usize> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let client = SnapshotApiClient::new(snapshot_api_base_url()?);

    let mut uploaded = 0;
    let mut failed_sources = Vec::new();
    // This standalone path runs on the shared agents too, so its transport
    // evidence feeds the same outage streak (folded per invocation): a
    // persistent agent-status-only transport failure must not stay invisible
    // to the recovery ladder just because snapshot sync was quiet.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    for source in enabled_snapshot_sources(&device) {
        let source_kind = source_kind(source);
        let source_snapshots = snapshots
            .iter()
            .filter(|snapshot| snapshot.source == source_kind)
            .cloned()
            .collect::<Vec<_>>();
        if source_snapshots.is_empty() {
            continue;
        }
        if source_upload_backoff_remaining(source).is_some() {
            failed_sources.push(source.api_slug());
            continue;
        }
        let relay_token = match client.issue_status_relay_token(&device, &device_secret, source) {
            Ok(token) => token,
            Err(error) => {
                transport_cycle.note_error(&error);
                failed_sources.push(source.api_slug());
                continue;
            }
        };
        match upload_agent_status(&client, &relay_token, &machine_id, &source_snapshots) {
            Ok(accepted) => {
                uploaded += accepted;
                transport_cycle.note_success();
            }
            Err(error) => {
                transport_cycle.note_error(&error);
                failed_sources.push(source.api_slug());
            }
        }
    }
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);

    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "agent status upload failed for {} source(s)",
            failed_sources.len()
        ));
    }

    Ok(uploaded)
}

/// Best-effort: cache the AI-generated machine icon URL the backend echoes on the
/// agent-status sync response, so the status command can surface it on
/// `status.machine.icon_url`. Never fails sync on a write error.
fn persist_machine_icon(response: &AgentStatusSnapshotUploadResponse) {
    persist_machine_icon_at(&default_support_dir().join("machine_icon.json"), response);
}

fn persist_machine_icon_at(path: &Path, response: &AgentStatusSnapshotUploadResponse) {
    // This is a best-effort echo, not a deletion signal: older backends omit it
    // and icon lookup failures return null. Leave the original machine binding
    // and version intact; status only applies cached icons to that machine.
    if !response
        .machine_icon_url
        .as_deref()
        .is_some_and(|url| !url.trim().is_empty())
    {
        return;
    }
    let payload = serde_json::json!({
        "machine_id": response.machine_id,
        "icon_url": response.machine_icon_url,
        "icon_version": response.machine_icon_version,
    });
    if let Ok(serialized) = serde_json::to_string(&payload) {
        let _ = std::fs::write(path, serialized);
    }
}

fn capture_codex_recovery_evidence(
    index: &mut ScanIndex,
    committed_index: &mut ScanIndex,
    scan_result: &mut SourceScanResult,
    index_path: &Path,
    progress_path: &Path,
    validate_authority: impl Fn() -> Result<()>,
) -> bool {
    let (mut captured, changed) =
        index.stage_codex_recovery_capture(committed_index, &scan_result.snapshots);
    let mut adopted = false;
    if !changed.is_empty() {
        let protected = scan_result
            .snapshots
            .iter()
            .filter(|item| changed.contains(&item.source_session_id))
            .cloned()
            .collect::<Vec<_>>();
        let saved = (|| -> Result<()> {
            // A state-store save runs its progress recovery under this owner,
            // as the partial checkpoint does: locking the progress file again
            // on a second descriptor would refuse this process's own lock.
            let progress_owner = SnapshotProgressLock::acquire(progress_path)?;
            let progress_owner = if crate::snapshots::state_v2_growth_retention_active(&captured) {
                progress_owner.for_v2(progress_path)
            } else {
                progress_owner
            };
            validate_authority()?;
            let validator = scan_result
                .codex_joining_validator()
                .context("Codex recovery capture lacks a source witness")?;
            validator.validate(&protected)?;
            captured.save_with_progress_owner(index_path, None, &progress_owner)
        })();
        match saved {
            Ok(()) => {
                index.generation = captured.generation;
                index.retain_persistence_baseline_from(&captured);
                *committed_index = captured;
                adopted = true;
            }
            Err(error) => scan_result.hold_codex_groups(
                index,
                committed_index,
                &changed,
                &format!(
                    "recovery capture could not durably publish ({})",
                    safe_error(&error)
                ),
            ),
        }
    }
    scan_result.finish_codex_capture_boundary(index);
    adopted
}

/// Progress claims were saved by the caller. Mirror claims and current-again
/// ordinary retries before source acquisition, then bind each retry to one file.
/// Ordinary offered/queued retries stay due; source-held ones use ordinary backoff.
fn save_terminal_contract_claims_for_scan(
    index: &mut ScanIndex,
    progress: &SnapshotUploadProgress,
    index_path: &Path,
) -> Result<Vec<PathBuf>> {
    let mut changed = index.merge_terminal_contract_claims(&progress.quarantined_fingerprints);
    for (fingerprint, record) in &progress.quarantined_fingerprints {
        let current_again = progress.active_quarantine_retries.contains(fingerprint)
            && index
                .eligible_snapshot_fingerprint_refs()
                .any(|current| current == fingerprint)
            && !index.decode_holds_entity(fingerprint)
            && !progress.permanent_rejections.contains_key(fingerprint)
            && record.contract_retry_claims.is_none()
            && record.disposition == SnapshotQuarantineDisposition::RetryPending
            && record.failed_reconstruction_count < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
            && index
                .quarantined_snapshot_fingerprints
                .get(fingerprint)
                .is_some_and(|old| {
                    let mut pending = old.clone();
                    pending.disposition = record.disposition;
                    pending.retry_after_unix_seconds = record.retry_after_unix_seconds;
                    pending.witness = record.witness.clone();
                    old.disposition == SnapshotQuarantineDisposition::SupersededTerminal
                        && old.witness.same_retry_contract(&record.witness)
                        && pending == *record
                });
        if (current_again
            || record
                .upload_body_witness
                .as_deref()
                .is_some_and(|body| progress.owed_stale_body(fingerprint, body)))
            && index.quarantined_snapshot_fingerprints.get(fingerprint) != Some(record)
        {
            index
                .quarantined_snapshot_fingerprints
                .insert(fingerprint.clone(), record.clone());
            changed = true;
        }
    }
    if changed {
        index.save(index_path)?;
    }
    let paths =
        index.activate_terminal_contract_retries(progress.active_quarantine_retries.clone());
    Ok(paths)
}

/// Prepare the disposable upload ledger against the durable scan-index replay.
///
/// The index owns both the replay generation and conflict quarantine after a
/// completed cycle clears upload progress. For a new generation, old index
/// quarantine must not be restored after progress is rearmed. For the same
/// generation, restore it only after progress has claimed that generation so a
/// clean follow-up cannot erase a replacement conflict before its retry.
#[cfg(test)]
fn prepare_upload_progress_for_cycle(
    upload_progress: &mut SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    historical_replay_pending: bool,
) -> bool {
    prepare_upload_progress_for_cycle_with_reoffer(
        upload_progress,
        index,
        replay_generation,
        historical_replay_pending,
        None,
    )
}

/// Ordinary and continuation prepares bind both runtime witnesses together,
/// and mirror the open head-CAS challenge sessions into the index.
/// Neither retained body ACKs nor receipt candidates acquire new authority here.
fn activate_source_upload_context(
    source: SnapshotSource,
    context: String,
    index: &mut ScanIndex,
    progress: &mut SnapshotUploadProgress,
) {
    progress.active_quarantine_witness = Some(
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &context),
    );
    index.activate_file_upload_context(source, context.clone());
    // A session whose upload can carry a head-CAS answer reads natively, never
    // from Tail. The answer replaces a saved base (`attach_head_conflict_answers`);
    // a challenge without one never answers; only an ACK with a head clears it.
    index.activate_head_conflict_sessions(
        progress
            .head_conflict_challenges
            .keys()
            .filter(|key| progress.accepted_cache_heads.contains_key(*key))
            .cloned()
            .collect(),
    );
    progress.fresh_context_body_acks.clear();
    progress.context_receipt_candidates.clear();
    progress.context_resend = upload_context_resend::Cycle::new(context);
}

/// Production form of the above: outside a historical replay, due refusal
/// re-offers share the ordinary retry budget. A replay neither re-offers nor
/// resets a cooldown.
fn prepare_upload_progress_for_cycle_with_reoffer(
    upload_progress: &mut SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    historical_replay_pending: bool,
    reoffer: Option<&reason_reoffer::Scope<'_>>,
) -> bool {
    if !historical_replay_pending {
        return upload_progress.prepare_quarantine_and_reason_retries(
            &index.quarantined_snapshot_fingerprints,
            reoffer,
        );
    }

    let same_index_replay = index.historical_replay_generation_matches(replay_generation);
    let mut progress_changed = upload_progress.prepare_historical_replay(replay_generation);
    if same_index_replay {
        progress_changed |=
            upload_progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    }
    progress_changed
}

/// Aggregate this cycle's snapshots into detected uses, merge them into the
/// persisted per-source cache, and write it back atomically (temp + rename,
/// like the backfill-state writer). The merge keeps historical destinations
/// that this incremental cycle did not re-scan.
fn update_detected_uses_cache(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
) -> Result<()> {
    let dir = support_dir.join("detected_uses");
    let path = detected_uses_cache_path(support_dir, source);
    let merged = merge_detected_uses(
        read_detected_uses_cache(&path),
        aggregate_detected_uses(snapshots),
        OffsetDateTime::now_utc(),
        TimeDuration::days(DETECTED_USE_RETENTION_DAYS),
    );

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create detected_uses dir {}", dir.display()))?;
    let payload = serde_json::to_vec_pretty(&merged).context("serialize detected uses to JSON")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = std::fs::File::create(&temp_path)
        .with_context(|| format!("create detected_uses temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write detected_uses temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    std::fs::rename(&temp_path, &path)
        .with_context(|| format!("rename detected_uses cache into place {}", path.display()))?;
    Ok(())
}

/// Read the persisted detected-uses cache, or an empty list when it is missing
/// or unreadable (a fresh machine, or a malformed file we simply rebuild).
pub(crate) fn detected_uses_cache_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("detected_uses")
        .join(format!("{}.json", source.api_slug()))
}

fn read_detected_uses_cache(path: &Path) -> Vec<DetectedUse> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn upload_agent_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    machine_id: &str,
    snapshots: &[AgentStatusSnapshot],
) -> Result<usize> {
    if snapshots.is_empty() {
        return Ok(0);
    }
    let request = AgentStatusSnapshotUploadRequest {
        machine_id: machine_id.to_string(),
        snapshots: snapshots
            .iter()
            .cloned()
            .map(AgentStatusSnapshot::redacted_for_backend)
            .collect(),
    };
    let response = small_source_upload(snapshot_source_of_kind(&snapshots[0].source), || {
        client.upload_agent_status(relay_token, &request)
    })?;
    persist_machine_icon(&response);
    crate::net_resilience::note_upstream_upload_succeeded("agent_status");
    Ok(response.accepted as usize)
}

pub(crate) fn snapshot_source_of_kind(kind: &SourceKind) -> SnapshotSource {
    match kind {
        SourceKind::Codex => SnapshotSource::Codex,
        SourceKind::ClaudeCode => SnapshotSource::ClaudeCode,
        SourceKind::Pi => SnapshotSource::Pi,
    }
}

fn source_kind(source: SnapshotSource) -> SourceKind {
    match source {
        SnapshotSource::Codex => SourceKind::Codex,
        SnapshotSource::ClaudeCode => SourceKind::ClaudeCode,
        SnapshotSource::Pi => SourceKind::Pi,
    }
}

/// Build the terminal collector receipt for a completed cycle.
///
/// Split from the send so tests can assert against the exact typed payload —
/// including its declared `report_kind` — rather than a hand-rolled lookalike.
fn collector_status_request(
    destination_namespace: &str,
    status: CollectorStatus<'_>,
    census_residue_status_admitted: bool,
) -> Result<SnapshotStatusRequest> {
    let finished_at = current_rfc3339();
    let disclosed_loss = status.counts.disclosed_loss();
    let census_status_active =
        matches!(&status.state, CollectorState::Success) && !status.counts.census_complete;
    let (
        enabled,
        disabled_reason,
        mut last_error_code,
        last_error_message,
        mut consecutive_failures,
        terminal_succeeded,
    ) = match status.state {
        // A census that completed and whose every disclosed loss class is
        // exactly the loss the daemon settled as non-progressing. The scan
        // succeeded: the clock binds (`last_success_at`), nothing is retried,
        // and the code still names the residue so a consumer that needs a
        // fully clean receipt sees that loss was disclosed. Only under the
        // backend's explicit admission — its error-code set is closed, and an
        // unadmitted code would have the whole receipt rejected.
        CollectorState::Success
            if disclosed_loss == DisclosedLoss::Terminal && census_residue_status_admitted =>
        {
            (
                true,
                None,
                Some(CENSUS_RESIDUE_ERROR_CODE.to_string()),
                Some(census_residue_message(&status.counts)),
                0,
                true,
            )
        }
        // Loss the daemon has not proved non-progressing — or settled residue
        // that a backend predating the admission can only read in this legacy
        // shape. Byte-identical to every released daemon apart from the
        // additive residue counters, which such a backend ignores.
        CollectorState::Success if disclosed_loss != DisclosedLoss::None => (
            true,
            None,
            Some("parse_error".to_string()),
            Some("local usage evidence produced no session snapshot".to_string()),
            1,
            false,
        ),
        CollectorState::Success => (true, None, None, None, 0, true),
        CollectorState::PolicyTombstone => (true, None, None, None, 0, false),
        CollectorState::Disabled(disabled_reason) => (false, disabled_reason, None, None, 0, false),
        CollectorState::Error { code, message } => (
            true,
            None,
            Some(code.to_string()),
            Some(message.to_string()),
            1,
            false,
        ),
    };
    let mut block_cause = None;
    let mut next_retry_at = None;
    if census_status_active {
        let census = status.counts.census_status;
        // First failed gate wins; settled ownership does not block advancing discovery.
        block_cause = if status.counts.unreadable_path_count > 0 {
            Some(CensusBlockCause::UnreadableEvents)
        } else if status.counts.disappeared_file_count > 0 {
            Some(CensusBlockCause::DisappearedFiles)
        } else if census.state_loader_failed {
            Some(CensusBlockCause::StateLoader)
        } else if census.transport_reservation_refused {
            Some(CensusBlockCause::TransportReservation)
        } else if census.reconciliation_incomplete
            && status.counts.ownership_incomplete_file_count
                > status.counts.terminal_ownership_incomplete_file_count
        {
            Some(CensusBlockCause::OwnershipIncomplete)
        } else if !census.pending_work || census.retryable_problem {
            Some(CensusBlockCause::Other)
        } else {
            None
        };
        last_error_code = Some(
            if block_cause.is_some() {
                "census_blocked"
            } else {
                "census_incomplete"
            }
            .to_string(),
        );
        consecutive_failures = u64::from(census.retry_attempt);
        next_retry_at = census
            .retry_not_before_unix_seconds
            .and_then(|seconds| i64::try_from(seconds).ok())
            .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
            .and_then(|time| time.format(&Rfc3339).ok());
    }
    let manifest = cached_source_manifest(destination_namespace, status.source);
    if let Some(manifest) = manifest.as_ref() {
        if manifest.window_end != status.scan_started_at {
            return Err(anyhow!(
                "snapshot manifest window end does not match terminal scan start"
            ));
        }
        let manifest_window_days = snapshot_manifest_window_days(manifest)?;
        if manifest_window_days != status.counts.backfill_window_days {
            return Err(anyhow!(
                "snapshot manifest window does not match terminal receipt evidence window"
            ));
        }
    }
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: status.source.api_slug().to_string(),
        machine_id: status.machine_id.to_string(),
        // This function has exactly one caller shape: a completed collector
        // cycle reporting its outcome. Success, parse failure, scan/upload
        // error, policy tombstone, and the disabled transition are all NEW
        // scan results, so the kind is a constant here rather than anything
        // derived from the fields below.
        report_kind: SnapshotStatusReportKind::ScanStatus,
        enabled,
        disabled_reason,
        last_scan_started_at: Some(status.scan_started_at.to_string()),
        last_scan_finished_at: Some(finished_at.clone()),
        last_success_at: terminal_succeeded.then_some(finished_at),
        last_error_code,
        last_error_message,
        last_uploaded_count: status.counts.uploaded_count,
        last_scanned_session_count: status.counts.scanned_session_count,
        last_scanned_file_count: status.counts.scanned_file_count,
        last_zero_snapshot_confirmed_count: status.counts.zero_snapshot_confirmed_count,
        last_zero_snapshot_usage_evidence_count: status.counts.zero_snapshot_usage_evidence_count,
        last_dropped_usage_record_count: status.counts.dropped_usage_record_count,
        last_ownership_incomplete_file_count: status.counts.ownership_incomplete_file_count,
        last_snapshot_unproven_terminal_count: status.counts.snapshot_unproven_terminal_count,
        last_snapshot_superseded_terminal_count: status.counts.snapshot_superseded_terminal_count,
        last_backfill_window_days: status.counts.backfill_window_days,
        first_read_cutoff: None,
        last_backfill_file_limit: status.counts.backfill_file_limit,
        last_discovered_file_count: status.counts.discovered_file_count,
        last_skipped_file_count_due_to_limit: status.counts.skipped_file_count_due_to_limit,
        last_scan_cap_hit: status.counts.scan_cap_hit,
        last_semantic_noop_count: status.counts.semantic_noop_count,
        last_census_complete: Some(status.counts.census_complete),
        last_symlink_rejected_count: status.counts.symlink_rejected_count,
        last_unreadable_path_count: status.counts.unreadable_path_count,
        last_oversized_file_count: 0,
        last_disappeared_file_count: status.counts.disappeared_file_count,
        last_malformed_json_line_count: status.counts.malformed_json_line_count,
        last_invalid_utf8_line_count: status.counts.invalid_utf8_line_count,
        last_over_line_cap_count: status.counts.over_line_cap_count,
        last_recognized_usage_drop_count: status.counts.recognized_usage_drop_count,
        // Always sent, whichever error code the receipt carries: the settled
        // shares are scan evidence like the counters they decompose, and a
        // backend that declares them journals the disclosure even while the
        // code still reads `parse_error`. A backend that predates them ignores
        // them.
        last_terminal_ownership_incomplete_file_count: status
            .counts
            .terminal_ownership_incomplete_file_count,
        last_terminal_zero_snapshot_usage_evidence_count: status
            .counts
            .terminal_zero_snapshot_usage_evidence_count,
        last_terminal_recognized_usage_drop_count: status
            .counts
            .terminal_recognized_usage_drop_count,
        last_terminal_dropped_usage_record_count: status.counts.terminal_dropped_usage_record_count,
        last_terminal_over_line_cap_count: status.counts.terminal_over_line_cap_count,
        // A census verdict, so it is a function of the counts alone and not of
        // the admission: true exactly when every disclosed loss class was
        // settled this generation.
        last_census_residue_settled: disclosed_loss == DisclosedLoss::Terminal,
        last_census_residue_index_key_count: status.counts.census_residue_index_key_count,
        last_census_residue_archived_rollout_count: status
            .counts
            .census_residue_archived_rollout_count,
        last_census_pending_file_count: Some(status.counts.skipped_file_count_due_to_limit),
        last_census_block_cause: block_cause,
        consecutive_failures,
        next_retry_at,
        collector_version: Some(collector_version()),
        parser_version: Some(status.source.parser_version().to_string()),
        manifest,
        // A scan result, not a check-in: the field stays off this wire shape.
        control_plane: None,
    };
    Ok(request)
}

/// The residue a `census_residue` receipt names: classes and settled counts
/// only. Never a path, an index key, or a session id — the backend rejects a
/// path-shaped message outright, and the witness identifiers stay in the local
/// index.
fn census_residue_message(counts: &SyncCounts) -> String {
    format!(
        "census completed with settled non-progressing residue: \
         ownership_incomplete_files={}, zero_snapshot_usage_evidence_files={}, \
         recognized_usage_drops={}, dropped_usage_records={}, over_line_cap_lines={}",
        counts.terminal_ownership_incomplete_file_count,
        counts.terminal_zero_snapshot_usage_evidence_count,
        counts.terminal_recognized_usage_drop_count,
        counts.terminal_dropped_usage_record_count,
        counts.terminal_over_line_cap_count,
    )
}

#[cfg(test)]
fn report_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let request = collector_status_request(destination_namespace, status, false)?;
    client.report_status(relay_token, &request)?;
    Ok(())
}

/// The terminal activity hint owns evidence width and admission of the census
/// residue code; both are read from the same fresh server answer.
#[derive(Debug, Clone, Copy)]
struct TerminalReceiptPolicy {
    receipt_window_days: u64,
    /// Exact match on `CENSUS_RESIDUE_STATUS_CONTRACT`, fail-closed: absent,
    /// null, and any other token keep the legacy receipt shape. The backend's
    /// error-code set is closed, so this is what keeps a daemon from having
    /// its entire terminal receipt rejected by a backend that predates the
    /// admission — whatever order the two are deployed in.
    census_residue_status_admitted: bool,
}

fn current_terminal_receipt_policy(
    client: &SnapshotApiClient,
    relay_token: &str,
    source: SnapshotSource,
) -> Result<TerminalReceiptPolicy> {
    let activity_hint = small_source_upload(source, || client.get_activity_hint(relay_token))?;
    Ok(TerminalReceiptPolicy {
        receipt_window_days: validated_receipt_window_days(activity_hint.backfill_window_days)?,
        census_residue_status_admitted: activity_hint.census_residue_status_contract.as_deref()
            == Some(CENSUS_RESIDUE_STATUS_CONTRACT),
    })
}

fn current_receipt_window_days(
    client: &SnapshotApiClient,
    relay_token: &str,
    source: SnapshotSource,
) -> Result<u64> {
    Ok(current_terminal_receipt_policy(client, relay_token, source)?.receipt_window_days)
}

fn refresh_terminal_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    scan_started_at: &str,
    receipt_window_days: u64,
    manifest_source: TerminalManifestSource<'_>,
) -> Result<()> {
    // Withdraw first so a failed refresh cannot leave a stale-width witness for
    // the independent heartbeat to repeat. Zero has no v2 manifest by design.
    withdraw_source_manifest(destination_namespace, source);
    if receipt_window_days == 0 {
        return Ok(());
    }
    let TerminalManifestSource::CompleteCensus(index) = manifest_source else {
        return Ok(());
    };
    let (window_start, window_end) =
        snapshot_manifest_window(scan_started_at, receipt_window_days)?;
    publish_source_manifest(
        destination_namespace,
        source,
        index.manifest_for_window(source, &window_start, &window_end)?,
    );
    Ok(())
}

fn report_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    support_dir: &Path,
    source: SnapshotSource,
    manifest_source: TerminalManifestSource<'_>,
    mut status: CollectorStatus<'_>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    // This is the single terminal report boundary. Every terminal outcome
    // reacquires its width here, after scanning/uploading and immediately
    // before deriving both the manifest and status scalar from that same hint
    // — and reads the census residue admission off that hint, so receipt
    // shape and evidence width are decided by one server answer.
    let TerminalReceiptPolicy {
        receipt_window_days,
        census_residue_status_admitted,
    } = current_terminal_receipt_policy(client, &relay_token, source)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    status.counts.backfill_window_days = receipt_window_days;
    if receipt_window_days == 0 {
        status.counts.census_complete = false;
        status.state = CollectorState::PolicyTombstone;
    }
    refresh_terminal_manifest(
        &destination_namespace,
        source,
        status.scan_started_at,
        receipt_window_days,
        manifest_source,
    )?;
    // Keep non-blocking cooldown debt beside the terminal census counters on
    // every report, even when the re-offer work summary is unchanged/quiet.
    eprintln!("{}", status.counts.terminal_census_line(source.api_slug()));
    let mut request = collector_status_request(
        &destination_namespace,
        status,
        census_residue_status_admitted,
    )?;
    request.first_read_cutoff = load_backfill_state(support_dir)
        .first_read_cutoff(&destination_namespace, source.api_slug());
    small_source_upload(source, || client.report_status(&relay_token, &request))?;
    // Content-free, after a successful send: the closed error-code slug and
    // enabled flag, once per change per source (and once after start).
    let line = (request.enabled, request.last_error_code);
    if rejection_log::changed(&SOURCE_STATUS_LOGS, source, line.clone()).is_some() {
        let code = line.1.as_deref().unwrap_or("none");
        eprintln!(
            "ottto-service: collector status source={} enabled={} code={code}",
            source.api_slug(),
            line.0
        );
    }
    Ok(())
}

/// Last reported status log line per source slot.
static SOURCE_STATUS_LOGS: Mutex<[Option<StatusLogLine>; 3]> = Mutex::new([None, None, None]);

/// Enabled flag and closed error-code slug of one terminal status report.
type StatusLogLine = (bool, Option<String>);

/// A policy stop before scanning: withdraw this source's manifest, clear its
/// active sessions, then report `status` with the manifest withdrawn.
fn withdraw_and_report_policy_stop(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    support_dir: &Path,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let source = status.source;
    withdraw_source_manifest(
        &snapshot_upload_destination_namespace(device, device_secret),
        source,
    );
    let _ =
        crate::active_sessions::clear_active_sessions(support_dir, source, status.scan_started_at);
    report_status_with_fresh_relay_token(
        client,
        device,
        device_secret,
        support_dir,
        source,
        TerminalManifestSource::Withdraw,
        status,
    )
}

/// Post a non-terminal collector check-in receipt.
///
/// The receipt declares `report_kind: checkin`: it says "the collector is
/// alive" and nothing else. The backend bumps the server-received freshness
/// marker (and the scan-start marker when a cycle-start one is carried) while
/// preserving the previous terminal report's success evidence, error state, and
/// counters. Terminal reports stay the source of truth for scan outcomes.
///
/// The declaration is honest by construction, not by convention: this function
/// has no access to any scan outcome. It takes a source, a machine id, an
/// optional cycle-start clock, and the server's own width hint; every
/// scan-result field below is a literal absence or zero — census completeness
/// included, which is `None` here so it never reaches the wire at all — and the
/// only evidence
/// it forwards is the manifest witness the backend already accepted from the
/// last completed terminal report. `last_scan_finished_at` stays deliberately
/// absent so a backend that predates `report_kind` still infers the same
/// liveness classification from the shape.
///
/// That absence is also why this body must stay byte-identical to the shape the
/// backend classifies as a check-in (`last_scan_finished_at is None && enabled
/// && last_error_code is None && next_retry_at is None && consecutive_failures
/// == 0`). Replaying the terminal receipt
/// `report_status_with_fresh_relay_token` posts here would silently retire
/// check-in receipts, make the cycle-start in-progress marker dead code, flip
/// manifest preservation to invalidation on every heartbeat while an error is
/// retained, and put a `scan_status` payload behind a `checkin` declaration.
fn report_checkin_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
    receipt_window_days: u64,
) -> Result<()> {
    let receipt_window_days = validated_receipt_window_days(receipt_window_days)?;
    let manifest = match cached_source_manifest(destination_namespace, source) {
        Some(manifest)
            if receipt_window_days > 0
                && snapshot_manifest_window_days(&manifest)? == receipt_window_days =>
        {
            Some(manifest)
        }
        Some(_) => {
            // A cached witness is usable only at the exact current hint width.
            // Withdrawing it prevents later heartbeats from repeating a stale
            // policy shape; the next complete terminal report can rebuild it.
            withdraw_source_manifest(destination_namespace, source);
            None
        }
        None => None,
    };
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: source.api_slug().to_string(),
        machine_id: machine_id.to_string(),
        // Liveness only. Both callers — the independent heartbeat and the
        // cycle-start in-progress marker — reach this one construction site,
        // and neither can supply a scan outcome to contradict the claim.
        report_kind: SnapshotStatusReportKind::Checkin,
        enabled: true,
        disabled_reason: None,
        last_scan_started_at: scan_started_at.map(str::to_string),
        last_scan_finished_at: None,
        last_success_at: None,
        last_error_code: None,
        last_error_message: None,
        last_uploaded_count: 0,
        last_scanned_session_count: 0,
        last_scanned_file_count: 0,
        last_zero_snapshot_confirmed_count: 0,
        last_zero_snapshot_usage_evidence_count: 0,
        last_dropped_usage_record_count: 0,
        last_ownership_incomplete_file_count: 0,
        last_snapshot_unproven_terminal_count: 0,
        last_snapshot_superseded_terminal_count: 0,
        last_backfill_window_days: receipt_window_days,
        first_read_cutoff: None,
        last_backfill_file_limit: 0,
        last_discovered_file_count: 0,
        last_skipped_file_count_due_to_limit: 0,
        last_scan_cap_hit: false,
        last_semantic_noop_count: 0,
        // ABSENT, not `false`. A beat has run no census, and the backend
        // resolves an explicitly declared `false` by lowering the completeness
        // it already accepted while resolving an omitted one by retaining it.
        // Sending `false` here would retract a complete census on every
        // heartbeat; sending `true` would assert one it never measured.
        last_census_complete: None,
        last_symlink_rejected_count: 0,
        last_unreadable_path_count: 0,
        last_oversized_file_count: 0,
        last_disappeared_file_count: 0,
        last_malformed_json_line_count: 0,
        last_invalid_utf8_line_count: 0,
        last_over_line_cap_count: 0,
        last_recognized_usage_drop_count: 0,
        // Census evidence like the loss counters above; a beat measured none.
        last_terminal_ownership_incomplete_file_count: 0,
        last_terminal_zero_snapshot_usage_evidence_count: 0,
        last_terminal_recognized_usage_drop_count: 0,
        last_terminal_dropped_usage_record_count: 0,
        last_terminal_over_line_cap_count: 0,
        last_census_residue_settled: false,
        last_census_residue_index_key_count: 0,
        last_census_residue_archived_rollout_count: 0,
        last_census_pending_file_count: None,
        last_census_block_cause: None,
        consecutive_failures: 0,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(source.parser_version().to_string()),
        // The liveness-only shape carries the manifest deliberately: it is the
        // cheapest cadence the server gets it on, and a check-in that says
        // "alive" while the entity sets disagree is exactly the state the
        // manifest exists to expose.
        manifest,
        // Local control-plane health rides every check-in (public ottto#440):
        // the beat proves uploads are alive, this says whether the socket/XPC
        // plane Setup, Repair, Verify and the Companion use is too. `None`
        // outside a serving daemon process.
        control_plane: crate::control_plane_health::snapshot(),
    };
    small_source_upload(source, || client.report_status(relay_token, &request))?;
    Ok(())
}

fn report_checkin_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let receipt_window_days = current_receipt_window_days(client, &relay_token, source)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    report_checkin_status(
        client,
        &relay_token,
        &destination_namespace,
        source,
        machine_id,
        scan_started_at,
        receipt_window_days,
    )
}

/// Spawn the periodic non-terminal collector check-in heartbeat.
///
/// Terminal receipts track cycle completion, not liveness: the sync loop
/// sleeps a fixed interval AFTER each cycle and scans sources sequentially, so
/// a source's receipt can age by cycle_duration + interval — past the
/// backend's five-minute sources.status freshness promise — while the daemon
/// is healthy and actively uploading. This loop posts a cheap in-progress
/// status per enabled source on its own clock, independent of the sync cycle,
/// so the server-received check-in stays comfortably inside that promise even
/// during a multi-hour backlog drain.
pub fn spawn_collector_checkin_heartbeat() -> Result<()> {
    let phase_offset = local_cadence_phase_offset(COLLECTOR_CHECKIN_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-collector-checkin".to_string())
        .spawn(move || {
            std::thread::sleep(phase_offset);
            loop {
                if let Err(error) = collector_checkin_once() {
                    if !collector_checkin_can_wait_quietly(&error) {
                        eprintln!("collector check-in skipped: {}", safe_error(&error));
                    }
                }
                std::thread::sleep(COLLECTOR_CHECKIN_INTERVAL);
            }
        })
        .context("spawn collector check-in heartbeat")?;
    Ok(())
}

fn collector_checkin_once() -> Result<()> {
    let _stage = StageWindow::begin("unknown", "offpass_collector_checkin");
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let enabled_sources = enabled_snapshot_sources(&device);
    if enabled_sources.is_empty() {
        return Err(anyhow!("registered device has no enabled sources"));
    }
    let client = SnapshotApiClient::new(snapshot_api_base_url()?);
    let mut failed_sources = Vec::new();
    for source in enabled_sources {
        if report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            None,
        )
        .is_err()
        {
            failed_sources.push(source.api_slug());
        }
    }
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "collector check-in failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

fn collector_checkin_can_wait_quietly(error: &anyhow::Error) -> bool {
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}

const SNAPSHOT_SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::Codex,
    SnapshotSource::ClaudeCode,
    SnapshotSource::Pi,
];

pub(crate) fn enabled_snapshot_sources(device: &LocalDeviceBinding) -> Vec<SnapshotSource> {
    enabled_snapshot_sources_in(device, &default_support_dir())
}

/// A source with a removal marker is off at every boundary, whatever its grant.
pub(crate) fn enabled_snapshot_sources_in(
    device: &LocalDeviceBinding,
    support_dir: &Path,
) -> Vec<SnapshotSource> {
    SNAPSHOT_SOURCES
        .into_iter()
        .filter(|source| source_granted(device, *source))
        .filter(|source| source_marker(support_dir, *source).is_none())
        .collect()
}

fn source_granted(device: &LocalDeviceBinding, source: SnapshotSource) -> bool {
    device.sources.iter().any(|slug| slug == source.api_slug())
}

/// The heartbeat's relay-token source: the first enabled one, else the first
/// granted one, so a device with every source paused still hears an ON.
fn heartbeat_source(device: &LocalDeviceBinding) -> Option<SnapshotSource> {
    enabled_snapshot_sources(device)
        .first()
        .copied()
        .or_else(|| {
            SNAPSHOT_SOURCES
                .into_iter()
                .find(|source| source_granted(device, *source))
        })
}

/// Consecutive resume failures per marker. Held across each resume turn, so a
/// concurrent control-thread marker change cannot be overwritten by that
/// turn's completion.
static SOURCE_ERASURE_TURN: Mutex<BTreeMap<PathBuf, u32>> = Mutex::new(BTreeMap::new());

fn source_erasure_turn() -> std::sync::MutexGuard<'static, BTreeMap<PathBuf, u32>> {
    SOURCE_ERASURE_TURN
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Any content but `reconnect` means paused (`pending`; `done` from older
/// builds). Nothing local is erased while a source is off.
fn source_marker_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    snapshot_index_path(support_dir, source)
        .with_file_name(format!("{}.source-disabled", source.api_slug()))
}

/// `None` only when clearly absent. An unreadable marker stays paused.
pub(crate) fn source_marker(support_dir: &Path, source: SnapshotSource) -> Option<String> {
    match std::fs::read_to_string(source_marker_path(support_dir, source)) {
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        marker => Some(marker.unwrap_or_default()),
    }
}

/// This source alone is paused: a marker that is not already resuming.
pub(crate) fn source_paused(support_dir: &Path, source: SnapshotSource) -> bool {
    source_marker(support_dir, source).is_some_and(|marker| marker != "reconnect")
}

fn write_source_marker(path: &Path, state: &str) -> Result<()> {
    ottto_core::write_owner_only_file_atomic(path, state.as_bytes())?;
    sync_progress_parent(path)
}

/// Stops collection now and keeps every local file. Claude's legacy relay
/// closes after the marker is written and the guard is dropped.
pub(crate) fn disable_snapshot_source(support_dir: &Path, source: SnapshotSource) -> Result<()> {
    {
        let _turn = source_erasure_turn();
        write_source_marker(&source_marker_path(support_dir, source), "pending")?;
        reset_collection_health(source);
    }
    if source == SnapshotSource::ClaudeCode {
        crate::otlp_relay::legacy::revoke_now();
    }
    Ok(())
}

/// Applies the web's per-source OFF/ON from a heartbeat reply. Revisions are
/// per device and source; each newer one applies once, recorded in
/// `snapshots/<slug>.source-control` after its marker (a crash between them
/// re-applies the same revision). A missing or another device's record reads
/// as revision 0. OFF pauses like a local disable; ON resumes a paused source
/// and changes nothing for a running one. A block for another device, an
/// unknown source or a malformed entry is ignored.
pub(crate) fn apply_source_control(support_dir: &Path, reply: &serde_json::Value) {
    let block = &reply["source_control"];
    let (Some("source_control:v1"), Some(device_id), Some(entries)) = (
        block["contract"].as_str(),
        block["device_id"].as_str(),
        block["sources"]
            .as_array()
            .filter(|entries| !entries.is_empty()),
    ) else {
        return;
    };
    // Identity, then source: the marker writers take the erasure turn.
    let _binding = crate::control::lock_setup_run_binding();
    let current = ottto_core::FileDeviceStore::default().load().ok().flatten();
    if !current.is_some_and(|current| current.device_id == device_id) {
        return;
    }
    for entry in entries {
        let source = SNAPSHOT_SOURCES
            .into_iter()
            .find(|source| entry["source"].as_str() == Some(source.api_slug()));
        let (Some(source), Some(revision @ 1..), Some(state @ ("enabled" | "disabled"))) = (
            source,
            entry["revision"].as_u64(),
            entry["desired_state"].as_str(),
        ) else {
            continue;
        };
        let record = source_marker_path(support_dir, source)
            .with_file_name(format!("{}.source-control", source.api_slug()));
        let last = std::fs::read(&record)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(|record| record["device_id"] == device_id)
            .and_then(|record| record["revision"].as_u64())
            .unwrap_or(0);
        if revision <= last {
            continue;
        }
        let applied = match state {
            "disabled" => disable_snapshot_source(support_dir, source),
            _ => reconnect_snapshot_source(support_dir, source),
        };
        let body = serde_json::json!({"device_id": device_id, "revision": revision});
        let _ = applied.and_then(|()| write_source_marker(&record, &body.to_string()));
    }
}

/// The explicit way back. A source that was never paused has nothing to resume.
pub(crate) fn reconnect_snapshot_source(support_dir: &Path, source: SnapshotSource) -> Result<()> {
    let _turn = source_erasure_turn();
    match source_marker(support_dir, source) {
        Some(_) => write_source_marker(&source_marker_path(support_dir, source), "reconnect"),
        None => Ok(()),
    }
}

/// A credential generation that drops a source pauses it like an explicit disable.
pub(crate) fn disable_sources_dropped_from_grant(
    support_dir: &Path,
    current: &LocalDeviceBinding,
    next: &LocalDeviceBinding,
) -> Result<()> {
    SNAPSHOT_SOURCES
        .into_iter()
        .filter(|source| source_granted(current, *source) && !source_granted(next, *source))
        .try_for_each(|source| disable_snapshot_source(support_dir, source))
}

/// One attempt per re-enabled source, under the cycle lock. Only the marker
/// goes: the kept index, Tail rows, backfill progress and upload witnesses
/// make its next pass a warm Tail that re-sends nothing already sent (the
/// server keeps data while a source is off). A failure keeps the source
/// paused for the next cycle. Errors can name paths, so only counts are
/// logged.
pub(crate) fn resume_reconnected_sources(support_dir: &Path) {
    for source in SNAPSHOT_SOURCES {
        let mut turn = source_erasure_turn();
        if source_marker(support_dir, source).as_deref() != Some("reconnect") {
            continue;
        }
        let marker = source_marker_path(support_dir, source);
        let resumed = std::fs::remove_file(&marker)
            .map_err(anyhow::Error::from)
            .and_then(|()| {
                // The source is eligible now, even if the later directory sync fails.
                // A prepare hint in flight at pause may have re-armed its pulse.
                reset_collection_health(source);
                sync_progress_parent(&marker)
            });
        let failures = turn.entry(marker).or_default();
        *failures = if resumed.is_ok() { 0 } else { *failures + 1 };
        if *failures > 3 {
            crate::snapshots::state_v2::source_erasure_alarm(*failures);
        }
    }
}

pub(crate) fn snapshot_api_base_url() -> Result<String> {
    snapshot_api_base_url_from(
        FileConnectionStore::default().load(),
        std::env::var("OTTTO_API_BASE_URL").ok(),
    )
}
fn snapshot_api_base_url_from(
    connection: Result<Option<ottto_core::LocalConnectionBinding>>,
    env_value: Option<String>,
) -> Result<String> {
    // Read/parse/cap errors are not an absent binding: never redirect secrets
    // to the environment/default destination after a persisted binding fails.
    let connection = crate::local_resource_diagnostics::connection_binding_read(connection)?;
    Ok(normalize_api_base_url(
        connection.map(|binding| binding.api_base_url),
        env_value,
    ))
}

fn normalize_api_base_url(connection_value: Option<String>, env_value: Option<String>) -> String {
    connection_value
        .or(env_value)
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

pub(crate) fn snapshot_machine_id(device: &LocalDeviceBinding) -> Result<Option<String>> {
    if let Some(machine_id) = device.machine_id.as_ref().filter(|value| !value.is_empty()) {
        return Ok(Some(machine_id.clone()));
    }
    Ok(FileMachineStore::default()
        .load()?
        .map(|machine| machine.machine_id)
        .filter(|value| !value.is_empty()))
}

fn snapshot_upload_context_fingerprint(
    upload_policy: SnapshotUploadPolicy,
    attribution_checkpoint_namespace: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:snapshot-upload-context:v1\0");
    digest.update(serde_json::to_vec(&upload_policy).expect("upload policy is serializable"));
    digest.update(b"\0");
    digest.update(
        attribution_checkpoint_namespace
            .unwrap_or("none")
            .as_bytes(),
    );
    format!("{:x}", digest.finalize())
}

/// Evidence probe only: decoding, migration and custody checks remain with the
/// locked source loaders. Never inspect a different destination for ownership.
pub(crate) fn snapshot_namespace_has_store(support: &Path, namespace: &str) -> Result<bool> {
    anyhow::ensure!(
        crate::hex::is_sha256_lower(namespace),
        "invalid snapshot namespace"
    );
    let dir = support.join("snapshots/destinations").join(namespace);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match std::fs::symlink_metadata(&dir) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                _ => anyhow::bail!("uncertain snapshot namespace directory"),
            };
        }
        Err(_) => anyhow::bail!("inspect snapshot namespace"),
    };
    anyhow::ensure!(
        std::fs::symlink_metadata(&dir)?.is_dir(),
        "uncertain snapshot namespace directory"
    );
    let mut present = false;
    for entry in entries {
        let entry = entry.context("inspect snapshot namespace entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let relevant = [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ]
        .iter()
        .any(|source| name.starts_with(&format!("{}-scan-index", source.api_slug())));
        if !relevant {
            continue;
        }
        let sharded = name.ends_with(".json.shards") || name.ends_with(".json.v1-readonly.shards");
        let checkpoint = [
            ".v1-readonly.shards",
            ".shards",
            ".v1-readonly",
            ".v2-ack-receipt",
            ".v2.sqlite.import",
            ".v2.sqlite",
        ]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
        if checkpoint.ends_with(".json")
            && !checkpoint.contains("-upload-progress")
            && !checkpoint.contains(".tmp")
            && !checkpoint.contains(".backup")
        {
            let metadata = std::fs::symlink_metadata(entry.path())
                .context("inspect snapshot namespace custody")?;
            anyhow::ensure!(
                (sharded && metadata.is_dir()) || (!sharded && metadata.is_file()),
                "uncertain snapshot namespace custody"
            );
            present = true;
        }
    }
    Ok(present)
}

/// One destination-scoped index is shared by every privacy policy. A policy
/// change applies to bodies acquired from then on; exact entity proofs retain
/// their original upload context.
fn snapshot_index_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("snapshots")
        .join(format!("{}-scan-index.json", source.api_slug()))
}

fn legacy_policy_scoped_snapshot_index_path(
    support_dir: &Path,
    source: SnapshotSource,
    upload_policy: SnapshotUploadPolicy,
    attribution_checkpoint_namespace: Option<&str>,
) -> PathBuf {
    let mut suffixes: Vec<String> = Vec::new();
    if !upload_policy.session_titles_enabled {
        suffixes.push("no-titles".to_string());
    }
    if !upload_policy.workspace_labels_enabled {
        suffixes.push("no-labels".to_string());
    }
    // Artifacts are opt-in (default off), so the suffix marks the ENABLED state.
    // Enabling switches to the fresh `-artifacts` index, forcing a full re-scan
    // so existing/closed sessions retroactively gain artifacts. (Disabling
    // reverts to the base index; unchanged transcripts are not re-scanned, so
    // artifacts already uploaded persist on the backend until the file changes
    // — consistent with the titles/labels suffix behavior.)
    if upload_policy.session_artifacts_enabled {
        suffixes.push("artifacts".to_string());
    }
    // Attribution is opt-in. A separate index makes a later enablement revisit
    // unchanged transcripts instead of waiting for their next filesystem edit.
    // The namespace is key-epoch-only: scheduler inventory changes affect
    // sessions parsed from that point forward and require an explicit replay
    // for history. They must not silently invalidate every local checkpoint.
    if upload_policy.session_attribution_enabled {
        let namespace = attribution_checkpoint_namespace
            .map(str::to_string)
            .unwrap_or_else(|| "pending".to_string());
        suffixes.push(format!("attribution-{namespace}"));
    }
    // The capability changes only wire-safe display metadata, but it still
    // needs a fresh index so unchanged historical transcripts are revisited
    // once after backend support becomes available.
    if upload_policy.session_attribution_labels_enabled {
        suffixes.push("attribution-labels".to_string());
    }
    let policy_suffix = if suffixes.is_empty() {
        String::new()
    } else {
        format!("-{}", suffixes.join("-"))
    };
    support_dir.join("snapshots").join(format!(
        "{}-scan-index{}.json",
        source.api_slug(),
        policy_suffix
    ))
}

fn adopt_legacy_checkpoint_file(legacy_path: &Path, stable_path: &Path) -> Result<()> {
    if legacy_path == stable_path || stable_path.exists() || !legacy_path.exists() {
        return Ok(());
    }
    if let Some(parent) = stable_path.parent() {
        std::fs::create_dir_all(parent).context("create stable checkpoint directory")?;
    }
    // Adoption targets the same lock sibling used by scan-index/progress
    // load/save. Without it, two overlapping upgraded daemons can both observe
    // an absent stable path and a late legacy copy can overwrite the winner's
    // already-advanced CAS generation. Recheck after acquiring because another
    // process may have completed adoption between the optimistic check above
    // and this non-blocking lock attempt.
    let _lock = SnapshotProgressLock::acquire(stable_path)?;
    if stable_path.exists() || !legacy_path.exists() {
        return Ok(());
    }
    let temp_path = stable_path.with_extension(format!("json.{}.migrate", std::process::id()));
    let migration = (|| -> Result<()> {
        let mut source =
            std::fs::File::open(legacy_path).context("open legacy checkpoint for migration")?;
        let mut destination =
            std::fs::File::create(&temp_path).context("create stable checkpoint migration temp")?;
        std::io::copy(&mut source, &mut destination)
            .context("copy legacy checkpoint into stable namespace")?;
        destination
            .sync_all()
            .context("sync stable checkpoint migration temp")?;
        std::fs::rename(&temp_path, stable_path).context("publish stable checkpoint migration")?;
        if let Some(parent) = stable_path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("sync stable checkpoint migration directory")?;
        }
        Ok(())
    })();
    if migration.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    migration
}

/// Test access to a source's progress path under its progress owner.
#[cfg(test)]
pub(crate) fn with_state_v2_progress_lock<T>(
    index_path: &Path,
    action: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    with_state_v2_progress_owner(index_path, None, |_, path| action(path))
}

/// A borrowed owner cannot outlive its flock. Verify its path before reusing it;
/// partial settlement retains this same owner from subset CAS through COMMIT.
pub(crate) fn with_state_v2_progress_owner<T>(
    index_path: &Path,
    owner: Option<&SnapshotProgressLock>,
    action: impl FnOnce(&SnapshotProgressLock, &Path) -> Result<T>,
) -> Result<T> {
    let path = snapshot_upload_progress_path(index_path);
    match owner {
        Some(owner) => {
            anyhow::ensure!(
                owner.path.as_deref() == Some(path.as_path()),
                "state_v2_progress_owner_path"
            );
            action(owner, &path)
        }
        None => {
            let owner = SnapshotProgressLock::acquire(&path)?.for_v2(&path);
            action(&owner, &path)
        }
    }
}

/// The removed upload-progress bound, (64 MiB - 16 KiB) / 6 bytes.
#[cfg(test)]
pub(crate) const OLD_PROGRESS_BOUND_FOR_TEST: usize = 11_182_080;

#[cfg(test)]
pub(crate) fn validate_state_v2_original_progress(bytes: &[u8], namespace: &str) -> Result<()> {
    // Unknown payload slots are carried byte-exactly. Decode only the owner
    // headers; Serde rejects duplicate headers and consumes the entire object.
    #[derive(Deserialize)]
    struct Owner {
        schema_version: u16,
        destination_namespace_hash: String,
        #[serde(default)]
        generation: u64,
    }
    let owner: Owner = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        owner.schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            && is_snapshot_fingerprint(namespace)
            && owner.destination_namespace_hash == namespace
            && owner.generation < u64::MAX,
        "state_v2_original_progress_owner"
    );
    Ok(())
}

fn snapshot_upload_progress_path(index_path: &Path) -> PathBuf {
    let stem = index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    index_path.with_file_name(format!("{stem}-upload-progress.json"))
}

fn snapshot_v2_index_path(v1_index_path: &Path) -> PathBuf {
    let stem = v1_index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    v1_index_path.with_file_name(format!("{stem}-v2.json"))
}

fn snapshot_v3_index_path(destination_index_path: &Path) -> PathBuf {
    let stem = destination_index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    destination_index_path.with_file_name(format!("{stem}-v3.json"))
}

fn snapshot_destination_scoped_index_path(
    policy_index_path: &Path,
    destination_namespace_hash: &str,
) -> PathBuf {
    let parent = policy_index_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = policy_index_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("snapshot-scan-index.json"));
    parent
        .join("destinations")
        .join(destination_namespace_hash)
        .join(file_name)
}

/// Namespaces carried by the credentials `load_snapshot_device_credentials`
/// read, keyed by device id and sha256(secret): an entry only ever applies to
/// its exact credential, so resolving needs no second `device.json` read.
static CARRIED_NAMESPACES: Mutex<BTreeMap<(String, String), String>> = Mutex::new(BTreeMap::new());

/// Called by the credential loader on every load. It overwrites this exact
/// credential's entry with what it resolves now: the alias only when its
/// commitment is sha256(secret), else the raw hash. A reload after a legacy
/// writer stripped the alias therefore resolves raw, as a fresh process does.
pub(crate) fn carry_snapshot_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
    alias: Option<&ottto_core::SnapshotNamespaceAlias>,
) {
    let key = (
        device.device_id.clone(),
        crate::control::secret_sha256(device_secret),
    );
    let namespace = snapshot_destination_namespace(device, device_secret, alias);
    let mut carried = CARRIED_NAMESPACES.lock().unwrap_or_else(|p| p.into_inner());
    carried.insert(key, namespace);
}

/// Test-only: forget what earlier loads carried for these devices.
#[cfg(test)]
pub(crate) fn forget_carried_namespaces_for_test(device_ids: &[&str]) {
    let mut carried = CARRIED_NAMESPACES.lock().unwrap_or_else(|p| p.into_inner());
    carried.retain(|(device_id, _), _| !device_ids.contains(&device_id.as_str()));
}

/// Destination namespace of a loaded relay credential.
pub(crate) fn snapshot_upload_destination_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> String {
    let key = (
        device.device_id.clone(),
        crate::control::secret_sha256(device_secret),
    );
    let carried = CARRIED_NAMESPACES.lock().unwrap_or_else(|p| p.into_inner());
    match carried.get(&key) {
        Some(namespace) => namespace.clone(),
        None => snapshot_destination_namespace(device, device_secret, None),
    }
}

/// Test-only: `links` same-account re-logins from a credential resolving to
/// `canonical`. Each successor carries the namespace as promotion writes it
/// and the loader reads it; returns what the last successor resolves to.
#[cfg(test)]
pub(crate) fn relogin_namespace(canonical: &str, links: usize) -> String {
    let mut namespace = canonical.to_string();
    for link in 1..=links {
        let device = LocalDeviceBinding {
            device_id: format!("relogin-{canonical}-{link}"),
            machine_id: Some("otm_test".into()),
            sources: Vec::new(),
        };
        let secret = format!("relogin-secret-{link}");
        let alias = ottto_core::SnapshotNamespaceAlias {
            namespace,
            secret_commitment_sha256: crate::control::secret_sha256(&secret),
        };
        carry_snapshot_namespace(&device, &secret, Some(&alias));
        namespace = snapshot_upload_destination_namespace(&device, &secret);
        assert_ne!(
            namespace,
            snapshot_destination_namespace(&device, &secret, None)
        );
    }
    namespace
}

/// The one namespace derivation: a confirmed same-account successor's alias
/// while the secret matches its commitment, else hash(device id, secret).
pub(crate) fn snapshot_destination_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
    alias: Option<&ottto_core::SnapshotNamespaceAlias>,
) -> String {
    if let Some(alias) = alias.filter(|alias| {
        crate::hex::is_sha256_lower(&alias.namespace)
            && crate::control::secret_commitment_matches(
                &alias.secret_commitment_sha256,
                device_secret,
            )
    }) {
        return alias.namespace.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:snapshot-delivery-destination:relay-device:v1\0");
    hasher.update(device.device_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn ensure_snapshot_scan_authority(
    expected_device: &LocalDeviceBinding,
    source: SnapshotSource,
    client: &SnapshotApiClient,
    expected_account: &[u8; 32],
    daemon: &LocalDaemon,
) -> Result<()> {
    let rejected = || {
        anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "source authority changed during owned scan",
        })
    };
    let current = crate::local_resource_diagnostics::credential_file_read(
        ottto_core::FileDeviceStore::default().load(),
    )
    .map_err(|_| rejected())?
    .ok_or_else(rejected)?;
    let account = daemon
        .snapshot_scan_account_witness()
        .map_err(|_| rejected())?;
    validate_snapshot_scan_authority(
        expected_device,
        &current,
        source,
        client.matches_api_base(&snapshot_api_base_url().map_err(|_| rejected())?),
        expected_account,
        &account,
    )
}
fn validate_snapshot_scan_authority(
    expected_device: &LocalDeviceBinding,
    current: &LocalDeviceBinding,
    source: SnapshotSource,
    endpoint_matches: bool,
    expected_account: &[u8; 32],
    current_account: &[u8; 32],
) -> Result<()> {
    if current.device_id != expected_device.device_id
        || current.machine_id != expected_device.machine_id
        || !enabled_snapshot_sources(current).contains(&source)
        || !endpoint_matches
        || expected_account != current_account
    {
        return Err(anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "source authority changed during owned scan",
        }));
    }
    Ok(())
}

fn ensure_snapshot_destination_current(expected_namespace_hash: &str) -> Result<()> {
    let (current_device, current_device_secret) =
        load_snapshot_device_credentials().map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "revalidate relay destination",
            })
        })?;
    validate_snapshot_destination(
        expected_namespace_hash,
        &current_device,
        &current_device_secret,
    )
}

fn validate_snapshot_destination(
    expected_namespace_hash: &str,
    current_device: &LocalDeviceBinding,
    current_device_secret: &str,
) -> Result<()> {
    if snapshot_upload_destination_namespace(current_device, current_device_secret)
        != expected_namespace_hash
    {
        return Err(anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "relay destination changed during snapshot sync",
        }));
    }
    Ok(())
}

pub(crate) fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

fn current_rfc3339() -> String {
    Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn rfc3339_after_minutes(minutes: i64) -> Option<String> {
    OffsetDateTime::now_utc()
        .checked_add(TimeDuration::minutes(minutes))
        .and_then(|value| value.format(&Rfc3339).ok())
}

/// Bounded, redacted cause for the catch-all snapshot upload failure log.
///
/// The catch-all arm has no status code of its own, so this reconstructs the
/// most specific failure shape still present in the error chain. Everything it
/// emits is either a typed redacted diagnostic (endpoint + status family, never
/// a URL or token) or one of this module's own compile-time reason literals —
/// never raw error text, which can carry file paths.
fn upload_failure_diagnostic(error: &anyhow::Error) -> String {
    if let Some(settlement) = error.downcast_ref::<ack_retention::AckSettlementRequired>() {
        return settlement.to_string();
    }
    if let Some(diagnostics) = error.downcast_ref::<UploadFailureDiagnostics>() {
        return diagnostics.safe_message();
    }
    if let Some(rejected) = error.downcast_ref::<BatchRejected>() {
        return rejected.to_string();
    }
    if let Some(rejected) = error.downcast_ref::<BatchAuthorizationRejected>() {
        return format!(
            "endpoint=snapshot_batch, status={}, kind=authorization_rejected",
            rejected.status,
        );
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
        return format!(
            "endpoint=snapshot_batch, kind=daemon_contract_preflight, detail={}",
            rejected.reason,
        );
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotBatchResponseRejected>() {
        return format!(
            "endpoint=snapshot_batch, kind=response_count_mismatch, expected={}, accepted={}",
            rejected.expected, rejected.accepted,
        );
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotLocalStateRejected>() {
        return format!("kind=local_state, operation={}", rejected.operation);
    }
    if let Some(rejected) = error.downcast_ref::<SnapshotAckRejected>() {
        return format!("kind=backend_response, detail={}", rejected.reason);
    }
    // This module's own upload-loop reasons. Matching on the literals keeps the
    // emitted text a fixed vocabulary rather than arbitrary chain content.
    let text = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    for reason in [
        "snapshot adaptive upload attempt limit reached",
        "snapshot adaptive upload split limit reached",
        "snapshot response uses an unsupported entity ACK contract",
        "local snapshot preflight index was out of bounds",
    ] {
        if text.contains(reason) {
            return format!("kind=uploader_guard, detail={reason}");
        }
    }
    "kind=unclassified (no typed diagnostic in the error chain)".to_string()
}

pub(crate) fn safe_error(error: &anyhow::Error) -> String {
    // A state v2 hold is a fixed content-free code: no text, no paths.
    if let Some(hold) = error.downcast_ref::<crate::snapshots::state_v2::Hold>() {
        return format!("local state store held: {hold}");
    }
    if let Some(failed) = error.downcast_ref::<SourcesFailed>() {
        return failed.to_string();
    }
    if let Some(settlement) = error.downcast_ref::<ack_retention::AckSettlementRequired>() {
        return settlement.to_string();
    }
    if let Some(diagnostics) = error.downcast_ref::<UploadFailureDiagnostics>() {
        return diagnostics.safe_message();
    }
    if error.downcast_ref::<BatchRejected>().is_some() {
        return "local snapshot payload validation failed".to_string();
    }
    if error.downcast_ref::<SnapshotEntityDeferred>().is_some() {
        return "local snapshot upload deferred by unsettled entities".to_string();
    }
    if error.downcast_ref::<LocalHealthRefreshHeld>().is_some() {
        return "local health upload held after setup-run refresh failed".to_string();
    }
    match snapshot_upload_error_class(error) {
        Some(SnapshotUploadErrorClass::LocalState) => {
            return "local snapshot state failed".to_string();
        }
        Some(SnapshotUploadErrorClass::BackendResponse) => {
            return "backend snapshot response was invalid".to_string();
        }
        None => {}
    }
    // Scan the whole context chain, not just the outermost message, so a known
    // failure phrase wrapped under another context still classifies instead of
    // collapsing to the undiagnosable bare "sync failed".
    let text = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    if text.contains("connection binding") {
        "connection binding is unavailable or invalid; reconnect this device".to_string()
    } else if text.contains("relay device") {
        "relay device credentials are unavailable".to_string()
    } else if text.contains("machine identity") {
        "machine identity is unavailable".to_string()
    } else if text.contains("issue relay token failed") {
        "relay token request failed".to_string()
    } else if text.contains("backend rejected local health projection") {
        "local health projection rejected".to_string()
    } else if text.contains("backend rejected local health authorization") {
        "local health authorization rejected".to_string()
    } else if text.contains("get activity hint failed") {
        "activity hint request failed".to_string()
    } else if text.contains("upload agent status failed")
        || text.contains("agent status upload failed")
    {
        "agent status upload failed".to_string()
    } else if text.contains("scan local snapshots") {
        "local snapshot scan failed".to_string()
    } else if text.contains("daemon/backend contract preflight")
        || text.contains("backend rejected snapshot batch payload")
    {
        "local snapshot payload validation failed".to_string()
    } else if text.contains("snapshot adaptive upload attempt limit reached")
        || text.contains("snapshot adaptive upload split limit reached")
    {
        // Distinct from a network failure: the page reached the backend and the
        // uploader exhausted its bounded poison-isolation budget. Collapsing
        // this into the generic upload message hid a whole failure family.
        "local snapshot upload isolation limit reached".to_string()
    } else if text.contains("snapshot response uses an unsupported entity ACK contract") {
        "backend snapshot response was invalid".to_string()
    } else if text.contains("upload local snapshots")
        || text.contains("upload snapshot batch failed")
    {
        "local snapshot upload failed".to_string()
    } else if text.contains("report snapshot status failed") {
        "local collector status upload failed".to_string()
    } else if text.contains("mcp inventory")
        || text.contains("mcp handshake")
        || text.contains("mcp server")
    {
        "mcp inventory sync failed".to_string()
    } else if text.contains("backend rejected context footprint") {
        "context footprint upload rejected".to_string()
    } else if text.contains("context footprint") {
        "context footprint upload failed".to_string()
    } else if text.contains("response failed") {
        // "parse <endpoint> response failed" family: the request went through
        // but the backend reply didn't decode.
        "backend response was invalid".to_string()
    } else if text.contains(crate::snapshot_roots::CLAUDE_ROOTS_CHANGED_DURING_SCAN) {
        crate::snapshot_roots::CLAUDE_ROOTS_CHANGED_DURING_SCAN.to_string()
    } else if let Some(step) = PARTIAL_CHECKPOINT_FAILURES
        .into_iter()
        .find(|step| text.contains(step))
    {
        step.to_string()
    } else if let Some(check) = crate::snapshots::CODEX_JOIN_VALIDATION_FAILURES
        .into_iter()
        .find(|check| text.contains(check))
    {
        check.to_string()
    } else {
        "sync failed".to_string()
    }
}

#[cfg(test)]
pub(crate) use tests::codex_archive_tests::{
    archive_upload_checkpoint, assert_archive_debt_preserves_replay_progress,
    codex_transition_acked_route, codex_transition_cold_batches,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "snapshot_sync/h357_ack_tests.rs"]
mod h357_ack_tests;

#[cfg(test)]
#[path = "snapshot_sync/tail_ack_ledger.rs"]
pub(crate) mod tail_ack_ledger;

#[cfg(test)]
#[path = "snapshot_sync/usage_decrease_hold_tests.rs"]
mod usage_decrease_hold_tests;

#[cfg(test)]
#[path = "snapshot_sync/head_conflict_answer_tests.rs"]
pub(crate) mod head_conflict_answer_tests;

#[cfg(test)]
#[path = "snapshot_sync/change_reason_tests.rs"]
mod change_reason_tests;

#[cfg(test)]
#[path = "snapshot_sync/progress_unchanged_save_tests.rs"]
mod progress_unchanged_save_tests;

#[cfg(test)]
#[path = "snapshot_sync/head_conflict_released_progress_fixture.rs"]
mod head_conflict_released_progress_fixture;

#[cfg(test)]
mod codex_sidecar_reuse_tests;

#[cfg(all(test, unix))]
pub(crate) mod resource_schedule;
