use self::continuation::PlatformGates;
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
// A short, explicitly transient batch failure is resent in place rather than
// abandoning the page and marking the bounded sweep unsettled: a 429/503 whose
// Retry-After is at most 5 s (cursor allocation and shared-lock timeouts send
// 1 s) or a fast 500/502. The wait holds the sync lock, so each source page
// gets at most two resends and 10 s of waiting, shared by its cache-head
// bootstrap stages and its main upload. A failure that took 15 s or longer is
// overload and is never resent; the identity deferral, recognized by its code,
// keeps its backoff whatever its Retry-After.
const SNAPSHOT_INPLACE_RETRY_LIMIT: usize = 2;
const SNAPSHOT_INPLACE_RETRY_MAX_WAIT: Duration = Duration::from_secs(5);
const SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET: Duration = Duration::from_secs(10);
const SNAPSHOT_INPLACE_RETRY_FAST_FAILURE: Duration = Duration::from_secs(15);
const SNAPSHOT_INPLACE_RETRY_SERVER_ERROR_WAIT: Duration = Duration::from_secs(2);
const SNAPSHOT_INPLACE_RETRY_MIN_WAIT: Duration = Duration::from_millis(250);
// A pre-ledger checkpoint with ambiguous settlement is re-entered through the
// existing entity-ACK upload machine. Arm at most one normal 50-entity page per
// five-minute source cycle; the scan-index cursor and quarantine map resume the
// remaining identities across restarts.
const LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE: usize = SNAPSHOT_BATCH_LIMIT;
const SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION: u16 = 3;
static ONE_SHOT_SYNC_IN_FLIGHT: OnceLock<Mutex<bool>> = OnceLock::new();
static SNAPSHOT_SYNC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
pub(crate) fn status_test_scan_lock() -> std::sync::MutexGuard<'static, ()> {
    SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Bootstrap a fresh source page's cache heads under its own in-place resend
/// budget.
#[cfg(test)]
fn bootstrap_cache_heads(
    probes: &[SnapshotItem],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    upload: impl FnMut(&[&SnapshotItem], bool) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    persist: impl FnMut(&mut SnapshotUploadProgress) -> Result<()>,
) -> Result<usize> {
    bootstrap_cache_heads_with_budget(
        probes,
        poison_scope,
        progress,
        &mut InplaceRetryBudget::default(),
        upload,
        persist,
    )
}

/// Bootstrap only through existing ordinary authority followed by an exact
/// CAS repeat. Both settlements share the normal atomic ACK progress seam and
/// the source page's in-place resend budget.
fn bootstrap_cache_heads_with_budget(
    probes: &[SnapshotItem],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    inplace_retry: &mut InplaceRetryBudget,
    mut upload: impl FnMut(
        &[&SnapshotItem],
        bool,
    ) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    mut persist: impl FnMut(&mut SnapshotUploadProgress) -> Result<()>,
) -> Result<usize> {
    let leased = progress.active_reason_reoffers.clone();
    // A catch-up probe must not precede any ordinary full body in this pass,
    // including one whose own probe is sent in the first bootstrap stage.
    progress.context_resend.bootstrap_blocks_catchup =
        progress.context_resend.has_pending_ordinary();
    let mut shed = false;
    let result = (|| -> Result<usize> {
        let mut deferred = 0usize;
        // A headless patched body reaches here only when head CAS is optional
        // and no legacy reconciliation is pending; otherwise prepare strips it.
        for enforce_head_cas in [false, true] {
            // A prior ordinary body ACK has no head proof. Force the exact probe
            // even when delivery of these bytes was previously acknowledged.
            if enforce_head_cas {
                // Refusal must leave the in-memory ledger equal to its saved
                // checkpoint so partial settlement can commit retirement proof.
                progress.admit_ack_reoffers(probes)?;
                for probe in probes {
                    progress
                        .accepted_fingerprints
                        .remove(&probe.snapshot_fingerprint);
                    progress
                        .accepted_body_witnesses
                        .remove(&probe.snapshot_fingerprint);
                }
            }
            let mut accepted = 0;
            let outcome = upload_resumable_batches_with_literal_families(
                probes,
                poison_scope,
                progress,
                &mut accepted,
                |item| item.snapshot_fingerprint.as_str(),
                snapshot_upload_body_witness,
                |item| Some(item.source_session_id.as_str()),
                |_| 0,
                |_| None,
                inplace_retry,
                |items| upload(items, enforce_head_cas),
                |progress| persist(progress),
            )?;
            match outcome {
                ResumableUploadResult::Completed | ResumableUploadResult::Rejected { .. } => {}
                // The partitioned uploader persisted each conflicting probe's exact
                // body quarantine. Carry that hold into the normal upload rather
                // than discarding every unrelated file's progress. An isolated
                // refusal is held alone and does not defer the pass.
                ResumableUploadResult::Deferred { count, isolated } => {
                    deferred = deferred.saturating_add(count.saturating_sub(isolated));
                }
                outcome => {
                    shed = matches!(outcome, ResumableUploadResult::Shed { .. });
                    return Err(anyhow::Error::new(SnapshotAckRejected {
                        reason: "cache head probe did not settle exact predecessor evidence",
                    }));
                }
            }
        }
        Ok(deferred)
    })();
    progress.context_resend.bootstrap_blocks_catchup = false;
    if result.is_err() {
        progress.finish_reason_reoffers(&leased, shed, poison_scope);
    }
    result
}

fn cache_head_probe(item: &SnapshotItem) -> SnapshotItem {
    let mut probe = item.clone();
    probe.cache_observations = None;
    probe.cache_observations_state = None;
    probe.cache_conflict_answer = None;
    probe
}

/// Exact non-acceptance of these bytes, using the uploader's existing hold
/// predicate. An accepted body without a head is not a quarantine certificate.
fn cache_head_probe_held(progress: &SnapshotUploadProgress, probe: &SnapshotItem) -> bool {
    let fingerprint = &probe.snapshot_fingerprint;
    let witness = snapshot_upload_body_witness(probe);
    if progress.active_reason_reoffers.get(fingerprint) == Some(&witness) {
        return false;
    }
    progress.refused_body(fingerprint, &witness)
        || (!progress.active_quarantine_retries.contains(fingerprint)
            && progress
                .quarantined_fingerprints
                .get(fingerprint)
                .is_some_and(|record| {
                    record.upload_body_witness.as_deref() == Some(witness.as_str())
                }))
}

fn held_cache_head_probe(
    progress: &SnapshotUploadProgress,
    item: &SnapshotItem,
) -> Option<SnapshotItem> {
    let probe = cache_head_probe(item);
    (item.cache_observations.is_some()
        && item.cache_base_head_etag.is_none()
        && cache_head_probe_held(progress, &probe))
    .then_some(probe)
}

/// Every headless patched body takes the probe stages first, so its patch
/// is never sent without a predecessor token.
fn apply_bootstrapped_cache_heads(
    source: &str,
    snapshots: &mut [SnapshotItem],
    progress: &SnapshotUploadProgress,
) -> Result<Vec<(String, String, String)>> {
    let mut held = Vec::new();
    for snapshot in snapshots {
        if snapshot.cache_observations.is_none() {
            continue;
        }
        if snapshot.cache_base_head_etag.is_none() {
            // Check the hold before looking up the head: another entity for
            // the same session may have acquired one, but that cannot release
            // this exact body's quarantine or bypass its bounded retry.
            if let Some(probe) = held_cache_head_probe(progress, snapshot) {
                // No cache patch or accepted head is invented. The normal
                // uploader sees the exact held probe and keeps its quarantine;
                // healthy siblings retain their own independent settlement.
                crate::local_resource_diagnostics::traversal_point(
                    "held_cache_head_probe",
                    source,
                    &serde_json::json!({"fingerprint_hash8": SessionHash::of(&probe.snapshot_fingerprint).to_string(),
                        "body_witness_hash8": &snapshot_upload_body_witness(&probe)[..8],
                        "saved_head_present": progress.accepted_cache_heads.contains_key(&cache_session_key(&probe.source_session_id))}),
                );
                held.push((
                    snapshot.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(snapshot),
                    snapshot_upload_body_witness(&probe),
                ));
                *snapshot = probe;
                continue;
            }
        }
        snapshot.cache_base_head_etag = progress
            .accepted_cache_heads
            .get(&cache_session_key(&snapshot.source_session_id))
            .cloned();
        if snapshot.cache_base_head_etag.is_none() {
            return Err(anyhow::Error::new(SnapshotAckRejected {
                reason: "cache head probe lacks accepted predecessor token",
            }));
        }
    }
    Ok(held)
}

fn with_bootstrap_deferred(
    result: ResumableUploadResult,
    deferred: usize,
) -> ResumableUploadResult {
    if deferred == 0 {
        return result;
    }
    match result {
        ResumableUploadResult::Completed | ResumableUploadResult::Rejected { .. } => {
            ResumableUploadResult::Deferred {
                count: deferred,
                isolated: 0,
            }
        }
        ResumableUploadResult::Deferred { count, isolated } => ResumableUploadResult::Deferred {
            count: count.saturating_add(deferred),
            isolated,
        },
        other => other,
    }
}

/// Carry a newer refused-body conflict even when the frozen upload delta is
/// empty. New conflicts were already counted by bootstrap/main upload; this
/// adds only older, untransmitted debt from the current source universe.
/// A later traversal's proven unchanged cooldown is counted and disclosed,
/// but leaves settlement to the normal clean-traversal boundary.
fn with_retained_refusal_conflicts(
    result: ResumableUploadResult,
    index: &ScanIndex,
    progress: &SnapshotUploadProgress,
    reoffer_now: u64,
) -> ResumableUploadResult {
    let retained = index
        .current_snapshot_fingerprint_refs()
        .filter(|fingerprint| {
            !progress.attempted_reason_reoffers.contains(*fingerprint)
                && progress
                    .permanent_rejections
                    .get(*fingerprint)
                    .is_some_and(|refusal| {
                        // The I/O view also holds due records waiting for
                        // budget. Only a still-future reservation grants the
                        // settlement exception; at D that debt blocks again.
                        !(index.reason_reoffer_conflict_is_deferred(
                            fingerprint,
                            &refusal.body_witness,
                        ) && refusal
                            .reoffer
                            .and_then(reason_reoffer::RefusalReoffer::retry_after)
                            .is_some_and(|deadline| deadline > reoffer_now))
                            && progress
                                .quarantined_fingerprints
                                .get(*fingerprint)
                                .is_some_and(|record| {
                                    record.disposition
                                        == SnapshotQuarantineDisposition::RetryPending
                                        && record.upload_body_witness.as_deref()
                                            == Some(refusal.body_witness.as_str())
                                })
                    })
        })
        .collect::<BTreeSet<_>>();
    with_bootstrap_deferred(result, retained.len())
}

/// Exercise the real retained-conflict settlement boundary from Codex scan
/// fixtures, without replacing its cooldown decision with a test predicate.
#[cfg(test)]
pub(crate) fn retained_refusal_settles_for_test(
    index: &ScanIndex,
    fingerprint: &str,
    record: SnapshotQuarantineRecord,
    body: &str,
    now: u64,
    deadline: u64,
) -> bool {
    let mut progress =
        SnapshotUploadProgress::new("synthetic-codex-cooldown".into(), record.witness.clone());
    progress
        .quarantined_fingerprints
        .insert(fingerprint.into(), record);
    progress.permanent_rejections.insert(
        fingerprint.into(),
        PermanentSnapshotRejection {
            body_witness: body.into(),
            exposure: None,
            revisions: BTreeMap::new(),
            reason: crate::upload_receipts::RejectedUsageReason::Other,
            reoffer: Some(reason_reoffer::RefusalReoffer::OriginalPair {
                retry_after_unix_seconds: deadline,
            }),
        },
    );
    matches!(
        with_retained_refusal_conflicts(ResumableUploadResult::Completed, index, &progress, now),
        ResumableUploadResult::Completed
    )
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

#[derive(Debug)]
struct DeferredCacheHeadIdentity {
    source_file_fingerprint: Option<String>,
    snapshot_fingerprint: String,
    session_key: String,
}

#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
fn capture_deferred_cache_head_identities(
    source: SnapshotSource,
    items: &[SnapshotItem],
    progress: &SnapshotUploadProgress,
    enabled: bool,
    head_cas_required: bool,
    legacy_pending: &BTreeSet<String>,
    active_legacy: &BTreeSet<String>,
    disposition: &crate::snapshots::ClaudeUsageAuthorityDisposition,
) -> Vec<DeferredCacheHeadIdentity> {
    if !enabled {
        return Vec::new();
    }
    let held = disposition.quarantined_fingerprints(items);
    items
        .iter()
        .filter_map(|item| {
            if item.cache_observations.is_none() || held.contains(&item.snapshot_fingerprint) {
                return None;
            }
            // Use the same public semantic primitives as finalization after policy.
            let fingerprint = crate::snapshots::snapshot_fingerprint_from_component_hashes(
                source,
                &item.source_session_id,
                &crate::snapshots::snapshot_semantic_component_hashes(source, item),
            );
            let legacy = legacy_pending.contains(&fingerprint);
            if legacy && !active_legacy.contains(&fingerprint) {
                return None;
            }
            let session_key = cache_session_key(&item.source_session_id);
            ((head_cas_required || legacy)
                && !progress.accepted_cache_heads.contains_key(&session_key))
            .then(|| DeferredCacheHeadIdentity {
                source_file_fingerprint: item.source_file_fingerprint.clone(),
                snapshot_fingerprint: fingerprint,
                session_key,
            })
        })
        .collect()
}

/// Both exact contracts, so Pi (no base cache contract) never marks a patch.
fn cache_full_replacement_negotiated(
    source: SnapshotSource,
    hint: &crate::snapshot_client::ActivityHintResponse,
) -> bool {
    source != SnapshotSource::Pi
        && hint.session_cache_observations_contract.as_deref()
            == Some("session_cache_observations:v1")
        && hint.cache_full_replacement_contract.as_deref() == Some("cache_full_replacement:v1")
}

/// Pure projection shared by no-op/index witnesses and the network boundary.
/// Local consumers retain the original cache patch and provisional state.
fn prepare_snapshot_cache_for_upload(
    snapshot: &mut SnapshotItem,
    progress: &SnapshotUploadProgress,
    enabled: bool,
    head_cas_required: bool,
    legacy_pending: &BTreeSet<String>,
) {
    // Telemetry bodies use head CAS without negotiating cache evidence. Their
    // predecessor is the exact saved ACK, and they never carry a cache patch.
    if snapshot.evidence_basis == Some("otel_only") {
        snapshot.cache_observations = None;
        snapshot.cache_observations_state = None;
        snapshot.cache_base_head_etag = progress
            .accepted_cache_heads
            .get(&cache_session_key(&snapshot.source_session_id))
            .cloned();
        return;
    }
    if !enabled {
        snapshot.cache_observations = None;
        snapshot.cache_observations_state = None;
        snapshot.cache_base_head_etag = None;
        return;
    }
    let key = cache_session_key(&snapshot.source_session_id);
    snapshot.cache_base_head_etag = progress.accepted_cache_heads.get(&key).cloned();
    if (head_cas_required || legacy_pending.contains(&snapshot.snapshot_fingerprint))
        && snapshot.cache_base_head_etag.is_none()
    {
        snapshot.cache_observations = None;
        snapshot.cache_observations_state = None;
        return;
    }
    crate::snapshots::prepare_cache_observations(
        snapshot,
        progress.accepted_cache_states.get(&key),
    );
}

/// Reserve growth from the ACKed cache predecessor without changing the local
/// patch. Missing-head/legacy fencing can only remove this projected material.
fn identity_cache_wire_reserve(
    snapshot: &SnapshotItem,
    progress: &SnapshotUploadProgress,
    full_replacement: bool,
) -> usize {
    if snapshot.evidence_basis != Some("otel_only")
        && snapshot.cache_observations.is_none()
        && !progress
            .accepted_cache_heads
            .contains_key(&cache_session_key(&snapshot.source_session_id))
    {
        return 0;
    }
    let mut projected = snapshot.clone();
    prepare_snapshot_cache_for_upload(&mut projected, progress, true, false, &BTreeSet::new());
    // An owed answer can become eligible between admission and upload. Reserve
    // its framing even while paced, using the real attachment/size paths.
    attach_head_conflict_answers(
        std::slice::from_mut(&mut projected),
        progress,
        u64::MAX,
        |_| full_replacement,
    );
    crate::snapshots::claude_request_identity::item_bytes(&projected).saturating_sub(
        crate::snapshots::claude_request_identity::item_bytes(snapshot),
    )
}

/// Keep ordinary (0), patched or headed (1), legacy (2), and telemetry-only (3)
/// requests separate: the head-CAS declaration applies to the entire batch.
/// Class 1 is a body with a cache patch (admitted, unchanged or partial-empty)
/// or a saved head; class 0 has neither, sends no CAS contract and cannot
/// conflict with a server head it never claimed.
fn snapshot_upload_batch_class(snapshot: &SnapshotItem, legacy: bool) -> u8 {
    if snapshot.evidence_basis == Some("otel_only") {
        3
    } else if legacy {
        2
    } else {
        u8::from(crate::snapshot_client::declares_head_cas(snapshot))
    }
}

/// Answer each owed head-CAS challenge on the outgoing body of its session.
/// After a validated conflict refuses this exact challenge's answer, only a
/// re-send of a held conflicted body waits, until that body's own conflict
/// probe (within one hour); a new revision answers at once. Only a body that
/// declares head CAS carries the answer; telemetry is freshly rebuilt from its
/// ordinary evidence chunk and needs neither a cache patch nor a saved base. The
/// body itself, its fingerprint and its witness are unchanged.
/// `replacement_owed` (negotiated, real-Full session) may also mark the patch
/// a full replacement when no local cache state exists: that patch already
/// completes from empty, so only the receiver's predecessor changes.
fn attach_head_conflict_answers(
    snapshots: &mut [SnapshotItem],
    progress: &SnapshotUploadProgress,
    now: u64,
    replacement_owed: impl Fn(&str) -> bool,
) -> usize {
    let mut attached = 0usize;
    for snapshot in snapshots {
        snapshot.cache_conflict_answer = None;
        if let Some(patch) = snapshot.cache_observations.as_mut() {
            patch.full_replacement = false;
        }
        // A saved base declares head CAS with or without a patch, and
        // telemetry declares it with or without a base, so the request and
        // its ACK validation admit the handshake.
        if snapshot.evidence_basis != Some("otel_only") && snapshot.cache_base_head_etag.is_none() {
            continue;
        }
        let key = cache_session_key(&snapshot.source_session_id);
        let Some(record) = progress.head_conflict_challenges.get(&key) else {
            continue;
        };
        if record.last_answer_unix != 0
            && progress
                .quarantined_fingerprints
                .contains_key(&snapshot.snapshot_fingerprint)
            && now < conflict_probe_after(&snapshot.snapshot_fingerprint, record.last_answer_unix)
        {
            continue;
        }
        snapshot.cache_conflict_answer = Some((
            record.challenge.clone(),
            record.stale_revision_v2_hash.clone(),
        ));
        if let Some(patch) = snapshot.cache_observations.as_mut().filter(|patch| {
            replacement_owed(&key)
                && !progress.accepted_cache_states.contains_key(&key)
                && patch.operations.iter().all(|operation| {
                    matches!(operation, crate::snapshots::cache_observations::Operation::Upsert { observation }
                        if observation.status != "retracted")
                })
        }) {
            // Over the patch bound the answer stays unmarked, as before.
            patch.full_replacement = true;
            patch.full_replacement = patch.validate();
        }
        attached = attached.saturating_add(1);
    }
    attached
}

fn effective_snapshot_upload_body_witness(
    snapshot: &SnapshotItem,
    progress: &SnapshotUploadProgress,
    enabled: bool,
    head_cas_required: bool,
    legacy_pending: &BTreeSet<String>,
    local_authority: &crate::snapshots::ClaudeUsageAuthorityDisposition,
) -> String {
    if !local_authority
        .quarantined_fingerprints(std::slice::from_ref(snapshot))
        .is_empty()
    {
        // A held group retains its prior local-finalization semantics. It does
        // not acquire a network settlement or a head retry obligation here.
        return snapshot_upload_body_witness(snapshot);
    }
    let mut projected = snapshot.clone();
    prepare_snapshot_cache_for_upload(
        &mut projected,
        progress,
        enabled,
        head_cas_required,
        legacy_pending,
    );
    snapshot_upload_body_witness(
        held_cache_head_probe(progress, &projected)
            .as_ref()
            .unwrap_or(&projected),
    )
}

/// One hash-only group per current file. Duplicate source witnesses are not an
/// exact mapping and are excluded rather than guessed. O(current index files).
fn cache_head_file_groups(
    index: &ScanIndex,
) -> BTreeMap<String, (String, String, &BTreeSet<String>)> {
    let mut groups = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (index_key, entry) in &index.files {
        let Some(group) = entry.last_snapshot_fingerprint.as_ref() else {
            continue;
        };
        let Some(entities) = index
            .file_snapshot_fingerprints
            .get(index_key)
            .filter(|set| !set.is_empty())
        else {
            continue;
        };
        let file = &entry.source_file_fingerprint;
        if groups
            .insert(
                file.clone(),
                (cache_head_index_key(index_key), group.clone(), entities),
            )
            .is_some()
        {
            ambiguous.insert(file.clone());
        }
    }
    for file in ambiguous {
        groups.remove(&file);
    }
    groups
}

fn cache_head_selection_witness(accepted_head: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("cache_head_selection:v1:{accepted_head}"))
    )
}

fn cache_head_index_key(index_key: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("cache_head_file:v1:{index_key}"))
    )
}

pub(crate) fn cache_session_key(session: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(session.as_bytes()))
}

/// Durable, privacy-minimal progress for one policy-scoped scan index.
///
/// The scanner cannot commit its final `ScanIndex` until every changed
/// snapshot is accepted: committing it earlier would silently drop the files
/// represented by a later failed batch. Persisting only the stable semantic
/// snapshot fingerprints lets a restart skip already-accepted pages without
/// retaining titles, paths, or prompts. Numeric cache evidence and opaque accepted
/// head tokens survive cycle cleanup for later corrections; session keys are hashes.
/// A subset of the current file/entity incidence table, containing only cache
/// evidence actually deferred for missing accepted predecessor authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingCacheHeadFile {
    source_file_fingerprint: String,
    group_fingerprint: String,
    /// Semantic entity -> hashed session key; no source body or authority.
    entities: BTreeMap<String, String>,
    /// Sessions whose head arrival already reached a saved current file group.
    /// Failed bodies remain owed, but normal quarantine drives their retry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    reselected_heads: BTreeMap<String, String>,
    /// Exact cache-bearing settlements recorded only after the index save.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    settled_entities: BTreeSet<String>,
}

/// A server head-CAS challenge this session still owes an answer. The
/// challenge binds the server's current head to the exact refused revision v2
/// hash, so the next upload can replace the stale base through the backend's
/// existing rescan handshake instead of conflicting on it forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeadConflictChallenge {
    challenge: String,
    stale_revision_v2_hash: String,
    /// Answers the server refused again. Counted and logged; never terminal,
    /// so an unrecovered session keeps today's retryable conflict hold.
    #[serde(default)]
    answer_attempts: u32,
    /// When an answer to THIS challenge and revision was last refused; 0 when
    /// none was. A re-send of the same held body waits its conflict probe
    /// after it; a new challenge or revision resets it.
    #[serde(default)]
    last_answer_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PermanentSnapshotRejection {
    body_witness: String,
    /// Old enum vocabulary only: `original_pair_candidate_unproved` is
    /// written as `other`, so an older daemon keeps reading and suppressing it.
    reason: crate::upload_receipts::RejectedUsageReason,
    /// Optional daily/one-time re-offer schedule for this exact body. Older
    /// daemons ignore it; a malformed value disables only this record's retry.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "reason_reoffer::serialize",
        deserialize_with = "reason_reoffer::deserialize"
    )]
    reoffer: Option<reason_reoffer::RefusalReoffer>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "stale_owed::decode_exposure"
    )]
    exposure: Option<stale_owed::Exposure>,
    /// Exact older revisions remain with their existing refusal owner.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    revisions: BTreeMap<String, PermanentSnapshotRejection>,
}

mod ack_retention;
mod progress_rows;
mod telemetry_only;
mod upload_context_resend;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotUploadProgress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    telemetry_only: Option<Box<telemetry_only::Ledger>>,
    schema_version: u16,
    /// A routed source's progress rows; never serialized into the ledger.
    #[serde(skip)]
    rows: Option<Box<crate::snapshots::ProgressRows>>,
    #[serde(default)]
    generation: u64,
    destination_namespace_hash: String,
    /// Full replay generation whose ACKs populate this ledger. A new reviewed
    /// replay must not inherit ACKs for identical entities from an older
    /// generation, while a restart of the same generation must still resume.
    #[serde(default)]
    historical_replay_generation: Option<String>,
    #[serde(default)]
    accepted_fingerprints: BTreeSet<String>,
    /// Exact local body witness accepted for each semantic entity. Schema v3
    /// prevents a crash-resume ledger for curve A from suppressing corrected
    /// curve B, while the backend continues to ACK the stable semantic
    /// fingerprint.
    #[serde(default)]
    accepted_body_witnesses: BTreeMap<String, String>,
    /// Exact context of each durable stored-body ACK; absent means unknown.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    accepted_body_contexts: BTreeMap<String, String>,
    #[serde(skip)]
    context_resend: upload_context_resend::Cycle,
    /// Admission only: current live incidence plus bounded unsettled ACK debt.
    #[serde(skip, default = "ack_retention::default_ack_capacity")]
    ack_capacity: usize,
    /// ACKs outside known live incidence; includes valid unindexed debt.
    #[serde(skip)]
    retained_stale_ack_count: usize,
    #[serde(default)]
    accepted_cache_states: BTreeMap<String, serde_json::Value>,
    /// Class L bucket/share fingerprints, written only for stored-body ACKs.
    #[serde(
        default,
        skip_serializing_if = "crate::snapshots::claude_request_identity::AcceptedBuckets::is_empty"
    )]
    accepted_identity_buckets: crate::snapshots::claude_request_identity::AcceptedBuckets,
    /// Routed progress: the stored identity rows' barriers. The hints
    /// themselves are rows of their own, loaded per page.
    #[serde(
        default,
        skip_serializing_if = "crate::snapshots::claude_request_identity::IdentityScope::is_unset"
    )]
    accepted_identity_scope: crate::snapshots::claude_request_identity::IdentityScope,
    #[serde(default)]
    accepted_cache_heads: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pending_cache_heads: BTreeMap<String, PendingCacheHeadFile>,
    /// Head-CAS conflict challenges keyed like `accepted_cache_heads`. Any
    /// accepted or unchanged ACK for the session clears its entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    head_conflict_challenges: BTreeMap<String, HeadConflictChallenge>,
    #[serde(default)]
    quarantined_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
    /// Exact server-permanent refusals. Same destination, entity and body only;
    /// parser/replay epochs and premature retry timers cannot erase this fact.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    permanent_rejections: BTreeMap<String, PermanentSnapshotRejection>,
    #[serde(skip)]
    active_quarantine_witness: Option<SnapshotQuarantineWitness>,
    /// Runtime leases for quarantine entries selected this cycle. The durable
    /// record stays armed with its next future deadline until an exact ACK
    /// clears it; this set only bypasses suppression for the current request.
    #[serde(skip)]
    active_quarantine_retries: BTreeSet<String>,
    /// Runtime leases for refusals re-offered this cycle: fingerprint -> the
    /// exact refused body witness. Only that body passes permanent
    /// suppression, once per logical offer; the refusal stays durable.
    #[serde(skip)]
    active_reason_reoffers: BTreeMap<String, String>,
    #[serde(skip)]
    attempted_reason_reoffers: BTreeSet<String>,
    #[serde(skip)]
    reason_reoffer_counts: reason_reoffer::ReofferCounts,
    #[serde(skip)]
    terminal_contract_retry_pending_save: bool,
    /// Only exact entity ACKs observed in this cycle; never restored from disk.
    #[serde(skip)]
    fresh_context_body_acks: BTreeMap<String, String>,
    #[serde(skip)]
    context_receipt_candidates: Vec<crate::snapshots::UploadContextReceiptCandidate>,
}
/// What a save's compare-and-swap reads from the on-disk progress: the writer
/// stamp and the quarantine claims to merge. Other fields are skipped, not kept.
#[derive(Deserialize)]
struct SnapshotUploadProgressCas {
    schema_version: u16,
    #[serde(default)]
    generation: u64,
    destination_namespace_hash: String,
    #[serde(default)]
    quarantined_fingerprints: BTreeMap<String, SnapshotQuarantineRecord>,
}

impl SnapshotUploadProgress {
    /// A server-attested record of an earlier upload to this destination: an
    /// accepted, quarantined or refused body, or accepted cache evidence
    /// (prior history). A saved generation, a replay claim or a
    /// pending cache head is this daemon's own claim, saved before any upload,
    /// so it is not evidence.
    fn records_server_attested_upload(&self) -> bool {
        !self.accepted_fingerprints.is_empty()
            || !self.accepted_body_witnesses.is_empty()
            || !self.accepted_cache_states.is_empty()
            || !self.accepted_cache_heads.is_empty()
            || !self.quarantined_fingerprints.is_empty()
            || !self.permanent_rejections.is_empty()
    }

    fn new(
        destination_namespace_hash: String,
        active_quarantine_witness: SnapshotQuarantineWitness,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
            telemetry_only: None,
            rows: None,
            generation: 0,
            destination_namespace_hash,
            historical_replay_generation: None,
            accepted_fingerprints: BTreeSet::new(),
            accepted_body_witnesses: BTreeMap::new(),
            accepted_body_contexts: BTreeMap::new(),
            context_resend: upload_context_resend::Cycle::default(),
            ack_capacity: ack_retention::default_ack_capacity(),
            retained_stale_ack_count: 0,
            accepted_cache_states: BTreeMap::new(),
            accepted_identity_buckets: Default::default(),
            accepted_identity_scope: Default::default(),
            accepted_cache_heads: BTreeMap::new(),
            pending_cache_heads: BTreeMap::new(),
            head_conflict_challenges: BTreeMap::new(),
            quarantined_fingerprints: BTreeMap::new(),
            permanent_rejections: BTreeMap::new(),
            active_quarantine_witness: Some(active_quarantine_witness),
            active_quarantine_retries: BTreeSet::new(),
            active_reason_reoffers: BTreeMap::new(),
            attempted_reason_reoffers: BTreeSet::new(),
            reason_reoffer_counts: reason_reoffer::ReofferCounts::default(),
            terminal_contract_retry_pending_save: false,
            fresh_context_body_acks: BTreeMap::new(),
            context_receipt_candidates: Vec::new(),
        }
    }

    fn load(
        path: &Path,
        expected_destination_namespace_hash: &str,
        active_quarantine_witness: SnapshotQuarantineWitness,
    ) -> Result<Self> {
        let _lock = SnapshotProgressLock::acquire(path)?;
        if !path.exists() {
            return Ok(Self::new(
                expected_destination_namespace_hash.to_string(),
                active_quarantine_witness,
            ));
        }
        let parsed = std::fs::read(path)
            .context("read snapshot upload progress")
            .and_then(|bytes| {
                serde_json::from_slice::<Self>(&bytes)
                    .context("parse v3 local snapshot upload progress")
            });
        // Option (ii) proof is scoped to the namespace that ACKed it.
        if let Ok(progress) = &parsed {
            if progress.destination_namespace_hash != expected_destination_namespace_hash {
                progress
                    .accepted_identity_buckets
                    .count_retained_cleared_if_any();
            }
        }
        let mut progress = match parsed {
            Ok(progress)
                if progress.valid(expected_destination_namespace_hash)
                    && progress
                        .accepted_cache_states
                        .iter()
                        .all(|(key, state)| progress_rows::valid_cache_state(key, state))
                    && progress
                        .accepted_cache_heads
                        .iter()
                        .all(|(key, head)| progress_rows::valid_cache_head(key, head)) =>
            {
                progress
            }
            Ok(_) | Err(_) => {
                quarantine_invalid_progress(path)?;
                return Ok(Self::new(
                    expected_destination_namespace_hash.to_string(),
                    active_quarantine_witness,
                ));
            }
        };
        progress.finish_load(active_quarantine_witness);
        Ok(progress)
    }

    /// Every durable field but the keyed cache maps is admissible for this
    /// destination.
    fn valid(&self, namespace: &str) -> bool {
        self.schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            && self.destination_namespace_hash == namespace
            && is_snapshot_fingerprint(&self.destination_namespace_hash)
            && self
                .accepted_fingerprints
                .iter()
                .all(|value| is_snapshot_fingerprint(value))
            && self.accepted_body_witnesses.len() == self.accepted_fingerprints.len()
            && self.accepted_body_witnesses.keys().all(|value| {
                is_snapshot_fingerprint(value) && self.accepted_fingerprints.contains(value)
            })
            && self
                .accepted_body_witnesses
                .values()
                .all(|value| is_snapshot_fingerprint(value))
            && self.accepted_body_contexts.iter().all(|(key, context)| {
                self.accepted_body_witnesses.contains_key(key) && is_snapshot_fingerprint(context)
            })
            && self.pending_cache_heads.iter().all(|(file, pending)| {
                let sessions = pending.entities.values().collect::<BTreeSet<_>>();
                is_snapshot_fingerprint(file)
                    && is_snapshot_fingerprint(&pending.source_file_fingerprint)
                    && is_snapshot_fingerprint(&pending.group_fingerprint)
                    && !pending.entities.is_empty()
                    && pending.reselected_heads.iter().all(|(key, witness)| {
                        is_snapshot_fingerprint(witness) && sessions.contains(key)
                    })
                    && pending
                        .settled_entities
                        .iter()
                        .all(|entity| pending.entities.contains_key(entity))
                    && pending.entities.iter().all(|(entity, session)| {
                        is_snapshot_fingerprint(entity) && is_snapshot_fingerprint(session)
                    })
            })
            && self
                .quarantined_fingerprints
                .keys()
                .all(|value| is_snapshot_fingerprint(value))
            && self
                .permanent_rejections
                .iter()
                .all(|(fingerprint, record)| {
                    is_snapshot_fingerprint(fingerprint)
                        && is_snapshot_fingerprint(&record.body_witness)
                })
            && self.quarantined_fingerprints.values().all(|record| {
                snapshot_quarantine_deadline_is_bounded(record)
                    && record
                        .upload_body_witness
                        .as_deref()
                        .map_or(true, is_snapshot_fingerprint)
            })
    }

    /// Runtime state a loaded ledger starts every pass with.
    fn finish_load(&mut self, active_quarantine_witness: SnapshotQuarantineWitness) {
        let permanent = &self.permanent_rejections;
        self.terminal_contract_retry_pending_save = crate::snapshots::terminal_contract_retry::rearm(
            self.quarantined_fingerprints
                .iter_mut()
                .filter(|(fingerprint, record)| {
                    !permanent.get(*fingerprint).is_some_and(|refusal| {
                        record.upload_body_witness.as_deref() == Some(refusal.body_witness.as_str())
                    })
                }),
            Some(&active_quarantine_witness),
        ) > 0;
        self.active_quarantine_witness = Some(active_quarantine_witness);
        self.active_quarantine_retries.clear();
        self.active_reason_reoffers.clear();
    }

    /// Rearm every current entity exactly once for a new historical replay.
    ///
    /// The scan index independently clears its file checkpoints, but stable
    /// semantic fingerprints mean an older accepted/quarantined progress entry
    /// could otherwise suppress the re-derived upload. Keep same-generation
    /// progress intact so page ACKs and conflict retries remain resumable.
    fn prepare_historical_replay(&mut self, generation: &str) -> bool {
        if self.historical_replay_generation.as_deref() == Some(generation) {
            return false;
        }
        self.historical_replay_generation = Some(generation.to_string());
        self.accepted_identity_buckets.clear_retained();
        if self.rows.is_some() && !self.accepted_identity_scope.is_unset() {
            self.accepted_identity_scope.retained_before = self.generation.saturating_add(1);
        }
        self.accepted_fingerprints.clear();
        self.accepted_body_witnesses.clear();
        self.accepted_body_contexts.clear();
        self.quarantined_fingerprints.clear();
        for pending in self.pending_cache_heads.values_mut() {
            pending.settled_entities.clear();
            pending.reselected_heads.clear();
        }
        true
    }

    #[cfg(test)]
    fn contains(&self, fingerprint: &str) -> bool {
        !self.active_quarantine_retries.contains(fingerprint)
            && (self.accepted_fingerprints.contains(fingerprint)
                || self.quarantined_fingerprints.contains_key(fingerprint))
    }

    fn contains_body(&self, fingerprint: &str, body_witness: &str) -> bool {
        // Durable exact-body ACKs still resume interrupted uploads. Receipt
        // adoption separately requires current-context ACKs (fresh, or stamped
        // in this context); it must not force an accepted page through again.
        if self
            .permanent_rejections
            .get(fingerprint)
            .is_some_and(|record| record.refused_body(body_witness))
        {
            // Only this exact body's own re-offer lease passes suppression.
            return self.owed_stale_body(fingerprint, body_witness)
                || self
                    .active_reason_reoffers
                    .get(fingerprint)
                    .map(String::as_str)
                    != Some(body_witness);
        }
        if self.active_quarantine_retries.contains(fingerprint) {
            return false;
        }
        (self
            .accepted_body_witnesses
            .get(fingerprint)
            .is_some_and(|accepted| accepted == body_witness)
            && !self
                .context_resend
                .requires_resend(fingerprint, &self.accepted_body_contexts))
            || self
                .quarantined_fingerprints
                .get(fingerprint)
                .is_some_and(|record| record.upload_body_witness.as_deref() == Some(body_witness))
    }

    #[cfg(test)]
    fn record<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        for fingerprint in fingerprints {
            self.record_body(fingerprint, fingerprint);
        }
    }

    fn note_reprojected_context_refusals(&mut self, items: &[SnapshotItem]) -> bool {
        let Some(active) = self.active_quarantine_witness.as_ref() else {
            return false;
        };
        let mut changed = false;
        for item in items {
            if let Some(record) = self
                .quarantined_fingerprints
                .get_mut(&item.snapshot_fingerprint)
            {
                if record.witness != *active
                    && record.upload_body_witness.as_deref()
                        == Some(snapshot_upload_body_witness(item).as_str())
                {
                    record.witness = active.clone();
                    changed = true;
                }
            }
        }
        changed
    }

    fn record_body(&mut self, fingerprint: &str, body_witness: &str) {
        self.accepted_body_contexts.remove(fingerprint);
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            self.reason_reoffer_counts.accepted += 1;
        }
        if let Some(mut refusal) = self.permanent_rejections.remove(fingerprint) {
            refusal.revisions.remove(body_witness);
            if refusal.body_witness == body_witness {
                if let Some((_, mut remaining)) = refusal.revisions.pop_first() {
                    remaining.revisions = refusal.revisions;
                    self.permanent_rejections
                        .insert(fingerprint.into(), remaining);
                }
            } else if refusal.owed() || !refusal.revisions.is_empty() {
                self.permanent_rejections
                    .insert(fingerprint.into(), refusal);
            }
        }
        self.accepted_fingerprints.insert(fingerprint.to_string());
        self.accepted_body_witnesses
            .insert(fingerprint.to_string(), body_witness.to_string());
        self.quarantined_fingerprints.remove(fingerprint);
        self.active_quarantine_retries.remove(fingerprint);
        self.active_reason_reoffers.remove(fingerprint);
    }

    /// Keep the newest challenge for this session. A refused answer counts one
    /// attempt. The server binds a challenge to its current head and the exact
    /// stale revision, so a changed pair is new work: it inherits no hold and
    /// its answer is owed on the next page. Only the identical pair refusing
    /// an answer again starts the answer hold. Returns the cumulative attempt
    /// count for diagnostics and whether the answer is owed now.
    fn record_head_conflict_challenge(
        &mut self,
        session_id: &str,
        challenge: &str,
        rescan: &crate::snapshot_client::SnapshotConflictRescan,
        now: u64,
    ) -> Option<(u32, bool)> {
        if !is_snapshot_fingerprint(challenge) || !is_snapshot_fingerprint(&rescan.revision_v2_hash)
        {
            return None;
        }
        let key = cache_session_key(session_id);
        let previous = self.head_conflict_challenges.get(&key);
        let identical = previous.filter(|record| {
            record.challenge == challenge
                && record.stale_revision_v2_hash == rescan.revision_v2_hash
        });
        let answer_attempts = previous
            .map_or(0, |record| record.answer_attempts)
            .saturating_add(u32::from(rescan.answered));
        let last_answer_unix = match identical {
            None => 0,
            Some(_) if rescan.answered => now,
            Some(record) => record.last_answer_unix,
        };
        let owed_now = identical.is_none();
        self.head_conflict_challenges.insert(
            key,
            HeadConflictChallenge {
                challenge: challenge.to_string(),
                stale_revision_v2_hash: rescan.revision_v2_hash.clone(),
                answer_attempts,
                last_answer_unix,
            },
        );
        Some((answer_attempts, owed_now))
    }

    fn record_cache_state<T: Serialize>(
        &mut self,
        item: &T,
        head_changed_without_proof: bool,
    ) -> Result<()> {
        self.record_stored_state(item, head_changed_without_proof, None)
    }

    /// `stored` is the item's stored-body entity ACK (fingerprint-exact, no
    /// `unchanged_basis`) and this body's local witness. Option (ii) admits
    /// positive tags only while the server advertises retention and the ref
    /// carries a versioned witness equal to the local one on a body with a
    /// public witness version, so the entity-ACK validator also checked the
    /// exact version. Count-only and legacy ACKs pass `None`.
    /// `retained_proof_missing` only removes, so it is always applied.
    fn record_stored_state<T: Serialize>(
        &mut self,
        item: &T,
        head_changed_without_proof: bool,
        stored: Option<(&crate::snapshot_client::SnapshotEntityRef, &str)>,
    ) -> Result<()> {
        let value = serde_json::to_value(item)?;
        let Some(session) = value
            .get("source_session_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(());
        };
        if value["provenance"]["collector"].as_str()
            == Some(crate::snapshots::claude_request_identity::COLLECTOR)
        {
            // Record must see the stored frozen set.
            self.load_identity([session])?;
        }
        self.accepted_identity_buckets.record(&value);
        // `cache_state_ack:v1`: ACK validation refuses a cache-bearing stored
        // ref whose digest differs from this body's witness unless its echoed
        // state reproduces that digest with this body's own account and tool
        // parts. Such a ref's echo is the server's stored cache state, and its
        // digest is this body's witness with that state. This relies on every
        // caller passing a ref from a response already validated against this
        // exact request (`validate_entity_ack_with_head_cas`), as all upload
        // paths do; a new recording path must validate first.
        let echoed_cache_state = stored
            .filter(|(entity, local_witness)| {
                value.get("cache_observations").is_some()
                    && entity.body_witness_digest.as_deref() != Some(*local_witness)
            })
            .and_then(|(entity, _)| entity.cache_observations_state.as_ref())
            .and_then(crate::snapshots::cache_state_from_echo);
        // The re-projected body keeps the echoed rows, so its witness is the
        // server's digest: record that, and an unchanged body stays quiet.
        if let Some((entity, _)) = stored.filter(|_| echoed_cache_state.is_some()) {
            if let Some(digest) = &entity.body_witness_digest {
                self.accepted_body_witnesses
                    .insert(entity.snapshot_fingerprint.clone(), digest.clone());
            }
        }
        if let Some((entity, local_witness)) = stored {
            // Mirrors `snapshot_ack_body_witness_version`'s public domains.
            let versioned_body = ["session_account_evidence", "cache_observations"]
                .iter()
                .any(|field| value.get(field).is_some_and(|leaf| !leaf.is_null()));
            let witnessed = self.accepted_identity_buckets.retained_enabled()
                && versioned_body
                && entity.body_witness_version.is_some()
                && (entity.body_witness_digest.as_deref() == Some(local_witness)
                    || echoed_cache_state.is_some());
            if witnessed || !entity.retained_proof_missing.is_empty() {
                self.accepted_identity_buckets.record_proved(
                    &value,
                    witnessed,
                    &entity.retained_proof_missing,
                );
            }
        }
        let key = cache_session_key(session);
        // Count-only legacy ACKs cannot distinguish changed from unchanged.
        // Recover authority through the same bootstrap rather than retaining
        // a token whose continued validity the response cannot certify.
        if head_changed_without_proof {
            self.accepted_cache_heads.remove(&key);
        }
        let Some(patch) = value.get("cache_observations") else {
            return Ok(());
        };
        let state = match echoed_cache_state {
            Some(state) => state,
            None => {
                let patch = serde_json::from_value(patch.clone())?;
                crate::snapshots::cache_state_from_patch(
                    self.accepted_cache_states.get(&key),
                    &patch,
                )
                .ok_or_else(|| anyhow!("cache observations have unparseable accepted state"))?
            }
        };
        self.accepted_cache_states.insert(key, state);
        Ok(())
    }

    #[cfg(test)]
    fn quarantine<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        for fingerprint in fingerprints {
            self.quarantine_body(fingerprint, fingerprint);
        }
    }

    fn quarantine_body(&mut self, fingerprint: &str, body_witness: &str) {
        let witness = self
            .active_quarantine_witness
            .clone()
            .expect("upload progress always has an active quarantine witness");
        let budget = self
            .quarantined_fingerprints
            .get(fingerprint)
            .filter(|record| {
                record.upload_body_witness.as_deref() == Some(body_witness)
                    || (record.upload_body_witness.is_none()
                        && record.contract_retry_claims.is_some())
            });
        let existing = budget.filter(|record| record.witness.same_retry_contract(&witness));
        let contract_retry_claims = budget.and_then(|record| record.contract_retry_claims);
        let reconstruction_contract = budget.map_or(
            crate::snapshots::terminal_contract_retry::current_contract(),
            |record| {
                record
                    .reconstruction_contract
                    .max(crate::snapshots::terminal_contract_retry::current_contract())
            },
        );
        let stale_owed = self.owed_stale_body(fingerprint, body_witness);
        // A refused stale body owes an answer; it spends no reconstruction
        // exhaustion budget. Keep the existing RetryPending decoder contract.
        let failed_reconstruction_count = if stale_owed {
            1
        } else {
            existing
                .map(|record| record.failed_reconstruction_count.saturating_add(1))
                .unwrap_or(1)
                .min(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES)
        };
        let disposition = if !stale_owed
            && failed_reconstruction_count == MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
        {
            if existing.map_or(0, |record| record.failed_reconstruction_count)
                < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
            {
                UNPROVEN_TERMINAL_ATTEMPT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            SnapshotQuarantineDisposition::UnprovenTerminal
        } else {
            SnapshotQuarantineDisposition::RetryPending
        };
        self.quarantined_fingerprints.insert(
            fingerprint.to_string(),
            SnapshotQuarantineRecord {
                contract_retry_claims,
                reconstruction_contract,
                witness,
                retry_after_unix_seconds: if disposition
                    == SnapshotQuarantineDisposition::UnprovenTerminal
                {
                    0
                } else {
                    quarantine_retry_after(fingerprint)
                },
                upload_body_witness: Some(body_witness.to_string()),
                failed_reconstruction_count,
                disposition,
            },
        );
        self.accepted_fingerprints.remove(fingerprint);
        self.accepted_body_witnesses.remove(fingerprint);
        self.accepted_body_contexts.remove(fingerprint);
        self.active_quarantine_retries.remove(fingerprint);
    }

    fn quarantine_permanent_body(&mut self, fingerprint: &str, body_witness: &str, reason: &str) {
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            if reason == reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED {
                self.reason_reoffer_counts.refused_same += 1;
            } else {
                self.reason_reoffer_counts.refused_other += 1;
            }
        }
        self.quarantine_body(fingerprint, body_witness);
        let record = self.quarantined_fingerprints.get_mut(fingerprint).unwrap();
        // Current servers prove coverage before issuing a permanent stale
        // refusal. Fresh exposure records its recording generation; no legacy
        // record receives that marker without a new server answer.
        record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
        record.retry_after_unix_seconds = 0;
        let persisted_reason = crate::upload_receipts::RejectedUsageReason::from_wire(reason);
        // Each same-reason refusal restarts the 24 h clock. Any other `other`
        // answer is the server's classification of this body: done, never
        // re-offered. Known reasons keep their old record byte-for-byte.
        let reoffer = if reason == reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED {
            Some(reason_reoffer::RefusalReoffer::OriginalPair {
                retry_after_unix_seconds: reason_reoffer::next_offer_after(
                    reason_reoffer::now_unix_seconds(),
                ),
            })
        } else if persisted_reason == crate::upload_receipts::RejectedUsageReason::Other {
            Some(reason_reoffer::RefusalReoffer::Classified)
        } else {
            None
        };
        let revisions = self.retained_revisions(fingerprint, body_witness);
        self.permanent_rejections.insert(
            fingerprint.to_string(),
            PermanentSnapshotRejection {
                body_witness: body_witness.to_string(),
                reason: persisted_reason,
                reoffer,
                exposure: Some(stale_owed::Exposure::new(current_unix_seconds())),
                revisions,
            },
        );
        self.active_reason_reoffers.remove(fingerprint);
    }

    /// Counts only: the delivery cause when this exact body is already held,
    /// quarantined, refused, re-offered or owed only a stamp catch-up here;
    /// `None` for a changed body, which keeps its selection cause.
    fn change_reason_resend(
        &self,
        fingerprint: &str,
        session_id: Option<&str>,
        body_witness: impl FnOnce() -> String,
    ) -> Option<crate::local_resource_diagnostics::change_reason::Token> {
        use crate::local_resource_diagnostics::change_reason::Token;
        if self.context_resend.is_catchup(fingerprint) {
            return Some(Token::AckRecovery);
        }
        let held = self
            .quarantined_fingerprints
            .get(fingerprint)
            .map(|record| record.upload_body_witness.as_deref());
        let refused = self
            .permanent_rejections
            .get(fingerprint)
            .map(|record| record.body_witness.as_str());
        let reoffer = self.active_reason_reoffers.get(fingerprint);
        if held.is_none() && refused.is_none() && reoffer.is_none() {
            return None;
        }
        let body = body_witness();
        if reoffer == Some(&body) {
            return Some(Token::AdminOther);
        }
        if held.flatten() != Some(body.as_str()) && refused != Some(body.as_str()) {
            return None;
        }
        let conflict = session_id.is_some_and(|session| {
            self.head_conflict_challenges
                .contains_key(&cache_session_key(session))
        });
        Some(if conflict {
            Token::HeadConflict
        } else {
            Token::AckRecovery
        })
    }

    /// The server answered `unchanged` with an `unchanged_basis`: it did not
    /// store this body. Hold the exact body terminally, like a permanent
    /// refusal of the same body before that answer existed, but record no
    /// refusal: no usage was rejected. A changed body is a new fingerprint and
    /// is offered again; a historical replay rearms it once.
    fn hold_unstored_body(&mut self, fingerprint: &str, body_witness: &str) {
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            self.reason_reoffer_counts.unchanged_unstored += 1;
        }
        // A validated unchanged answer for a re-offered refused body replaces
        // that refusal's verdict. Retire it, so its reason schedules no more
        // offers; the hold below keeps the no-body-stored disclosure.
        let stale_owed = self.owed_stale_body(fingerprint, body_witness);
        if !stale_owed
            && self
                .permanent_rejections
                .get(fingerprint)
                .is_some_and(|refusal| refusal.body_witness == body_witness)
        {
            self.permanent_rejections.remove(fingerprint);
        }
        self.active_reason_reoffers.remove(fingerprint);
        self.quarantine_body(fingerprint, body_witness);
        let record = self
            .quarantined_fingerprints
            .get_mut(fingerprint)
            .expect("quarantine just recorded");
        if stale_owed {
            record.disposition = SnapshotQuarantineDisposition::RetryPending;
            record.contract_retry_claims = None;
        } else if self.context_resend.is_candidate(fingerprint) {
            // Current-context not_stored re-offers retain ordinary retry custody.
            // Exponential 6h/12h, capped by the existing 12h decoder bound.
            if record.disposition == SnapshotQuarantineDisposition::RetryPending {
                let delay = SNAPSHOT_QUARANTINE_RETRY_SECONDS.saturating_mul(
                    1u64 << record.failed_reconstruction_count.saturating_sub(1).min(1),
                );
                record.retry_after_unix_seconds =
                    reason_reoffer::now_unix_seconds().saturating_add(delay);
            }
        } else {
            record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
            record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
            record.retry_after_unix_seconds = 0;
        }
    }

    /// `retry_after_unix_seconds`: `quarantine_retry_after` for a refusal or
    /// conflict, the server's own `Retry-After` window for an identity deferral.
    fn quarantine_retryable_body(
        &mut self,
        fingerprint: &str,
        body_witness: &str,
        retry_after_unix_seconds: u64,
    ) {
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            self.reason_reoffer_counts.retryable += 1;
        }
        self.active_reason_reoffers.remove(fingerprint);
        self.quarantine_body(fingerprint, body_witness);
        let record = self
            .quarantined_fingerprints
            .get_mut(fingerprint)
            .expect("quarantine just recorded");
        record.failed_reconstruction_count = if record.contract_retry_claims.is_some() {
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        } else {
            1
        };
        record.disposition = SnapshotQuarantineDisposition::RetryPending;
        record.retry_after_unix_seconds = retry_after_unix_seconds;
        crate::snapshots::terminal_contract_retry::exhaust(record);
    }

    /// Outage custody: hold each body of the page that has no exact ACK, hold
    /// or refusal of these exact bytes yet, as an ordinary retryable
    /// quarantine until `retry_after_unix_seconds`. Returns how many were held.
    fn hold_outage_bodies(
        &mut self,
        items: &[SnapshotItem],
        retry_after_unix_seconds: u64,
    ) -> usize {
        let mut held = 0;
        for item in items {
            let fingerprint = item.snapshot_fingerprint.as_str();
            let witness = snapshot_upload_body_witness(item);
            if self.accepted_body_witnesses.get(fingerprint) == Some(&witness)
                || self
                    .quarantined_fingerprints
                    .get(fingerprint)
                    .is_some_and(|record| record.upload_body_witness.as_ref() == Some(&witness))
                || self.refused_body(fingerprint, &witness)
            {
                continue;
            }
            self.quarantine_retryable_body(fingerprint, &witness, retry_after_unix_seconds);
            held += 1;
        }
        held
    }

    fn retain_current_quarantines_with_diagnostics(
        &mut self,
        current: &BTreeSet<String>,
        index: &ScanIndex,
        diagnostic: Option<&mut CodexScanDiagnostics>,
    ) -> bool {
        let changed = self.retain_current_quarantines(current, index);
        if let Some(diagnostic) = diagnostic {
            for (fingerprint, record) in &self.quarantined_fingerprints {
                let fingerprint_digest = codex_scan_diagnostics::digest(fingerprint);
                for sample in diagnostic.lineage.iter_mut().flatten() {
                    if sample.fingerprint_digest == fingerprint_digest {
                        sample.after_current = current.contains(fingerprint);
                        sample.after_disposition = record.disposition;
                    }
                }
            }
        }
        changed
    }

    fn retain_current_quarantines(
        &mut self,
        current: &BTreeSet<String>,
        index: &ScanIndex,
    ) -> bool {
        let eligible = index
            .eligible_snapshot_fingerprint_refs()
            .collect::<BTreeSet<_>>();
        let before = self.quarantined_fingerprints.clone();
        for (fingerprint, record) in &mut self.quarantined_fingerprints {
            if current.contains(fingerprint)
                && eligible.contains(fingerprint.as_str())
                && !index.decode_holds_entity(fingerprint)
                && !self.permanent_rejections.contains_key(fingerprint)
                && record.disposition == SnapshotQuarantineDisposition::SupersededTerminal
                && record.failed_reconstruction_count < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                && record
                    .contract_retry_claims
                    .is_none_or(|n| n < crate::snapshots::terminal_contract_retry::MAX_CLAIMS)
            {
                record.disposition = SnapshotQuarantineDisposition::RetryPending;
                record.retry_after_unix_seconds = 0;
            } else if !current.contains(fingerprint)
                && !self
                    .permanent_rejections
                    .get(fingerprint)
                    .is_some_and(PermanentSnapshotRejection::has_stale_debt)
                && record.disposition != SnapshotQuarantineDisposition::SupersededTerminal
            {
                record.disposition = SnapshotQuarantineDisposition::SupersededTerminal;
                record.retry_after_unix_seconds = 0;
            }
        }
        self.active_quarantine_retries
            .retain(|fingerprint| current.contains(fingerprint));
        self.quarantined_fingerprints != before
    }

    fn save(&mut self, path: &Path) -> Result<()> {
        self.save_with_read_limit(path, None)
    }
    /// The concurrent-writer stamp of every progress write: the on-disk stamp
    /// is this owner's last save and nobody has saved since.
    fn same_writer(&self, (schema_version, generation, namespace): (u16, u64, &str)) -> bool {
        schema_version == SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            && generation == self.generation
            && namespace == self.destination_namespace_hash
    }
    fn stamp(&self) -> (u16, u64, &str) {
        let namespace = self.destination_namespace_hash.as_str();
        (self.schema_version, self.generation, namespace)
    }
    fn save_with_read_limit(&mut self, path: &Path, read_limit: Option<usize>) -> Result<()> {
        self.accepted_body_contexts
            .retain(|fp, _| self.accepted_body_witnesses.contains_key(fp));
        if self.rows.is_some() {
            return self.save_rows(path);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let _lock = SnapshotProgressLock::acquire(path)?;
        let mut unchanged = false;
        if path.exists() {
            let bytes = match read_limit {
                Some(cap) => crate::snapshot_retry::read_state(path, cap),
                None => std::fs::read(path),
            }
            .context("read current snapshot upload progress")?;
            let current: SnapshotUploadProgressCas = if read_limit.is_some() {
                crate::snapshot_retry::decode_state(&bytes)
            } else {
                serde_json::from_slice(&bytes).map_err(anyhow::Error::from)
            }
            .context("parse current snapshot upload progress for compare-and-swap")?;
            let namespace = current.destination_namespace_hash.as_str();
            if !self.same_writer((current.schema_version, current.generation, namespace)) {
                return Err(anyhow!("snapshot upload progress changed concurrently"));
            }
            crate::snapshots::terminal_contract_retry::merge_maps(
                &mut self.quarantined_fingerprints,
                &current.quarantined_fingerprints,
            );
            unchanged = serializes_to(&*self, &bytes);
        } else if self.generation != 0 {
            return Err(anyhow!("snapshot upload progress disappeared concurrently"));
        }
        if unchanged {
            // The durable ledger already holds these exact bytes at this
            // generation: write nothing and claim no generation, so the next
            // writer's compare-and-swap still matches. Retry only the
            // durability barrier: an earlier rename may be visible but not
            // yet synced.
            return sync_progress_parent(path);
        }
        let previous_generation = self.generation;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("snapshot upload progress generation overflow"))?;
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file =
            std::fs::File::create(&temp_path).context("create snapshot upload progress temp")?;
        let result = (|| -> Result<()> {
            serde_json::to_writer(&mut file, &*self)
                .context("write snapshot upload progress temp")?;
            file.sync_all()
                .context("sync snapshot upload progress temp")?;
            std::fs::rename(&temp_path, path).context("replace snapshot upload progress")?;
            sync_progress_parent(path)
        })();
        if result.is_err() {
            self.generation = previous_generation;
            let _ = std::fs::remove_file(&temp_path);
        }
        result
    }

    /// Use only the successfully loaded destination/source index, before any
    /// working scan changes. Missing entries remain unknown to candidate_decision
    /// and will Parse/rebind if the source still exists; no settlement is minted.
    fn prune_pending_cache_head_orphans_from_loaded_index(&mut self, index: &ScanIndex) -> bool {
        // Invalid-index quarantine and absent-index adoption return generation 0.
        // Such fallback/default state cannot certify an orphan disposition.
        if index.generation == 0 || self.pending_cache_heads.is_empty() {
            return false;
        }
        let indexed = index
            .files
            .keys()
            .map(String::as_str)
            .chain(index.decode_held_file_keys())
            .map(cache_head_index_key)
            .collect::<BTreeSet<_>>();
        let before = self.pending_cache_heads.len();
        self.pending_cache_heads
            .retain(|key, _| indexed.contains(key));
        before != self.pending_cache_heads.len()
    }

    fn record_pending_cache_head(
        &mut self,
        item: &SnapshotItem,
        groups: &BTreeMap<String, (String, String, &BTreeSet<String>)>,
        actually_deferred: bool,
    ) -> Result<bool> {
        self.record_pending_cache_head_identity(
            item.source_file_fingerprint.as_ref(),
            &item.snapshot_fingerprint,
            &cache_session_key(&item.source_session_id),
            groups,
            actually_deferred,
        )
    }

    fn record_pending_cache_head_identity(
        &mut self,
        source_file_fingerprint: Option<&String>,
        fingerprint: &str,
        session: &str,
        groups: &BTreeMap<String, (String, String, &BTreeSet<String>)>,
        actually_deferred: bool,
    ) -> Result<bool> {
        let invalid_binding = || {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "bind deferred cache head to current file entities",
            })
        };
        let Some(file) = source_file_fingerprint else {
            return if actually_deferred {
                Err(invalid_binding())
            } else {
                Ok(false)
            };
        };
        let Some((index_key, group, entities)) = groups.get(file) else {
            return if actually_deferred {
                Err(invalid_binding())
            } else {
                Ok(false)
            };
        };
        if !entities.contains(fingerprint) {
            return if actually_deferred {
                Err(invalid_binding())
            } else {
                Ok(false)
            };
        }
        if !actually_deferred && !self.pending_cache_heads.contains_key(index_key) {
            return Ok(false);
        }
        let mut changed = false;
        let pending = self
            .pending_cache_heads
            .entry(index_key.clone())
            .or_insert_with(|| {
                changed = true;
                PendingCacheHeadFile {
                    source_file_fingerprint: file.clone(),
                    group_fingerprint: group.clone(),
                    entities: BTreeMap::new(),
                    reselected_heads: BTreeMap::new(),
                    settled_entities: BTreeSet::new(),
                }
            });
        // A fully parsed replacement group owns its own obligation. Never
        // graft the old entity/session incidence onto a new file revision.
        if pending.group_fingerprint != *group || pending.source_file_fingerprint != *file {
            changed = true;
            pending.source_file_fingerprint = file.clone();
            pending.group_fingerprint = group.clone();
            pending.entities.clear();
            pending.reselected_heads.clear();
            pending.settled_entities.clear();
        }
        changed |= pending
            .entities
            .insert(fingerprint.to_owned(), session.to_owned())
            .as_deref()
            != Some(session);
        Ok(changed)
    }

    fn rearm_held_probe_witness_files(&self, index: &mut ScanIndex) -> usize {
        use crate::snapshots::snapshot_file_upload_body_set_hex;
        let covered = self.covered_stale_bodies();
        let selected = index
            .files
            .iter()
            .filter_map(|(key, entry)| {
                if index.decode_holds_file(key) {
                    return None;
                }
                let entities = index.file_snapshot_fingerprints.get(key)?;
                if entities.is_empty() {
                    return None;
                }
                let bodies = entities
                    .iter()
                    .map(|fp| {
                        let record = self.quarantined_fingerprints.get(fp)?;
                        let body = covered.get(fp)?;
                        (record.disposition == SnapshotQuarantineDisposition::UnprovenTerminal
                            && record.upload_body_witness.as_ref() == Some(body))
                        .then(|| body.clone())
                    })
                    .collect::<Option<BTreeSet<_>>>()?;
                (entry.last_upload_body_witness != Some(snapshot_file_upload_body_set_hex(bodies)))
                    .then(|| key.clone())
            })
            .collect::<Vec<_>>();
        for key in &selected {
            let entry = index.files.get_mut(key).expect("selected indexed file");
            entry.last_snapshot_fingerprint = None;
            entry.last_upload_body_witness = None;
        }
        selected.len()
    }

    fn reselect_pending_cache_heads(&mut self, index: &mut ScanIndex, enabled: bool) -> usize {
        if !enabled || self.pending_cache_heads.is_empty() {
            return 0;
        }
        for pending in self.pending_cache_heads.values_mut() {
            pending
                .reselected_heads
                .retain(|session, _| self.accepted_cache_heads.contains_key(session));
        }
        let mut selected = 0;
        for (index_key, entry) in index.files.slots_mut() {
            let Some(pending) = self
                .pending_cache_heads
                .get(&cache_head_index_key(index_key))
            else {
                continue;
            };
            if entry.source_file_fingerprint == pending.source_file_fingerprint
                && entry.last_snapshot_fingerprint.as_ref() == Some(&pending.group_fingerprint)
                && pending.entities.values().any(|session| {
                    self.accepted_cache_heads.get(session).is_some_and(|head| {
                        pending.reselected_heads.get(session)
                            != Some(&cache_head_selection_witness(head))
                    })
                })
            {
                // Existing candidate_decision treats a nonempty file without a
                // final group as Parse. Entity membership/ACK state stays intact.
                let entry = entry.make_mut();
                entry.last_snapshot_fingerprint = None;
                entry.last_upload_body_witness = None;
                selected += 1;
            }
        }
        selected
    }

    fn pending_cache_head_file_witnesses(
        &self,
        index: &ScanIndex,
    ) -> BTreeMap<String, Option<String>> {
        index
            .files
            .iter()
            .filter_map(|(key, entry)| {
                let key = cache_head_index_key(key);
                self.pending_cache_heads
                    .contains_key(&key)
                    .then(|| (key, entry.last_upload_body_witness.clone()))
            })
            .collect()
    }

    /// Call only after the index's settled save. A failed save or failed upload
    /// cannot retire a head obligation; repeating a reselect after a crash is safe.
    fn retire_pending_cache_heads(
        &mut self,
        index: &ScanIndex,
        items: &[SnapshotItem],
        held: &BTreeSet<String>,
        census_complete: bool,
        projected_file_witnesses: &BTreeMap<String, Option<String>>,
    ) {
        if self.pending_cache_heads.is_empty() {
            return;
        }
        let current_files = index
            .files
            .iter()
            .map(|(key, entry)| (cache_head_index_key(key), (key, entry)))
            .collect::<BTreeMap<_, _>>();
        let projected = items
            .iter()
            .filter(|item| item.cache_observations.is_some())
            .filter_map(|item| {
                item.source_file_fingerprint
                    .as_ref()
                    .map(|file| ((file.clone(), item.snapshot_fingerprint.clone()), item))
            })
            .collect::<BTreeMap<_, _>>();
        let opaque_files = index
            .decode_held_file_keys()
            .map(cache_head_index_key)
            .collect::<BTreeSet<_>>();
        self.pending_cache_heads.retain(|file, pending| {
            if opaque_files.contains(file) {
                return true;
            }
            let Some((index_key, entry)) = current_files.get(file) else {
                return !census_complete;
            };
            if index.decode_holds_file(index_key) {
                return true;
            }
            // Neither held absence nor a changed aggregate alone certifies
            // enrichment. Rebinding comes from the current admitted raw item.
            if entry.source_file_fingerprint != pending.source_file_fingerprint
                || entry.last_snapshot_fingerprint.as_ref() != Some(&pending.group_fingerprint)
            {
                return true;
            }
            for (entity, session) in &pending.entities {
                if held.contains(entity) {
                    continue;
                }
                let Some(item) =
                    projected.get(&(pending.source_file_fingerprint.clone(), entity.clone()))
                else {
                    continue;
                };
                if self.accepted_cache_heads.contains_key(session)
                    && self.accepted_body_witnesses.get(entity)
                        == Some(&snapshot_upload_body_witness(item))
                {
                    pending.settled_entities.insert(entity.clone());
                }
                if let Some(head) = item.cache_base_head_etag.as_ref().filter(|_| {
                    entry.last_upload_body_witness.is_some()
                        && projected_file_witnesses.get(file)
                            == Some(&entry.last_upload_body_witness)
                }) {
                    pending
                        .reselected_heads
                        .insert(session.clone(), cache_head_selection_witness(head));
                }
            }
            let all_siblings_settled = index
                .file_snapshot_fingerprints
                .get(*index_key)
                .is_some_and(|entities| {
                    entities.iter().all(|entity| {
                        !index.decode_holds_entity(entity)
                            && (pending.settled_entities.contains(entity)
                                || (self.accepted_fingerprints.contains(entity)
                                    && !index
                                        .quarantined_snapshot_fingerprints
                                        .contains_key(entity)))
                    })
                });
            !(all_siblings_settled
                && pending
                    .entities
                    .keys()
                    .all(|entity| pending.settled_entities.contains(entity)))
        });
    }

    fn finish_cycle(&mut self, path: &Path) -> Result<()> {
        if self.rows.is_none()
            && self.accepted_fingerprints.is_empty()
            && self.permanent_rejections.is_empty()
            && self.accepted_cache_states.is_empty()
            && self.accepted_cache_heads.is_empty()
            && self.pending_cache_heads.is_empty()
            && self.head_conflict_challenges.is_empty()
            && self.accepted_identity_buckets.is_empty()
        {
            return self.clear(path);
        }
        // Unadopted ACKs survive until a successful index save transfers them.
        // A later conflict on the refused bytes is the stronger settlement
        // fact, even while the retained refusal gates its next daily offer.
        // Keep it in the same atomic ledger so an older index-only timer can
        // still be distinguished from this newer server answer on restart.
        self.quarantined_fingerprints.retain(|fingerprint, record| {
            record.disposition == SnapshotQuarantineDisposition::RetryPending
                && self
                    .permanent_rejections
                    .get(fingerprint)
                    .is_some_and(|refusal| {
                        record.upload_body_witness.as_deref() == Some(refusal.body_witness.as_str())
                    })
        });
        self.active_quarantine_retries.clear();
        self.active_reason_reoffers.clear();
        self.save(path)
    }

    fn clear(&self, path: &Path) -> Result<()> {
        let _lock = SnapshotProgressLock::acquire(path)?;
        let current = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Self>(&bytes)
                .context("parse snapshot upload progress before clear")?,
            Err(error) if error.kind() == ErrorKind::NotFound && self.generation == 0 => {
                return Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(anyhow!("snapshot upload progress disappeared concurrently"))
            }
            Err(error) => return Err(error).context("read snapshot upload progress before clear"),
        };
        if !self.same_writer(current.stamp()) {
            return Err(anyhow!("snapshot upload progress changed concurrently"));
        }
        let tombstone = unique_progress_sibling(path, "cleared");
        std::fs::rename(path, &tombstone).context("atomically clear snapshot upload progress")?;
        sync_progress_parent(path)?;
        std::fs::remove_file(&tombstone).context("remove cleared snapshot upload progress")?;
        sync_progress_parent(path)
    }
}

pub(crate) struct SnapshotProgressLock {
    file: std::fs::File,
    path: Option<Box<Path>>,
}

impl SnapshotProgressLock {
    fn acquire(path: &Path) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .context("open snapshot upload progress lock")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("snapshot upload progress is owned by another daemon");
            }
        }
        Ok(Self { file, path: None })
    }

    fn for_v2(mut self, path: &Path) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl Drop for SnapshotProgressLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            use std::os::fd::AsRawFd;
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn unique_progress_sibling(path: &Path, kind: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{kind}.{}.{nanos}.json", std::process::id()))
}

/// Whether `value` serializes to exactly `bytes` (compact JSON). Streams into
/// the comparison and stops at the first differing byte; nothing is buffered.
fn serializes_to(value: &impl Serialize, bytes: &[u8]) -> bool {
    struct Same<'a>(&'a [u8]);
    impl Write for Same<'_> {
        fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.strip_prefix(chunk).ok_or(ErrorKind::InvalidData)?;
            Ok(chunk.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut same = Same(bytes);
    serde_json::to_writer(&mut same, value).is_ok() && same.0.is_empty()
}

fn sync_progress_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("sync snapshot upload progress directory")
}

fn quarantine_invalid_progress(path: &Path) -> Result<()> {
    let quarantine_path = unique_progress_sibling(path, "corrupt");
    std::fs::rename(path, quarantine_path)
        .context("quarantine invalid local snapshot upload progress")?;
    sync_progress_parent(path)
}

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

/// Hard ceiling on how long a source may go unscanned on cadence grounds alone.
///
/// The cost tiers are allowed to stretch a quiet source out to here and no
/// further: neither the filesystem watcher nor a server directive can suppress
/// a scan, because a watcher that silently stops delivering events would
/// otherwise stop collection with every health signal green.
const MAX_CYCLE_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How long the loop is willing to sit inside one wait before re-deciding.
/// Filesystem events shorten a wait to the next tier boundary; they never
/// shorten it below the floor, which is what makes a 2-second debounce incapable
/// of producing a per-event upload.
const CADENCE_WAIT_SLICE: Duration = Duration::from_secs(30);

/// Per-source adaptive cadence state.
static SOURCE_CADENCES: OnceLock<Mutex<BTreeMap<&'static str, SourceCadence>>> = OnceLock::new();

fn source_cadences() -> &'static Mutex<BTreeMap<&'static str, SourceCadence>> {
    SOURCE_CADENCES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn with_source_cadence<T>(
    source: SnapshotSource,
    apply: impl FnOnce(&mut SourceCadence) -> T,
) -> Option<T> {
    let power = continuation::MacPlatformSignals::default().power();
    with_source_cadence_state(source, |cadence| {
        cadence.set_power_stretch(continuation::session_power_stretch(power));
        apply(cadence)
    })
}

// Collection observations must not refresh power inputs or change scheduling.
fn with_source_cadence_state<T>(
    source: SnapshotSource,
    apply: impl FnOnce(&mut SourceCadence) -> T,
) -> Option<T> {
    let mut cadences = source_cadences().lock().ok()?;
    let cadence = cadences
        .entry(source.api_slug())
        .or_insert_with(|| SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL)));
    Some(apply(cadence))
}

pub(crate) fn start_collection_health(source: SnapshotSource) {
    // A small-route shed may predate the first offered scan of this run.
    let deadline = source_upload_deadlines()
        .lock()
        .ok()
        .and_then(|deadlines| deadlines.get(source.api_slug()).copied());
    with_source_cadence_state(source, |cadence| {
        let pulse = cadence
            .collection
            .get_or_insert_with(crate::collection_health::Pulse::start);
        if let Some(deadline) = deadline {
            pulse.defer(deadline);
        }
    });
}

pub(crate) fn reset_collection_health(source: SnapshotSource) {
    let Ok(mut cadences) = source_cadences().lock() else {
        return;
    };
    if let Some(cadence) = cadences.get_mut(source.api_slug()) {
        cadence.collection = None;
    }
}

pub(crate) fn collection_health(
    source: SnapshotSource,
    applicable: bool,
    wall: &str,
) -> Option<ottto_protocol::SourceCollectionHealth> {
    let mut cadences = source_cadences().lock().ok()?;
    let cadence = cadences.get_mut(source.api_slug())?;
    if !applicable {
        cadence.collection = None;
    }
    cadence
        .collection
        .as_ref()
        .map(|pulse| pulse.project(cadence.ordinary_interval(), wall))
}

/// The negotiated wait for one source: `clamp(directive, floor, ceiling)`.
///
/// The tier arithmetic — including the server's requested minimum interval — lives
/// in [`SourceCadence`], anchored to the last scan. That anchoring is load-bearing:
/// a *relative* directive re-read on every cycle would push its own deadline
/// forward forever and the scan would never run again, silently, on a healthy
/// machine. All that remains here is the ceiling, which bounds a directive that
/// would otherwise silence a source for a day.
fn negotiated_wait(cadence: &SourceCadence, now: Instant) -> Duration {
    cadence
        .next_scan_after(now)
        .clamp(Duration::ZERO, MAX_CYCLE_INTERVAL)
}

/// When `source`'s paced scan may run; `None` without one or under backoff.
fn source_paced_due(source: SnapshotSource) -> Option<Instant> {
    source_upload_backoff_remaining(source)
        .is_none()
        .then(|| with_source_cadence(source, |cadence| cadence.paced_scan_due()).flatten())
        .flatten()
}

/// The earliest paced scan across sources, for the cycle's wake time.
fn paced_scan_due() -> Option<Instant> {
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter_map(|source| {
        let paced = with_source_cadence(source, |cadence| cadence.paced_scan_due()).flatten()?;
        let deadlines = source_upload_deadlines().lock().ok()?;
        Some(
            deadlines
                .get(source.api_slug())
                .map_or(paced, |due| paced.max(*due)),
        )
    })
    .min()
}

fn source_cadence_wait(source: SnapshotSource) -> Option<Duration> {
    let now = crate::scan_clock::now();
    let wait = with_source_cadence(source, |cadence| negotiated_wait(cadence, now))
        .unwrap_or(Duration::ZERO);
    (!wait.is_zero()).then_some(wait)
}

/// Fold the server's `recommended_scan_after` into the source's cadence as a
/// minimum interval between scans.
///
/// An unparsable value leaves the previous directive alone rather than inventing
/// one, and a value in the past means "no minimum", not a negative wait.
fn record_server_scan_directive(source: SnapshotSource, recommended_scan_after: &str) {
    let Ok(recommended) = OffsetDateTime::parse(recommended_scan_after, &Rfc3339) else {
        return;
    };
    let delay = recommended - OffsetDateTime::now_utc();
    let requested = if delay.is_negative() {
        Duration::ZERO
    } else {
        Duration::from_secs(delay.whole_seconds().unsigned_abs()).min(MAX_CYCLE_INTERVAL)
    };
    with_source_cadence(source, |cadence| {
        cadence.set_server_min_interval(Some(requested))
    });
}

#[cfg(test)]
fn clear_cadence_state_for_test() {
    if let Ok(mut cadences) = source_cadences().lock() {
        cadences.clear();
    }
}

/// Base of the local backoff ladder for missing headers and repeated sheds.
const SHED_BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Uniform random in `[0, span]`, from the OS entropy source already used for
/// token material. Jitter that is not random is not jitter.
fn uniform_duration(span: Duration) -> Duration {
    #[cfg(test)]
    if let Some(sample) =
        tests::permanent_finish_pipeline_tests::once_credit_oracle_tests::backoff_sample_for_test(
            span,
        )
    {
        return sample;
    }
    if span.is_zero() {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Entropy is not available. Half the span is a poor sample but a correct
        // wait; refusing to wait would be the actual bug.
        return span / 2;
    }
    let fraction = u64::from_le_bytes(bytes) as f64 / u64::MAX as f64;
    Duration::from_secs_f64(span.as_secs_f64() * fraction)
}

/// The wait after a shed request.
///
/// With a server-supplied `Retry-After`, wait `Retry-After × uniform(1.0, 1.2)`.
/// The jitter is one-sided on purpose: the whole fleet was told the same number,
/// so obeying it exactly re-synchronises every machine onto the same instant —
/// which is how a shed becomes a thundering herd — but jittering *below* it
/// returns before the server said it would be ready, which is the overload the
/// shed was protecting against. Never early, sometimes late.
///
/// Without a `Retry-After`, full jitter over an exponential ladder: `random(0,
/// min(cap, base·2^n))`, which is the form that actually decorrelates retries,
/// not the "exponential plus a little noise" form.
///
/// The result is capped like a parsed `Retry-After` is, so the upper jitter
/// cannot push a wait past the longest silence the freshness promise tolerates.
pub(crate) fn shed_backoff(retry_after: Option<Duration>) -> Duration {
    match retry_after {
        Some(retry_after) => (retry_after + uniform_duration(retry_after.mul_f64(0.2)))
            .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER),
        None => full_jitter_backoff(0),
    }
}

/// `random(0, min(cap, base·2^attempt))` — full jitter, capped.
pub(crate) fn full_jitter_backoff(attempt: u32) -> Duration {
    let ceiling = SHED_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(6))
        .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER);
    uniform_duration(ceiling)
}

/// A deterministic per-machine offset inside `interval`.
///
/// Cycle phase is otherwise set by install or restart time, so any fleet-wide
/// event — a deploy, a shed, a network partition healing — re-aligns every
/// machine onto the same tick and keeps them aligned. The offset is derived from
/// the client id so it is stable across restarts (a random offset would
/// re-scatter on every launch, which is worse for the freshness promise than
/// being predictable).
fn cadence_phase_offset(client_id: &str, interval: Duration) -> Duration {
    let seconds = interval.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let mut digest = Sha256::new();
    digest.update(b"ottto.cadence.phase:v1");
    digest.update(client_id.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[..8]);
    Duration::from_secs(u64::from_be_bytes(bytes) % seconds)
}

/// Consecutive sheds per source, so persistent refusal climbs the ladder.
///
/// Without it every shed draws from `random(0, 30s)`, which the five-minute cycle
/// has already outlived by the next tick — a ladder that never leaves its first
/// rung is not backoff, it is a rounding error on the normal cadence. Reset by any
/// completed upload.
static SOURCE_SHED_STREAKS: OnceLock<Mutex<BTreeMap<&'static str, u32>>> = OnceLock::new();

fn source_shed_streaks() -> &'static Mutex<BTreeMap<&'static str, u32>> {
    SOURCE_SHED_STREAKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Count this shed and return the wait to honour.
fn note_shed_and_backoff(source: SnapshotSource, retry_after: Option<Duration>) -> Duration {
    let attempt = match source_shed_streaks().lock() {
        Ok(mut streaks) => {
            let streak = streaks.entry(source.api_slug()).or_insert(0);
            let attempt = *streak;
            *streak = streak.saturating_add(1);
            attempt
        }
        Err(_) => 0,
    };
    match retry_after {
        // The server's time is always the floor; repeated sheds also draw
        // from the existing ladder to ease sustained refusal.
        Some(retry_after) if attempt > 0 => {
            shed_backoff(Some(retry_after)).max(full_jitter_backoff(attempt))
        }
        Some(retry_after) => shed_backoff(Some(retry_after)),
        None => full_jitter_backoff(attempt),
    }
}

fn clear_shed_streak(source: SnapshotSource) {
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.remove(source.api_slug());
    }
}

/// Per-source "do not upload before" deadlines, set by an honoured shed.
static SOURCE_UPLOAD_DEADLINES: OnceLock<Mutex<BTreeMap<&'static str, Instant>>> = OnceLock::new();

fn source_upload_deadlines() -> &'static Mutex<BTreeMap<&'static str, Instant>> {
    SOURCE_UPLOAD_DEADLINES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn defer_source_uploads(source: SnapshotSource, retry_after: Duration) {
    let deadline = source_upload_deadlines().lock().ok().map(|mut deadlines| {
        let deadline = crate::scan_clock::now() + retry_after;
        *deadlines
            .entry(source.api_slug())
            .and_modify(|existing| *existing = (*existing).max(deadline))
            .or_insert(deadline)
    });
    // Release the deadline lock before the collector lock. All shed routes latch here.
    if let Some(deadline) = deadline {
        with_source_cadence_state(source, |cadence| {
            if let Some(pulse) = cadence.collection.as_mut() {
                pulse.defer(deadline);
            }
        });
    }
}

/// Small-route errors keep their typed diagnostics while sharing source backoff.
/// Terminal reports and heartbeats still send during an existing batch backoff.
pub(crate) fn small_source_upload<T>(
    source: SnapshotSource,
    send: impl FnOnce() -> Result<T>,
) -> Result<T> {
    send().inspect_err(|error| {
        if let Some(shed) = error.downcast_ref::<UploadShed>() {
            defer_source_uploads(source, note_shed_and_backoff(source, shed.retry_after));
        }
    })
}

/// Remaining backoff for `source`, or `None` when it may upload now.
fn source_upload_backoff_remaining(source: SnapshotSource) -> Option<Duration> {
    let mut deadlines = source_upload_deadlines().lock().ok()?;
    let deadline = *deadlines.get(source.api_slug())?;
    let now = crate::scan_clock::now();
    if deadline <= now {
        deadlines.remove(source.api_slug());
        return None;
    }
    Some(deadline - now)
}

#[cfg(test)]
fn clear_source_upload_deadlines_for_test() {
    if let Ok(mut deadlines) = source_upload_deadlines().lock() {
        deadlines.clear();
    }
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.clear();
    }
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

pub fn spawn_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    let phase_offset = local_cadence_phase_offset(SNAPSHOT_SYNC_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
        .spawn(move || {
            // Spread the fleet's cycle phase deterministically before the first
            // cycle. Otherwise phase is set by install or restart time, and every
            // fleet-wide event re-aligns every machine onto the same tick.
            std::thread::sleep(phase_offset);
            // Nothing watched the transcripts while the daemon was down.
            crate::snapshot_watcher::request_listing_all(
                crate::snapshot_watcher::ListingTrigger::Start,
            );
            // Best effort, and deliberately so: the loop below is driven by the
            // cadence tiers and the unconditional sweep, and the watcher only ever
            // shortens a wait. A machine that cannot watch its transcripts (no
            // permission, exhausted descriptors, a root that does not exist yet)
            // collects on exactly the schedule it does today.
            let mut watcher = watch_snapshot_source_roots(&home);
            if watcher.is_none() {
                eprintln!(
                    "local snapshot sync: filesystem watch unavailable; cadence follows the scan tiers only"
                );
            }
            let mut account_switch = ClaudeAccountSwitchProbe::default();
            let mut retry = live_snapshot_retry::LiveRetryOwner::production();
            loop {
                let prior = watcher.as_ref().map_or(&[][..], |current| current.roots());
                if let Ok(roots) = crate::snapshot_roots::watcher_roots(&home, prior) {
                    if watcher.as_ref().map_or(true, |current| !current.matches_roots(&roots)) {
                        // Nothing watched the changed or new targets until now.
                        crate::snapshot_watcher::request_listing_all(
                            crate::snapshot_watcher::ListingTrigger::Watcher,
                        );
                        watcher = crate::snapshot_watcher::watch_snapshot_roots(roots)
                            .inspect_err(|error| {
                                eprintln!(
                                    "local snapshot sync: filesystem watch re-create failed: {}",
                                    safe_error(error)
                                );
                            })
                            .ok();
                    }
                }
                match sync_once_with_retry(&home, &support_dir, &daemon, &mut retry) {
                    Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                    Err(error) => {
                        eprintln!("local snapshot sync skipped: {}", safe_error(&error));
                        crate::net_resilience::handle_sync_failure(&daemon);
                    }
                }
                // The cycle cadence itself is unchanged. What the tiers gate is the
                // expensive part — the local transcript scan and its upload — while
                // agent-status/quota freshness has an independent source owner.
                // Paced cursor continuation pages run inside the same ordinary
                // interval; the ordinary cycle keeps its deadline.
                continuation::wait_for_ordinary_cycle(
                    &mut ContinuationLoop {
                        watcher: watcher.as_ref(),
                        account_switch: &mut account_switch,
                        retry: &mut retry,
                        home: &home,
                        support_dir: &support_dir,
                        daemon: &daemon,
                    },
                    SNAPSHOT_SYNC_INTERVAL,
                );
            }
        })
        .context("spawn local snapshot sync")?;
    Ok(())
}

/// The delivery-only retry wake inside a cadence wait.
fn delivery_wake<'a>(
    retry: &'a mut live_snapshot_retry::LiveRetryOwner,
    home: &'a Path,
    support_dir: &'a Path,
    daemon: &'a LocalDaemon,
) -> impl FnMut(Instant) -> Instant + 'a {
    move |ordinary| {
        if !retry.enabled() {
            return ordinary;
        }
        // The native cycle lock also excludes the UI one-shot
        // path during a delivery-only turn. This wake never
        // starts a provider scan or resets ordinary cadence.
        let _guard = SNAPSHOT_SYNC_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        retry.boundary(home, support_dir, daemon);
        retry.wake_before(ordinary)
    }
}

/// The production loop host for continuation pages: real time, the watcher
/// wait and the delivery wake, with no network beyond what each already does.
struct ContinuationLoop<'a> {
    watcher: Option<&'a crate::snapshot_watcher::SnapshotWatcher>,
    account_switch: &'a mut ClaudeAccountSwitchProbe,
    retry: &'a mut live_snapshot_retry::LiveRetryOwner,
    home: &'a Path,
    support_dir: &'a Path,
    daemon: &'a LocalDaemon,
}

impl continuation::LoopHost for ContinuationLoop<'_> {
    fn now(&mut self) -> Instant {
        crate::scan_clock::now()
    }
    fn wait(&mut self, wait: Duration) -> bool {
        collect_file_activity_for(
            wait,
            self.watcher,
            self.account_switch,
            delivery_wake(self.retry, self.home, self.support_dir, self.daemon),
        )
    }
    fn pending(&mut self) -> Option<(Instant, Duration)> {
        continuation::production_pending()
    }
    fn paced_due(&mut self) -> Option<Instant> {
        paced_scan_due()
    }
    fn page(&mut self, deadline: Instant) -> continuation::Outcome {
        continuation::run_production_page(self.home, self.support_dir, self.daemon, deadline)
    }
}

/// Watch every enabled source's transcript roots, if the platform allows it.
fn watch_snapshot_source_roots(home: &Path) -> Option<crate::snapshot_watcher::SnapshotWatcher> {
    let roots = crate::snapshot_roots::watcher_roots(home, &[]).ok()?;
    crate::snapshot_watcher::watch_snapshot_roots(roots).ok()
}

/// Sleep for `wait`, folding any filesystem activity into the cadence tiers.
///
/// This is where the watcher earns its place, and it is deliberately the only
/// thing it does: an event **promotes a tier**, it never triggers a scan. A
/// promoted source becomes due at its floor on a later tick, so a transcript being
/// written continuously cannot produce an upload per event — and a machine whose
/// watcher never fires still collects on the tiers and the ceiling.
///
/// The one exception that ends a wait early is a Claude account switch (see
/// [`ClaudeAccountSwitchProbe`]): the next cycle then re-reads agent status and
/// re-attributes active sessions right away instead of up to a full interval
/// later. The transcript scan itself stays on its cadence. Returns `true` when
/// the wait ended early for that reason.
fn collect_file_activity_for(
    wait: Duration,
    watcher: Option<&crate::snapshot_watcher::SnapshotWatcher>,
    account_switch: &mut ClaudeAccountSwitchProbe,
    retry_boundary: impl FnMut(Instant) -> Instant,
) -> bool {
    collect_file_activity_with_retry(
        wait,
        watcher,
        account_switch,
        retry_boundary,
        crate::agent_status::claude_default_account_fingerprint,
    )
}

fn collect_file_activity_with_retry(
    wait: Duration,
    watcher: Option<&crate::snapshot_watcher::SnapshotWatcher>,
    account_switch: &mut ClaudeAccountSwitchProbe,
    mut retry_boundary: impl FnMut(Instant) -> Instant,
    mut read_account: impl FnMut() -> Option<String>,
) -> bool {
    let deadline = crate::scan_clock::now() + wait;
    let mut watcher = watcher;
    loop {
        // A delivery retry may share the ordinary deadline. Service it before
        // returning to collection, which can replace its retained checkpoint.
        let wake = retry_boundary(deadline).min(deadline);
        let now = crate::scan_clock::now();
        if now >= deadline {
            return false;
        }
        let slice = wake.saturating_duration_since(now).min(CADENCE_WAIT_SLICE);
        match watcher.map(|watcher| watcher.events.recv_timeout(slice)) {
            None => std::thread::sleep(slice),
            Some(Ok(event)) => {
                let _stage = StageWindow::begin(event.source.api_slug(), "offpass_hint");
                with_source_cadence(event.source, |cadence| {
                    cadence.record_file_event(crate::scan_clock::now())
                });
            }
            Some(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => {}
            // The watcher thread is gone. Keep waiting plainly rather than
            // spinning: collection is not gated on the watcher.
            Some(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) => {
                watcher = None;
            }
        }
        if account_switch.observe(crate::scan_clock::now(), &mut read_account) {
            eprintln!("local snapshot sync: Claude account switch detected; refreshing now");
            with_source_cadence(SnapshotSource::ClaudeCode, |cadence| {
                cadence.record_account_switch(crate::scan_clock::now())
            });
            return true;
        }
    }
}

/// How often the default Claude account is re-read while the loop waits.
const CLAUDE_ACCOUNT_SWITCH_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Notices when this Mac's default Claude account changes — the Claude Desktop
/// app signing into another account, or `claude /login` in a terminal.
///
/// Neither touches a watched transcript root, so without this the switch waited
/// for the next scheduled cycle (up to a full interval plus a slow cycle) before
/// the new account's sessions stopped showing under the old one. The first
/// observation only records a baseline; an unreadable fingerprint is never a
/// switch.
#[derive(Default)]
struct ClaudeAccountSwitchProbe {
    last_fingerprint: Option<String>,
    checked_at: Option<Instant>,
}

impl ClaudeAccountSwitchProbe {
    fn observe(&mut self, now: Instant, read: impl FnOnce() -> Option<String>) -> bool {
        if self.checked_at.is_some_and(|checked| {
            now.saturating_duration_since(checked) < CLAUDE_ACCOUNT_SWITCH_CHECK_INTERVAL
        }) {
            return false;
        }
        let _stage = StageWindow::begin("unknown", "offpass_account_check");
        self.checked_at = Some(now);
        let Some(current) = read() else {
            return false;
        };
        let switched = self
            .last_fingerprint
            .as_ref()
            .is_some_and(|previous| previous != &current);
        self.last_fingerprint = Some(current);
        switched
    }
}

/// This machine's cadence phase offset inside `interval`.
///
/// Derived from the durable machine id when there is one. A machine that has not
/// been claimed yet has no stable id, and inventing a random one would re-scatter
/// the phase on every launch — so an unclaimed machine simply starts on time.
fn local_cadence_phase_offset(interval: Duration) -> Duration {
    match FileMachineStore::default().load() {
        Ok(Some(machine)) if !machine.machine_id.is_empty() => {
            cadence_phase_offset(&machine.machine_id, interval)
        }
        _ => Duration::ZERO,
    }
}

pub fn spawn_local_health_projection_sync(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-local-health-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = upload_local_health_projection_now(&daemon) {
                if !local_health_upload_can_wait_quietly(&error) {
                    eprintln!(
                        "local health projection upload skipped: {}",
                        safe_error(&error)
                    );
                }
            }
            crate::control::reconcile_setup_scan_in_background(&daemon);
            std::thread::sleep(LOCAL_HEALTH_PROJECTION_INTERVAL);
        })
        .context("spawn local health projection sync")?;
    Ok(())
}

/// A freshly restarted daemon seeds registered sources as `verifying` (see
/// [`LocalDaemon::with_registered_device_sources`]) so a connected account never
/// momentarily shows zero sources while the first agent scan is pending. Nothing
/// else proactively runs that scan, so without this burst the seeded rows can
/// dwell in `verifying` for tens of seconds until a client polls with refresh or
/// the next session emits telemetry — a transient that can read as "not working"
/// to a customer right after a daemon restart. Reconfirm them shortly after
/// boot, retrying a few times so a cold CLI that is not yet ready on the first
/// pass still settles quickly. Honest by construction: this runs the same
/// agent-status scan a GUI/CLI refresh runs and only promotes `Available`
/// sources (see `LocalDaemon::reconfirm_verifying_sources_for_trusted_client`),
/// so it never reports `healthy` before the scan actually finds the source ready.
const STARTUP_REVERIFY_SCHEDULE: &[Duration] = &[
    Duration::from_secs(2),
    Duration::from_secs(6),
    Duration::from_secs(15),
];

pub fn spawn_startup_source_reverify(daemon: LocalDaemon) {
    let spawn_result = std::thread::Builder::new()
        .name("ottto-startup-reverify".to_string())
        .spawn(move || {
            for delay in STARTUP_REVERIFY_SCHEDULE {
                std::thread::sleep(*delay);
                let captured_at = current_rfc3339();
                let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
                    .unwrap_or_else(|| captured_at.clone());
                match daemon.reconfirm_verifying_sources_for_trusted_client(captured_at, expires_at)
                {
                    // All seeded rows reconfirmed (or none seeded / not
                    // connected) — nothing left to do.
                    Ok(0) => break,
                    // Some sources were not `Available` yet (cold CLI); retry on
                    // the next, longer tick once they have had time to warm up.
                    Ok(_) => continue,
                    Err(error) => {
                        eprintln!("startup source re-verify skipped: {error}");
                        break;
                    }
                }
            }
        });
    if let Err(error) = spawn_result {
        eprintln!("startup source re-verify unavailable: {error}");
    }
}

/// Startup/wake/upkeep share the source owner; transcript scans hold no
/// status lock and no hook starts a competing upload thread.
pub fn spawn_claude_agent_status_refresh(_opportunity: &'static str) {
    crate::agent_status_refresh::request(&SourceKind::ClaudeCode);
}

/// Cadence for the blocking-verification retry loop below: how often it checks
/// for sources stuck in a failed verification, and the exponential backoff for
/// actual re-verify attempts. Each attempt runs a real smoke session (a small
/// LLM call), so a fixed short interval would burn provider quota exactly when
/// the machine is quota-starved; exponential backoff recovers transient
/// failures (network blip, brief provider outage) within minutes while capping
/// steady-state cost at one smoke per source per half hour until it heals.
const FAILED_VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(60);
const FAILED_VERIFY_RETRY_INITIAL: Duration = Duration::from_secs(2 * 60);
const FAILED_VERIFY_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// Exponential backoff for background re-verify attempts: 2m, 4m, 8m, 16m,
/// then capped at 30m for as long as the source stays failed. The counter
/// resets whenever the source leaves the failed state (a successful retry,
/// a manual Verify, or a fresh sign-in).
fn reverify_backoff_delay(completed_attempts: u32) -> Duration {
    let factor = 1u32.checked_shl(completed_attempts).unwrap_or(u32::MAX);
    FAILED_VERIFY_RETRY_INITIAL
        .saturating_mul(factor)
        .min(FAILED_VERIFY_RETRY_MAX)
}

struct ReverifySchedule {
    source: SourceKind,
    completed_attempts: u32,
    next_attempt_at: Option<Instant>,
    // Outer None is a transient failure; Some holds the last nonsecret auth marker.
    reauth_marker: Option<Option<String>>,
    verification_baseline: Option<Option<String>>,
}

impl ReverifySchedule {
    fn new(source: SourceKind, now: Instant) -> Self {
        Self {
            source,
            completed_attempts: 0,
            next_attempt_at: Some(now + reverify_backoff_delay(0)),
            reauth_marker: None,
            verification_baseline: None,
        }
    }

    fn observe_verification_baseline(&mut self, baseline: Option<Option<String>>) {
        if self.verification_baseline != baseline {
            self.reauth_marker = baseline.clone();
            self.verification_baseline = baseline;
            self.next_attempt_at = None;
        }
    }

    fn is_due(&mut self, now: Instant, requires_reauth: bool, marker: Option<String>) -> bool {
        if requires_reauth {
            let Some(previous) = self.reauth_marker.as_mut() else {
                self.reauth_marker = Some(marker);
                self.next_attempt_at = None;
                return false;
            };
            if marker.is_none() {
                // Keep both the last known marker and any unconsumed retry.
                // Unavailable reads neither create a retry nor discard one.
                return false;
            }
            if *previous != marker {
                // A new marker gets one attempt after the quiet window,
                // even if that attempt still fails auth.
                self.next_attempt_at = Some(now + reverify_backoff_delay(0));
                *previous = marker;
                return false;
            }
        } else if self.reauth_marker.take().is_some() {
            self.completed_attempts = 0;
            self.next_attempt_at = Some(now + reverify_backoff_delay(0));
        }
        if self.next_attempt_at.is_some_and(|deadline| now >= deadline) {
            self.next_attempt_at = None;
            true
        } else {
            false
        }
    }

    fn record_attempt(&mut self, now: Instant) {
        self.completed_attempts = self.completed_attempts.saturating_add(1);
        if self.reauth_marker.is_none() {
            self.next_attempt_at = Some(now + reverify_backoff_delay(self.completed_attempts));
        }
    }
}

/// A blocking verification failure (`Failed` + `TelemetryNotVerified`) is
/// sticky by design: data refreshes only re-pin it and nothing re-runs the
/// smoke, so before this loop existed a transient failure sat on "needs
/// attention / Critical" until the customer pressed Verify by hand — even
/// though pressing Verify immediately healed it. Retry those sources
/// automatically with exponential backoff so the state converges on its own;
/// the companion app already self-heals once the daemon reports healthy.
/// Provider sign-in failures stay quiet until the Default Claude credential's
/// nonsecret modification marker changes. Other sources keep their existing backoff.
pub fn spawn_failed_verification_reverify(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-failed-verify-retry".to_string())
        .spawn(move || {
            let mut schedules: Vec<ReverifySchedule> = Vec::new();
            loop {
                std::thread::sleep(FAILED_VERIFY_POLL_INTERVAL);
                let failed = match daemon.blocking_verification_retry_states() {
                    Ok(failed) => failed,
                    Err(_) => continue,
                };
                // A source that healed (retry success, manual Verify, sign-in)
                // drops its schedule so a future failure restarts the backoff
                // from the initial delay.
                schedules
                    .retain(|schedule| failed.iter().any(|(source, _)| source == &schedule.source));
                for (source, requires_reauth) in failed {
                    let now = crate::scan_clock::now();
                    let index = schedules
                        .iter()
                        .position(|schedule| schedule.source == source)
                        .unwrap_or_else(|| {
                            schedules.push(ReverifySchedule::new(source.clone(), now));
                            schedules.len() - 1
                        });
                    let schedule = &mut schedules[index];
                    let marker = if requires_reauth && source == SourceKind::ClaudeCode {
                        let Ok(baseline) = daemon.claude_verification_auth_marker() else {
                            continue;
                        };
                        schedule.observe_verification_baseline(baseline);
                        crate::agent_status::claude_credential_modified_marker(
                            &ottto_core::ClaudeConfigDirSlot::Default,
                        )
                    } else {
                        None
                    };
                    if !schedule.is_due(now, requires_reauth, marker) {
                        continue;
                    }
                    match crate::control::reverify_failed_source(&daemon, source.clone()) {
                        Ok(result) => eprintln!(
                            "background re-verify for {} finished: {}",
                            crate::source_slug(&source),
                            result.message.code
                        ),
                        Err(error) => eprintln!(
                            "background re-verify for {} skipped: {error}",
                            crate::source_slug(&source)
                        ),
                    }
                    schedule.record_attempt(crate::scan_clock::now());
                }
            }
        })
        .context("spawn failed-verification re-verify loop")?;
    Ok(())
}

pub fn spawn_one_shot_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    if !claim_one_shot_sync_slot() {
        return Ok(());
    }
    let spawn_result = std::thread::Builder::new()
        .name("ottto-snapshot-sync-now".to_string())
        .stack_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES)
        .spawn(move || {
            match sync_once(&home, &support_dir, &daemon) {
                Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                Err(error) => {
                    eprintln!(
                        "local snapshot sync after setup skipped: {}",
                        safe_error(&error)
                    );
                    crate::net_resilience::handle_sync_failure(&daemon);
                }
            }
            set_one_shot_sync_in_flight(false);
        });
    if let Err(error) = spawn_result {
        set_one_shot_sync_in_flight(false);
        return Err(error).context("spawn immediate local snapshot sync");
    }
    Ok(())
}

fn claim_one_shot_sync_slot() -> bool {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    match lock.lock() {
        Ok(mut in_flight) => {
            if *in_flight {
                false
            } else {
                *in_flight = true;
                true
            }
        }
        Err(_) => true,
    }
}

fn set_one_shot_sync_in_flight(value: bool) {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    if let Ok(mut in_flight) = lock.lock() {
        *in_flight = value;
    }
}

fn sync_once(home: &Path, support_dir: &Path, daemon: &LocalDaemon) -> Result<()> {
    // Manual one-shot collection never owns the long-lived background queue.
    sync_once_with_retry(
        home,
        support_dir,
        daemon,
        &mut live_snapshot_retry::LiveRetryOwner::closed(),
    )
}

fn sync_once_with_retry(
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    retry: &mut live_snapshot_retry::LiveRetryOwner,
) -> Result<()> {
    // The periodic loop and setup/UI one-shot path can otherwise scan and save
    // the same per-source index concurrently. Serialize the full cycle so a
    // one-shot rescan cannot race the background loop or publish an older
    // incremental index after it.
    let _sync_guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Before credentials: a re-enabled source resumes even with no live device.
    resume_reconnected_sources(support_dir);
    crate::claude_local_otel::close_append_handles();
    // Declared after the guard, so it settles before the lock is released.
    let mut continuation_cycle = continuation::CycleSettlement::default();
    let (device, device_secret) = load_snapshot_device_credentials()?;
    daemon
        .record_source_grants(&device)
        .map_err(|_| anyhow!("source grants unavailable"))?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let account_witness = daemon
        .snapshot_scan_account_witness()
        .map_err(|_| anyhow!("snapshot account authority unavailable"))?;
    let client = snapshot_cycle_client(support_dir, daemon)?;
    let enabled_sources = cycle_heartbeat(&client, &device, &device_secret, &machine_id, daemon);
    for source in enabled_sources.iter().copied() {
        start_collection_health(source);
    }

    // Cycle-start scan receipts: one cheap non-terminal status per enabled
    // source before any scanning. Sources late in the sequential cycle would
    // otherwise hold receipts from the PREVIOUS cycle for this whole cycle, and
    // a backlog drain (e.g. after a daemon restart) stretches that well past
    // the backend's five-minute freshness promise even though uploads are
    // healthy. Best-effort: a failed receipt must never block the actual sync.
    let cycle_started_at = current_rfc3339();
    for source in enabled_sources.iter().copied() {
        if let Err(error) = report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            Some(&cycle_started_at),
        ) {
            eprintln!(
                "local snapshot cycle-start receipt skipped for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
        }
    }

    // Transport-layer outage evidence is folded here, in the per-source loop,
    // because this is the last point where each failure still carries the
    // typed `UploadFailureDiagnostics` (the aggregate error below collapses
    // to a count). One folded verdict per cycle feeds the streak.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    let mut failed_sources = Vec::new();
    let mut owner = SnapshotCycleOwner {
        client: &client,
        device: &device,
        device_secret: &device_secret,
        machine_id: &machine_id,
        home,
        support_dir,
        daemon,
        transport_cycle: &mut transport_cycle,
        failed_sources: &mut failed_sources,
        started: crate::scan_clock::now(),
        codex_started: None,
        paced_qos: None,
        account_witness,
        retry,
    };
    crate::source_rotation::run(
        &mut owner,
        &enabled_sources,
        crate::source_rotation::PARKED_BUDGET,
    );
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);
    crate::local_resource_diagnostics::rotate_service_log_if_due();
    if !failed_sources.is_empty() {
        return Err(SourcesFailed(failed_sources).into());
    }
    continuation_cycle.succeeded(enabled_sources.contains(&SnapshotSource::Codex));
    Ok(())
}

/// The cycle's heartbeat, then the sources this cycle collects: an OFF its
/// reply carries stops that source in this same cycle.
fn cycle_heartbeat(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Vec<SnapshotSource> {
    if let Some(source) = heartbeat_source(device) {
        if let Err(error) = upload_local_health_projection_reporting(
            client,
            device,
            device_secret,
            source,
            machine_id,
            daemon,
        ) {
            eprintln!(
                "local health projection upload skipped: {}",
                safe_error(&error)
            );
        }
    }
    enabled_snapshot_sources(device)
}

/// The cycle's API client, with the receipt state and context every cycle uses.
fn snapshot_cycle_client(support_dir: &Path, daemon: &LocalDaemon) -> Result<SnapshotApiClient> {
    let device_label = daemon
        .machine_for_trusted_client()
        .ok()
        .map(|machine| machine.display_name);
    let account_binding = daemon
        .account_for_trusted_client()
        .ok()
        .map(|account| account.state);
    Ok(SnapshotApiClient::new(snapshot_api_base_url()?)
        .with_receipt_state_dir(support_dir)
        .with_receipt_context(device_label, account_binding))
}

fn retry_ordinary_owned(item: &SnapshotItem) -> Option<SnapshotItem> {
    if item.cache_observations.is_some() || item.cache_base_head_etag.is_some() {
        return None;
    }
    Some(SnapshotItem {
        evidence_basis: None,
        request_evidence: Vec::new(),
        request_identity_refusals: 0,
        claude_org_markers: None,
        claude_account_withheld_reason: None,
        claude_account_display: None,
        session_billing_route: item.session_billing_route.clone(),
        claude_route_evidence: None,
        session_account_evidence: item.session_account_evidence.clone(),
        source_session_id: item.source_session_id.clone(),
        snapshot_fingerprint: item.snapshot_fingerprint.clone(),
        status: item.status.clone(),
        input_tokens: item.input_tokens,
        output_tokens: item.output_tokens,
        cache_read_tokens: item.cache_read_tokens,
        cache_creation_5m_tokens: item.cache_creation_5m_tokens,
        cache_creation_1h_tokens: item.cache_creation_1h_tokens,
        reasoning_output_tokens: item.reasoning_output_tokens,
        unattributed_total_tokens: item.unattributed_total_tokens,
        request_count: item.request_count,
        usage_accounting_contract: item.usage_accounting_contract.clone(),
        removed_request_count: item.removed_request_count,
        removed_usage: item.removed_usage,
        telemetry_owned_complete: item.telemetry_owned_complete,
        resolver_conflict_count: item.resolver_conflict_count,
        copy_unproven_counts: item.copy_unproven_counts,
        claude_money: None,
        claude_usage_request_ids: BTreeSet::new(),
        claude_usage_occurrences: BTreeMap::new(),
        cache_observations: item.cache_observations.clone(),
        cache_observations_state: None,
        cache_base_head_etag: None,
        cache_conflict_answer: None,
        cache_requests: Vec::new(),
        cache_requests_complete: false,
        avg_duration_ms: item.avg_duration_ms,
        avg_time_to_first_token_ms: item.avg_time_to_first_token_ms,
        max_duration_ms: item.max_duration_ms,
        max_time_to_first_token_ms: item.max_time_to_first_token_ms,
        peak_context_fill_tokens: item.peak_context_fill_tokens,
        first_turn_context_tokens: item.first_turn_context_tokens,
        last_turn_context_tokens: item.last_turn_context_tokens,
        // Copied, never dropped: a retry that lost the windows would settle as
        // UNCHANGED (they are outside every hash) and never deliver them.
        first_turn_context_window_tokens: item.first_turn_context_window_tokens,
        peak_context_fill_window_tokens: item.peak_context_fill_window_tokens,
        last_turn_context_window_tokens: item.last_turn_context_window_tokens,
        compaction_count: item.compaction_count,
        compaction_timestamps: item.compaction_timestamps.clone(),
        compaction_events: item.compaction_events.clone(),
        first_own_request_at: item.first_own_request_at.clone(),
        local_context_points: Vec::new(),
        compaction_total_pre_tokens: item.compaction_total_pre_tokens,
        compaction_total_post_tokens: item.compaction_total_post_tokens,
        compaction_total_cumulative_dropped_tokens: item.compaction_total_cumulative_dropped_tokens,
        compaction_total_duration_ms: item.compaction_total_duration_ms,
        context_curve: item.context_curve.clone(),
        claude_context_curve_boundaries: Vec::new(),
        claude_context_curve_identity_complete: false,
        claude_context_curve_request_index_complete: false,
        claude_context_curve_owned_start_proven: false,
        claude_file_birth: item.claude_file_birth,
        claude_file_birth_verdict: item.claude_file_birth_verdict(),
        activity_summary: item.activity_summary.clone(),
        tool_usage: item.tool_usage.clone(),
        tool_usage_truncated: item.tool_usage_truncated,
        session_start: item.session_start.clone(),
        model_usage: item.model_usage.clone(),
        usage_buckets: item.usage_buckets.clone(),
        cost: item.cost.clone(),
        session_display_name: item.session_display_name.clone(),
        session_display_name_source: item.session_display_name_source.clone(),
        source_started_at: item.source_started_at.clone(),
        source_ended_at: item.source_ended_at.clone(),
        source_last_activity_at: item.source_last_activity_at.clone(),
        collected_at: item.collected_at.clone(),
        workspace_hash: item.workspace_hash.clone(),
        workspace_display_label: item.workspace_display_label.clone(),
        workspace_label_source: item.workspace_label_source.clone(),
        repository_hash: item.repository_hash.clone(),
        repository_label: item.repository_label.clone(),
        repository_label_source: item.repository_label_source.clone(),
        repository_identity_source: item.repository_identity_source.clone(),
        workspace_kind: item.workspace_kind.clone(),
        source_file_fingerprint: item.source_file_fingerprint.clone(),
        session_artifacts: item.session_artifacts.clone(),
        provenance: item.provenance.clone(),
        origin: item
            .origin
            .as_ref()
            .map(|o| crate::snapshots::SnapshotOrigin {
                thread_source: o.thread_source.clone(),
                source: o.source.clone(),
                source_subagent: o.source_subagent,
                originator: o.originator.clone(),
                agent_role: o.agent_role.clone(),
                entrypoint: o.entrypoint.clone(),
                is_sidechain: o.is_sidechain,
                session_kind: o.session_kind.clone(),
                used_workflow_orchestration: o.used_workflow_orchestration,
                parent_session_ref: None,
            }),
        originator: item.originator.clone(),
        attribution_facts: item.attribution_facts.clone(),
    })
}

#[allow(dead_code, reason = "preparation is compiled ahead of its activation")]
#[path = "bounded_snapshot_retry.rs"]
mod bounded_snapshot_retry;
#[path = "live_snapshot_retry.rs"]
mod live_snapshot_retry;

struct SnapshotCycleOwner<'a> {
    retry: &'a mut live_snapshot_retry::LiveRetryOwner,
    account_witness: [u8; 32],
    client: &'a SnapshotApiClient,
    device: &'a LocalDeviceBinding,
    device_secret: &'a str,
    machine_id: &'a str,
    home: &'a Path,
    support_dir: &'a Path,
    daemon: &'a LocalDaemon,
    transport_cycle: &'a mut crate::net_resilience::TransportCycleOutcome,
    failed_sources: &'a mut Vec<&'static str>,
    started: Instant,
    /// When this cycle's Codex preparation began, for a continuation ticket's
    /// measured work. Only written while continuation pages are enabled.
    codex_started: Option<Instant>,
    /// Background QoS for the one source whose paced scan is due, held from
    /// its prepare through its finish; its outcome (or unwind) restores.
    paced_qos: Option<continuation::MacPlatformSignals>,
}
impl SnapshotCycleOwner<'_> {
    fn finish_completed(
        &mut self,
        (preparation, index, scan): (SourcePreparation, ScanIndex, SourceScanResult),
    ) -> Result<()> {
        use crate::source_rotation::Owner as _;
        codex_scan_diagnostics::observe_existing_outer_census_fence(
            preparation.source,
            self.support_dir,
            || {
                self.validate(&preparation)?;
                ensure_snapshot_destination_current(&preparation.upload_destination_namespace)
            },
        )?;
        let source = preparation.source;
        finish_sync_source(
            preparation,
            index,
            scan,
            self.client,
            self.device,
            self.device_secret,
            source,
            self.machine_id,
            self.home,
            self.support_dir,
            self.daemon,
            self.transport_cycle,
            self.retry,
        )
    }
}

impl crate::source_rotation::Owner for SnapshotCycleOwner<'_> {
    type Source = SnapshotSource;
    type Frame = SourcePreparation;
    type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        _remaining: Option<usize>,
    ) -> Result<Option<SourcePreparation>> {
        continuation::enter_source_qos(&mut self.paced_qos, source);
        if source == SnapshotSource::Codex {
            self.codex_started = Some(crate::scan_clock::now());
            // K2: this prepare's policy replaces any older cached inputs.
            continuation::invalidate_on_ordinary_prepare();
        }
        ensure_snapshot_scan_authority(
            self.device,
            source,
            self.client,
            &self.account_witness,
            self.daemon,
        )?;
        prepare_sync_source(
            self.client,
            self.device,
            self.device_secret,
            source,
            self.machine_id,
            self.home,
            self.support_dir,
            self.daemon,
            self.transport_cycle,
            self.account_witness,
            self.retry.enabled(),
        )
    }
    fn validate(&mut self, frame: &SourcePreparation) -> Result<()> {
        ensure_snapshot_scan_authority(
            self.device,
            frame.source,
            &frame.receipt_client,
            &frame.account_witness,
            self.daemon,
        )
    }
    fn step(
        &mut self,
        frame: SourcePreparation,
        _remaining: Option<usize>,
    ) -> crate::source_rotation::Step<SourcePreparation, Self::Completed> {
        match frame.step() {
            SourcePreparationStep::Pending(frame) => crate::source_rotation::Step::Pending(frame),
            SourcePreparationStep::Refused(frame, reason) => {
                drop(frame);
                crate::source_rotation::Step::Refused(reason)
            }
            SourcePreparationStep::Complete {
                preparation,
                index,
                scan,
            } => crate::source_rotation::Step::Complete((preparation, index, scan)),
        }
    }
    fn finish(&mut self, mut completed: Self::Completed, remaining: Option<usize>) -> Result<()> {
        let source = completed.0.source;
        // Read before the scan is consumed; kept only if the finish succeeds.
        let continuation_ticket = (source == SnapshotSource::Codex
            && completed.2.continuation_ticket().is_some())
        .then(|| {
            let endpoint = snapshot_api_base_url().ok()?;
            let authority =
                continuation::current_authority(self.device, &endpoint, &self.account_witness)
                    .filter(|_| self.client.matches_api_base(&endpoint));
            continuation::ordinary_ticket(
                &continuation::CodexContinuation::new(
                    &self.daemon.transcript_cache,
                    self.home,
                    self.support_dir,
                ),
                &completed.2,
                &completed.0.upload_destination_namespace,
                authority,
                continuation::ticket_lifetime(self.codex_started),
            )
            .and_then(continuation_finish_inputs(
                &mut completed.0,
                &mut completed.2,
                remaining,
                &self.daemon.codex_preludes,
                self.daemon.codex_versions.clone(),
            ))
        });
        let v2_active = crate::snapshots::state_v2_growth_retention_active(&completed.1);
        let exposure = completed.1.refusal_exposure;
        let finished = crate::local_resource_diagnostics::source_finish_with_refusals(
            source.api_slug(),
            v2_active,
            exposure,
            || self.finish_completed(completed),
        );
        if let Some(ticket) = continuation_ticket {
            continuation::after_ordinary_codex_page(ticket, self.codex_started, finished.is_ok());
        }
        finished
    }
    fn outcome(&mut self, source: SnapshotSource, result: Result<()>) {
        continuation::leave_source_qos(&mut self.paced_qos);
        crate::local_resource_diagnostics::pass_ended(source.api_slug());
        if result.is_err() {
            continuation::after_ordinary_source_failure(source);
        }
        match result {
            Ok(()) => self.transport_cycle.note_success(),
            Err(error) => {
                if error
                    .downcast_ref::<crate::source_rotation::LocalRefusal>()
                    .is_none()
                {
                    self.transport_cycle.note_error(&error);
                }
                eprintln!(
                    "local snapshot sync skipped for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
                crate::snapshots::money_freshness::report_failed_pass(source);
                self.failed_sources.push(source.api_slug());
            }
        }
    }
    fn monotonic(&self) -> Duration {
        self.started.elapsed()
    }
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        retained_with_withheld(
            &self.daemon.transcript_cache.withheld_memo,
            limit,
            |limit| {
                let versions = crate::heap_layout_bound::bound(&self.daemon.codex_versions, limit)?;
                let continuation = continuation::retained_bound(limit.checked_sub(versions)?)?;
                versions.checked_add(continuation)
            },
        )
    }
    fn retained_budget_unavailable(&mut self) {
        self.daemon
            .transcript_cache
            .withheld_memo
            .discard_retained();
        self.discard_retained();
    }
    fn discard_retained(&mut self) {
        continuation::discard_retained();
        self.daemon
            .transcript_cache
            .withheld_memo
            .discard_if_refused();
    }
    fn boundary(&mut self) {
        self.retry
            .boundary(self.home, self.support_dir, self.daemon);
    }
}

// Existing retained graphs have priority over the advisory memo. Refusing only
// the memo must not trigger the rotation's discard of admitted sibling graphs.
pub(crate) fn retained_with_withheld(
    memo: &crate::snapshots::withheld_account::Memo,
    limit: usize,
    other: impl FnOnce(usize) -> Option<usize>,
) -> Option<usize> {
    let owned = other(limit);
    // Even when siblings are unsupported, price the portable memo against the
    // available allowance so their discard preserves it only if it fits.
    let remaining = limit.checked_sub(owned.unwrap_or(0))?;
    match memo.retained_bound(remaining) {
        Some(withheld) => owned?.checked_add(withheld),
        None => {
            // Frees all memo allocations; held population remains disclosed
            // with unavailable details and no optional memo storage to charge.
            memo.discard_if_refused();
            owned
        }
    }
}

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

// Preparation stays owned by the existing cycle. No partially finalized body
// crosses a collection step.
struct SourcePreparation {
    retry_authority: Option<live_snapshot_retry::LiveAuthority>,
    source: SnapshotSource,
    claude_scan_roots: Option<Vec<PathBuf>>,
    account_witness: [u8; 32],
    scan_started_at: String,
    activity_hint: crate::snapshot_client::ActivityHintResponse,
    receipt_window_days: u64,
    cache_observations_enabled: bool,
    /// `None` only on a continuation page's preparation, which never finishes.
    scan_agent_status_collection: Option<std::sync::Arc<AgentStatusCollection>>,
    attribution_context: Option<SessionAttributionContext>,
    upload_policy: SnapshotUploadPolicy,
    upload_destination_namespace: String,
    receipt_client: SnapshotApiClient,
    index_path: PathBuf,
    upload_progress_path: PathBuf,
    upload_progress: SnapshotUploadProgress,
    committed_index: ScanIndex,
    backfill_state: crate::backfill::BackfillState,
    backfill_pending: bool,
    legacy_reconciliation_pending: BTreeSet<String>,
    active_legacy_reconciliation: BTreeSet<String>,
    scan: Option<crate::snapshots::OwnedSourceScan>,
}
#[allow(clippy::large_enum_variant, reason = "moves the owned context unboxed")]
enum SourcePreparationStep {
    Pending(SourcePreparation),
    Refused(SourcePreparation, crate::source_rotation::LocalRefusal),
    Complete {
        preparation: SourcePreparation,
        index: ScanIndex,
        scan: SourceScanResult,
    },
}
impl SourcePreparation {
    fn step(self) -> SourcePreparationStep {
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(
            self.source == SnapshotSource::ClaudeCode,
        );
        let result = self.step_inner();
        let counts = diagnostics.finish();
        crate::local_resource_diagnostics::claude_reread::emit_without_lease(counts);
        result
    }
    fn step_inner(mut self) -> SourcePreparationStep {
        let state = self.scan.take().expect("active source preparation");
        match state.step_fallible(self.attribution_context.as_ref()) {
            Err(reason) => SourcePreparationStep::Refused(self, reason),
            Ok(crate::snapshots::OwnedSourceScanStep::Pending(next)) => {
                self.scan = Some(next);
                SourcePreparationStep::Pending(self)
            }
            Ok(crate::snapshots::OwnedSourceScanStep::Complete { index, scan }) => {
                SourcePreparationStep::Complete {
                    preparation: self,
                    index,
                    scan,
                }
            }
        }
    }
}
#[cfg(test)]
fn collect_preparation_with_rotation(
    frame: SourcePreparation,
) -> (SourcePreparation, ScanIndex, SourceScanResult) {
    try_collect_preparation_with_rotation(frame).expect("owned source completion")
}
#[cfg(test)]
fn try_collect_preparation_with_rotation(
    frame: SourcePreparation,
) -> Result<(SourcePreparation, ScanIndex, SourceScanResult)> {
    struct Collect {
        frame: Option<SourcePreparation>,
        completed: Option<(SourcePreparation, ScanIndex, SourceScanResult)>,
        failure: Option<anyhow::Error>,
        started: Instant,
        steps: usize,
    }
    impl crate::source_rotation::Owner for Collect {
        type Source = SnapshotSource;
        type Frame = SourcePreparation;
        type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
        fn prepare(
            &mut self,
            _: SnapshotSource,
            _remaining: Option<usize>,
        ) -> Result<Option<Self::Frame>> {
            Ok(self.frame.take())
        }
        fn validate(&mut self, _: &Self::Frame) -> Result<()> {
            Ok(())
        }
        fn step(
            &mut self,
            frame: Self::Frame,
            _remaining: Option<usize>,
        ) -> crate::source_rotation::Step<Self::Frame, Self::Completed> {
            self.steps += 1;
            assert!(
                self.steps <= 1024,
                "same owned scanner must finish within existing fixture steps"
            );
            match frame.step() {
                SourcePreparationStep::Pending(frame) => {
                    crate::source_rotation::Step::Pending(frame)
                }
                SourcePreparationStep::Refused(frame, reason) => {
                    drop(frame);
                    crate::source_rotation::Step::Refused(reason)
                }
                SourcePreparationStep::Complete {
                    preparation,
                    index,
                    scan,
                } => crate::source_rotation::Step::Complete((preparation, index, scan)),
            }
        }
        fn finish(&mut self, completed: Self::Completed, _remaining: Option<usize>) -> Result<()> {
            self.completed = Some(completed);
            Ok(())
        }
        fn outcome(&mut self, _: SnapshotSource, result: Result<()>) {
            if let Err(error) = result {
                self.failure = Some(error);
            }
        }
        fn monotonic(&self) -> Duration {
            self.started.elapsed()
        }
    }
    let source = frame.source;
    let mut owner = Collect {
        frame: Some(frame),
        completed: None,
        failure: None,
        started: Instant::now(),
        steps: 0,
    };
    // The original rotation calculates queue/retained deductions. No
    // independently fabricated full-budget argument reaches the collector.
    let budget =
        tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::rotation_budget();
    crate::source_rotation::run(&mut owner, &[source], budget);
    if let Some(error) = owner.failure {
        return Err(error);
    }
    owner.completed.context("owned source completion")
}
/// The upload-context fingerprint a cycle activates on its index (pure; the
/// ordinary prepare and a Stage 1 continuation page share it).
fn cycle_upload_context(
    upload_policy: SnapshotUploadPolicy,
    checkpoint_namespace: Option<&str>,
    cache_observations_enabled: bool,
) -> String {
    let upload_context = snapshot_upload_context_fingerprint(upload_policy, checkpoint_namespace);
    if cache_observations_enabled {
        // Reuse the existing per-file upload context invalidation when a
        // backend upgrade admits cache evidence from previously scanned files.
        format!(
            "{:x}",
            Sha256::digest(format!("{upload_context}:session_cache_observations:v1"))
        )
    } else {
        upload_context
    }
}

/// Bind persisted retry pages to the Claude copy-prefix money mode; pages
/// persisted under the earlier context cannot replay old bodies.
pub(crate) fn resumed_prefix_upload_context(context: String, enabled: bool) -> String {
    if enabled {
        format!(
            "{:x}",
            Sha256::digest(format!("{context}:resumed-prefix:v1"))
        )
    } else {
        context
    }
}

/// Keep capability-qualified ACK contexts in the loader's 64-hex domain.
pub(crate) fn copy_unproven_upload_context(context: String, enabled: bool) -> String {
    if enabled {
        format!(
            "{:x}",
            Sha256::digest(format!("{context}:copy_unproven:v1"))
        )
    } else {
        context
    }
}

/// The replay generation of a cycle (pure; shared as above).
fn cycle_replay_generation(source: SnapshotSource, upload_destination_namespace: &str) -> String {
    let replay = current_historical_replay(source);
    format!(
        "{}:{}:{}",
        source.api_slug(),
        replay.revision,
        upload_destination_namespace
    )
}

/// The sampled-acquisition scope of a cycle: the cursor and retained
/// namespace (pure; a continuation page must use the same bytes, K5).
pub(crate) fn cycle_sampled_scope(
    account_witness: &[u8; 32],
    upload_destination_namespace: &str,
    index_path: &Path,
    request_identity_capture: bool,
) -> crate::transcript_acquisition::Scope {
    // The trailing `false` is the retired context-curve flag; the scope bytes
    // are unchanged.
    let mut sampled_scope = format!(
        "sampled_scan:v1:{account_witness:?}:{upload_destination_namespace}:{}:false",
        index_path.display(),
    );
    if request_identity_capture {
        // A retained parser never crosses capture modes; the dark scope bytes
        // are unchanged.
        sampled_scope.push_str(":request_identity");
    }
    crate::transcript_acquisition::Scope(format!("{:x}", Sha256::digest(sampled_scope.as_bytes())))
}

#[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
fn prepare_sync_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
    account_witness: [u8; 32],
    retry_enabled: bool,
) -> Result<Option<SourcePreparation>> {
    let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(
        source == SnapshotSource::ClaudeCode,
    );
    let result = crate::local_resource_diagnostics::source_prepare(
        source.api_slug(),
        || {
            prepare_sync_source_inner(
                client,
                device,
                device_secret,
                source,
                machine_id,
                home,
                support_dir,
                daemon,
                transport_cycle,
                account_witness,
                retry_enabled,
            )
        },
        |result| {
            result
                .as_ref()
                .ok()
                .and_then(Option::as_ref)
                .is_some_and(|preparation| {
                    crate::snapshots::state_v2_growth_retention_active(&preparation.committed_index)
                })
        },
    );
    with_source_cadence_state(source, |cadence| {
        if let Some(pulse) = cadence.collection.as_mut() {
            pulse.prepare_outcome(result.as_ref().err());
        }
    });
    let counts = diagnostics.finish();
    if source == SnapshotSource::ClaudeCode {
        crate::local_resource_diagnostics::claude_reread::emit_without_lease(counts);
    }
    result
}

/// Preserve main's progress admission before any v1 containment. Published
/// custody must instead authenticate the route before progress can be renamed.
fn load_source_checkpoints(
    index_path: &Path,
    progress_path: &Path,
    source: SnapshotSource,
    support_dir: &Path,
    destination: &str,
    witness: SnapshotQuarantineWitness,
) -> Result<(
    ScanIndex,
    crate::snapshots::ScanIndexLoadOrigin,
    SnapshotUploadProgress,
)> {
    let custody = crate::snapshots::state_v2_custody_published(index_path)?;
    if custody {
        // Begin once at preparation admission. Claim-only nested loads must
        // preserve the pass's measurements rather than start another pass.
        crate::snapshots::state_v2_pass_start();
    }
    if !custody {
        // A busy progress owner refuses the pass before any v1 containment.
        drop(SnapshotProgressLock::acquire(progress_path)?);
    }
    let (index, origin) =
        ScanIndex::load_for_snapshot_source_with_custody(index_path, source, support_dir, custody)?;
    crate::snapshots::state_v2_before_collection(&index)?;
    index.require_persistence_available()?;
    // A first import may publish during this load: progress follows the index.
    let progress = SnapshotUploadProgress::load_for_index(
        &index,
        index_path,
        progress_path,
        destination,
        witness,
    )?;
    Ok((index, origin, progress))
}

#[allow(
    clippy::too_many_arguments,
    reason = "preparation retains the cycle transport, identity and resource inputs"
)]
fn prepare_sync_source_inner(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
    account_witness: [u8; 32],
    retry_enabled: bool,
) -> Result<Option<SourcePreparation>> {
    if let Some(remaining) = source_upload_backoff_remaining(source) {
        // The server asked for room and we said yes. Re-running the cycle now
        // would scan, re-derive and re-POST the same pages it just shed, which is
        // precisely the loop the backoff exists to break. No status receipt: the
        // last one still describes reality, and the check-in heartbeat keeps
        // freshness alive on its own clock.
        eprintln!(
            "local snapshot sync deferred for {}: backend backoff has {}s remaining",
            source.api_slug(),
            remaining.as_secs()
        );
        return Ok(None);
    }
    let mut scan_started_at = current_rfc3339();
    let relay_token = client.issue_status_relay_token(device, device_secret, source)?;
    let mut activity_hint = small_source_upload(source, || client.get_activity_hint(&relay_token))?;
    // Treat the activity hint as the only authority for the semantic evidence
    // window. Missing/malformed hints already fail JSON decoding; future
    // out-of-contract widths fail here before any scan or receipt can
    // manufacture a fallback policy. Zero is an explicit tombstone control.
    let receipt_window_days = validated_receipt_window_days(activity_hint.backfill_window_days)?;
    let cache_observations_enabled = source != SnapshotSource::Pi
        && activity_hint.session_cache_observations_contract.as_deref()
            == Some("session_cache_observations:v1");
    // Contract 5 is always on: every Claude cycle captures markers and keeps
    // the Desktop census witness; the hint's identity token is never read.
    let request_identity_capture = crate::snapshots::claude_request_identity::captures(source);
    // The server's scan directive was parsed and discarded before this. It is a
    // cost lever, so it may only lengthen the local cadence (see
    // `negotiated_wait`), never shorten it.
    record_server_scan_directive(source, &activity_hint.recommended_scan_after);
    with_source_cadence(source, |cadence| {
        cadence.record_backend_hint(
            Instant::now(),
            activity_hint.record_count_15m,
            false,
            activity_hint.local_usage_reconciliation_enabled,
        )
    });
    // Cache the raw workspace policy for status and tracking eligibility together.
    daemon
        .record_reconciliation_enabled(
            source_kind(source),
            activity_hint.local_usage_reconciliation_enabled,
            receipt_window_days,
        )
        .map_err(|_| anyhow!("tracking state unavailable"))?;
    if receipt_window_days == 0 {
        withdraw_and_report_policy_stop(
            client,
            device,
            device_secret,
            support_dir,
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(0),
                state: CollectorState::PolicyTombstone,
            },
        )?;
        return Ok(None);
    }
    let agent_status_captured_at = current_rfc3339();
    let agent_status_expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| agent_status_captured_at.clone());
    let scan_agent_status_collection = crate::agent_status_refresh::collection(
        &source_kind(source),
        agent_status_captured_at,
        agent_status_expires_at,
        false,
    )?;
    // Standalone/manual one-shot sync has no periodic daemon owner. Preserve
    // its original status upload without restoring the automatic duplicate.
    if !crate::agent_status_refresh::active() {
        if let Err(error) = upload_agent_status(
            client,
            &relay_token,
            machine_id,
            &scan_agent_status_collection.snapshots,
        ) {
            transport_cycle.note_error(&error);
            eprintln!("local agent status upload skipped: {}", safe_error(&error));
            if error.downcast_ref::<UploadShed>().is_some() {
                return Err(error);
            }
        }
    }

    // The configured-MCP context-footprint harvest runs on its own slower
    // schedule (run-at-start + every 6 h, `spawn_mcp_inventory_sync_for_daemon`),
    // NOT on the 5-minute snapshot sync: each harvest spawns every configured
    // MCP server's stdio process, so doing it every cycle would be needlessly
    // intrusive and re-POST unchanged inventories 12×/hour. See
    // `crate::mcp_inventory`.

    if !activity_hint.local_usage_reconciliation_enabled {
        withdraw_and_report_policy_stop(
            client,
            device,
            device_secret,
            support_dir,
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(receipt_window_days),
                state: CollectorState::Disabled(Some("disabled_by_admin".to_string())),
            },
        )?;
        return Ok(None);
    }

    // Status acquisition/upload runs on its independent source owner. The
    // reconciliation policy cache and the
    // active-session projection are all cheap and all product-visible. The
    // negotiated cadence gates what is actually expensive — the local transcript
    // scan below, which re-reads every changed transcript on this machine.
    if let Some(remaining) = source_cadence_wait(source) {
        eprintln!(
            "local snapshot scan deferred for {}: next scan in {}s on the negotiated cadence; power={:?} effective_interval={}s",
            source.api_slug(),
            remaining.as_secs(),
            continuation::MacPlatformSignals::default().power(),
            with_source_cadence(source, |cadence| cadence.ordinary_interval().min(MAX_CYCLE_INTERVAL))
                .unwrap_or(SNAPSHOT_SYNC_INTERVAL).as_secs()
        );
        return Ok(None);
    }

    let roots = crate::snapshot_roots::scan_roots(
        source,
        home,
        &scan_agent_status_collection.codex_scan_homes,
    )?;
    let mut encoded_attribution_key = activity_hint.session_attribution_hmac_key.take();
    let attribution_context = SessionAttributionContext::from_activity_hint(
        source,
        home,
        activity_hint.session_attribution_enabled,
        encoded_attribution_key.as_deref(),
        activity_hint
            .session_attribution_hmac_key_version
            .as_deref(),
    );
    if let Some(encoded_key) = encoded_attribution_key.as_mut() {
        encoded_key.zeroize();
    }
    if source == SnapshotSource::ClaudeCode {
        // A key change is scrubbed where a stored reduction loads
        // (`tail_source::load`): every parse, cursor and count stays, so a
        // server hint never causes a re-read.
        crate::snapshots::claude_request_identity::bind_session_context_key(
            attribution_context.as_ref(),
        );
    }
    let upload_policy = SnapshotUploadPolicy::from_hint(&activity_hint);
    let upload_destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    let receipt_client = client
        .clone()
        .with_receipt_destination_namespace(upload_destination_namespace.clone());
    let checkpoint_namespace = attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    let upload_context = cycle_upload_context(
        upload_policy,
        checkpoint_namespace.as_deref(),
        cache_observations_enabled,
    );
    let base_upload_context = upload_context.clone();
    let claude = source == SnapshotSource::ClaudeCode;
    let copy_unproven_enabled =
        claude && activity_hint.copy_unproven_contract.as_deref() == Some("copy_unproven:v1");
    // Context adoption invalidates stale pending pages on capability downgrade.
    let upload_context = resumed_prefix_upload_context(upload_context, claude);
    let upload_context = copy_unproven_upload_context(upload_context, copy_unproven_enabled);
    let legacy_policy_index_path = legacy_policy_scoped_snapshot_index_path(
        support_dir,
        source,
        upload_policy,
        checkpoint_namespace.as_deref(),
    );
    let v1_index_path = snapshot_destination_scoped_index_path(
        &legacy_policy_index_path,
        &upload_destination_namespace,
    );
    // Adopt both the scan checkpoint and any in-flight accepted-page ledger
    // from the exact pre-v2 namespace. This keeps a normal upgrade—and an
    // upgrade after a partially acknowledged batch—from replaying history.
    if let Some(legacy_namespace) = attribution_context
        .as_ref()
        .map(SessionAttributionContext::legacy_cache_namespace)
    {
        let legacy_policy_index_path = legacy_policy_scoped_snapshot_index_path(
            support_dir,
            source,
            upload_policy,
            Some(&legacy_namespace),
        );
        let legacy_index_path = snapshot_destination_scoped_index_path(
            &legacy_policy_index_path,
            &upload_destination_namespace,
        );
        adopt_legacy_checkpoint_file(&legacy_index_path, &v1_index_path)?;
    }
    // State schema, resumable cursor, and CAS generation are v2-only. Keep the
    // old daemon's path immutable so an overlapping downgrade cannot clobber
    // a new daemon's proof or progress. Adopt the v1 scan checkpoint once, but
    // never adopt v1 upload progress: it lacks entity-grain ACK/quarantine.
    let v2_index_path = snapshot_v2_index_path(&v1_index_path);
    adopt_legacy_checkpoint_file(&v1_index_path, &v2_index_path)?;
    let destination_index_path = snapshot_destination_scoped_index_path(
        &snapshot_index_path(support_dir, source),
        &upload_destination_namespace,
    );
    let index_path = snapshot_v3_index_path(&destination_index_path);
    adopt_legacy_checkpoint_file(&v2_index_path, &index_path)?;
    let legacy_upload_progress_path = snapshot_upload_progress_path(&v2_index_path);
    let upload_progress_path = snapshot_upload_progress_path(&index_path);
    adopt_legacy_checkpoint_file(&legacy_upload_progress_path, &upload_progress_path)?;
    let (mut index, load_origin, mut upload_progress) = load_source_checkpoints(
        &index_path,
        &upload_progress_path,
        source,
        support_dir,
        &upload_destination_namespace,
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &upload_context),
    )?;
    let first_census_end = crate::backfill::record_first_census(
        support_dir,
        source,
        &upload_destination_namespace,
        &scan_started_at,
        load_origin == crate::snapshots::ScanIndexLoadOrigin::Missing,
    )?;
    // Missing-index import stays at generation zero until the first collection save.
    // A restart after the anchor save must admit against that same census end.
    if index.generation == 0 {
        if let Some(anchor) = first_census_end {
            scan_started_at = anchor;
        }
    }
    if source == SnapshotSource::ClaudeCode {
        daemon.transcript_cache.bind_withheld(&mut index);
    }
    upload_progress.recover_ack_retirement_handoff(
        &mut index,
        &index_path,
        &upload_progress_path,
    )?;
    upload_progress.configure_ack_capacity(&index);
    // Absent, quarantined or undecodable: every file would come back new. The
    // load origin decides it; an empty saved index counts too.
    let claude_index_loaded_fresh = load_origin.is_fresh(&index);
    if index_path.exists()
        && upload_progress.prune_pending_cache_head_orphans_from_loaded_index(&index)
    {
        upload_progress.save(&upload_progress_path)?;
    }
    // One serialization feeds both input digests: the traversal contract
    // (Claude) and the per-item proof's input record (every source).
    let policy_bytes = serde_json::to_vec(&upload_policy).expect("upload policy is serializable");
    if claude {
        claude_contract::prepare_context(
            &policy_bytes,
            checkpoint_namespace.as_deref(),
            cache_observations_enabled,
        );
    }
    continuation::observe(source, &upload_context, upload_policy);
    activate_source_upload_context(source, upload_context, &mut index, &mut upload_progress);
    index.copy_unproven_enabled = copy_unproven_enabled;
    index.set_copy_prefix_base_upload_context(claude.then_some(base_upload_context));
    index.note_upload_context_inputs(
        source,
        crate::snapshots::UploadContextInputs::new(
            &policy_bytes,
            checkpoint_namespace.as_deref(),
            cache_observations_enabled,
            copy_unproven_enabled,
            claude,
        ),
        upload_policy,
    );
    let backfill_state = load_backfill_state(support_dir);
    // Read before this cycle's replay claims a generation in the upload
    // ledger: only a generation an earlier cycle left there is evidence.
    let prior_claude_history = (source == SnapshotSource::ClaudeCode).then(|| {
        claude_prior_history(
            &backfill_state,
            &upload_destination_namespace,
            &upload_progress,
            &index_path,
            support_dir,
        )
    });
    note_claude_index_rebuild_for_destination(
        source,
        claude_index_loaded_fresh,
        &backfill_state,
        &upload_destination_namespace,
        &upload_progress,
        &index_path,
        support_dir,
    );
    if let Some(prior) = prior_claude_history {
        crate::snapshots::note_prior_history_unverified(
            prior == crate::snapshots::PriorHistory::Unverified,
        );
    }
    crate::local_resource_diagnostics::change_reason::index_loaded(
        source.api_slug(),
        claude_index_loaded_fresh,
        prior_claude_history,
    );
    let replay_generation = cycle_replay_generation(source, &upload_destination_namespace);
    // An unreadable backfill state arms no Claude replay and no replay-wide
    // scan window (StateMissing H1, N2).
    let backfill_pending =
        backfill_replay_pending(source, &backfill_state, &upload_destination_namespace);
    index.first_read_pending = backfill_pending;
    if !backfill_pending
        && index.prepare_snapshot_admission_reoffer(SNAPSHOT_QUARANTINE_RETRY_LIMIT_PER_CYCLE)
    {
        // Persist the one-shot policy adoption before progress or scan can
        // advance. Existing generation CAS rejects overlapping stale writers.
        index.save(&index_path)?;
    }
    let admission_reoffer_pending =
        index.snapshot_admission_reoffer_pending_for_scan(source, receipt_window_days);
    let mut legacy_reconciliation_pending = BTreeSet::new();
    if !backfill_pending && index.legacy_settlement_ledger_needs_migration() {
        let (armed, changed) = index.prepare_legacy_settlement_reconciliation(
            source,
            LEGACY_SETTLEMENT_RECONCILE_LIMIT_PER_CYCLE,
        );
        legacy_reconciliation_pending =
            index.legacy_settlement_reconciliation_pending_fingerprints();
        if changed {
            // The bounded cursor and armed identities are durable before the
            // disposable upload ledger can lease this cycle's retry page.
            index.save(&index_path)?;
            if !armed.is_empty() {
                eprintln!(
                    "ottto-service: re-armed {} ambiguous legacy snapshot revision(s) through the existing entity-ACK contract for {}; remaining revisions resume on later source cycles",
                    armed.len(),
                    source.api_slug()
                );
            }
        }
    }
    // Due exact refusal re-offers are reserved from the loaded, committed
    // index and saved below before any lease reaches the scan or uploader.
    let reoffer_now = reason_reoffer::now_unix_seconds();
    let reoffer_scope = reason_reoffer::Scope {
        index: &index,
        now: reoffer_now,
        window_start_unix_seconds: reoffer_now
            .saturating_sub(receipt_window_days.saturating_mul(86_400)),
    };
    if prepare_upload_progress_for_cycle_with_reoffer(
        &mut upload_progress,
        &index,
        &replay_generation,
        backfill_pending,
        Some(&reoffer_scope),
    ) {
        // Claim the new generation before the potentially long historical
        // scan. This prevents ACKs from the prior revision from suppressing
        // identical entities and gives overlapping writers a CAS boundary.
        upload_progress.save(&upload_progress_path)?;
    }
    let quarantine_retry_paths =
        save_terminal_contract_claims_for_scan(&mut index, &upload_progress, &index_path)?;
    index.refusal_exposure = upload_progress.refusal_exposure(current_unix_seconds());
    index.refusal_exposure.held_terminal_entities = index.snapshot_unproven_terminal_count();
    if !quarantine_retry_paths.is_empty() {
        crate::local_resource_diagnostics::traversal_point(
            "quarantine_retry",
            source.api_slug(),
            &serde_json::json!({"action": "enqueued", "count": quarantine_retry_paths.len()}),
        );
    }
    let active_legacy_reconciliation = upload_progress
        .active_quarantine_retries
        .intersection(&legacy_reconciliation_pending)
        .cloned()
        .collect::<BTreeSet<_>>();
    // Under this pass's sync lock, before the scan is built. Every source
    // replays when one is pending; true when it reset the index.
    let replay_dropped_entries =
        backfill_pending && index.prepare_historical_replay(replay_generation.clone());
    if let Some(prior_history) = prior_claude_history {
        note_claude_history_cutoff_for_cycle(
            &mut index,
            source,
            prior_history,
            &backfill_state,
            claude_index_loaded_fresh || replay_dropped_entries,
        );
    }
    // The committed state, before the scan advances it. A partial commit needs
    // both: which entries this scan produced, and which ones the server was
    // already known to hold.
    index.activate_effective_upload_body_witness_revision(cycle_body_witness_revision(source));
    if source == SnapshotSource::ClaudeCode {
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(support_dir);
        crate::snapshots::claude_request_money::e2::apply_money_rules(&mut index);
        // Observe the always-on contract BEFORE the committed baseline, so an
        // unaccepted/shed page keeps it and its latch. It re-owes no history.
        index.observe_claude_request_identity_contract(true);
    }
    let scan_window_days = scan_request_window_days(
        receipt_window_days,
        backfill_pending || admission_reoffer_pending,
    );
    let copy_prefix_scope = if source == SnapshotSource::ClaudeCode {
        match crate::snapshots::claude_copy_prefix_reread::prepare(
            &mut index,
            support_dir,
            &roots,
            &scan_started_at,
            scan_window_days,
        ) {
            Ok(paths) => paths,
            Err(_) => {
                eprintln!("local Claude copy-prefix re-read: request_refused=1");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    crate::local_resource_diagnostics::index_clone_start(source.api_slug());
    let mut committed_index = index.clone();
    let reoffer_paths =
        index.activate_reason_reoffer_retries(upload_progress.active_reason_reoffers.clone());
    let mut cooldowns = upload_progress.reason_reoffer_cooldowns(reoffer_now);
    if backfill_pending {
        cooldowns.retain(|_, cooldown| cooldown.input_change_only);
    }
    index.activate_reason_reoffer_cooldowns(cooldowns);
    stale_owed::rearm_held_probe_once(source, &upload_progress, &mut index);
    upload_progress.reselect_pending_cache_heads(&mut index, cache_observations_enabled);
    let mut watcher_hints = crate::snapshot_watcher::take_pending_snapshot_paths(source);
    // Leased unchanged files join the same bounded, revalidated hint queue.
    watcher_hints.paths.extend(reoffer_paths);
    watcher_hints.paths.extend(quarantine_retry_paths);
    if watcher_hints.overflowed {
        eprintln!(
            "local snapshot watcher hint queue overflowed for {}; durable traversal will reconcile",
            source.api_slug()
        );
    }
    // The initial hint/status relay token dies here; sends acquire fresh tokens.
    drop(relay_token);
    let retry_authority = if retry_enabled
        && !index.legacy_settlement_ledger_needs_migration()
        && legacy_reconciliation_pending.is_empty()
        && active_legacy_reconciliation.is_empty()
    {
        live_snapshot_retry::LiveAuthority::capture(
            source,
            home,
            support_dir,
            &activity_hint,
            &upload_destination_namespace,
            &backfill_state,
            client.api_base_seal(),
        )
    } else {
        None
    };
    let sampled_scope = cycle_sampled_scope(
        &account_witness,
        &upload_destination_namespace,
        &index_path,
        request_identity_capture,
    );
    #[cfg(unix)]
    crate::snapshots::begin_source_pass(
        &daemon.transcript_cache,
        support_dir,
        source,
        &index_path,
        &sampled_scope,
        request_identity_capture,
    );
    let mut scan = crate::snapshots::OwnedSourceScan::new_with_recovery_priority(
        source,
        &roots,
        index,
        &scan_started_at,
        scan_window_days,
        MAX_BACKFILL_FILES_PER_SOURCE,
        (source == SnapshotSource::ClaudeCode).then_some(support_dir),
        &watcher_hints.paths,
        watcher_hints.overflowed,
        &mut watcher_hints.list_all,
        request_identity_capture,
        &copy_prefix_scope,
        Some((daemon.transcript_cache.as_ref(), &sampled_scope)),
    )
    .with_sampled_acquisition(daemon.transcript_cache.clone(), sampled_scope.clone())
    .with_launch_events(home)
    .with_codex_versions(daemon.codex_versions.clone());
    // A walk already running keeps the request: the first pass after it lists.
    crate::snapshot_watcher::defer_listing(source, watcher_hints.list_all);
    scan.rehome_withheld_baseline(&mut committed_index)?;
    if source == SnapshotSource::ClaudeCode {
        scan = scan.with_line_observer("footprint", daemon.footprint_cwds.observer());
    } else if source == SnapshotSource::Codex {
        scan = scan.with_line_observer("codex_prelude", daemon.codex_preludes.observer(&roots));
    }
    Ok(Some(SourcePreparation {
        retry_authority,
        source,
        claude_scan_roots: (source == SnapshotSource::ClaudeCode).then_some(roots),
        account_witness,
        scan_started_at,
        activity_hint,
        receipt_window_days,
        cache_observations_enabled,
        scan_agent_status_collection: Some(scan_agent_status_collection),
        attribution_context,
        upload_policy,
        upload_destination_namespace,
        receipt_client,
        index_path,
        upload_progress_path,
        upload_progress,
        committed_index,
        backfill_state,
        backfill_pending,
        legacy_reconciliation_pending,
        active_legacy_reconciliation,
        scan: Some(scan),
    }))
}

/// Stage 1 (K1 a″, K2/P-1): what a Codex continuation page needs from the
/// ordinary prepare of the cycle that minted its ticket. The attribution
/// context is that cycle's own, moved out of its preparation, never copied
/// or re-decoded; the policy copies (hint, upload policy, receipt client)
/// carry no raw key. A ticket holds these for at most its fixed lifetime
/// (`continuation::ticket_lifetime`) and drops them, zeroizing the key, on
/// every other end. Charged as process-retained memory
/// (`continuation::retained_bound`).
struct ContinuationInputs {
    codex_preludes: std::sync::Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
    codex_versions: std::sync::Arc<crate::snapshots::codex_version::CodexVersionFeed>,
    account_witness: [u8; 32],
    activity_hint: crate::snapshot_client::ActivityHintResponse,
    receipt_window_days: u64,
    cache_observations_enabled: bool,
    /// The one status input a continuation page reads: its finish never runs.
    codex_scan_homes: Vec<PathBuf>,
    attribution_context: Option<SessionAttributionContext>,
    upload_policy: SnapshotUploadPolicy,
    upload_destination_namespace: String,
    receipt_client: SnapshotApiClient,
    index_path: PathBuf,
    upload_progress_path: PathBuf,
    evidence: Option<crate::snapshots::CodexContinuationEvidence>,
    runtime_context: continuation::RuntimeContext,
}

crate::heap_layout_bound::fields!(ContinuationInputs; codex_preludes, account_witness, activity_hint,
    receipt_window_days, cache_observations_enabled,
    codex_scan_homes, attribution_context, upload_policy,
    upload_destination_namespace, receipt_client, index_path, upload_progress_path, evidence, runtime_context; shared codex_versions);

impl ContinuationInputs {
    /// Whether the moved attribution context is present (tests read this
    /// instead of the context itself).
    #[cfg(test)]
    fn holds_attribution(&self) -> bool {
        self.attribution_context.is_some()
    }
}

fn continuation_finish_inputs<'a>(
    preparation: &'a mut SourcePreparation,
    scan: &'a mut SourceScanResult,
    remaining: Option<usize>,
    codex_preludes: &'a std::sync::Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
    codex_versions: std::sync::Arc<crate::snapshots::codex_version::CodexVersionFeed>,
) -> impl FnOnce(continuation::ContinuationTicket) -> Option<continuation::ContinuationTicket> + 'a
{
    move |ticket| {
        let evidence = scan.take_continuation_evidence()?;
        let mut inputs = take_continuation_inputs(preparation, codex_preludes, codex_versions);
        inputs.evidence = Some(evidence);
        let refusal = remaining.map_or("no_remaining", |_| "over_bound");
        let ticket = remaining.and_then(|limit| ticket.with_inputs(inputs, limit));
        crate::local_resource_diagnostics::codex_continuation_mint(
            ticket.as_ref().map_or(refusal, |_| "minted"),
        );
        ticket
    }
}
/// Stage 1 (K2): the continuation inputs of a just-finished ordinary Codex
/// page, taken before its finish. `finish_sync_source` never reads the
/// attribution context, so moving it out changes nothing for the finish.
/// Called only while continuation pages are enabled and a ticket was minted.
fn take_continuation_inputs(
    preparation: &mut SourcePreparation,
    codex_preludes: &std::sync::Arc<crate::codex_prelude_footprint::CodexPreludeFeed>,
    codex_versions: std::sync::Arc<crate::snapshots::codex_version::CodexVersionFeed>,
) -> ContinuationInputs {
    let mut activity_hint = preparation.activity_hint.clone();
    // The prepare took the raw key out of its hint already; never keep one.
    if let Some(mut key) = activity_hint.session_attribution_hmac_key.take() {
        key.zeroize();
    }
    ContinuationInputs {
        codex_preludes: std::sync::Arc::clone(codex_preludes),
        codex_versions,
        evidence: None,
        runtime_context: continuation::runtime_context(),
        account_witness: preparation.account_witness,
        activity_hint,
        receipt_window_days: preparation.receipt_window_days,
        cache_observations_enabled: preparation.cache_observations_enabled,
        codex_scan_homes: preparation
            .scan_agent_status_collection
            .as_ref()
            .map(|collection| collection.codex_scan_homes.clone())
            .unwrap_or_default(),
        attribution_context: preparation.attribution_context.take(),
        upload_policy: preparation.upload_policy,
        upload_destination_namespace: preparation.upload_destination_namespace.clone(),
        receipt_client: preparation.receipt_client.clone(),
        index_path: preparation.index_path.clone(),
        upload_progress_path: preparation.upload_progress_path.clone(),
    }
}

/// Stage 1 (K1.1): why a continuation page refused before reading any
/// transcript. Each state changes only through an ordinary prepare, so the
/// paused job waits in its slot for the ordinary pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContinuationRefusal {
    HistoricalReplay,
    AdmissionReoffer,
    LegacySettlement,
    UploadClaim,
    ReasonReoffer,
    EvidenceChanged,
}

impl ContinuationRefusal {
    fn label(self) -> &'static str {
        match self {
            Self::HistoricalReplay => "historical_replay_pending",
            Self::AdmissionReoffer => "admission_reoffer_pending",
            Self::LegacySettlement => "legacy_settlement_pending",
            Self::UploadClaim => "upload_progress_claim_needed",
            Self::ReasonReoffer => "reason_reoffer_active",
            Self::EvidenceChanged => "continuation_evidence_changed",
        }
    }
}

/// Stage 1 (K1, ruled a″): whether this cycle's ordinary prepare would claim
/// an upload-progress generation or lease a retry or re-offer (and save that
/// claim). Pure: it runs the ordinary selection on a copy, so its answer is
/// the mutating function's by construction, and nothing is persisted.
fn continuation_upload_claim_needed(
    upload_progress: &SnapshotUploadProgress,
    index: &ScanIndex,
    replay_generation: &str,
    reoffer: &reason_reoffer::Scope<'_>,
) -> bool {
    let mut probe = upload_progress.clone();
    prepare_upload_progress_for_cycle_with_reoffer(
        &mut probe,
        index,
        replay_generation,
        false,
        Some(reoffer),
    )
}

/// How a continuation page's scan ended, on the worker.
enum ContinuationScan {
    /// Refused before any transcript read: nothing was stepped or saved.
    Refused(ContinuationRefusal),
    /// The scan's own local admission refused a step.
    StepRefused,
    /// Completed without committing its job. `ticket` is the byte-budget
    /// pause's new ticket; `snapshots` how many snapshots the page produced
    /// (zero on every valid non-EOF end, K7.1). Nothing was saved.
    Uncommitted {
        ticket: Option<crate::snapshots::CodexCursorTicket>,
        snapshots: usize,
    },
}

fn run_continuation_scan(
    home: &Path,
    support_dir: &Path,
    cache: &std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    inputs: &mut ContinuationInputs,
    ordinary_equivalent: Option<Duration>,
    deadline: Instant,
) -> Result<ContinuationScan> {
    let current = continuation::runtime_context();
    let contexts = |value: continuation::RuntimeContext| value.map(|slot| slot.map(|v| v.0));
    let held = if contexts(inputs.runtime_context) != contexts(current) {
        "context_changed"
    } else if inputs.runtime_context != current {
        "policy_changed"
    } else if inputs.evidence.is_none() {
        "other"
    } else {
        "roster_changed"
    };
    if inputs.runtime_context != current
        || !inputs
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.content_unchanged())
    {
        crate::local_resource_diagnostics::codex_continuation(Some(held));
        return Ok(ContinuationScan::Refused(
            ContinuationRefusal::EvidenceChanged,
        ));
    }
    let mut preparation = match prepare_continuation_source(
        home,
        support_dir,
        cache,
        inputs,
        ordinary_equivalent,
        deadline,
    )
    .inspect_err(|_| crate::local_resource_diagnostics::codex_continuation(Some("other")))?
    {
        Ok(preparation) => preparation,
        Err(reason) => {
            crate::local_resource_diagnostics::codex_continuation(Some("other"));
            return Ok(ContinuationScan::Refused(reason));
        }
    };
    crate::local_resource_diagnostics::codex_continuation(None);
    loop {
        match preparation.step() {
            SourcePreparationStep::Pending(next) => preparation = next,
            SourcePreparationStep::Refused(mut refused, _) => {
                crate::local_resource_diagnostics::codex_continuation(Some("other"));
                inputs.attribution_context = refused.attribution_context.take();
                return Ok(ContinuationScan::StepRefused);
            }
            SourcePreparationStep::Complete {
                mut preparation,
                index: _,
                mut scan,
            } => {
                inputs.evidence = scan.take_continuation_evidence();
                inputs.attribution_context = preparation.attribution_context.take();
                return Ok(ContinuationScan::Uncommitted {
                    ticket: scan.continuation_ticket().cloned(),
                    snapshots: scan.snapshots.len(),
                });
            }
        }
    }
}

/// Stage 1 (K1, ruled a″): the continuation-local prepare. It is not
/// `prepare_sync_source`'s tail: it takes no watcher hint, spends no
/// per-cycle budget, saves nothing and never resets the index. Every state
/// that would need one of those refuses first, before C14 or any transcript
/// read (K1.1). The rest follows the ordinary prepare's order on the freshly
/// loaded index and upload progress, with the same-cycle cached inputs. On
/// `Ok(Ok(..))` the attribution context has moved into the preparation; on a
/// refusal it is still in `inputs`.
fn prepare_continuation_source(
    home: &Path,
    support_dir: &Path,
    cache: &std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    inputs: &mut ContinuationInputs,
    ordinary_equivalent: Option<Duration>,
    deadline: Instant,
) -> Result<std::result::Result<SourcePreparation, ContinuationRefusal>> {
    let source = SnapshotSource::Codex;
    let scan_started_at = current_rfc3339();
    let checkpoint_namespace = inputs
        .attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    let upload_context = cycle_upload_context(
        inputs.upload_policy,
        checkpoint_namespace.as_deref(),
        inputs.cache_observations_enabled,
    );
    let (mut index, _) =
        ScanIndex::load_for_snapshot_source_with_origin(&inputs.index_path, source, support_dir)?;
    index.require_persistence_available()?;
    let mut upload_progress = SnapshotUploadProgress::load_for_index(
        &index,
        &inputs.index_path,
        &inputs.upload_progress_path,
        &inputs.upload_destination_namespace,
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &upload_context),
    )?;
    upload_progress.configure_ack_capacity(&index);
    let backfill_state = load_backfill_state(support_dir);
    let replay_generation = cycle_replay_generation(source, &inputs.upload_destination_namespace);
    if backfill_replay_pending(
        source,
        &backfill_state,
        &inputs.upload_destination_namespace,
    ) {
        return Ok(Err(ContinuationRefusal::HistoricalReplay));
    }
    if index.snapshot_admission_reoffer_pending() {
        return Ok(Err(ContinuationRefusal::AdmissionReoffer));
    }
    if index.legacy_settlement_ledger_needs_migration()
        || !index
            .legacy_settlement_reconciliation_pending_fingerprints()
            .is_empty()
    {
        return Ok(Err(ContinuationRefusal::LegacySettlement));
    }
    let reoffer_now = reason_reoffer::now_unix_seconds();
    let claim_needed = continuation_upload_claim_needed(
        &upload_progress,
        &index,
        &replay_generation,
        &reason_reoffer::Scope {
            index: &index,
            now: reoffer_now,
            window_start_unix_seconds: reoffer_now
                .saturating_sub(inputs.receipt_window_days.saturating_mul(86_400)),
        },
    );
    if claim_needed {
        return Ok(Err(ContinuationRefusal::UploadClaim));
    }
    activate_source_upload_context(source, upload_context, &mut index, &mut upload_progress);
    // The ordinary selection's in-memory effects, on this page's own copy;
    // the probe above found no claim, so there is nothing to save.
    let claimed = prepare_upload_progress_for_cycle_with_reoffer(
        &mut upload_progress,
        &index,
        &replay_generation,
        false,
        Some(&reason_reoffer::Scope {
            index: &index,
            now: reoffer_now,
            window_start_unix_seconds: reoffer_now
                .saturating_sub(inputs.receipt_window_days.saturating_mul(86_400)),
        }),
    );
    if claimed {
        return Ok(Err(ContinuationRefusal::UploadClaim));
    }
    if !upload_progress.active_reason_reoffers.is_empty() {
        return Ok(Err(ContinuationRefusal::ReasonReoffer));
    }
    index.activate_effective_upload_body_witness_revision(cycle_body_witness_revision(source));
    // K3: as the ordinary prepare, before the scan advances it. It is dropped
    // here unless the page commits, and crosses to the parent only by move.
    crate::local_resource_diagnostics::index_clone_start(source.api_slug());
    let committed_index = index.clone();
    // No lease is active (refused above), so this only installs the empty
    // set, as the ordinary prepare does; there are no hint paths to take.
    let leased_paths =
        index.activate_reason_reoffer_retries(upload_progress.active_reason_reoffers.clone());
    debug_assert!(leased_paths.is_empty());
    index.activate_reason_reoffer_cooldowns(upload_progress.reason_reoffer_cooldowns(reoffer_now));
    stale_owed::rearm_held_probe_once(source, &upload_progress, &mut index);
    upload_progress.reselect_pending_cache_heads(&mut index, inputs.cache_observations_enabled);
    let roots = crate::snapshot_roots::scan_roots(source, home, &inputs.codex_scan_homes)?;
    // K5: reuse the ordinary page's namespace and durable pass, including GC/breaker state.
    let sampled_scope = cycle_sampled_scope(
        &inputs.account_witness,
        &inputs.upload_destination_namespace,
        &inputs.index_path,
        false,
    );
    let scan = crate::snapshots::OwnedSourceScan::new_continuation(
        &roots,
        index,
        &scan_started_at,
        scan_request_window_days(inputs.receipt_window_days, false),
        MAX_BACKFILL_FILES_PER_SOURCE,
        ordinary_equivalent,
        inputs.evidence.take(),
    )
    .with_continuation_deadline(deadline)
    .with_sampled_acquisition(std::sync::Arc::clone(cache), sampled_scope)
    .with_launch_events(home)
    .with_line_observer("codex_prelude", inputs.codex_preludes.observer(&roots))
    .with_codex_versions(inputs.codex_versions.clone());
    Ok(Ok(SourcePreparation {
        retry_authority: None,
        source,
        claude_scan_roots: None,
        account_witness: inputs.account_witness,
        scan_started_at,
        activity_hint: inputs.activity_hint.clone(),
        receipt_window_days: inputs.receipt_window_days,
        cache_observations_enabled: inputs.cache_observations_enabled,
        scan_agent_status_collection: None,
        attribution_context: inputs.attribution_context.take(),
        upload_policy: inputs.upload_policy,
        upload_destination_namespace: inputs.upload_destination_namespace.clone(),
        receipt_client: inputs.receipt_client.clone(),
        index_path: inputs.index_path.clone(),
        upload_progress_path: inputs.upload_progress_path.clone(),
        upload_progress,
        committed_index,
        backfill_state,
        backfill_pending: false,
        legacy_reconciliation_pending: BTreeSet::new(),
        active_legacy_reconciliation: BTreeSet::new(),
        scan: Some(scan),
    }))
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

/// The batch request around `snapshots` for this collector's source,
/// machine, version and upload policy.
pub(crate) fn snapshot_batch_request<T>(
    source: SnapshotSource,
    machine_id: &str,
    snapshots: Vec<T>,
    upload_policy: SnapshotUploadPolicy,
    client_report: crate::client_report::ClientReport,
) -> SnapshotBatchRequest<T> {
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: source.api_slug().to_string(),
        machine_id: machine_id.to_string(),
        collector_version: Some(collector_version()),
        snapshots,
        upload_policy,
        client_report,
    }
}

#[expect(clippy::too_many_arguments, reason = "13 args; no options struct yet")]
fn finish_sync_source(
    preparation: SourcePreparation,
    mut index: ScanIndex,
    mut scan_result: SourceScanResult,
    _client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    _source: SnapshotSource,
    machine_id: &str,
    _home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    _transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
    retry: &mut live_snapshot_retry::LiveRetryOwner,
) -> Result<()> {
    let _diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::finish_decision(
        preparation.source == SnapshotSource::ClaudeCode,
    );
    let SourcePreparation {
        retry_authority,
        source,
        claude_scan_roots,
        account_witness,
        scan_started_at,
        activity_hint,
        receipt_window_days,
        cache_observations_enabled,
        scan_agent_status_collection,
        attribution_context,
        upload_policy,
        upload_destination_namespace,
        receipt_client,
        index_path,
        upload_progress_path,
        mut upload_progress,
        mut committed_index,
        backfill_state,
        backfill_pending,
        legacy_reconciliation_pending,
        active_legacy_reconciliation,
        scan: _,
    } = preparation;
    let cache_full_replacement = cache_full_replacement_negotiated(source, &activity_hint);
    // Telemetry retention keeps the sessions this page names, read before any
    // page filter drops a snapshot.
    let telemetry_named = claude_scan_roots
        .as_ref()
        .map(|_| claude_evidence_session_ids(&scan_result.snapshots));
    let scan_agent_status_collection =
        scan_agent_status_collection.context("a continuation preparation reached its finish")?;
    let identity_item_cap = crate::snapshots::claude_request_identity::effective_item_cap(
        activity_hint.max_snapshot_item_bytes,
    );
    upload_progress
        .accepted_identity_buckets
        .bind_context(attribution_context.as_ref());
    upload_progress
        .accepted_identity_buckets
        .set_item_cap(identity_item_cap);
    upload_progress
        .accepted_identity_buckets
        .set_retained_enabled(
            source == SnapshotSource::ClaudeCode
                && activity_hint
                    .session_request_identity_retained_contract
                    .as_deref()
                    == Some(crate::snapshots::claude_request_identity::IDENTITY_RETAINED_CONTRACT),
        );
    upload_progress
        .accepted_identity_buckets
        .set_account_source_enabled(
            activity_hint
                .session_request_account_source_contract
                .as_deref()
                == Some(crate::snapshots::ACCOUNT_SOURCE_CONTRACT),
        );
    let state_v2_baseline = crate::snapshots::state_v2_baseline_release(&index_path, &index);
    // Resets the census-wait count on every exit that is not a capacity stop.
    let mut census_wait = ack_retention::CapacityStopCensusCount::begin(source);
    let client = &receipt_client;
    let codex_join_validator = scan_result.codex_joining_validator();
    let validate_joined = |snapshots: &[&SnapshotItem]| -> Result<()> {
        if let Some(validator) = &codex_join_validator {
            validator.validate(snapshots)?;
        }
        Ok(())
    };
    let state_v2_guard = crate::snapshots::state_v2_side_effect_guard(&index_path, &index);
    let recovery_save_guard = crate::snapshots::state_v2_recovery_save_guard(&index_path, &index)?;
    let ensure_destination_authority = || {
        ensure_snapshot_scan_authority(device, source, client, &account_witness, daemon)?;
        ensure_snapshot_destination_current(&upload_destination_namespace)?;
        if let Some(roots) = &claude_scan_roots {
            crate::snapshot_roots::validate_claude_roots(_home, roots)?;
        }
        Ok(())
    };
    let ensure_authority = || {
        state_v2_guard()?;
        ensure_destination_authority()
    };
    if let Some(validate_recovery_save) = recovery_save_guard.as_ref() {
        // The ordinary early census fence includes the external upload hold.
        // A held pass authenticates local recovery here before any upload IO.
        validate_recovery_save()?;
        ensure_destination_authority()?;
    } else {
        codex_scan_diagnostics::after_existing_census_fence(
            source,
            support_dir,
            ensure_authority,
            || codex_scan_diagnostics::write_fenced_census(support_dir, &scan_result, &index),
        )?;
    }
    let scan_agent_status = reconciliation_agent_status(&scan_agent_status_collection);
    // State advances only after the exact paged replay census and its upload
    // both finish. Incomplete pages persist their cursor in the destination
    // index and remain pending across restarts.
    let mut backfill_succeeded = backfill_pending && scan_result.census_complete;
    if backfill_pending && !backfill_succeeded {
        eprintln!(
            "local snapshot backfill remains pending for {}: census incomplete",
            source.api_slug(),
        );
    }

    // Backfill snapshots are appended after the live scan, so run the same
    // content-free effort enrichment over the combined set. Already-split live
    // buckets are naturally skipped because they now have multiple effort rows.
    // This must precede upload-policy stripping: parent/root references are
    // identity evidence needed locally even when the org disables attribution
    // labels on the wire.
    let mut claude_authority_disposition =
        crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    if source == SnapshotSource::ClaudeCode {
        let evidence_started = Instant::now();
        crate::snapshots::claude_request_identity::retain_root_accounts(
            &mut scan_result.snapshots,
            &index,
            machine_id,
        );
        let telemetry_window = upload_progress.seed_telemetry(
            support_dir,
            &activity_hint,
            &mut scan_result,
            &index,
            &upload_progress_path,
        )?;
        upload_progress.load_identity(
            (scan_result.snapshots.iter()).map(|item| item.source_session_id.as_str()),
        )?;
        let mut telemetry_ledger = upload_progress.telemetry_only.take();
        let reserve_cache_bytes = |item: &SnapshotItem| {
            if cache_observations_enabled || item.evidence_basis == Some("otel_only") {
                identity_cache_wire_reserve(item, &upload_progress, cache_full_replacement)
            } else {
                0
            }
        };
        let (mut disposition, census_withheld, stats) =
            apply_claude_local_evidence_to_scan_with_ledger_and_budget(
                support_dir,
                &mut scan_result,
                &mut index,
                Some(&upload_progress.accepted_identity_buckets),
                crate::snapshots::claude_request_identity::WireBudget {
                    max_item_bytes: identity_item_cap,
                    reservation: Some(&reserve_cache_bytes),
                },
                telemetry_window.zip(telemetry_ledger.as_deref_mut()),
            );
        upload_progress.telemetry_only = telemetry_ledger;
        scan_result.queue_side_call_hints(
            &mut index,
            claude_scan_roots.as_deref().unwrap_or_default(),
            receipt_window_days,
            &mut disposition,
        );
        // Copy-derived rows (#944): the bodies just built treat these
        // rows as never accepted; the ledger records that durably before any
        // upload, so a lost reply or restart cannot restore their proof.
        if upload_progress
            .accepted_identity_buckets
            .invalidate_copy_derived(&std::mem::take(&mut disposition.copy_invalidated))
        {
            upload_progress.save(&upload_progress_path)?;
        }
        if let Ok(counts) = serde_json::to_string(&stats) {
            eprintln!(
                "local snapshot sync: claude local evidence duration_ms={} cache_creation_rejected_interpretations_total={} counts={counts}",
                evidence_started.elapsed().as_millis(),
                crate::snapshots::claude_api_cache_creation_rejection_count(),
            );
        }
        if let Ok(counts) = serde_json::to_string(&stats.context_file_birth) {
            eprintln!("local snapshot sync: claude context basis counts={counts}");
        }
        claude_authority_disposition = disposition;
        if census_withheld {
            backfill_succeeded = false;
        }
    }
    // The history-upgrade emission seam: after the local evidence fold, before
    // every ordinary and correction upload path can see a held body.
    index.veto_claude_history_emission(source, &mut scan_result.snapshots);
    // Diagnostics only: counted from the finished bodies, borrowed.
    crate::local_resource_diagnostics::usage_gaps(source.api_slug(), &scan_result.snapshots);

    // Recheck after the potentially long scan, not only when status was
    // acquired. A cached login must not claim sessions created after a switch.
    let current_codex_bindings =
        crate::agent_status_refresh::current_codex_home_bindings(&scan_agent_status_collection);
    let cached_codex_login_changed = source == SnapshotSource::Codex
        && current_codex_bindings.len() != scan_agent_status_collection.codex_home_bindings.len();
    let creator_slots = (source == SnapshotSource::Codex)
        .then(crate::agent_status::registered_codex_creator_slots)
        .unwrap_or_default();
    let codex_diagnostics = scan_result.local_codex_diagnostics.as_mut();
    let deferred_accounts = index.bind_session_accounts_with_mixed(
        source,
        machine_id,
        &mut scan_result.snapshots,
        &current_codex_bindings,
        (
            &creator_slots,
            codex_diagnostics.map_or(&mut [0; 9], |d| &mut d.creator_slot_naming),
        ),
        &claude_authority_disposition.mixed_uploads,
    );
    claude_authority_disposition.defer_sessions(deferred_accounts);
    // Billing route annotation: after ownership is bound, before upload policy.
    // Process memory only; off, nothing runs.
    crate::snapshots::billing_route::annotate_session_billing_routes(
        &upload_destination_namespace,
        source,
        machine_id,
        &mut scan_result.snapshots,
        activity_hint.session_billing_route_contract.as_deref(),
    );

    // The Companion uses machine-local labels before upload policy clears them.
    let reconciliation_status = crate::agent_status_refresh::status_for_reconciliation(
        scan_agent_status,
        &current_codex_bindings,
        cached_codex_login_changed,
    );
    // Claude activity remains recent relative to the scan's observation
    // horizon, while future timestamps are bounded by the reconciliation clock.
    let tracking_episode = daemon.tracking_episode(&source_kind(source));
    let reconciled_at = current_rfc3339();
    let since = tracking_episode
        .as_ref()
        .and_then(|(_, since)| OffsetDateTime::parse(since, &Rfc3339).ok());
    let mut latest = None;
    let mut observe = |new, previous, within_ceiling| {
        latest = latest.max(crate::tracking_confirmation::parsed_activity_witness(
            since,
            new,
            previous,
            within_ceiling,
        ));
    };
    if crate::active_sessions::reconcile_with_registrations(
        support_dir,
        source,
        &scan_result.snapshots,
        Some(&reconciliation_status),
        (source == SnapshotSource::ClaudeCode).then_some(scan_started_at.as_str()),
        &reconciled_at,
        Some("local"),
        with_source_cadence(source, |cadence| {
            cadence.ordinary_interval().min(MAX_CYCLE_INTERVAL)
        })
        .unwrap_or(SNAPSHOT_SYNC_INTERVAL),
        crate::agent_status::claude_session_registrations,
        tracking_episode
            .as_ref()
            .map(|_| &mut observe as &mut dyn FnMut(_, _, _)),
    )
    .is_err()
    {
        eprintln!(
            "local active-session cache update skipped for {}",
            source.api_slug()
        );
    }

    // A scan completed even if the optional cache write failed or upload later fails.
    with_source_cadence_state(source, |cadence| {
        if let Some(pulse) = cadence.collection.as_mut() {
            pulse.complete(&reconciled_at);
        }
    });

    if let (Some((generation, _)), Some(at)) = (
        tracking_episode,
        latest.and_then(|at| at.format(&Rfc3339).ok()),
    ) {
        daemon
            .confirm_tracking_activity(&source_kind(source), generation, &at)
            .map_err(|_| anyhow!("tracking state unavailable"))?;
    }

    crate::snapshots::apply_upload_policy(source, &mut scan_result.snapshots, upload_policy);

    // Account-switch backfill cutoff (server-issued at claim completion): a
    // machine claimed by a different same-org user must not re-attribute the
    // previous owner's already-ingested history. Applies to everything headed
    // upstream this cycle — sessions whose activity ended strictly before the
    // cutoff are historical by definition, whichever scan produced them; live
    // sessions always have activity at/after the cutoff and pass untouched.
    let (skipped_before_cutoff, claude_cutoff_corrections) = if source == SnapshotSource::ClaudeCode
    {
        apply_backfill_cutoff_with_claude_corrections(
            &mut scan_result,
            &index,
            &claude_authority_disposition,
            &backfill_state,
        )
    } else {
        (
            apply_backfill_cutoff(&mut scan_result.snapshots, &backfill_state),
            Vec::new(),
        )
    };
    if skipped_before_cutoff > 0 {
        eprintln!(
            "ottto-service: skipped {} historical {} snapshot(s) that ended before the account-switch backfill cutoff",
            skipped_before_cutoff,
            source.api_slug(),
        );
    }
    scan_result.reconcile_codex_legacy_joining(
        &mut index,
        &committed_index,
        machine_id,
        |index, snapshots| {
            index.bind_session_accounts(source, machine_id, snapshots, &current_codex_bindings);
            // Checks a fingerprint an older release persisted, under that release's rules.
            crate::upload_policy::apply_upload_policy_v1(source, snapshots, upload_policy);
            apply_backfill_cutoff(snapshots, &backfill_state);
        },
    );
    backfill_succeeded &= scan_result.census_complete;
    let deferred_cache_head_identities = capture_deferred_cache_head_identities(
        source,
        &scan_result.snapshots,
        &upload_progress,
        cache_observations_enabled,
        activity_hint.snapshot_head_cas_required,
        &legacy_reconciliation_pending,
        &active_legacy_reconciliation,
        &claude_authority_disposition,
    );
    exclude_held_effective_body_witness_revision(
        &mut index,
        &scan_result.snapshots,
        &claude_authority_disposition,
    );
    prepare_codex_recovery_diagnostics(
        &mut scan_result,
        &index,
        &upload_progress.quarantined_fingerprints,
    );
    // Preserve current-proof/current-revision evidence before the finalizer
    // removes exact semantic no-ops. Held/account-filtered bodies are excluded.
    let claude_proof_correction_candidates = if source == SnapshotSource::ClaudeCode {
        index.capture_claude_proof_corrections(
            &mut scan_result,
            &claude_authority_disposition,
            |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &upload_progress,
                    cache_observations_enabled,
                    activity_hint.snapshot_head_cas_required,
                    &legacy_reconciliation_pending,
                    &claude_authority_disposition,
                )
            },
        )
    } else {
        Vec::new()
    };
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::reason_reoffer_pipeline_tests::prepare_probe_for_test(
        &mut scan_result.snapshots,
        &mut upload_progress,
    );
    finalize_scan_after_policy_with_body_witness(
        source,
        &mut scan_result,
        &mut index,
        |snapshot| {
            effective_snapshot_upload_body_witness(
                snapshot,
                &upload_progress,
                cache_observations_enabled,
                activity_hint.snapshot_head_cas_required,
                &legacy_reconciliation_pending,
                &claude_authority_disposition,
            )
        },
    );
    index.advance_empty_claude_proof_corrections(&scan_result);
    let mut capture_adopted = false;
    if source == SnapshotSource::Codex {
        capture_adopted = capture_codex_recovery_evidence(
            &mut index,
            &mut committed_index,
            &mut scan_result,
            &index_path,
            &upload_progress_path,
            ensure_authority,
        );
        backfill_succeeded &= scan_result.census_complete;
    }
    // An adopted capture moved this graph to the generation it saved, and the
    // guard built before it refuses that graph. Every later boundary takes a
    // new guard from the same constructor, as after any adopted save.
    let state_v2_guard = if capture_adopted {
        crate::snapshots::state_v2_side_effect_guard(&index_path, &index)
    } else {
        state_v2_guard
    };
    let ensure_authority = || {
        state_v2_guard()?;
        ensure_destination_authority()
    };
    // A parsed file can emit several legacy siblings. Only the persisted
    // migration lease may re-enter an ambiguous old identity this cycle; new
    // fingerprints and ordinary changed entities continue through normally.
    scan_result.snapshots.retain(|snapshot| {
        !legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint)
            || active_legacy_reconciliation.contains(&snapshot.snapshot_fingerprint)
    });
    // A long-lived poison item can keep upload progress around while unrelated
    // files continue changing. Drop quarantine revisions no longer represented
    // by the authoritative current index before any early upload error can
    // preserve them forever.
    let current_fingerprints = index.current_snapshot_fingerprints();
    if upload_progress.retain_current_quarantines_with_diagnostics(
        &current_fingerprints,
        &index,
        scan_result.local_codex_diagnostics.as_mut(),
    ) {
        upload_progress.save(&upload_progress_path)?;
    }
    if !scan_result.census_complete {
        // A stale prior manifest must not survive a lossy census. The healthy
        // siblings may still upload, but no source-wide agreement witness is
        // publishable until every discovered path was read completely.
        withdraw_source_manifest(&upload_destination_namespace, source);
    }
    let (manifest_window_start, manifest_window_end) =
        snapshot_manifest_window(&scan_result.census_window_end, receipt_window_days)?;
    // A bounded traversal may span process restarts. Its manifest is scoped to
    // the first tick's pinned census boundary, so every post-scan terminal
    // receipt must identify that same logical scan start rather than the later
    // resume attempt. This gives the backend an exact, restart-stable binding:
    // manifest.window_end == last_scan_started_at.
    let terminal_scan_started_at = manifest_window_end.as_str();

    // Persist the Companion-facing posture projection as soon as an
    // activity-hint-authorized local scan is complete and account-switch
    // filtering has been applied. This deliberately stays behind the master
    // `local_usage_reconciliation_enabled` collection switch: an unavailable
    // hint or explicit disable must not cause an offline bypass of user/org
    // policy. Once a scan is authorized, however, a later batch-upload failure
    // must not discard its machine-local evidence. Cache writes are best-effort
    // and never block usage sync; omit raw filesystem errors.
    if source == SnapshotSource::ClaudeCode
        && crate::context_posture::update_context_posture_cache(
            support_dir,
            &scan_result.snapshots,
            OffsetDateTime::now_utc(),
        )
        .is_err()
    {
        eprintln!(
            "local context-posture cache update skipped for {}",
            source.api_slug()
        );
    }

    // Keep the full local scan available to active-session/context-posture
    // consumers above, then remove only authority-demoting revisions at the
    // network boundary. They are not backend poison and are not counted as
    // accepted/quarantined upload settlement.
    let local_holds = LocalHoldSettlement::classify(
        source,
        &mut index,
        &mut scan_result,
        &claude_authority_disposition,
    );
    let locally_held_fingerprints = &local_holds.held_fingerprints;
    if let Some(validate_recovery_save) = recovery_save_guard {
        // Retry a consistent local delta before any upload/ACK. Reuse the
        // partial-checkpoint settlement rules: unACKed files stay owed, exact
        // durable receipts remain authoritative, and no manifest is published.
        withdraw_source_manifest(&upload_destination_namespace, source);
        checkpoint_partial_snapshot_index_with_audit_release(
            &index,
            &committed_index,
            &upload_progress,
            &scan_result.snapshots,
            Some(&scan_result),
            locally_held_fingerprints,
            &index_path,
            &upload_progress_path,
            || {
                validate_recovery_save()?;
                ensure_destination_authority()
            },
            None,
            Some(UnsettledUploadCause::UploadError),
            (source == SnapshotSource::ClaudeCode).then_some(AccountAuditRelease {
                previous: &committed_index,
                roots: claude_scan_roots.as_deref().unwrap_or_default(),
                backfill_window_days: receipt_window_days,
            }),
            // Pre-upload recovery: no proof corrections were drained yet.
            Default::default(),
        )?;
        // A new pass reconstructs external guards from the saved generation.
        return Err(anyhow!("state_v2_save_recovered_retry"));
    }
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_cache_probe_for_test(&mut scan_result.snapshots);

    let headless = |progress: &SnapshotUploadProgress, snapshot: &SnapshotItem| {
        snapshot.cache_observations.is_some()
            && !progress
                .accepted_cache_heads
                .contains_key(&cache_session_key(&snapshot.source_session_id))
    };
    let cache_head_groups = if cache_observations_enabled
        && (activity_hint.snapshot_head_cas_required
            || !legacy_reconciliation_pending.is_empty()
            || !upload_progress.pending_cache_heads.is_empty()
            || scan_result
                .snapshots
                .iter()
                .any(|snapshot| headless(&upload_progress, snapshot)))
    {
        cache_head_file_groups(&index)
    } else {
        BTreeMap::new()
    };
    let mut pending_cache_heads_changed = false;
    for identity in &deferred_cache_head_identities {
        pending_cache_heads_changed |= upload_progress.record_pending_cache_head_identity(
            identity.source_file_fingerprint.as_ref(),
            &identity.snapshot_fingerprint,
            &identity.session_key,
            &cache_head_groups,
            true,
        )?;
    }

    for snapshot in &mut scan_result.snapshots {
        if cache_observations_enabled && snapshot.cache_observations.is_some() {
            // Every headless patch is owed until its exact patched ACK with a
            // head is saved. Only a required head fails on a missing binding.
            let owed = headless(&upload_progress, snapshot);
            let required = activity_hint.snapshot_head_cas_required
                || legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint);
            pending_cache_heads_changed |=
                match upload_progress.record_pending_cache_head(snapshot, &cache_head_groups, owed)
                {
                    Err(_) if !required => false,
                    recorded => recorded?,
                };
        }
        prepare_snapshot_cache_for_upload(
            snapshot,
            &upload_progress,
            cache_observations_enabled,
            activity_hint.snapshot_head_cas_required,
            &legacy_reconciliation_pending,
        );
    }
    if pending_cache_heads_changed {
        // Durable before ordinary delivery can acquire a head or fail. The
        // obligation survives until both cache settlement and index save.
        upload_progress.save(&upload_progress_path)?;
    }
    upload_progress
        .reason_reoffer_counts
        .cooldown_conflict_deferred = index.reason_reoffer_cooldown_deferred_count();
    // One logical offer per leased refusal: its next deadline is at least
    // this first transmission + 24 h, and durable before it. A failed save
    // sends nothing.
    if upload_progress
        .extend_reason_reoffers_before_upload(&scan_result.snapshots, locally_held_fingerprints)
    {
        upload_progress.save(&upload_progress_path)?;
    }
    let attempted_reason_reoffers = upload_progress.active_reason_reoffers.clone();
    // Existing entities cannot authorize their first cache enrichment without
    // a producer-owned predecessor token. Probe the unchanged semantic body
    // through the existing CAS contract, omitting the additive cache patch.
    // Exact settled ACKs enter the same atomic progress ledger as normal pages.
    // Bootstrap and main upload must drain the same admitted subset. A larger
    // page stops through partial settlement only after those bodies can finish.
    let census_absent_upload_acks =
        upload_progress.complete_census_ack_retirements(&index, scan_result.census_complete);
    // Current scanner incidence grants live slots on a first install, too.
    // No absent ACK or unrelated entity borrows those slots.
    upload_progress.prepare_context_receipt_candidates(
        &index,
        &committed_index,
        &scan_result.snapshots,
    );
    scan_result.snapshots.sort_by_key(|item| {
        upload_progress
            .context_resend
            .is_catchup(&item.snapshot_fingerprint)
    });
    let ack_admission_limited =
        upload_progress.admit_upload_input(&mut scan_result.snapshots, &index);
    if matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex)
        && upload_progress.note_reprojected_context_refusals(&scan_result.snapshots)
    {
        upload_progress.save(&upload_progress_path)?;
    }
    upload_progress.context_receipt_candidates = index.file_upload_context_ack_candidates(
        &scan_result.snapshots,
        &upload_progress.covered_stale_bodies(),
    );
    upload_progress
        .context_resend
        .retain_candidates(&upload_progress.context_receipt_candidates);
    crate::local_resource_diagnostics::change_reason::propagate(source.api_slug(), &index);
    let probes = scan_result
        .snapshots
        .iter()
        .filter(|item| item.cache_observations.is_some() && item.cache_base_head_etag.is_none())
        .map(cache_head_probe)
        .collect::<Vec<_>>();
    let mut bootstrap_deferred = 0usize;
    let mut bootstrap_capacity_error = None;
    // One in-place resend budget for the whole source page: both bootstrap
    // stages and the main upload draw on it, so the page never waits more
    // than two resends and 10 s under the sync lock.
    let mut inplace_retry = InplaceRetryBudget::default();
    // One page upload, probe or main: preflight at the identity item cap,
    // authority around a fresh relay token, Codex joins, then the exact ACK.
    let upload_checked = |request: &SnapshotBatchRequest<&SnapshotItem>,
                          enforce_head_cas: bool|
     -> Result<crate::snapshot_client::SnapshotBatchResponse> {
        if let Err(reason) = crate::snapshots::validate_snapshot_batch_request_with_item_limit(
            request,
            identity_item_cap,
        ) {
            return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                reason,
            }));
        }
        ensure_authority()?;
        let token = client.issue_relay_token(device, device_secret, source)?;
        ensure_authority()?;
        validate_joined(&request.snapshots)?;
        let response = client.upload_batch_with_item_cap(
            &token,
            request,
            enforce_head_cas,
            identity_item_cap,
        )?;
        response.validate_entity_ack_with_head_cas(request, enforce_head_cas)?;
        Ok(response)
    };
    if !probes.is_empty() {
        // These failures precede the main upload's diagnostic. Preserve only
        // the existing typed, content-free cause and the fixed failing role.
        let log_bootstrap_failure = |role: &'static str| {
            move |error: &anyhow::Error| {
                if snapshot_upload_error_class(error).is_some() {
                    eprintln!(
                        "ottto-service: local snapshot cache-head bootstrap did not settle for {} — role={role}, {}",
                        source.api_slug(),
                        upload_failure_diagnostic(error)
                    );
                }
            }
        };
        let bootstrap_result = bootstrap_cache_heads_with_budget(
            &probes,
            source.api_slug(),
            &mut upload_progress,
            &mut inplace_retry,
            |snapshots, enforce_head_cas| {
                let request = snapshot_batch_request(
                    source,
                    machine_id,
                    snapshots.to_vec(),
                    upload_policy,
                    crate::client_report::ClientReport::empty(),
                );
                upload_checked(&request, enforce_head_cas)
            },
            |progress| progress.save(&upload_progress_path),
        )
        .inspect_err(log_bootstrap_failure("probe"));
        match bootstrap_result {
            Ok(deferred) => bootstrap_deferred = deferred,
            Err(error)
                if error
                    .downcast_ref::<ack_retention::AckSettlementRequired>()
                    .is_some() =>
            {
                // A local probe stop owes the same partial-index retirement
                // and cadence handling as a stop in the main uploader.
                bootstrap_capacity_error =
                    Some(error.context("cache-head bootstrap ACK settlement pending"));
            }
            // A probe outage owes the main uploader's outage custody and
            // partial checkpoint below.
            Err(error) if is_upload_outage(&error) => bootstrap_capacity_error = Some(error),
            Err(error) => return Err(error),
        }
        if bootstrap_capacity_error.is_none() {
            // A paced-out probe has no head token yet. Keep its existing
            // selection debt for the next pass rather than failing healthy
            // ordinary uploads or fabricating a predecessor token.
            scan_result.snapshots.retain(|item| {
                !upload_progress
                    .context_resend
                    .deferred
                    .contains(&item.snapshot_fingerprint)
            });
            let held = apply_bootstrapped_cache_heads(
                source.api_slug(),
                &mut scan_result.snapshots,
                &upload_progress,
            )
            .inspect_err(log_bootstrap_failure("apply"))
            .inspect_err(|_| {
                upload_progress.finish_reason_reoffers(
                    &attempted_reason_reoffers,
                    false,
                    source.api_slug(),
                );
            })?;
            index.substitute_file_upload_context_bodies(
                &mut upload_progress.context_receipt_candidates,
                &held,
            );
            let held = held.len();
            if held > 0 {
                eprintln!(
                "local snapshot cache-head bootstrap carried {held} held probe(s) for {} as exact quarantined bodies; siblings continue",
                source.api_slug()
            );
            }
        }
    }
    // The same hook every resend path calls; nothing held is left by now.
    index.retain_claude_history_emission_permitted(&mut scan_result.snapshots);
    if upload_progress.defer_held_quarantine_retries(&scan_result.snapshots, &index, source) {
        upload_progress.save(&upload_progress_path)?;
    }
    // After bootstrap set each base, so an answer never borrows a fresh head.
    let head_conflict_answers = attach_head_conflict_answers(
        &mut scan_result.snapshots,
        &upload_progress,
        current_unix_seconds(),
        |key| cache_full_replacement && index.head_conflict_owed(key),
    );
    if head_conflict_answers > 0 {
        eprintln!(
            "local snapshot upload answers {head_conflict_answers} head-CAS conflict challenge(s) for {} through the rescan handshake",
            source.api_slug()
        );
    }
    upload_progress.bind_telemetry_bodies(support_dir, &mut scan_result.snapshots);
    if scan_result
        .snapshots
        .iter()
        .any(|item| item.evidence_basis == Some("otel_only"))
    {
        upload_progress.save(&upload_progress_path)?;
    }
    let projected_pending_head_file_witnesses =
        upload_progress.pending_cache_head_file_witnesses(&index);
    let mut accepted = 0;
    let bootstrap_offer_finished = bootstrap_capacity_error.is_some();
    let upload_result = if let Some(error) = bootstrap_capacity_error {
        Err(error)
    } else {
        upload_resumable_batches_with_literal_families(
            &scan_result.snapshots,
            source.api_slug(),
            &mut upload_progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |snapshot| Some(snapshot.source_session_id.as_str()),
            |snapshot| {
                snapshot_upload_batch_class(
                    snapshot,
                    legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint),
                )
            },
            crate::snapshots::claude_request_money::request_owned_family_root,
            &mut inplace_retry,
            |snapshots| {
                // A first Codex/Claude scan can spend several minutes parsing local
                // history and retroactive backfill before the first upload. Relay
                // tokens are intentionally short-lived, so mint them at the network
                // boundary instead of reusing the pre-scan activity-hint token.
                // Leased, not read: exactly one in-flight batch may claim the
                // counters, and dropping the lease on any failure below leaves the
                // losses owed instead of stranded.
                let client_report = crate::client_report::lease();
                let request = snapshot_batch_request(
                    source,
                    machine_id,
                    snapshots.to_vec(),
                    upload_policy,
                    client_report.report().clone(),
                );
                let reconcile_class = request.snapshots.iter().all(|snapshot| {
                    legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint)
                });
                debug_assert!(
                    reconcile_class
                        || request.snapshots.iter().all(|snapshot| {
                            !legacy_reconciliation_pending.contains(&snapshot.snapshot_fingerprint)
                        }),
                    "legacy reconciliation must stay isolated at a batch boundary"
                );
                let mut response = upload_checked(&request, reconcile_class)?;
                response.bind_conflict_rescans(&request);
                let request_fingerprints = request
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect::<BTreeSet<_>>();
                require_normal_write_ack_for_legacy_reconciliation(
                    &response,
                    &request_fingerprints,
                    &legacy_reconciliation_pending,
                )?;
                // Clear only what this accepted request carried. A failed upload
                // leaves the counters in place so the losses are reported on the
                // next batch instead of vanishing with the request that died.
                client_report.commit();
                Ok(response)
            },
            |progress| progress.save(&upload_progress_path),
        )
        .and_then(|result| {
            if matches!(
                result,
                ResumableUploadResult::Completed
                    | ResumableUploadResult::Deferred { .. }
                    | ResumableUploadResult::Rejected { .. }
            ) {
                // A setup/account switch can replace the relay binding while a
                // long historical scan is uploading. Never commit destination A's
                // delivery cursor after the machine has moved to destination B.
                ensure_authority()?;
            }
            // Never certify omitted files as a completed scan. Drain admitted
            // bodies, then enter partial settlement with its typed local counts.
            ack_retention::require_settlement(result, ack_admission_limited, &upload_progress)
        })
        .map(|result| {
            with_retained_refusal_conflicts(
                with_bootstrap_deferred(result, bootstrap_deferred),
                &index,
                &upload_progress,
                reason_reoffer::now_unix_seconds(),
            )
        })
    };
    // The logical offer ends here; normal bounded HTTP retries happened inside.
    if !bootstrap_offer_finished {
        // Bootstrap already classified its failed logical offer. A routed
        // capacity stop must not count unattempted leases a second time.
        upload_progress.finish_reason_reoffers(
            &attempted_reason_reoffers,
            matches!(upload_result, Ok(ResumableUploadResult::Shed { .. })),
            source.api_slug(),
        );
    }
    // An outage (a transport failure, timeout or 5xx, or a plain shed) ends
    // the pass before the server answered for every body. Hold each body with
    // no exact ACK, hold or refusal in ordinary retryable custody, durably,
    // before the partial checkpoint below: its files and heads then commit,
    // and the next pass re-sends from the head instead of reading the file
    // again. No ACK, refusal or loss is recorded; the entities stay owed.
    let outage_retry_after = match &upload_result {
        Ok(ResumableUploadResult::Shed { retry_after }) => Some(*retry_after),
        Err(error) if is_upload_outage(error) => Some(None),
        _ => None,
    };
    if let Some(retry_after) = outage_retry_after {
        let before = upload_progress.clone();
        let retry_at = current_unix_seconds().saturating_add(shed_backoff(retry_after).as_secs());
        let held = upload_progress.hold_outage_bodies(&scan_result.snapshots, retry_at);
        if held > 0 {
            if upload_progress.save(&upload_progress_path).is_err() {
                // Nothing durable changed: the page stays owed as before.
                upload_progress = before;
            } else {
                crate::local_resource_diagnostics::traversal_point(
                    "quarantine_retry",
                    source.api_slug(),
                    &serde_json::json!({"reason": "outage", "count": held}),
                );
            }
        }
    }

    // Exact progress is durable before this seam. The same subsequent index
    // save carries settled file bodies and correction progress; local-state
    // errors cannot certify an uncertain ACK. UnACKed/held members stay owed.
    // Selection below may keep a drained member's committed entry; each save
    // then restores that member's debt (R2).
    let mut claude_proof_body_drains = crate::snapshots::ClaudeProofBodyDrains::default();
    if !upload_result.as_ref().err().is_some_and(|error| {
        snapshot_upload_error_class(error) == Some(SnapshotUploadErrorClass::LocalState)
    }) {
        claude_proof_body_drains = index.settle_claude_proof_corrections(
            &committed_index,
            &claude_proof_correction_candidates,
            &upload_progress.accepted_fingerprints,
            &upload_progress.accepted_body_witnesses,
        );
    }

    index.log_claude_proof_correction_debt();

    // The server may have accepted new entities even when the final result is a
    // timeout, a disabled response, or a later local-state failure. Withdraw
    // the pre-cycle cache for every outcome; completed/shed branches republish
    // only after their exact replacement index is durable.
    withdraw_source_manifest(&upload_destination_namespace, source);

    let mut upload_fully_settled = true;
    let mut deferred_entity_count = None;
    let mut resolved_permanent_rejections = false;
    let mut isolated_only = false;
    // Local-hold Completed/Deferred/Rejected subsets and selected-state
    // restoration below can omit a still-live file. Capture which retirement
    // obligations this full scan references before any selection (#794 F1).
    let ack_scan_referenced =
        upload_progress.ack_retirement_scan_references(&committed_index, &index);
    // Shed and upload-error partial checkpoint: save wholly settled files,
    // then release adopted ACK capacity against the full scan's references
    // (#778 R2-2). A failed save is logged and yields `None`; a failed
    // release fails the pass.
    let mut partial_checkpoint =
        |cause: UnsettledUploadCause, keep_adopted_for_retry: bool| -> Result<Option<ScanIndex>> {
            match checkpoint_partial_snapshot_index_with_audit_release(
                &index,
                &committed_index,
                &upload_progress,
                &scan_result.snapshots,
                Some(&scan_result),
                locally_held_fingerprints,
                &index_path,
                &upload_progress_path,
                || {
                    ensure_authority()?;
                    scan_result.validate_codex_checkpoint()
                },
                None,
                Some(cause),
                (source == SnapshotSource::ClaudeCode).then_some(AccountAuditRelease {
                    previous: &committed_index,
                    roots: claude_scan_roots.as_deref().unwrap_or_default(),
                    backfill_window_days: receipt_window_days,
                }),
                std::mem::take(&mut claude_proof_body_drains),
            ) {
                Ok(committable) => {
                    upload_progress.release_acks_after_partial_index_save_with_scan(
                        &upload_progress_path,
                        &committed_index,
                        &committable,
                        &ack_scan_referenced,
                        locally_held_fingerprints,
                        keep_adopted_for_retry,
                    )?;
                    Ok(Some(committable))
                }
                Err(error) => {
                    eprintln!(
                        "local snapshot partial scan checkpoint failed for {}: {}",
                        source.api_slug(),
                        safe_error(&error)
                    );
                    Ok(None)
                }
            }
        };
    // Telemetry retention follows only a completed upload: a rejected,
    // deferred, shed, disabled or failed page drops it even when it settles.
    let upload_completed = matches!(upload_result, Ok(ResumableUploadResult::Completed));
    match upload_result {
        Ok(ResumableUploadResult::Completed) => {
            clear_shed_streak(source);
            let settlement =
                settle_completed_upload(index, &committed_index, &upload_progress, &local_holds);
            index = settlement.index;
            if !settlement.fully_settled {
                backfill_succeeded = false;
                upload_fully_settled = false;
            }
        }
        Ok(
            outcome @ (ResumableUploadResult::Deferred { .. }
            | ResumableUploadResult::Rejected { .. }),
        ) => {
            let count = match outcome {
                ResumableUploadResult::Rejected { count } => {
                    resolved_permanent_rejections = true;
                    count
                }
                ResumableUploadResult::Deferred { count, isolated } => {
                    isolated_only = count == isolated;
                    count
                }
                _ => unreachable!(),
            };
            clear_shed_streak(source);
            let settlement = settle_checkpointed_upload(
                index,
                &committed_index,
                &upload_progress,
                &local_holds,
                resolved_permanent_rejections,
            );
            index = settlement.index;
            if !settlement.fully_settled {
                backfill_succeeded = false;
                upload_fully_settled = false;
            }
            deferred_entity_count = Some(count);
            eprintln!(
                "local snapshot upload checkpointed accepted siblings but left {count} \
                 unsettled entity(ies) pending for {}; a clean follow-up scan is required \
                 ({} page(s) settled with terminal-bound holds)",
                source.api_slug(),
                CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
        }
        Ok(ResumableUploadResult::Shed { retry_after }) => {
            let first_shed = Instant::now();
            let retry_after = note_shed_and_backoff(source, retry_after);
            defer_source_uploads(source, retry_after);
            let (checkpoint_succeeded, committable) =
                match partial_checkpoint(UnsettledUploadCause::Shed, true)? {
                    Some(committable) => (true, committable),
                    None => (false, committed_index),
                };
            if retry.enabled()
                && checkpoint_succeeded
                && locally_held_fingerprints.is_empty()
                && legacy_reconciliation_pending.is_empty()
                && active_legacy_reconciliation.is_empty()
            {
                if let Some(live) = retry_authority {
                    retry.capture_after_shed(
                        live,
                        _home,
                        source,
                        machine_id,
                        upload_policy,
                        account_witness,
                        &scan_result.snapshots,
                        &mut index,
                        &committable,
                        &upload_progress,
                        &index_path,
                        &upload_progress_path,
                        first_shed,
                        retry_after,
                    );
                }
            }
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&committable),
                    // `server_error` is the closest code the receipt contract
                    // carries; the loss report is where the shed is named
                    // precisely.
                    state: CollectorState::Error {
                        code: "server_error",
                        message: "backend shed the snapshot upload; honouring backoff",
                    },
                },
            )?;
            return Ok(());
        }
        Ok(ResumableUploadResult::Disabled(disabled_reason)) => {
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&index),
                    state: CollectorState::Disabled(
                        disabled_reason.or_else(|| Some("disabled_by_admin".to_string())),
                    ),
                },
            )?;
            return Ok(());
        }
        Err(error) => {
            // Earlier pages may have durable exact ACKs even though this pass
            // failed. Save their wholly settled files and release adopted ACK
            // capacity. Local-state failures leave durability
            // uncertain and must not certify an in-memory mutated ledger.
            if snapshot_upload_error_class(&error) != Some(SnapshotUploadErrorClass::LocalState) {
                if let Some(committable) =
                    partial_checkpoint(UnsettledUploadCause::UploadError, false)?
                {
                    index = committable;
                }
            }
            if snapshot_upload_error_class(&error).is_some() {
                eprintln!(
                    "ottto-service: local snapshot upload did not settle for {} — {}",
                    source.api_slug(),
                    upload_failure_diagnostic(&error)
                );
            }
            // Distinguish local serializer drift, authorization failures, and
            // backend payload rejection. The resumable driver has already
            // checkpointed every accepted sibling before this terminal error.
            let (state, context) = if let Some(settlement) =
                error.downcast_ref::<ack_retention::AckSettlementRequired>()
            {
                let incomplete_census_stops =
                    census_wait.capacity_stop(scan_result.census_complete);
                eprintln!(
                    "ottto-service: local snapshot upload deferred for {} — {} consecutive_incomplete_census_stops={}",
                    source.api_slug(),
                    upload_failure_diagnostic(&error),
                    incomplete_census_stops
                );
                (
                    settlement.collector_state(),
                    "local snapshot ACK settlement pending",
                )
            } else if snapshot_upload_error_class(&error)
                == Some(SnapshotUploadErrorClass::LocalState)
            {
                (
                    CollectorState::Error {
                        code: "scan_error",
                        message: "local snapshot checkpoint or destination state failed",
                    },
                    "local snapshot state failed",
                )
            } else if snapshot_upload_error_class(&error)
                == Some(SnapshotUploadErrorClass::BackendResponse)
            {
                (
                    CollectorState::Error {
                        code: "server_error",
                        message: "backend snapshot response did not match the request",
                    },
                    "backend snapshot response was invalid",
                )
            } else if let Some(rejected) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
                eprintln!(
                    "ottto-service: local snapshot batch failed daemon v{} contract preflight for {} — {}; usage/cost sync is NOT reaching the backend until the daemon serializer is fixed.",
                    SNAPSHOT_SCHEMA_VERSION,
                    source.api_slug(),
                    rejected.reason,
                );
                (
                    CollectorState::Error {
                        code: "backend_validation_error",
                        message: "local snapshot batch failed daemon/backend contract preflight",
                    },
                    "local snapshot batch failed daemon/backend contract preflight",
                )
            } else if let Some(rejected) = error.downcast_ref::<BatchAuthorizationRejected>() {
                eprintln!(
                    "ottto-service: snapshot batch authorization rejected by backend (HTTP {}) \
                     for {}; start setup or sign in from the Ottto app before retrying \
                     local usage sync.",
                    rejected.status,
                    source.api_slug(),
                );
                (
                    CollectorState::Error {
                        code: "auth_error",
                        message: "backend rejected snapshot batch authorization",
                    },
                    "backend rejected snapshot batch authorization",
                )
            } else if let Some(rejected) = error.downcast_ref::<BatchRejected>() {
                eprintln!("ottto-service: source={} {rejected}", source.api_slug());
                (
                    CollectorState::Error {
                        code: "backend_validation_error",
                        message: "backend rejected snapshot batch payload validation",
                    },
                    "backend rejected snapshot batch payload validation",
                )
            } else {
                // A shed request is not a network failure. 429 is unambiguous in
                // the redacted diagnostics today; 503 joins it with the typed
                // `Retry-After` handling, which is where the backoff itself
                // lives. The collector status code stays `network_error` — that
                // string is a backend contract, and only the loss category is
                // being classified here.
                ack_retention::record_upload_failure_loss(&error);
                // Everything above this arm names its own cause. This arm is
                // the catch-all, and it used to log the bare phrase "local
                // snapshot upload failed" with no status code, endpoint, or
                // body — which is undiagnosable from a log alone and cost a
                // full reverse-engineering pass to classify. Always emit the
                // redacted failure shape here: the typed transport/HTTP
                // diagnostic when the request reached the wire, and the
                // classified reason when it failed before that.
                eprintln!(
                    "ottto-service: local snapshot upload failed for {} — {}; \
                     daemon SNAPSHOT_SCHEMA_VERSION={}.",
                    source.api_slug(),
                    upload_failure_diagnostic(&error),
                    SNAPSHOT_SCHEMA_VERSION,
                );
                (
                    CollectorState::Error {
                        code: "network_error",
                        message: "local snapshot upload failed",
                    },
                    "upload local snapshots",
                )
            };
            with_source_cadence(source, |cadence| {
                ack_retention::record_upload_error_cadence(
                    cadence,
                    Instant::now(),
                    accepted,
                    &error,
                )
            });
            let _ = report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                support_dir,
                source,
                TerminalManifestSource::Withdraw,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: terminal_scan_started_at,
                    counts: SyncCounts::from_scan_result(
                        &scan_result,
                        accepted,
                        receipt_window_days,
                    )
                    .with_snapshot_terminal_counts(&index),
                    state,
                },
            );
            return Err(error.context(context));
        }
    }

    settle_index_after_upload(&mut index, &committed_index, &upload_progress);
    // Completed/checkpointed outcomes have now selected their retained file
    // facts. No-body completion must share that exact durable checkpoint.
    upload_fully_settled = finish_selected_settlement(
        &mut index,
        SelectedSettlementInputs {
            scan: &scan_result,
            committed_index: &committed_index,
            progress: &upload_progress,
            candidates: &claude_proof_correction_candidates,
            cutoff_candidates: &claude_cutoff_corrections,
            transport_fully_settled: upload_fully_settled,
            body_drains: claude_proof_body_drains,
            audit_release: (source == SnapshotSource::ClaudeCode).then_some(AccountAuditRelease {
                previous: &committed_index,
                roots: claude_scan_roots.as_deref().unwrap_or_default(),
                backfill_window_days: receipt_window_days,
            }),
        },
    );
    let mut retired_upload_acks = upload_progress.stage_selected_ack_retirement(
        &committed_index,
        &mut index,
        &ack_scan_referenced,
        locally_held_fingerprints,
        &census_absent_upload_acks,
    )?;
    // Every selected-state restoration above has finished. Retire the Claude
    // prior index before the full disk-index CAS decode.
    let context_rearm_counts = index.accept_file_upload_context_acks(
        &upload_progress.split_context_receipt_candidates(),
        &upload_progress.fresh_context_body_acks,
        &upload_progress.covered_stale_bodies(),
    );
    index.stamp_entity_upload_context_acks(
        &upload_progress.destination_namespace_hash,
        &upload_progress.accepted_body_witnesses,
        &upload_progress.accepted_body_contexts,
    );
    let telemetry_removed = claude_scan_roots.as_ref().map(|_| {
        crate::snapshots::claude_telemetry_retention::removed_index_keys(&committed_index, &index)
    });
    let retire_prior_index = source == SnapshotSource::ClaudeCode;
    #[cfg(test)]
    let retire_prior_index = retire_prior_index
        && !tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::keep_prior();
    let _committed_index = if retire_prior_index {
        drop(committed_index);
        None
    } else {
        Some(committed_index)
    };
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::prior_index_lifetime_tests::after_retirement(
        _committed_index.is_some(),
    );
    backfill_succeeded &= upload_fully_settled;
    // A quiet/delta-only scan still discloses current permanent refusals even
    // though no body needed another upload. The committed census owns scope.
    let current_entities = index.current_snapshot_fingerprints();
    let retained_permanent = upload_progress
        .permanent_rejections
        .keys()
        .filter(|fingerprint| current_entities.contains(*fingerprint))
        .count();
    if deferred_entity_count.is_none() && retained_permanent > 0 {
        deferred_entity_count = Some(retained_permanent);
        resolved_permanent_rejections = true;
    }
    // The whole ledger, before the current-entity prune below: a refusal from
    // this page that is not current still keeps its reported reason.
    let permanent_refusals = PermanentRefusalCounts::of(&upload_progress);
    index.finish_legacy_settlement_reconciliation();
    ensure_authority()?;
    scan_result.validate_codex_checkpoint()?;
    save_index_and_publish_manifest(
        &mut index,
        &index_path,
        &upload_destination_namespace,
        source,
        scan_result.census_complete,
        &manifest_window_start,
        &manifest_window_end,
    )?;
    scan_result.report_discovery_growth_after_save(&index);
    context_rearm_counts.emit(source);
    index.emit_upload_context_owed(source);
    #[cfg(unix)]
    crate::snapshots::after_source_save(
        &daemon.transcript_cache,
        support_dir,
        source,
        &mut index,
        &index_path,
    );
    if let Some(((roots, removed), named)) = claude_scan_roots
        .as_deref()
        .zip(telemetry_removed.as_ref())
        .zip(telemetry_named.as_deref())
        .filter(|_| upload_completed && upload_fully_settled)
    {
        crate::snapshots::claude_telemetry_retention::retire_claude_telemetry(
            support_dir,
            &index,
            roots,
            removed,
            named,
        );
    }
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("selected_save")?;
    // Tail state staged after this pass's last full save commits here, once.
    // On error the guard's drop discards and counts it; the next read replays
    // from the previous head. Never print private engine errors.
    if state_v2_baseline.commit_tail().is_err() {
        eprintln!("local tail state commit deferred for {}", source.api_slug());
    }
    // Maintenance is advisory: privacy deadlines alarm without failing an
    // otherwise committed collection cycle. Never print private engine errors.
    if crate::snapshots::maintain_state_v2_idle(
        &index_path,
        &index,
        scan_result.snapshots.is_empty(),
    )
    .is_err()
    {
        eprintln!("local state maintenance deferred for {}", source.api_slug());
    }
    // A completed cycle is what moves the tier: uploads keep a source warm, a
    // quiet cycle lets it fall to idle and then cold. A conflict pass durably
    // committed its accepted siblings and each held entity waits on its own
    // quarantine clock, so it is not a source failure; the failure ladder is
    // for upload errors. The sweep marker is stamped only for settled scans,
    // and the status below still reports the held entities.
    with_source_cadence(source, |cadence| {
        cadence.record_scan_success(Instant::now(), accepted)
    });
    let first_read_bootstrap = backfill_pending
        && crate::backfill::bootstrap_pending_for_destination(
            &backfill_state,
            source,
            &upload_destination_namespace,
        );
    if continuation::resident_scan_requested(&scan_result, first_read_bootstrap) {
        continuation::request_resident_scan(source, first_read_bootstrap);
    }

    // Refresh the per-source detected-uses cache the daemon health assembly
    // reads for the Companion's "Detected Uses" panel. The scan is incremental,
    // so this cycle's snapshots are a delta; the cache merge preserves
    // historical destinations. A failure here must never fail the sync, and the
    // error is not logged verbatim because it can embed a local filesystem path.
    if update_detected_uses_cache(support_dir, source, &scan_result.snapshots).is_err() {
        eprintln!(
            "local detected-uses cache update skipped for {}",
            source.api_slug()
        );
    }

    // StateMissing N2: a Claude census completed and settled under the
    // history gate clears the unverified marker. A fresh index recorded its
    // cutoff this cycle and an intact one keeps its entries, so the rebuilt
    // history stays gated; Claude's bootstrap and replays may then run.
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("unverified_marker")?;
    if claude_replay_suppressed(source, &backfill_state)
        && scan_result.census_complete
        && upload_fully_settled
    {
        if let Err(error) = crate::backfill::clear_prior_history_unverified(support_dir) {
            eprintln!(
                "local snapshot backfill state save failed for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
            return Err(anyhow!("local snapshot backfill state save failed"));
        }
    }

    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("backfill_completion")?;
    if backfill_succeeded {
        // Keep completion's reload, mutation and save atomic with claims,
        // list intent and deliberate installation reset.
        if let Err(error) = update_backfill_state(support_dir, |backfill_state| {
            mark_backfill_complete_for_destination(
                backfill_state,
                source,
                &upload_destination_namespace,
            );
            backfill_state.last_completed_at = Some(scan_started_at.clone());
        }) {
            eprintln!(
                "local snapshot backfill state save failed for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
            return Err(anyhow!("local snapshot backfill state save failed"));
        }
    }

    // Final scan/backfill markers are durable before page progress is retired.
    // Accepted cache evidence and head tokens remain in this same ACK-owned
    // ledger across successful cycles so later corrections can retract safely.
    upload_progress.retire_pending_cache_heads(
        &index,
        &scan_result.snapshots,
        locally_held_fingerprints,
        scan_result.census_complete,
        &projected_pending_head_file_witnesses,
    );
    upload_progress
        .permanent_rejections
        .retain(|fingerprint, refusal| {
            refusal.has_stale_debt() || current_entities.contains(fingerprint)
        });
    // Before `finish_cycle` retires this cycle's quarantine records.
    let retained_refusals = PermanentRefusalCounts::of(&upload_progress);
    let retained_downgrades = PermanentRefusalCounts::authority_downgrades(&upload_progress);
    log_retained_permanent_refusals(
        source,
        retained_refusals,
        retained_downgrades,
        upload_fully_settled,
    );
    upload_progress.add_saved_handoff_retirements(&mut retired_upload_acks, &index);
    upload_progress.retire_planned_acks_after_index_save(
        &index,
        &retired_upload_acks,
        locally_held_fingerprints,
    );
    #[cfg(test)]
    tests::permanent_finish_pipeline_tests::ack_post_save_failure("finish_cycle")?;
    upload_progress.finish_cycle(&upload_progress_path)?;
    crate::local_resource_diagnostics::pass_retained(source.api_slug(), || {
        daemon.transcript_cache.retained_heap_bytes(&index)
    });

    if let Some(count) = deferred_entity_count {
        let state = refused_entity_state(
            resolved_permanent_rejections,
            permanent_refusals,
            upload_fully_settled,
        );
        // The uploader drained its frozen, scan-capped queue before returning
        // `Deferred`, and the index above now owns both accepted siblings and
        // entity quarantine. Surface the conflict only after those
        // facts are durable: returning earlier would recreate the per-source
        // starvation wedge, while reporting success would hide the backend's
        // capacity condition from source-level isolation and cadence handling.
        let _ = report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            if scan_result.census_complete {
                TerminalManifestSource::CompleteCensus(&index)
            } else {
                TerminalManifestSource::Withdraw
            },
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: terminal_scan_started_at,
                counts: SyncCounts::from_scan_result(&scan_result, accepted, receipt_window_days)
                    .with_snapshot_terminal_counts(&index),
                state,
            },
        );
        if isolated_only {
            // Each refused body keeps its own exact retry custody; the sweep
            // stays unsettled, but the refusal no longer fails the pass.
            eprintln!(
                "local snapshot upload completed with {count} refused entity(ies) held for retry for {}",
                source.api_slug()
            );
        } else if !resolved_permanent_rejections {
            return Err(snapshot_entity_deferred(count));
        }
        // Permanent refusals remain disclosed after the durable save; a
        // reporting failure does not change the resolved transport outcome.
        return Ok(());
    } else {
        report_status_with_fresh_relay_token(
            client,
            device,
            device_secret,
            support_dir,
            source,
            if scan_result.census_complete {
                TerminalManifestSource::CompleteCensus(&index)
            } else {
                TerminalManifestSource::Withdraw
            },
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: terminal_scan_started_at,
                counts: SyncCounts::from_scan_result(&scan_result, accepted, receipt_window_days)
                    .with_snapshot_terminal_counts(&index),
                state: CollectorState::Success,
            },
        )?;
    }
    Ok(())
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

fn reconciliation_agent_status(collection: &AgentStatusCollection) -> &AgentStatusSnapshot {
    &collection.source_health_snapshot
}

fn claude_evidence_session_ids(snapshots: &[SnapshotItem]) -> Vec<String> {
    snapshots
        .iter()
        .flat_map(|snapshot| {
            std::iter::once(snapshot.source_session_id.clone()).chain(
                snapshot
                    .attribution_facts
                    .iter()
                    .filter(|fact| {
                        matches!(
                            fact.field.as_str(),
                            "parent_session_ref" | "root_session_ref"
                        )
                    })
                    .map(|fact| fact.value.clone()),
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn claude_evidence_root_session_ids(snapshots: &[SnapshotItem]) -> Vec<String> {
    snapshots
        .iter()
        .map(|snapshot| {
            snapshot
                .attribution_facts
                .iter()
                .find(|fact| fact.field == "root_session_ref")
                .map(|fact| fact.value.clone())
                .or_else(|| {
                    snapshot
                        .source_session_id
                        .split_once("_agent-")
                        .map(|(root, _)| root.to_string())
                })
                .unwrap_or_else(|| snapshot.source_session_id.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn trace_discard_count_is_zero(count: &u64) -> bool {
    *count == 0
}

/// Apply the exact local Claude API/trace evidence path used by production.
///
/// Kept as one shared derivation so privacy-safe offline audits cannot drift
/// from the sync loop's ownership, completeness, and quarantine semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeLocalEvidenceStats {
    pub requested_session_count: usize,
    pub candidate_root_count: usize,
    pub paired_sidecar_root_count: usize,
    pub complete_sidecar_root_count: usize,
    pub api_incomplete_root_count: usize,
    pub trace_incomplete_root_count: usize,
    /// Strict trace reads dropped as grown or replaced; absent while empty.
    #[serde(skip_serializing_if = "crate::claude_local_otel::ClaudeTraceRowsDiscarded::is_empty")]
    pub trace_rows_discarded: crate::claude_local_otel::ClaudeTraceRowsDiscarded,
    /// Items whose upload this page deferred because it discarded their
    /// family's strict trace read.
    #[serde(skip_serializing_if = "trace_discard_count_is_zero")]
    pub trace_discard_deferred_items: u64,
    pub api_evidence_row_count: usize,
    pub trace_evidence_row_count: usize,
    pub exact_request_set_root_count: usize,
    pub request_set_mismatch_root_count: usize,
    pub api_only_request_count: usize,
    pub trace_only_request_count: usize,
    pub identity_complete_session_count: usize,
    pub request_index_complete_session_count: usize,
    pub explicit_owned_start_session_count: usize,
    pub session_exclusive_reported_usage_count: usize,
    pub effort_evidence_load_failed: bool,
    pub own_request_complete_root_count: usize,
    pub own_request_unknown_root_count: usize,
    /// Request-census shadow of a complete Claude terminal scan; absent
    /// otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_census: Option<crate::snapshots::ClaudeRequestCensusShadowCounts>,
    /// How this pass's Claude context scalars were decided (proof or file
    /// birth rule) and why any were withheld. Local only, never uploaded.
    /// Logged on its own line; kept out of this struct's serialized form so
    /// the counts line and snapshot-audit stay unchanged.
    #[serde(skip)]
    pub context_file_birth: crate::snapshots::ClaudeContextFileBirthCounts,
}

/// The ordinary evidence stage without identity ledger or wire budget inputs.
pub(crate) fn apply_claude_local_evidence_to_scan(
    support_dir: &Path,
    scan_result: &mut crate::snapshots::SourceScanResult,
    index: &mut ScanIndex,
) -> (
    crate::snapshots::ClaudeUsageAuthorityDisposition,
    bool,
    ClaudeLocalEvidenceStats,
) {
    apply_claude_local_evidence_to_scan_with_ledger_and_budget(
        support_dir,
        scan_result,
        index,
        None,
        Default::default(),
        None,
    )
}

/// The production evidence stage with this cycle's accepted-identity ledger.
#[cfg(test)]
pub(crate) fn apply_claude_local_evidence_to_scan_with_accepted_for_test(
    support_dir: &Path,
    scan_result: &mut crate::snapshots::SourceScanResult,
    index: &mut ScanIndex,
    accepted_identity_buckets: Option<&crate::snapshots::claude_request_identity::AcceptedBuckets>,
) -> (
    crate::snapshots::ClaudeUsageAuthorityDisposition,
    bool,
    ClaudeLocalEvidenceStats,
) {
    apply_claude_local_evidence_to_scan_with_ledger_and_budget(
        support_dir,
        scan_result,
        index,
        accepted_identity_buckets,
        Default::default(),
        None,
    )
}

// Test-only file repair at the real attachment/strict-read boundary. It
// changes no reader verdict or accumulator and has no production state.
#[cfg(test)]
thread_local! {
    static E2_AFTER_API_ATTACH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

// Test seam for the streamed-evidence equality arm: its reference keeps every
// scope root's rows and folds them whole, as one pass over every root would.
#[cfg(test)]
thread_local! {
    static WHOLE_CORPUS_EVIDENCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Test seam for the scope's reference: the next enrichment on this thread
// reads these roots beside the page's own, as a pass over every side-file
// root would.
#[cfg(test)]
thread_local! {
    static REFERENCE_ROOTS: std::cell::RefCell<Option<BTreeSet<String>>> =
        const { std::cell::RefCell::new(None) };
}

fn whole_corpus_evidence() -> bool {
    #[cfg(test)]
    if WHOLE_CORPUS_EVIDENCE.with(std::cell::Cell::get) {
        return true;
    }
    false
}

// Test seam for the chunked-evidence equality arm: its reference runs the
// whole page as one evidence chunk.
#[cfg(test)]
thread_local! {
    static ONE_EVIDENCE_CHUNK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Packed chunks run on this thread, reference arms excluded.
    static EVIDENCE_CHUNKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The release-timing reference: emitted folds released once at page end.
    static PAGE_END_RELEASE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Emitted folds released once at page end: the release-timing reference.
fn page_end_release() -> bool {
    #[cfg(test)]
    if PAGE_END_RELEASE.with(std::cell::Cell::get) {
        return true;
    }
    false
}

#[cfg(test)]
pub(crate) fn evidence_chunks_for_test() -> usize {
    EVIDENCE_CHUNKS.with(std::cell::Cell::get)
}

/// The whole page in one evidence chunk: the test references only.
fn one_evidence_chunk() -> bool {
    #[cfg(test)]
    if ONE_EVIDENCE_CHUNK.with(std::cell::Cell::get)
        || whole_corpus_evidence()
        || REFERENCE_ROOTS.with(|roots| roots.borrow().is_some())
    {
        return true;
    }
    false
}

/// One evidence chunk: the page slots of whole families, how many families,
/// and their side-file bytes (`None`: a size could not be read).
struct ClaudeEvidenceChunk {
    slots: Vec<usize>,
    families: usize,
    side_file_bytes: Option<u64>,
}

/// Next-fit packing of the page's families, in page order, into the chunks the
/// evidence body runs once each. The batch size is the page's largest family
/// by side-file bytes (file metadata only): a family is never split, and one
/// whose size cannot be read runs alone. An empty page is one empty chunk.
fn pack_claude_evidence_families(
    support_dir: &Path,
    items: &[SnapshotItem],
) -> Vec<ClaudeEvidenceChunk> {
    let mut families = crate::snapshots::claude_request_money::e2::page_families(items)
        .into_iter()
        .map(|(root, slots)| {
            let stem = crate::claude_local_otel::telemetry_stem(&root);
            let bytes = crate::claude_local_otel::telemetry_pair_bytes(support_dir, &stem);
            (slots, bytes.ok().map(|bytes| bytes.unwrap_or(0)))
        })
        .collect::<Vec<_>>();
    families.sort_unstable_by_key(|(slots, _)| slots[0]);
    let batch = families.iter().filter_map(|(_, bytes)| *bytes).max();
    let fits = |total: Option<u64>| {
        one_evidence_chunk()
            || total
                .zip(batch)
                .is_some_and(|(total, batch)| total <= batch)
    };
    let mut chunks = vec![ClaudeEvidenceChunk {
        slots: Vec::new(),
        families: 0,
        side_file_bytes: Some(0),
    }];
    for (slots, bytes) in families {
        let open = chunks.last_mut().expect("packing starts with one chunk");
        let total =
            (open.side_file_bytes.zip(bytes)).map(|(used, bytes)| used.saturating_add(bytes));
        if open.families == 0 || fits(total) {
            open.slots.extend(slots);
            open.families += 1;
            open.side_file_bytes = total;
        } else {
            chunks.push(ClaudeEvidenceChunk {
                slots,
                families: 1,
                side_file_bytes: bytes,
            });
        }
    }
    for chunk in &mut chunks {
        chunk.slots.sort_unstable();
    }
    chunks
}

/// What the chunks of one page share: its original carriers and the counters.
struct ClaudeEvidencePage<'p> {
    telemetry_window: Option<(telemetry_only::Window, &'p mut telemetry_only::Ledger)>,
    originals: &'p BTreeMap<String, crate::snapshots::SessionAccountEvidence>,
    request_owned_originals: &'p crate::snapshots::claude_request_identity::RequestOwnedOriginals,
    stats: ClaudeLocalEvidenceStats,
    /// Roots already counted: a scope root two chunks read counts once.
    counted_roots: BTreeSet<String>,
    /// Sessions withheld for an absent content twin, decided once over the
    /// whole page before copy decisions; every chunk's finish uses it.
    content_held: BTreeSet<String>,
    side_call_discovery: crate::snapshots::claude_request_money::e2::SideCallDiscovery,
}

/// The evidence stage over one page: its families are packed into chunks and
/// the evidence body runs once per chunk, so one chunk's rows are resident at
/// a time. Copy decisions, original carriers and census health run once over
/// the page; each chunk's emitted folds are released when it ends.
fn apply_claude_local_evidence_to_scan_with_ledger_and_budget(
    support_dir: &Path,
    scan_result: &mut SourceScanResult,
    index: &mut ScanIndex,
    accepted_identity_buckets: Option<&crate::snapshots::claude_request_identity::AcceptedBuckets>,
    wire_budget: crate::snapshots::claude_request_identity::WireBudget<'_>,
    telemetry_window: Option<(telemetry_only::Window, &mut telemetry_only::Ledger)>,
) -> (
    crate::snapshots::ClaudeUsageAuthorityDisposition,
    bool,
    ClaudeLocalEvidenceStats,
) {
    // Preserve this scan's original carrier independently from later request
    // logins; only a fully qualified mixed body may undo the legacy login veto.
    let originals = scan_result
        .snapshots
        .iter()
        .filter_map(|item| {
            item.session_account_evidence
                .clone()
                .map(|original| (item.source_session_id.clone(), original))
        })
        .collect();
    let request_owned_originals =
        crate::snapshots::claude_request_identity::capture_request_owned_originals(
            &scan_result.snapshots,
        );
    let mut page = ClaudeEvidencePage {
        telemetry_window,
        originals: &originals,
        request_owned_originals: &request_owned_originals,
        stats: ClaudeLocalEvidenceStats {
            requested_session_count: claude_evidence_session_ids(&scan_result.snapshots).len(),
            ..Default::default()
        },
        counted_roots: BTreeSet::new(),
        content_held: crate::snapshots::claude_request_money::e2::page_content_holds(
            &scan_result.snapshots,
            index,
        ),
        side_call_discovery: crate::snapshots::claude_request_money::e2::SideCallDiscovery::new(
            scan_result
                .completed_parses()
                .map(|(key, _)| Path::new(key)),
        ),
    };
    // The named fork parents, whatever route the copy decisions take.
    let fork_parents = crate::snapshots::claude_cross_root_evidence::EvidenceScope::fork_parents(
        &scan_result.snapshots,
    );
    // `e2`: every held copy skip is decided (or the session held) before
    // telemetry attaches, so a copy that counts after all can be matched.
    crate::snapshots::claude_request_money::e2::decide_page_copies_planned(
        &mut scan_result.snapshots,
        index,
        accepted_identity_buckets,
        &page.content_held,
    )
    .apply(index);
    // Footprint window of the whole stage, once per page; each chunk's read,
    // fold and step windows nest inside it. Local diagnostics only.
    let evidence_window = crate::local_resource_diagnostics::StageWindow::begin(
        "claude_code",
        "claude_local_evidence",
    );
    let chunks = pack_claude_evidence_families(support_dir, &scan_result.snapshots);
    #[cfg(test)]
    if !one_evidence_chunk() && !page_end_release() {
        EVIDENCE_CHUNKS.with(|count| count.set(count.get() + chunks.len()));
    }
    // Each session's first page slot: chunk outputs go back in page order.
    let first_slot = (scan_result.snapshots.iter().enumerate().rev())
        .map(|(slot, item)| (item.source_session_id.clone(), slot))
        .collect::<BTreeMap<_, _>>();
    let mut slots = std::mem::take(&mut scan_result.snapshots)
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    let mut restored = (0..slots.len())
        .map(|_| None)
        .collect::<Vec<Option<SnapshotItem>>>();
    let location =
        |item: &SnapshotItem| (item.claude_money.as_deref()).and_then(|fold| fold.location_key());
    let mut disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    for chunk in chunks {
        scan_result.snapshots = (chunk.slots.iter())
            .map(|&slot| slots[slot].take().expect("each slot is in one chunk"))
            .collect();
        let keys = (scan_result.snapshots.iter())
            .map(|item| (item.source_session_id.clone(), location(item)))
            .collect::<Vec<_>>();
        let roots = claude_evidence_root_session_ids(&scan_result.snapshots)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let chunk_fork_parents = (fork_parents.iter())
            .filter(|(root, _)| roots.contains(root))
            .cloned()
            .collect();
        let evidence_mem = crate::local_resource_diagnostics::EvidenceMem::of_chunk(
            chunk.families,
            chunk.side_file_bytes,
        );
        disposition.absorb(apply_claude_local_evidence_chunk(
            support_dir,
            scan_result,
            index,
            accepted_identity_buckets,
            wire_budget,
            &mut page,
            (chunk_fork_parents, evidence_mem),
        ));
        // The body only removes items (index unavailable, or an emitted
        // session's later path twins), keeping the rest in order: each
        // survivor goes back to its slot; a removed slot stays empty.
        let mut survivors = std::mem::take(&mut scan_result.snapshots)
            .into_iter()
            .peekable();
        for (&slot, (session, located)) in chunk.slots.iter().zip(&keys) {
            if survivors.peek().is_some_and(|item| {
                item.source_session_id == *session && location(item) == *located
            }) {
                restored[slot] = survivors.next();
            }
        }
        debug_assert!(
            survivors.next().is_none(),
            "the evidence body only removes items"
        );
        // After the restore, which matches on the folds: no later chunk or
        // page step reads an emitted fold, so its inputs go with its chunk.
        if !page_end_release() {
            for &slot in &chunk.slots {
                if let Some(item) = restored[slot].as_mut() {
                    release_emitted(item);
                }
            }
        }
    }
    scan_result.snapshots = restored.into_iter().flatten().collect();
    disposition
        .copy_invalidated
        .sort_by_key(|row| first_slot.get(row.session()).copied());
    disposition
        .side_call_hints
        .extend(page.side_call_discovery.hints);
    let ClaudeEvidencePage { mut stats, .. } = page;
    for item in &scan_result.snapshots {
        if !item.source_session_id.contains("_agent-") {
            match item.provenance.collector.as_str() {
                crate::snapshots::claude_request_accounts::COMPLETE => {
                    stats.own_request_complete_root_count += 1
                }
                crate::snapshots::claude_request_accounts::UNKNOWN => {
                    stats.own_request_unknown_root_count += 1
                }
                _ => {}
            }
        }
    }
    stats.identity_complete_session_count = scan_result
        .snapshots
        .iter()
        .filter(|item| item.claude_context_curve_identity_complete)
        .count();
    stats.request_index_complete_session_count = scan_result
        .snapshots
        .iter()
        .filter(|item| item.claude_context_curve_request_index_complete)
        .count();
    stats.explicit_owned_start_session_count = scan_result
        .snapshots
        .iter()
        .filter(|item| item.claude_context_curve_owned_start_proven)
        .count();
    stats.session_exclusive_reported_usage_count = scan_result
        .snapshots
        .iter()
        .filter(|item| {
            item.usage_accounting_contract.as_deref() == Some("session_exclusive_reported_usage:v1")
        })
        .count();
    stats.request_census = scan_result.claude_request_census_shadow;
    stats.context_file_birth = disposition.context_file_birth.clone();
    let window = crate::local_resource_diagnostics::StageWindow::begin(
        "claude_code",
        "evidence_census_health",
    );
    let census_withheld = index.account_claude_usage_authority_census_health(scan_result);
    drop(window);
    if census_withheld {
        // These revisions were fully readable, but uploading them would demote
        // a previously proven usage authority. Keep the census non-terminal
        // until a complete family pass reconstructs the exact witness. The
        // debt alone does not mark the sweep unsettled (path-(a) bridge): each
        // held revision settles or blocks on its own page, and full completion
        // stays pending while any RetryPending family remains.
        scan_result.census_complete = false;
        scan_result.scan_cap_hit = true;
    }
    if page_end_release() {
        scan_result.snapshots.iter_mut().for_each(release_emitted);
    }
    drop(evidence_window);
    (disposition, census_withheld, stats)
}

/// All local consumers of a chunk's bodies (finalizer, identity, account
/// qualification and the optional shadow) have finished. Release native
/// inputs only for emitted `e2` bodies before upload clones/checkpoints;
/// held and legacy bodies retain their inputs for their existing owners.
fn release_emitted(item: &mut SnapshotItem) {
    #[cfg(test)]
    crate::snapshots::claude_request_money::e2::pipeline_test_observer::before_release(item);
    // Route evidence only; captured before the native request inputs go.
    if crate::snapshots::billing_route::PRODUCER_ENABLED {
        crate::snapshots::billing_route::capture_claude_route_evidence(item);
    }
    crate::snapshots::claude_request_money::e2::release_emitted_fold(item);
}

/// The evidence body over one chunk (`scan_result`'s snapshots), from the API
/// read through account qualification; returns the chunk's disposition.
fn apply_claude_local_evidence_chunk(
    support_dir: &Path,
    scan_result: &mut SourceScanResult,
    index: &mut ScanIndex,
    accepted_identity_buckets: Option<&crate::snapshots::claude_request_identity::AcceptedBuckets>,
    wire_budget: crate::snapshots::claude_request_identity::WireBudget<'_>,
    page: &mut ClaudeEvidencePage<'_>,
    (fork_parents, mut evidence_mem): (
        Vec<(String, String)>,
        crate::local_resource_diagnostics::EvidenceMem,
    ),
) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
    let synthetic_roots = scan_result
        .snapshots
        .iter()
        .filter(|item| item.evidence_basis == Some("otel_only"))
        .map(|item| item.source_session_id.clone())
        .collect::<BTreeSet<_>>();
    let mut synthetic_healthy = BTreeSet::new();
    let builds_evidence = crate::snapshots::claude_request_identity::builds_evidence();
    let (originals, request_owned_originals) = (page.originals, page.request_owned_originals);
    let stats = &mut page.stats;
    let session_ids = claude_evidence_session_ids(&scan_result.snapshots)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut read_window =
        crate::local_resource_diagnostics::StageWindow::begin("claude_code", "evidence_read");
    let mut api_read = crate::claude_local_otel::ClaudeApiEvidenceRead::default();
    let api_load = crate::claude_local_otel::ClaudeApiEvidenceRead::load(support_dir, session_ids);
    match api_load {
        Ok(evidence) => {
            crate::snapshots::claude_request_money::e2::attach_page(
                &mut scan_result.snapshots,
                &evidence,
            );
            crate::snapshots::apply_claude_effort_evidence_with_index(
                &mut scan_result.snapshots,
                &evidence.evidence,
                index,
            );
            api_read = evidence;
        }
        Err(_) => {
            stats.effort_evidence_load_failed = true;
        }
    }
    evidence_mem.sample(0);
    #[cfg(test)]
    E2_AFTER_API_ATTACH.with(|hook| {
        if let Some(after_attach) = hook.borrow_mut().take() {
            after_attach();
        }
    });
    let telemetry_read_failed = stats.effort_evidence_load_failed;
    // Only the page's own roots keep their rows (both root spellings, so a
    // page family can never lose its own rows).
    let kept_roots = claude_evidence_root_session_ids(&scan_result.snapshots)
        .into_iter()
        .chain(scan_result.snapshots.iter().filter_map(|item| {
            crate::snapshots::claude_request_identity::owner_root(item).map(str::to_owned)
        }))
        .collect::<BTreeSet<_>>();
    // Summed CPU/wall sub-windows of evidence_read: the scope's census walk
    // and the cross-root summary build, and strict per-root decode. One
    // record each per pass.
    let mut cross_window =
        crate::local_resource_diagnostics::StageSum::begin("claude_code", "evidence_cross_root");
    // Side files are read for this page's scope only.
    let scope = cross_window.time(|| {
        crate::snapshots::claude_cross_root_evidence::EvidenceScope::of_page(
            &scan_result.snapshots,
            index,
            &kept_roots,
            fork_parents,
            &api_read.evidence,
        )
    });
    #[cfg(test)]
    let scope = match REFERENCE_ROOTS.with(std::cell::RefCell::take) {
        Some(roots) => crate::snapshots::claude_cross_root_evidence::EvidenceScope::every(
            kept_roots.iter().cloned().chain(roots),
        ),
        None => scope,
    };
    let usage_roots = scope.roots().cloned().collect::<Vec<_>>();
    // A root counts on its first read in the pass only.
    let fresh = (usage_roots.iter())
        .filter(|root| page.counted_roots.insert((*root).clone()))
        .cloned()
        .collect::<BTreeSet<_>>();
    stats.candidate_root_count += fresh.len();
    // A family kept on ordinary money (listed) reads its telemetry as gate off.
    let request_owned =
        |root: &str| crate::snapshots::claude_request_money::e2::family_applies(index, root, None);
    let mut identity_unhealthy_roots = BTreeSet::new();
    let usage_roots = usage_roots
        .into_iter()
        .filter(|session_id| {
            let paired = !crate::claude_local_otel::claude_effort_sidecar_fingerprint(
                support_dir,
                session_id,
            )
            .is_empty()
                && !crate::claude_local_otel::claude_trace_ownership_sidecar_fingerprint(
                    support_dir,
                    session_id,
                )
                .is_empty();
            // Attachment already consumed the permissive read. A later strict
            // reread may recover, but this page must not settle the earlier
            // incomplete attachment as final history.
            if request_owned(session_id)
                && paired
                && api_read
                    .session_report(session_id)
                    .is_some_and(|read| !read.complete)
            {
                identity_unhealthy_roots.insert(session_id.clone());
            }
            // Contract 5 must tell absent evidence from failed evidence.
            if !paired
                && !crate::claude_local_otel::claude_sidecars_absent(support_dir, session_id)
                && (builds_evidence || request_owned(session_id))
            {
                identity_unhealthy_roots.insert(session_id.clone());
            }
            paired
        })
        .collect::<Vec<_>>();
    stats.paired_sidecar_root_count += usage_roots
        .iter()
        .filter(|root| fresh.contains(*root))
        .count();

    // Release all non-paired rows before moving the selected roots into the
    // usage aggregate.
    let paired_roots: BTreeSet<String> = usage_roots.iter().cloned().collect();
    // Every root read adds its cross-root answers first, so the fold sees
    // the scope's answers.
    let mut cross = crate::snapshots::claude_cross_root_evidence::CrossRootEvidence::new(
        &scan_result.snapshots,
        scope,
    );
    let mut whole_corpus = whole_corpus_evidence().then(crate::snapshots::ClaudeVetoApiRows::new);
    // Context scalars only: API rows of roots without a sidecar pair still
    // veto (never prove) the file birth rule.
    let unpaired = api_read
        .evidence
        .keys()
        .filter(|root| !paired_roots.contains(*root))
        .cloned()
        .collect::<Vec<_>>();
    for root in unpaired {
        if let Some(rows) = api_read.evidence.remove(&root) {
            cross.add_vetoing_api(&root, &rows);
            if let Some(veto_api_rows) = whole_corpus.as_mut() {
                veto_api_rows.insert(root, rows);
            }
        }
    }
    api_read.retain_roots(&paired_roots);
    // Health is family-scoped: one malformed historical sidecar must make
    // that family unproven, not suppress an unrelated healthy family.
    let mut api_report = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let mut trace_report = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    // `e2`: roots whose strict API and trace reads were both healthy. A healthy
    // sidecar may hold no rows for the root, so evidence keys cannot say this.
    let mut strict_healthy_roots = BTreeSet::new();
    let mut trace_discarded_roots = BTreeSet::new();
    let mut decode_window =
        crate::local_resource_diagnostics::StageSum::begin("claude_code", "evidence_decode");
    cross_window.demanded_requests = Some(cross.request_roots.demand_count());
    for root_session_id in usage_roots {
        // A root another chunk already read counts nowhere.
        let mut reread = ClaudeLocalEvidenceStats::default();
        let stats = if fresh.contains(&root_session_id) {
            &mut *stats
        } else {
            &mut reread
        };
        let (mut api, mut trace) = decode_window.time(|| {
            let api = api_read.take_strict_report(support_dir, &root_session_id);
            let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                support_dir,
                [root_session_id.clone()],
            );
            (api, trace)
        });
        if !api.health.is_complete() {
            stats.api_incomplete_root_count += 1;
        }
        if !trace.is_complete() {
            stats.trace_incomplete_root_count += 1;
        }
        stats.trace_rows_discarded.add(&trace.rows_discarded);
        if !trace.rows_discarded.is_empty() {
            trace_discarded_roots.insert(root_session_id.clone());
        }
        if !api.health.is_complete() || !trace.is_complete() {
            if let Some(rows) = api.evidence.remove(&root_session_id) {
                cross.add_vetoing_api(&root_session_id, &rows);
                if let Some(veto_api_rows) = whole_corpus.as_mut() {
                    veto_api_rows.insert(root_session_id.clone(), rows);
                }
            }
            if builds_evidence || request_owned(&root_session_id) {
                identity_unhealthy_roots.insert(root_session_id);
            }
            continue;
        }
        if synthetic_roots.contains(&root_session_id) && trace.rows_discarded.is_empty() {
            synthetic_healthy.insert(root_session_id.clone());
        }
        stats.complete_sidecar_root_count += 1;
        if request_owned(&root_session_id) {
            strict_healthy_roots.insert(root_session_id.clone());
        }
        let api_request_ids = api
            .evidence
            .get(&root_session_id)
            .into_iter()
            .flatten()
            .map(|row| row.request_id.as_str())
            .collect::<BTreeSet<_>>();
        let trace_request_ids = trace
            .evidence
            .get(&root_session_id)
            .into_iter()
            .flatten()
            .map(|row| row.request_id.as_str())
            .collect::<BTreeSet<_>>();
        if api_request_ids == trace_request_ids {
            stats.exact_request_set_root_count += 1;
        } else {
            stats.request_set_mismatch_root_count += 1;
            stats.api_only_request_count += api_request_ids.difference(&trace_request_ids).count();
            stats.trace_only_request_count +=
                trace_request_ids.difference(&api_request_ids).count();
        }
        cross_window.time(|| {
            cross.add_root(
                &root_session_id,
                api.evidence.get(&root_session_id),
                trace.evidence.get(&root_session_id),
                &api_request_ids,
                &trace_request_ids,
            )
        });
        let api_rows = api.evidence.remove(&root_session_id);
        let trace_rows = trace.evidence.remove(&root_session_id);
        let keep = whole_corpus.is_some() || kept_roots.contains(&root_session_id);
        evidence_mem.note_root(
            api_rows.as_ref().map_or(0, Vec::len) + trace_rows.as_ref().map_or(0, Vec::len),
            keep,
        );
        if let Some(rows) = api_rows {
            stats.api_evidence_row_count += rows.len();
            if keep {
                api_report.evidence.insert(root_session_id.clone(), rows);
            }
        }
        if let Some(rows) = trace_rows {
            stats.trace_evidence_row_count += rows.len();
            if keep {
                trace_report.evidence.insert(root_session_id, rows);
            }
        }
    }
    evidence_mem.kept_rows = api_report.evidence.values().map(Vec::len).sum::<usize>()
        + trace_report.evidence.values().map(Vec::len).sum::<usize>();
    evidence_mem.legacy_owners = cross.legacy_request_owners.owner_count();
    evidence_mem.sample(1);
    cross_window.time(|| cross.finish());
    drop(decode_window);
    drop(cross_window);
    evidence_mem.sample(2);
    read_window.set_evidence_mem(evidence_mem);
    drop(read_window);
    let fold_window =
        crate::local_resource_diagnostics::StageWindow::begin("claude_code", "evidence_fold");
    // Nested footprint windows, one per fold step. Counts only.
    let step = |stage: &'static str| {
        crate::local_resource_diagnostics::StageWindow::begin("claude_code", stage)
    };
    let (synthetic, ordinary): (Vec<_>, Vec<_>) = std::mem::take(&mut scan_result.snapshots)
        .into_iter()
        .partition(|item| item.evidence_basis == Some("otel_only"));
    scan_result.snapshots = ordinary;
    let window = step("evidence_side_calls");
    // `e2` side calls need the trace-named owner, so they follow the trace read.
    let side_calls_unresolved = crate::snapshots::claude_request_money::e2::side_calls_page(
        &mut scan_result.snapshots,
        &api_report,
        &trace_report,
        index,
        &mut page.side_call_discovery,
    );
    let trace_discard_unfolded = {
        // Reuse the per-root read verdict before identity consumes it. Missing
        // sidecars are ordinary absence; partial pairs and failed strict reads
        // hold only that root's permitted owed history through the existing seam.
        index.hold_claude_history_for_unhealthy_telemetry_roots(&identity_unhealthy_roots);
        // A side-call census walk past its deadline decided nothing for its
        // families: the same seam keeps their owed history for a later page.
        index.hold_claude_history_for_unhealthy_telemetry_roots(&side_calls_unresolved);
        // A discarded strict trace read defers the family's bodies through the
        // `e2` withhold: the accepted revision stays, delayed one pass, never
        // replaced by an untagged one. Listed families included.
        let (deferred, unfolded) = crate::snapshots::claude_request_money::e2::hold_trace_discarded(
            &mut scan_result.snapshots,
            &trace_discarded_roots,
        );
        stats.trace_discard_deferred_items += deferred;
        unfolded
    };
    drop(window);
    let window = step("evidence_identity_index");
    // Contract-5 evidence is always built; the reported rebuild then
    // classifies and groups each request as it places it.
    let identity_evidence = builds_evidence.then(|| {
        let evidence = crate::snapshots::claude_request_identity::ScanEvidence::new(
            &api_report,
            &trace_report,
            identity_unhealthy_roots,
        );
        let evidence = match &whole_corpus {
            Some(_) => evidence.with_scope(&cross),
            None => evidence.with_cross_root(&cross),
        };
        evidence
            .with_trace_discarded_roots(trace_discarded_roots)
            .with_native_originals(originals)
            .with_accepted_buckets(accepted_identity_buckets)
            .with_wire_budget(wire_budget)
    });
    drop(window);
    let window = step("evidence_reported_usage");
    let mut disposition = crate::snapshots::apply_claude_reported_usage_to_scan_with_rows(
        scan_result,
        &api_report,
        &trace_report,
        index,
        identity_evidence.as_ref(),
        match &whole_corpus {
            Some(veto_api_rows) => crate::snapshots::ClaudeEvidenceRows::Whole(veto_api_rows),
            None => crate::snapshots::ClaudeEvidenceRows::Streamed(&cross),
        },
    );
    drop(whole_corpus);
    drop(window);
    let window = step("evidence_reconcile");
    if let Some(evidence) = &identity_evidence {
        crate::snapshots::claude_request_identity::reconcile_request_accounts(
            &mut scan_result.snapshots,
            evidence,
        );
    }

    let request_owned_activity = identity_evidence.as_ref().map(|evidence| {
        crate::snapshots::claude_request_identity::stage_request_owned_activity(
            &scan_result.snapshots,
            evidence,
            request_owned_originals,
        )
    });
    drop(window);
    let window = step("evidence_finish_page");
    // `e2` bodies are final before any identity owner runs: contract 5, transcript ownership and
    // the account hash then tag the rows that upload.
    // Gate off this only counts, so the page is unchanged.
    // Withheld entities stay on the page and owed: delayed, never settled.
    let mut withheld = crate::snapshots::claude_request_money::e2::finish_page_planned(
        &mut scan_result.snapshots,
        index,
        if telemetry_read_failed {
            crate::snapshots::claude_request_money::e2::TelemetryRead::Failed
        } else {
            crate::snapshots::claude_request_money::e2::TelemetryRead::Loaded
        },
        &mut disposition.request_owned_hold_reasons,
        &scan_result.claude_queued_family_deferred_paths,
        &page.content_held,
    );
    if !trace_discard_unfolded.is_empty() {
        *disposition
            .request_owned_hold_reasons
            .entry("trace_discarded")
            .or_default() += trace_discard_unfolded.len() as u64;
    }
    withheld.extend(trace_discard_unfolded);
    disposition.hold_request_owned(withheld);
    {
        for item in &mut scan_result.snapshots {
            if let Some(root) =
                crate::snapshots::claude_request_money::request_owned_family_root(item)
            {
                // API attachment alone cannot certify side-call coverage. A
                // root is complete only after BOTH strict reads succeed.
                if !strict_healthy_roots.contains(root) {
                    item.telemetry_owned_complete = Some(false);
                }
            }
        }
    }
    if telemetry_read_failed {
        // No owed history file settles on estimates because this page could
        // not read telemetry: the emission seam drops its bodies, keeps its
        // upload tuple, and it stays owed for a later page.
        index.hold_claude_history_for_unread_telemetry();
    }
    drop(window);
    let window = step("evidence_identity_tags");
    if let Some(evidence) = &identity_evidence {
        // Contract 5 first: the ownership step below leaves new-collector items untouched.
        let request_identity = crate::snapshots::claude_request_identity::apply_scan_page(
            &mut scan_result.snapshots,
            evidence,
            std::mem::take(&mut disposition.request_groupings),
        );
        disposition.copy_invalidated = request_identity.copy_invalidated;
        if !request_identity.held.is_empty() {
            disposition.hold_request_owned(request_identity.held);
        }
        if let Some(activity) = request_owned_activity {
            crate::snapshots::claude_request_identity::publish_request_owned_activity(
                &scan_result.snapshots,
                activity,
            );
        }
    }
    drop(window);
    let window = step("evidence_qualification");
    let qualification = match &identity_evidence {
        Some(evidence) => crate::snapshots::claude_request_accounts::apply_with_shared_index(
            &mut scan_result.snapshots,
            &api_report,
            &trace_report,
            originals,
            evidence,
        ),
        None => crate::snapshots::claude_request_accounts::apply_with_originals(
            &mut scan_result.snapshots,
            &api_report,
            &trace_report,
            originals,
        ),
    };
    drop(window);
    drop(identity_evidence);
    drop(cross);
    if let Some((window, ledger)) = page.telemetry_window.as_mut() {
        scan_result.snapshots.extend(
            synthetic
                .into_iter()
                .filter(|item| synthetic_healthy.contains(&item.source_session_id))
                .filter_map(|item| {
                    let root = item.source_session_id.clone();
                    match telemetry_only::build(
                        item,
                        &api_report,
                        &trace_report,
                        index,
                        *window,
                        accepted_identity_buckets,
                        wire_budget,
                    ) {
                        Ok(Some(item)) => Some(item),
                        Ok(None) => {
                            ledger.settle(&root);
                            None
                        }
                        Err(()) => None,
                    }
                }),
        );
    }
    // Qualification above was the last row reader.
    drop(api_report);
    drop(trace_report);
    let _account_coverage = qualification.coverage;
    disposition.mixed_uploads = qualification.mixed;
    // Request identity is not the session owner: admit only this scan's
    // exact contract-5 bodies, never rewriting a retained owner.
    // Nor is an unhealthy read's cleared account: admit this scan's exact
    // Unknown bodies so a bound session uploads them.
    for item in &scan_result.snapshots {
        disposition.mixed_uploads.admit_request_identity(item);
        disposition.mixed_uploads.admit_unhealthy_unknown(item);
    }
    drop(fold_window);
    disposition
}

#[derive(Debug, PartialEq, Eq)]
enum ResumableUploadResult {
    Completed,
    /// Valid complete ACK: transport finished, but exact permanent refusals
    /// remain terminal/incomplete usage, never accepted or automatically retried.
    Rejected {
        count: usize,
    },
    /// Accepted siblings are durably checkpointed; backend conflicts remain
    /// held for bounded retry and paced context offers wait for a later pass.
    /// `isolated` (included in `count`) are validated ordinary retryable
    /// entity refusals, each held alone; when they are all of `count`, the
    /// pass finishes with them still owed.
    Deferred {
        count: usize,
        isolated: usize,
    },
    Disabled(Option<String>),
    /// The backend shed a page. Every earlier page is accepted and
    /// checkpointed; this is a "come back later", not a failure.
    ///
    /// Carries the server's own `Retry-After` verbatim (absent when it sent
    /// none). Turning that into a wait needs the per-source shed history, which
    /// the caller owns, not this pass.
    Shed {
        retry_after: Option<Duration>,
    },
}

#[derive(Debug)]
struct SnapshotBatchPreflightRejected {
    reason: String,
}

impl std::fmt::Display for SnapshotBatchPreflightRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "local snapshot batch contract preflight failed: {}",
            self.reason
        )
    }
}

impl std::error::Error for SnapshotBatchPreflightRejected {}

#[derive(Debug)]
struct SnapshotLocalStateRejected {
    operation: &'static str,
}

impl std::fmt::Display for SnapshotLocalStateRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local snapshot state failed: {}", self.operation)
    }
}

impl std::error::Error for SnapshotLocalStateRejected {}

#[derive(Debug)]
struct SnapshotBatchResponseRejected {
    expected: u64,
    accepted: u64,
}

impl std::fmt::Display for SnapshotBatchResponseRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "snapshot batch accepted-count mismatch: expected {}, received {}",
            self.expected, self.accepted
        )
    }
}

impl std::error::Error for SnapshotBatchResponseRejected {}

/// Legacy ambiguity is resolved by the normal upload/quarantine machine. The
/// deployed handler's exact-repeat contract is deliberately truthful: it
/// commits the source-freshness acceptance UPSERT, but skips the
/// bronze snapshot, payload, reconciliation revision, accepted-log sequence,
/// archive occurrence, and entity-head writes. Consequently an exact repeat
/// has zero census-membership delta. A genuinely missing head creates exactly
/// one new/updated census member; a divergent body is fenced by head CAS and
/// remains quarantined with zero census delta until an explicit resolution.
fn require_normal_write_ack_for_legacy_reconciliation(
    response: &crate::snapshot_client::SnapshotBatchResponse,
    request_fingerprints: &BTreeSet<String>,
    legacy_pending: &BTreeSet<String>,
) -> Result<()> {
    let carries_legacy_reconciliation = request_fingerprints
        .iter()
        .any(|fingerprint| legacy_pending.contains(fingerprint));
    if !carries_legacy_reconciliation {
        return Ok(());
    }
    if response.disabled {
        return Err(anyhow::Error::new(SnapshotAckRejected {
            reason: "disabled snapshot response cannot settle legacy reconciliation",
        }));
    }
    if response.entity_ack_contract.as_deref()
        != Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT)
    {
        return Err(anyhow::Error::new(SnapshotAckRejected {
            reason: "legacy snapshot reconciliation requires the exact entity ACK contract",
        }));
    }
    Ok(())
}

/// A cycle's summary. Each source's cause is on its own "skipped for" line.
#[derive(Debug)]
struct SourcesFailed(Vec<&'static str>);

impl std::fmt::Display for SourcesFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "local snapshot sync failed for {}",
            self.0.join(", ")
        )
    }
}

impl std::error::Error for SourcesFailed {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotEntityDeferred {
    count: usize,
}

impl std::fmt::Display for SnapshotEntityDeferred {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "snapshot upload deferred {} unsettled entity(ies)",
            self.count
        )
    }
}

impl std::error::Error for SnapshotEntityDeferred {}

fn snapshot_entity_deferred(count: usize) -> anyhow::Error {
    anyhow::Error::new(SnapshotEntityDeferred { count })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotUploadErrorClass {
    LocalState,
    BackendResponse,
}

fn snapshot_upload_error_class(error: &anyhow::Error) -> Option<SnapshotUploadErrorClass> {
    if error.downcast_ref::<SnapshotLocalStateRejected>().is_some() {
        Some(SnapshotUploadErrorClass::LocalState)
    } else if error.downcast_ref::<SnapshotAckRejected>().is_some()
        || error
            .downcast_ref::<SnapshotBatchResponseRejected>()
            .is_some()
    {
        Some(SnapshotUploadErrorClass::BackendResponse)
    } else {
        None
    }
}

fn is_item_specific_local_preflight_failure(error: &anyhow::Error) -> bool {
    item_specific_local_preflight_index(error).is_some()
}

fn item_specific_local_preflight_index(error: &anyhow::Error) -> Option<usize> {
    error
        .downcast_ref::<SnapshotBatchPreflightRejected>()
        .and_then(|preflight| preflight.reason.strip_prefix("snapshot["))
        .and_then(|suffix| suffix.split_once(']'))
        .and_then(|(index, _)| index.parse().ok())
}

/// True when the backend shed this request rather than failing it.
fn is_shed_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| diagnostics.status_family() == "http_429")
}

/// The server never answered the page: a transport failure, a timeout or a
/// 5xx. A plain shed arrives as `ResumableUploadResult::Shed` instead.
fn is_upload_outage(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(UploadFailureDiagnostics::is_outage)
}

fn is_snapshot_batch_split_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| {
            diagnostics.is_snapshot_batch_deadline() || diagnostics.is_snapshot_batch_too_large()
        })
}

/// The wait before resending a failed batch in place, with the HTTP status
/// that earned it, or `None` when the failure keeps its existing path. The
/// wait is never earlier than the server's own `Retry-After`.
fn transient_inplace_retry_wait(error: &anyhow::Error) -> Option<(u16, Duration)> {
    let (status, base) = if let Some(shed) = error.downcast_ref::<UploadShed>() {
        // The identity deferral waits on the identity, not on this request:
        // excluded by its code before any admission, even with a short
        // Retry-After.
        if shed.is_original_identity_unavailable() {
            return None;
        }
        // No Retry-After keeps the jittered ladder; a long one is not worth
        // holding the sync lock for.
        let retry_after = shed
            .retry_after
            .filter(|wait| *wait <= SNAPSHOT_INPLACE_RETRY_MAX_WAIT)?;
        (shed.status, retry_after)
    } else {
        let status = error
            .downcast_ref::<UploadFailureDiagnostics>()?
            .transient_batch_status()?;
        (status, SNAPSHOT_INPLACE_RETRY_SERVER_ERROR_WAIT)
    };
    let base = base.max(SNAPSHOT_INPLACE_RETRY_MIN_WAIT);
    let wait = (base + uniform_duration(base.mul_f64(0.2))).min(SNAPSHOT_INPLACE_RETRY_MAX_WAIT);
    Some((status, wait))
}

/// In-place resends spent by one source page: every batch of its cache-head
/// bootstrap stages and of its main upload draws on the same budget.
#[derive(Default)]
struct InplaceRetryBudget {
    resends: usize,
    waited: Duration,
}

impl InplaceRetryBudget {
    fn admit(&self, error: &anyhow::Error, failed_after: Duration) -> Option<(u16, Duration)> {
        if self.resends >= SNAPSHOT_INPLACE_RETRY_LIMIT
            || failed_after >= SNAPSHOT_INPLACE_RETRY_FAST_FAILURE
        {
            return None;
        }
        transient_inplace_retry_wait(error)
            .filter(|(_, wait)| self.waited + *wait <= SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET)
    }
}

fn inplace_retry_failed_after(started: Instant) -> Duration {
    #[cfg(test)]
    if let Some(failed_after) = INPLACE_RETRY_TEST_CLOCK
        .with(|clock| clock.borrow().as_ref().and_then(|clock| clock.failed_after))
    {
        return failed_after;
    }
    started.elapsed()
}

fn inplace_retry_sleep(wait: Duration) {
    #[cfg(test)]
    if INPLACE_RETRY_TEST_CLOCK.with(|clock| match clock.borrow_mut().as_mut() {
        Some(clock) => {
            clock.waits.push(wait);
            true
        }
        None => false,
    }) {
        return;
    }
    std::thread::sleep(wait);
}

/// Test-only stand-in for the in-place resend clock: it records every wait
/// instead of sleeping and may override how long a failed POST took.
#[cfg(test)]
struct InplaceRetryTestClock {
    failed_after: Option<Duration>,
    waits: Vec<Duration>,
}

#[cfg(test)]
thread_local! {
    static INPLACE_RETRY_TEST_CLOCK: std::cell::RefCell<Option<InplaceRetryTestClock>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `body` with this thread's in-place resend clock replaced. Returns the
/// result and every wait the uploader asked for, in order.
#[cfg(test)]
fn with_inplace_retry_test_clock<R>(
    failed_after: Option<Duration>,
    body: impl FnOnce() -> R,
) -> (R, Vec<Duration>) {
    INPLACE_RETRY_TEST_CLOCK.with(|clock| {
        *clock.borrow_mut() = Some(InplaceRetryTestClock {
            failed_after,
            waits: Vec::new(),
        });
    });
    let result = body();
    let waits = INPLACE_RETRY_TEST_CLOCK
        .with(|clock| clock.borrow_mut().take())
        .map(|clock| clock.waits)
        .unwrap_or_default();
    (result, waits)
}

/// Upload changed snapshots in bounded pages while durably checkpointing every
/// accepted page. Item-specific validation failures are bisected so one poison
/// snapshot cannot replay or block its valid siblings; pages that exceed the
/// client or gateway deadline are also bisected to reduce per-request
/// reconciliation work. Splits are capped so an outage or broad contract
/// mismatch cannot fan out into unbounded calls.
#[cfg(test)]
fn upload_resumable_batches<T, Fingerprint, Upload, Persist>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    upload: Upload,
    persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Serialize,
    Fingerprint: Fn(&T) -> &str + Copy,
    Upload: FnMut(&[&T]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    upload_resumable_batches_with_body_witness(
        items,
        poison_scope,
        progress,
        accepted,
        fingerprint,
        move |item| fingerprint(item).to_string(),
        upload,
        persist,
    )
}

#[expect(clippy::too_many_arguments, reason = "test helper, 8 case inputs")]
#[cfg(test)]
fn upload_resumable_batches_with_body_witness<T, Fingerprint, BodyWitness, Upload, Persist>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    body_witness: BodyWitness,
    upload: Upload,
    persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    Upload: FnMut(&[&T]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    upload_resumable_batches_with_literal_families(
        items,
        poison_scope,
        progress,
        accepted,
        fingerprint,
        body_witness,
        |_| None,
        |_| 0,
        |_| None,
        &mut InplaceRetryBudget::default(),
        upload,
        persist,
    )
}

#[derive(Debug)]
enum SnapshotPageOutcome {
    Settled { conflicted: usize, isolated: usize },
    Disabled(Option<String>),
}

/// Diagnostics only (`change_reason`): an unchanged ACK without a basis
/// (the stored body itself) or with `usage_identical` settles identical
/// usage; an accepted one never does.
fn ack_usage_identical(unchanged: bool, basis: Option<&str>) -> bool {
    unchanged && matches!(basis, None | Some("usage_identical"))
}

// Scratch extraction only: the upload callback remains the existing canonical
// preflight/token/ACK-validator/client-report boundary. No inventory pruning.
#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
fn attempt_snapshot_page<T, Fingerprint, BodyWitness, SessionId, Upload, Persist>(
    items: &[T],
    indices: &[usize],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: &Fingerprint,
    body_witness: &BodyWitness,
    session_id: &SessionId,
    upload: &mut Upload,
    persist: &mut Persist,
) -> Result<SnapshotPageOutcome>
where
    T: Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    SessionId: Fn(&T) -> Option<&str>,
    Upload: FnMut(&[&T]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    // Reserve every possible ACK before any remote side effect, including the
    // retained retry driver. Capacity stops use the partial-index save path.
    let new_acks = indices
        .iter()
        .filter(|index| {
            !progress
                .accepted_fingerprints
                .contains(fingerprint(&items[**index]))
        })
        .count();
    progress.admit_ack_batch(new_acks)?;
    let batch = indices
        .iter()
        .map(|index| &items[*index])
        .collect::<Vec<_>>();
    for index in indices {
        let item = &items[*index];
        let fp = fingerprint(item);
        if progress.active_reason_reoffers.get(fp) == Some(&body_witness(item))
            && progress.attempted_reason_reoffers.insert(fp.to_string())
        {
            progress.reason_reoffer_counts.attempted += 1;
            progress.reason_reoffer_counts.attempted_bytes = progress
                .reason_reoffer_counts
                .attempted_bytes
                .saturating_add(snapshot_packing_json_length(item)?);
        }
    }
    for index in indices {
        let item = &items[*index];
        let bytes = snapshot_packing_json_length(item)? as u64;
        // Counts only; on the sync path `poison_scope` is the source slug.
        crate::local_resource_diagnostics::change_reason::attempted(
            poison_scope,
            fingerprint(item),
            session_id(item),
            progress
                .change_reason_resend(fingerprint(item), session_id(item), || body_witness(item)),
            bytes,
        );
        progress
            .context_resend
            .note_attempt(fingerprint(item), bytes);
    }
    let mut replaced_retained_proof = false;
    if !progress.accepted_identity_scope.is_unset() {
        progress.load_identity(batch.iter().copied().filter_map(session_id))?;
    }
    // Only proof the ledger holds can be replaced, whatever the capability.
    if progress.accepted_identity_buckets.has_retained() {
        for item in &batch {
            let value = serde_json::to_value(item)?;
            replaced_retained_proof |= progress
                .accepted_identity_buckets
                .invalidate_replaced(&value);
        }
    }
    // Option (ii): the server may store a replacement proof even if this
    // reply is lost; drop the superseded one durably so no later marker can
    // preserve the replacement in its place.
    if replaced_retained_proof {
        persist(progress)?;
    }
    // This page's attempt rows are written once its progress save returns.
    let attempt_history = crate::upload_receipts::defer();
    let response = upload(&batch);
    // The callback includes local preflight and authority checks. Only a reply
    // or a typed batch response proves this ordinary retry reached a send.
    if response.is_ok()
        || response.as_ref().is_err_and(|error| {
            error.downcast_ref::<BatchRejected>().is_some()
                || error.downcast_ref::<BatchAuthorizationRejected>().is_some()
                || error
                    .downcast_ref::<UploadFailureDiagnostics>()
                    .is_some_and(UploadFailureDiagnostics::is_snapshot_batch_response)
                || error.downcast_ref::<UploadShed>().is_some()
                || error.downcast_ref::<SnapshotAckRejected>().is_some()
        })
    {
        let mut retry_attempted = false;
        for index in indices {
            let fp = fingerprint(&items[*index]);
            if progress.active_quarantine_retries.contains(fp)
                && progress
                    .quarantined_fingerprints
                    .get(fp)
                    .is_some_and(|record| record.contract_retry_claims.is_none())
            {
                progress.pace_retry(fp);
                retry_attempted = true;
            }
        }
        if retry_attempted {
            persist(progress)?;
        }
    }
    let response = response?;
    if response.disabled {
        return Ok(SnapshotPageOutcome::Disabled(response.disabled_reason));
    }
    let mut conflicted_entities = 0usize;
    let mut isolated_entities = 0usize;
    let mut head_conflicts_recovered = Vec::new();
    let mut head_conflicts_recorded = Vec::new();
    let entity_ack = match response.entity_ack_contract.as_deref() {
        None => false,
        Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT) => true,
        Some(_) => {
            return Err(anyhow!(
                "snapshot response uses an unsupported entity ACK contract"
            ));
        }
    };
    if !entity_ack && response.accepted != indices.len() as u64 {
        return Err(anyhow::Error::new(SnapshotBatchResponseRejected {
            expected: indices.len() as u64,
            accepted: response.accepted,
        }));
    }
    if entity_ack {
        // An ordinary changed write may omit CAS/head proof while
        // cache is disabled. Its old predecessor no longer grants
        // authority; the existing bootstrap must recover it later.
        // An unchanged ACK leaves the saved head valid.
        for entity in &response.accepted_entities {
            if entity.head_etag.is_none() {
                progress
                    .accepted_cache_heads
                    .remove(&cache_session_key(&entity.source_session_id));
            }
        }
        for entity in response
            .accepted_entities
            .iter()
            .chain(&response.unchanged_entities)
        {
            if let Some(head) = &entity.head_etag {
                progress
                    .accepted_cache_heads
                    .insert(cache_session_key(&entity.source_session_id), head.clone());
            }
        }
        // Only a settled ref with a head resolves the session's owed
        // challenge: a headless ref (a stripped base without CAS) proves no
        // head. A conflict in the same page for a session so settled records
        // nothing.
        let mut settled_sessions = BTreeSet::new();
        for entity in response
            .accepted_entities
            .iter()
            .chain(&response.unchanged_entities)
            .filter(|entity| entity.head_etag.is_some())
        {
            let key = cache_session_key(&entity.source_session_id);
            if let Some(record) = progress.head_conflict_challenges.remove(&key) {
                head_conflicts_recovered.push((
                    SessionHash::of(&entity.source_session_id),
                    record.answer_attempts,
                ));
            }
            settled_sessions.insert(key);
        }
        let now = current_unix_seconds();
        // Conflicted bodies whose new challenge answer is owed on the next page.
        let mut answer_owed_now = BTreeSet::new();
        for entity in &response.conflict_entities {
            let key = cache_session_key(&entity.source_session_id);
            if settled_sessions.contains(&key) {
                continue;
            }
            let (Some(challenge), Some(rescan)) = (
                entity.head_challenge.as_deref(),
                response.conflict_rescans.get(&entity.snapshot_fingerprint),
            ) else {
                continue;
            };
            if let Some((attempts, owed_now)) = progress.record_head_conflict_challenge(
                &entity.source_session_id,
                challenge,
                rescan,
                now,
            ) {
                if owed_now {
                    answer_owed_now.insert(entity.snapshot_fingerprint.as_str());
                }
                head_conflicts_recorded.push((
                    SessionHash::of(&entity.source_session_id),
                    attempts,
                    rescan.answered,
                ));
            }
        }
        // An unchanged ref with `unchanged_basis` means the server did not
        // store this body (its head already covers the usage). Nothing
        // body-scoped is recorded as stored: the exact body is held instead,
        // so it is offered once per change and never marked emitted.
        let not_stored = response
            .unchanged_entities
            .iter()
            .filter(|entity| entity.unchanged_basis.is_some())
            .map(|entity| entity.snapshot_fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        let settled = response
            .accepted_entities
            .iter()
            .chain(&response.unchanged_entities)
            .map(|entity| entity.snapshot_fingerprint.as_str())
            .filter(|fingerprint| !not_stored.contains(fingerprint))
            .collect::<BTreeSet<_>>();
        let stored_refs = response
            .accepted_entities
            .iter()
            .chain(&response.unchanged_entities)
            .filter(|entity| entity.unchanged_basis.is_none())
            .map(|entity| (entity.snapshot_fingerprint.as_str(), entity))
            .collect::<BTreeMap<_, _>>();
        for (entity, unchanged) in response
            .accepted_entities
            .iter()
            .map(|entity| (entity, false))
            .chain(
                response
                    .unchanged_entities
                    .iter()
                    .map(|entity| (entity, true)),
            )
        {
            crate::local_resource_diagnostics::change_reason::settled(
                poison_scope,
                &entity.snapshot_fingerprint,
                ack_usage_identical(unchanged, entity.unchanged_basis.as_deref()),
            );
        }
        for index in indices {
            let item = &items[*index];
            let item_fingerprint = fingerprint(item);
            if settled.contains(item_fingerprint) {
                let witness = body_witness(item);
                progress.record_body(item_fingerprint, &witness);

                if let Some(context) = &progress.context_resend.active {
                    progress
                        .accepted_body_contexts
                        .insert(item_fingerprint.to_string(), context.clone());
                }
                progress
                    .fresh_context_body_acks
                    .insert(item_fingerprint.to_string(), witness.clone());
                progress.record_stored_state(
                    item,
                    false,
                    stored_refs
                        .get(item_fingerprint)
                        .map(|entity| (*entity, witness.as_str())),
                )?;
            } else if not_stored.contains(item_fingerprint) {
                progress.hold_unstored_body(item_fingerprint, &body_witness(item));
                progress
                    .context_resend
                    .not_stored
                    .insert(item_fingerprint.to_string());
            }
        }
        if !not_stored.is_empty() {
            let usage_identical = response
                .unchanged_entities
                .iter()
                .filter(|entity| entity.unchanged_basis.as_deref() == Some("usage_identical"))
                .count();
            eprintln!(
                "local snapshot unchanged not stored for {poison_scope}: count={} \
                 usage_identical={usage_identical} other={}; exact bodies held, not marked emitted",
                not_stored.len(),
                not_stored.len().saturating_sub(usage_identical),
            );
        }
        let rejected = response
            .rejected_entities
            .iter()
            .map(|entity| (entity.snapshot_fingerprint.as_str(), entity))
            .collect::<BTreeMap<_, _>>();
        let conflicted = response
            .conflict_entities
            .iter()
            .map(|entity| entity.snapshot_fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        for index in indices {
            let item = &items[*index];
            let item_fingerprint = fingerprint(item);
            if let Some(rejection) = rejected.get(item_fingerprint) {
                if rejection.permanent {
                    progress
                        .head_conflict_challenges
                        .remove(&cache_session_key(&rejection.source_session_id));
                    progress.quarantine_permanent_body(
                        item_fingerprint,
                        &body_witness(item),
                        rejection.safe_reason(),
                    );
                    progress.note_refused_exposure(item_fingerprint, item);
                    progress.settle_telemetry_root(&rejection.source_session_id);
                } else {
                    // Any validated non-permanent answer keeps only this
                    // entity owed. Accepted siblings settle independently.
                    progress.quarantine_retryable_body(
                        item_fingerprint,
                        &body_witness(item),
                        quarantine_retry_after(item_fingerprint),
                    );
                }
            } else if conflicted.contains(item_fingerprint) {
                // An owed new answer rides the next selecting page; any other
                // conflict gets its mandatory probe within one hour.
                // Terminal-contract re-arm: main's 6-12 h cadence, unchanged (separate timer).
                let contract_rearm = progress
                    .quarantined_fingerprints
                    .get(item_fingerprint)
                    .is_some_and(|record| record.contract_retry_claims.is_some());
                let retry_after = if contract_rearm {
                    quarantine_retry_after(item_fingerprint)
                } else if answer_owed_now.contains(item_fingerprint) {
                    now
                } else {
                    conflict_probe_after(item_fingerprint, now)
                };
                progress.quarantine_retryable_body(
                    item_fingerprint,
                    &body_witness(item),
                    retry_after,
                );
                crate::local_resource_diagnostics::traversal_point(
                    "quarantine_retry_body",
                    poison_scope,
                    &serde_json::json!({"origin": "conflict",
                        "fingerprint_hash8": SessionHash::of(item_fingerprint).to_string(),
                        "body_witness_hash8": body_witness(item).get(..8).filter(|v| v.bytes().all(|b| b.is_ascii_hexdigit()))}),
                );
            }
        }
        // A conflict is not a settlement, but it IS retryable: the
        // backend is asking for this entity again later, not never.
        // It therefore uses the quarantine ledger's bounded backoff, but
        // never consumes the permanent reconstruction-failure budget.
        // A transient conflict remains retryable.
        //
        // Returning the whole page as an error here (the previous
        // behaviour) discarded the entities the backend had ALREADY
        // written in this same response, so nothing was ever
        // checkpointed: the identical page replayed every cycle,
        // the scan index could never commit, and the "fresh
        // complete scan" that recovery waited on could never
        // happen. One conflicting entity deadlocked its whole
        // source permanently, across restarts.
        // A held body is pending the same way.
        conflicted_entities = response.conflict_entities.len().saturating_add(
            response
                .rejected_entities
                .iter()
                .filter(|entity| !entity.permanent)
                .count(),
        );
        isolated_entities = response
            .rejected_entities
            .iter()
            .filter(|entity| !entity.permanent && entity.ordinary_retryable())
            .count()
            .saturating_add(response.conflict_entities.len());
        progress.context_resend.counts.server_conflicts += conflicted_entities as u64;
    } else {
        for index in indices {
            let item = &items[*index];
            progress.record_body(fingerprint(item), &body_witness(item));
            progress.record_cache_state(item, true)?;
        }
    }
    // The remote write happened first. If this local atomic save
    // fails, stop: at most this one idempotent page can replay.
    let saved = persist(progress);
    drop(attempt_history);
    saved.map_err(|_| {
        anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "save upload checkpoint",
        })
    })?;
    for (session_hash, answer_attempts) in &head_conflicts_recovered {
        eprintln!(
            "local snapshot head-CAS conflict resolved for {poison_scope}: session_hash={session_hash} \
             refused_answers={answer_attempts}; saved head replaced by the server's",
        );
    }
    for (session_hash, answer_attempts, answered) in &head_conflicts_recorded {
        eprintln!(
            "local snapshot head-CAS conflict for {poison_scope}: session_hash={session_hash} answered={answered} \
             refused_answers={answer_attempts}; challenge saved, the next eligible upload answers it",
        );
    }
    if entity_ack {
        for entity in &response.rejected_entities {
            if entity.permanent {
                record_poison_loss_once(poison_scope, &entity.snapshot_fingerprint);
            }
            eprintln!(
                "local snapshot entity rejected for {poison_scope}: reason={} permanent={} session_hash={}; \
                 accepted siblings checkpointed, rejected body retained in bounded quarantine",
                entity.safe_reason(),
                entity.permanent,
                rejection_log::rejected_session_hash(
                    items, indices, &entity.snapshot_fingerprint, fingerprint, session_id,
                ),
            );
        }
    }
    *accepted = accepted.saturating_add(response.accepted);

    Ok(SnapshotPageOutcome::Settled {
        conflicted: conflicted_entities,
        isolated: isolated_entities,
    })
}

// Packing needs encoded lengths, not a retained copy of every pending body.
// Use the same serde JSON encoding without allocating its output. There is no
// early size cap: serializers must still finish or report their original error.
struct SnapshotPackingLength {
    bytes: usize,
}
impl std::io::Write for SnapshotPackingLength {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snapshot packing length overflow",
            )
        })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn snapshot_packing_json_length<T: Serialize + ?Sized>(
    item: &T,
) -> serde_json::Result<usize> {
    let mut length = SnapshotPackingLength { bytes: 0 };
    serde_json::to_writer(&mut length, item)?;
    Ok(length.bytes)
}

/// Cut one request-owned family (root first) into consecutive groups that
/// each fit one batch: at most `SNAPSHOT_BATCH_LIMIT` bodies and
/// `SNAPSHOT_BATCH_MAX_BYTES`, one batch class. A family that fits stays one
/// group. A single body over the byte bound is its own group and meets the
/// existing request preflight.
fn literal_family_groups(members: Vec<(usize, usize, u8)>) -> Vec<Vec<(usize, usize, u8)>> {
    let mut groups = Vec::new();
    let mut group = Vec::<(usize, usize, u8)>::new();
    let mut bytes = 2usize;
    for member in members {
        if !group.is_empty()
            && (group.len() == SNAPSHOT_BATCH_LIMIT
                || bytes.saturating_add(member.1) > SNAPSHOT_BATCH_MAX_BYTES
                || group[0].2 != member.2)
        {
            groups.push(std::mem::take(&mut group));
            bytes = 2;
        }
        bytes = bytes.saturating_add(member.1);
        group.push(member);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    groups
}

/// `literal_family` names the family root of a request-owned literal body
/// (`None` for every other body); see `literal_family_groups`.
#[expect(clippy::too_many_arguments, reason = "12 args; no options struct yet")]
fn upload_resumable_batches_with_literal_families<
    T,
    Fingerprint,
    BodyWitness,
    SessionId,
    BatchClass,
    LiteralFamily,
    Upload,
    Persist,
>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    body_witness: BodyWitness,
    session_id: SessionId,
    batch_class: BatchClass,
    literal_family: LiteralFamily,
    inplace_retry: &mut InplaceRetryBudget,
    mut upload: Upload,
    mut persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Serialize,
    Fingerprint: Fn(&T) -> &str,
    BodyWitness: Fn(&T) -> String,
    SessionId: Fn(&T) -> Option<&str>,
    BatchClass: Fn(&T) -> u8,
    LiteralFamily: Fn(&T) -> Option<&str>,
    Upload: FnMut(&[&T]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&mut SnapshotUploadProgress) -> Result<()>,
{
    // Input is a page/delta, not a census. Only an explicitly changed body
    // invalidates its previous ACK here. Index settlement owns retirement;
    // bounded admission below prevents unindexed revisions growing forever.
    let mut current_body_witnesses = BTreeMap::new();
    for item in items {
        let item_fingerprint = fingerprint(item).to_string();
        let item_body_witness = body_witness(item);
        if current_body_witnesses
            .insert(item_fingerprint.clone(), item_body_witness.clone())
            .is_some_and(|previous| previous != item_body_witness)
        {
            return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "resolve conflicting snapshot body witnesses",
            }));
        }
    }
    let current_fingerprints = current_body_witnesses
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let progress_len_before_prune = progress.accepted_fingerprints.len();
    progress
        .accepted_body_witnesses
        .retain(|fingerprint, witness| {
            current_body_witnesses
                .get(fingerprint)
                .map_or(true, |current| current == witness)
        });
    progress
        .accepted_fingerprints
        .retain(|value| progress.accepted_body_witnesses.contains_key(value));
    retain_counted_poison_fingerprints(poison_scope, &current_fingerprints);
    // Replay and cycle retirement clear disposable quarantine records. Restore
    // the index-facing refusal only when this frozen input proves the same body.
    // Otherwise suppression could leave a rejected entity in the accepted census.
    let permanent_to_restore = current_body_witnesses
        .iter()
        .filter(|(fingerprint, body)| {
            progress
                .permanent_rejections
                .get(*fingerprint)
                .is_some_and(|record| record.body_witness == **body && !record.owed())
                && !progress
                    .quarantined_fingerprints
                    .get(*fingerprint)
                    .is_some_and(|record| {
                        record.upload_body_witness.as_deref() == Some(body.as_str())
                            && matches!(
                                record.disposition,
                                SnapshotQuarantineDisposition::UnprovenTerminal
                                    | SnapshotQuarantineDisposition::RetryPending
                            )
                    })
        })
        .map(|(fingerprint, body)| (fingerprint.clone(), body.clone()))
        .collect::<Vec<_>>();
    for (fingerprint, body) in &permanent_to_restore {
        progress.quarantine_body(fingerprint, body);
        let record = progress
            .quarantined_fingerprints
            .get_mut(fingerprint)
            .unwrap();
        record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
        record.retry_after_unix_seconds = 0;
    }
    if progress.accepted_fingerprints.len() != progress_len_before_prune
        || !permanent_to_restore.is_empty()
    {
        persist(progress).map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "prune upload checkpoint",
            })
        })?;
    }

    let mut pending_by_fingerprint: BTreeMap<String, (usize, usize, String)> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let witness = body_witness(item);
        if !progress.contains_body(fingerprint(item), &witness) {
            match pending_by_fingerprint.entry(fingerprint(item).to_string()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let body_length = snapshot_packing_json_length(item).map_err(|_| {
                        anyhow::Error::new(SnapshotLocalStateRejected {
                            operation: "serialize snapshot for batch packing",
                        })
                    })?;
                    entry.insert((index, body_length, witness));
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    // The finalized fingerprint covers every post-policy
                    // semantic field and production preflight recomputes it
                    // before upload. Observation/inventory fields deliberately
                    // excluded from that identity (for example collected_at or
                    // source_file_fingerprint after a rotate/recopy) may make
                    // whole item bytes differ without creating another remote
                    // entity. Upload one representative for that semantic
                    // identity; every local file entry settles from the same
                    // accepted fingerprint.
                }
            }
        }
    }
    let mut batches = VecDeque::new();
    // Request-owned literal bodies travel with their Claude family (early-t7
    // Q1). A family that fits one batch is packed whole; a larger one is cut
    // into consecutive batch-sized groups, root first, never refused. Each
    // group still settles by its own exact entity ACKs. Units are kept as one
    // ordered list plus end offsets; an ordinary body is a unit of one, so
    // without literal items (gate off) packing is the previous order.
    // Each unit also carries its family key: the class of its family's first
    // group, or its own class for a single body (see the class sort below).
    let mut order = Vec::<(usize, usize, u8)>::with_capacity(pending_by_fingerprint.len());
    let mut unit_ends = Vec::<(usize, u8)>::with_capacity(pending_by_fingerprint.len());
    let mut literal_families = BTreeMap::<&str, Vec<(usize, usize, u8)>>::new();
    for (index, body_length, _) in pending_by_fingerprint.into_values() {
        let item = (
            index,
            body_length.saturating_add(1),
            batch_class(&items[index]),
        );
        match literal_family(&items[index]) {
            Some(root) => literal_families.entry(root).or_default().push(item),
            None => {
                order.push(item);
                unit_ends.push((order.len(), item.2));
            }
        }
    }
    for (root, mut members) in literal_families {
        members.sort_by_key(|(index, _, _)| {
            let member = session_id(&items[*index]);
            (member != Some(root), member)
        });
        let family_key = members[0].2;
        for group in literal_family_groups(members) {
            order.extend(group);
            unit_ends.push((order.len(), family_key));
        }
    }
    let mut units = Vec::with_capacity(unit_ends.len());
    let mut start = 0;
    for (end, family_key) in unit_ends {
        units.push((order[start..end].to_vec(), family_key));
        start = end;
    }
    // Preserve the native census/family selection. At this transport boundary
    // split stamp-only offers out of mixed units, so no ordinary new/changed
    // body shares a request (and its retry latency) with context catch-up.
    let mut ordinary_units = Vec::new();
    let mut catchup_units = Vec::new();
    for (unit, family_key) in units {
        let (catchup, ordinary): (Vec<_>, Vec<_>) = unit.into_iter().partition(|(index, _, _)| {
            progress
                .context_resend
                .is_catchup(fingerprint(&items[*index]))
        });
        if !ordinary.is_empty() {
            ordinary_units.push((ordinary, family_key));
        }
        if !catchup.is_empty() {
            catchup_units.push((catchup, family_key));
        }
    }
    // Cache patches and telemetry bodies declare head CAS for the request,
    // so every request is class-pure: an ordinary body never travels under
    // another body's CAS contract. Stable-sort each lane by family key so
    // single bodies form one run per class, each family's groups stay
    // contiguous and root first, and a single-class page keeps its order.
    ordinary_units.sort_by_key(|(_, family_key)| *family_key);
    catchup_units.sort_by_key(|(_, family_key)| *family_key);
    let ordinary_entities = ordinary_units
        .iter()
        .flat_map(|(unit, _)| unit)
        .map(|(index, _, _)| fingerprint(&items[*index]))
        .collect::<BTreeSet<_>>();
    // A bootstrap invocation sees only its probes. It cannot send catch-up
    // ahead of ordinary bodies that the main uploader has not reached yet.
    let ordinary_in_this_call = progress
        .context_resend
        .ordinary_work_is_in(&ordinary_entities);
    let ordinary_bytes = ordinary_units
        .iter()
        .flat_map(|(unit, _)| unit)
        .fold(0usize, |sum, (_, bytes, _)| {
            sum.saturating_add(bytes.saturating_add(2))
        });
    // Charge all ordinary input before admitting any stamp-only offer. New
    // usage always passes, including a pass larger than the allowance. The
    // existing 2 MiB packing target is also the maximum catch-up allowance
    // per source pass; successive invocations share the remaining allowance.
    progress
        .context_resend
        .reserve_ordinary_bytes(ordinary_bytes);
    let mut unit_ends = Vec::new();
    order.clear();
    for (unit, _) in ordinary_units {
        order.extend(unit);
        unit_ends.push((order.len(), false));
    }
    for (unit, _) in catchup_units {
        let start = order.len();
        for item in unit {
            if ordinary_in_this_call
                && progress
                    .context_resend
                    .admit_catchup_bytes(item.1.saturating_add(2))
            {
                order.push(item);
            } else {
                // Local pacing debt, not a backend conflict: the body stays
                // owed by its file's missing receipt and does not make the
                // page Deferred (or the sweep unsettled).
                progress.context_resend.counts.budget_deferred += 1;
                progress
                    .context_resend
                    .deferred
                    .insert(fingerprint(&items[item.0]).to_string());
            }
        }
        if order.len() > start {
            unit_ends.push((order.len(), true));
        }
    }
    let mut batch = Vec::new();
    let mut batch_bytes = 2usize;
    let mut current_batch_class = None;
    let mut unit_start = 0;
    for (unit_end, catchup) in unit_ends {
        let unit = &order[unit_start..unit_end];
        unit_start = unit_end;
        let unit_bytes = unit
            .iter()
            .fold(0usize, |sum, (_, bytes, _)| sum.saturating_add(*bytes));
        let unit_class = (unit[0].2, catchup);
        if !batch.is_empty()
            && (batch.len() + unit.len() > SNAPSHOT_BATCH_LIMIT
                || batch_bytes.saturating_add(unit_bytes) > SNAPSHOT_BATCH_MAX_BYTES
                || current_batch_class != Some(unit_class))
        {
            batches.push_back((std::mem::take(&mut batch), false));
            batch_bytes = 2;
        }
        current_batch_class = Some(unit_class);
        batch.extend(unit.iter().map(|(index, _, _)| *index));
        batch_bytes = batch_bytes.saturating_add(unit_bytes);
    }
    if !batch.is_empty() {
        batches.push_back((batch, false));
    }
    let mut adaptive_splits = 0usize;
    let mut adaptive_attempts = 0usize;
    let mut conflicted_entities = 0usize;
    let mut isolated_entities = 0usize;

    while let Some((indices, adaptive)) = batches.pop_front() {
        // A duplicate fingerprint may occur in the live scan and historical
        // bootstrap. Re-check after earlier batches checkpointed it.
        let indices = indices
            .into_iter()
            .filter(|index| {
                !progress.contains_body(fingerprint(&items[*index]), &body_witness(&items[*index]))
            })
            .collect::<Vec<_>>();
        if indices.is_empty() {
            continue;
        }
        if adaptive {
            if adaptive_attempts >= SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT {
                return Err(anyhow!("snapshot adaptive upload attempt limit reached"));
            }
            adaptive_attempts += 1;
        }
        let attempt_started = Instant::now();
        // The same exact witnesses, looked up instead of re-hashed: the input
        // map above refused any fingerprint with two bodies.
        let known_body_witness = |item: &T| {
            current_body_witnesses
                .get(fingerprint(item))
                .cloned()
                .unwrap_or_else(|| body_witness(item))
        };
        let attempt = attempt_snapshot_page(
            items,
            &indices,
            poison_scope,
            progress,
            accepted,
            &fingerprint,
            &known_body_witness,
            &session_id,
            &mut upload,
            &mut persist,
        );
        let inplace_wait = attempt.as_ref().err().and_then(|error| {
            inplace_retry.admit(error, inplace_retry_failed_after(attempt_started))
        });
        match attempt {
            Ok(SnapshotPageOutcome::Disabled(reason)) => {
                return Ok(ResumableUploadResult::Disabled(reason));
            }
            Ok(SnapshotPageOutcome::Settled {
                conflicted,
                isolated,
            }) => {
                conflicted_entities = conflicted_entities.saturating_add(conflicted);
                isolated_entities = isolated_entities.saturating_add(isolated);
            }
            Err(error) if is_item_specific_local_preflight_failure(&error) => {
                // The daemon validator names the exact request-local item. It
                // has already proved those bytes cannot fit or satisfy the
                // current wire contract, so quarantine that entity directly
                // and retry only its siblings. This avoids spending remote
                // adaptive-request budget or turning one bad item into twenty
                // one-item network requests.
                let request_index = item_specific_local_preflight_index(&error)
                    .expect("local item preflight guard parsed an index");
                let Some(poison_index) = indices.get(request_index).copied() else {
                    return Err(error.context("local snapshot preflight index was out of bounds"));
                };
                let poison_fingerprint = fingerprint(&items[poison_index]);
                let progress_before_quarantine = progress.clone();
                progress.quarantine_body(
                    fingerprint(&items[poison_index]),
                    &body_witness(&items[poison_index]),
                );
                if persist(progress).is_err() {
                    *progress = progress_before_quarantine;
                    return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                        operation: "save local preflight quarantine",
                    }));
                }
                // Count the loss only after its quarantine is durable. A local
                // save failure must leave both the settlement and the once-set
                // untouched so a successful retry can report the real loss.
                record_poison_loss_once(poison_scope, poison_fingerprint);
                let remaining = indices
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, item)| (index != request_index).then_some(item))
                    .collect::<Vec<_>>();
                if !remaining.is_empty() {
                    batches.push_front((remaining, false));
                }
            }
            Err(error) if server_named_items(&error, &indices).is_some() => {
                let held = server_named_items(&error, &indices).expect("named items");
                // The server named these items: a validation rejection, an
                // identity deferral that waits for its identity only, or ACK
                // refs that echoed another body witness. Hold them; their
                // siblings settle only from their own exact ACK, re-sent in
                // this pass, and later batches continue.
                let (status, reason, identity_retry_at) = match (
                    error.downcast_ref::<UploadShed>().copied(),
                    error.downcast_ref::<BatchRejected>(),
                ) {
                    (Some(shed), _) => (
                        Some(shed.status),
                        "identity_deferred",
                        Some(
                            current_unix_seconds()
                                .saturating_add(shed_backoff(shed.retry_after).as_secs()),
                        ),
                    ),
                    (None, Some(rejected)) => (Some(rejected.status), "validation_reject", None),
                    (None, None) => (None, "body_witness_refused", None),
                };
                let before = progress.clone();
                for index in &held {
                    let item_fingerprint = fingerprint(&items[*index]);
                    progress.quarantine_retryable_body(
                        item_fingerprint,
                        &body_witness(&items[*index]),
                        identity_retry_at
                            .unwrap_or_else(|| quarantine_retry_after(item_fingerprint)),
                    );
                    crate::local_resource_diagnostics::traversal_point(
                        "quarantine_retry_body",
                        poison_scope,
                        &serde_json::json!({"origin": if identity_retry_at.is_some() { "identity_retry" } else { reason },
                            "fingerprint_hash8": SessionHash::of(item_fingerprint).to_string(),
                            "body_witness_hash8": body_witness(&items[*index]).get(..8).filter(|v| v.bytes().all(|b| b.is_ascii_hexdigit()))}),
                    );
                }
                if persist(progress).is_err() {
                    *progress = before;
                    return Err(anyhow::Error::new(SnapshotLocalStateRejected {
                        operation: if identity_retry_at.is_some() {
                            "save identity deferral quarantine"
                        } else {
                            "save validation rejection quarantine"
                        },
                    }));
                }
                conflicted_entities = conflicted_entities.saturating_add(held.len());
                if identity_retry_at.is_some() && status == Some(503) {
                    isolated_entities = isolated_entities.saturating_add(held.len());
                }
                crate::local_resource_diagnostics::traversal_point(
                    "quarantine_retry",
                    poison_scope,
                    &serde_json::json!({"reason": reason, "status": status,
                        "count": held.len()}),
                );
                let remaining = indices
                    .into_iter()
                    .filter(|index| !held.contains(index))
                    .collect::<Vec<_>>();
                if !remaining.is_empty() {
                    batches.push_front((remaining, false));
                }
            }
            Err(error)
                if indices.len() > 1
                    && adaptive_splits < SNAPSHOT_ADAPTIVE_SPLIT_LIMIT
                    && is_snapshot_batch_split_failure(&error) =>
            {
                adaptive_splits += 1;
                let midpoint = indices.len() / 2;
                let right = indices[midpoint..].to_vec();
                let left = indices[..midpoint].to_vec();
                batches.push_front((right, true));
                batches.push_front((left, true));
            }
            Err(_) if inplace_wait.is_some() => {
                // A short, explicitly transient failure: wait briefly and
                // resend the same page. Each resend re-runs the whole upload
                // boundary (lease, authority, fresh relay token), and the
                // loop-top filter drops anything settled meanwhile. When the
                // budget runs out the failure takes the arms below unchanged.
                let (status, wait) = inplace_wait.expect("admitted in-place retry");
                inplace_retry.resends += 1;
                inplace_retry.waited += wait;
                eprintln!(
                    "local snapshot upload transient status={status} for {poison_scope}; \
                     retrying the batch in place after {} ms (source page resend {}/{SNAPSHOT_INPLACE_RETRY_LIMIT}; \
                     {} of {} ms source page in-place wait budget held under the sync lock)",
                    wait.as_millis(),
                    inplace_retry.resends,
                    inplace_retry.waited.as_millis(),
                    SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET.as_millis(),
                );
                inplace_retry_sleep(wait);
                batches.push_front((indices, adaptive));
            }
            Err(error) if error.downcast_ref::<UploadShed>().is_some() => {
                let shed = error
                    .downcast_ref::<UploadShed>()
                    .copied()
                    .expect("shed diagnostics");
                crate::client_report::record(
                    crate::client_report::ClientReportReason::RatelimitBackoff,
                    1,
                );
                // Fixed labels only: which shed this was (load shedding or the
                // identity-unavailable 503) decides whether a retry can follow.
                eprintln!(
                    "local snapshot upload shed for {poison_scope}: status={}, \
                     retry_after={}, code={}",
                    shed.status,
                    if shed.retry_after.is_some() {
                        "present"
                    } else {
                        "absent"
                    },
                    shed.code.map_or("none", |code| code.as_str()),
                );
                // Stop the pass here rather than hammering the remaining pages
                // at a server that just asked for room. Everything accepted so
                // far is already checkpointed, so the retry resumes instead of
                // restarting.
                return Ok(ResumableUploadResult::Shed {
                    retry_after: shed.retry_after,
                });
            }
            Err(error) => {
                if indices.len() == 1
                    && error
                        .downcast_ref::<UploadFailureDiagnostics>()
                        .is_some_and(UploadFailureDiagnostics::is_snapshot_batch_too_large)
                {
                    crate::local_resource_diagnostics::traversal_point(
                        "quarantine_retry",
                        poison_scope,
                        &serde_json::json!({"status": 413, "count": 1}),
                    );
                }
                return Err(error);
            }
        }
    }

    if conflicted_entities > 0 {
        // Every retryable refused entity is durably quarantined with the same
        // bounded backoff a rejection gets, and every sibling in the page is
        // checkpointed. The distinct result prevents the caller from marking
        // a broad historical backfill complete while preserving that progress.
        eprintln!(
            "local snapshot upload deferred {conflicted_entities} unsettled \
             entity(ies) for {poison_scope}; they are quarantined for a bounded \
             retry while every other entity in the page settled."
        );
    }
    // Backend conflicts and indexed validation holds defer this upload. Local preflight holds
    // disclose local loss through index counters, not a backend capacity error.
    // Exact permanent refusals remain visible without another HTTP request.
    let permanent_rejected = current_body_witnesses
        .iter()
        .filter(|(fingerprint, body)| {
            progress
                .permanent_rejections
                .get(*fingerprint)
                .is_some_and(|record| record.body_witness == **body)
        })
        .count();
    if conflicted_entities > 0 {
        Ok(ResumableUploadResult::Deferred {
            count: conflicted_entities,
            isolated: isolated_entities,
        })
    } else if permanent_rejected > 0 {
        Ok(ResumableUploadResult::Rejected {
            count: permanent_rejected,
        })
    } else {
        Ok(ResumableUploadResult::Completed)
    }
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

crate::heap_layout_bound::fields!(SnapshotUploadProgress; telemetry_only, schema_version, rows, generation, destination_namespace_hash, historical_replay_generation, accepted_fingerprints, accepted_body_witnesses, accepted_body_contexts, context_resend, ack_capacity, retained_stale_ack_count, accepted_cache_states, accepted_identity_buckets, accepted_identity_scope, accepted_cache_heads, pending_cache_heads, head_conflict_challenges, quarantined_fingerprints, permanent_rejections, active_quarantine_witness, active_quarantine_retries, active_reason_reoffers, attempted_reason_reoffers, reason_reoffer_counts, terminal_contract_retry_pending_save, fresh_context_body_acks, context_receipt_candidates);

crate::heap_layout_bound::fields!(PendingCacheHeadFile; source_file_fingerprint, group_fingerprint, entities, reselected_heads, settled_entities);

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

crate::heap_layout_bound::fields!(PermanentSnapshotRejection; body_witness, reason, reoffer, exposure, revisions);
crate::heap_layout_bound::fields!(HeadConflictChallenge; challenge, stale_revision_v2_hash, answer_attempts, last_answer_unix);

#[cfg(test)]
mod codex_sidecar_reuse_tests;

#[cfg(all(test, unix))]
pub(crate) mod resource_schedule;
