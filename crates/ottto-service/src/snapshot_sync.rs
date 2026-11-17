#[cfg(test)]
use self::status::collector_status_request;
#[cfg(test)]
use self::status::counted_poison_fingerprints_for_test;
#[cfg(test)]
use self::status::deferred_entity_state;
#[cfg(test)]
pub(crate) use self::status::detected_uses_cache_path;
use self::status::log_retained_permanent_refusals;
use self::status::record_poison_loss_once;
use self::status::refused_entity_state;
use self::status::report_checkin_status_with_fresh_relay_token;
#[cfg(test)]
use self::status::report_status;
use self::status::report_status_with_fresh_relay_token;
use self::status::retain_counted_poison_fingerprints;
use self::status::scan_request_window_days;
use self::status::snapshot_manifest_window;
#[cfg(test)]
use self::status::snapshot_manifest_window_days;
pub(crate) use self::status::snapshot_source_of_kind;
use self::status::source_kind;
pub use self::status::spawn_collector_checkin_heartbeat;
use self::status::update_detected_uses_cache;
use self::status::upload_agent_status;
use self::status::validated_receipt_window_days;
use self::status::withdraw_and_report_policy_stop;
use self::status::CollectorState;
use self::status::CollectorStatus;
#[cfg(test)]
use self::status::DisclosedLoss;
use self::status::PermanentRefusalCounts;
use self::status::SyncCounts;
use self::status::TerminalManifestSource;
mod status;
#[cfg(test)]
pub(crate) use self::finish::accept_account_release_for_test;
#[cfg(test)]
pub(crate) use self::finish::ack_current_again_quarantines_for_test;
#[cfg(test)]
use self::finish::apply_backfill_cutoff_with_claude_corrections;
use self::finish::cached_source_manifest;
#[cfg(test)]
pub(crate) use self::finish::checkpoint_account_release_for_test;
#[cfg(test)]
pub(crate) use self::finish::checkpoint_page_for_test;
#[cfg(test)]
use self::finish::checkpoint_partial_snapshot_index;
use self::finish::checkpoint_partial_snapshot_index_with_audit_release;
#[cfg(test)]
pub(crate) use self::finish::checkpoint_unselected_for_test;
#[cfg(test)]
pub(crate) use self::finish::classify_holds_for_test;
#[cfg(test)]
use self::finish::clear_source_manifests_for_test;
#[cfg(test)]
use self::finish::commit_completed_with_local_holds;
#[cfg(test)]
pub(crate) use self::finish::decode_hold_manifest_published_for_test;
#[cfg(test)]
use self::finish::finish_selected_settlement;
use self::finish::finish_sync_source;
use self::finish::publish_source_manifest;
#[cfg(test)]
use self::finish::save_index_and_publish_manifest;
use self::finish::server_named_items;
#[cfg(test)]
use self::finish::settle_checkpointed_upload;
#[cfg(test)]
use self::finish::settle_completed_upload;
#[cfg(test)]
use self::finish::settle_index_after_upload;
#[cfg(test)]
use self::finish::settle_upload_corrections_after_selection;
#[cfg(test)]
use self::finish::upload_settled_without_account_holds;
use self::finish::withdraw_source_manifest;
#[cfg(test)]
use self::finish::AccountAuditRelease;
#[cfg(test)]
use self::finish::LocalHoldSettlement;
#[cfg(test)]
use self::finish::SelectedSettlementInputs;
#[cfg(test)]
use self::finish::UploadIndexSettlement;
use self::finish::PARTIAL_CHECKPOINT_FAILURES;
use self::finish::UNPROVEN_TERMINAL_ATTEMPT_COUNT;
use self::prepare::activate_source_upload_context;
use self::prepare::backfill_replay_pending;
use self::prepare::capture_codex_recovery_evidence;
#[cfg(test)]
use self::prepare::claude_destination_history_here;
#[cfg(test)]
use self::prepare::claude_prior_history;
use self::prepare::claude_replay_suppressed;
use self::prepare::cycle_body_witness_revision;
pub(crate) use self::prepare::effective_upload_body_witness_revision;
use self::prepare::exclude_held_effective_body_witness_revision;
#[cfg(test)]
use self::prepare::note_claude_history_cutoff_for_cycle;
#[cfg(test)]
use self::prepare::note_claude_index_rebuild_for_destination;
#[cfg(test)]
use self::prepare::prepare_upload_progress_for_cycle;
use self::prepare::prepare_upload_progress_for_cycle_with_reoffer;
#[cfg(test)]
use self::prepare::save_terminal_contract_claims_for_scan;
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

/// Process-local, content-free count of `Rejected` pages whose local holds
/// were all terminal-bound and settled through the `Completed` restore path.
static CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

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
