pub(crate) use self::lane::apply_source_control;
pub(crate) use self::lane::carry_snapshot_namespace;
pub(crate) use self::lane::disable_snapshot_source;
pub(crate) use self::lane::disable_sources_dropped_from_grant;
pub(crate) use self::lane::enabled_snapshot_sources;
pub(crate) use self::lane::enabled_snapshot_sources_in;
#[cfg(test)]
use self::lane::ensure_snapshot_scan_authority;
#[cfg(test)]
pub(crate) use self::lane::forget_carried_namespaces_for_test;
use self::lane::heartbeat_source;
pub(crate) use self::lane::home_dir;
pub(crate) use self::lane::reconnect_snapshot_source;
#[cfg(test)]
pub(crate) use self::lane::relogin_namespace;
#[cfg(test)]
pub(crate) use self::lane::resume_reconnected_sources;
pub(crate) use self::lane::snapshot_api_base_url;
#[cfg(test)]
use self::lane::snapshot_api_base_url_from;
pub(crate) use self::lane::snapshot_destination_namespace;
use self::lane::snapshot_destination_scoped_index_path;
use self::lane::snapshot_index_path;
pub(crate) use self::lane::snapshot_machine_id;
pub(crate) use self::lane::snapshot_namespace_has_store;
use self::lane::snapshot_upload_context_fingerprint;
pub(crate) use self::lane::snapshot_upload_destination_namespace;
use self::lane::snapshot_upload_progress_path;
use self::lane::snapshot_v3_index_path;
#[cfg(test)]
use self::lane::source_erasure_turn;
pub(crate) use self::lane::source_marker;
#[cfg(test)]
use self::lane::source_marker_path;
pub(crate) use self::lane::source_paused;
#[cfg(test)]
use self::lane::validate_snapshot_destination;
#[cfg(test)]
use self::lane::validate_snapshot_scan_authority;
#[cfg(test)]
pub(crate) use self::lane::validate_state_v2_original_progress;
#[cfg(test)]
pub(crate) use self::lane::with_state_v2_progress_lock;
pub(crate) use self::lane::with_state_v2_progress_owner;
#[cfg(test)]
pub(crate) use self::lane::OLD_PROGRESS_BOUND_FOR_TEST;
#[cfg(test)]
use self::lane::SNAPSHOT_SOURCES;
use self::retry::conflict_probe_after;
use self::retry::current_rfc3339;
use self::retry::current_unix_seconds;
#[cfg(test)]
use self::retry::jittered_retry_after;
pub(crate) use self::retry::quarantine_retry_after;
use self::retry::rfc3339_after_minutes;
pub(crate) use self::retry::safe_error;
use self::retry::upload_failure_diagnostic;
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
pub(crate) use self::telemetry_only::agent_status_source_enabled;
#[cfg(test)]
pub(crate) use self::telemetry_only::agent_status_source_enabled_in;
#[cfg(test)]
use self::telemetry_only::clear_setup_run_refresh_hold;
use self::telemetry_only::local_health_upload_can_wait_quietly;
use self::telemetry_only::persist_machine_icon;
#[cfg(test)]
use self::telemetry_only::persist_machine_icon_at;
pub(crate) use self::telemetry_only::reset_relay_authorization_backoff;
pub use self::telemetry_only::upload_agent_status_snapshots;
pub use self::telemetry_only::upload_local_health_projection_now;
use self::telemetry_only::upload_local_health_projection_reporting;
use self::telemetry_only::LocalHealthRefreshHeld;
use self::telemetry_only::NoHeartbeatSource;
mod status;

/// Rest-heap diagnostics: counted poison scopes and fingerprints, or None while busy.
pub(crate) fn counted_poison_entries() -> Option<(usize, usize)> {
    status::counted_poison_entries()
}
#[cfg(test)]
pub(crate) use self::finish::accept_account_release_for_test;
#[cfg(test)]
pub(crate) use self::finish::accept_request_contributions_for_test;
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
#[cfg(test)]
use self::finish::checkpoint_partial_snapshot_index_with_hold_release;
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
use self::finish::AccountHoldRelease;
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
use self::lane::cycle_heartbeat;
use self::lane::local_cadence_phase_offset;
#[cfg(test)]
pub(crate) use self::lane::retained_with_withheld;
pub use self::lane::spawn_claude_agent_status_refresh;
pub use self::lane::spawn_local_health_projection_sync;
pub use self::lane::spawn_local_snapshot_sync;
pub use self::lane::spawn_one_shot_local_snapshot_sync;
pub use self::lane::spawn_startup_source_reverify;
#[cfg(test)]
use self::lane::ClaudeAccountSwitchProbe;
#[cfg(test)]
use self::lane::SnapshotCycleOwner;
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
pub(crate) use self::retry::MAX_CYCLE_INTERVAL;
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
#[cfg(test)]
use self::upload::attempt_snapshot_page;
use self::upload::is_shed_failure;
#[cfg(test)]
use self::upload::is_snapshot_batch_split_failure;
use self::upload::is_upload_outage;
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
use self::upload::SnapshotEntityDeferred;
use self::upload::SnapshotLocalStateRejected;
#[cfg(test)]
use self::upload::SnapshotPackingLength;
#[cfg(test)]
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
    aggregate_detected_uses, merge_detected_uses, without_pre_account_cache,
    DETECTED_USE_RETENTION_DAYS,
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
#[cfg(test)]
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
use std::io::ErrorKind;
#[cfg(test)]
use std::io::Write;
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

#[cfg(test)]
pub(crate) use tests::codex_archive_tests::{
    archive_upload_checkpoint, assert_archive_debt_preserves_replay_progress,
    codex_transition_acked_route, codex_transition_cold_batches,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "snapshot_sync/tests/exact_body_ack_tests.rs"]
mod exact_body_ack_tests;

#[cfg(test)]
#[path = "snapshot_sync/tests/tail_ack_ledger.rs"]
pub(crate) mod tail_ack_ledger;

#[cfg(test)]
#[path = "snapshot_sync/tests/usage_decrease_hold_tests.rs"]
mod usage_decrease_hold_tests;

#[cfg(test)]
#[path = "snapshot_sync/tests/head_conflict_answer_tests.rs"]
pub(crate) mod head_conflict_answer_tests;

#[cfg(test)]
#[path = "snapshot_sync/tests/change_reason_tests.rs"]
mod change_reason_tests;

#[cfg(test)]
#[path = "snapshot_sync/tests/progress_unchanged_save_tests.rs"]
mod progress_unchanged_save_tests;

#[cfg(test)]
#[path = "snapshot_sync/tests/head_conflict_released_progress_fixture.rs"]
mod head_conflict_released_progress_fixture;

#[cfg(test)]
mod codex_sidecar_reuse_tests;

#[cfg(all(test, unix))]
pub(crate) mod resource_schedule;
