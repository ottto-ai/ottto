use crate::codex_scan_diagnostics::{
    self, CensusGates, CodexScanDiagnostics, FileReason, IdentityConflictTaxonomy, IncompleteShape,
    RecoveryLineage, SidecarOpenCounts, StateRowFieldDiffs, UnreadableCause, UnreadableCauses,
    CREATOR_DIFFERENT_OWNER, CREATOR_NAMED, CREATOR_NO_PAIR, CREATOR_PREVIOUSLY_UPLOADED,
    LINEAGE_SAMPLES,
};
use crate::local_resource_diagnostics::claude_absence::Parent;
use crate::local_resource_diagnostics::claude_contract;
use crate::local_resource_diagnostics::claude_reread::IgnoredVeto;
use crate::local_resource_diagnostics::rearm_cause;
use crate::local_resource_diagnostics::{
    line_delivery_unselected, page_selection, CapCounts, PageSelection, UnselectedReason,
};
use crate::snapshot_watcher::ListingRequest;
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// The owed-key `DiscoveryRetention` of a `ScanIndex`, borrowing only its
/// registered fields so the traversal can stay mutably borrowed.
macro_rules! discovery_retention {
    ($index:expr, $growth:expr) => {
        $crate::snapshots::DiscoveryRetention {
            growth: Some($growth),
            ..discovery_retention!($index)
        }
    };
    ($index:expr) => {
        $crate::snapshots::DiscoveryRetention {
            files: &$index.files,
            account_holds: &$index.claude_account_deferred_holds,
            memo: Some(&$index.withheld_memo),
            growth: None,
        }
    };
}

/// `fn $with(body)` runs `body` on one process-wide value: a `static Mutex`
/// in the daemon, whose poisoned value is used as is (`clear_poison: true`
/// also clears the poison); each test thread has its own copy, since tests
/// share one process.
macro_rules! process_state {
    (
        $(#[$attr:meta])*
        $vis:vis fn $with:ident: $ty:ty = $init:expr; clear_poison: $clear:literal
    ) => {
        $(#[$attr])*
        $vis fn $with<T>(body: impl FnOnce(&mut $ty) -> T) -> T {
            #[cfg(not(test))]
            {
                static STATE: std::sync::Mutex<$ty> = std::sync::Mutex::new($init);
                let mut state = STATE.lock().unwrap_or_else(|poisoned| {
                    if $clear {
                        STATE.clear_poison();
                    }
                    poisoned.into_inner()
                });
                body(&mut state)
            }
            #[cfg(test)]
            {
                thread_local! {
                    static STATE: std::cell::RefCell<$ty> =
                        const { std::cell::RefCell::new($init) };
                }
                STATE.with(|state| body(&mut state.borrow_mut()))
            }
        }
    };
}

pub(crate) mod cache_observations;
#[cfg(test)]
pub(crate) mod cache_overcap_tests;
mod change_reason;
mod claude_context_file_birth;
pub(crate) mod claude_cross_root_evidence;
mod upload_context_read;
mod upload_context_receipt;
pub(crate) use upload_context_receipt::Candidate as UploadContextReceiptCandidate;
pub(crate) use upload_context_receipt::ContextInputs as UploadContextInputs;
#[cfg(test)]
pub(crate) mod privacy_flip_modes;
#[cfg(test)]
mod upload_context_receipt_tests;
#[cfg(test)]
mod upload_policy_tests;
pub use claude_context_file_birth::{ClaudeContextBasisCounts, ClaudeContextFileBirthCounts};
pub(crate) use claude_context_file_birth::{
    ClaudeFileBirth, ClaudeFileBirthVerdict, ClaudeVetoApiRows,
};
pub mod claude_copy_prefix_reread;
mod claude_history_upgrade;
#[cfg(test)]
mod codex_creator_slot_tests;
mod codex_root_copies;
pub(crate) mod ownership_diagnostics;
#[cfg(test)]
pub(crate) use claude_history_upgrade::{
    local_count as history_local_count, with_max_gated_claude_revision,
    LocalCount as HistoryLocalCount, REQUEST_OWNED_USAGE_CONTRACT,
};
use ownership_diagnostics as ownership;
#[cfg(test)]
mod admission_reoffer_window_tests;
mod claude_family_census_shadow;
#[cfg(test)]
mod claude_family_census_shadow_tests;
#[cfg(test)]
mod claude_history_upgrade_tests;
mod claude_reemission_exclusions;
#[cfg(all(test, unix))]
mod claude_terminal_e2_retry_tests;
#[cfg(test)]
mod contract5_cutover_tests;
mod g7_debt;
pub(crate) mod money_freshness;
#[cfg(test)]
pub(crate) use claude_reemission_exclusions::with_no_list_cutoff;
mod shared_value;
#[cfg(test)]
mod shared_value_tests;
pub(crate) use shared_value::{Shared, SharedMap};
#[path = "snapshots/claude_request_money/birth_store.rs"]
pub(crate) mod claude_money_birth_store;
pub(crate) mod claude_request_accounts;
// These census helpers remain until the separate persisted-format cleanup.
#[allow(
    dead_code,
    reason = "these census helpers await the persisted-format cleanup"
)]
pub(crate) mod claude_request_census;
pub(crate) mod claude_request_identity;
pub(crate) mod claude_request_money;
pub(crate) mod claude_telemetry_retention;
mod scan_index_integration;
pub(crate) mod scan_index_persistence;
pub(crate) mod state_v2;
use scan_index_integration::read_scan_index_representation;
pub(crate) mod scan_index_health;
#[cfg(test)]
pub(crate) use tests::claude_request_account_mixed_fixture;
#[cfg(test)]
pub(crate) use tests::output as claude_request_account_output;
mod codex_compressed_input;
mod codex_rollout_carry;
pub(crate) mod codex_sqlite_read;
#[cfg(test)]
mod codex_zst_refusal_tests;
mod compaction_events;
pub(crate) use compaction_events::bounded_compaction_events;
pub use compaction_events::SnapshotCompactionEvent;
use compaction_events::{ClaudeCompactionTrigger, CodexCompactionSizes};
#[cfg(test)]
mod codex_context_window_tests;
#[cfg(test)]
mod codex_counting_lifecycle_tests;
#[cfg(test)]
mod codex_counting_rss_tests;
#[cfg(test)]
mod codex_counting_v2_tests;
mod codex_counting_version;
mod codex_dictionary_slots;
mod codex_file_join;
pub(crate) use codex_file_join::CODEX_JOIN_VALIDATION_FAILURES;
#[cfg(test)]
mod file_set_digest_tests;
#[cfg(test)]
pub(crate) use codex_counting_version::TestCutover;
#[cfg(test)]
pub(crate) use codex_file_join::tests::{counting_v2_fixture, native_join_fixture_root};
#[cfg(test)]
mod claude_response_compaction_tests;
mod claude_response_records;
#[cfg(test)]
mod claude_thinking_tokens_tests;
#[cfg(test)]
mod claude_usage_iterations_tests;
mod codex_usage_occurrence;
mod context_curve;
mod session_start;
/// Tail state codecs: each source's head and pages in the state database.
#[cfg(unix)]
mod tail_source;
pub(crate) use session_start::OpeningFileCandidate;
pub(crate) use session_start::{session_start_verdict, StartVerdict};
pub use session_start::{SnapshotOpeningFile, SnapshotSessionStart};
mod disappearance_diagnostics;
#[cfg(test)]
mod launch_demand_tests;
#[cfg(test)]
mod launcher_recognition_tests;
mod local_context_points;
pub(crate) use local_context_points::LocalContextPoint;
use local_context_points::LocalContextPoints;
mod codex_fragment;
pub(crate) mod codex_version;
pub(crate) mod discovery_growth;
#[cfg(test)]
mod discovery_growth_tests;
#[cfg(unix)]
pub(crate) mod durable_sources;
#[cfg(test)]
pub(crate) mod e2_pipeline_scan_fixture;
#[cfg(test)]
mod first_read_tests;
#[cfg(test)]
mod held_audit_restore_tests;
pub(crate) mod line_delivery;
#[cfg(test)]
mod line_delivery_tests;
mod oversized_discovery;
#[path = "pi_retry_inputs.rs"]
mod pi_retry_inputs;
mod sampled_audit;
mod sampled_jsonl;
pub(crate) mod sampled_scan;
#[cfg(test)]
mod source_erasure_tests;
#[cfg(test)]
mod transcript_acquisition_tests;
mod traversal_transition;
#[cfg(test)]
mod usage_occurrence_retention_tests;
pub(crate) mod withheld_account;
#[cfg(test)]
mod withheld_owner_charge_tests;
use crate::local_resource_diagnostics::CodexZstCause;
use cache_observations::{CacheObservations, OwnedRequest, RequestSlot};
pub(crate) use claude_history_upgrade::{
    note_prior_history_unverified, PriorHistory, MAX_GATED_CLAUDE_REVISION,
};
use claude_history_upgrade::{
    HistoryDecision, HistoryEmission, HistoryHold, HistoryPage, NoListPolicy,
};
use claude_reemission_exclusions::ReemissionExclusions;
use claude_request_census::{ClaudeRequestCensus, ClaudeRequestCensusShadowState};
pub(crate) use claude_response_records::ClaudeTranscriptUsageOccurrence;
use claude_response_records::{
    ClaudeResolveFailure, ClaudeResponseBook, ClaudeResponseObservation, ClaudeSelectorTable,
    CLAUDE_RECORDS_PER_FILE_ALARM,
};
#[cfg(test)]
use claude_response_records::{ClaudeResponseRecord, CompactClaudeSelector};
use codex_compressed_input::{is_compressed_codex_rollout, refuse_compressed_codex, OpenedInput};
pub(crate) use pi_retry_inputs::PiRetryInputs;
#[cfg(test)]
pub(crate) use sampled_scan::codex_cursor::{cursor_limit_for_test, with_test_limits_for_test};
pub(crate) use sampled_scan::codex_cursor::{CodexCursorPort, CodexCursorTicket};

#[cfg(test)]
pub(crate) use context_curve::v1::CONTEXT_CURVE_CONTRACT_VERSION;
#[cfg(test)]
use context_curve::v1::{
    CONTEXT_CURVE_RETENTION_ANCHOR, CONTEXT_CURVE_RETENTION_COMPACTION_AFTER,
    CONTEXT_CURVE_RETENTION_COMPACTION_BEFORE, CONTEXT_CURVE_RETENTION_FILL,
    CONTEXT_CURVE_RETENTION_PEAK, CONTEXT_CURVE_RETENTION_TAIL, CONTEXT_CURVE_SAMPLING_REVISION,
    MAX_CONTEXT_CURVE_BOUNDARIES, MAX_CONTEXT_CURVE_MODEL_WINDOWS, MAX_CONTEXT_CURVE_POINTS,
    MAX_CONTEXT_CURVE_WIRE_BYTES,
};
use context_curve::{ContextCurveCandidateBoundary, ContextCurveCandidatePoint};
pub use context_curve::{
    SnapshotContextCurve, SnapshotContextCurveBoundary, SnapshotContextCurveModelWindow,
    SnapshotContextCurvePoint,
};

pub fn collector_version() -> String {
    ottto_core::compiled_release_version()
}

pub const SNAPSHOT_SCHEMA_VERSION: u16 = 6;
pub const SNAPSHOT_ENTITY_ACK_CONTRACT: &str = "snapshot_entity_ack:v1";
pub const SNAPSHOT_HEAD_CAS_CONTRACT: &str = "snapshot_head_etag:v1";
/// Backend money-decrease holds: a held request-owned literal body is
/// refused as retryable (`permanent=false`) instead of being applied.
pub const USAGE_DECREASE_HOLD_ACK_CONTRACT: &str = "usage_decrease_hold_ack:v1";
/// Cache-bearing batches ask the server to echo the completed cache state
/// behind each stored ref's body witness. Older servers ignore the field.
pub const CACHE_STATE_ACK_CONTRACT: &str = "cache_state_ack:v1";
// SnapshotStatusRequest endpoint stayed at v5; only the batch endpoint
// cut over to v6 in this change. Backend's AgentSessionSnapshotStatusRequest
// is still Literal[5] (backend/app/schemas/agent_session_snapshots.py).
pub const SNAPSHOT_STATUS_SCHEMA_VERSION: u16 = 5;
// The per-request long-context price bucket (`provider_context_bucket`)
// restates recent Codex history once. It rides the release's single bundled
// parser-version bump rather than bumping here. Rollouts last modified on or
// after the price-line effective date are revisited; older rollouts are never
// re-read for it. That is file selection only, not a guaranteed superset: a
// rollout copied or restored with an older preserved mtime is missed, and
// compressed `.jsonl.zst` rollouts are never scanned at all, so recent history
// is restated only where its `.jsonl` is still present. Inside a revisited file
// only requests dated on or after that instant gain a bucket, so older hours
// re-parse to the rows they already had. The instant is fixed, not relative to
// now, so the revisit set never moves; each file settles once its fingerprint
// carrying this token is durably saved.
const CODEX_CONTEXT_BUCKET_REVISIT: &str = "codex_context_bucket_revisit:v1";

mod usage;
#[cfg(test)]
use scan::identity::CODEX_CONTEXT_BUCKET_REVISIT_FROM_UNIX_NANOS;
use scan::identity::{
    candidate_scan_identity, CODEX_CREATED_THREAD_TIME_TOLERANCE_NANOS,
    JSONL_TERMINAL_DISPOSITION_GENERATION, LOCAL_SCAN_INDEX_IDENTITY_VERSION,
    OPENED_OBJECT_IDENTITY_VERSION,
};
pub use scan::identity::{
    CLAUDE_CODE_SCAN_IDENTITY_VERSION, CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
    CODEX_SCAN_IDENTITY_VERSION, CODEX_SNAPSHOT_PARSER_VERSION, PI_SCAN_IDENTITY_VERSION,
    PI_SNAPSHOT_PARSER_VERSION,
};
#[cfg(test)]
use scan::limits::CODEX_FORWARD_EVIDENCE_FROM_UNIX_SECONDS;
pub(crate) use scan::limits::LISTING_INTERVAL_SECONDS;
use scan::limits::{
    dated_on_or_after, in_codex_forward_evidence_epoch, CODEX_LEGACY_REPEAT_FROM_UNIX_SECONDS,
    LISTING_OWED_PACE_SECONDS, UNHEALTHY_SCAN_RETRY_BASE_SECONDS,
    UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS, UNHEALTHY_SCAN_RETRY_MAX_SECONDS,
};
pub use scan::limits::{
    BACKFILL_WINDOW_DAYS, MAX_BACKFILL_FILES_PER_SOURCE, MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK,
    MAX_WATCHER_HINTED_FILES_PER_TICK,
};
pub(crate) use usage::provider_context_bucket;
pub use usage::CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS;
use usage::PROVIDER_PRICE_LINE_EFFECTIVE_FROM_UNIX_SECONDS;
#[cfg(test)]
use usage::{
    provider_price_line, provider_price_line_model_key, ProviderPriceLineKind, PROVIDER_PRICE_LINES,
};
use usage::{
    usage_totals_equal, usage_totals_from_item, usage_totals_from_model_usage,
    usage_totals_has_usage, UsageCosts, UsageTotals, PI_COST_FIELD_CEILING_PICOS, USD_PICO_SCALE,
};

const REPOSITORY_IDENTITY_CACHE_MAX_ENTRIES: usize = 512;
const REPOSITORY_IDENTITY_CACHE_TTL_SECONDS: u64 = 6 * 60 * 60;

mod sources;
pub(crate) use sources::claude::context_posture::{
    bounded_compaction_timestamps, ClaudeCompactionObservation, MAX_COMPACTION_TIMESTAMPS,
};
use sources::claude::context_posture::{
    claude_compaction_summary, clear_claude_context_posture, paired_claude_legacy_compactions,
    set_claude_compaction_scalars, ClaudeCompactionKind, CompactionMetrics,
};

mod wire;
pub use wire::batch_validation::validate_snapshot_batch_request;
pub(crate) use wire::batch_validation::validate_snapshot_batch_request_with_item_limit;
#[cfg(test)]
use wire::content_hash::{
    policy_neutral_component_hashes, snapshot_content_hash, snapshot_content_identity_body,
    snapshot_revision_hash, snapshot_revision_v2_body, snapshot_revision_v2_hash,
};
pub(crate) use wire::content_hash::{
    snapshot_fingerprint, snapshot_fingerprint_from_component_hashes,
    snapshot_semantic_component_hashes, snapshot_semantic_envelope, snapshot_upload_body_witness,
    snapshot_upload_body_witness_version, snapshot_upload_body_witness_with_cache_state,
    SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_SESSION_ACCOUNT_VERSION,
    SNAPSHOT_BODY_WITNESS_ENVELOPE_SESSION_ACCOUNT_VERSION,
};
#[cfg(test)]
pub(crate) use wire::content_hash::{
    SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION,
    SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION,
};
pub(crate) use wire::{
    declares_usage_decrease_hold_ack, ACCOUNT_SOURCE_CONTRACT,
    CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE, CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS,
    CLAUDE_ACCOUNT_WITHHELD_TOO_MANY_ACCOUNTS, MAX_SEMANTIC_ENVELOPE_BYTES,
    MAX_SESSION_ARTIFACT_VALUE_CHARS, MAX_SNAPSHOT_BATCH_WIRE_BYTES,
    MAX_SNAPSHOT_ITEM_CLEAR_WIRE_BYTES, MAX_SNAPSHOT_ITEM_WIRE_BYTES,
    MAX_SNAPSHOT_RECONSTRUCTION_FAILURES, POLICY_NEUTRAL_COMPONENTS,
    SNAPSHOT_REVISION_CONTRACT_VERSION, SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
    SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
};
use wire::{
    default_true, is_false, is_zero_u16, is_zero_u64, is_zero_u8, SnapshotItemWire,
    CLAUDE_ATTRIBUTION_SELECTOR_KEYS, CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION,
    CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION, CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS,
    FILE_CONTENT_SAMPLE_BYTES, MAX_CLAUDE_USAGE_AUTHORITY_FAILURES, MAX_MODEL_USAGE_ROWS,
    MAX_SESSION_ARTIFACTS, MAX_TOOL_USAGE_NAMES, MAX_TOOL_USAGE_NAME_LENGTH, ROW_BILLING_FIELDS,
    SCAN_INDEX_SCHEMA_VERSION, SNAPSHOT_ACCEPTED_LEDGER_PRE_LEDGER_VERSION,
    SNAPSHOT_ACCEPTED_LEDGER_UNPROVEN_VERSION, SNAPSHOT_ACCEPTED_LEDGER_VERSION,
    SNAPSHOT_UNPROVEN_RETRY_CONTRACT_VERSION,
};
pub use wire::{
    AccountSource, ClaudeRemovedUsage, CopyUnprovenCounts, SessionAccountEvidence, SessionArtifact,
    SnapshotActivityCount, SnapshotActivitySummary, SnapshotBatchRequest, SnapshotCapabilityBucket,
    SnapshotCapabilityCount, SnapshotCost, SnapshotIdentityPart, SnapshotItem, SnapshotModelUsage,
    SnapshotOrigin, SnapshotProvenance, SnapshotRequestEvidence, SnapshotSemanticEnvelope,
    SnapshotSource, SnapshotToolUsage, SnapshotUsageBucket, SNAPSHOT_CONTENT_HASH_EPOCH,
    SNAPSHOT_MANIFEST_CONTRACT_VERSION, SNAPSHOT_MANIFEST_SCOPE,
    SNAPSHOT_QUARANTINE_CONTRACT_VERSION, SNAPSHOT_QUARANTINE_RETRY_SECONDS,
};

#[cfg(test)]
use discovery::traversal::state::SettledScanResidue;
#[cfg(unix)]
pub(crate) use discovery::traversal::state::{after_source_save, begin_source_pass};
#[cfg(test)]
pub(crate) use discovery::traversal::state::{
    begin_continuation_read_ranges_for_test, take_continuation_read_ranges_for_test,
};
pub(crate) use discovery::traversal::state::{
    CodexContinuationEvidence, ReasonReofferCooldown, TailDiscovery, UploadAckRetirementHandoff,
};
use discovery::traversal::state::{
    CodexInventoryHold, ScanResidueWitness, ScanTraversalCheckpoint, ScanTraversalCounts,
    ScanTraversalPath, ScanTraversalResidue, TerminalJsonlDisposition, TerminalJsonlLoss,
};
pub use scan_index::entry::ScanIndexEntry;
use scan_index::serde_lenient::deserialize_lenient_default;
#[cfg(test)]
pub use scan_index::snapshot_quarantine_record;
#[cfg(all(test, unix))]
use scan_index::PRE_E2_TERMINAL_DEADLINE_CUTOFF;
use scan_index::{
    claude_terminal_predates_e2, codex_protected_owner,
    initial_claude_usage_authority_failure_count, snapshot_quarantine_deadline_is_bounded_at,
    valid_codex_protected_owner, ClaudeUsageAuthorityQuarantineDisposition,
    ClaudeUsageAuthorityQuarantineRecord, ClaudeUsageFamilyWitness, SessionAccountBinding,
};
pub(crate) use scan_index::{
    quarantine_context_only_changed, snapshot_quarantine_deadline_is_bounded,
    snapshot_quarantine_witness_for_context, UnsettledUploadCause,
};
pub use scan_index::{
    snapshot_quarantine_witness, ScanIndex, SnapshotQuarantineDisposition,
    SnapshotQuarantineRecord, SnapshotQuarantineWitness,
};

#[cfg(test)]
pub(crate) use upload::finalize::snapshot_item_wire_size;
#[cfg(test)]
use upload::finalize::snapshot_semantic_activity_at;
use upload::finalize::PendingIndexFinalization;
pub use upload::finalize::{
    finalize_scan_after_policy, finalize_scan_after_policy_with_body_witness,
};
pub(crate) use upload::finalize::{
    prepare_codex_recovery_diagnostics, record_lineage_parentless_while_incomplete,
    snapshot_source_from_api_slug,
};

#[cfg(test)]
pub(crate) use sources::claude::census::authority_proof_correction::claude_authority_drops_for_test;
#[cfg(test)]
use sources::claude::census::authority_proof_correction::ClaudeEmptyMapAdvance;
use sources::claude::census::authority_proof_correction::{
    claude_authority_record_contract_is_valid, count_claude_authority_unwitnessed_demotion,
    ClaudeAuthorityProofCorrection,
};
pub(crate) use sources::claude::census::authority_proof_correction::{
    ClaudeCutoffCorrectionCandidate, ClaudeProofBodyDrains, ClaudeProofCorrectionCandidate,
};
include!("snapshots/load_containment.rs");

#[cfg(test)]
mod compact_index_tests;
mod lenient_decode;
#[cfg(test)]
mod lenient_decode_tests;
#[cfg(test)]
mod pi_ledger_tests;
pub(crate) mod terminal_contract_retry;
#[cfg(test)]
mod terminal_contract_retry_tests;

#[cfg(test)]
pub(crate) const MAX_CLAUDE_USAGE_AUTHORITY_FAILURES_FOR_TEST: u8 =
    MAX_CLAUDE_USAGE_AUTHORITY_FAILURES;

#[cfg(test)]
pub(crate) use sources::claude::census::authority::ClaudeAuthorityRecordForTest;
pub use sources::claude::census::authority::ClaudeRequestCensusShadowCounts;
pub use sources::claude::census::authority::ClaudeUsageAuthorityDisposition;
use sources::claude::census::authority::{
    claude_accepted_ledger_is_current, claude_index_file_body_accepted,
    claude_usage_authority_deadline_is_bounded, claude_usage_authority_preserves_pending,
    claude_usage_authority_retry_deadline, claude_usage_family_witness_fingerprint,
    ClaudeTranscriptUsageOccurrenceWitness, ProvenClaudeUsageFamily,
    MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS,
};
#[cfg(test)]
use sources::claude::census::authority::{sha256_hex_is_well_formed, ClaudePostureAdmission};

// Coverage requires a non-quarantined body ACK, not a refusal checkpoint.
fn codex_index_file_body_accepted(index: &ScanIndex, key: &str, entry: &ScanIndexEntry) -> bool {
    codex_counting_version::proven_owner(entry).is_some()
        && claude_index_file_body_accepted(index, key, entry)
}

#[derive(Debug, Clone)]
struct ReducedClaudeUsageLedger<R = crate::claude_local_otel::ClaudeLocalOtelEvidence> {
    evidence_fingerprint: String,
    assigned_request_id_hashes: BTreeMap<String, BTreeSet<String>>,
    rows_by_member: BTreeMap<String, Vec<R>>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanParseOutcome {
    /// Old indexes cannot distinguish an empty parse from an interrupted one.
    #[default]
    Unknown,
    Snapshot,
    ConfirmedEmpty,
    PolicySuppressed,
}

/// Exact `snapshot_manifest:v2` wire contract carried on collector check-ins.
/// Census diagnostics stay in the top-level status counters rather than
/// masquerading as server proof inside this producer-side manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotSourceManifest {
    pub contract_version: String,
    pub scope: String,
    pub source: String,
    pub window_start: String,
    pub window_end: String,
    pub entity_count: u64,
    pub rolling_hash: String,
}

/// RAM-only receipt inputs from existing traversal/admission state. No census
/// decision, durable field, or scheduling change is made by this projection.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CensusStatus {
    pub pending_work: bool,
    pub retryable_problem: bool,
    pub transport_reservation_refused: bool,
    pub state_loader_failed: bool,
    pub reconciliation_incomplete: bool,
    pub retry_attempt: u8,
    pub retry_not_before_unix_seconds: Option<u64>,
}

macro_rules! scan_result {
    (pub struct $name:ident { pub source: SnapshotSource,
        $($(#[$attr:meta])* $vis:vis $field:ident: $ty:ty,)*
    }) => {
        #[derive(Debug, Clone)]
        pub struct $name { pub source: SnapshotSource, $($(#[$attr])* $vis $field: $ty,)* }
        impl $name {
            fn empty(source: SnapshotSource) -> Self {
                Self { source, $($field: Default::default(),)* }
            }
        }
    };
}
scan_result! {
pub struct SourceScanResult {
    pub source: SnapshotSource,
    pub(crate) census_status: CensusStatus,
    pub backfill_window_days: u64,
    pub backfill_file_limit: usize,
    pub discovered_file_count: usize,
    pub skipped_file_count_due_to_limit: usize,
    pub scan_cap_hit: bool,
    pub scanned_file_count: usize,
    pub scanned_session_count: usize,
    pub semantic_noop_count: usize,
    pub census_complete: bool,
    pub census_window_end: String,
    /// State-only Codex census is separate from transcript discovery. If an
    /// existing SQLite source was unreadable, its previous durable map must be
    /// retained even while healthy transcript siblings progress.
    pub state_census_complete: bool,
    /// Display/naming sidecars are optional enrichment, but a partial read
    /// cannot publish a source-wide manifest or advance the upload context.
    pub sidecar_census_complete: bool,
    pub symlink_rejected_count: usize,
    pub directory_entry_cap_exceeded_count: usize,
    pub unreadable_path_count: usize,
    pub oversized_file_count: usize,
    pub disappeared_file_count: usize,
    pub malformed_json_line_count: usize,
    pub invalid_utf8_line_count: usize,
    pub over_line_cap_count: usize,
    pub recognized_usage_drop_count: usize,
    pub ownership_incomplete_file_count: usize,
    pub(crate) causes: ownership::Counts,
    pub zero_snapshot_confirmed_count: usize,
    pub zero_snapshot_usage_evidence_count: usize,
    pub dropped_usage_record_count: u64,
    /// The generation's SETTLED share of each public loss counter above
    /// (`ScanTraversalCounts::terminal_*`): loss that carries a durable
    /// terminal disposition or was settled as non-progressing once discovery
    /// finished without a retryable problem. Each is a decomposition of the
    /// public counter it is named after, never an addend, so `terminal <=
    /// public` always holds; equality in every class is what lets a receipt
    /// prove that all the loss it discloses is loss no retry can change.
    pub terminal_ownership_incomplete_file_count: usize,
    pub terminal_zero_snapshot_usage_evidence_count: usize,
    pub terminal_recognized_usage_drop_count: usize,
    pub terminal_dropped_usage_record_count: u64,
    pub terminal_over_line_cap_count: usize,
    /// Cardinalities of the residue witness this generation recorded
    /// (`ScanIndex::scan_residue_witness`), counts only. All zero when the
    /// generation did not complete (the durable witness then describes an
    /// earlier census, not this scan) and when it completed clean.
    pub census_residue_index_key_count: usize,
    pub census_residue_archived_rollout_count: usize,
    pub snapshots: Vec<SnapshotItem>,
    /// Exact selection deferrals from this page, diagnostic only; never persisted.
    pub(crate) claude_queued_family_deferred_paths: BTreeSet<claude_money_birth_store::LocationKey>,
    pending_finalization: Vec<PendingIndexFinalization>,
    /// RAM-only observations of this bounded page; never serialized or uploaded.
    discovery_growth: discovery_growth::Page,
    pub(crate) local_codex_diagnostics: Option<CodexScanDiagnostics>,
    /// Local-only V2 counting receipts of this scan, moved out of its census.
    /// `None` when no configured counting parse finished (never a zero block).
    /// No production reader; scan tests assert the receipts.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "receipts are asserted by scan tests only")
    )]
    pub(crate) codex_counting_v2: Option<Box<crate::codex_scan_diagnostics::CountingV2Receipts>>,
    codex_join_validation: Option<codex_file_join::Validation>,
    codex_legacy_join_baselines: Vec<codex_file_join::LegacyBaseline>,
    /// Request-census shadow, measured by a complete Claude terminal scan.
    /// Count-only; the local evidence line reports it.
    pub(crate) claude_request_census_shadow: Option<ClaudeRequestCensusShadowCounts>,
    /// Stage 1 hunk A: the paused cursor job's continuation ticket, minted
    /// at this page's pause (`PauseEnd::Paused` only). None on every other
    /// end, and on an unaccelerated attempt.
    continuation_ticket: Option<sampled_scan::codex_cursor::CodexCursorTicket>,
    continuation_evidence: Option<Arc<Mutex<Option<CodexContinuationEvidence>>>>,
}
}

#[derive(Clone, Debug)]
pub(crate) struct CodexJoinValidator(codex_file_join::Validation);
impl CodexJoinValidator {
    pub(crate) fn validate(&self, snapshots: &[SnapshotItem]) -> Result<()> {
        let owners = snapshots
            .iter()
            .map(|item| resolve_codex_identity(&item.source_session_id))
            .collect();
        self.0.validate(&owners).map(|_| ())
    }
}
impl SourceScanResult {
    /// Call only after the selected index was saved, including partial saves.
    pub(crate) fn report_discovery_growth_after_save(&self, index: &ScanIndex) {
        self.discovery_growth.report(self.source, index);
    }

    pub(crate) fn take_continuation_evidence(&mut self) -> Option<CodexContinuationEvidence> {
        self.continuation_evidence.take()?.lock().ok()?.take()
    }
    /// Stage 1 hunk A: the ticket `CodexCursorPort::ticket_for` reads.
    pub(crate) fn continuation_ticket(
        &self,
    ) -> Option<&sampled_scan::codex_cursor::CodexCursorTicket> {
        self.continuation_ticket.as_ref()
    }
    pub(crate) fn validate_codex_checkpoint(&self) -> Result<()> {
        if let Some(validation) = &self.codex_join_validation {
            validation.validate_all()?;
        }
        Ok(())
    }
    pub(crate) fn reconcile_codex_legacy_joining(
        &mut self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
        machine_id: &str,
        mut project: impl FnMut(&mut ScanIndex, &mut Vec<SnapshotItem>),
    ) {
        let mut held = BTreeSet::new();
        for mut baseline in std::mem::take(&mut self.codex_legacy_join_baselines) {
            project(index, &mut baseline.snapshots);
            let matches = |snapshots: &[SnapshotItem]| {
                let fingerprints = snapshots
                    .iter()
                    .map(|snapshot| snapshot_fingerprint(SnapshotSource::Codex, snapshot))
                    .collect::<BTreeSet<_>>();
                snapshot_file_entity_set_hex(fingerprints) == baseline.expected
            };
            if matches(&baseline.snapshots) {
                continue;
            }
            // Explicit missing/conflict creator evidence intentionally retracts
            // legacy guessed ownership. Compare with the previously cached
            // binding only to isolate that authorized correction; never emit it.
            for item in &mut baseline.snapshots {
                if item
                    .session_account_evidence
                    .as_ref()
                    .is_some_and(|evidence| {
                        evidence.evidence_source == "codex_creator_header:v1"
                            && matches!(evidence.identity_disposition, Some("missing" | "conflict"))
                    })
                {
                    let key =
                        sha256_hex(&["session_owner:v1", machine_id, &item.source_session_id]);
                    if let Some(binding) = previous.session_account_bindings.get(&key) {
                        set_session_account_hash(item, Some(&binding.account_identifier_hash));
                    }
                }
            }
            if !matches(&baseline.snapshots) {
                held.insert(baseline.owner);
            }
        }
        if held.is_empty() {
            if self.census_complete
                && !self.pending_finalization.iter().any(|pending| {
                    index
                        .files
                        .get(&pending.index_key)
                        .is_some_and(|entry| entry.codex_applied_tier_receipt.is_some())
                })
            {
                index.traversal = None;
                index.resume_after_path = None;
                index.resume_upper_bound_path = None;
                index.resume_census_window_end = None;
            }
            return;
        }
        self.hold_codex_groups(
            index,
            previous,
            &held,
            "legacy applied output could not be reproduced",
        );
    }
    pub(crate) fn hold_codex_groups(
        &mut self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
        held: &BTreeSet<String>,
        reason: &str,
    ) {
        if held.is_empty() {
            return;
        }
        self.census_complete = false;
        self.scan_cap_hit = true;
        if let Some(diagnostic) = self.local_codex_diagnostics.as_mut() {
            diagnostic.gates.census_complete = false;
            diagnostic.gates.traversal_healthy = false;
        }
        let sources = self
            .snapshots
            .iter()
            .filter(|snapshot| held.contains(&resolve_codex_identity(&snapshot.source_session_id)))
            .filter_map(|snapshot| snapshot.source_file_fingerprint.as_ref())
            .collect::<BTreeSet<_>>();
        let mut keys = index
            .files
            .iter()
            .filter(|(_, entry)| sources.contains(&entry.source_file_fingerprint))
            .map(|(key, _)| key.clone())
            .collect::<BTreeSet<_>>();
        if let Some(validation) = &self.codex_join_validation {
            keys.extend(
                validation
                    .groups
                    .iter()
                    .filter(|group| held.contains(&group.owner))
                    .flat_map(|group| {
                        group
                            .members
                            .iter()
                            .map(|member| local_index_key(&member.path))
                    }),
            );
        }
        self.ownership_incomplete_file_count += keys.len();
        self.causes.add(ownership::GROUP, keys.len());
        for key in &keys {
            index.remove_file_entry(key);
            if let Some(entry) = previous.files.get(key) {
                index.files.insert(key.clone(), entry.clone());
            }
            if let Some(fingerprints) = previous.file_snapshot_fingerprints.get(key) {
                index
                    .file_snapshot_fingerprints
                    .insert(key.clone(), fingerprints.clone());
            }
            if previous.confirmed_empty_files.contains(key) {
                index.confirmed_empty_files.insert(key.clone());
            }
        }
        self.pending_finalization
            .retain(|pending| !keys.contains(&pending.index_key));
        self.snapshots.retain(|snapshot| {
            !held.contains(&resolve_codex_identity(&snapshot.source_session_id))
        });
        if let Some(traversal) = index.traversal.as_mut() {
            traversal.counts.ownership_incomplete_file_count += keys.len();
            traversal.counts.causes.add(ownership::GROUP, keys.len());
            traversal
                .counts
                .record_unreadable(UnreadableCause::LegacyHold, 1);
            traversal.residue.index_keys.extend(keys);
            let now = rfc3339_unix_seconds(&self.census_window_end).unwrap_or_default();
            traversal.unhealthy_retry_attempt = traversal
                .unhealthy_retry_attempt
                .saturating_add(1)
                .min(UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS);
            traversal.unhealthy_retry_not_before_unix_seconds = Some(now.saturating_add(
                unhealthy_scan_retry_delay_seconds(traversal.unhealthy_retry_attempt),
            ));
        }
        if let Some(validation) = &mut self.codex_join_validation {
            validation.remove_owners(held);
        }
        index.scan_residue_witness = previous.scan_residue_witness.clone();
        eprintln!(
            "ottto-service: held {} Codex file group(s): {reason}",
            held.len()
        );
    }
    pub(crate) fn finish_codex_capture_boundary(&self, index: &mut ScanIndex) {
        if self.census_complete {
            index.traversal = None;
            index.resume_after_path = None;
            index.resume_upper_bound_path = None;
            index.resume_census_window_end = None;
        }
    }
    /// Index keys this scan read to completion, with their parsed source
    /// fingerprints.
    pub(crate) fn completed_parses(&self) -> impl Iterator<Item = (&str, &str)> {
        self.pending_finalization
            .iter()
            .filter(|pending| pending.parse_complete)
            .map(|pending| {
                (
                    pending.index_key.as_str(),
                    pending.source_file_fingerprint.as_str(),
                )
            })
    }
    /// A validated completed parse owns this RAM witness immediately; no
    /// metadata-sensitive next-pass re-key is required.
    pub(crate) fn remember_withheld_content(&self, index: &ScanIndex) {
        for pending in self
            .pending_finalization
            .iter()
            .filter(|pending| pending.parse_complete)
        {
            if let Some(seen) = pending.withheld_content {
                index.remember_withheld_content(&pending.index_key, seen);
            } else {
                index.forget_withheld_content(&pending.index_key);
            }
        }
    }
    pub(crate) fn codex_joining_validator(&self) -> Option<CodexJoinValidator> {
        self.codex_join_validation.clone().map(CodexJoinValidator)
    }
}

pub use crate::upload_policy::apply_upload_policy;
pub use crate::upload_policy::SnapshotUploadPolicy;

/// Reasoning-effort tiers Claude Code reports today. Kept in one place so the
/// transcript reader and the OTLP sidecar admit exactly the same vocabulary.
const CLAUDE_EFFORT_TIERS: &[&str] = &["low", "medium", "high", "xhigh", "max"];

#[cfg(test)]
pub use sources::claude::census::reported_usage::apply_claude_reported_usage_with_index;
pub use sources::claude::census::reported_usage::{
    apply_claude_effort_evidence, apply_claude_effort_evidence_with_index,
};
#[cfg(test)]
pub(crate) use sources::claude::census::reported_usage::{
    apply_claude_reported_usage_to_scan_with_identity, apply_claude_reported_usage_with_identity,
};
pub(crate) use sources::claude::census::reported_usage::{
    apply_claude_reported_usage_to_scan_with_rows, ClaudeEvidenceRows,
};
use sources::claude::census::reported_usage::{
    claude_snapshot_family_root, claude_snapshot_family_root_ref, claude_transcript_effort,
};

/// Installs the local re-emission list naming exactly `roots` (protected
/// roots) in `support_dir`.
#[cfg(test)]
pub(crate) fn write_claude_reemission_list_for_test(support_dir: &Path, roots: &[&str]) {
    let path = claude_reemission_exclusions::ReemissionExclusions::path(support_dir);
    fs::create_dir_all(path.parent().expect("list directory")).expect("create list directory");
    let lines = roots
        .iter()
        .map(|root| format!("{:x}\n", Sha256::digest(root.as_bytes())))
        .collect::<String>();
    fs::write(path, lines).expect("write the re-emission list");
}

/// Whether a throttled alarm last raised at `last` is due at `now`, at least
/// `interval` later; takes its slot when it is.
fn take_throttled_alarm_slot(
    last: &mut Option<std::time::Instant>,
    now: std::time::Instant,
    interval: std::time::Duration,
) -> bool {
    let due = last.map_or(true, |at| now.saturating_duration_since(at) >= interval);
    if due {
        *last = Some(now);
    }
    due
}

use sources::claude::census::usage_ledger::{
    classify_claude_legacy_request_owners, claude_api_cache_creation,
    claude_api_evidence_fingerprint_is_valid, claude_api_reasoning_matches,
    claude_snapshot_request_id_hashes, claude_trace_evidence_fingerprint_is_valid,
    claude_trace_owner_session_id, reconstruct_claude_usage_family, serialized_json_digest,
};
pub(crate) use sources::claude::census::usage_ledger::{
    claude_api_cache_creation_rejection_count, claude_api_matches_transcript_occurrence,
    validate_claude_api_row, ClaudeLegacyRequestOwners,
};
#[cfg(test)]
use sources::claude::census::usage_ledger::{
    claude_occurrence_map_fingerprint, claude_request_id_set_fingerprint,
    reduce_claude_usage_ledger_with_rows,
};

/// Borrow exactly the identity used by the canonical index resolver. No path
/// component vector or owned identity is needed to decide optional membership.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ClaudeIndexPathMemberRef<'a> {
    root: &'a str,
    subagent_stem: Option<&'a str>,
}
impl<'a> ClaudeIndexPathMemberRef<'a> {
    /// The identity a pending member name of family `root` names: the root
    /// itself, or `<root>_<stem>` for a subagent (the member `into_owned`
    /// renders). `None` when the name belongs to no member of this family.
    fn of_family_member(root: &'a str, member: &'a str) -> Option<Self> {
        let subagent_stem = if member == root {
            None
        } else {
            Some(member.strip_prefix(root)?.strip_prefix('_')?)
        };
        Some(Self {
            root,
            subagent_stem,
        })
    }

    fn matches_member(&self, member: &str) -> bool {
        ClaudeIndexPathMemberRef::of_family_member(self.root, member) == Some(*self)
    }

    fn into_owned(self) -> (String, String) {
        let member = match self.subagent_stem {
            Some(stem) => {
                let mut member = String::with_capacity(self.root.len() + 1 + stem.len());
                member.push_str(self.root);
                member.push('_');
                member.push_str(stem);
                member
            }
            None => self.root.to_owned(),
        };
        (self.root.to_owned(), member)
    }
}

/// The re-emission list's seen-marker: prior-history evidence for the gate.
pub(crate) fn claude_reemission_seen_marker_path(support_dir: &Path) -> PathBuf {
    ReemissionExclusions::seen_marker_path(support_dir)
}

/// A subagent file's family `subagents` directory: its nearest `subagents`
/// ancestor, as `claude_index_path_member_ref` reads it, whose parent is the
/// family's `root` directory. `None` when the path does not have that shape.
fn claude_family_subagents_dir<'a>(path: &'a Path, root: &str) -> Option<&'a Path> {
    path.parent()?
        .ancestors()
        .find(|ancestor| {
            ancestor.file_name().and_then(std::ffi::OsStr::to_str) == Some("subagents")
        })
        .filter(|subagents| {
            subagents
                .parent()
                .and_then(Path::file_name)
                .and_then(std::ffi::OsStr::to_str)
                == Some(root)
        })
}

/// The family root transcript `<project>/<root>.jsonl` of a member path.
fn claude_family_root_path(path: &Path, root: &str) -> Option<PathBuf> {
    let project = claude_family_subagents_dir(path, root)?
        .parent()?
        .parent()?;
    Some(project.join(format!("{root}.jsonl")))
}

fn claude_index_path_member_ref(path: &Path) -> Option<ClaudeIndexPathMemberRef<'_>> {
    if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
        return None;
    }
    let stem = path
        .file_stem()?
        .to_str()
        .filter(|value| !value.is_empty())?;
    // Same nearest-marker and UTF-8-normal-component rule as
    // claude_subagent_identity. Keep the owned parser as the independent oracle.
    let mut directories =
        path.parent()?
            .components()
            .rev()
            .filter_map(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            });
    let root = directories
        .find(|value| *value == "subagents")
        .and_then(|_| directories.next());
    if let Some(root) = root.filter(|value| !value.is_empty()) {
        if stem == "journal" {
            return None;
        }
        Some(ClaudeIndexPathMemberRef {
            root,
            subagent_stem: Some(stem),
        })
    } else {
        Some(ClaudeIndexPathMemberRef {
            root: stem,
            subagent_stem: None,
        })
    }
}
fn claude_index_path_family_member(path: &Path) -> Option<(String, String)> {
    Some(claude_index_path_member_ref(path)?.into_owned())
}

#[cfg(test)]
use sources::claude::account::evidence::claude_account_evidence_covers_snapshot;
use sources::claude::account::evidence::{
    apply_claude_account_evidence, exact_session_account_hash, set_claude_account_hash,
    set_session_account_hash, veto_claude_original_identity,
};

use sources::claude::census::usage_ledger::{
    claude_reported_usage_inputs, rebuild_claude_reported_usage, rebuild_retagged_model_usage,
    rebuild_snapshot_model_usage_with, semantic_attribution, semantic_model_usage,
    semantic_usage_buckets,
};

#[cfg(test)]
use wire::content_hash::snapshot_upload_body_witness_payload;

use wire::batch_validation::validate_snapshot_item;

#[cfg(test)]
use sources::codex::sidecar::{
    codex_created_thread_parent, insert_codex_sidecar_title, load_codex_rollout_extents,
    retry_transient_sqlite, CODEX_SIDECAR_OPEN_RETRIES,
};
use sources::codex::sidecar::{
    codex_state_thread_field_diffs, CodexPathSidecarCandidate, CodexRolloutExtent,
    CodexStateThread, CodexTitleMetadata, CodexTurnTraceMap,
};

#[cfg(test)]
use sources::claude::desktop_titles::{
    claude_desktop_account_identifier_hash, claude_desktop_original_identity,
    claude_transcript_file_live_window, load_claude_desktop_session_title,
    ClaudeDesktopIdentityEvidence, ClaudeTitleCandidate, CLAUDE_TRANSCRIPT_WINDOW_READ_BYTES,
    MAX_CLAUDE_DESKTOP_SESSION_FILES, MAX_CLAUDE_DESKTOP_SESSION_FILE_BYTES,
};
use sources::claude::desktop_titles::{
    claude_desktop_store_inventory_is_legacy, ClaudeDesktopSpawnLineage,
    ClaudeDesktopTitleIndexEntry, ClaudeTitleMetadata,
};

#[cfg(test)]
use scan::accumulator::SELECTOR_CONTEXT_ALLOWED;
use scan::accumulator::{
    build_row_identity, cached_repository_identity, claude_row_placement, merge_session_row,
    model_usage_from_row, row_key_from_model_usage, selector_hash, ActivityCallId,
    ActivityCallTool, BucketRowAccumulator, CodexOwnershipBoundary, RowKey, SelectorCapture,
    SelectorHashes, SnapshotAccumulator, UsageBucketState, CODEX_THREAD_TIER,
};
pub(crate) use scan::accumulator::{
    copy_unproven_selector_hash, PlacedClaudeUsage, IMPLICIT_USAGE_MODEL,
};

use scan::entry::{codex_census_walk_pending, codex_frozen_census_valid, CodexParentUnresolvable};
#[cfg(test)]
pub use scan::entry::{
    scan_source_roots, scan_source_roots_with_attribution,
    scan_source_roots_with_attribution_and_claude_effort,
    scan_source_roots_with_attribution_and_hints,
};
pub use scan::entry::{
    scan_source_roots_before_policy, scan_source_roots_with_attribution_and_claude_effort_and_hints,
};
#[cfg(test)]
use scan::entry::{
    scan_source_roots_with_limit, scan_source_roots_with_limit_and_attribution,
    with_after_reader_eof, with_codex_before_parse, AFTER_READER_EOF, CODEX_BEFORE_PARSE,
};
#[cfg(test)]
pub(crate) use scan::entry::{
    scan_source_roots_with_test_limit, scan_source_roots_with_test_limit_and_claude_support,
    scan_source_roots_with_test_limit_and_hints, transcript_io_allowed, with_transcript_io_denied,
};

use scan::entry::LoadOrigin;
pub(crate) use scan::entry::ScanIndexLoadOrigin;
use scan::owned_scan::{prepare_owned_scan_candidate, OwnedActiveFile};
pub(crate) use scan::owned_scan::{OwnedSourceScan, OwnedSourceScanStep};

impl OwnedSourceScan {
    pub(crate) fn step(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> OwnedSourceScanStep {
        self.step_inner(attribution_context)
            .expect("ordinary serial collection is available")
    }

    pub(crate) fn step_fallible(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        state_v2::before_collection(&self.index).map_err(|_| {
            crate::source_rotation::LocalRefusal("state_v2_maintenance_before_collection")
        })?;
        self.step_inner(attribution_context)
    }

    fn step_inner(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let _acquire_window = state_v2::telemetry::acquire_window(&self.index);
        let mut result =
            crate::local_resource_diagnostics::jsonl::page(self.source.api_slug(), || {
                self.step_inner_page(attribution_context)
            });
        match &result {
            Ok(OwnedSourceScanStep::Pending(scan)) => state_v2::telemetry::acquired(&scan.index),
            Ok(OwnedSourceScanStep::Complete { index, .. }) => state_v2::telemetry::acquired(index),
            Err(_) => {}
        }
        let counts = diagnostics.finish();
        if let Ok(OwnedSourceScanStep::Pending(scan)) = &mut result {
            scan.resource_probe.page_events.merge(counts);
        }
        result
    }

    #[inline(never)]
    fn step_inner_page(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        if !self.index.persistence_available() {
            return Err(crate::source_rotation::LocalRefusal(
                "scan_index_map_unavailable",
            ));
        }

        // Prepare one demand batch through bounded native continuations. Group
        // owners come from the completed header census, never arbitrary names.
        if self.active_file.is_none()
            && self.codex_join_active.is_none()
            && (self.source != SnapshotSource::Codex || self.codex_join_prepared)
        {
            let launch_lookup = attribution_context
                .map(|context| context.launch_events())
                .or(self.launch_events.as_deref());
            if let Some(events) = launch_lookup {
                let first = self
                    .codex_join_groups
                    .front()
                    .map(|group| vec![group.owner.clone()])
                    .or_else(|| {
                        self.identified_candidates.front().map(|candidate| {
                            launch_workers_for_candidate(
                                self.source,
                                candidate,
                                self.codex_join_inventory.as_ref(),
                            )
                        })
                    })
                    .unwrap_or_default();
                // A completed batch covers its remaining members. Looking at
                // a sliding window here would add one new worker after every
                // file and repeat the complete retained-store sweep per file.
                if !events.prepared(&first) {
                    let mut workers = BTreeSet::new();
                    for worker in self
                        .codex_join_groups
                        .iter()
                        .map(|group| group.owner.clone())
                        .chain(self.identified_candidates.iter().flat_map(|candidate| {
                            launch_workers_for_candidate(
                                self.source,
                                candidate,
                                self.codex_join_inventory.as_ref(),
                            )
                        }))
                        .take(crate::launch_events::MAX_DEMANDED_WORKERS)
                    {
                        if crate::launch_events::valid_worker(&worker) {
                            workers.insert(worker.to_ascii_lowercase());
                        }
                        if workers.len() == crate::launch_events::MAX_DEMANDED_WORKERS {
                            break;
                        }
                    }
                    let workers = workers.into_iter().collect::<Vec<_>>();
                    match events.prepare_step(&workers) {
                        Ok(false) => return Ok(OwnedSourceScanStep::Pending(self)),
                        Err(()) => {} // Candidate handling keeps unreadable evidence owed.
                        Ok(true) => {}
                    }
                }
            }
        }
        let Self {
            mut resource_probe,
            mut sampling,
            index: mut index_storage,
            source,
            roots,
            collected_at,
            audit_now,
            backfill_window_days,
            file_limit,
            claude_request_identity_capture,
            claude_effort_support_dir,
            codex_title_metadata,
            claude_title_metadata,
            state_census_complete,
            sidecar_census_complete,
            codex_turn_traces,
            codex_census_valid,
            census_window_end,
            discovered_file_count,
            census_unix_seconds,
            mut census,
            mut snapshots,
            mut scanned_file_count,
            mut scanned_session_count,
            mut semantic_noop_count,
            mut history_upgrade,
            mut context_read_budget,
            mut residue_index_keys,
            mut settled_residue_index_keys,
            mut pending_finalization,
            claude_authority_preflight,
            mut forced_claude_family_reparses,
            claude_twin_only_family_reparses,
            claude_family_shadow,
            mut identified_candidates,
            active_file: active_frame,
            mut codex_join_inventory,
            mut codex_join_prepared,
            mut codex_join_groups,
            mut codex_join_active,
            mut codex_join_completed,
            mut codex_legacy_join_baselines,
            mut codex_page,
            codex_selected_flags,
            mut continuation_ticket,
            mut line_delivery,
            codex_versions,
            launch_events,
        } = self;
        let scan_launch_events = launch_events.clone();
        let launch_lookup = attribution_context
            .map(|context| context.launch_events())
            .or(scan_launch_events.as_deref());
        // Held while this scan object runs the shared cursor job.
        let (mut active_file, mut codex_cursor_lease) = active_frame.into_parts();
        let index = &mut index_storage;
        let claude_effort_support_dir_ref = claude_effort_support_dir.as_deref();
        // Construct the large continuation once. Repeating it in every yield
        // branch multiplies debug-build stack slots and can overflow native
        // callers even though the retained scanner state is unchanged.
        'scan_step: {
            macro_rules! pending {
                () => {
                    break 'scan_step
                };
            }
            // Every Codex disclosure in this step writes into the same five
            // step-local sinks.
            macro_rules! targets {
                () => {
                    sampled_scan::codex_cursor::DisclosureTargets {
                        census: &mut census,
                        residue_index_keys: &mut residue_index_keys,
                        pending_finalization: &mut pending_finalization,
                    }
                };
            }
            if source == SnapshotSource::Codex && !codex_join_prepared {
                if let Some(inventory) = codex_join_inventory.as_mut() {
                    if !inventory.step_selected(
                        &codex_title_metadata,
                        index,
                        &codex_selected_flags,
                        sampling.as_ref().map(|context| &context.cache),
                    ) {
                        pending!();
                    }
                    let selected = identified_candidates
                        .iter()
                        .map(|candidate| local_index_key(&candidate.path))
                        .collect::<BTreeSet<_>>();
                    let inventoried = inventory
                        .headers
                        .iter()
                        .map(|header| local_index_key(&header.candidate.path))
                        .collect::<BTreeSet<_>>();
                    inventory.complete &= selected.difference(&inventoried).all(|key| {
                        let owners = codex_session_id_candidates_from_path(Path::new(key));
                        !owners.is_empty()
                            && owners
                                .iter()
                                .all(|owner| inventory.held_owners.contains(owner))
                    });
                    let current_owners = inventory
                        .headers
                        .iter()
                        .map(|header| {
                            (
                                local_index_key(&header.candidate.path),
                                codex_protected_owner(&header.owner),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    let absence_coverage = inventory.held_owners.is_empty()
                        && codex_counting_version::absence_coverage_complete(index, inventory);
                    codex_counting_version::note_inventory_created(index, inventory);
                    codex_counting_version::prepare_moved_evidence(
                        index,
                        &current_owners,
                        absence_coverage,
                    );
                    let mut repurposed_protected_paths = BTreeSet::new();
                    let mut missing_protected_owners = BTreeSet::new();
                    let mut missing_unknown_owner = false;
                    for owner in index.decode_held_codex_owners() {
                        match owner {
                            Some(owner) => {
                                missing_protected_owners.insert(owner.to_owned());
                            }
                            None => missing_unknown_owner = true,
                        }
                    }
                    for (key, entry) in &index.files {
                        let repurposed = entry.codex_history_is_protected()
                            && entry
                                .codex_protected_owner
                                .as_ref()
                                .is_some_and(|previous| {
                                    current_owners
                                        .get(key)
                                        .is_some_and(|current| current != previous)
                                });
                        if repurposed {
                            repurposed_protected_paths.insert(key.clone());
                        }
                        if entry.codex_history_is_protected()
                            && (!inventoried.contains(key) || repurposed)
                        {
                            if let Some(owner) = entry
                                .codex_protected_owner
                                .as_ref()
                                .filter(|owner| valid_codex_protected_owner(owner))
                            {
                                missing_protected_owners.insert(owner.clone());
                            } else {
                                missing_unknown_owner = true;
                            }
                        }
                    }
                    let affected_owners = inventory.affected_owners();
                    census.unreadable_path_count += inventory.refused.len();
                    census.unreadable_causes.merge(inventory.unreadable_causes);
                    let mut grouped_paths = BTreeSet::new();
                    let mut used = 0usize;
                    // R2-N6: a group with more members than the page's file
                    // limit is never excluded; it goes first and takes a page
                    // of its own (it pages through the cursor like any group).
                    // So does a group whose probes outran a page's
                    // remaining singleton budget (`ProbeBudgetOrder`).
                    let fence = sampled_scan::codex_cursor::census_token(index);
                    let own_page = |group: &codex_file_join::Group| {
                        group.members.len() > file_limit
                            || sampling.as_ref().is_some_and(|context| {
                                context.cache.group_own_page(
                                    &context.namespace,
                                    &codex_file_join::job_key(group),
                                    fence.as_deref(),
                                )
                            })
                    };
                    let mut groups = inventory
                        .groups()
                        .into_values()
                        .map(|group| (own_page(&group), group))
                        .collect::<Vec<_>>();
                    // Context-only groups spend only the file allowance left by
                    // ordinary groups. Partition before admission can defer a
                    // group; sorting the admitted queue would be too late.
                    groups.sort_by_key(|(own, group)| {
                        (
                            index.file_upload_context_enabled()
                                && group
                                    .members
                                    .iter()
                                    .all(|member| index.context_only_read(member)),
                            !*own,
                            !sampled_scan::codex_cursor::census_member(
                                &codex_selected_flags,
                                group.members.iter().map(|member| member.path.as_path()),
                            ),
                        )
                    });
                    let mut ordinary_singleton_slots = None;
                    for (own, group) in groups {
                        if group
                            .members
                            .iter()
                            .any(|member| index.decode_holds_file(&local_index_key(&member.path)))
                        {
                            grouped_paths.extend(
                                group
                                    .members
                                    .iter()
                                    .map(|member| local_index_key(&member.path)),
                            );
                            index.mark_bounded_sweep_unsettled();
                            continue;
                        }
                        let protected_history_missing = missing_unknown_owner
                            || missing_protected_owners
                                .contains(&codex_protected_owner(&group.owner));
                        let previously_joined = group.members.iter().any(|member| {
                            index
                                .files
                                .get(&local_index_key(&member.path))
                                .is_some_and(|entry| {
                                    entry.codex_joined_member_set.is_some()
                                        || entry.codex_captured_joined_member_set.is_some()
                                })
                        });
                        if (group.members.len() < 2
                            && !previously_joined
                            && !protected_history_missing
                            && inventory
                                .membership_complete(&group.owner, affected_owners.as_ref()))
                            || !group
                                .members
                                .iter()
                                .any(|member| selected.contains(&local_index_key(&member.path)))
                        {
                            continue;
                        }
                        grouped_paths.extend(
                            group
                                .members
                                .iter()
                                .map(|member| local_index_key(&member.path)),
                        );
                        // §d.1.2 c: a paused or active cursor job owns a
                        // member. Its selected members stay pending (holding
                        // the census) and are not read again while it lives.
                        if sampling.as_ref().is_some_and(|context| {
                            group.members.iter().any(|member| {
                                context
                                    .cache
                                    .cursor_job_owns(&local_index_key(&member.path))
                            })
                        }) {
                            let owned = group
                                .members
                                .iter()
                                .filter(|member| selected.contains(&local_index_key(&member.path)))
                                .collect::<Vec<_>>();
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                owned,
                            );
                            continue;
                        }
                        let malformed_pending = group.members.iter().any(|member| {
                            index
                                .files
                                .get(&local_index_key(&member.path))
                                .is_some_and(|entry| {
                                    entry
                                        .codex_captured_joined_member_set
                                        .as_deref()
                                        .is_some_and(|marker| {
                                            !codex_file_join::valid_captured_join(marker)
                                        })
                                })
                        });
                        if !inventory.membership_complete(&group.owner, affected_owners.as_ref())
                            || malformed_pending
                            || protected_history_missing
                            || group.members.iter().any(|member| {
                                repurposed_protected_paths.contains(&local_index_key(&member.path))
                            })
                            || group.members.len() < 2
                        {
                            census.ownership_incomplete_file_count += group.members.len();
                            census.causes.add(ownership::INVENTORY, group.members.len());
                            census.record_unreadable(UnreadableCause::AliasParser, 1);
                            residue_index_keys.extend(
                                group
                                    .members
                                    .iter()
                                    .map(|member| local_index_key(&member.path)),
                            );
                            continue;
                        }
                        // G1: a group whose attempt already ended in this
                        // generation is fenced at its pop (M-5 b) and reads
                        // nothing. Decide it here, so it takes no file
                        // allowance a waiting census member needs.
                        let fenced = sampling.as_ref().is_some_and(|context| {
                            context.cache.group_fenced(
                                &context.namespace,
                                &codex_file_join::job_key(&group),
                                fence.as_deref(),
                            )
                        });
                        // G1: a group whose selected members are all re-reads
                        // never takes file allowance a waiting census-member
                        // singleton needs (own page or not). It waits for a
                        // page without one; its members stay pending as
                        // re-reads.
                        let rereads_crowd_members = !fenced
                            && !sampled_scan::codex_cursor::census_member(
                                &codex_selected_flags,
                                group.members.iter().map(|member| member.path.as_path()),
                            )
                            && {
                                let waiting = identified_candidates
                                    .iter()
                                    .filter(|candidate| {
                                        let key = local_index_key(&candidate.path);
                                        !grouped_paths.contains(&key)
                                            && sampled_scan::codex_cursor::selected_census_member(
                                                &codex_selected_flags,
                                                &candidate.path,
                                            )
                                    })
                                    .count();
                                waiting > 0
                                    && (own || used + group.members.len() + waiting > file_limit)
                            };
                        // Ordinary groups have already spent their slots. Before
                        // the first context group, reserve the remaining ordinary
                        // singletons too; catch-up must never evict one below.
                        let context_group = index.file_upload_context_enabled()
                            && group
                                .members
                                .iter()
                                .all(|member| index.context_only_read(member));
                        let waiting_ordinary = if context_group {
                            *ordinary_singleton_slots.get_or_insert_with(|| {
                                identified_candidates
                                    .iter()
                                    .filter(|candidate| {
                                        !grouped_paths.contains(&local_index_key(&candidate.path))
                                            && !index.context_only_read(candidate)
                                            && index
                                                .candidate_decision_with_reason_at(
                                                    candidate,
                                                    sampled_scan::now_seconds(),
                                                )
                                                .0
                                                != CandidateDecision::Skip
                                    })
                                    .count()
                            })
                        } else {
                            0
                        };
                        let context_crowds_ordinary = !fenced
                            && waiting_ordinary > 0
                            && (own
                                || used
                                    .saturating_add(group.members.len())
                                    .saturating_add(waiting_ordinary)
                                    > file_limit);
                        if context_crowds_ordinary
                            || rereads_crowd_members
                            || (!fenced
                                && used > 0
                                && (own || used + group.members.len() > file_limit))
                        {
                            // Keep the existing traversal as the only queue. A whole
                            // group is selected on a subsequent ordinary page.
                            if let Some(traversal) = index.traversal.as_mut() {
                                for member in &group.members {
                                    if selected.contains(&local_index_key(&member.path)) {
                                        traversal.pending_candidates.push_back(ScanTraversalPath {
                                            scan_root: member.scan_root.clone(),
                                            path: member.path.clone(),
                                            // G1: a re-read is not re-enrolled.
                                            census_member:
                                                sampled_scan::codex_cursor::selected_census_member(
                                                    &codex_selected_flags,
                                                    &member.path,
                                                ),
                                            watcher_hint: false,
                                        });
                                    }
                                }
                            }
                            continue;
                        }
                        if !fenced {
                            used += group.members.len();
                            if own {
                                // Nothing else joins its page.
                                used = used.max(file_limit);
                            }
                        }
                        if let Some(traversal) = index.traversal.as_mut() {
                            // R2-L3: one set per group, not a member scan per
                            // pending path.
                            let paths = group
                                .members
                                .iter()
                                .map(|member| member.path.as_path())
                                .collect::<std::collections::HashSet<_>>();
                            traversal
                                .pending_candidates
                                .retain(|pending| !paths.contains(pending.path.as_path()));
                        }
                        if !fenced {
                            codex_join_groups.push_back(group);
                        }
                    }
                    identified_candidates.retain(|candidate| {
                        !grouped_paths.contains(&local_index_key(&candidate.path))
                    });
                    let held = identified_candidates
                        .iter()
                        .filter(|candidate| {
                            !inventory
                                .owner_for_path(&candidate.path)
                                .is_some_and(|owner| {
                                    inventory.membership_complete(owner, affected_owners.as_ref())
                                })
                        })
                        .map(|candidate| local_index_key(&candidate.path))
                        .collect::<BTreeSet<_>>();
                    census.ownership_incomplete_file_count += held.len();
                    census.causes.add(ownership::INVENTORY, held.len());
                    residue_index_keys.extend(held.iter().cloned());
                    identified_candidates
                        .retain(|candidate| !held.contains(&local_index_key(&candidate.path)));
                    while !identified_candidates.is_empty()
                        && used + identified_candidates.len() > file_limit
                    {
                        // G1: re-reads leave before any census member.
                        let context_evict = index
                            .file_upload_context_enabled()
                            .then(|| {
                                let disposable = |candidate: &CandidateFile| {
                                    index.context_only_read(candidate)
                                        || index
                                            .candidate_decision_with_reason_at(
                                                candidate,
                                                sampled_scan::now_seconds(),
                                            )
                                            .0
                                            == CandidateDecision::Skip
                                };
                                identified_candidates
                                    .iter()
                                    .rposition(|candidate| {
                                        disposable(candidate)
                                            && !sampled_scan::codex_cursor::selected_census_member(
                                                &codex_selected_flags,
                                                &candidate.path,
                                            )
                                    })
                                    .or_else(|| identified_candidates.iter().rposition(disposable))
                            })
                            .flatten();
                        let evict = context_evict
                            .or_else(|| {
                                identified_candidates.iter().rposition(|candidate| {
                                    !sampled_scan::codex_cursor::selected_census_member(
                                        &codex_selected_flags,
                                        &candidate.path,
                                    )
                                })
                            })
                            .unwrap_or(identified_candidates.len() - 1);
                        if let Some(candidate) = identified_candidates.remove(evict) {
                            if let Some(traversal) = index.traversal.as_mut() {
                                // G1: a re-read is not re-enrolled.
                                let census_member =
                                    sampled_scan::codex_cursor::selected_census_member(
                                        &codex_selected_flags,
                                        &candidate.path,
                                    );
                                traversal.pending_candidates.push_front(ScanTraversalPath {
                                    scan_root: candidate.scan_root,
                                    path: candidate.path,
                                    census_member,
                                    watcher_hint: false,
                                });
                            }
                        }
                    }
                }
                if index.file_upload_context_enabled() {
                    codex_join_groups
                        .make_contiguous()
                        .sort_by_cached_key(|group| {
                            group
                                .members
                                .iter()
                                .all(|candidate| index.context_only_read(candidate))
                        });
                }
                codex_join_prepared = true;
                pending!();
            }
            if let Some(mut boot) = codex_join_active.take() {
                if boot
                    .group
                    .members
                    .iter()
                    .any(|candidate| context_read_budget.is_admitted(candidate))
                {
                    // The group's cursor shares the room left by ordinary
                    // native reads, just like a singleton or resumed cursor.
                    context_read_budget.charge_cursor_ordinary(&mut codex_page);
                }
                // R2-N2: a group larger than the singleton budget asks for
                // the cursor before its first header read; one that would
                // wait (or is fenced) reads no header or probe this page.
                // Only after the unchanged decision, and
                // never for a group with a memo entry or parked record: those
                // reach their lookups first and leave without the slot.
                if let Some(context) = sampling.as_ref().filter(|context| {
                    boot.awaits_read()
                        && !boot.independent()
                        && crate::heap_layout_bound::layout_supported()
                        && boot.expected_bytes()
                            > sampled_scan::codex_cursor::Limits::current().singleton()
                        && !context.cache.group_recorded(&context.namespace, &boot.key)
                }) {
                    match context.cache.cursor_plan(
                        &mut codex_page,
                        sampled_scan::codex_cursor::Limits::current(),
                        boot.expected_bytes(),
                        codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                        true,
                        &context.namespace,
                        &boot.key,
                        sampled_scan::codex_cursor::census_token(index).as_deref(),
                        sampled_scan::codex_cursor::census_member(
                            &codex_selected_flags,
                            boot.group
                                .members
                                .iter()
                                .map(|member| member.path.as_path()),
                        ),
                    ) {
                        sampled_scan::codex_cursor::StartPlan::Defer => {
                            context.cache.cursor_note_deferred();
                            if boot.own_page {
                                context
                                    .cache
                                    .request_group_own_page(&context.namespace, &boot.key);
                            }
                            scanned_file_count =
                                scanned_file_count.saturating_sub(boot.group.members.len());
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &boot.group.members,
                            );
                            pending!();
                        }
                        sampled_scan::codex_cursor::StartPlan::Fenced => {
                            scanned_file_count =
                                scanned_file_count.saturating_sub(boot.group.members.len());
                            pending!();
                        }
                        _ => {}
                    }
                }
                boot.allow_probe_bytes(
                    codex_page.singleton_remaining(sampled_scan::codex_cursor::Limits::current()),
                );
                let outcome = boot.step_with_cache(
                    launch_lookup,
                    index,
                    sampling.as_ref().map(|context| &context.cache),
                );
                // Header and probe bytes are singleton-budget reads (§d.2).
                let boot_input = boot.take_charge();
                codex_page.charge(false, boot_input);
                let members = boot.group.members.len();
                match outcome {
                    codex_file_join::Boot::Pending => {
                        codex_join_active = Some(boot);
                        pending!();
                    }
                    codex_file_join::Boot::Unchanged => {
                        // The accepted joined body is current, with no job
                        // or debt. Nothing read for a job; it does not wait.
                        if let Some(context) = sampling.as_ref() {
                            context.cache.cursor_unwait(&context.namespace, &boot.key);
                        }
                        semantic_noop_count += members;
                        census.note_codex_group(CodexSelection::GroupUnchanged, members);
                        if !boot.independent() {
                            codex_join_completed.push(boot.group);
                        }
                        pending!();
                    }
                    codex_file_join::Boot::Strict => {
                        if let Some(context) = sampling.as_ref() {
                            context.cache.cursor_unwait(&context.namespace, &boot.key);
                        }
                        codex_file_join::disclose_strict(&boot.group.members, targets!());
                        pending!();
                    }
                    codex_file_join::Boot::Refused(_reason) => {
                        // Decided from headers at no replay cost: terminal
                        // debt (outcome R), fenced, never memoized.
                        if let Some(context) = sampling.as_ref() {
                            context.cache.group_attempted(
                                &context.namespace,
                                &boot.key,
                                sampled_scan::codex_cursor::census_token(index).as_deref(),
                            );
                        }
                        codex_file_join::disclose_members(
                            &codex_file_join::refusal_disclosure(),
                            &boot.group.members,
                            index,
                            targets!(),
                        );
                        pending!();
                    }
                    codex_file_join::Boot::Ready => {
                        census.note_codex_group(CodexSelection::GroupSelected, members);
                    }
                }
                let expected = boot.expected_bytes();
                let dependencies = boot.dependencies(&codex_title_metadata);
                let mut paged = false;
                if let Some(context) = sampling.as_ref() {
                    let live_file = boot.live().and_then(|(live, _)| {
                        open_candidate_file_stat_retained(
                            SnapshotSource::Codex,
                            &mut live.clone(),
                            Some(&context.cache),
                            false,
                        )
                        .ok()
                        .map(|(file, _)| file)
                    });
                    let wake_stamp =
                        boot.live()
                            .zip(live_file.as_ref())
                            .and_then(|((live, _), file)| {
                                sampled_scan::codex_cursor::OpenStamp::capture(file)
                                    .ok()
                                    .map(|stamp| context.cache.retained_stamp(&live.path, stamp))
                            });
                    let memo_key =
                        sampled_scan::codex_cursor::memo_key(&context.namespace, &boot.key);
                    if let Some(entry) = context.cache.memo_lookup(&memo_key) {
                        // The match re-reads two samples of the live member.
                        codex_page.charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                        let hit = boot
                            .memo_digest(index, &codex_title_metadata)
                            .zip(live_file.as_ref())
                            .and_then(|(digest, file)| {
                                entry.matches_stamp(
                                    &boot.live()?.0.path,
                                    &digest,
                                    file,
                                    "",
                                    wake_stamp.clone()?,
                                )
                            });
                        if let Some(stamp) = hit {
                            // No wake dependency changed: the same terminal
                            // debt again, per member, at zero replay bytes.
                            context.cache.memo_hit(&memo_key, stamp);

                            context.cache.cursor_unwait(&context.namespace, &boot.key);
                            codex_file_join::disclose_members(
                                entry.disclosure(),
                                &boot.group.members,
                                index,
                                targets!(),
                            );
                            pending!();
                        }
                        context.cache.memo_forget(&memo_key);
                    }
                    let parked = context.cache.cursor_parked_stamp(
                        &boot.key,
                        wake_stamp,
                        dependencies.as_deref(),
                    );
                    if let Some(disclosure) = parked {
                        context.cache.cursor_unwait(&context.namespace, &boot.key);
                        codex_file_join::disclose_members(
                            &disclosure,
                            &boot.group.members,
                            index,
                            targets!(),
                        );
                        pending!();
                    }
                    match context.cache.cursor_plan(
                        &mut codex_page,
                        sampled_scan::codex_cursor::Limits::current(),
                        expected,
                        codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                        crate::heap_layout_bound::layout_supported() && !boot.independent(),
                        &context.namespace,
                        &boot.key,
                        sampled_scan::codex_cursor::census_token(index).as_deref(),
                        sampled_scan::codex_cursor::census_member(
                            &codex_selected_flags,
                            boot.group
                                .members
                                .iter()
                                .map(|member| member.path.as_path()),
                        ),
                    ) {
                        sampled_scan::codex_cursor::StartPlan::Singleton => {}
                        sampled_scan::codex_cursor::StartPlan::Cursor => paged = true,
                        sampled_scan::codex_cursor::StartPlan::Unpaged => {
                            codex_page.disclose_disabled(&context.cache);
                        }
                        sampled_scan::codex_cursor::StartPlan::Defer => {
                            // The whole group waits its turn on a later page.
                            context.cache.cursor_note_deferred();
                            if boot.own_page {
                                context
                                    .cache
                                    .request_group_own_page(&context.namespace, &boot.key);
                            }
                            scanned_file_count = scanned_file_count.saturating_sub(members);
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &boot.group.members,
                            );
                            pending!();
                        }
                        // Processed for this generation (K7 fence).
                        sampled_scan::codex_cursor::StartPlan::Fenced => {
                            scanned_file_count = scanned_file_count.saturating_sub(members);
                            pending!();
                        }
                    }
                }
                // No group byte or member cap: a group larger than
                // the singleton budget pages through the cursor; without one
                // (unsupported layout, uncached scan) it is read in one page
                // like an ordinary unpaged read; group bytes are uncapped.
                let active_dependencies = boot.live().map(|(live, _)| {
                    sampled_scan::codex_cursor::group_dependencies(
                        &boot.group.members,
                        &live.path,
                        &codex_title_metadata,
                        |member| member.opened_object_identity.clone(),
                    )
                });
                let group_members = boot.group.members.clone();
                let boot_key = boot.key.clone();
                let job = boot.into_job(codex_file_join::JobInputs {
                    metadata: &codex_title_metadata,
                    traces: codex_turn_traces.clone(),
                    cache: sampling.as_ref().map(|context| &context.cache),
                    index,
                });
                let Ok(mut job) = job else {
                    // No lease exists yet; a waiter it left is
                    // dropped like the boot-`Strict` exit's.
                    if let Some(context) = sampling.as_ref() {
                        context.cache.cursor_unwait(&context.namespace, &boot_key);
                    }
                    codex_file_join::disclose_strict(&group_members, targets!());
                    pending!();
                };
                if let Some(context) = sampling.as_ref().filter(|_| paged) {
                    match context.cache.cursor_start_group(
                        &mut job,
                        &context.namespace,
                        active_dependencies,
                        state_census_complete && sidecar_census_complete,
                        index,
                    ) {
                        Ok(lease) => {
                            // The members hold the strict census until the
                            // job's attempt ends (accepted or debt).
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &group_members,
                            );
                            codex_cursor_lease = Some(lease);
                        }
                        Err(sampled_scan::codex_cursor::StartRefusal::Busy) => {
                            context.cache.cursor_note_deferred();
                            scanned_file_count = scanned_file_count.saturating_sub(members);
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &group_members,
                            );
                            pending!();
                        }
                        // Never an unbounded in-page read of a group larger
                        // than the singleton budget (compressed members > B
                        // keep refusing, named debt).
                        Err(_) => {
                            match group_members.first() {
                                Some(member) => census.record_unreadable_file(
                                    UnreadableCause::OpenRead,
                                    &member.path,
                                ),
                                None => census.record_unreadable(UnreadableCause::OpenRead, 1),
                            }
                            pending!();
                        }
                    }
                }
                active_file = Some(job);
                pending!();
            }
            if source == SnapshotSource::Codex
                && active_file.is_none()
                && codex_join_active.is_none()
            {
                // A lease without an active file means this scan lost its job
                // on an error path; dropping the lease frees the slot.
                codex_cursor_lease = None;
                if let Some(context) = sampling.as_ref() {
                    codex_page.note_page(&context.cache);
                }
                // At most one resume attempt per page, and none on a page
                // that selected no candidates (no header inventory: no
                // evidence for the job this page). A deferred job therefore
                // never spins within a page.
                if let Some(context) = sampling.as_ref().filter(|_| {
                    !codex_page.cursor_exhausted(sampled_scan::codex_cursor::Limits::current())
                        && codex_join_inventory.is_some()
                        && (!codex_page.continuation() || codex_census_valid)
                        && (!index.file_upload_context_enabled()
                            || !identified_candidates.iter().any(|candidate| {
                                !index.context_only_read(candidate)
                                    && index
                                        .candidate_decision_with_reason_at(
                                            candidate,
                                            sampled_scan::now_seconds(),
                                        )
                                        .0
                                        == CandidateDecision::Parse
                            }))
                        && (!index.file_upload_context_enabled()
                            || !codex_join_groups.iter().any(|group| {
                                group
                                    .members
                                    .iter()
                                    .any(|candidate| !index.context_only_read(candidate))
                            }))
                        && codex_page.claim_resume()
                }) {
                    // Continuing the paused job is the highest scheduling class.
                    match sampled_scan::codex_cursor::resume_paused_job(
                        sampled_scan::codex_cursor::ResumeContext {
                            source,
                            sampling: context,
                            codex: &codex_title_metadata,
                            claude: &claude_title_metadata,
                            support: claude_effort_support_dir_ref,
                            traces: codex_turn_traces.clone(),
                            inventory: codex_join_inventory.as_ref(),
                            flags: &codex_selected_flags,
                            census_complete: state_census_complete && sidecar_census_complete,
                            continuation: codex_page.continuation(),
                            ordinary_equivalent: codex_page.ordinary_equivalent(),
                        },
                        index,
                        &mut identified_candidates,
                        targets!(),
                    ) {
                        sampled_scan::codex_cursor::Resumed::Active(job, lease) => {
                            if index.context_only_read(&job.candidate) {
                                let admitted = if job.aliases.is_empty() {
                                    context_read_budget.admit(
                                        source,
                                        index,
                                        &job.candidate,
                                        &snapshots,
                                    )
                                } else {
                                    context_read_budget.admit_unit(
                                        source,
                                        index,
                                        &job.aliases,
                                        &snapshots,
                                    )
                                };
                                if !admitted {
                                    // Return the intact parser and lease, never restart a Full.
                                    drop(sampled_scan::codex_cursor::ActiveFrame::new(
                                        Some(job),
                                        Some(lease),
                                    ));
                                    pending!();
                                }
                                context_read_budget.charge_cursor_ordinary(&mut codex_page);
                            }
                            codex_cursor_lease = Some(lease);
                            active_file = Some(job);
                            pending!();
                        }
                        // Deferred, invalidated or ended as strict debt: this
                        // page is spent; a pending path resumes or restarts.
                        sampled_scan::codex_cursor::Resumed::Spent => pending!(),
                        sampled_scan::codex_cursor::Resumed::Idle => {}
                    }
                }
                // Stage 1 hunk D: a continuation page only resumes. Without
                // an active job it plans and starts nothing: every path it
                // identified, and every group it prepared, goes back to the
                // queue untouched, and the page finishes.
                if codex_page.continuation() {
                    for candidate in identified_candidates.drain(..) {
                        sampled_scan::codex_cursor::requeue(
                            index,
                            &codex_selected_flags,
                            &candidate,
                        );
                    }
                    for group in codex_join_groups.drain(..) {
                        sampled_scan::codex_cursor::requeue_members(
                            index,
                            &codex_selected_flags,
                            &group.members,
                        );
                    }
                }
            }
            // G1 (fix 2): a group whose selected members are all re-reads
            // waits until this page's census singletons are read, so its
            // replay cannot spend the singleton budget a first read needs.
            // Evaluated between files only, and the candidate scan only when
            // the next group is a re-read.
            let rereads_wait = || {
                codex_join_groups.front().is_some_and(|group| {
                    (!index.file_upload_context_enabled()
                        || group
                            .members
                            .iter()
                            .all(|candidate| index.context_only_read(candidate)))
                        && !sampled_scan::codex_cursor::census_member(
                            &codex_selected_flags,
                            group.members.iter().map(|member| member.path.as_path()),
                        )
                }) && identified_candidates.iter().any(|candidate| {
                    sampled_scan::codex_cursor::selected_census_member(
                        &codex_selected_flags,
                        &candidate.path,
                    )
                })
            };
            let context_group_waits = index.file_upload_context_enabled()
                && codex_join_groups.front().is_some_and(|group| {
                    group
                        .members
                        .iter()
                        .all(|candidate| index.context_only_read(candidate))
                })
                && identified_candidates.iter().any(|candidate| {
                    !index.context_only_read(candidate)
                        && index
                            .candidate_decision_with_reason_at(
                                candidate,
                                sampled_scan::now_seconds(),
                            )
                            .0
                            == CandidateDecision::Parse
                });
            if active_file.is_none() && !rereads_wait() && !context_group_waits {
                if let Some(group) = codex_join_groups.pop_front() {
                    if index.file_upload_context_enabled()
                        && group
                            .members
                            .iter()
                            .all(|candidate| index.context_only_read(candidate))
                        && !context_read_budget.admit_unit(
                            source,
                            index,
                            &group.members,
                            &snapshots,
                        )
                    {
                        sampled_scan::codex_cursor::requeue_members(
                            index,
                            &codex_selected_flags,
                            &group.members,
                        );
                        pending!();
                    }
                    if group
                        .members
                        .iter()
                        .any(|member| index.decode_holds_file(&local_index_key(&member.path)))
                    {
                        index.mark_bounded_sweep_unsettled();
                        pending!();
                    }
                    // M-5 (b): a group whose attempt already ended as terminal
                    // debt in this generation is not attempted again; its
                    // members were disclosed then.
                    let fenced = sampling.as_ref().is_some_and(|context| {
                        context.cache.group_fenced(
                            &context.namespace,
                            &codex_file_join::job_key(&group),
                            sampled_scan::codex_cursor::census_token(index).as_deref(),
                        )
                    });
                    if !fenced {
                        scanned_file_count += group.members.len();
                        let mut boot = Box::new(codex_file_join::GroupBoot::new(group, index));
                        if let Some(context) = sampling.as_ref() {
                            boot.own_page = context
                                .cache
                                .take_group_own_page(&context.namespace, &boot.key);
                        }
                        codex_join_active = Some(boot);
                    }
                    pending!();
                }
            }
            if let Some(mut active) = active_file.take() {
                let compressed = active.parser.reader.reader.is_compressed();
                let _input_qos = compressed
                    .then(crate::snapshot_sync::continuation::MacPlatformSignals::background);

                if active.parser.reader.reader.is_compressed()
                    && codex_page.singleton_remaining(sampled_scan::codex_cursor::Limits::current())
                        == 0
                {
                    codex_page.continue_singleton();
                    active_file = Some(active);
                    pending!();
                }
                let before_body_read = active.parser.reader.consumed_bytes();
                if let Some(delivery) = line_delivery.as_mut() {
                    delivery.begin_armed(&active, &roots);
                }
                let mut group_end = None;
                let stepped = if active.group.is_some() {
                    // A group job: one record of the current member, or one
                    // member transition (P2).
                    let live_scope = |member: &CandidateFile| {
                        let context = sampling.as_ref()?;
                        let dependency = sampled_scan::reduction_dependencies(
                            source,
                            member,
                            &codex_title_metadata,
                            &claude_title_metadata,
                            claude_effort_support_dir_ref,
                        )?;
                        Some(context.file_scope(source, member, &dependency))
                    };
                    match codex_file_join::step_group(
                        &mut active,
                        &codex_file_join::StepInputs {
                            metadata: &codex_title_metadata,
                            attribution: attribution_context,
                            live_scope: &live_scope,
                            cache: sampling.as_ref().map(|context| &context.cache),
                            collected_at: &collected_at,
                            index,
                        },
                    ) {
                        codex_file_join::GroupStep::Read(result) => result,
                        codex_file_join::GroupStep::End(end) => {
                            group_end = Some(end);
                            Ok(false)
                        }
                    }
                } else if let Some(delivery) = line_delivery.as_mut() {
                    delivery.step(&mut active.parser)
                } else {
                    active.parser.step()
                };
                context_read_budget.record(
                    index,
                    &active.candidate,
                    active.cursor.is_some(),
                    active
                        .parser
                        .reader
                        .consumed_bytes()
                        .saturating_sub(before_body_read),
                );

                if source == SnapshotSource::ClaudeCode
                    && before_body_read == 0
                    && active.parser.reader.consumed_bytes() > 0
                {
                    // Count only the first actual body bytes. SourceChanged
                    // includes Desktop/usage sidecar and object revisions;
                    // ScopeChanged also catches a metadata change concurrent
                    // with growth (whose selection reason is TranscriptChanged).
                    // LegacyIdentity is the separate one-time legacy upgrade.
                    if claude_title_metadata
                        .recovered_account_holds
                        .contains(&local_index_key(&active.candidate.path))
                    {
                        crate::local_resource_diagnostics::claude_reread::desktop_recovered_hold_body_read();
                    } else {
                        match index.candidate_decision_with_reason_at(&active.candidate, audit_now).1 {
                            Some(CandidateParseReason::LegacyIdentity) => {
                                crate::local_resource_diagnostics::claude_reread::desktop_revision_body_read(true);
                            }
                            reason if reason == Some(CandidateParseReason::SourceChanged)
                                || active.sampling.as_ref().is_some_and(|read| matches!(read.mode,
                                    crate::transcript_acquisition::ReadMode::Full(crate::transcript_acquisition::FullReason::ScopeChanged))) => {
                                crate::local_resource_diagnostics::claude_reread::desktop_revision_body_read(false);
                            }
                            _ => {}
                        }
                    }
                }
                if source == SnapshotSource::Codex {
                    let consumed = active.parser.reader.consumed_bytes();
                    let moved = codex_file_join::take_charge(&mut active);
                    codex_page.charge(
                        active.cursor.is_some(),
                        consumed
                            .saturating_sub(active.charged_bytes)
                            .saturating_add(moved),
                    );
                    active.charged_bytes = consumed;
                    if active.hold_offset.is_none()
                        && sampled_scan::codex_cursor::held_monotone(&active.parser.accumulator)
                    {
                        // File offset: a tail's reader counts from its start.
                        let start = active
                            .parser
                            .reader
                            .acquisition
                            .as_ref()
                            .map_or(0, crate::transcript_acquisition::ReadPlan::start_offset);
                        active.hold_offset =
                            Some(start + active.parser.reader.last_complete_line_end());
                    }
                }
                if let Some(end) = group_end {
                    codex_file_join::end_group(
                        active,
                        end,
                        codex_cursor_lease.take(),
                        codex_file_join::EndInputs {
                            sampling: sampling.as_ref(),
                            index,
                            targets: targets!(),
                        },
                    );
                    pending!();
                }
                match stepped {
                    Ok(false) => {
                        // Stage 1 (K6): or a continuation page past its
                        // deadline, which pauses without a ticket.
                        if active.cursor.is_some()
                            && codex_page.cursor_stop(sampled_scan::codex_cursor::Limits::current())
                        {
                            if let Some(lease) = codex_cursor_lease.take() {
                                // Stage 1 hunk A: minted before the pause
                                // consumes the job, kept only if it pauses.
                                let ticket = sampling.as_ref().and_then(|context| {
                                    context.cache.continuation_ticket(&active, &codex_page)
                                });
                                continuation_ticket = None;
                                if let sampled_scan::codex_cursor::PauseEnd::StateBound(
                                    job,
                                    disclosure,
                                ) = lease.pause(active)
                                {
                                    // No unbounded fallback: `JoinStateBound`
                                    // debt, prior body kept, file parked.
                                    sampled_scan::codex_cursor::disclose_job_debt(
                                        &job,
                                        &disclosure,
                                        index,
                                        targets!(),
                                    );
                                    sampled_scan::codex_cursor::dequeue_members(
                                        index,
                                        sampled_scan::codex_cursor::job_files(&job),
                                    );
                                } else {
                                    continuation_ticket = ticket;
                                }
                                pending!();
                            }
                            // A job without its lease is dropped, never
                            // continued in-page past the budget; its pending
                            // path restarts it (L2).
                            if let Some(context) = sampling.as_ref() {
                                context.cache.cursor_note_lost();
                            }
                            pending!();
                        }
                        active_file = Some(active);
                        pending!();
                    }
                    Err(error) => {
                        // Static reader text only, never a path or content. A
                        // live rollout appended while it is read reports
                        // "acquisition exceeds stable source"; that file is
                        // retried when its next write is hinted.
                        eprintln!(
                            "local snapshot scan: {} transcript read failed: {error}",
                            source.api_slug()
                        );
                        if let Some(lease) = codex_cursor_lease.take() {
                            lease.release();
                        }
                        if let Some(group) = active.group.as_ref() {
                            // A member read failure: strict, as before P2.
                            codex_file_join::disclose_strict(&group.members, targets!());
                            sampled_scan::codex_cursor::dequeue_members(index, &group.members);
                            pending!();
                        }
                        if active.cursor.is_some() {
                            sampled_scan::codex_cursor::dequeue(index, &active.candidate);
                        }
                        if source == SnapshotSource::ClaudeCode {
                            claude_request_census::invalidate_claude_request_census(
                                index,
                                &active.candidate.path,
                            );
                        }
                        if sampled_scan::codex_cursor::requeue_refused(
                            source,
                            &error,
                            index,
                            &codex_selected_flags,
                            &active.candidate,
                        ) {
                            active.parser.reader.reader.close();
                            pending!();
                        }
                        active.parser.reader.reader.close();
                        census.record_unreadable_file(
                            UnreadableCause::OpenRead,
                            &active.candidate.path,
                        );
                        pending!();
                    }
                    Ok(true) if codex_page.continuation() => {
                        continuation_ticket = None;
                        if let Some(lease) = codex_cursor_lease.take() {
                            #[cfg(test)]
                            sampled_scan::codex_cursor::tests::constrain_eof_park(&mut active);
                            drop(lease.pause(active)); // StateBound: ordinary disclosure only.
                        }
                        pending!();
                    }
                    Ok(true) => {}
                }
                #[cfg(test)]
                AFTER_READER_EOF.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().as_mut() {
                        hook(&active);
                    }
                });
                // Retain native trailing-line behavior at a genuine
                // unchanged EOF. A grown read keeps this fragment withheld.
                if source == SnapshotSource::ClaudeCode
                    && active.cursor.is_none()
                    && active.parser.reader.sealed_fragment()
                    && active
                        .parser
                        .reader
                        .acquisition
                        .as_ref()
                        .is_some_and(|plan| {
                            plan.start_offset()
                                .checked_add(active.parser.reader.consumed_bytes())
                                == Some(plan.frozen_length())
                                && active
                                    .parser
                                    .reader
                                    .reader
                                    .get_ref()
                                    .metadata()
                                    .is_ok_and(|held| held.len() == plan.frozen_length())
                        })
                {
                    active.parser.apply_sealed_fragment();
                }
                if active.cursor.is_some() && active.group.is_none() {
                    // Apply the EOF record before the protected-tier gate below. A group
                    // job applies it to its live member in `member_eof`, before
                    // that member's proof ends (R2-N1).
                    sampled_scan::codex_cursor::apply_eof_record(&mut active);
                }
                // Consumer-only: publish retained native state at primary EOF.
                if active.is_primary_for(SnapshotSource::Codex) {
                    if let Some(feed) = codex_versions.as_ref() {
                        feed.observe(&active);
                    }
                }
                if let Some(context) = attribution_context {
                    let workers = launch_workers_for_parsed(
                        source,
                        active.parser.accumulator.source_session_id.as_deref(),
                        &active.candidate.path,
                    );
                    match context.launch_events().prepare_step(&workers) {
                        Ok(false) => {
                            active_file = Some(active);
                            pending!();
                        }
                        Err(()) => {
                            if source == SnapshotSource::ClaudeCode {
                                claude_request_census::invalidate_claude_request_census(
                                    index,
                                    &active.candidate.path,
                                );
                            }
                            census.record_unreadable_file(
                                UnreadableCause::Reduction,
                                &active.candidate.path,
                            );
                            pending!();
                        }
                        Ok(true) => {}
                    }
                }
                if let Some(context) = sampling.as_mut() {
                    if let Some(plan) = active.parser.reader.acquisition.as_ref() {
                        context.record_input(
                            plan.metrics(),
                            matches!(
                                plan.mode(),
                                crate::transcript_acquisition::ReadMode::Full(_)
                            ),
                        );
                        // D168's replays, with the bytes they read: a group
                        // from its first member, and a file with protected
                        // tiers re-read from its start.
                        #[cfg(unix)]
                        {
                            let replay = if let Some(group) = active.group.as_deref() {
                                Some((
                                    tail_source::counters::Replay::Group,
                                    group
                                        .consumed_before
                                        .saturating_add(active.parser.reader.consumed_bytes()),
                                ))
                            } else {
                                active
                                    .sampling
                                    .as_ref()
                                    .is_some_and(|acquisition| acquisition.tier_prefix_replay)
                                    .then_some((
                                        tail_source::counters::Replay::TierPrefix,
                                        plan.metrics().native_bytes,
                                    ))
                            };
                            if let Some((cause, bytes)) = replay {
                                tail_source::counters::replay(source, cause, bytes);
                            }
                        }
                        resource_probe.rearm_full_completed(
                            &local_index_key(&active.candidate.path),
                            plan.mode(),
                            plan.metrics().native_bytes,
                        );
                        resource_probe.full_parse_reason(
                            plan.mode(),
                            active.parse_reason,
                            0,
                            plan.metrics().native_bytes,
                        );
                        crate::local_resource_diagnostics::change_reason::read(
                            source.api_slug(),
                            &local_index_key(&active.candidate.path),
                            plan.mode(),
                            plan.metrics().native_bytes,
                            plan.metrics().sample_bytes as u64,
                        );
                    }
                }
                if active.sampling.as_ref().is_some_and(|acquisition| {
                    !matches!(
                        acquisition.mode,
                        crate::transcript_acquisition::ReadMode::Full(_)
                    ) && active
                        .parser
                        .accumulator
                        .codex_tier_replay
                        .as_ref()
                        .is_some_and(codex_file_join::TierReplay::has_protected_tiers)
                }) {
                    // Native finish compares the reopened descriptor to the captured
                    // identity, so replacement during fallback cannot publish.
                    let reopened =
                        reopen_for_replay(source, &active.candidate, &active.parser.reader.reader);
                    let Ok(file) = reopened else {
                        census.record_unreadable_file(
                            UnreadableCause::OpenRead,
                            &active.candidate.path,
                        );
                        pending!();
                    };
                    let Ok(mut parser) = sampled_scan::new_source_parser(
                        file,
                        &active.candidate,
                        index,
                        sampled_scan::ParserOptions {
                            source,
                            metadata: &codex_title_metadata,
                            traces: codex_turn_traces.clone(),
                            identity_capture: claude_request_identity_capture,
                            cache: sampling.as_ref().map(|c| &c.cache),
                        },
                    ) else {
                        census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        pending!();
                    };

                    let acquisition = active.sampling.as_mut().expect("sampled acquisition");
                    let debt = sampled_audit::debt_for_key(
                        index,
                        &acquisition.key,
                        sampled_scan::now_seconds(),
                    );
                    let Ok(mode) = parser.prepare_acquisition(
                        None,
                        &acquisition.scope,
                        debt,
                        sampled_scan::now_seconds(),
                    ) else {
                        census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        pending!();
                    };
                    acquisition.mode = mode;
                    acquisition.tier_prefix_replay = true;
                    if let Some(context) = sampling.as_mut() {
                        context.priority_replays += 1;
                        context.record_mode(mode, acquisition.audit_due);
                    }
                    active.parser = parser;
                    active.charged_bytes = 0;
                    active.hold_offset = None;
                    if active.cursor.is_some()
                        && !sampled_scan::codex_cursor::restart_in_place(&mut active)
                    {
                        // The full replay cannot be frozen: end this attempt
                        // (a retryable failure), never an unpaged read.
                        active.cursor = None;
                        if let Some(lease) = codex_cursor_lease.take() {
                            lease.release();
                        }
                        sampled_scan::codex_cursor::dequeue(index, &active.candidate);
                        census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        pending!();
                    }
                    // LD: the replay is a fresh Full delivery from 0.
                    if let Some(delivery) = line_delivery.as_mut() {
                        delivery.arm();
                    }
                    active_file = Some(active);
                    pending!();
                }
                // #631 review: the bytes this attempt read, taken before
                // `finish_job` consumes the acquisition's start offset. An
                // exact-stamp memo below must not cover anything past them.
                if source == SnapshotSource::Codex && active.group.is_none() {
                    if let (Some(entry), Some(plan)) = (
                        active
                            .sampling
                            .as_ref()
                            .and_then(|sampled| index.files.get(&sampled.key)),
                        active.parser.reader.acquisition.as_ref(),
                    ) {
                        let start = plan.start_offset();
                        codex_fragment::note_tail_repeat(
                            entry,
                            &active.candidate,
                            codex_fragment::TailRead {
                                mode: plan.mode(),
                                start,
                                end: start.saturating_add(active.parser.reader.consumed_bytes()),
                                terminated_end: active.parser.reader.last_complete_line_end(),
                            },
                            census_unix_seconds,
                            backfill_window_days,
                        );
                    }
                }
                let attempt_read_end = sampled_scan::codex_cursor::read_end(&active);
                // S6: a cursor job commits only through its sealed-prefix
                // certificate; an invalidated attempt publishes nothing.
                let mut cursor_certificate = None;
                let mut cursor_publication = None;
                let mut cursor_fragment = None;
                // A certified job's native EOF bit for its Tail write.
                let mut cursor_eof_applied = None;
                if let Some(context) = sampling.as_ref().filter(|_| active.cursor.is_some()) {
                    let current_scope = sampled_scan::reduction_dependencies(
                        source,
                        &active.candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )
                    .map(|dependency| context.file_scope(source, &active.candidate, &dependency));
                    let counting_now =
                        sampled_scan::codex_cursor::job_counting_view(&active, index);
                    let group_scope_now = sampled_scan::codex_cursor::group_scope();
                    let census_trusted = state_census_complete
                        && sidecar_census_complete
                        && active
                            .cursor
                            .as_ref()
                            .is_some_and(sampled_scan::codex_cursor::JobMeta::census_trusted);
                    // G1: growth past a job's frozen extent is next-generation
                    // evidence when the job started in this census generation.
                    let job_in_generation = active
                        .cursor
                        .as_ref()
                        .is_some_and(|meta| meta.in_generation(index));
                    // The certificate re-reads two samples from the held FD.
                    codex_page.charge(true, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                    match sampled_scan::codex_cursor::finish_job(
                        &context.cache,
                        codex_cursor_lease.take(),
                        &mut active,
                        current_scope.as_ref(),
                        &counting_now,
                        &group_scope_now,
                        census_trusted,
                    ) {
                        sampled_scan::codex_cursor::JobEnd::Certified {
                            checkpoint,
                            grown,
                            publication,
                            fragment,
                        } => {
                            // N2: a withheld record keeps the path pending, so
                            // the next page tails it from `s`.
                            let next_generation = grown && fragment.is_none() && job_in_generation;
                            sampled_scan::codex_cursor::release_path(
                                index,
                                &active.candidate,
                                grown || fragment.is_some(),
                                next_generation,
                            );
                            context
                                .cache
                                .cursor_note_next_generation(u64::from(next_generation));
                            // N1: a cursor-only job (census incomplete at start
                            // or now) publishes like main's unsampled read: the
                            // certificate fenced the object, but no checkpoint,
                            // copy or verification is kept. A group job retains
                            // no reduction (its replay is joined).
                            cursor_eof_applied = Some(publication.eof_applied());
                            cursor_certificate = Some(
                                Some(checkpoint)
                                    .filter(|_| census_trusted && active.group.is_none()),
                            );
                            cursor_publication = Some(publication);
                            cursor_fragment = fragment;
                        }
                        sampled_scan::codex_cursor::JobEnd::Uncertified {
                            grown,
                            publication,
                            fragment,
                        } => {
                            // N2: a withheld record keeps the path pending, so
                            // the next page tails it from `s`.
                            let next_generation = grown && fragment.is_none() && job_in_generation;
                            sampled_scan::codex_cursor::release_path(
                                index,
                                &active.candidate,
                                grown || fragment.is_some(),
                                next_generation,
                            );
                            context
                                .cache
                                .cursor_note_next_generation(u64::from(next_generation));
                            cursor_certificate = Some(None);
                            cursor_publication = Some(publication);
                            cursor_fragment = fragment;
                        }
                        // Its path is still pending: the next page re-bootstraps.
                        sampled_scan::codex_cursor::JobEnd::Restart => pending!(),
                        sampled_scan::codex_cursor::JobEnd::MemberChanged(disclosure) => {
                            sampled_scan::codex_cursor::disclose_job_debt(
                                &active,
                                &disclosure,
                                index,
                                targets!(),
                            );
                            sampled_scan::codex_cursor::dequeue_members(
                                index,
                                sampled_scan::codex_cursor::job_files(&active),
                            );
                            pending!();
                        }
                    }
                    // A group's sealed members ended with the job; only its
                    // live member's path follows `release_path` above.
                    if let Some(group) = active.group.as_ref() {
                        sampled_scan::codex_cursor::dequeue_members(
                            index,
                            group
                                .members
                                .iter()
                                .filter(|member| member.path != active.candidate.path),
                        );
                    }
                }
                // S12: the live member's certified grant reaches validation.
                let group_live = active
                    .group
                    .as_ref()
                    .and_then(|_| sampled_scan::codex_cursor::certified_prefix(&active))
                    .map(|prefix| (local_index_key(&active.candidate.path), prefix));
                // PR-1 class 3: a non-monotone held file is memoized too, at the
                // read end; the record gate decides. Only a file the accumulator
                // already holds, and that is not parent-pending (the gate refuses
                // those), pays the two samples.
                let accumulator = &active.parser.accumulator;
                let memo_offset = active
                    .hold_offset
                    .or_else(|| {
                        (!accumulator.codex_usage_accounting_complete()
                            && !sampled_scan::codex_cursor::held_monotone(accumulator))
                        .then_some(attempt_read_end)
                    })
                    .filter(|_| {
                        source == SnapshotSource::Codex
                            && active.aliases.is_empty()
                            && sampling.is_some()
                    });
                if memo_offset.is_some() {
                    // The live witness reads two samples of the held file.
                    codex_page.charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                }
                let memo_candidate = memo_offset.and_then(|offset| {
                    let file = active.parser.reader.reader.get_ref();
                    let live = sampled_scan::codex_cursor::LiveWitness::read(
                        &active.candidate.path,
                        file,
                        offset,
                    )?;
                    let stamp = sampled_scan::codex_cursor::OpenStamp::capture(file).ok()?;
                    // PR-1: every singleton entry is exact until a counted tail
                    // makes growth replayable, so the stamp must cover exactly
                    // the bytes read (#631 review: captured after
                    // `finish_job`'s check).
                    if stamp.extent() != attempt_read_end {
                        return None;
                    }
                    // L-6: a curable hold is stamped only at the length its bind saw.
                    if sampled_scan::codex_cursor::growth_may_cure(&active.parser.accumulator)
                        && active.parser.accumulator.codex_bind_seed_len != Some(attempt_read_end)
                    {
                        return None;
                    }
                    let dependencies = sampled_scan::reduction_dependencies(
                        source,
                        &active.candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )?;
                    let digest = sampled_scan::codex_cursor::memo_digest(
                        index,
                        &active.candidate,
                        file,
                        &dependencies,
                        &codex_title_metadata,
                        sampled_scan::codex_cursor::owner_members(
                            codex_join_inventory.as_ref(),
                            &active.candidate.path,
                        ),
                        &sampled_scan::codex_cursor::counting_view(&active.candidate, index),
                    )?;
                    let sidecar = sampled_scan::codex_cursor::sidecar_wakes(
                        &active.parser.accumulator,
                    )
                    .then(|| {
                        sampled_scan::codex_cursor::sidecar_fingerprint(
                            &codex_title_metadata,
                            &active.candidate.path,
                        )
                    });
                    Some((digest, live, stamp, sidecar))
                });
                let OwnedActiveFile {
                    first_read,
                    sampling: file_sampling,
                    candidate,
                    decision,
                    parse_reason: _,
                    previous_snapshot_fingerprint,
                    previous_upload_body_witness,
                    projection_adoption_required,
                    source_file_fingerprint,
                    parser,
                    aliases,
                    mut applied_receipts,
                    cursor: _,
                    charged_bytes: _,
                    hold_offset: _,
                    mut group,
                } = *active;
                let mut independent_contributions = Vec::new();
                let mut independent_group = false;
                let group_members = group.as_deref_mut().map_or(0, |group| {
                    independent_group = group.independent;
                    independent_contributions = std::mem::take(&mut group.contributions);
                    codex_legacy_join_baselines.extend(group.take_legacy_baselines());
                    group.members.len()
                });
                let _first_read = first_read;
                let mut parser = parser;
                if let Some(replay) = parser.accumulator.codex_tier_replay.take() {
                    match replay.finish() {
                        Ok(receipt) => {
                            applied_receipts.insert(local_index_key(&candidate.path), receipt);
                        }

                        Err(_) => {
                            if let Some(group) = group.as_deref().filter(|group| group.independent)
                            {
                                codex_file_join::refuse_independent(
                                    group,
                                    sampling.as_ref(),
                                    index,
                                    targets!(),
                                );
                                pending!();
                            }
                            if let Some((context, publication)) =
                                sampling.as_ref().zip(cursor_publication.take())
                            {
                                context.cache.cursor_published(publication, false);
                            }
                            census.ownership_incomplete_file_count += 1;
                            census.causes.add(ownership::GROUP, 1);
                            census.record_unreadable(UnreadableCause::AliasParser, 1);
                            residue_index_keys.insert(local_index_key(&candidate.path));
                            pending!();
                        }
                    }
                }
                // N4 (fe-seam-ack §5): the file branch decides its H3c route
                // before its completion.
                let file_acquisition = file_sampling
                    .as_ref()
                    .filter(|_| cursor_certificate.is_none());
                let (current_scope, prefix) = match file_acquisition {
                    Some(acquisition) => {
                        // Known dependencies and the current path are separate from the
                        // sampled prefix promise. Neither may be stale at completion.
                        let current_scope = sampled_scan::reduction_dependencies(
                            source,
                            &candidate,
                            &codex_title_metadata,
                            &claude_title_metadata,
                            claude_effort_support_dir_ref,
                        )
                        .zip(sampling.as_ref())
                        .map(|(dependency, context)| {
                            context.file_scope(source, &candidate, &dependency)
                        });
                        // H3c: a passed certificate permits native finish of
                        // this prefix only. Discard its checkpoint: no cache copy,
                        // audit credit or source verification can follow it.
                        let prefix = current_scope
                            .as_ref()
                            .filter(|scope| *scope == &acquisition.scope)
                            .filter(|_| {
                                // H3c preserves an already-read prefix while an
                                // audit waits. A byte-zero Full must instead
                                // reach normal completion and discharge its
                                // audit, even when RAM retention is unavailable.
                                acquisition.audit_due.is_some()
                                    && sampling.as_ref().is_some_and(|context| {
                                        context.audit_metadata_supported
                                            && (context.audit_slots > 0
                                                || index.files.get(&acquisition.key).is_some_and(
                                                    ScanIndexEntry::has_unverified_source,
                                                ))
                                    })
                            })
                            .and_then(|scope| {
                                parser.commit_claude_grown_prefix(
                                    &candidate.path,
                                    scope,
                                    index
                                        .files
                                        .get(&acquisition.key)
                                        .map_or(0, |entry| entry.size_bytes),
                                )
                            });
                        (current_scope, prefix)
                    }
                    None => (None, None),
                };
                let completed_acquisition = if let Some(certificate) = cursor_certificate {
                    certificate.map(|checkpoint| sampled_jsonl::CompletedNativeAcquisition {
                        checkpoint,
                        unsealed: true,
                    })
                } else if let Some(acquisition) = file_sampling.as_ref() {
                    if let Some(prefix) = prefix {
                        match prefix {
                            Ok(grant) => parser.reader.sealed_prefix = Some(grant),
                            Err(refusal) => {
                                claude_request_census::invalidate_claude_request_census(
                                    index,
                                    &candidate.path,
                                );
                                let cause = match refusal {
                                    crate::transcript_acquisition::PrefixRefusal::AuditDue => {
                                        UnreadableCause::Reduction
                                    }
                                    _ => UnreadableCause::ScopeObject,
                                };
                                census.record_unreadable_file(cause, &candidate.path);
                                pending!();
                            }
                        }
                        None
                    } else {
                        let mut current_path = candidate.clone();
                        if let Some(cause) = sampled_revalidation_cause(
                            current_scope.as_ref() == Some(&acquisition.scope),
                            || {
                                drop(open_candidate_file(source, &mut current_path)?);
                                Ok(current_path.opened_object_identity
                                    == candidate.opened_object_identity)
                            },
                        ) {
                            if source == SnapshotSource::ClaudeCode {
                                claude_request_census::invalidate_claude_request_census(
                                    index,
                                    &candidate.path,
                                );
                            }
                            census.record_unreadable_file(cause, &candidate.path);
                            pending!();
                        }
                        #[cfg(test)]
                        sampled_scan::test_hooks::fire(
                            sampled_scan::test_hooks::Point::BeforeRetain,
                        );
                        match parser
                            .retain_reduction(&acquisition.scope, sampled_scan::now_seconds())
                        {
                            Ok(completed) => completed,
                            Err(_) => {
                                if source == SnapshotSource::ClaudeCode {
                                    claude_request_census::invalidate_claude_request_census(
                                        index,
                                        &candidate.path,
                                    );
                                }
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                        }
                    }
                } else {
                    None
                };
                // Retain the obligation until native finish and RAM admission.
                // Only due complete-c Unchanged acquisitions can retire it;
                // incidental telemetry refreshes keep the original obligation.
                let quiet_audit_checked = if let (Some(completed), Some(active), Some(context)) = (
                    completed_acquisition.as_ref(),
                    file_sampling.as_ref(),
                    sampling.as_mut(),
                ) {
                    if active.mode == crate::transcript_acquisition::ReadMode::Unchanged
                        // Withheld bodies retain their obligation until release.
                        && !index.claude_account_deferred_holds.contains_key(&active.key)
                        && index.files.get(&active.key).is_some_and(|entry| {
                            entry.audit_requires_full(audit_now)
                                && !entry.has_prefix_provenance()
                        })
                        && !index.claude_request_census.get(&active.key).is_some_and(
                            claude_request_census::ClaudeRequestCensusRecord::identity_incomplete_hold,
                        )
                    {
                        let mut bytes = 0;
                        let checked = completed
                            .checkpoint
                            .quiet_audit_matches(
                                parser.reader.reader.get_mut(),
                                &active.scope,
                                &mut bytes,
                            )
                            .unwrap_or(false);
                        context.sample_bytes = context.sample_bytes.saturating_add(bytes as u64);
                        checked
                    } else {
                        false
                    }
                } else {
                    false
                };
                #[cfg(test)]
                sampled_scan::test_hooks::fire_for_key(
                    sampled_scan::test_hooks::Point::AfterRetain,
                    &local_index_key(&candidate.path),
                );
                let joined_owner = if aliases.is_empty() {
                    None
                } else {
                    parser
                        .accumulator
                        .source_session_id
                        .as_deref()
                        .map(resolve_codex_identity)
                };
                let codex_counting_v2 = parser.accumulator.codex_counting_v2();
                let evicted_legacy_v2_owner = parser
                    .accumulator
                    .source_session_id
                    .as_deref()
                    .filter(|_| {
                        codex_counting_version::evicted_legacy_selected_v2(
                            &parser.accumulator,
                            index,
                        )
                    })
                    .map(codex_protected_owner);
                // Counting receipts reach the scan's local diagnostics only
                // when this parse finishes: once per finished active file (a
                // joined group is one).
                let codex_counting_receipts =
                    parser
                        .accumulator
                        .codex_counting
                        .as_deref()
                        .map(|counting| {
                            let mut receipts = census.codex_counting_v2.clone().unwrap_or_default();
                            counting.fold_receipts(&mut receipts);
                            if evicted_legacy_v2_owner.is_some() {
                                receipts.legacy_to_v2_after_tombstone_eviction = receipts
                                    .legacy_to_v2_after_tombstone_eviction
                                    .saturating_add(1);
                            }
                            receipts
                        });
                // Before `finish` consumes the parser. Ledger
                // birth: `created()` and identity of the descriptor this parse
                // opened, taken at open (never a path); unknown is None.
                let claude_opened_birth = (source == SnapshotSource::ClaudeCode
                    && claude_index_path_family_member(&candidate.path).is_some())
                .then_some(parser.claude_opened_birth)
                .flatten();
                let claude_itemless_request_hashes =
                    if source == SnapshotSource::ClaudeCode && !parser.positive_usage_evidence {
                        claude_request_census::claude_buffered_request_hashes(&parser)
                    } else {
                        Vec::new()
                    };
                let claude_grown_prefix =
                    source == SnapshotSource::ClaudeCode && parser.reader.sealed_prefix.is_some();
                let finish_request = FinishRequest {
                    expected_opened_object_identity: &candidate.opened_object_identity,
                    path: &candidate.path,
                    collected_at: collected_at.as_str(),
                    source_file_fingerprint: source_file_fingerprint.clone(),
                    codex_title_metadata: (source == SnapshotSource::Codex)
                        .then_some(&codex_title_metadata),
                    claude_title_metadata: (source == SnapshotSource::ClaudeCode)
                        .then_some(&claude_title_metadata),
                    attribution_context,
                    repository_identity: None,
                    money_context: Some(claude_request_money::e2::ReadContext {
                        index,
                        path: &candidate.path,
                        twins: history_upgrade.twin_groups(),
                    }),
                };
                // This completion's Tail write: encoded at PRE into a local
                // buffer, published only on the native finish's verdict.
                #[cfg(unix)]
                let tail_base = parser.take_tail_base();
                #[cfg(unix)]
                let mut tail = completed_acquisition
                    .as_ref()
                    .zip(file_sampling.as_ref())
                    .filter(|_| sampling.is_some())
                    .and_then(|(completed, active)| {
                        // `None` off a Tail route.
                        tail_source::pending(
                            source,
                            index,
                            completed,
                            active,
                            &candidate,
                            parser.reader.reader.get_ref(),
                            claude_request_identity_capture,
                            tail_base,
                            quiet_audit_checked,
                        )
                    })
                    // A certified cursor job stages its Tail the same way,
                    // under its own seal bit.
                    .map(|tail| match cursor_eof_applied {
                        Some(eof_applied) => tail.sealed_by_job(eof_applied),
                        None => tail,
                    });
                #[cfg(unix)]
                let parsed_file = {
                    let tailed = tail.is_some();
                    let mut encode = |live: PreFinalization<'_>| {
                        if let Some(tail) = tail.as_mut() {
                            tail.encode(&live);
                        }
                    };
                    let pre = tailed.then_some(&mut encode as &mut dyn FnMut(PreFinalization<'_>));
                    parser.finish_boxed_native(finish_request, pre)
                };
                // On a Tail route: whether this file's committed head stays
                // its continuation (staged, or nothing to restate).
                #[cfg(unix)]
                let tail_reused = tail.map(|tail| tail.publish(&parsed_file));
                #[cfg(not(unix))]
                let parsed_file = parser.finish_boxed_native(finish_request, None);
                #[cfg(test)]
                sampled_scan::test_hooks::fire(
                    sampled_scan::test_hooks::Point::BeforeNativeEffects,
                );
                // A committed cursor attempt counts as published only now.
                if let Some((context, publication)) =
                    sampling.as_ref().zip(cursor_publication.take())
                {
                    context
                        .cache
                        .cursor_published(publication, parsed_file.is_ok());
                }
                if let Ok(parsed) = &parsed_file {
                    if source == SnapshotSource::ClaudeCode {
                        for item in &parsed.snapshots {
                            if let Some(fold) = item.claude_money.as_deref() {
                                claude_request_money::e2::remember_birth(
                                    index,
                                    &candidate.path,
                                    fold,
                                );
                            }
                        }
                    }
                }
                let parsed_file = match parsed_file.and_then(|mut parsed| {
                    if !independent_contributions.is_empty() {
                        codex_file_join::fold_independent(
                            &mut parsed.snapshots,
                            independent_contributions,
                        )?;
                    }
                    Ok(parsed)
                }) {
                    Ok(parsed) => parsed,

                    Err(_error) => {
                        if let Some(group) = group.as_deref().filter(|group| group.independent) {
                            codex_file_join::refuse_independent(
                                group,
                                sampling.as_ref(),
                                index,
                                targets!(),
                            );
                            pending!();
                        }
                        if source == SnapshotSource::Codex && !aliases.is_empty() {
                            codex_file_join::disclose_strict(&aliases, targets!());
                            pending!();
                        }
                        #[cfg(test)]
                        sampled_scan::test_hooks::record_finish_error(&_error);
                        if source == SnapshotSource::ClaudeCode {
                            claude_request_census::invalidate_claude_request_census(
                                index,
                                &candidate.path,
                            );
                        }
                        census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                        pending!();
                    }
                };
                if let Some(receipts) = codex_counting_receipts {
                    if let Some(owner) = evicted_legacy_v2_owner {
                        codex_counting_version::note_evicted_legacy_v2_selection(index, &owner);
                    }
                    census.codex_counting_v2 = Some(receipts);
                }
                let parse_complete = parsed_file.progress_complete();
                // Claude response conflicts may be discovered only by native
                // finalization. A prefix cannot publish that late loss: it
                // would have neither a committed audit marker nor necessarily
                // a request-census record when the record budget is exhausted.
                if claude_grown_prefix && !parse_complete {
                    claude_request_census::invalidate_claude_request_census(index, &candidate.path);
                    census.record_unreadable(UnreadableCause::ScopeObject, 1);
                    pending!();
                }
                if !aliases.is_empty() && !parse_complete {
                    // Joining authorizes a complete replacement only. Native
                    // ownership/parser loss cannot publish a partial union body.
                    census.ownership_incomplete_file_count += aliases.len();
                    census.causes.add(ownership::GROUP, aliases.len());
                    census.record_unreadable(UnreadableCause::AliasParser, 1);
                    residue_index_keys
                        .extend(aliases.iter().map(|member| local_index_key(&member.path)));
                    pending!();
                }
                if !aliases.is_empty() {
                    if aliases
                        .iter()
                        .any(|member| codex_archive_path(&member.path))
                        && codex_file_join::stage_independent_inventory(
                            index,
                            &aliases,
                            joined_owner.as_deref().expect("joined owner"),
                        )
                        .is_err()
                    {
                        codex_file_join::disclose_strict(&aliases, targets!());
                        pending!();
                    }
                    codex_join_completed.push(codex_file_join::Group {
                        owner: joined_owner
                            .expect("joined replay owner was bound before native finish"),
                        home: codex_file_join::member_home(&candidate.scan_root),
                        members: aliases.clone(),
                        live: group_live.clone(),
                    });
                }
                let diagnostic_reason = if parse_complete {
                    FileReason::Complete
                } else if parsed_file.ownership_incomplete_file_count > 0 {
                    FileReason::OwnershipIncomplete
                } else if parsed_file.recognized_usage_drop_count > 0 {
                    FileReason::RecognizedUsageDropped
                } else {
                    FileReason::ReadOrLineLoss
                };
                let terminal_loss = parsed_file.terminal_loss();
                let index_key = local_index_key(&candidate.path);
                let non_progressing_residue = parsed_file.non_progressing_residue();
                if non_progressing_residue {
                    residue_index_keys.insert(index_key.clone());
                } else {
                    settled_residue_index_keys.insert(index_key.clone());
                }
                let report = parsed_file.report;
                let recognized_usage_drop_count = parsed_file.recognized_usage_drop_count;
                let ownership_incomplete_file_count = parsed_file.ownership_incomplete_file_count;
                let zero_snapshot_usage_evidence = parsed_file.zero_snapshot_usage_evidence;
                let dropped_usage_record_count = parsed_file.dropped_usage_record_count;
                let claude_compaction_unlinked_parent_count =
                    parsed_file.claude_compaction_unlinked_parent_count;
                if let Some(context) = sampling
                    .as_ref()
                    .filter(|_| source == SnapshotSource::Codex && aliases.is_empty())
                {
                    // Memoize a non-progressing ownership-held singleton.
                    // Anything else, completion included, clears a stale entry.
                    let held = !parse_complete
                        && non_progressing_residue
                        && ownership_incomplete_file_count > 0;
                    match memo_candidate.filter(|_| held) {
                        Some((digest, live, stamp, sidecar)) => {
                            context.cache.memo_record(
                                sampled_scan::codex_cursor::memo_key(
                                    &context.namespace,
                                    &index_key,
                                ),
                                sampled_scan::codex_cursor::MemoEntry::new(
                                    digest,
                                    live,
                                    context.cache.retained_stamp(&candidate.path, stamp),
                                    sidecar,
                                    sampled_scan::codex_cursor::Disclosure {
                                        reason:
                                            sampled_scan::codex_cursor::DebtReason::HeldTerminal,
                                        ownership_incomplete_file_count,
                                        cause: parsed_file.cause,
                                        zero_snapshot_usage_evidence,
                                        diagnostic_reason,
                                        parsed_snapshot_count: parsed_file.snapshots.len(),
                                        held: sampled_scan::codex_cursor::HeldCounts {
                                            loss: parsed_file.terminal_loss(),
                                        },
                                    },
                                )
                                // Every singleton entry is exact (PR-1).
                                .growth_may_cure(true),
                            )
                        }
                        None => context
                            .cache
                            .memo_forget(&sampled_scan::codex_cursor::memo_key(
                                &context.namespace,
                                &index_key,
                            )),
                    }
                }
                // A new prefix/lossy obligation without a slot cannot publish
                // or mutate its index entry. Existing marked files keep custody.
                let needs_marker = cursor_fragment.is_some()
                    || completed_acquisition
                        .as_ref()
                        .is_some_and(|completed| completed.checkpoint.audit_debt().is_some())
                    || (completed_acquisition.is_none()
                        && file_sampling
                            .as_ref()
                            .is_some_and(|active| active.audit_due.is_some()));
                let slot_unfunded = sampling
                    .as_ref()
                    .is_some_and(|context| context.audit_slots == 0)
                    && !index
                        .files
                        .get(&index_key)
                        .is_some_and(ScanIndexEntry::has_unverified_source);
                if needs_marker
                    && !index.claude_account_deferred_holds.contains_key(&index_key)
                    && (slot_unfunded || !index.can_stage_sampled_audit(&index_key))
                {
                    // A refused prefix/lossy completion is a delay, not a Full.
                    if let Some(context) = sampling.as_mut() {
                        context.audit_cap_delay += 1;
                    }
                    sampled_audit::queue_cap_retry(index, &candidate);
                    census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    pending!();
                }
                // Debt-free after quiet retirement is scheduling state, not
                // Full authority, including a later forced Unchanged read.
                let source_verified = sampled_jsonl::loss_free_source_report(
                    &report,
                    recognized_usage_drop_count,
                    dropped_usage_record_count,
                ) && (cursor_fragment.is_none()
                    && file_sampling.as_ref().is_some_and(|active| {
                        matches!(
                            active.mode,
                            crate::transcript_acquisition::ReadMode::Full(_)
                        )
                    })
                    && completed_acquisition
                        .as_ref()
                        .is_some_and(|completed| completed.checkpoint.audit_debt().is_none())
                    || (file_sampling.is_none()
                        && state_census_complete
                        && sidecar_census_complete));
                let mut parsed = parsed_file.snapshots;
                if source == SnapshotSource::ClaudeCode {
                    claude_request_census::record_claude_request_census(
                        index,
                        claude_request_census::ClaudeRequestCensusParse {
                            path: &candidate.path,
                            index_key: &index_key,
                            source_file_fingerprint: &source_file_fingerprint,
                            census_window_end: &census_window_end,
                            complete: parse_complete,
                            lossy: terminal_loss.is_some(),
                            source_verified,
                            // The loader bound the predecessor; completion must
                            // seal the whole loss-free suffix. This is not Full credit.
                            continued_source: cursor_fragment.is_none()
                                && file_sampling.as_ref().is_some_and(|active| {
                                    active.census_base_bound
                                        && matches!(
                                            active.mode,
                                            crate::transcript_acquisition::ReadMode::Unchanged
                                                | crate::transcript_acquisition::ReadMode::Tail
                                        )
                                })
                                && completed_acquisition.as_ref().is_some_and(|completed| {
                                    completed.checkpoint.sealed_offset() == candidate.size_bytes
                                })
                                && sampled_jsonl::loss_free_source_report(
                                    &report,
                                    recognized_usage_drop_count,
                                    dropped_usage_record_count,
                                ),
                            itemless_request_hashes: claude_itemless_request_hashes,
                            opened_birth: claude_opened_birth,
                            modified_unix_seconds: candidate.modified_unix_seconds,
                        },
                        &parsed,
                    );
                }
                if source == SnapshotSource::Codex {
                    for snapshot in parsed.iter_mut() {
                        apply_codex_state_evidence(
                            snapshot,
                            &codex_title_metadata,
                            &candidate.path,
                        );
                    }
                }
                if parse_complete && !aliases.is_empty() {
                    for alias in &aliases {
                        if alias.path == candidate.path {
                            continue;
                        }
                        let alias_fingerprint = alias.source_file_fingerprint.clone();
                        pending_finalization.push(PendingIndexFinalization {
                            withheld_content: None,
                            sampled_audit_verified: false,
                            codex_pending_recovery: index
                                .files
                                .get(&local_index_key(&alias.path))
                                .is_some_and(ScanIndexEntry::codex_recovery_is_pending),
                            index_key: local_index_key(&alias.path),
                            source_file_fingerprint: alias_fingerprint.clone(),
                            previous_snapshot_fingerprint: index.last_snapshot_fingerprint(alias),
                            previous_upload_body_witness: index.last_upload_body_witness(alias),
                            parse_complete,
                            diagnostic_reason,
                            parsed_snapshot_count: parsed.len(),
                            effective_upload_body_witness_revision: index
                                .active_effective_upload_body_witness_revision,
                        });
                        let alias_items = parsed
                            .iter()
                            .cloned()
                            .map(|mut item| {
                                if !independent_group {
                                    item.source_file_fingerprint = Some(alias_fingerprint.clone());
                                    item.snapshot_fingerprint = snapshot_fingerprint(source, &item);
                                }
                                item
                            })
                            .collect::<Vec<_>>();
                        index.record(
                            alias.clone(),
                            alias_items
                                .last()
                                .map(|item| item.snapshot_fingerprint.clone()),
                            ScanParseOutcome::Snapshot,
                        );
                        census
                            .observed_index_keys
                            .insert(local_index_key(&alias.path));
                        if !independent_group {
                            snapshots.extend(alias_items);
                        }
                    }
                }
                scanned_session_count += parsed.len();
                let last_snapshot_fingerprint = parsed
                    .last()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone());
                let parsed_snapshot_count = parsed.len();
                let sampled_audit_verified = parse_complete
                    && cursor_fragment.is_none()
                    && completed_acquisition
                        .as_ref()
                        .is_some_and(|completed| completed.checkpoint.audit_debt().is_none())
                    && file_sampling
                        .as_ref()
                        .is_some_and(|active| active.audit_due.is_some());
                if sampled_audit_verified {
                    if let Some(context) = sampling.as_mut() {
                        context.complete_audit(
                            file_sampling
                                .as_ref()
                                .and_then(|active| active.audit_due)
                                .expect("verified audit due"),
                        );
                    }
                }
                pending_finalization.push(PendingIndexFinalization {
                    withheld_content: parse_complete
                        .then(|| index.withheld_completed_seen(&candidate))
                        .flatten(),
                    sampled_audit_verified,
                    codex_pending_recovery: index
                        .files
                        .get(&index_key)
                        .is_some_and(ScanIndexEntry::codex_recovery_is_pending),
                    index_key: index_key.clone(),
                    source_file_fingerprint: source_file_fingerprint.clone(),
                    previous_snapshot_fingerprint: (decision != CandidateDecision::ReconcileLegacy
                        && !projection_adoption_required)
                        .then_some(previous_snapshot_fingerprint)
                        .flatten(),
                    previous_upload_body_witness: (decision != CandidateDecision::ReconcileLegacy
                        && !projection_adoption_required)
                        .then_some(previous_upload_body_witness)
                        .flatten(),
                    parse_complete,
                    diagnostic_reason,
                    parsed_snapshot_count,
                    effective_upload_body_witness_revision: index
                        .active_effective_upload_body_witness_revision,
                });
                if source == SnapshotSource::Codex
                    && parse_complete
                    && aliases.is_empty()
                    && applied_receipts.values().any(Option::is_some)
                {
                    if let Some(item) = parsed.first() {
                        codex_join_completed.push(codex_file_join::Group {
                            owner: resolve_codex_identity(&item.source_session_id),
                            home: codex_file_join::member_home(&candidate.scan_root),
                            members: vec![candidate.clone()],
                            live: None,
                        });
                    }
                }
                let counting_owner = parsed.first().and_then(|item| {
                    if source != SnapshotSource::Codex {
                        return None;
                    }
                    let owner = codex_join_inventory
                        .as_ref()?
                        .owner_for_path(&candidate.path)?;
                    let binding = codex_protected_owner(owner);
                    (binding == codex_protected_owner(&item.source_session_id)).then_some(binding)
                });
                let joined_marker =
                    (!aliases.is_empty()).then(|| codex_file_join::member_set_witness(&aliases));
                let protected_owner = (!aliases.is_empty()
                    || applied_receipts.values().any(Option::is_some))
                .then(|| {
                    parsed
                        .first()
                        .map(|item| codex_protected_owner(&item.source_session_id))
                })
                .flatten();
                let joined_keys = aliases
                    .iter()
                    .map(|member| local_index_key(&member.path))
                    .collect::<Vec<_>>();
                if parse_complete {
                    index.record_terminal_jsonl_disposition(&candidate, terminal_loss.clone());
                    let outcome = if last_snapshot_fingerprint.is_some() {
                        ScanParseOutcome::Snapshot
                    } else {
                        ScanParseOutcome::ConfirmedEmpty
                    };
                    // N2: with the certified prefix continued (its staged
                    // Tail head), the entry records only `[0, s)` as read, so
                    // the next page tails the withheld record with main's EOF
                    // behavior. Without a continuation it records the length
                    // read and the staged debt re-selects it at the audit
                    // cadence.
                    let prefix_continued = tail_reused == Some(true);
                    let bound_fragment = cursor_fragment.and_then(|fragment| {
                        completed_acquisition.as_ref().and_then(|completed| {
                            (prefix_continued
                                && completed.checkpoint.sealed_offset() == fragment.offset)
                                .then(|| {
                                    codex_fragment::BoundFragment::bind(&candidate, fragment.offset)
                                })
                                .flatten()
                        })
                    });
                    let mut recorded = candidate;
                    if let Some(fragment) = cursor_fragment
                        .filter(|_| prefix_continued && completed_acquisition.is_some())
                    {
                        recorded.size_bytes = fragment.offset;
                    }
                    // record consumes the candidate but does not use its root.
                    // Move that existing allocation into the commit-sensitive
                    // retry instead of cloning it or guessing a nested root.
                    let quiet_scan_root =
                        quiet_audit_checked.then(|| std::mem::take(&mut recorded.scan_root));
                    if parse_complete && !non_progressing_residue {
                        sampled_audit::settle_growth(index, &index_key);
                    }
                    index.record(recorded, last_snapshot_fingerprint, outcome);
                    // The counting version travels in the same entry as the
                    // fingerprint it describes; no separate save can split them.
                    if let Some(entry) = index.files.get_mut(&index_key) {
                        entry.codex_counting_v2 = codex_counting_v2;
                        entry.codex_counting_owner =
                            counting_owner.clone().map(String::into_boxed_str);
                        entry.codex_fragment = bound_fragment.map(Box::new);
                    }
                    // Each grouped member, aliases included, settles its own
                    // audit on its native-created entry: verified retires and counts.
                    for member in aliases.iter().take(group_members) {
                        let key = local_index_key(&member.path);
                        let marked = index
                            .files
                            .get(&key)
                            .and_then(ScanIndexEntry::unverified_deadline);
                        if let Some(context) = sampling.as_mut() {
                            if let Some(owed) = marked.filter(|_| source_verified) {
                                context.complete_audit(owed);
                            }
                        }
                    }
                    // Native settlement accepts disclosed terminal row loss, even
                    // though that acquisition cannot certify a verified prefix.
                    // Its sampled publication still owes the prepared deadline;
                    // losing a completion certificate must never erase that debt.
                    let obligation = match completed_acquisition.as_ref() {
                        Some(completed) => completed.checkpoint.audit_debt(),
                        None => file_sampling
                            .as_ref()
                            .and_then(|active| active.audit_due)
                            .map(
                                |due_unix_seconds| crate::transcript_acquisition::AuditDebt {
                                    due_unix_seconds,
                                },
                            ),
                    };
                    if let Some(debt) = obligation {
                        let was_pending = index
                            .files
                            .get(&index_key)
                            .is_some_and(ScanIndexEntry::has_unverified_source);
                        // Held retries bypass cap Full/counting, not the
                        // committed-slot reservation for a NEW marker.
                        if !slot_unfunded
                            && index.stage_sampled_audit(&index_key, &source_file_fingerprint, debt)
                            && !was_pending
                        {
                            if let Some(context) = sampling.as_mut() {
                                context.audit_slots = context.audit_slots.saturating_sub(1);
                            }
                        }
                    } else if source_verified {
                        index.complete_full_audit(&index_key, &source_file_fingerprint);
                    }
                    if source == SnapshotSource::ClaudeCode {
                        if claude_grown_prefix {
                            if !slot_unfunded {
                                index.mark_sealed_prefix(&index_key, &source_file_fingerprint);
                            }
                        } else if completed_acquisition.is_some()
                            && cursor_fragment.is_none()
                            && file_sampling.as_ref().is_some_and(|active| {
                                !matches!(
                                    active.mode,
                                    crate::transcript_acquisition::ReadMode::Unchanged
                                )
                            })
                            && state_census_complete
                            && sidecar_census_complete
                            && parse_complete
                        {
                            index.complete_native_recomposition(
                                &index_key,
                                &source_file_fingerprint,
                            );
                        }
                    }
                    if let Some(fragment) = cursor_fragment {
                        let was_pending = index
                            .files
                            .get(&index_key)
                            .is_some_and(ScanIndexEntry::has_unverified_source);
                        if !slot_unfunded
                            && index.stage_sampled_audit(
                                &index_key,
                                &source_file_fingerprint,
                                fragment.debt,
                            )
                            && !was_pending
                        {
                            if let Some(context) = sampling.as_mut() {
                                context.audit_slots = context.audit_slots.saturating_sub(1);
                            }
                        }
                    }
                    // Codex: after every audit staging above (staging
                    // matches the fingerprint), before this entry's save
                    // settles the degraded publication.
                    if let Some(mut completed) = completed_acquisition {
                        if let Some(context) = sampling.as_mut() {
                            let retained = tail_reused == Some(true);
                            let quiet_retired = quiet_audit_checked
                                && !completed.unsealed
                                && retained
                                && cursor_fragment.is_none()
                                && state_census_complete
                                && sidecar_census_complete
                                && parse_complete;
                            // All source/census/Full-credit decisions above saw
                            // the owed debt. This clears only scheduling state.
                            if quiet_retired {
                                completed.checkpoint.retire_quiet_audit();
                            }
                            // The completion's continuation is its committed
                            // head on its route, or none.
                            let quiet_proven = quiet_retired
                                && context
                                    .cache
                                    .quiet_certified(&index_key, &completed.checkpoint);
                            drop(completed);
                            if retained {
                                if quiet_retired {
                                    // A partial save may restore the old marker.
                                    // Preserve this path AND its exact scope root
                                    // until a committed retirement makes it skip.
                                    sampled_audit::queue_quiet_retirement(
                                        index,
                                        &index_key,
                                        quiet_scan_root.expect("checked quiet retirement root"),
                                    );
                                }
                                #[cfg(unix)]
                                let durable_pending = quiet_retired
                                    && context.cache.quiet_stage(
                                        source,
                                        &index_key,
                                        &source_file_fingerprint,
                                        quiet_proven,
                                    );
                                #[cfg(not(unix))]
                                let durable_pending = false;
                                if quiet_retired
                                    && !durable_pending
                                    && index
                                        .retire_quiet_audit(&index_key, &source_file_fingerprint)
                                {
                                    context.audit_quiet_retired += 1;
                                    // Reuse only on the next committed scan:
                                    // partial-save reconciliation may restore
                                    // this marker without accepting its body.
                                }
                            }
                        }
                    }
                    for key in joined_keys {
                        if let Some(entry) = index.files.get_mut(&key) {
                            if source_verified {
                                entry.scan_identity_version =
                                    Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
                            }
                            entry.codex_joined_member_set = joined_marker.clone();
                            entry.codex_protected_owner = protected_owner.clone();
                            // Set only by a V2 decision; a Legacy group clears
                            // any stale mark with the ACK it rewrites.
                            entry.codex_counting_v2 = codex_counting_v2;
                            entry.codex_counting_owner =
                                counting_owner.clone().map(String::into_boxed_str);
                        }
                    }
                }
                if parse_complete {
                    for (key, receipt) in applied_receipts {
                        if let Some(entry) = index.files.get_mut(&key) {
                            if receipt.is_some() {
                                entry.codex_protected_owner = protected_owner.clone();
                            }
                            entry.codex_applied_tier_receipt_required = receipt.is_some();
                            entry.codex_applied_tier_receipt = receipt;
                        }
                    }
                }
                if let Some(loss) = terminal_loss.as_ref() {
                    census.add_terminal_jsonl_loss(loss);
                }
                census.ownership_incomplete_file_count += ownership_incomplete_file_count;
                census
                    .causes
                    .add(parsed_file.cause, ownership_incomplete_file_count);
                census.zero_snapshot_usage_evidence_count +=
                    usize::from(zero_snapshot_usage_evidence);
                census.claude_compaction_unlinked_parent_count = census
                    .claude_compaction_unlinked_parent_count
                    .saturating_add(claude_compaction_unlinked_parent_count);
                // Only classified holds suppress independently valid siblings.
                if parse_complete {
                    snapshots.extend(parsed);
                }
                pending!();
            }
            let Some(mut candidate) = identified_candidates.pop_front() else {
                context_read_budget.flush(index, &codex_selected_flags);
                if codex_page.continuation() {
                    if let Some(traversal) = index.traversal.as_mut() {
                        traversal.counts.caps.drain(source.api_slug());
                    }
                    let continuation_evidence = codex_join_inventory
                        .map(|inventory| CodexContinuationEvidence {
                            inventory,
                            codex: codex_title_metadata,
                            traces: codex_turn_traces,
                        })
                        .and_then(|evidence| match continuation_ticket.as_ref() {
                            Some(ticket) => evidence.for_paused_job(
                                sampling.as_ref().map(|context| context.cache.as_ref()),
                                ticket,
                            ),
                            None => Some(evidence),
                        })
                        .map(|evidence| Arc::new(Mutex::new(Some(evidence))));
                    return Ok(OwnedSourceScanStep::Complete {
                        index: index_storage,
                        scan: SourceScanResult {
                            discovery_growth: std::mem::take(&mut resource_probe.discovery_growth),
                            continuation_ticket,
                            continuation_evidence,
                            ..SourceScanResult::empty(SnapshotSource::Codex)
                        },
                    });
                }
                // Current-page metadata/open uncertainty must reach every F4
                // caller before any hold can retire. The remaining census fold
                // below keeps its existing order; each count is merged once.
                if let Some(traversal) = index.traversal.as_mut() {
                    traversal.counts.directory_entry_cap_exceeded_count +=
                        census.directory_entry_cap_exceeded_count;
                    traversal.counts.unreadable_path_count += census.unreadable_path_count;
                    traversal
                        .counts
                        .unreadable_causes
                        .merge(census.unreadable_causes);
                    traversal.counts.growth_deferred += census.growth_deferred;
                }
                // Per-key absence is independent of aggregate terminal authority.
                if source == SnapshotSource::ClaudeCode {
                    index.probe_absent_claude_account_deferred_holds();
                }
                if let Some(traversal) = index.traversal.as_mut() {
                    // A residue file that this page parsed to completion, or that a
                    // watcher hint proved absent, leaves the generation's residue set; a
                    // file that reproduced its residue (re)enters it.
                    for index_key in settled_residue_index_keys.iter().chain(
                        census.removed_index_keys.iter().filter(|key| {
                            !index
                                .files
                                .get(*key)
                                .is_some_and(ScanIndexEntry::codex_history_is_protected)
                        }),
                    ) {
                        traversal.residue.index_keys.remove(index_key);
                    }
                    if let Some(inventory) = codex_join_inventory
                        .as_ref()
                        .filter(|inventory| !inventory.complete)
                    {
                        record_codex_inventory_hold(traversal, inventory, &residue_index_keys);
                    }
                    traversal.residue.index_keys.extend(residue_index_keys);
                    // Exact watcher remove/rename hints must amend the same durable
                    // observation set used by directory census reconciliation. Apply
                    // removals first so a valid observation later in this page wins.
                    for index_key in census.removed_index_keys.iter() {
                        traversal.observed_index_keys.remove(index_key);
                    }
                    traversal
                        .observed_index_keys
                        .extend(census.observed_index_keys.iter().cloned());
                    traversal.counts.symlink_rejected_count += census.symlink_rejected_count;
                    traversal.counts.oversized_file_count += census.oversized_file_count;
                    traversal.counts.disappeared_file_count += census.disappeared_file_count;
                    traversal.counts.malformed_json_line_count += census.malformed_json_line_count;
                    traversal.counts.invalid_utf8_line_count += census.invalid_utf8_line_count;
                    traversal.counts.over_line_cap_count += census.over_line_cap_count;
                    traversal.counts.recognized_usage_drop_count +=
                        census.recognized_usage_drop_count;
                    traversal.counts.ownership_incomplete_file_count +=
                        census.ownership_incomplete_file_count;
                    traversal.counts.causes.merge(&census.causes);
                    traversal.counts.zero_snapshot_usage_evidence_count +=
                        census.zero_snapshot_usage_evidence_count;
                    traversal.counts.dropped_usage_record_count = traversal
                        .counts
                        .dropped_usage_record_count
                        .saturating_add(census.dropped_usage_record_count);
                    traversal.counts.terminal_over_line_cap_count = traversal
                        .counts
                        .terminal_over_line_cap_count
                        .saturating_add(census.terminal_over_line_cap_count);
                    traversal.counts.terminal_recognized_usage_drop_count = traversal
                        .counts
                        .terminal_recognized_usage_drop_count
                        .saturating_add(census.terminal_recognized_usage_drop_count);
                    traversal.counts.terminal_dropped_usage_record_count = traversal
                        .counts
                        .terminal_dropped_usage_record_count
                        .saturating_add(census.terminal_dropped_usage_record_count);
                }
                if source == SnapshotSource::Codex {
                    // Count-only attribution of why Codex files were selected
                    // on this page. No path, session, or identifier is named.
                    if let Some(line) = census.codex_parse_reasons_line() {
                        eprintln!("{line}");
                    }
                }
                if source == SnapshotSource::ClaudeCode
                    && (census.parse_reasons.iter().any(|count| *count > 0)
                        || census.claude_compaction_unlinked_parent_count > 0
                        || history_upgrade.any()
                        || index.claude_reemission_exclusions.pauses_adoption()
                        || claude_reemission_stop_latched())
                {
                    claude_history_upgrade::alarm_if_owed_without_list(
                        &history_upgrade,
                        index.claude_reemission_exclusions.state(),
                    );
                    // Count-only attribution of why Claude files were selected
                    // on this page. No path, session, or identifier is named.
                    eprintln!(
                        "local snapshot census claude parse reasons: {} compaction_summary_unlinked_parent={} body_witness_adoption_deferred={} body_witness_adoption_excluded={} body_witness_adoption_held_no_list={} body_witness_adoption_exclusions_invalid={} body_witness_adoption_list={} body_witness_adoption_stop={} body_witness_adoption_stop_withheld_folds={} history_upgrade_owed={} history_upgrade_permitted={} history_emission_denied={} history_listed_literal_roots={} history_reowed={} history_activation_refused={} claude_reemission_family_closure_root_absent_excluded={} identity_incomplete_holds_entered_process_total={} identity_incomplete_holds_cleared_process_total={}",
                        census_count_fields(&CANDIDATE_PARSE_REASON_NAMES, &census.parse_reasons),
                        census.claude_compaction_unlinked_parent_count,
                        history_upgrade.denied_for(&[
                            HistoryHold::UngatedRevision,
                            HistoryHold::ListPaused,
                            HistoryHold::Latched,
                            HistoryHold::Budget,
                        ]),
                        history_upgrade.denied_for(&[HistoryHold::Listed]),
                        history_upgrade
                            .denied_for(&[HistoryHold::NoListBirth, HistoryHold::MoveNotFull]),
                        u8::from(index.claude_reemission_exclusions.is_invalid()),
                        index.claude_reemission_exclusions.status(),
                        claude_reemission_stop_reason(),
                        claude_reemission_stop_withheld_folds(),
                        history_upgrade.owed,
                        history_upgrade.permitted,
                        history_upgrade.denied_summary(),
                        history_upgrade.listed_literal_roots.len(),
                        claude_history_upgrade::local_count(
                            claude_history_upgrade::LocalCount::Reowed
                        ),
                        claude_history_upgrade::local_count(
                            claude_history_upgrade::LocalCount::ActivationRefused
                        ),
                        history_upgrade.family_closure_root_absent_excluded,
                        claude_request_census::identity_incomplete_hold_totals().0,
                        claude_request_census::identity_incomplete_hold_totals().1,
                    );
                    if history_upgrade.family_closure_root_absent_excluded > 0 {
                        crate::local_resource_diagnostics::claude_reemission_family_closure_root_absent_excluded(
                            history_upgrade.family_closure_root_absent_excluded,
                        );
                    }
                }
                // A remove/rename hint can arrive after bounded reconciliation has already
                // passed this key. Removing it only from `observed_index_keys` is then too
                // late: the reconciliation cursor will never revisit the stale entry and a
                // terminal manifest can still publish it. The hint was revalidated as
                // absent beneath the configured root above, so retire the corresponding
                // derived index state directly. Any recreation after this absence witness
                // belongs to the next generation.
                if source == SnapshotSource::Codex {
                    census.removed_index_keys.retain(|key| {
                        index.files.contains_key(key)
                            && !index
                                .traversal
                                .as_ref()
                                .is_some_and(|walk| walk.codex_rollout_paths.contains(key))
                    });
                }
                let account_members = index.observed_account_members();
                let unacked = index.unacked_bodies(census.removed_index_keys.iter());
                let mut tally = (0, 0);
                for index_key in census.removed_index_keys.iter() {
                    if source == SnapshotSource::ClaudeCode
                        && !census.claude_vanished_index_keys.contains(index_key)
                        && sampled_audit::revalidate_growth(index, index_key, &roots, &mut tally)
                    {
                        continue;
                    }
                    if source == SnapshotSource::ClaudeCode
                        && index.claude_account_deferred_holds.contains_key(index_key)
                    {
                        index.retire_absent_account_hold(index_key, &account_members);

                        // Successful retirement is complete; an uncertain
                        // disappearance must not enter the older audit exit.
                        continue;
                    }
                    // F4 or indexed reconciliation may already have retired the
                    // audit entry this page. Its retained incidence is
                    // not a second ordinary file removal (and grants no ACK).
                    if source == SnapshotSource::ClaudeCode && !index.files.contains_key(index_key)
                    {
                        continue;
                    }
                    // Codex records its counting evidence before either exit
                    // below, as terminal reconciliation does; a refusal keeps
                    // the entry whole.
                    if !index
                        .files
                        .get(index_key)
                        .is_some_and(ScanIndexEntry::codex_history_is_protected)
                        && (source != SnapshotSource::Codex
                            || codex_counting_version::tombstone_before_retire(index, index_key))
                    {
                        // A member that vanished beneath its present parent
                        // also drops its unverified audit debt, proven again
                        // here; every other removal keeps that debt. Both
                        // retire its request-census record.
                        let vanished = census.claude_vanished_index_keys.contains(index_key);
                        let census_record =
                            vanished && index.claude_request_census.get(index_key).is_some();
                        if vanished
                            && index
                                .files
                                .get(index_key)
                                .is_some_and(ScanIndexEntry::has_unverified_source)
                            && sampled_audit::proven_absent(Path::new(index_key), &roots)
                            && index.retire_vanished_claude_audit_debt_entry(index_key)
                        {
                            crate::local_resource_diagnostics::audit_retired_absent(
                                source.api_slug(),
                            );
                            disappearance_diagnostics::vanished(
                                source,
                                disappearance_diagnostics::Vanished::AuditDebtDropped,
                            );
                        } else {
                            index.remove_file_entry_unless_held(index_key);
                        }
                        if census_record && index.claude_request_census.get(index_key).is_none() {
                            disappearance_diagnostics::vanished(
                                source,
                                disappearance_diagnostics::Vanished::RequestCensusRemoved,
                            );
                        }
                    }
                }
                crate::local_resource_diagnostics::v2_growth_revalidate(tally);
                index.count_unacked_retired(source, unacked);
                // G1: only census members hold discovery. A pending re-read
                // (growth after this generation processed its path) is
                // next-generation evidence; retiring drops it and the next
                // walk re-reads the file if it is stale.
                let traversal_discovery_done = index.traversal.as_ref().is_some_and(|traversal| {
                    traversal.pending_directories.is_empty()
                        && !traversal
                            .pending_candidates
                            .iter()
                            .any(|candidate| candidate.census_member)
                });
                if traversal_discovery_done {
                    if source == SnapshotSource::Codex {
                        let missing = index
                            .files
                            .iter()
                            .filter(|(key, entry)| {
                                entry.codex_history_is_protected()
                                    && !index
                                        .traversal
                                        .as_ref()
                                        .expect("traversal")
                                        .codex_rollout_paths
                                        .contains(*key)
                            })
                            .map(|(key, _)| key.clone())
                            .collect::<BTreeSet<_>>();
                        if !missing.is_empty() {
                            let traversal = index.traversal.as_mut().expect("traversal");
                            // Quiet ticks reuse this generation's red witness. Count
                            // each absent protected source once, without rearming the
                            // retry latch or rescanning headers before its deadline.
                            let newly_missing =
                                missing.difference(&traversal.residue.index_keys).count();
                            traversal.counts.ownership_incomplete_file_count += newly_missing;
                            traversal
                                .counts
                                .causes
                                .add(ownership::ABSENT, newly_missing);
                            traversal.counts.record_unreadable(
                                UnreadableCause::ProtectedAbsence,
                                usize::from(newly_missing > 0),
                            );
                            traversal.residue.index_keys.extend(missing);
                        }
                    }
                    // Discovery has visited every directory and parsed every candidate,
                    // so the counts are the complete re-derivation for this generation.
                    // Loss that only a change to the corpus can move is settled now, so a
                    // machine whose only problem is an unresolvable rollout still reaches
                    // a terminal census instead of retrying the same bytes forever with
                    // every downstream gate (historical backfill, the legacy settlement
                    // sweep, the terminal manifest) held behind it. Retryable problems
                    // veto the settlement inside the helper.
                    if let Some(traversal) = index.traversal.as_mut() {
                        traversal.counts.settle_non_progressing_residue();
                    }
                }
                if let Some(traversal) = index.traversal.as_mut() {
                    traversal.counts.caps.drain(source.api_slug());
                }
                let traversal_snapshot = index
                    .traversal
                    .as_ref()
                    .cloned()
                    .expect("traversal remains active");
                let traversal_healthy = !traversal_snapshot.counts.has_errors();
                let clean_frozen_generation = !traversal_snapshot.watcher_hint_seen;
                // Count-only per-family completion, from the page's
                // settled state before any terminal effect. Acts on nothing.
                if source == SnapshotSource::ClaudeCode {
                    claude_family_census_shadow::observe_page(
                        index,
                        &claude_family_shadow,
                        &pending_finalization,
                        &census,
                        &sampling,
                        audit_now,
                    );
                }
                let reconciliation_complete = if traversal_discovery_done
                    && traversal_healthy
                    && clean_frozen_generation
                    && state_census_complete
                    && sidecar_census_complete
                {
                    reconcile_missing_index_entries_bounded(index, source)
                } else {
                    false
                };
                // Vanished paths are retired from `files` just above - by exact watcher
                // remove/rename hints and by bounded census reconciliation. Terminal
                // dispositions are keyed identically, so retire their orphans in the same
                // place instead of carrying a renamed or deleted file's record forever.
                // This keeps the map a subset of `files`, which is the whole bound it
                // needs.
                index.prune_terminal_jsonl_dispositions();
                // Retirements on this page can already have a moved header in
                // the inventory, even while that file's parse is deferred.
                if let Some(inventory) = codex_join_inventory.as_ref() {
                    codex_counting_version::note_inventory_created(index, inventory);
                }
                let raw_census_complete = traversal_discovery_done
                    && traversal_healthy
                    && clean_frozen_generation
                    && state_census_complete
                    && sidecar_census_complete
                    && reconciliation_complete;
                let needs_clean_followup =
                    raw_census_complete && index.bounded_sweep_had_unsettled_upload;
                // Path-(a) bridge: RetryPending authority debt no longer marks
                // the sweep, but it still withholds the ordinary census (and so
                // its complete fold and upload-context adoption), as the mark
                // did. It owes no clean follow-up of its own.
                let authority_debt_withholds_census = raw_census_complete
                    && source == SnapshotSource::ClaudeCode
                    && index.claude_usage_authority_pending_count() > 0;
                let census_complete = raw_census_complete
                    && !needs_clean_followup
                    && !authority_debt_withholds_census;
                // Prune and measure only, before any fold.
                let claude_request_census_shadow =
                    (source == SnapshotSource::ClaudeCode && census_complete).then(|| {
                        claude_request_census::settle_claude_request_census_terminal(
                            index,
                            &traversal_snapshot.residue.index_keys,
                            &census_window_end,
                        )
                    });
                let reconciliation_pending = traversal_discovery_done
                    && traversal_healthy
                    && clean_frozen_generation
                    && state_census_complete
                    && sidecar_census_complete
                    && !reconciliation_complete;
                let pending_work_count = index
                    .traversal
                    .as_ref()
                    .map(|traversal| {
                        traversal
                            .pending_candidates
                            .len()
                            .saturating_add(traversal.pending_directories.len())
                            .saturating_add(usize::from(reconciliation_pending))
                    })
                    .unwrap_or_default();
                let skipped_file_count_due_to_limit =
                    claude_family_census_shadow::skipped_view(index).count();
                let restart_after_hints =
                    traversal_discovery_done && traversal_healthy && !clean_frozen_generation;
                let terminal_unhealthy = traversal_discovery_done && !traversal_healthy;
                if terminal_unhealthy {
                    let now = rfc3339_unix_seconds(collected_at.as_str()).unwrap_or_default();
                    let traversal = index.traversal.as_mut().expect("traversal remains active");
                    if traversal.unhealthy_retry_not_before_unix_seconds.is_none() {
                        let previous_attempt = traversal.unhealthy_retry_attempt;
                        // The counter saturates at the attempt whose delay is already the
                        // hourly ceiling. A persistent problem therefore costs at most one
                        // bounded re-walk per hour and the persisted witness stays small.
                        traversal.unhealthy_retry_attempt = previous_attempt
                            .saturating_add(1)
                            .min(UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS);
                        traversal.unhealthy_retry_not_before_unix_seconds =
                            Some(now.saturating_add(unhealthy_scan_retry_delay_seconds(
                                traversal.unhealthy_retry_attempt,
                            )));
                        if previous_attempt < UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                            && traversal.unhealthy_retry_attempt
                                == UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                        {
                            eprintln!(
                    "ottto-service: bounded scan retry for {} reached attempt {}; the traversal \
                     stays a durable red witness and is re-walked at most hourly until the \
                     problem clears or the scan context changes",
                    source.api_slug(),
                    UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                );
                        }
                    }
                }
                let pending_work_count = pending_work_count
                    .saturating_add(usize::from(restart_after_hints))
                    .saturating_add(usize::from(terminal_unhealthy))
                    .saturating_add(usize::from(needs_clean_followup));
                let traversal = index.traversal.as_ref().expect("traversal remains active");
                let loaders = &codex_title_metadata.local_diagnostics;
                let census_status = CensusStatus {
                    pending_work: !traversal.pending_directories.is_empty()
                        || !traversal.pending_candidates.is_empty(),
                    retryable_problem: traversal.counts.has_retryable_problems(),
                    transport_reservation_refused: index
                        .context_read_counts
                        .transport_reservation_refused,
                    // Completeness also falls on identity conflicts: require
                    // an actual failed loader (#985), not just a false gate.
                    state_loader_failed: source == SnapshotSource::Codex
                        && (!state_census_complete || !sidecar_census_complete)
                        && [
                            loaders.state_titles.failed_roots,
                            loaders.state_threads.failed_roots,
                            loaders.spawn_edges.failed_roots,
                            loaders.rollout_extents.failed_roots,
                            loaders.session_index.failed_roots,
                        ]
                        .into_iter()
                        .any(|failed| failed > 0),
                    reconciliation_incomplete: !reconciliation_complete,
                    retry_attempt: traversal.unhealthy_retry_attempt,
                    retry_not_before_unix_seconds: traversal
                        .unhealthy_retry_not_before_unix_seconds,
                };
                if raw_census_complete {
                    index.record_scan_residue_witness(source, &traversal_snapshot);
                }
                let mut carried_next_generation = Vec::new();
                if (raw_census_complete
                    && codex_legacy_join_baselines.is_empty()
                    && !pending_finalization.iter().any(|pending| {
                        index.files.get(&pending.index_key).is_some_and(|entry| {
                            entry.codex_applied_tier_receipt.is_some()
                                || entry.codex_joined_member_set.is_some()
                        })
                    }))
                    || restart_after_hints
                {
                    traversal_transition::retiring(
                        source,
                        index.generation,
                        &traversal_snapshot,
                        raw_census_complete,
                        index.unsettled_cause_bits(),
                        CensusGates {
                            discovery_done: traversal_discovery_done,
                            traversal_healthy,
                            frozen_generation: clean_frozen_generation,
                            state_complete: state_census_complete,
                            sidecar_complete: sidecar_census_complete,
                            reconciliation_complete,

                            clean_followup: needs_clean_followup,
                            census_complete,
                        },
                    );
                    // G1 carry: the closing generation's waiting re-reads
                    // (watcher hints, budget-deferred re-reads, growth past
                    // its window end) are next-generation evidence. Hand them
                    // to the next generation as members rather than dropping
                    // them; they never re-enter the generation closing here.
                    carried_next_generation = index
                        .traversal
                        .as_ref()
                        .filter(|_| source == SnapshotSource::Codex)
                        .map_or_else(Vec::new, |traversal| {
                            traversal
                                .pending_candidates
                                .iter()
                                .filter(|candidate| !candidate.census_member)
                                .map(|candidate| candidate.path.clone())
                                .collect::<Vec<_>>()
                        });
                    index.traversal = None;
                    index.resume_after_path = None;
                    index.resume_upper_bound_path = None;
                    index.resume_census_window_end = None;
                }
                let counts = traversal_snapshot.counts;
                let zero_snapshot_confirmed_count = index.confirmed_empty_files.len();
                let zero_snapshot_usage_evidence_count = counts.zero_snapshot_usage_evidence_count;
                let dropped_usage_record_count = counts.dropped_usage_record_count;
                // The witness just recorded above describes THIS generation only when the
                // generation completed; otherwise the durable one is an earlier census's
                // and must not be reported as this scan's evidence. Counts only: the
                // witness's index keys never leave the local index.
                let (census_residue_index_key_count, census_residue_archived_rollout_count) =
                    if raw_census_complete {
                        index
                            .scan_residue_witness
                            .as_ref()
                            .map(|witness| {
                                (
                                    witness.index_keys.len(),
                                    witness.archived_residue_file_count(),
                                )
                            })
                            .unwrap_or_default()
                    } else {
                        (0, 0)
                    };
                // Full context-curve upload is retired: a restored old curve
                // never leaves the Mac.
                for snapshot in &mut snapshots {
                    snapshot.context_curve = None;
                }
                index.preserve_decode_held_files(source, &snapshots, &mut pending_finalization);
                snapshots.retain(|item| !index.decode_holds_snapshot(source, item));
                let census_complete = census_complete && index.decode_holds.is_empty();
                if census_complete {
                    // Only a healthy EFFECTIVE terminal can prove a
                    // carried file gone. A raw terminal, another file's census,
                    // or an unknown original association cannot retire its ACKs.
                    index.accepted_rebuild_incidence.retain(|key, _| {
                        key.is_empty()
                            || traversal_snapshot.observed_index_keys.contains(key)
                            || traversal_snapshot.residue.index_keys.contains(key)
                            || index.files.contains_key(key)
                    });
                    index.accepted_incidence_pending_census =
                        !index.accepted_rebuild_incidence.is_empty();
                    // A4d: the same proof retires a Tail whose file is gone.
                    #[cfg(unix)]
                    tail_source::load::retire_absent(
                        source,
                        index,
                        &traversal_snapshot.observed_index_keys,
                        &traversal_snapshot.residue.index_keys,
                    );
                }
                if !index.decode_holds.is_empty() {
                    index.mark_bounded_sweep_unsettled();
                }
                // Only a settled close starts the next generation in this
                // page. A partially settled sweep (including a decode hold
                // just marked) keeps its marker for the clean follow-up the
                // next page starts, and that walk re-reads the stale files.
                if !carried_next_generation.is_empty() && !index.bounded_sweep_had_unsettled_upload
                {
                    ensure_bounded_traversal(
                        source,
                        &roots,
                        index,
                        &collected_at,
                        backfill_window_days,
                    );
                    if let Some(next) = index.traversal.as_mut() {
                        enqueue_watcher_hints(source, next, &carried_next_generation, false);
                    }
                }
                let mut local_diagnostics = codex_title_metadata.local_diagnostics;
                if source == SnapshotSource::Codex {
                    let cutoff = codex_turn_traces
                        .as_ref()
                        .map_or(0, |traces| traces.since_epoch as u64);
                    local_diagnostics.price_tier_old_files_without_receipt = index
                        .file_snapshot_fingerprints
                        .iter()
                        .filter(|(key, fingerprints)| {
                            index
                                .files
                                .get(*key)
                                .is_some_and(|entry| entry.codex_applied_tier_receipt.is_none())
                                && !fingerprints.is_empty()
                                && fingerprints.iter().all(|fingerprint| {
                                    index
                                        .snapshot_activity_at
                                        .get(fingerprint)
                                        .and_then(Option::as_deref)
                                        .and_then(rfc3339_unix_seconds)
                                        .is_some_and(|activity| activity < cutoff)
                                })
                        })
                        .count()
                        as u64;
                }
                let continuation_evidence = (codex_join_completed.is_empty()
                    && continuation_ticket.is_some())
                .then(|| codex_join_inventory.take())
                .flatten()
                .filter(|inventory| inventory.complete)
                .map(|inventory| CodexContinuationEvidence {
                    inventory,
                    codex: codex_title_metadata,
                    traces: codex_turn_traces,
                });
                if continuation_ticket.is_some() && continuation_evidence.is_none() {
                    crate::local_resource_diagnostics::codex_continuation_mint(
                        if codex_join_completed.is_empty() {
                            "inventory_incomplete"
                        } else {
                            "groups_completed"
                        },
                    );
                }
                if source == SnapshotSource::Codex {
                    crate::local_resource_diagnostics::codex_zst_refused_flush();
                }
                let continuation_evidence = continuation_evidence
                    .zip(continuation_ticket.as_ref())
                    .and_then(|(evidence, ticket)| {
                        evidence.for_paused_job(
                            sampling.as_ref().map(|context| context.cache.as_ref()),
                            ticket,
                        )
                    });
                let codex_join_validation = codex_join_inventory.and_then(|inventory| {
                    let surviving: BTreeSet<_> = pending_finalization
                        .iter()
                        .filter_map(|pending| {
                            inventory.owner_for_path(Path::new(&pending.index_key))
                        })
                        .map(str::to_owned)
                        .collect();
                    (!surviving.is_empty()).then(|| {
                        codex_file_join::Validation::new(
                            inventory,
                            codex_join_completed,
                            &surviving,
                            traversal_snapshot.codex_rollout_paths,
                        )
                    })
                });
                let scan = SourceScanResult {
                    census_status,
                    claude_queued_family_deferred_paths: std::mem::take(
                        &mut history_upgrade.queued_family_deferred_paths,
                    ),
                    discovery_growth: std::mem::take(&mut resource_probe.discovery_growth),
                    source,
                    backfill_window_days,
                    backfill_file_limit: file_limit,
                    discovered_file_count,
                    skipped_file_count_due_to_limit,
                    scan_cap_hit: pending_work_count > 0,
                    scanned_file_count,
                    scanned_session_count,
                    semantic_noop_count,
                    census_complete,
                    census_window_end,
                    state_census_complete,
                    sidecar_census_complete,
                    symlink_rejected_count: counts.symlink_rejected_count,
                    directory_entry_cap_exceeded_count: counts.directory_entry_cap_exceeded_count,
                    unreadable_path_count: counts.unreadable_path_count,
                    oversized_file_count: counts.oversized_file_count,
                    disappeared_file_count: counts.disappeared_file_count,
                    malformed_json_line_count: counts.malformed_json_line_count,
                    invalid_utf8_line_count: counts.invalid_utf8_line_count,
                    over_line_cap_count: counts.over_line_cap_count,
                    recognized_usage_drop_count: counts.recognized_usage_drop_count,
                    ownership_incomplete_file_count: counts.ownership_incomplete_file_count,
                    causes: counts.causes,
                    zero_snapshot_confirmed_count,
                    zero_snapshot_usage_evidence_count,
                    dropped_usage_record_count,
                    terminal_ownership_incomplete_file_count: counts
                        .terminal_ownership_incomplete_file_count,
                    terminal_zero_snapshot_usage_evidence_count: counts
                        .terminal_zero_snapshot_usage_evidence_count,
                    terminal_recognized_usage_drop_count: counts
                        .terminal_recognized_usage_drop_count,
                    terminal_dropped_usage_record_count: counts.terminal_dropped_usage_record_count,
                    terminal_over_line_cap_count: counts.terminal_over_line_cap_count,
                    census_residue_index_key_count,
                    census_residue_archived_rollout_count,
                    snapshots,
                    pending_finalization,
                    codex_legacy_join_baselines,
                    claude_request_census_shadow,
                    continuation_ticket,
                    continuation_evidence: continuation_evidence
                        .map(|e| Arc::new(Mutex::new(Some(e)))),
                    codex_join_validation,
                    // Moved, not copied: the box was charged with the census.
                    codex_counting_v2: if source == SnapshotSource::Codex {
                        codex_counting_version::take_local_receipts(
                            index,
                            census.codex_counting_v2.take(),
                        )
                    } else {
                        census.codex_counting_v2.take()
                    },
                    local_codex_diagnostics: (source == SnapshotSource::Codex).then_some(
                        CodexScanDiagnostics {
                            version: 1,
                            generation: index.generation,
                            unreadable_causes: counts.unreadable_causes,
                            // PR-P: traversal-cumulative per-page counts, as
                            // `unreadable_causes`.
                            gates: CensusGates {
                                discovery_done: traversal_discovery_done,
                                traversal_healthy,
                                frozen_generation: clean_frozen_generation,
                                state_complete: state_census_complete,
                                sidecar_complete: sidecar_census_complete,
                                reconciliation_complete,

                                clean_followup: needs_clean_followup,
                                census_complete,
                            },
                            ..local_diagnostics
                        },
                    ),
                };
                if source == SnapshotSource::ClaudeCode {
                    rearm_cause::retain(index);
                }
                let sampled_acquisition = sampling.as_ref().map(|context| {
                    let audit_now = sampled_scan::now_seconds();
                    let pending = index
                        .files
                        .values()
                        .filter(|entry| entry.has_unverified_source())
                        .count();
                    let overdue = index
                        .files
                        .values()
                        .filter(|entry| entry.audit_requires_full(audit_now))
                        .count();
                    let oldest_due_age = index
                        .files
                        .values()
                        .filter_map(|entry| entry.audit_obligation(audit_now))
                        .map(|debt| audit_now.saturating_sub(debt.due_unix_seconds))
                        .max()
                        .unwrap_or(0);
                    if context.audit_cap_full > 0 {
                        crate::local_resource_diagnostics::traversal_point("sampled_audit_cap_alarm", source.api_slug(),
                            &serde_json::json!({"audit_cap_full": context.audit_cap_full, "pending_audits": pending}));
                    }
                    if context.audit_cap_delay > 0 {
                        crate::local_resource_diagnostics::traversal_point("sampled_audit_cap_delay", source.api_slug(),
                            &serde_json::json!({"audit_cap_delay": context.audit_cap_delay}));
                    }
                    if context.pace_evicted > 0 {
                        crate::local_resource_diagnostics::traversal_point("sampled_audit_pace_alarm", source.api_slug(),
                            &serde_json::json!({"pace_evicted": context.pace_evicted}));
                    }
                    crate::local_resource_diagnostics::ReadCounts {
                        full_selections: context.full_files,
                        tail_selections: context.tail_files,
                        unchanged_selections: context.unchanged_files,
                        completed_native_bytes: context.native_bytes,
                        completed_full_native_bytes: context.full_native_bytes,
                        completed_guard_bytes: context.sample_bytes,
                        acquisition_admission: context.admission,
                        page_events: crate::local_resource_diagnostics::PageEvents {
                            full_cause: resource_probe.rearm_fulls(),
                            full_by_parse_reason: resource_probe.full_by_parse_reason(),
                            full_reasons: crate::local_resource_diagnostics::FullReasons(
                                context.full_reasons,
                            ),
                            priority_full_replays: context.priority_replays,
                            audits_started: context.audits_started,
                            audits_completed: context.audits_completed,
                            max_start_overdue_seconds: context.start_overdue_seconds,
                            max_completion_overdue_seconds: context.completion_overdue_seconds,
                        },
                        index_state_at_page_end: crate::local_resource_diagnostics::IndexState {
                            audit_quiet_retired: context.audit_quiet_retired,
                            audit_cap_full: context.audit_cap_full,
                            pending_audits: pending,
                            overdue_audits: overdue,
                            oldest_due_age_seconds: oldest_due_age,
                        },
                        codex_cursor: context.cache.cursor_diagnostics(&codex_page),
                    }
                });
                if sampled_acquisition.is_some() {
                    crate::local_resource_diagnostics::cache_lifecycle_totals();
                    crate::local_resource_diagnostics::codex_memo_lifecycle_totals(
                        source.api_slug(),
                    );
                }
                if let Some(delivery) = line_delivery.as_mut() {
                    if active_file.is_none() {
                        delivery.left_active();
                    }
                    resource_probe.line_delivery = Some(delivery.take_page());
                }
                let full_causes = std::mem::take(&mut resource_probe.full_causes);
                resource_probe.collection(
                    source.api_slug(),
                    crate::local_resource_diagnostics::CollectionCounts {
                        scanned_files: scanned_file_count,
                        semantic_noops: semantic_noop_count,
                        sampled_acquisition,
                        full_causes,
                    },
                );
                return Ok(OwnedSourceScanStep::Complete {
                    index: index_storage,
                    scan,
                });
            };
            // Reject budget debt before opening/constructing any body parser.
            // Requeue the original census membership; absence/completion stays owed.
            if index.context_only_read(&candidate)
                && !context_read_budget.admit(source, index, &candidate, &snapshots)
            {
                context_read_budget.defer(candidate);
                pending!();
            }
            if let Some(context) = sampling
                .as_ref()
                .filter(|_| source == SnapshotSource::Codex)
            {
                if context
                    .cache
                    .cursor_job_owns(&local_index_key(&candidate.path))
                {
                    // The paused or active cursor job owns this file (a group
                    // job owns every member); it stays pending (holding the
                    // census) until that job's attempt ends (§d.1.2 c).
                    sampled_scan::codex_cursor::requeue(index, &codex_selected_flags, &candidate);
                    pending!();
                }
            }
            let preflight_source_file_fingerprint =
                claude_authority_preflight_fingerprint(index, &candidate);
            if let Some(events) = launch_lookup {
                let workers =
                    launch_workers_for_candidate(source, &candidate, codex_join_inventory.as_ref());
                match events.prepare_step(&workers) {
                    Ok(false) => {
                        identified_candidates.push_front(candidate);
                        pending!();
                    }
                    Err(()) => {
                        census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                        pending!();
                    }
                    Ok(true) => {}
                }
            }
            // Keep the prepass physical identity intact while lookup yields. Only
            // replace it with sidecar inputs immediately before the second open.
            prepare_owned_scan_candidate(
                source,
                &mut candidate,
                &codex_title_metadata,
                &claude_title_metadata,
                claude_effort_support_dir_ref,
            );
            let unchanged = if source == SnapshotSource::Codex {
                match index.codex_unchanged_decision(
                    &mut candidate,
                    &codex_title_metadata,
                    audit_now,
                    true,
                ) {
                    Ok(input) => input,
                    Err(_) => {
                        sampled_scan::codex_cursor::requeue(
                            index,
                            &codex_selected_flags,
                            &candidate,
                        );
                        pending!();
                    }
                }
            } else {
                None
            };
            let logical_decision = unchanged
                .as_ref()
                .map(|(_, decision, reason)| (*decision, *reason));
            let acquired = match unchanged {
                Some((file, _, _)) => Some((candidate, file)),
                None => open_and_identify_scan_candidate_with_rescue_at(
                    source,
                    candidate,
                    &mut census,
                    CandidateWindow {
                        census_unix_seconds,
                        backfill_window_days,
                        retention: discovery_retention!(index, &resource_probe.discovery_growth),
                        growth: sampled_audit::growth_active(index)
                            .then_some(&index.v2().growth_retention),
                    },
                    sampling.as_ref().map(|context| context.cache.as_ref()),
                ),
            };
            let Some((mut candidate, opened_file)) = acquired else {
                pending!();
            };
            if preflight_source_file_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| fingerprint != &candidate.source_file_fingerprint)
            {
                // A quarantined candidate changed after the family prepass. Do not
                // parse a mixed family or refresh its retry record; keep this
                // generation non-terminal and retry the new exact object together.
                disappearance_diagnostics::increment(
                    &mut census.disappeared_file_count,
                    source,
                    disappearance_diagnostics::Cause::PreflightFingerprintChanged,
                );
                pending!();
            }
            // The preflight fences physical/sidecar identity. Local launcher facts
            // are semantic context and must not contaminate that two-open witness.
            if let Some(events) = launch_lookup.filter(|_| logical_decision.is_none()) {
                let workers =
                    launch_workers_for_candidate(source, &candidate, codex_join_inventory.as_ref());
                if let Some(witness) = events.witness(&workers) {
                    candidate.source_file_fingerprint = sha256_hex(&[
                        "launcher_worker_context:v1",
                        &candidate.source_file_fingerprint,
                        &witness,
                    ]);
                }
            }
            // Constructor preflight has only physical identities. Reconcile its
            // family retry decision once launcher context is prepared, while keeping
            // the two-open equality check above physical. Every family member must
            // match the retained revision before withdrawing a forced retry.
            if source == SnapshotSource::ClaudeCode {
                if let Some(events) = launch_lookup {
                    if let Some((root, _)) = claude_index_path_family_member(&candidate.path) {
                        if forced_claude_family_reparses.contains(&root)
                            && claude_held_family_matches_launch_context(
                                index,
                                &root,
                                &candidate,
                                &identified_candidates,
                                events,
                            )
                        {
                            forced_claude_family_reparses.remove(&root);
                        }
                    }
                }
            }
            if index.decode_holds_file(&local_index_key(&candidate.path)) {
                index.mark_bounded_sweep_unsettled();
                pending!();
            }
            let mut source_change = None;
            let (mut decision, mut parse_reason) = match claude_index_path_family_member(
                &candidate.path,
            )
            .filter(|(root_session_id, _)| forced_claude_family_reparses.contains(root_session_id))
            {
                // A twin-only forced member that owes only adoption keeps that
                // reason, so the history gate can hold the whole twin group.
                Some((root_session_id, _))
                    if claude_twin_only_family_reparses.contains(&root_session_id)
                        && index.candidate_decision_with_reason_at(&candidate, audit_now)
                            == (
                                CandidateDecision::Parse,
                                Some(CandidateParseReason::BodyWitnessAdoption),
                            ) =>
                {
                    (
                        CandidateDecision::Parse,
                        Some(CandidateParseReason::BodyWitnessAdoption),
                    )
                }
                Some(_) => (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::ForcedFamily),
                ),
                // Use the same audit clock as slot preparation.
                None => {
                    index.candidate_decision_in_window(&candidate, audit_now, &mut source_change)
                }
            };
            if let Some((logical, reason)) = logical_decision {
                decision = logical;
                parse_reason = reason;
            }
            // History-upgrade gate, whatever selected the file:
            // unchanged Claude history that would carry a new body-witness
            // revision passes the list, the no-list birth hold, the family
            // skip, the stop latch and this page's budget (reserved once per
            // file). A held file that only owes the upgrade is skipped with
            // its old stamp, and so is one that also owes only its upload
            // context. A held file selected for another reason (re-arm,
            // family, audit, authority, a rebuilt or replayed index) still
            // parses for its local work, but none of its bodies
            // is emitted and its upload tuple stays (`veto_claude_history_emission`).
            // A skipped Claude file held only by this page's budget is queued
            // again as a re-read for the next page of the walk. Codex and Pi
            // keep the adoption-only page budget.
            if decision == CandidateDecision::Parse {
                let adoption_only = parse_reason == Some(CandidateParseReason::BodyWitnessAdoption)
                    && (index.candidate_requires_only_body_witness_adoption(&candidate, audit_now)
                        || (source == SnapshotSource::ClaudeCode
                            && claude_copy_prefix_reread::unchanged_requested(
                                index, &candidate, audit_now,
                            )));
                let history = if source == SnapshotSource::ClaudeCode {
                    index.claude_history_upgrade_decision(
                        &candidate,
                        opened_file
                            .metadata()
                            .and_then(|metadata| metadata.created())
                            .ok()
                            .and_then(unix_seconds),
                        &mut history_upgrade,
                    )
                } else if adoption_only
                    && !history_upgrade.reserve_admitting_first_file(
                        &local_index_key(&candidate.path),
                        candidate.size_bytes,
                    )
                {
                    history_upgrade.note_denied(
                        HistoryHold::Budget,
                        index.claude_reemission_exclusions.state(),
                    );
                    HistoryDecision::Held(HistoryHold::Budget)
                } else {
                    HistoryDecision::NotOwed
                };
                // A held, unchanged member owed only a proof correction is not
                // re-read every traversal either: its bodies would be vetoed,
                // and the correction waits for the gate (StateMissing).
                let correction_only = parse_reason
                    == Some(CandidateParseReason::AuthorityQuarantine)
                    && index.claude_authority_correction_only(&candidate);
                // A listed genuine change is never held (it is literal-only
                // denied), so a held correction-only member is unchanged.
                match history {
                    HistoryDecision::Held(hold) if adoption_only || correction_only => {
                        if source == SnapshotSource::ClaudeCode {
                            let carried = index
                                .accepted_rebuild_incidence
                                .get(&local_index_key(&candidate.path))
                                .map_or(0, BTreeSet::len);
                            index.claude_history_emission.skipped_carried_entries = index
                                .claude_history_emission
                                .skipped_carried_entries
                                .saturating_add(carried);
                            // A budget hold paces the upgrade page by page:
                            // the file goes back to the walk's queue as a
                            // re-read, so the next page of this walk continues
                            // the upgrade (the switch-on
                            // re-read). A re-read is not a census member
                            // (G1): it never holds the census, and a walk
                            // that ends first drops it for the next walk to
                            // list again. Only once this page admitted
                            // history: a file that cannot fit an empty page
                            // waits for the next walk as before.
                            if hold == HistoryHold::Budget && history_upgrade.admitted_any() {
                                if let Some(traversal) = index.traversal.as_mut() {
                                    traversal.pending_candidates.push_back(ScanTraversalPath {
                                        scan_root: candidate.scan_root.clone(),
                                        path: candidate.path.clone(),
                                        census_member: false,
                                        watcher_hint: false,
                                    });
                                }
                            }
                        }
                        decision = CandidateDecision::Skip;
                    }
                    HistoryDecision::Held(hold) => {
                        index.gate_claude_history_candidate(&candidate, Some(hold));
                    }
                    HistoryDecision::Owed => index.gate_claude_history_candidate(&candidate, None),
                    HistoryDecision::LiteralDenied => {
                        index.deny_claude_history_literal(&candidate);
                    }
                    HistoryDecision::NotOwed => {}
                }
            }
            // A file whose Tail failed alone is selected by its set-aside
            // marker before an ordinary Skip, even with equal stamps, and
            // re-reads from its committed head.
            #[cfg(unix)]
            if decision == CandidateDecision::Skip
                && matches!(state_v2::tail_route_path(index), Ok(Some(_)))
                && tail_source::load::set_aside(index, &local_index_key(&candidate.path))
            {
                decision = CandidateDecision::Parse;
            }
            let stale_input_held = index.stale_refusal_holds_unchanged_input(&candidate);
            if stale_input_held {
                decision = CandidateDecision::Skip;
                parse_reason = None;
            }
            if source == SnapshotSource::ClaudeCode && decision == CandidateDecision::Parse {
                if let Some(reason) = parse_reason {
                    let count = &mut census.parse_reasons[reason as usize];
                    *count = count.saturating_add(1);
                }
            }
            index.note_reason_reoffer_cooldown_candidate(
                &candidate,
                decision == CandidateDecision::Skip && parse_reason.is_none(),
            );
            if source == SnapshotSource::Codex {
                census.note_codex_selection(decision, parse_reason, None);
            }
            match decision {
                CandidateDecision::Skip => {
                    page_selection(source.api_slug(), PageSelection::Skipped, 1);
                    if let Some(loss) = index.terminal_jsonl_loss(&candidate) {
                        census.add_terminal_jsonl_loss(loss);
                    }
                    // The ordinary equality Skip attests this revision
                    // for the shadow family census. Counts only.
                    if source == SnapshotSource::ClaudeCode && parse_reason.is_none() {
                        claude_family_census_shadow::attest_equality_skip(
                            index, &candidate, &sampling, audit_now,
                        );
                    }
                    pending!();
                }
                CandidateDecision::Migrate => {
                    index.migrate(candidate);
                    pending!();
                }
                CandidateDecision::ReconcileLegacy | CandidateDecision::Parse => {}
            }
            #[cfg(test)]
            sampled_scan::test_hooks::after_selection(index, parse_reason);
            if let Some(context) = sampling
                .as_ref()
                .filter(|_| source == SnapshotSource::Codex && !codex_archive_path(&candidate.path))
            {
                let wake_stamp = sampled_scan::codex_cursor::OpenStamp::capture(&opened_file)
                    .ok()
                    .map(|stamp| context.cache.retained_stamp(&candidate.path, stamp));
                let key = local_index_key(&candidate.path);
                // Keyed per namespace: the digest carries the upload
                // context, so concurrent namespaces must not evict each other.
                let memo_key = sampled_scan::codex_cursor::memo_key(&context.namespace, &key);
                use crate::local_resource_diagnostics::codex_memo_lifecycle;
                if let Some(entry) = context.cache.memo_lookup(&memo_key) {
                    // The match re-reads two samples of the held file.
                    codex_page.charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                    let sidecar_now = sampled_scan::codex_cursor::sidecar_fingerprint(
                        &codex_title_metadata,
                        &candidate.path,
                    );
                    let digest = sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )
                    .and_then(|dependencies| {
                        sampled_scan::codex_cursor::memo_digest(
                            index,
                            &candidate,
                            &opened_file,
                            &dependencies,
                            &codex_title_metadata,
                            sampled_scan::codex_cursor::owner_members(
                                codex_join_inventory.as_ref(),
                                &candidate.path,
                            ),
                            &sampled_scan::codex_cursor::counting_view(&candidate, index),
                        )
                    });
                    let hit = digest.as_deref().and_then(|digest| {
                        entry.matches_stamp(
                            &candidate.path,
                            digest,
                            &opened_file,
                            &sidecar_now,
                            wake_stamp.clone()?,
                        )
                    });
                    if let Some(stamp) = hit {
                        // An append cannot cure this hold and no wake
                        // dependency changed: disclose the same terminal
                        // debt again at zero transcript bytes.
                        codex_memo_lifecycle::add(
                            codex_memo_lifecycle::Event::HitEstimatedAvoidedParserBytes,
                            stamp.extent(),
                        );
                        context.cache.memo_hit(&memo_key, stamp);
                        let keep_previous = decision != CandidateDecision::ReconcileLegacy
                            && !index
                                .effective_upload_body_witness_revision_requires_adoption(&key);
                        let previous = (
                            keep_previous
                                .then(|| index.last_snapshot_fingerprint(&candidate))
                                .flatten(),
                            keep_previous
                                .then(|| index.last_upload_body_witness(&candidate))
                                .flatten(),
                        );
                        sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                            entry.disclosure(),
                            &candidate,
                            previous,
                            index,
                            targets!(),
                        );
                        // The fresh path's session count, replayed.
                        scanned_session_count += entry.disclosure().parsed_snapshot_count;
                        pending!();
                    }
                    match digest.as_deref().and_then(|digest| {
                        entry.grew_past_exact(&candidate.path, digest, &opened_file, &sidecar_now)
                    }) {
                        Some(extent) => {
                            codex_memo_lifecycle::record(
                                codex_memo_lifecycle::Event::MissExactStamp,
                            );
                            codex_memo_lifecycle::add(
                                codex_memo_lifecycle::Event::MissExactStampBytes,
                                extent,
                            );
                        }
                        None => {
                            codex_memo_lifecycle::record(codex_memo_lifecycle::Event::MissOther)
                        }
                    }
                    context.cache.memo_forget(&memo_key);
                }
                // A parked `JoinStateBound` file is not read again until it
                // is replaced, shrunk or edited, or its reduction dependencies
                // change; growth cannot cure it (§c.2, M-2).
                let parked = context.cache.cursor_parked_stamp(
                    &key,
                    wake_stamp.clone(),
                    sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )
                    .as_deref(),
                );
                if let Some(disclosure) = parked {
                    let keep_previous = decision != CandidateDecision::ReconcileLegacy
                        && !index.effective_upload_body_witness_revision_requires_adoption(&key);
                    let previous = (
                        keep_previous
                            .then(|| index.last_snapshot_fingerprint(&candidate))
                            .flatten(),
                        keep_previous
                            .then(|| index.last_upload_body_witness(&candidate))
                            .flatten(),
                    );
                    sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                        &disclosure,
                        &candidate,
                        previous,
                        index,
                        targets!(),
                    );
                    pending!();
                }
                #[cfg(test)]
                CODEX_BEFORE_PARSE.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().as_mut() {
                        hook(&candidate.path);
                    }
                });
                // Fresh-first page budget, decided before any stored state is
                // consumed: the optimistic read is the tail extent when a
                // continuation exists, the whole file otherwise. The
                // continuation is the committed head on its route, so an
                // append is sized from the head's sealed offset.
                let extent = opened_file.metadata().map_or(0, |metadata| metadata.len());
                let continued = tail_source::committed_sealed_offset(source, index, &key);
                let expected = extent.saturating_sub(continued.unwrap_or(0));
                if index.context_only_read(&candidate) {
                    context_read_budget.charge_cursor_ordinary(&mut codex_page);
                }
                match context.cache.cursor_plan_paced(
                    &mut codex_page,
                    sampled_scan::codex_cursor::Limits::current(),
                    expected,
                    codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                    crate::heap_layout_bound::layout_supported(),
                    &context.namespace,
                    &key,
                    sampled_scan::codex_cursor::census_token(index).as_deref(),
                    sampled_scan::codex_cursor::census_member(
                        &codex_selected_flags,
                        [candidate.path.as_path()],
                    ),
                    Some(sampled_scan::codex_cursor::PaceProbe { file: &opened_file }),
                ) {
                    sampled_scan::codex_cursor::StartPlan::Defer => {
                        context.cache.cursor_note_deferred();
                        sampled_scan::codex_cursor::requeue(
                            index,
                            &codex_selected_flags,
                            &candidate,
                        );
                        pending!();
                    }
                    // Processed for this generation (K7 fence): not requeued,
                    // so the census can complete; the next generation reads it.
                    sampled_scan::codex_cursor::StartPlan::Fenced => pending!(),
                    sampled_scan::codex_cursor::StartPlan::Singleton
                    | sampled_scan::codex_cursor::StartPlan::Cursor
                    | sampled_scan::codex_cursor::StartPlan::Unpaged => {}
                }
            }
            scanned_file_count += 1;
            let previous_snapshot_fingerprint = index.last_snapshot_fingerprint(&candidate);
            let previous_upload_body_witness = index.last_upload_body_witness(&candidate);
            let projection_adoption_required = index
                .effective_upload_body_witness_revision_requires_adoption(&local_index_key(
                    &candidate.path,
                ));
            let source_file_fingerprint = candidate.source_file_fingerprint.clone();
            let mut parser = match sampled_scan::new_source_parser(
                opened_file,
                &candidate,
                index,
                sampled_scan::ParserOptions {
                    source,
                    metadata: &codex_title_metadata,
                    traces: codex_turn_traces.clone(),
                    identity_capture: claude_request_identity_capture,
                    cache: sampling.as_ref().map(|c| &c.cache),
                },
            ) {
                Ok(parser) => parser,

                Err(error) => {
                    if sampled_scan::codex_cursor::requeue_refused(
                        source,
                        &error,
                        index,
                        &codex_selected_flags,
                        &candidate,
                    ) {
                        pending!();
                    }
                    if source == SnapshotSource::ClaudeCode {
                        claude_request_census::invalidate_claude_request_census(
                            index,
                            &candidate.path,
                        );
                    }
                    census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    pending!();
                }
            };

            let mut file_sampling = None;
            let mut retained_offset = None;
            // Counted once the page actually reads the file: a fence
            // or deferral below does not inflate the read diagnostics.
            let mut planned_mode = None;
            if let Some(context) = sampling
                .as_mut()
                .filter(|_| !parser.reader.reader.is_compressed())
            {
                let key = local_index_key(&candidate.path);
                // Every source's continuation is its committed Tail. A route
                // that cannot be read now holds the file for its next
                // selection.
                #[cfg(unix)]
                let tail_route = match state_v2::tail_route_path(index) {
                    Ok(route) => route,
                    Err(_) => {
                        tail_source::counters::bump(source, "tail_db_loads", "held");
                        residue_index_keys.insert(key.clone());
                        pending!();
                    }
                };
                // No database route (v1, a paused import, no support dir): its
                // growth reads Full.
                #[cfg(unix)]
                if tail_route.is_none() && index.files.contains_key(&key) {
                    tail_source::counters::bump(source, "tail_bootstrap_full", "unrouted");
                }
                #[cfg(not(unix))]
                let tail_route: Option<PathBuf> = None;
                // On a Tail route the held-new custody is durable: the
                // withheld read's census record, and its committed head.
                let e2_held_new_file = source == SnapshotSource::ClaudeCode
                    && tail_route.is_some()
                    && tail_source::load::held_new(index, &key);
                context.admission.attempts = context.admission.attempts.saturating_add(1);
                let owning_header_is_current = source != SnapshotSource::Codex
                    || codex_join_inventory.as_ref().is_some_and(|inventory| {
                        inventory.complete
                            && inventory
                                .headers
                                .iter()
                                .any(|header| header.candidate.path == candidate.path)
                    });
                context
                    .admission
                    .owning_header_current
                    .observe(owning_header_is_current);
                context
                    .admission
                    .state_census_complete
                    .observe(state_census_complete);
                context
                    .admission
                    .sidecar_census_complete
                    .observe(sidecar_census_complete);
                // Claude's retained reduction is captured before metadata is
                // applied in finish. Its exact per-session dependencies still
                // fence reuse; unrelated inventory coverage cannot force a Full
                // on growth. Coverage/identity/publication gates below remain
                // unchanged, and Codex still needs its closed-world sidecars.
                // Partial Desktop coverage permits continuing a known native
                // session, not admitting a new cold file to sampled acquisition.
                // Without an index entry or its own held-new certificate, keep
                // main's unsampled read and copy-refusal exemption.
                let scoped_claude_metadata = tail_route.is_some()
                    && source == SnapshotSource::ClaudeCode
                    && !sidecar_census_complete
                    && (index.files.contains_key(&key) || e2_held_new_file);
                if owning_header_is_current
                    && state_census_complete
                    && (sidecar_census_complete || scoped_claude_metadata)
                {
                    if scoped_claude_metadata {
                        crate::local_resource_diagnostics::claude_reread::desktop_scoped_acquisition();
                    }
                    let reduction_sidecar = sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    );
                    context
                        .admission
                        .reduction_dependencies_available
                        .observe(reduction_sidecar.is_some());
                    if let Some(reduction_sidecar) = reduction_sidecar {
                        let debt = sampled_audit::debt_for_key(index, &key, audit_now);
                        let protected_entry = index.files.get(&key);
                        context
                            .admission
                            .index_entry_present
                            .observe(protected_entry.is_some());
                        let protected =
                            protected_entry.is_some_and(ScanIndexEntry::codex_history_is_protected);
                        let forced_family = claude_index_path_family_member(&candidate.path)
                            .is_some_and(|(root, _)| {
                                forced_claude_family_reparses.contains(&root)
                                    || index.claude_usage_authority_quarantine.contains_key(&root)
                            });
                        // Audit population/deadlines never gate ordinary
                        // restore. The legacy prefix/proof paths retain their
                        // own rules. A same-process `e2`-held read may
                        // reuse only its own certificate, without authority.
                        // On Claude's database route a forced member reads natively
                        // only for evidence stored state cannot supply.
                        let forced_native = forced_family
                            && (tail_route.is_none()
                                || claude_request_census::forced_member_needs_native(index, &key));
                        let mut allow_sample = (index.files.contains_key(&key) || e2_held_new_file)
                            && !protected
                            && !forced_native;
                        context
                            .admission
                            .audit_metadata_supported
                            .observe(context.audit_metadata_supported);
                        context.admission.protected_history.observe(protected);
                        context.admission.forced_family.observe(forced_family);
                        context.admission.comparison_target.observe(false);

                        context.admission.audit_debt_present.observe(debt.is_some());
                        context
                            .admission
                            .audit_slot_available
                            .observe(context.audit_slots > 0);
                        let scope = context.file_scope(source, &candidate, &reduction_sidecar);
                        // On a Tail route a read loads the committed Tail.
                        #[cfg(unix)]
                        let tail_load = tail_route.as_deref().filter(|_| {
                            allow_sample
                                && tail_source::load::reuses_stored(
                                    index,
                                    &key,
                                    parse_reason,
                                    index.files.get(&key).is_some_and(|entry| {
                                        candidate.size_bytes > entry.size_bytes
                                    }),
                                    e2_held_new_file,
                                )
                                && !parser.reader.reader.is_compressed()
                        });
                        #[cfg(unix)]
                        if tail_route.is_some()
                            && tail_load.is_none()
                            && parse_reason == Some(CandidateParseReason::NewFile)
                        {
                            tail_source::counters::bump(source, "tail_bootstrap_full", "new_file");
                        }
                        #[cfg(unix)]
                        let mut tail_proven_full = None;
                        #[cfg(unix)]
                        let (mut retained, debt) = match tail_load {
                            Some(route) => {
                                match tail_source::load_candidate(
                                    source,
                                    index,
                                    route,
                                    &candidate,
                                    &parser.accumulator,
                                    claude_request_identity_capture,
                                    parser.reader.reader.get_mut(),
                                    &scope,
                                ) {
                                    tail_source::load::Load::Reused(retained, base) => {
                                        if let Some(base) = base {
                                            parser.set_tail_base(base);
                                        }
                                        // A late-evidence re-fold from
                                        // stored state, counted by its reason.
                                        if let Some(reason) = parse_reason.filter(|reason| {
                                            tail_source::load::late_evidence(*reason)
                                        }) {
                                            tail_source::counters::bump(
                                                source,
                                                "tail_refold",
                                                CANDIDATE_PARSE_REASON_NAMES[reason as usize],
                                            );
                                        }
                                        retained_offset = Some(retained.checkpoint.sealed_offset());
                                        (Some(retained), debt)
                                    }
                                    // A newer build's head: untouched, held as residue.
                                    tail_source::load::Load::Held => {
                                        residue_index_keys.insert(key.clone());
                                        pending!();
                                    }
                                    tail_source::load::Load::Cold(proven) => {
                                        tail_proven_full = proven;
                                        (None, debt)
                                    }
                                }
                            }
                            None if allow_sample && !parser.reader.reader.is_compressed() => {
                                // A read with no stored continuation: counted by why.
                                resource_probe.full_causes.restore_outcome.record(
                                    sampled_scan::ram_miss_class(
                                        index,
                                        &key,
                                        context.cache.quiet_registered(source),
                                    ),
                                );
                                (None, debt)
                            }
                            None => (None, debt),
                        };
                        // The cap funds NEW obligations, never a global restore
                        // gate. Marked files Tail; quiet debt-free copies reuse.
                        let mut cap_full = false;
                        if allow_sample
                            // Account-held reparses belong to withheld_reparse;
                            // central staging still bounds fresh audit markers.
                            && !index.claude_account_deferred_holds.contains_key(&key)
                            && context.audit_slots == 0
                            && index.files.contains_key(&key)
                            && !index
                                .files
                                .get(&key)
                                .is_some_and(ScanIndexEntry::has_unverified_source)
                            && !retained.as_ref().is_some_and(|old| {
                                old.checkpoint.audit_debt().is_none()
                                    && old.checkpoint.sealed_offset() == candidate.size_bytes
                                    && old.checkpoint.scope() == &scope
                                    && old
                                        .checkpoint
                                        .stamp_matches(parser.reader.reader.get_ref())
                                        .unwrap_or(false)
                            })
                        {
                            if !context.cap_candidate(&key) {
                                sampled_audit::queue_cap_retry(index, &candidate);
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                            cap_full = true;
                            allow_sample = false;
                        }
                        context.admission.sampling_allowed.observe(allow_sample);
                        if !allow_sample {
                            drop(retained.take());
                        }
                        context.admission.prepare_started =
                            context.admission.prepare_started.saturating_add(1);
                        let census_base_bound = retained
                            .as_ref()
                            .zip(index.files.get(&key))
                            .is_some_and(|(old, entry)| {
                                old.checkpoint
                                    .durable_certificate(candidate.fingerprint_birth_nanos)
                                    .is_some_and(|cert| {
                                        cert.length == cert.sealed_offset
                                            && entry.size_bytes == cert.sealed_offset
                                            && entry.modified_unix_nanos.is_some_and(|nanos| {
                                                cert.modified
                                                    == (
                                                        (nanos / 1_000_000_000) as i64,
                                                        (nanos % 1_000_000_000) as i64,
                                                    )
                                            })
                                            && entry.opened_birth_nanos == cert.birth_nanos
                                            && index.claude_request_census.get(&key).is_some_and(
                                                |record| {
                                                    claude_request_census::fingerprint_matches(
                                                        record,
                                                        &entry.source_file_fingerprint,
                                                    )
                                                },
                                            )
                                    })
                            });
                        let mode = match parser.prepare_acquisition(
                            retained,
                            &scope,
                            debt,
                            sampled_scan::now_seconds(),
                        ) {
                            Ok(mode) => mode,
                            Err(_) => {
                                context.admission.prepare_failed =
                                    context.admission.prepare_failed.saturating_add(1);
                                if source == SnapshotSource::ClaudeCode {
                                    claude_request_census::invalidate_claude_request_census(
                                        index,
                                        &candidate.path,
                                    );
                                }
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                        };
                        #[cfg(unix)]
                        let mode = match (tail_proven_full, parser.reader.acquisition.as_mut()) {
                            (Some(reason), Some(plan)) => plan.name_proven_full(reason),
                            _ => mode,
                        };
                        if !sampled_audit::growth_read_admitted(index, &candidate, mode) {
                            sampled_audit::defer_growth_read(index, &mut census, &candidate);
                            pending!();
                        }
                        // H1c: the plan uses absolute offsets; the reader's
                        // extent is relative to its Full/Tail start.
                        if source == SnapshotSource::ClaudeCode
                            && (allow_sample || cap_full)
                            && matches!(
                                mode,
                                crate::transcript_acquisition::ReadMode::Full(_)
                                    | crate::transcript_acquisition::ReadMode::Tail
                            )
                        {
                            if let Some(plan) = parser.reader.acquisition.as_ref() {
                                parser
                                    .reader
                                    .set_extent_limit(plan.frozen_length() - plan.start_offset());
                            }
                        }
                        // Restore does not restore/extend an exact-prefix pricing receipt.
                        // Any new priority contribution below forces a real full replay.
                        if source == SnapshotSource::Codex {
                            sampled_scan::configure_tier_replay(&mut parser, &candidate, index);
                        }
                        let audit_due = parser
                            .reader
                            .acquisition
                            .as_ref()
                            .and_then(|plan| plan.metrics().audit_due)
                            .or_else(|| {
                                // A grown Full without an older obligation
                                // still owes a quiet audit. Prepare its bound
                                // now, never from the discarded checkpoint.
                                (source == SnapshotSource::ClaudeCode
                                    && allow_sample
                                    && matches!(
                                        mode,
                                        crate::transcript_acquisition::ReadMode::Full(_)
                                    ))
                                .then(|| {
                                    sampled_scan::now_seconds().saturating_add(
                                        crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
                                    )
                                })
                            });
                        planned_mode = Some((mode, audit_due));
                        file_sampling = Some(sampled_scan::Active {
                            key,
                            scope,
                            mode,
                            audit_due,
                            tier_prefix_replay: false,
                            census_base_bound,
                        });
                    }
                } else if source == SnapshotSource::Codex
                    && owning_header_is_current
                    && crate::heap_layout_bound::layout_supported()
                    && parser
                        .reader
                        .reader
                        .get_ref()
                        .metadata()
                        .is_ok_and(|metadata| {
                            metadata.len()
                                > sampled_scan::codex_cursor::Limits::current().singleton()
                        })
                {
                    // N1 (K9): the state or sidecar census is incomplete, so
                    // main's trust rule refuses verification and retention,
                    // yet main still reads and publishes this file. A file
                    // larger than the singleton budget therefore pages as a
                    // cursor-only job: a fresh `Full` acquisition with no
                    // retained state and no debt input, used only for the
                    // job's object certificate. Its completion keeps no
                    // checkpoint and no copy, so it is never source-verified.
                    let reduction_sidecar = sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    );
                    context
                        .admission
                        .reduction_dependencies_available
                        .observe(reduction_sidecar.is_some());
                    if let Some(reduction_sidecar) = reduction_sidecar {
                        let scope = context.file_scope(source, &candidate, &reduction_sidecar);
                        context.admission.prepare_started =
                            context.admission.prepare_started.saturating_add(1);
                        let mode = match parser.prepare_acquisition(
                            None,
                            &scope,
                            None,
                            sampled_scan::now_seconds(),
                        ) {
                            Ok(mode) => mode,
                            Err(_) => {
                                context.admission.prepare_failed =
                                    context.admission.prepare_failed.saturating_add(1);
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                        };
                        sampled_scan::configure_tier_replay(&mut parser, &candidate, index);
                        planned_mode = Some((mode, None));
                        file_sampling = Some(sampled_scan::Active {
                            key,
                            scope,
                            mode,
                            audit_due: None,
                            tier_prefix_replay: false,
                            census_base_bound: false,
                        });
                    }
                }
            }
            if source == SnapshotSource::ClaudeCode
                && file_sampling.is_none()
                && !sampled_audit::growth_read_admitted(
                    index,
                    &candidate,
                    crate::transcript_acquisition::ReadMode::Full(
                        crate::transcript_acquisition::FullReason::StateMissing,
                    ),
                )
            {
                sampled_audit::defer_growth_read(index, &mut census, &candidate);
                pending!();
            }
            index.note_change_reason_selected(source, &candidate, parse_reason, source_change);
            let mut active = Box::new(OwnedActiveFile {
                first_read: crate::local_resource_diagnostics::FirstRead::begin(
                    source,
                    candidate.size_bytes,
                    !index.files.contains_key(&local_index_key(&candidate.path)),
                ),
                sampling: file_sampling,
                candidate,
                decision,
                parse_reason: parse_reason.filter(|_| source == SnapshotSource::ClaudeCode),
                previous_snapshot_fingerprint,
                previous_upload_body_witness,
                projection_adoption_required,
                source_file_fingerprint,
                parser,
                aliases: Vec::new(),
                applied_receipts: BTreeMap::new(),
                cursor: None,
                charged_bytes: 0,
                hold_offset: None,
                group: None,
            });
            if let Some(context) = sampling.as_ref().filter(|_| {
                source == SnapshotSource::Codex && !codex_archive_path(&active.candidate.path)
            }) {
                let extent = active
                    .parser
                    .reader
                    .reader
                    .get_ref()
                    .metadata()
                    .map_or(0, |metadata| metadata.len());
                let expected = match active.sampling.as_ref().map(|acquisition| acquisition.mode) {
                    Some(crate::transcript_acquisition::ReadMode::Unchanged) => 0,
                    Some(crate::transcript_acquisition::ReadMode::Tail) => {
                        extent.saturating_sub(retained_offset.unwrap_or(0))
                    }
                    _ => extent,
                };

                let defer = match context.cache.cursor_plan_paced(
                    &mut codex_page,
                    sampled_scan::codex_cursor::Limits::current(),
                    expected,
                    codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                    crate::heap_layout_bound::layout_supported(),
                    &context.namespace,
                    &local_index_key(&active.candidate.path),
                    sampled_scan::codex_cursor::census_token(index).as_deref(),
                    sampled_scan::codex_cursor::census_member(
                        &codex_selected_flags,
                        [active.candidate.path.as_path()],
                    ),
                    Some(sampled_scan::codex_cursor::PaceProbe {
                        file: active.parser.reader.reader.get_ref(),
                    }),
                ) {
                    sampled_scan::codex_cursor::StartPlan::Singleton => false,
                    sampled_scan::codex_cursor::StartPlan::Unpaged => {
                        // Layout-unsupported build: the cursor is off as a
                        // whole and this file reads in its page, as before.
                        codex_page.disclose_disabled(&context.cache);
                        false
                    }
                    sampled_scan::codex_cursor::StartPlan::Cursor => {
                        let dependencies = sampled_scan::reduction_dependencies(
                            source,
                            &active.candidate,
                            &codex_title_metadata,
                            &claude_title_metadata,
                            claude_effort_support_dir_ref,
                        );
                        let owner = codex_join_inventory
                            .as_ref()
                            .and_then(|inventory| inventory.owner_for_path(&active.candidate.path))
                            .map(str::to_owned);
                        match context.cache.cursor_start(
                            &mut active,
                            &context.namespace,
                            dependencies,
                            owner,
                            state_census_complete && sidecar_census_complete,
                            index,
                        ) {
                            Ok(lease) => {
                                // The job's path holds the strict census until
                                // its attempt ends (accepted or debt).
                                sampled_scan::codex_cursor::requeue(
                                    index,
                                    &codex_selected_flags,
                                    &active.candidate,
                                );
                                codex_cursor_lease = Some(lease);
                                false
                            }
                            // The slot frees when its job ends: wait in turn.
                            Err(sampled_scan::codex_cursor::StartRefusal::Busy) => true,
                            // N1: no acquisition even cursor-only (no current
                            // owning header or no reduction dependencies, where
                            // main holds the file too). Never requeued: the
                            // path is processed for this generation with a
                            // retryable cause, so discovery finishes and the
                            // bounded unhealthy retry starts the next one.
                            Err(sampled_scan::codex_cursor::StartRefusal::InputsUnavailable) => {
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &active.candidate.path,
                                );
                                pending!();
                            }
                            Err(sampled_scan::codex_cursor::StartRefusal::Unstartable) => {
                                // Never an unbounded in-page read of a file
                                // larger than the singleton budget.
                                census.record_unreadable_file(
                                    UnreadableCause::OpenRead,
                                    &active.candidate.path,
                                );
                                pending!();
                            }
                        }
                    }
                    sampled_scan::codex_cursor::StartPlan::Defer => true,
                    // Processed for this generation (K7 fence).
                    sampled_scan::codex_cursor::StartPlan::Fenced => {
                        scanned_file_count = scanned_file_count.saturating_sub(1);
                        pending!();
                    }
                };
                if defer {
                    // Only a full read reaches here (a tail was planned
                    // before its retained state was consumed).
                    context.cache.cursor_note_deferred();
                    scanned_file_count = scanned_file_count.saturating_sub(1);
                    sampled_scan::codex_cursor::requeue(
                        index,
                        &codex_selected_flags,
                        &active.candidate,
                    );
                    pending!();
                }
            }
            if let Some(context) = sampling.as_mut() {
                if let Some((mode, audit_due)) = planned_mode {
                    context.record_mode(mode, audit_due);
                    resource_probe
                        .rearm_full_selected(&local_index_key(&active.candidate.path), mode);
                    resource_probe.full_parse_reason(mode, active.parse_reason, 1, 0);
                }
            }
            if let Some(delivery) = line_delivery.as_mut() {
                delivery.arm();
            }
            active_file = Some(active);
            pending!();
        }
        if let (None, Some(delivery)) = (&active_file, line_delivery.as_mut()) {
            delivery.left_active();
        }
        Ok(OwnedSourceScanStep::Pending(Self {
            resource_probe,
            sampling,
            source,
            roots,
            index: index_storage,
            collected_at,
            audit_now,
            backfill_window_days,
            file_limit,
            claude_request_identity_capture,
            claude_effort_support_dir,
            codex_title_metadata,
            claude_title_metadata,
            state_census_complete,
            sidecar_census_complete,
            codex_turn_traces,
            codex_census_valid,
            census_window_end,
            discovered_file_count,
            census_unix_seconds,
            census,
            snapshots,
            scanned_file_count,
            scanned_session_count,
            semantic_noop_count,
            history_upgrade,
            context_read_budget,
            residue_index_keys,
            settled_residue_index_keys,
            pending_finalization,
            claude_authority_preflight,
            forced_claude_family_reparses,
            claude_twin_only_family_reparses,
            claude_family_shadow,
            identified_candidates,
            active_file: sampled_scan::codex_cursor::ActiveFrame::new(
                active_file,
                codex_cursor_lease,
            ),
            codex_join_inventory,
            codex_join_prepared,
            codex_join_groups,
            codex_join_active,
            codex_join_completed,
            codex_legacy_join_baselines,
            codex_page,
            codex_selected_flags,
            continuation_ticket,
            line_delivery,
            codex_versions,
            launch_events,
        }))
    }
}

use scan::launch_demand::{
    claude_held_family_matches_launch_context, launch_workers_for_candidate,
    launch_workers_for_parsed, launch_workers_for_path,
};

/// Preserve the two-open identity fence only for the Claude family whose
/// authority reconstruction actually requested the preflight.
///
/// A quarantine anywhere enables the source-wide prepass so the scanner can
/// discover every current member of that family. Unrelated healthy sessions
/// must not inherit its equality check: their transcript or shared OTEL
/// sidecars may advance between the prepass and the authoritative parse open.
/// The second open remains fully revalidated for those sessions; only the
/// quarantined family's cross-member snapshot must stay byte-identical across
/// both phases.
fn claude_authority_preflight_fingerprint(
    index: &ScanIndex,
    candidate: &CandidateFile,
) -> Option<String> {
    let (root_session_id, _) = claude_index_path_family_member(&candidate.path)?;
    index
        .claude_usage_authority_quarantine
        .contains_key(&root_session_id)
        .then(|| candidate.source_file_fingerprint.clone())
}

fn apply_codex_state_evidence(item: &mut SnapshotItem, metadata: &CodexTitleMetadata, path: &Path) {
    let source_session_id = resolve_codex_identity(item.source_session_id.as_str());
    if metadata
        .identity_conflicts
        .contains(source_session_id.as_str())
    {
        return;
    }
    // Parsed usage and its recorded state total must describe the same home.
    // A missing file in a stale home cannot inflate the parsed file's evidence.
    let Some(thread) = metadata
        .thread_extent_for_path(source_session_id.as_str(), path)
        .0
    else {
        return;
    };
    if thread.tokens_used == 0 {
        return;
    }
    item.provenance.state_total_tokens = Some(thread.tokens_used);
    item.provenance.state_archived = Some(thread.archived);
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::Codex, item);
}

#[cfg(test)]
use scan::lines::parser::{
    claude_birth_seconds, parse_claude_code_jsonl_file_with_title_metadata,
    parse_claude_code_jsonl_file_with_title_metadata_and_attribution,
    parse_codex_jsonl_file_with_title_metadata,
    parse_codex_jsonl_file_with_title_metadata_and_attribution, parse_opened_jsonl_file,
};
#[cfg(test)]
pub use scan::lines::parser::{
    parse_claude_code_jsonl_file, parse_codex_jsonl_file, parse_pi_jsonl_file,
};
use scan::lines::parser::{FinishRequest, OwnedJsonlParser, ParsedJsonlFile, PreFinalization};

pub(crate) use scan::lines::parser::release_line_buffer;
use scan::lines::parser::{read_bounded_jsonl_lines, BoundedJsonlReader, JsonlReadReport};
#[cfg(test)]
use scan::lines::parser::{
    recognized_positive_usage_shape, recognized_usage_shape_was_dropped, JsonlReaderStep,
};

#[cfg(test)]
use scan::lines::selectors::detect_claude_gateway_provider;
use scan::lines::selectors::{
    bounded_activity_counts, bounded_activity_label, bounded_tool_usage_counts,
    bounded_tool_usage_name, claude_code_selector_from_line, codex_selector_from_line,
    codex_tool_usage_rows, for_each_skill_md_reference, insert_selector_raw,
    nested_unified_exec_tools, normalize_selector_raw, pi_selector_from_custom,
    pi_selector_from_usage_message, raw_value_at, MAX_ACTIVITY_SKILLS,
};

use sources::codex::rollout_header::{
    codex_creator_header_evidence, codex_header_declares_no_parent, codex_is_task_started,
    codex_legacy_trigger_turn, codex_native_created_thread_header,
    codex_paginated_fork_creation_header, codex_raw_creator_pair,
    codex_session_id_is_native_parent, codex_session_meta_payload,
    codex_sidecar_rollout_file_matches, creator_time_precedes_start,
};

/// Provider token fields only. `request_count` is a parser default when
/// Codex omits it, so it never decides cumulative/request equality.
fn codex_usage_token_fields(usage: &UsageTotals) -> [u64; 5] {
    [
        usage.input_tokens,
        usage.cache_read_tokens,
        usage.cache_creation_5m_tokens,
        usage.output_tokens,
        usage.reasoning_output_tokens,
    ]
}

#[cfg(unix)]
fn metadata_describes_same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn metadata_describes_same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn system_time_unix_nanos_i128(value: SystemTime) -> Option<i128> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
}

fn claude_response_key(value: &Value, sequence: u64) -> String {
    match claude_code_usage_dedup_key(value) {
        Some(key) => key,
        None => {
            // Preserve the historical, conservative one-line/one-response
            // fallback. Claude accounting proof remains absent for every
            // snapshot until api_request logs and trace ownership are
            // reconciled, regardless of transcript identity quality.
            format!("u\u{1f}{}", sequence)
        }
    }
}

use scan::lines::apply::{
    apply_codex_envelope_line, claude_prompt_content, claude_workspace_content,
    codex_opening_content, codex_prompt_content, codex_user_turn_content, codex_workspace_content,
    pi_prompt_content,
};
use sources::claude::line::claude_cache_request_slot;
#[cfg(test)]
use usage::cache_observations::cache_state_within_limits;
use usage::cache_observations::cache_wire;
pub(crate) use usage::cache_observations::{
    cache_state_from_echo, cache_state_from_patch, prepare_cache_observations,
};

use sources::codex::line::{
    apply_codex_line, codex_extract_quota_window_selectors, codex_first_user_prompt,
    codex_plan_window_bucket, codex_transcript_title,
};

use sources::claude::line::{
    apply_claude_code_line, claude_first_user_prompt, claude_fork_line_provenance,
    claude_response_tool_uses, ClaudeForkLineProvenance,
};
#[cfg(test)]
use sources::claude::line::{extract_session_artifacts, parse_artifact_url};

use sources::codex::line::{
    codex_last_usage, codex_last_usage_root, codex_total_usage, codex_usage_event_identity,
};

#[cfg(test)]
pub(crate) use sources::pi::PiFork;
use sources::pi::{apply_pi_line, pi_message_usage, pi_usage_event, pi_usage_value};
#[cfg(test)]
use sources::pi::{
    parse_pi_usd_picos, pi_usage_costs_with_observations, usd_picos_at, PiCostParseError,
};
pub(crate) use sources::pi::{PiLedger, PiUsageDedupState};

fn timestamp_is_before(candidate: &str, current: &str) -> bool {
    match (
        OffsetDateTime::parse(candidate, &Rfc3339),
        OffsetDateTime::parse(current, &Rfc3339),
    ) {
        (Ok(candidate), Ok(current)) => candidate < current,
        (Ok(_), Err(_)) => true,
        (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => candidate < current,
    }
}

fn timestamp_is_after(candidate: &str, current: &str) -> bool {
    match (
        OffsetDateTime::parse(candidate, &Rfc3339),
        OffsetDateTime::parse(current, &Rfc3339),
    ) {
        (Ok(candidate), Ok(current)) => candidate > current,
        (Ok(_), Err(_)) => true,
        (Err(_), Ok(_)) => false,
        (Err(_), Err(_)) => candidate > current,
    }
}

fn bounded_rfc3339_millis(ms: i64) -> Option<String> {
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()?;
    // Python/Pydantic datetimes, and therefore the backend snapshot contract,
    // admit only civil years 1..=9999. `time` deliberately supports a wider
    // internal range, so validate before formatting instead of minting a
    // superficially RFC3339-looking value that can poison an upload batch.
    if !(1..=9999).contains(&timestamp.year()) {
        return None;
    }
    let utc = timestamp.to_offset(time::UtcOffset::UTC);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond(),
    ))
}

fn activity_bucket_from_timestamp(value: &str) -> Option<(String, String)> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    let bucket_seconds = utc.unix_timestamp().div_euclid(3600) * 3600;
    let bucket_start = OffsetDateTime::from_unix_timestamp(bucket_seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()?;
    let normalized_timestamp = utc.format(&Rfc3339).ok()?;
    Some((bucket_start, normalized_timestamp))
}

fn usd_picos_string(value: u128) -> String {
    let whole = value / USD_PICO_SCALE;
    let fraction = value % USD_PICO_SCALE;
    if fraction == 0 {
        return whole.to_string();
    }
    let mut fraction_text = format!("{fraction:012}");
    while fraction_text.ends_with('0') {
        fraction_text.pop();
    }
    format!("{whole}.{fraction_text}")
}

#[cfg(test)]
use sources::claude::line::claude_code_cache_creation_split;
use sources::claude::line::{
    claude_code_delta_usage, claude_code_usage_dedup_key, claude_code_usage_root,
};

fn usage_object_has_numeric_field(root: &Value, fields: &[&str]) -> bool {
    root.as_object().is_some_and(|object| {
        fields
            .iter()
            .any(|field| object.get(*field).and_then(Value::as_u64).is_some())
    })
}

#[cfg(test)]
use discovery::candidate::BoundedCandidateSelection;
use discovery::candidate::{
    candidate_from_traversal_path, candidate_from_traversal_path_at, census_count_fields,
    sampled_revalidation_cause, CandidateDecision, CandidateDiscovery, CandidateFile,
    CandidateWindow, CodexSelection, OpenedObjectStat, ScanCensus,
};
pub(crate) use discovery::candidate::{
    CandidateParseReason, CANDIDATE_PARSE_REASON_COUNT, CANDIDATE_PARSE_REASON_NAMES,
};

/// How long a sidecar census statement waits on a lock Codex holds.
const CODEX_SIDECAR_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) use sources::claude::settings_defaults::{
    load_claude_settings_defaults, read_claude_settings_document, ClaudeConfigDefaultsOutcome,
    ClaudeSettingsDocument, ClaudeSettingsScope,
};
pub(crate) use sources::codex::config_defaults::parse_codex_config_defaults;

#[cfg(test)]
use discovery::traversal::{
    adopt_legacy_traversal_fingerprint, scan_traversal_context_fingerprint,
    scan_traversal_context_fingerprint_with,
};
use discovery::traversal::{
    changed_watcher_hints, codex_census_turn_was_last, codex_fresh_data_pending,
    codex_selection_may_exhaust_page, enqueue_watcher_hints, ensure_bounded_traversal,
    fresh_path_census_member, note_codex_census_turn, pace_listing_owed,
    record_codex_inventory_hold, refresh_retained_codex_roster, release_codex_inventory_hold,
    requeue_observed_keys, requeue_unindexed_observed, start_due_listing_pass, TraversalProgress,
};

pub(crate) fn rfc3339_unix_seconds(value: &str) -> Option<u64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()?
        .unix_timestamp()
        .try_into()
        .ok()
}

fn rfc3339_unix_nanos(value: &str) -> Option<i128> {
    Some(
        OffsetDateTime::parse(value, &Rfc3339)
            .ok()?
            .unix_timestamp_nanos(),
    )
}

fn unhealthy_scan_retry_delay_seconds(attempt: u8) -> u64 {
    let exponent = u32::from(attempt.saturating_sub(1)).min(6);
    UNHEALTHY_SCAN_RETRY_BASE_SECONDS
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(UNHEALTHY_SCAN_RETRY_MAX_SECONDS)
}

// One boundary for fresh, persisted and held work, including compressed rollouts.
// Every encoding uses ordinary continuation budgets and funded input memory.
fn transcript_path_admitted(source: SnapshotSource, path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("jsonl")
        || (source == SnapshotSource::Codex && codex_archive_path(path))
}

#[cfg(test)]
use discovery::directory::{
    advance_bounded_directory_traversal, collect_recent_jsonl_files,
    reconcile_missing_index_entries_with_limit, reconcile_missing_index_entries_with_side,
    with_directory_read_fault, with_test_directory_entries, FIRST_READ_WINDOW_DAYS,
};
use discovery::directory::{
    advance_bounded_directory_traversal_with_budget, claude_absence_is_removal,
    directory_entries_per_tick, effective_backfill_window_days, first_read_aged,
    is_recent_enough_at, opened_candidate_is_within_frozen_window,
    reconcile_missing_index_entries_bounded, DiscoveryRecovery,
};
use discovery::retention::{AccountMoveObservations, DiscoveryRetention};

mod discovery;
#[cfg(test)]
use discovery::candidate_open::{
    adopt_stored_changed_time, open_candidate_file_stat, opened_object_identity_and_stat_retained,
    physical_identity,
};
#[cfg(test)]
pub(crate) use discovery::candidate_open::{
    all_transcript_opens_for_test, with_body_witness_adoption_byte_budget,
    with_body_witness_adoption_page_budget,
};
use discovery::candidate_open::{
    body_witness_adoption_byte_budget, body_witness_adoption_page_budget,
    open_and_identify_scan_candidate_at, open_and_identify_scan_candidate_with_rescue_at,
    open_candidate_file, open_candidate_file_stat_retained, opened_object_identity_and_stat,
    opened_object_identity_from, reopen_for_replay, resolve_configured_scan_root, unix_nanos,
    unix_seconds, OpenedContentSamples,
};

use discovery::candidate_open::{open_candidate_beneath_root, opened_object_identity};
#[cfg(test)]
use discovery::candidate_open::{read_opened_content_samples, START_IDENTITY_SAMPLE_FOR_TEST};

#[cfg(test)]
pub(crate) use claude_reemission_exclusions::restart_claude_reemission_stop_for_test;
use claude_reemission_exclusions::{
    claude_reemission_stop_latched, claude_reemission_stop_reason,
    claude_reemission_stop_withheld_folds, note_claude_reemission_stop,
    note_claude_reemission_stop_with_cause_at, ClaudeReemissionStopCause,
};

#[cfg(test)]
use scan_index::checkpoint_lock::checkpoint_owners;
use scan_index::checkpoint_lock::CheckpointLock;

fn sync_checkpoint_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync checkpoint directory {}", parent.display()))
}

fn unique_checkpoint_sibling(path: &Path, kind: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_extension(format!("{kind}.{}.{nanos}.json", std::process::id()))
}

use scan_index::serde_lenient::{
    deserialize_lenient_claude_history_cutoff, deserialize_lenient_move_hold,
    deserialize_lenient_true, MALFORMED_CLAUDE_HISTORY_CUTOFF,
};

fn valid_snapshot_activity(value: &Option<String>) -> bool {
    match value.as_deref() {
        Some(timestamp) => OffsetDateTime::parse(timestamp, &Rfc3339).is_ok(),
        None => true,
    }
}

impl ScanIndex {
    /// The re-emission list's status reason (`missing_after_install` raises
    /// the local alarm each cycle).
    #[cfg(test)]
    pub(crate) fn claude_reemission_list_status_for_test(&self) -> &'static str {
        self.claude_reemission_exclusions.status()
    }

    /// Record (or clear) the residue the completing generation disclosed, and
    /// say so once per change rather than once per cycle. The log names counts
    /// only; the index keys stay in the local index.
    fn record_scan_residue_witness(
        &mut self,
        source: SnapshotSource,
        traversal: &ScanTraversalCheckpoint,
    ) {
        let next = traversal
            .counts
            .settled_residue()
            .map(|residue| ScanResidueWitness {
                census_window_end: traversal.census_window_end.clone(),
                ownership_incomplete_file_count: residue.ownership_incomplete_file_count,
                zero_snapshot_usage_evidence_count: residue.zero_snapshot_usage_evidence_count,
                dropped_usage_record_count: residue.dropped_usage_record_count,
                index_keys: traversal.residue.index_keys.clone(),
            });
        match (self.scan_residue_witness.as_ref(), next.as_ref()) {
            (Some(previous), Some(next)) if previous.same_residue(next) => {}
            (None, None) => {}
            (_, Some(next)) => eprintln!(
                "ottto-service: {} census completed with non-progressing residue: {} \
                 ownership-incomplete Codex rollout(s) ({} under an archived root), {} file(s) \
                 with usage evidence but no entity, {} dropped usage record(s); the residue is \
                 re-derived every generation and clears only when its files, their sidecar, or \
                 the parser change",
                source.api_slug(),
                next.ownership_incomplete_file_count,
                next.archived_residue_file_count(),
                next.zero_snapshot_usage_evidence_count,
                next.dropped_usage_record_count,
            ),
            (Some(_), None) => eprintln!(
                "ottto-service: {} census residue cleared; every previously non-progressing \
                 file now checkpoints",
                source.api_slug()
            ),
        }
        self.scan_residue_witness = next;
    }
}

pub(crate) use sources::codex::identity::codex_creator_pair;
#[cfg(test)]
use sources::codex::identity::safe_codex_agent_display_label;
use sources::codex::identity::{
    codex_archive_path, codex_creator_slot, codex_digest_from_hex, codex_identity_at,
    codex_reasoning_effort, codex_rollout_thread_id, codex_rows_all,
    codex_session_id_candidates_from_path, codex_session_id_from_path, resolve_codex_identity,
    resolve_codex_identity_option,
};

mod upload;

mod scan_index;
pub use scan_index::source_fingerprint::source_file_fingerprint;
use scan_index::source_fingerprint::{local_index_key, source_file_fingerprint_with_context};

mod session_facts;
#[cfg(test)]
use session_facts::display_title::claude_custom_title_display_title;
pub(crate) use session_facts::display_title::{
    claude_registration_display_title, prompt_prefix_display_title,
};
use session_facts::display_title::{
    first_prompt_display_title, normalize_display_title, normalize_title,
};

mod scan;
use scan::source_session_id::codex_identity_is_uuid_shaped;

#[cfg(test)]
use sources::claude::subagent_identity::claude_subagent_source_session_id;
pub(crate) use sources::claude::subagent_identity::{
    claude_subagent_identity, claude_transcript_excluded_from_snapshots,
};
use sources::claude::subagent_identity::{
    claude_subagent_sidecar_fingerprint, claude_usage_sidecars_fingerprint,
    claude_workflow_agent_label, read_claude_agent_meta,
};

pub(crate) use scan::source_session_id::snapshot_source_session_id;

#[cfg(test)]
#[path = "snapshots/source_session_id_tests.rs"]
mod source_session_id_tests;

use scan::json_fields::{string_at, string_eq_at, u64_at};

#[cfg(test)]
use scan_index::file_set_digest::snapshot_file_entity_set_digest;
use scan_index::file_set_digest::{
    sha256_digest, sha256_hex, sha256_hex_owned, snapshot_file_entity_set_hex,
    snapshot_file_upload_body_set_digest, snapshot_file_upload_body_set_hex,
    update_length_prefixed, PrefixDigest,
};

pub fn paths_from_events(
    source: SnapshotSource,
    paths: impl IntoIterator<Item = PathBuf>,
) -> BTreeSet<PathBuf> {
    paths
        .into_iter()
        .filter(|path| transcript_path_admitted(source, path))
        .collect()
}

/// Reads a curve from a committed golden fixture at a JSON pointer ("" is the
/// whole file). The daemon no longer builds curves; retained bodies may still
/// carry one.
#[cfg(test)]
pub(crate) fn context_curve_golden_fixture(file: &str, pointer: &str) -> SnapshotContextCurve {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/snapshot-audit")
        .join(file);
    let value: Value =
        serde_json::from_slice(&fs::read(path).expect("read curve fixture")).expect("json");
    serde_json::from_value(value.pointer(pointer).expect("curve pointer").clone())
        .expect("curve fixture decodes")
}

#[cfg(test)]
#[rustfmt::skip]
mod tests;

#[cfg(test)]
pub(crate) mod cache_adapter_tests {
    use super::*;
    pub(crate) fn cache_fixture_item() -> SnapshotItem {
        let mut parser = SnapshotAccumulator::new(SnapshotSource::Codex);
        apply_codex_line(
            &json!({"type":"session_meta","timestamp":"2026-09-30T10:00:00Z","payload":{"id":"00000000-0000-7000-8000-000000000001"}}),
            &mut parser,
        );
        apply_codex_line(
            &json!({"type":"turn_context","payload":{"model":"gpt-5.6-sol","effort":"high","current_date":"2026-09-30"}}),
            &mut parser,
        );
        let mut cumulative_read = 0;
        for (index, read) in [90_000, 0, 90_000].into_iter().enumerate() {
            let timestamp = format!("2026-09-30T10:00:0{index}Z");
            apply_codex_line(
                &json!({"type":"token_usage_record","timestamp":timestamp,"payload":{"response_id":format!("resp_cache_fixture_{index}"),"usage":{"input_tokens":100_000,"cached_input_tokens":read,"cache_write_input_tokens":0,"output_tokens":1}}}),
                &mut parser,
            );
            cumulative_read += read;
            apply_codex_line(
                &json!({"type":"event_msg","timestamp":timestamp,"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100_000*(index+1),"cached_input_tokens":cumulative_read,"output_tokens":index+1},"last_token_usage":{"input_tokens":100_000,"cached_input_tokens":read,"output_tokens":1}}}}),
                &mut parser,
            );
        }
        let mut item = parser
            .into_items(
                Path::new("cache-fixture.jsonl"),
                "2026-09-30T10:00:03Z",
                "f".repeat(64),
                None,
            )
            .remove(0);
        prepare_cache_observations(&mut item, None);
        item
    }
    fn cache_fixture_snapshot_value(source: SnapshotSource, item: &SnapshotItem) -> Value {
        // The frozen released wires predate the additive `session_start` field.
        let mut item = item.clone();
        item.session_start = None;
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: source.api_slug().into(),
            machine_id: "a".repeat(64),
            collector_version: Some(collector_version()),
            snapshots: vec![item],
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        serde_json::to_value(request).unwrap()["snapshots"][0].clone()
    }
    /// Optional bounded replay of sanitized numeric research evidence; source text stays outside the public tree.
    #[test]
    fn cache_research_numeric_adapter_replay() {
        let Ok(path) = std::env::var("OTTTO_CACHE_RESEARCH_REPLAY") else {
            return;
        };
        let evidence: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut examined = 0;
        for (case_index, example) in evidence["examples"].as_array().unwrap().iter().enumerate() {
            let provider = example["provider"].as_str().unwrap();
            let source = if provider == "Codex" {
                SnapshotSource::Codex
            } else {
                SnapshotSource::ClaudeCode
            };
            let mut parser = SnapshotAccumulator::new(source);
            let session = format!("00000000-0000-7000-8000-{:012}", case_index + 100);
            if source == SnapshotSource::Codex {
                apply_codex_line(
                    &json!({"type":"session_meta","payload":{"id":session}}),
                    &mut parser,
                );
            } else {
                apply_claude_code_line(
                    &json!({"type":"assistant","sessionId":session,"forkedFrom":{"sessionId":"fixture_parent","messageUuid":"fixture_copy"}}),
                    &mut parser,
                );
            }
            let mut total_input = 0u64;
            let mut total_read = 0u64;
            let mut total_output = 0u64;
            for (slot_index, slot) in example["slots"].as_array().unwrap().iter().enumerate() {
                let timestamp = slot["timestamp"].as_str().unwrap();
                let changed = slot_index > 0
                    && !example["changed_metadata_fields"]
                        .as_array()
                        .map_or(true, |fields| fields.is_empty());
                if source == SnapshotSource::Codex {
                    apply_codex_line(
                        &json!({"type":"turn_context","payload":{"model":slot["model"],"effort":slot["effort"],"fixture_recorded_config":changed}}),
                        &mut parser,
                    );
                    if slot_index == 1
                        && example["label"]
                            .as_str()
                            .unwrap()
                            .to_lowercase()
                            .contains("compaction")
                    {
                        apply_codex_line(
                            &json!({"type":"compacted","timestamp":timestamp}),
                            &mut parser,
                        );
                    }
                    apply_codex_line(
                        &json!({"type":"token_usage_record","timestamp":timestamp,"payload":{"response_id":format!("resp_replay_{case_index}_{slot_index}"),"usage":{"input_tokens":slot["prompt"],"cached_input_tokens":slot["cache_read"],"cache_write_input_tokens":slot["cache_write"],"output_tokens":slot["output"]}}}),
                        &mut parser,
                    );
                    total_input += slot["prompt"].as_u64().unwrap();
                    total_read += slot["cache_read"].as_u64().unwrap();
                    total_output += slot["output"].as_u64().unwrap();
                    apply_codex_line(
                        &json!({"type":"event_msg","timestamp":timestamp,"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":total_input,"cached_input_tokens":total_read,"output_tokens":total_output},"last_token_usage":{"input_tokens":slot["prompt"],"cached_input_tokens":slot["cache_read"],"output_tokens":slot["output"]}}}}),
                        &mut parser,
                    );
                } else {
                    if slot_index == 1
                        && example["label"]
                            .as_str()
                            .unwrap()
                            .to_lowercase()
                            .contains("compaction")
                    {
                        apply_claude_code_line(
                            &json!({"type":"system","subtype":"compact_boundary","sessionId":session,"timestamp":timestamp,"compactMetadata":{"trigger":"auto"}}),
                            &mut parser,
                        );
                    }
                    apply_claude_code_line(
                        &json!({"type":"assistant","sessionId":session,"requestId":format!("req_replay_{case_index}_{slot_index}"),"timestamp":timestamp,"message":{"id":format!("msg_replay_{case_index}_{slot_index}"),"model":slot["model"],"usage":{"input_tokens":slot["uncached"],"cache_read_input_tokens":slot["cache_read"],"cache_creation_input_tokens":slot["cache_write"],"output_tokens":slot["output"]}}}),
                        &mut parser,
                    );
                }
            }
            if source == SnapshotSource::ClaudeCode {
                parser.finalize_claude_responses();
            }
            assert_eq!(parser.cache_requests.len(), 3);
            // Effort and actual measured inactivity are additional verified source evidence,
            // supplied explicitly rather than inferred from response-report timestamps.
            let mut requests = std::mem::take(&mut parser.cache_requests).into_vec();
            for (request, slot) in requests
                .iter_mut()
                .zip(example["slots"].as_array().unwrap())
            {
                request.slot.effort = slot["effort"].as_str().map(str::to_string);
                assert_eq!(request.slot.prompt_tokens, slot["prompt"].as_u64());
                assert_eq!(request.slot.cache_read_tokens, slot["cache_read"].as_u64());
            }
            if source == SnapshotSource::Codex {
                requests[1].idle_seconds = example["idle_seconds"]
                    .as_f64()
                    .map(|seconds| seconds.floor() as u64);
            }
            parser.cache_requests = requests.into();
            let wire = cache_wire(&session, parser.cache_requests.iter(), true);
            let affected = wire
                .operations
                .iter()
                .find_map(|operation| match operation {
                    cache_observations::Operation::Upsert { observation }
                        if observation.affected_request_ref.ends_with("_1") =>
                    {
                        Some(observation)
                    }
                    _ => None,
                });
            let (kind, explanation) = affected
                .map(|row| (row.observation_kind.as_str(), row.explanation_code.as_str()))
                .unwrap_or(("warm", "none"));
            match case_index {
                0 | 1 | 4 => assert_eq!(explanation, "configuration_change"),
                2 => assert_eq!(explanation, "likely_expiry"),
                3 | 10 | 11 | 15 => assert_eq!(explanation, "unclear"),
                6 | 13 => assert_eq!(explanation, "compaction"),
                7 | 12 => assert_eq!(explanation, "model_change"),
                5 | 8 => assert_eq!(kind, "warm"),
                14 => assert_eq!(explanation, "configuration_change"),
                _ => {}
            }
            eprintln!("cache research case={} provider={} classification={} explanation={} operations={} bytes={}",case_index+1,provider,kind,explanation,wire.operations.len(),serde_json::to_vec(&wire).unwrap().len());
            examined += 3;
        }
        assert_eq!(examined, 48);
    }
    #[test]
    fn cache_generated_wire_fixture_and_witness() {
        let item = cache_fixture_item();
        assert_eq!(
            item.cache_observations.as_ref().unwrap().operations.len(),
            1
        );
        assert_eq!(snapshot_upload_body_witness_version(&item), Some(16));
        let fixture = json!({"snapshot":cache_fixture_snapshot_value(SnapshotSource::Codex,&item),"cache_observations_state":item.cache_observations_state,"body_witness_version":snapshot_upload_body_witness_version(&item),"body_witness_digest":snapshot_upload_body_witness(&item)});
        let golden: Value = serde_json::from_str(include_str!(
            "../../../fixtures/snapshot-audit/cache_observation_codex_v1.json"
        ))
        .unwrap();
        if let Ok(output) = std::env::var("OTTTO_CACHE_FIXTURE_OUT") {
            std::fs::write(output, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
        }
        assert_eq!(
            fixture, golden,
            "production codex cache fixture must remain exact"
        );
    }
    /// Export metadata from the already generated production-wire fixtures.
    #[test]
    fn cache_contract_manifest_generated_from_provider_wires() {
        let output = std::env::var("OTTTO_CACHE_MANIFEST_OUT").ok();
        let mut fixtures = serde_json::Map::new();
        for (provider, env, source, expected_version, normalized) in [
            (
                "codex",
                "OTTTO_CACHE_FIXTURE_OUT",
                SnapshotSource::Codex,
                16,
                14,
            ),
            (
                "claude",
                "OTTTO_CACHE_CLAUDE_FIXTURE_OUT",
                SnapshotSource::ClaudeCode,
                15,
                13,
            ),
        ] {
            let path = std::env::var(env).unwrap_or_else(|_| {
                format!(
                    "{}/../../fixtures/snapshot-audit/cache_observation_{provider}_v1.json",
                    env!("CARGO_MANIFEST_DIR")
                )
            });
            let fixture: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                fixture["snapshot"]["cache_observations"]["schema_version"],
                1
            );
            assert!(fixture["snapshot"].get("semantic_envelope").is_some());
            assert_eq!(fixture["body_witness_version"], expected_version);
            let canonical = crate::canonical_json::canonicalize(&fixture).unwrap();
            fixtures.insert(
                provider.into(),
                json!({
                    "fixture_file":format!("cache_observation_{provider}_v1.json"),
                    "fixture_canonical_sha256":format!("{:x}", Sha256::digest(&canonical)),
                    "fixture_wire_bytes":serde_json::to_vec(&fixture).unwrap().len(),
                    "parser_revision":source.parser_version(),
                    "scan_identity_revision":source.scan_identity_version(),
                    "body_witness_version":expected_version,
                    "normalized_public_body_witness_version":normalized,
                    "body_witness_digest":fixture["body_witness_digest"],
                }),
            );
        }
        let manifest = json!({
            "manifest_version":"local_cache_observations_wire_manifest:v1",
            "contract_version":"session_cache_observations:v1",
            "schema_version":1,
            "detector_revision":"v1",
            "canonicalization":crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
            "caps":{"operations":cache_observations::MAX_OPERATIONS,"wire_bytes":cache_observations::MAX_PATCH_BYTES,"canonical_rows":cache_observations::MAX_ROWS,"canonical_bytes":cache_observations::MAX_STATE_BYTES},
            "duration_policy":"nonnegative_whole_seconds_floor",
            "head_cas_contract":SNAPSHOT_HEAD_CAS_CONTRACT,
            "entity_ack_contract":SNAPSHOT_ENTITY_ACK_CONTRACT,
            "normalized_public_body_witness_map":{"15":13,"16":14},
            "fixtures":fixtures,
        });
        if let Some(output) = output {
            std::fs::write(output, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
        } else {
            let expected: Value = serde_json::from_str(include_str!(
                "../../../fixtures/snapshot-audit/cache-observations-v1-manifest.json"
            ))
            .unwrap();
            assert_eq!(
                manifest, expected,
                "cache wire manifest must match production fixtures"
            );
        }
    }

    #[test]
    fn cache_codex_adapter_skips_echoes_and_counts_legacy_fork_records() {
        let mut parser = SnapshotAccumulator::new(SnapshotSource::Codex);
        apply_codex_line(
            &json!({"type":"session_meta","payload":{"id":"session"}}),
            &mut parser,
        );
        apply_codex_line(
            &json!({"type":"turn_context","payload":{"model":"model","effort":"high","current_date":"2026-09-30"}}),
            &mut parser,
        );
        for (index, read) in [90_000, 0, 90_000].into_iter().enumerate() {
            apply_codex_line(
                &json!({"type":"token_usage_record","timestamp":format!("2026-09-30T10:00:0{}Z",index),"payload":{"response_id":format!("resp_{index}"),"usage":{"input_tokens":100_000,"cached_input_tokens":read,"cache_write_input_tokens":0,"output_tokens":0}}}),
                &mut parser,
            );
            apply_codex_line(
                &json!({"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100_000},"last_token_usage":{"input_tokens":100_000}}}}),
                &mut parser,
            );
        }
        assert_eq!(parser.cache_requests.len(), 3);
        let wire = cache_wire("session", parser.cache_requests.iter(), true);
        assert_eq!(wire.operations.len(), 1);
        assert_eq!(parser.cache_requests[1].slot.uncached_tokens, Some(100_000));
        let mut child = SnapshotAccumulator::new(SnapshotSource::Codex);
        apply_codex_line(
            &json!({"type":"session_meta","payload":{"id":"child","forked_from_id":"missing-parent"}}),
            &mut child,
        );
        apply_codex_line(
            &json!({"type":"token_usage_record","timestamp":"2026-09-30T10:00:00Z","payload":{"response_id":"copied","usage":{"input_tokens":100_000,"cached_input_tokens":0}}}),
            &mut child,
        );
        assert_eq!(child.cache_requests.len(), 1);
        assert_eq!(child.cache_requests[0].slot.prompt_tokens, Some(100_000));
        assert_eq!(child.cache_requests[0].slot.cache_creation_tokens, None);
        assert_eq!(child.cache_requests[0].slot.uncached_tokens, None);
    }
    #[test]
    fn cache_claude_resolved_chunks_preserve_nullable_fields() {
        let mut parser = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
        for (index, read) in [90_000, 0, 90_000].into_iter().enumerate() {
            for output in [1, 2] {
                apply_claude_code_line(
                    &json!({"type":"assistant","sessionId":"session","requestId":format!("req_{index}"),"timestamp":format!("2026-09-30T10:00:0{}Z",index),"message":{"id":format!("msg_{index}"),"model":"claude","usage":{"input_tokens":100_000-read,"cache_read_input_tokens":read,"cache_creation_input_tokens":0,"output_tokens":output}}}),
                    &mut parser,
                );
            }
        }
        parser.finalize_claude_responses();
        assert_eq!(parser.cache_requests.len(), 3);
        assert_eq!(parser.cache_requests[1].slot.output_tokens, Some(2));
        assert_eq!(
            cache_wire("session", parser.cache_requests.iter(), true)
                .operations
                .len(),
            1
        );
        let absent = claude_cache_request_slot(
            &json!({"requestId":"req_absent","message":{"usage":{"input_tokens":10,"output_tokens":0}}}),
            None,
            None,
            None,
        );
        assert_eq!(absent.cache_read_tokens, None);
        assert_eq!(absent.cache_creation_tokens, None);
        assert_eq!(absent.prompt_tokens, None);
    }
}

crate::heap_layout_bound::fields!(crate::context_footprint::RepositoryIdentity; repository_hash, repository_label, repository_label_source, repository_identity_source, workspace_kind);

impl crate::heap_layout_bound::HeapLayoutBound for fn(&Value, &mut SnapshotAccumulator) {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
crate::heap_layout_bound::unit_enum!(true;
    CandidateDecision: Skip | Migrate | Parse | ReconcileLegacy;
    CandidateParseReason: TerminalDisposition | NewFile | AuthorityQuarantine | Audit
        | BodyWitnessAdoption | UploadContext | ActivityOrQuarantineRetry | TranscriptChanged
        | CodexCapture | UnknownOutcome | LegacyActivity | LegacyIdentity | Rearmed
        | SourceChanged | ForcedFamily;
    ClaudeCompactionKind: LegacySummary | CurrentBoundary;
    SnapshotQuarantineDisposition: RetryPending | UnprovenTerminal | SupersededTerminal;
    ClaudeUsageAuthorityQuarantineDisposition: RetryPending | UnprovenTerminal;
    SnapshotSource: Pi | Codex | ClaudeCode;
    AccountSource: CarriedForward | CarriedBackward;
    CodexOwnershipBoundary: Undetermined | AllLocal | AwaitingLegacyTrigger | AwaitingParentPrefix
        | Ordinal { start: _ } | NativeCreatedThread | AmbiguousFork;
);

crate::heap_layout_bound::fields!(SnapshotUploadPolicy; session_titles_enabled, workspace_labels_enabled, session_artifacts_enabled, session_attribution_enabled, session_attribution_labels_enabled);

#[cfg(test)]
mod census_unreadable_tests {
    use super::*;

    fn projection(counts: &ScanTraversalCounts) -> Value {
        serde_json::to_value(
            counts
                .unreadable_causes
                .projection(counts.unreadable_path_count as u64),
        )
        .unwrap()
    }

    #[test]
    fn unreadable_causes_conserve_pages_and_preserve_health_and_legacy_unknowns() {
        let causes = [
            UnreadableCause::Metadata,
            UnreadableCause::Directory,
            UnreadableCause::OpenRead,
            UnreadableCause::ScopeObject,
            UnreadableCause::Reduction,
            UnreadableCause::AliasParser,
            UnreadableCause::ProtectedAbsence,
            UnreadableCause::LegacyHold,
        ];
        let mut traversal = ScanTraversalCounts::default();
        for (ordinal, cause) in causes.into_iter().enumerate() {
            let mut page = ScanCensus::default();
            page.record_unreadable(cause, ordinal + 1);
            traversal.unreadable_path_count += page.unreadable_path_count;
            traversal.unreadable_causes.merge(page.unreadable_causes);
            // Exactly the original predicate; metadata may not settle residue.
            assert!(traversal.has_retryable_problems());
            assert!(traversal.has_errors());
            assert!(!traversal.settle_non_progressing_residue());
        }
        assert_eq!(traversal.unreadable_path_count, 36);
        let projected = projection(&traversal);
        assert_eq!(projected["counts"], json!([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(projected["unattributed"], 0);
        assert_eq!(projected["consistent"], true);
        let mut retained: ScanTraversalCounts =
            serde_json::from_value(json!({"unreadable_path_count":37})).unwrap();
        assert_eq!(projection(&retained)["unattributed"], 37);
        retained.record_unreadable(UnreadableCause::Directory, 2);
        assert_eq!(retained.unreadable_path_count, 39);
        assert_eq!(projection(&retained)["unattributed"], 37);
        let roundtrip: ScanTraversalCounts =
            serde_json::from_slice(&serde_json::to_vec(&retained).unwrap()).unwrap();
        assert_eq!(projection(&roundtrip), projection(&retained));
    }

    /// [format] Old traversal parent counters decode in place and disappear at save.
    #[test]
    fn retired_parent_counters_decode_without_changing_sibling_counts() {
        let counts: ScanTraversalCounts = serde_json::from_value(json!({
            "parent_unresolvable": {"counts": [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]},
            "unreadable_path_count": 2,
            "discovered_file_count": 7,
            "ownership_incomplete_file_count": 3
        }))
        .unwrap();
        let value = serde_json::to_value(counts).unwrap();
        assert!(value.get("parent_unresolvable").is_none());
        assert_eq!(value["discovered_file_count"], 7);
        assert_eq!(value["ownership_incomplete_file_count"], 3);
        assert_eq!(value["unreadable_path_count"], 2);
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct PrePrP {
            unreadable_path_count: usize,
        }
        let older: PrePrP = serde_json::from_value(value).unwrap();
        assert_eq!(older.unreadable_path_count, 2);
    }

    #[test]
    fn unreadable_legacy_hold_persists_its_existing_event_without_new_public_loss() {
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots(
            SnapshotSource::Codex,
            &[],
            &mut index,
            "2026-10-12T00:00:00Z",
            30,
        )
        .unwrap();
        ensure_bounded_traversal(
            SnapshotSource::Codex,
            &[],
            &mut index,
            "2026-10-12T00:00:00Z",
            30,
        );
        let original = scan.unreadable_path_count;
        scan.hold_codex_groups(
            &mut index,
            &ScanIndex::default(),
            &BTreeSet::from(["fixture-held-owner".to_string()]),
            "synthetic legacy hold",
        );
        assert!(!scan.census_complete);
        assert!(scan.scan_cap_hit);
        assert_eq!(
            scan.unreadable_path_count, original,
            "the existing held-group behavior only augments the durable traversal"
        );
        let counts = &index.traversal.as_ref().unwrap().counts;
        assert_eq!(counts.unreadable_path_count, 1);
        assert_eq!(
            projection(counts)["counts"],
            json!([0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(projection(counts)["unattributed"], 0);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_native_metadata_directory_and_open_failures_name_existing_branch() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "ottto-unreadable-causes-{}",
            ottto_core::generate_control_token().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let path = root.join("one.jsonl");
        fs::write(&path, b"{}\n").unwrap();
        // Metadata fails below an inaccessible owned directory.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o000)).unwrap();
        let mut census = ScanCensus::default();
        assert!(candidate_from_traversal_path(
            SnapshotSource::Codex,
            ScanTraversalPath {
                scan_root: root.clone(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false
            },
            &mut census,
            None,
            30,
            &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
        )
        .is_none());
        assert_eq!(
            serde_json::to_value(
                census
                    .unreadable_causes
                    .projection(census.unreadable_path_count as u64)
            )
            .unwrap()["counts"],
            json!([1, 0, 0, 0, 0, 0, 0, 0])
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::Codex,
            ScanTraversalPath {
                scan_root: root.clone(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            },
            &mut census,
            None,
            30,
            &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(open_and_identify_scan_candidate(
            SnapshotSource::Codex,
            candidate,
            &mut census,
            None,
            30,
            DiscoveryRetention::unverified(&SharedMap::default())
        )
        .is_none());
        assert_eq!(
            serde_json::to_value(
                census
                    .unreadable_causes
                    .projection(census.unreadable_path_count as u64)
            )
            .unwrap()["counts"],
            json!([1, 0, 1, 0, 0, 0, 0, 0])
        );
        // The OpenRead sample names the file's kind and key digest,
        // never its path.
        let sample = serde_json::to_value(census.unreadable_causes).unwrap()["samples"]
            [UnreadableCause::OpenRead as usize][0]
            .clone();
        let key = crate::codex_scan_diagnostics::digest(&local_index_key(&path));
        let key = u64::from_be_bytes(std::array::from_fn(|byte| key[byte]));
        assert_eq!(
            (&sample["root"], &sample["kind"], &sample["key"]),
            (&json!("other_home"), &json!("jsonl"), &json!(key)),
            "{sample}"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o100)).unwrap();
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-10-12T00:00:00Z",
            30,
        );
        advance_bounded_directory_traversal(SnapshotSource::Codex, &mut index, 30, None);
        assert_eq!(
            projection(&index.traversal.as_ref().unwrap().counts)["counts"],
            json!([0, 1, 0, 0, 0, 0, 0, 0])
        );
    }
}

#[path = "snapshots/composition_compactions.rs"]
mod composition_compactions;
pub(crate) use composition_compactions::CompositionCompactions;
pub(crate) mod start_verdict_store;

#[cfg(test)]
pub(crate) use scan_index::save::pause_next_scan_index_cas_for_test;

crate::heap_layout_bound::fields!(ClaudeRemovedUsage; input_tokens, output_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, unattributed_total_tokens, reasoning_output_tokens);

#[cfg(all(test, unix))]
// Static receipts from the qualified 64-bit production layout. These keep
// the parser-box allocation honest; no runtime test executes. These are upper
// bounds until a qualified build re-pins them after the record store's removal.
#[cfg(all(unix, target_pointer_width = "64", not(test)))]
const _: () = {
    // The L04 lineage clocks (`Option<(i128, i128)>`) add at most 48 B.
    assert!(size_of::<OwnedJsonlParser>() <= 5360);
    assert!(std::mem::align_of::<OwnedJsonlParser>() == 16);
    // CandidateFile.withheld_content_stamp adds 24 B (Option<String>) to the
    // 856-byte active frame, and the first-read observation adds its own.
    // Parser/custody boxing is unchanged; sampling counters are charged separately.
    assert!(
        size_of::<OwnedActiveFile>()
            <= 880 + size_of::<Option<crate::local_resource_diagnostics::FirstRead>>()
    );
};
pub(crate) fn maintain_state_v2_idle(path: &Path, index: &ScanIndex, quiet: bool) -> Result<()> {
    let result = state_v2::idle(path, index, quiet);
    state_v2::telemetry::retained_pass_end(index);
    result
}
/// Hold for the whole collection cycle: releases a committed-page baseline on
/// every exit, including the error exits that skip maintain_state_v2_idle.
pub(crate) fn state_v2_baseline_release(
    path: &Path,
    index: &ScanIndex,
) -> state_v2::BaselineRelease {
    state_v2::BaselineRelease::new(path, index)
}
pub(crate) fn state_v2_side_effect_guard(
    path: &Path,
    index: &ScanIndex,
) -> impl Fn() -> Result<()> {
    let runtime = index.v2().persistence_v2.clone();
    // This guard belongs to this graph, not to the mutable shared connection.
    // After adopting a successful save, construct a new guard for further IO.
    let graph_generation =
        sampled_audit::own_growth_claim_generation(index, path).unwrap_or(index.generation);
    let path = runtime.as_ref().map(|_| path.to_owned());
    move || match path.as_deref() {
        Some(path) => state_v2::guard_external(path, runtime.as_ref(), graph_generation),
        None => Ok(()),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn invalidate_claude_state_v2_sessions(support: &Path) -> Result<()> {
    state_v2::invalidate_tree(support)
}

#[cfg(test)]
fn open_and_identify_scan_candidate(
    source: SnapshotSource,
    candidate: CandidateFile,
    census: &mut ScanCensus,
    census_unix_seconds: Option<u64>,
    backfill_window_days: u64,
    retention: DiscoveryRetention<'_>,
) -> Option<(CandidateFile, File)> {
    open_and_identify_scan_candidate_at(
        source,
        candidate,
        census,
        CandidateWindow {
            census_unix_seconds,
            backfill_window_days,
            retention,
            growth: None,
        },
    )
}

// Opaque v2-only companion for the unchanged upload-progress store.
pub(crate) use state_v2::ack::{ProgressRecovery, ProgressSeal};
// OPS diagnostics bridges; the private storage module stays private.
pub(crate) use state_v2::state_v2_growth_retention_active;
pub(crate) fn state_v2_pass_start() {
    state_v2::telemetry::pass_start();
}
pub(crate) fn state_v2_prepare_observed() {
    state_v2::telemetry::phase("prepare");
}
pub(crate) fn state_v2_finish_window() -> Option<impl Drop> {
    state_v2::telemetry::Window::begin("finish")
}
pub(crate) fn state_v2_post_pass_observed() {
    state_v2::telemetry::plateau();
}

pub(crate) fn state_v2_custody_published(path: &Path) -> Result<bool> {
    state_v2::published(path)
}

pub(crate) fn state_v2_before_collection(index: &ScanIndex) -> Result<()> {
    state_v2::before_collection(index)
}

#[cfg(test)]
mod state_v2_maintenance_lock_tests {
    use super::*;

    /// [off=main] ordinary sources retain nonblocking checkpoint contention.
    #[test]
    fn off_sources_keep_nonblocking_checkpoint_contention() {
        let root = crate::test_scratch::private_dir("off-checkpoint");
        let parent = root.join("b".repeat(64));
        for source in ["claude_code-test", "codex-test", "pi-test"] {
            let path = parent.join(format!("{source}-scan-index.json"));
            assert!(!state_v2::published(&path).unwrap());
            let lock = CheckpointLock::acquire(&path).unwrap();
            let error = CheckpointLock::acquire(&path).err().unwrap();
            assert_eq!(
                error.to_string(),
                "local snapshot checkpoint is owned by another daemon"
            );
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
            drop(lock);
            drop(CheckpointLock::acquire(&path).unwrap());
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// [behaviour] maintenance reserves the next turn ahead of our normal work.
    #[test]
    fn maintenance_reserves_the_next_turn_ahead_of_our_normal_work() {
        let root = crate::test_scratch::canonical_private_dir("ops-lock");
        let parent = root.join("snapshots/destinations").join("a".repeat(64));
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("claude_code-test-scan-index.json");
        let progress = serde_json::to_vec(&serde_json::json!({
            "schema_version": 3,
            "destination_namespace_hash": "a".repeat(64),
        }))
        .unwrap();
        // Native published custody: a live route with an open session.
        let index = state_v2::money_test_support::publish(&ScanIndex::default(), &path, &progress);
        assert!(state_v2::published(&path).unwrap());
        let normal = CheckpointLock::acquire(&path).unwrap();
        let (entered, acquired) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            let maintenance = CheckpointLock::acquire_for_maintenance(&worker_path).unwrap();
            entered.send(()).unwrap();
            finish
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            drop(maintenance);
        });
        let (owners, _) = checkpoint_owners()
            .1
            .wait_timeout_while(
                checkpoint_owners().0.lock().unwrap(),
                std::time::Duration::from_secs(1),
                |owners| !owners.maintenance.contains(&path),
            )
            .unwrap();
        assert!(owners.maintenance.contains(&path));
        drop(owners);
        assert!(CheckpointLock::acquire(&path).is_err());
        // Custody keeps its latch; releasing the normal owner hands the turn
        // to the reserved maintenance and new normal work still yields.
        drop(normal);
        acquired
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        assert!(state_v2::published(&path).unwrap());
        assert!(CheckpointLock::acquire(&path).is_err());
        release.send(()).unwrap();
        worker.join().unwrap();
        drop(CheckpointLock::acquire(&path).unwrap());
        drop(index);
        state_v2::money_test_support::erase_published(&path);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
pub(crate) use state_v2::money_test_support::roundtrip as state_v2_money_roundtrip;
#[cfg(test)]
pub(crate) use state_v2::money_test_support::{
    ColdSession as StateV2ColdSession, ColdStore as StateV2ColdStore,
};

#[cfg(test)]
pub(crate) use state_v2::money_test_support::publish as publish_state_v2_for_test;
#[cfg(test)]
pub(crate) use state_v2::{
    seed_tail_literals_for_test, stage_tail_for_test as state_v2_stage_tail_for_test,
    tail_published_for_test as state_v2_tail_published_for_test, TAIL_FACT_LITERALS,
};

/// Local-only recovery bypasses a save-pressure hold, never custody fencing.
/// OFF returns before allocating a guard or consulting any route state.
pub(crate) fn state_v2_recovery_save_guard(
    path: &Path,
    index: &ScanIndex,
) -> Result<Option<impl Fn() -> Result<()>>> {
    state_v2::recovery_save_guard(path, index)
}

#[cfg(test)]
fn former_file_cap(source: SnapshotSource) -> u64 {
    match source {
        SnapshotSource::ClaudeCode => 512 * 1024 * 1024,
        SnapshotSource::Codex => 2 * 1024 * 1024 * 1024,
        SnapshotSource::Pi => 256 * 1024 * 1024,
    }
}
