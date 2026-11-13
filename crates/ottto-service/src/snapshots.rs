#![deny(clippy::mod_module_files)]

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
    ($index:expr_2021, $growth:expr_2021) => {
        $crate::snapshots::DiscoveryRetention {
            growth: Some($growth),
            ..discovery_retention!($index)
        }
    };
    ($index:expr_2021) => {
        $crate::snapshots::DiscoveryRetention {
            files: &$index.files,
            confirmed_empty: &$index.confirmed_empty_files,
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
        $vis:vis fn $with:ident: $ty:ty = $init:expr_2021; clear_poison: $clear:literal
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

pub(crate) use usage::cache_observations;

use scan::read_cause as change_reason;
use sources::claude::context_file_birth as claude_context_file_birth;
#[cfg(test)]
pub(crate) use upload::tests::cache_overcap as cache_overcap_tests;
pub(crate) mod claude_cross_root_evidence;
use upload::context_read as upload_context_read;
mod upload_context_receipt;
pub(crate) use upload_context_receipt::Candidate as UploadContextReceiptCandidate;
pub(crate) use upload_context_receipt::ContextInputs as UploadContextInputs;
#[cfg(test)]
pub(crate) mod privacy_flip_modes;
#[cfg(test)]
mod upload_context_receipt_tests;
#[cfg(test)]
pub(crate) use claude_context_file_birth::with_remembered_tripwire_restored_for_test;
pub use claude_context_file_birth::{ClaudeContextBasisCounts, ClaudeContextFileBirthCounts};
pub(crate) use claude_context_file_birth::{
    ClaudeFileBirth, ClaudeFileBirthVerdict, ClaudeVetoApiRows,
};
pub mod claude_copy_prefix_reread;
mod claude_history_upgrade;
use sources::codex::root_copies as codex_root_copies;

#[cfg(test)]
pub(crate) use claude_history_upgrade::{
    local_count as history_local_count, with_max_gated_claude_revision,
    LocalCount as HistoryLocalCount, REQUEST_OWNED_USAGE_CONTRACT,
};
use ownership_diagnostics as ownership;
pub(crate) use scan::ownership_diagnostics;
#[cfg(test)]
mod admission_reoffer_window_tests;
#[cfg(test)]
mod claude_history_upgrade_tests;
mod claude_reemission_exclusions;
#[cfg(all(test, unix))]
mod claude_terminal_e2_retry_tests;
#[cfg(test)]
mod contract5_cutover_tests;
use upload::freshness_debt as g7_debt;
pub(crate) use upload::money_freshness;

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
mod codex_counting_v2_tests;
use sources::codex::counting::version as codex_counting_version;
use sources::codex::dictionary_slots as codex_dictionary_slots;
mod codex_file_join;
pub(crate) use codex_file_join::CODEX_JOIN_VALIDATION_FAILURES;

#[cfg(test)]
pub(crate) use codex_counting_version::TestCutover;
#[cfg(test)]
pub(in crate::snapshots) use codex_file_join::tests::older_build_logs_tier;
#[cfg(test)]
pub(crate) use codex_file_join::tests::{
    counting_v2_fixture, native_join_fixture_root, older_build_logs_expired,
    older_build_logs_priority,
};
use sources::claude::response_records as claude_response_records;
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
use sources::codex::eof_fragment as codex_fragment;
pub(crate) use sources::codex::mcp_version as codex_version;
pub(crate) mod discovery_growth;
#[cfg(test)]
mod discovery_growth_tests;
#[cfg(unix)]
pub(crate) use scan::durable_sources;
#[cfg(test)]
pub(crate) mod e2_pipeline_scan_fixture;
#[cfg(test)]
mod held_audit_restore_tests;
#[cfg(test)]
mod resident_wave_tests;
pub(crate) use scan::lines::delivery as line_delivery;
#[cfg(test)]
use scan::lines::delivery::tests as line_delivery_tests;
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
pub(crate) use sources::claude::account::withheld as withheld_account;
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

mod lenient_decode;
#[cfg(test)]
mod lenient_decode_tests;
pub(crate) use upload::terminal_contract_retry;

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

/// RAM-only traversal/admission observations for receipts and ordinary pacing.
/// This projection changes no census decision or durable field.
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
    pub(crate) charge_deferred: bool,
    /// Selection filled the effective AIMD file allowance before family deferrals.
    pub(crate) page_file_limit_hit: bool,
    /// This process started the generation after a clean census completion.
    pub(crate) routine_recensus: bool,
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
    CodexStateThread, CodexTitleMetadata,
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
use usage::cache_observations::upload::cache_state_within_limits;
use usage::cache_observations::upload::cache_wire;
pub(crate) use usage::cache_observations::upload::{
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

pub(crate) use discovery::directory::FIRST_READ_WINDOW_DAYS;

#[cfg(test)]
use discovery::directory::{
    advance_bounded_directory_traversal, collect_recent_jsonl_files,
    reconcile_missing_index_entries_with_limit, reconcile_missing_index_entries_with_side,
    with_directory_read_fault, with_test_directory_entries,
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

use claude_reemission_exclusions::{
    claude_reemission_stop_latched, claude_reemission_stop_reason,
    claude_reemission_stop_withheld_folds, note_claude_reemission_stop,
    note_claude_reemission_stop_with_cause_at, ClaudeReemissionStopCause,
};
#[cfg(test)]
pub(crate) use claude_reemission_exclusions::{
    restart_claude_reemission_stop_for_test, with_claude_reemission_stop_restored_for_test,
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
mod source_session_id_tests;

use scan::json_fields::{string_at, string_eq_at, u64_at};

#[cfg(test)]
use scan_index::file_set_digest::snapshot_file_entity_set_digest;
pub(crate) use scan_index::file_set_digest::snapshot_file_upload_body_set_hex;
use scan_index::file_set_digest::{
    sha256_digest, sha256_hex, sha256_hex_owned, snapshot_file_entity_set_hex,
    snapshot_file_upload_body_set_digest, update_length_prefixed, PrefixDigest,
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
) -> impl Fn() -> Result<()> + use<> {
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

// The upload-progress rows of a routed source.
pub(crate) use state_v2::{
    import_progress_rows, read_progress_ledger, read_progress_rows, ProgressMarker, ProgressPage,
    ProgressPoint, ProgressRead, ProgressRows,
};
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
pub(crate) fn state_v2_post_pass_observed(
    relief: crate::local_resource_diagnostics::AllocatorRelief,
) {
    state_v2::telemetry::plateau(relief);
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
) -> Result<Option<impl Fn() -> Result<()> + use<>>> {
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
