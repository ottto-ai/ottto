//! Privacy-safe snapshot upload receipts, one per batch attempt, kept 30 days
//! in the upload history file.

use anyhow::{Context, Result};
use ottto_protocol::{
    LocalAccountState, SourceKind, UploadReceiptEntityV1, UploadReceiptOutcomeV1, UploadReceiptV1,
    UploadReceiptsResponseV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef, SnapshotEntityRejection};
use crate::snapshots::state_v2::upload_history::{CloudAck, CloudAckWrite, Encoded, Filter, Store};
use crate::snapshots::SnapshotBatchRequest;

/// Most receipts one `ottto receipts` page returns.
pub const UPLOAD_RECEIPT_PAGE_SIZE: usize = 500;
/// The ring file earlier releases kept; now only imported once, then removed.
const UPLOAD_RECEIPTS_FILENAME: &str = "snapshot_upload_receipts.json";
const UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION: u16 = 1;
const UPLOAD_RECEIPTS_RESPONSE_SCHEMA: &str = "ottto.upload_receipts.v1";
const ID_PREFIX_LEN: usize = 12;
const MAX_SERVER_REQUEST_ID_LEN: usize = 128;
/// The process's one history writer. A failed open or write drops it; the
/// next attempt opens it again.
static HISTORY: Mutex<Option<Store>> = Mutex::new(None);
static CORRUPTION_LOGGED: AtomicBool = AtomicBool::new(false);
static APPEND_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
/// History rows this process could not write (open, lock or write failure),
/// shown as `history_rows_not_written` by `ottto receipts --json`.
static HISTORY_ROWS_NOT_WRITTEN: AtomicU64 = AtomicU64::new(0);
static IMPORT_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

thread_local! {
    static DEFERRED: RefCell<Option<Vec<(PathBuf, Encoded)>>> = const { RefCell::new(None) };
}
#[cfg(test)]
thread_local! {
    /// This thread's share of the process count, so a test can assert it
    /// exactly while other tests run.
    static ROWS_NOT_WRITTEN_HERE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The legacy ring, each row left as its borrowed JSON text so no row is
/// decoded into a generic value tree.
#[derive(Debug, Deserialize)]
struct RingFile<'a> {
    schema_version: u16,
    #[serde(borrow)]
    receipts: Vec<&'a serde_json::value::RawValue>,
}

/// The private part of one ring row. Decoded apart from the public part so
/// that unknown fields are skipped, never buffered (as `flatten` would).
#[derive(Debug, Deserialize)]
struct RingEvidence {
    #[serde(default)]
    validated_evidence: Option<ValidatedReceiptEvidence>,
}

// Internal disk fields never enter the public protocol DTO or diagnostics reader.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedReceipt {
    #[serde(flatten)]
    public: UploadReceiptV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validated_evidence: Option<ValidatedReceiptEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatedReceiptEvidence {
    schema_version: u16,
    destination_namespace_hash: String,
    api_destination_hash: String,
    producer_version: Option<String>,
    attempt_identity: String,
    head_cas: bool,
    entity_ack_contract: String,
    requested_occurrences: u64,
    requested_distinct_entities: usize,
    retained_entities: usize,
    total_entities: usize,
    outcome_occurrences: std::collections::BTreeMap<String, u64>,
    coverage: String,
    entities: Vec<ValidatedReceiptEntity>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatedReceiptEntity {
    session_hash: String,
    snapshot_fingerprint: String,
    request_occurrences: u64,
    uploaded_cache_patch_present: bool,
    uploaded_request_count: u64,
    uploaded_output_tokens: u64,
    outcome: String,
    outcome_occurrences: u64,
    request_body_witness_version: Option<u64>,
    request_body_witness_digest: String,
    acknowledged_body_witness_version: Option<u64>,
    acknowledged_body_witness_digest: Option<String>,
    accepted_head_hash: Option<String>,
    conflict_challenge_hash: Option<String>,
    // Private diagnostic only. Older receipts had no rejection comparison data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejection_usage: Option<RejectedUsageEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RejectedUsageEvidence {
    schema_version: u16,
    entity_ref: String,
    machine_ref: String,
    reason: RejectedUsageReason,
    permanent: bool,
    /// Optional classification keeps the persisted reason vocabulary compatible.
    exclusive_usage_contract: bool,
    // request, input, output, cache_read, cache_creation_5m,
    // cache_creation_1h, reasoning_output, unattributed_total.
    counters: [u64; 8],
    // total, input, output, cache_read, cache_creation. Invalid decimals are absent.
    costs_usd: [Option<String>; 5],
    semantic_activity_unix_nanos: Option<i128>,
    usage_bucket_count: usize,
    usage_grain_count: usize,
    // Sorted serialized grains; detects changes without retaining dimensions.
    usage_grain_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RejectedUsageReason {
    UsageAccountingAuthorityDowngrade,
    ReservedSessionIdentitySeparator,
    OccurredAtBeyondFutureHorizon,
    HourBucketCountAboveCap,
    DivergentDuplicateLogicalSession,
    AcceptedLogTransactionCap,
    OccurredAtBeyondWriteFenceFuture,
    OccurredAtBeyondJournalRetention,
    BodyExceedsMaxBytes,
    OccurredAtRequiresTimezone,
    OccurredAtUtcNormalizationOutOfRange,
    AcceptedLogStaleOlderUpload,
    Other,
}

impl RejectedUsageReason {
    /// Stale refusals additionally need their retained recording metadata;
    /// the wire reason alone cannot distinguish legacy owed records.
    pub(crate) fn is_dominated(self) -> bool {
        matches!(self, RejectedUsageReason::UsageAccountingAuthorityDowngrade)
    }

    pub(crate) fn from_wire(reason: &str) -> Self {
        match reason {
            "usage_accounting_authority_downgrade" => {
                RejectedUsageReason::UsageAccountingAuthorityDowngrade
            }
            "reserved_session_identity_separator" => {
                RejectedUsageReason::ReservedSessionIdentitySeparator
            }
            "occurred_at_beyond_future_horizon" => {
                RejectedUsageReason::OccurredAtBeyondFutureHorizon
            }
            "hour_bucket_count_above_cap" => RejectedUsageReason::HourBucketCountAboveCap,
            "divergent_duplicate_logical_session" => {
                RejectedUsageReason::DivergentDuplicateLogicalSession
            }
            "accepted_log_transaction_cap" => RejectedUsageReason::AcceptedLogTransactionCap,
            "accepted_log_stale_older_upload" => RejectedUsageReason::AcceptedLogStaleOlderUpload,
            "occurred_at_beyond_write_fence_future" => {
                RejectedUsageReason::OccurredAtBeyondWriteFenceFuture
            }
            "occurred_at_beyond_journal_retention" => {
                RejectedUsageReason::OccurredAtBeyondJournalRetention
            }
            "body_exceeds_max_bytes" => RejectedUsageReason::BodyExceedsMaxBytes,
            "occurred_at_requires_timezone" => RejectedUsageReason::OccurredAtRequiresTimezone,
            "occurred_at_utc_normalization_out_of_range" => {
                RejectedUsageReason::OccurredAtUtcNormalizationOutOfRange
            }
            _ => RejectedUsageReason::Other,
        }
    }
}

fn rejected_usage_evidence(
    request: &SnapshotBatchRequest,
    item: &crate::snapshots::SnapshotItem,
    rejection: &SnapshotEntityRejection,
) -> RejectedUsageEvidence {
    fn decimal(value: &Option<String>) -> Option<String> {
        value
            .as_ref()
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 32
                    && value.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                    && value.bytes().filter(|b| *b == b'.').count() <= 1
                    && value.bytes().any(|b| b.is_ascii_digit())
            })
            .cloned()
    }
    fn timestamp(value: &Option<String>) -> Option<i128> {
        OffsetDateTime::parse(value.as_deref()?, &Rfc3339)
            .ok()
            .map(|time| time.unix_timestamp_nanos())
    }
    let costs_usd = item
        .cost
        .as_ref()
        .map(|cost| {
            [
                decimal(&cost.total_cost_usd),
                decimal(&cost.input_cost_usd),
                decimal(&cost.output_cost_usd),
                decimal(&cost.cache_read_cost_usd),
                decimal(&cost.cache_creation_cost_usd),
            ]
        })
        .unwrap_or_default();
    // Persist hashes only, never model/selector/account values or arbitrary reasons.
    let mut grains = item
        .usage_buckets
        .iter()
        .flat_map(|bucket| {
            bucket
                .model_usage
                .iter()
                .map(|model| serde_json::json!([bucket.bucket_start, model]).to_string())
        })
        .collect::<Vec<_>>();
    grains.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(b"ottto.rejected_usage.grains:v1\0");
    for grain in &grains {
        digest.update((grain.len() as u64).to_be_bytes());
        digest.update(grain.as_bytes());
    }
    let entity_key = format!(
        "{}\x1f{}\x1f{}",
        request.source, request.machine_id, item.source_session_id
    );
    RejectedUsageEvidence {
        schema_version: 1,
        entity_ref: format!("{:x}", Sha256::digest(entity_key.as_bytes()))[..16].into(),
        machine_ref: format!("{:x}", Sha256::digest(request.machine_id.as_bytes()))[..12].into(),
        reason: RejectedUsageReason::from_wire(rejection.safe_reason()),
        permanent: rejection.permanent,
        exclusive_usage_contract: item.usage_accounting_contract.as_deref()
            == Some("session_exclusive_reported_usage:v1"),
        counters: [
            item.request_count,
            item.input_tokens,
            item.output_tokens,
            item.cache_read_tokens,
            item.cache_creation_5m_tokens,
            item.cache_creation_1h_tokens,
            item.reasoning_output_tokens,
            item.unattributed_total_tokens,
        ],
        costs_usd,
        semantic_activity_unix_nanos: std::iter::once(timestamp(&item.source_last_activity_at))
            .chain(
                item.usage_buckets
                    .iter()
                    .map(|bucket| timestamp(&bucket.last_activity_at)),
            )
            .flatten()
            .max(),
        usage_bucket_count: item.usage_buckets.len(),
        usage_grain_count: grains.len(),
        usage_grain_digest: format!("{:x}", digest.finalize()),
    }
}

pub(crate) fn full_hash(domain: &[u8], value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validated_evidence(
    request: &SnapshotBatchRequest,
    response: &SnapshotBatchResponse,
    destination: &str,
    api_destination: &str,
    head_cas: bool,
    attempt_time: &str,
    server_request_id: Option<&str>,
) -> Option<ValidatedReceiptEvidence> {
    let head_cas = head_cas
        || request
            .snapshots
            .iter()
            .any(|item| item.cache_observations.is_some());
    if !valid_digest(destination)
        || !valid_digest(api_destination)
        || response.disabled
        || response.entity_ack_contract.as_deref()
            != Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT)
        || response
            .validate_entity_ack_with_head_cas(request, head_cas)
            .is_err()
    {
        return None;
    }
    let mut requested = std::collections::BTreeMap::new();
    for item in &request.snapshots {
        if !valid_digest(&item.snapshot_fingerprint) {
            return None;
        }
        let entry = requested
            .entry((
                item.source_session_id.as_str(),
                item.snapshot_fingerprint.as_str(),
            ))
            .or_insert((0u64, item));
        entry.0 += 1;
    }
    let mut entities = Vec::new();
    // Failures take the bounded evidence slots first; successful siblings must
    // not erase the one rejected entity needed to diagnose a mixed page.
    for reference in &response.rejected_entities {
        let (count, item) = requested.get(&(
            reference.source_session_id.as_str(),
            reference.snapshot_fingerprint.as_str(),
        ))?;
        if entities.len() >= 50 {
            continue;
        }
        entities.push(ValidatedReceiptEntity {
            session_hash: full_hash(
                b"ottto.validated_receipt.session:v1",
                &reference.source_session_id,
            ),
            snapshot_fingerprint: reference.snapshot_fingerprint.clone(),
            request_occurrences: *count,
            uploaded_cache_patch_present: item.cache_observations.is_some(),
            uploaded_request_count: item.request_count,
            uploaded_output_tokens: item.output_tokens,
            outcome: "rejected".into(),
            outcome_occurrences: reference.occurrence_count,
            request_body_witness_version: crate::snapshots::snapshot_upload_body_witness_version(
                item,
            ),
            request_body_witness_digest: crate::snapshots::snapshot_upload_body_witness(item),
            acknowledged_body_witness_version: None,
            acknowledged_body_witness_digest: None,
            accepted_head_hash: None,
            conflict_challenge_hash: None,
            rejection_usage: Some(rejected_usage_evidence(request, item, reference)),
        });
    }
    for (outcome, refs) in [
        ("accepted", &response.accepted_entities),
        ("unchanged", &response.unchanged_entities),
        ("conflict", &response.conflict_entities),
    ] {
        for reference in refs {
            let (count, item) = requested.get(&(
                reference.source_session_id.as_str(),
                reference.snapshot_fingerprint.as_str(),
            ))?;
            if reference
                .head_etag
                .as_ref()
                .is_some_and(|v| !valid_digest(v))
                || reference
                    .head_challenge
                    .as_ref()
                    .is_some_and(|v| !valid_digest(v))
            {
                return None;
            }
            if reference
                .body_witness_digest
                .as_ref()
                .is_some_and(|v| !valid_digest(v))
            {
                return None;
            }
            if entities.len() >= 50 {
                continue;
            }
            entities.push(ValidatedReceiptEntity {
                session_hash: full_hash(
                    b"ottto.validated_receipt.session:v1",
                    &reference.source_session_id,
                ),
                snapshot_fingerprint: reference.snapshot_fingerprint.clone(),
                request_occurrences: *count,
                uploaded_cache_patch_present: item.cache_observations.is_some(),
                uploaded_request_count: item.request_count,
                uploaded_output_tokens: item.output_tokens,
                outcome: outcome.into(),
                outcome_occurrences: reference.occurrence_count,
                request_body_witness_version:
                    crate::snapshots::snapshot_upload_body_witness_version(item),
                request_body_witness_digest: crate::snapshots::snapshot_upload_body_witness(item),
                acknowledged_body_witness_version: reference.body_witness_version,
                acknowledged_body_witness_digest: reference.body_witness_digest.clone(),
                accepted_head_hash: reference
                    .head_etag
                    .as_deref()
                    .map(|h| full_hash(b"ottto.validated_receipt.head:v1", h)),
                conflict_challenge_hash: reference
                    .head_challenge
                    .as_deref()
                    .map(|h| full_hash(b"ottto.validated_receipt.challenge:v1", h)),
                rejection_usage: None,
            });
        }
    }
    let total_entities = response.accepted_entities.len()
        + response.unchanged_entities.len()
        + response.conflict_entities.len()
        + response.rejected_entities.len();
    entities.truncate(50);
    Some(ValidatedReceiptEvidence {
        schema_version: 1,
        destination_namespace_hash: destination.into(),
        api_destination_hash: api_destination.into(),
        producer_version: request
            .collector_version
            .as_ref()
            .filter(|v| {
                v.len() <= 64
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            })
            .cloned(),
        attempt_identity: full_hash(
            b"ottto.validated_receipt.attempt:v1",
            &format!(
                "{destination}:{attempt_time}:{}",
                server_request_id.unwrap_or("")
            ),
        ),
        head_cas,
        entity_ack_contract: response.entity_ack_contract.clone()?,
        requested_occurrences: request.snapshots.len() as u64,
        requested_distinct_entities: requested.len(),
        retained_entities: entities.len(),
        total_entities,
        outcome_occurrences: [
            (
                "accepted",
                response
                    .accepted_entities
                    .iter()
                    .map(|e| e.occurrence_count)
                    .sum(),
            ),
            (
                "unchanged",
                response
                    .unchanged_entities
                    .iter()
                    .map(|e| e.occurrence_count)
                    .sum(),
            ),
            (
                "conflict",
                response
                    .conflict_entities
                    .iter()
                    .map(|e| e.occurrence_count)
                    .sum(),
            ),
            (
                "rejected",
                response
                    .rejected_entities
                    .iter()
                    .map(|e| e.occurrence_count)
                    .sum(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        coverage: if total_entities <= 50 {
            "complete"
        } else {
            "truncated"
        }
        .into(),
        entities,
    })
}

/// Status-safe labels captured with a receipt. Neither value contains a raw
/// device, user, account, or organization identifier.
#[derive(Debug, Clone, Default)]
pub struct UploadReceiptContext {
    pub device_label: Option<String>,
    pub account_binding: Option<LocalAccountState>,
}

/// The ring file earlier releases wrote; read only by the one-time import.
pub fn upload_receipts_path(state_dir: &Path) -> PathBuf {
    state_dir.join(UPLOAD_RECEIPTS_FILENAME)
}

pub(crate) fn upload_history_path(state_dir: &Path) -> PathBuf {
    Store::path(&state_dir.join("snapshots"))
}

#[cfg(test)]
pub fn append_success(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    http_status: u16,
    server_request_id: Option<&str>,
    response: &SnapshotBatchResponse,
) -> Result<()> {
    append_success_with_context(
        state_dir,
        source,
        batch_item_count,
        http_status,
        server_request_id,
        response,
        &UploadReceiptContext::default(),
    )
}

pub fn append_success_with_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    http_status: u16,
    server_request_id: Option<&str>,
    response: &SnapshotBatchResponse,
    context: &UploadReceiptContext,
) -> Result<()> {
    append_success_with_evidence_context(
        state_dir,
        source,
        batch_item_count,
        http_status,
        server_request_id,
        response,
        context,
        None,
    )
}

#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
pub(crate) fn append_success_with_evidence_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    http_status: u16,
    server_request_id: Option<&str>,
    response: &SnapshotBatchResponse,
    context: &UploadReceiptContext,
    evidence_request: Option<(&SnapshotBatchRequest, &str, &str, bool)>,
) -> Result<()> {
    let outcome = if response.disabled {
        UploadReceiptOutcomeV1::Rejected
    } else if response.rejected_entities.is_empty() && response.conflict_entities.is_empty() {
        UploadReceiptOutcomeV1::Accepted
    } else if response.accepted > 0
        || !response.accepted_entities.is_empty()
        || !response.unchanged_entities.is_empty()
    {
        UploadReceiptOutcomeV1::Partial
    } else {
        UploadReceiptOutcomeV1::Rejected
    };
    let entity_limit = batch_item_count.min(50);
    let accepted_entities = response
        .accepted_entities
        .iter()
        .take(entity_limit)
        .map(sanitize_entity_ref)
        .collect::<Vec<_>>();
    let remaining = entity_limit.saturating_sub(accepted_entities.len());
    let unchanged_entities = response
        .unchanged_entities
        .iter()
        .take(remaining)
        .map(sanitize_entity_ref)
        .collect::<Vec<_>>();
    let remaining = remaining.saturating_sub(unchanged_entities.len());
    let conflict_entities = response
        .conflict_entities
        .iter()
        .take(remaining)
        .map(sanitize_entity_ref)
        .collect::<Vec<_>>();
    let remaining = remaining.saturating_sub(conflict_entities.len());
    let rejected_entities = response
        .rejected_entities
        .iter()
        .take(remaining)
        .map(sanitize_entity_rejection)
        .collect();
    let uploaded_at = now_rfc3339();
    let evidence = evidence_request.and_then(|(request, namespace, api_destination, cas)| {
        validated_evidence(
            request,
            response,
            namespace,
            api_destination,
            cas,
            &uploaded_at,
            server_request_id,
        )
    });
    // Rows keep at most 50 entities; the stored count is the response's total.
    let entity_count = response.accepted_entities.len()
        + response.unchanged_entities.len()
        + response.conflict_entities.len()
        + response.rejected_entities.len();
    record(
        state_dir,
        PersistedReceipt {
            public: UploadReceiptV1 {
                uploaded_at,
                outcome,
                http_status: Some(http_status),
                server_request_id: sanitize_server_request_id(server_request_id),
                retry_after_seconds: None,
                source,
                device_label: sanitize_device_label(context.device_label.as_deref()),
                account_binding: context.account_binding.clone(),
                batch_item_count: batch_item_count as u64,
                accepted_count: response.accepted,
                accepted_entities,
                unchanged_entities,
                conflict_entities,
                rejected_entities,
            },
            validated_evidence: evidence,
        },
        entity_count as u64,
    )
}

pub fn append_http_failure(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    outcome: UploadReceiptOutcomeV1,
    http_status: u16,
    server_request_id: Option<&str>,
    retry_after_seconds: Option<u64>,
) -> Result<()> {
    append_http_failure_with_context(
        state_dir,
        source,
        batch_item_count,
        outcome,
        http_status,
        server_request_id,
        retry_after_seconds,
        &UploadReceiptContext::default(),
    )
}

#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
pub fn append_http_failure_with_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    outcome: UploadReceiptOutcomeV1,
    http_status: u16,
    server_request_id: Option<&str>,
    retry_after_seconds: Option<u64>,
    context: &UploadReceiptContext,
) -> Result<()> {
    append(
        state_dir,
        empty_receipt(
            source,
            batch_item_count,
            outcome,
            Some(http_status),
            sanitize_server_request_id(server_request_id),
            retry_after_seconds,
            context,
        ),
    )
}

#[cfg(test)]
pub fn append_transport_error(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
) -> Result<()> {
    append_transport_error_with_context(
        state_dir,
        source,
        batch_item_count,
        &UploadReceiptContext::default(),
    )
}

pub fn append_transport_error_with_context(
    state_dir: &Path,
    source: SourceKind,
    batch_item_count: usize,
    context: &UploadReceiptContext,
) -> Result<()> {
    append(
        state_dir,
        empty_receipt(
            source,
            batch_item_count,
            UploadReceiptOutcomeV1::TransportError,
            None,
            None,
            None,
            context,
        ),
    )
}

/// Newest receipts first: the first page of [`read_page`].
pub fn read(
    state_dir: &Path,
    limit: u16,
    since: Option<&str>,
    source: Option<SourceKind>,
) -> Result<UploadReceiptsResponseV1> {
    read_page(state_dir, limit, since, source, None)
}

/// One page of receipts in append order, newest first. `before` is the
/// `next_before` cursor of the previous page. Only the public projection
/// leaves this function; private evidence never enters a response.
pub fn read_page(
    state_dir: &Path,
    limit: u16,
    since: Option<&str>,
    source: Option<SourceKind>,
    before: Option<u64>,
) -> Result<UploadReceiptsResponseV1> {
    let since_ns = since
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .with_context(|| format!("invalid receipts --since timestamp {value:?}"))
                .map(|since| clamp_ns(since.unix_timestamp_nanos()))
        })
        .transpose()?;
    let limit = usize::from(limit).min(UPLOAD_RECEIPT_PAGE_SIZE);
    let before = before.map(i64::try_from).transpose()?;
    let source = source.as_ref().map(crate::source_slug);
    let page = with_history(state_dir, false, |store| {
        store.page(&Filter {
            before,
            source,
            since_ns,
            limit,
        })
    })?;
    let mut receipts = Vec::new();
    let mut next_before = None;
    if let Some(page) = page {
        if page.examined == limit && limit > 0 {
            next_before = page.last_seq.and_then(|seq| u64::try_from(seq).ok());
        }
        receipts = page
            .rows
            .into_iter()
            .filter_map(|(_, json)| serde_json::from_slice::<PersistedReceipt>(&json).ok())
            .map(|receipt| receipt.public)
            .collect();
    }
    Ok(UploadReceiptsResponseV1 {
        schema: UPLOAD_RECEIPTS_RESPONSE_SCHEMA.to_string(),
        receipts,
        ring_capacity: UPLOAD_RECEIPT_PAGE_SIZE as u16,
        state_path_present: upload_history_path(state_dir).is_file(),
        next_before,
        history_rows_not_written: Some(HISTORY_ROWS_NOT_WRITTEN.load(Ordering::Relaxed))
            .filter(|rows| *rows > 0),
    })
}

fn empty_receipt(
    source: SourceKind,
    batch_item_count: usize,
    outcome: UploadReceiptOutcomeV1,
    http_status: Option<u16>,
    server_request_id: Option<String>,
    retry_after_seconds: Option<u64>,
    context: &UploadReceiptContext,
) -> UploadReceiptV1 {
    UploadReceiptV1 {
        uploaded_at: now_rfc3339(),
        outcome,
        http_status,
        server_request_id,
        retry_after_seconds,
        source,
        device_label: sanitize_device_label(context.device_label.as_deref()),
        account_binding: context.account_binding.clone(),
        batch_item_count: batch_item_count as u64,
        accepted_count: 0,
        accepted_entities: Vec::new(),
        unchanged_entities: Vec::new(),
        conflict_entities: Vec::new(),
        rejected_entities: Vec::new(),
    }
}

fn append(state_dir: &Path, receipt: UploadReceiptV1) -> Result<()> {
    record(
        state_dir,
        PersistedReceipt {
            public: receipt,
            validated_evidence: None,
        },
        0,
    )
}

/// Encode the attempt row now; write it now, or after the caller's progress
/// save when a [`defer`] scope is open on this thread.
fn record(state_dir: &Path, receipt: PersistedReceipt, entity_count: u64) -> Result<()> {
    let row = encode(&receipt, entity_count)?;
    let row = DEFERRED.with(|slot| match slot.borrow_mut().as_mut() {
        Some(rows) => {
            rows.push((state_dir.to_owned(), row));
            None
        }
        None => Some(row),
    });
    match row {
        Some(row) => append_now(state_dir, &row),
        None => Ok(()),
    }
}

/// Holds this thread's attempt rows until it is dropped, so a page writes
/// them after its progress save returns and its locks are free.
pub(crate) struct Deferred(());

pub(crate) fn defer() -> Deferred {
    DEFERRED.with(|slot| {
        slot.borrow_mut().get_or_insert_with(Vec::new);
    });
    Deferred(())
}

impl Drop for Deferred {
    fn drop(&mut self) {
        let rows = DEFERRED
            .try_with(|slot| slot.borrow_mut().take())
            .ok()
            .flatten()
            .unwrap_or_default();
        for (state_dir, row) in rows {
            if append_now(&state_dir, &row).is_err() {
                note_append_failure();
            }
        }
    }
}

/// One history row was not written. Every such row is counted; the first is
/// also logged. It never holds, refuses or retries an upload.
pub(crate) fn note_append_failure() {
    HISTORY_ROWS_NOT_WRITTEN.fetch_add(1, Ordering::Relaxed);
    #[cfg(test)]
    ROWS_NOT_WRITTEN_HERE.with(|rows| rows.set(rows.get() + 1));
    if !APPEND_FAILURE_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!("ottto-service: snapshot upload receipt persistence failed");
    }
}

fn append_now(state_dir: &Path, row: &Encoded) -> Result<()> {
    with_history(state_dir, true, |store| {
        store.append(
            row,
            clamp_ns(OffsetDateTime::now_utc().unix_timestamp_nanos()),
        )
    })?;
    Ok(())
}

/// Run `f` on the history writer for `state_dir`, opening it (and importing
/// any ring file) first. Without `create`, a support directory with neither a
/// history nor a ring file is reported as empty and nothing is created.
fn with_history<T>(
    state_dir: &Path,
    create: bool,
    f: impl FnOnce(&mut Store) -> Result<T>,
) -> Result<Option<T>> {
    let mut history = HISTORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = upload_history_path(state_dir);
    // Production passes one support directory; another one reopens.
    if history
        .as_ref()
        .is_some_and(|store| store.file_path() != path.as_path())
    {
        *history = None;
    }
    if history.is_none() {
        if !create && !path.exists() && !upload_receipts_path(state_dir).exists() {
            return Ok(None);
        }
        *history = Some(open_history(state_dir)?);
    }
    let result = f(history.as_mut().context("upload_history_unavailable")?);
    if result.is_err() {
        *history = None;
    }
    result.map(Some)
}

/// The Codex cloud-task ACK cache shares this owner for short SQL operations
/// only. Its failures are cloud cache failures: they never count as receipt
/// rows not written and never affect local delivery.
pub(crate) fn cloud_read_acks(
    state_dir: &Path,
    scope: &[u8; 32],
    keys: &[&str],
    now_unix: i64,
) -> Result<std::collections::HashMap<String, CloudAck>> {
    Ok(with_history(state_dir, true, |store| {
        store.cloud_read_acks(scope, keys, now_unix)
    })?
    .unwrap_or_default())
}

pub(crate) fn cloud_commit(
    state_dir: &Path,
    scope: &[u8; 32],
    acks: &[CloudAckWrite<'_>],
    crawl_completed_date: Option<&str>,
    now_unix: i64,
) -> Result<()> {
    with_history(state_dir, true, |store| {
        store.cloud_commit(scope, acks, crawl_completed_date, now_unix)
    })?;
    Ok(())
}

pub(crate) fn cloud_crawl_completed_date(
    state_dir: &Path,
    scope: &[u8; 32],
) -> Result<Option<String>> {
    Ok(with_history(state_dir, true, |store| {
        store.cloud_crawl_completed_date(scope)
    })?
    .flatten())
}

/// Erase the whole cloud cache after a local revoke. An absent history file
/// has nothing to erase and is not created.
pub(crate) fn cloud_erase_all(state_dir: &Path) -> Result<()> {
    with_history(state_dir, false, Store::cloud_erase_all)?;
    Ok(())
}

fn open_history(state_dir: &Path) -> Result<Store> {
    use std::os::unix::fs::DirBuilderExt;
    let snapshots = state_dir.join("snapshots");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&snapshots)?;
    let mut store = Store::open(&Store::path(&snapshots))?;
    // A failed import keeps the ring file for the next open, so no row is
    // lost and nothing is counted as not written.
    if import_ring(state_dir, &mut store).is_err()
        && !IMPORT_FAILURE_LOGGED.swap(true, Ordering::Relaxed)
    {
        eprintln!("ottto-service: snapshot upload receipt ring import failed; kept for retry");
    }
    Ok(store)
}

/// Import every row of the legacy ring file, oldest first, in one
/// transaction, then remove the file. Rows an earlier import of the same file
/// stored are skipped. A failure keeps the file for the next open.
fn import_ring(state_dir: &Path, store: &mut Store) -> Result<()> {
    let path = upload_receipts_path(state_dir);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file(), "upload_receipt_ring_unimportable");
    // Peak memory is the file (the old writers kept it under 4 MiB) plus the
    // encoded rows: each row is decoded typed from its own bytes, encoded,
    // and dropped.
    let bytes = std::fs::read(&path).context("read upload receipt ring")?;
    let ring = match serde_json::from_slice::<RingFile<'_>>(&bytes) {
        Ok(ring) if ring.schema_version == UPLOAD_RECEIPTS_DISK_SCHEMA_VERSION => ring,
        Ok(_) | Err(_) => {
            quarantine_corrupt_file(&path);
            return Ok(());
        }
    };
    let mut rows = Vec::with_capacity(ring.receipts.len());
    for raw in ring.receipts {
        // One undecodable row quarantines the whole file, like a bad file.
        let (Ok(public), Ok(private)) = (
            serde_json::from_str::<UploadReceiptV1>(raw.get()),
            serde_json::from_str::<RingEvidence>(raw.get()),
        ) else {
            quarantine_corrupt_file(&path);
            return Ok(());
        };
        let entity_count = private
            .validated_evidence
            .as_ref()
            .map(|evidence| evidence.total_entities)
            .unwrap_or(
                public.accepted_entities.len()
                    + public.unchanged_entities.len()
                    + public.conflict_entities.len()
                    + public.rejected_entities.len(),
            );
        rows.push(encode(
            &PersistedReceipt {
                public,
                validated_evidence: private.validated_evidence,
            },
            entity_count as u64,
        )?);
    }
    store.import_ring(&rows)?;
    std::fs::remove_file(&path)?;
    Ok(())
}

fn encode(receipt: &PersistedReceipt, entity_count: u64) -> Result<Encoded> {
    let json = serde_json::to_vec(receipt).context("serialize upload receipt")?;
    let uploaded_at_ns = OffsetDateTime::parse(&receipt.public.uploaded_at, &Rfc3339)
        .map(|at| clamp_ns(at.unix_timestamp_nanos()))
        .unwrap_or(0);
    Encoded::new(
        uploaded_at_ns,
        crate::source_slug(&receipt.public.source),
        entity_count,
        &json,
    )
}

fn clamp_ns(ns: i128) -> i64 {
    ns.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn quarantine_corrupt_file(path: &Path) {
    let suffix = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let quarantine = path.with_extension(format!("json.corrupt.{suffix}"));
    let _ = std::fs::rename(path, quarantine);
    if !CORRUPTION_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "ottto-service: corrupt snapshot upload receipt ring was quarantined; it was not imported"
        );
    }
}

/// Every stored private row, oldest first, for tests that inspect evidence.
#[cfg(test)]
pub(crate) fn private_rows_for_test(state_dir: &Path) -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    let mut before = None;
    loop {
        let page = with_history(state_dir, false, |store| {
            store.page(&Filter {
                before,
                source: None,
                since_ns: None,
                limit: UPLOAD_RECEIPT_PAGE_SIZE,
            })
        })
        .unwrap();
        let Some(page) = page else { break };
        rows.extend(
            page.rows
                .iter()
                .map(|(_, json)| serde_json::from_slice::<serde_json::Value>(json).unwrap()),
        );
        if page.examined < UPLOAD_RECEIPT_PAGE_SIZE {
            break;
        }
        before = page.last_seq;
    }
    rows.reverse();
    rows
}

fn sanitize_entity_ref(entity: &SnapshotEntityRef) -> UploadReceiptEntityV1 {
    sanitized_entity(
        &entity.source_session_id,
        &entity.snapshot_fingerprint,
        entity.occurrence_count,
    )
}

fn sanitize_entity_rejection(entity: &SnapshotEntityRejection) -> UploadReceiptEntityV1 {
    sanitized_entity(
        &entity.source_session_id,
        &entity.snapshot_fingerprint,
        entity.occurrence_count,
    )
}

fn sanitized_entity(
    source_session_id: &str,
    snapshot_fingerprint: &str,
    occurrence_count: u64,
) -> UploadReceiptEntityV1 {
    UploadReceiptEntityV1 {
        source_session_id_hash: digest_prefix(
            b"ottto.upload_receipt.source_session_id:v1",
            source_session_id,
        ),
        snapshot_fingerprint_prefix: if snapshot_fingerprint.len() >= ID_PREFIX_LEN
            && snapshot_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            snapshot_fingerprint[..ID_PREFIX_LEN].to_ascii_lowercase()
        } else {
            digest_prefix(
                b"ottto.upload_receipt.snapshot_fingerprint:v1",
                snapshot_fingerprint,
            )
        },
        occurrence_count,
    }
}

fn digest_prefix(domain: &[u8], value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(value.as_bytes());
    let encoded = format!("{:x}", digest.finalize());
    encoded[..ID_PREFIX_LEN].to_string()
}

fn sanitize_server_request_id(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= MAX_SERVER_REQUEST_ID_LEN)
        .filter(|value| {
            value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        })
        .map(str::to_string)
}

fn sanitize_device_label(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .chars()
                .filter(|character| !character.is_control())
                .take(80)
                .collect::<String>()
        })
        .filter(|value| !value.is_empty())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod history_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRef};
    use crate::test_scratch::ScratchDir;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir() -> ScratchDir {
        ScratchDir::canonical("ottto-upload-receipts")
    }

    pub(super) fn response(raw_id: &str) -> SnapshotBatchResponse {
        SnapshotBatchResponse {
            conflict_rescans: Default::default(),
            accepted: 1,
            sessions_reconciled: 1,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: Some("snapshot_entity_ack:v1".to_string()),
            accepted_entities: vec![SnapshotEntityRef {
                source_session_id: raw_id.to_string(),
                snapshot_fingerprint:
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
                occurrence_count: 1,
                body_witness_version: None,
                body_witness_digest: None,
                head_etag: None,
                head_challenge: None,
                unchanged_basis: None,
                retained_proof_missing: Vec::new(),
                cache_observations_state: None,
            }],
            unchanged_entities: Vec::new(),
            rejected_entities: Vec::new(),
            conflict_entities: Vec::new(),
        }
    }

    pub(super) fn proof_request(source: &str, cache: bool) -> SnapshotBatchRequest {
        let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        if !cache {
            item.cache_observations = None;
            item.cache_observations_state = None;
        }
        SnapshotBatchRequest {
            schema_version: crate::snapshots::SNAPSHOT_SCHEMA_VERSION,
            source: source.into(),
            machine_id: "a".repeat(64),
            collector_version: Some("0.1.synthetic".into()),
            snapshots: vec![item],
            upload_policy: crate::snapshots::SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        }
    }
    pub(super) fn proof_response(
        request: &SnapshotBatchRequest,
        cas: bool,
    ) -> SnapshotBatchResponse {
        let mut ack = response(&request.snapshots[0].source_session_id);
        ack.accepted_entities[0].snapshot_fingerprint =
            request.snapshots[0].snapshot_fingerprint.clone();
        if request.snapshots[0].cache_observations.is_some() {
            ack.accepted_entities[0].body_witness_version = Some(14);
            ack.accepted_entities[0].body_witness_digest = Some(
                crate::snapshots::snapshot_upload_body_witness(&request.snapshots[0]),
            );
        }
        ack.accepted_entities[0].head_etag = cas.then(|| "e".repeat(64));
        ack
    }
    fn evidence(
        request: &SnapshotBatchRequest,
        ack: &SnapshotBatchResponse,
        cas: bool,
    ) -> Option<ValidatedReceiptEvidence> {
        validated_evidence(
            request,
            ack,
            &"a".repeat(64),
            &"b".repeat(64),
            cas,
            "2026-10-03T00:00:00Z",
            Some("safe-request"),
        )
    }

    #[test]
    fn private_proof_refuses_unvalidated_legacy_disabled_and_foreign_acks() {
        let request = proof_request("codex", true);
        let good = proof_response(&request, true);
        assert!(evidence(&request, &good, true).is_some());
        assert!(validated_evidence(
            &request,
            &good,
            &"a".repeat(64),
            "short",
            true,
            "synthetic",
            None
        )
        .is_none());
        for kind in [
            "foreign",
            "missing_body",
            "bad_body",
            "missing_head",
            "short_head",
            "duplicate",
            "short_fp",
            "short_partition",
            "legacy",
            "disabled",
        ] {
            let mut req = request.clone();
            let mut ack = good.clone();
            match kind {
                "foreign" => ack.accepted_entities[0].source_session_id = "unrequested".into(),
                "missing_body" => {
                    ack.accepted_entities[0].body_witness_version = None;
                    ack.accepted_entities[0].body_witness_digest = None;
                }
                "bad_body" => ack.accepted_entities[0].body_witness_digest = Some("f".repeat(64)),
                "missing_head" => ack.accepted_entities[0].head_etag = None,
                "short_head" => ack.accepted_entities[0].head_etag = Some("e".repeat(12)),
                "duplicate" => ack.accepted_entities.push(ack.accepted_entities[0].clone()),
                "short_fp" => {
                    req.snapshots[0].snapshot_fingerprint = "123456789abc".into();
                    ack.accepted_entities[0].snapshot_fingerprint = "123456789abc".into();
                }
                "short_partition" => ack.accepted_entities.clear(),
                "legacy" => {
                    ack.entity_ack_contract = None;
                    ack.accepted_entities.clear();
                }
                "disabled" => {
                    ack.disabled = true;
                    ack.accepted = 0;
                    ack.accepted_entities.clear();
                }
                _ => unreachable!(),
            }
            assert!(evidence(&req, &ack, true).is_none(), "{kind}");
        }
        let ordinary = proof_request("codex", false);
        let mut legacy = proof_response(&ordinary, false);
        legacy.entity_ack_contract = None;
        legacy.accepted_entities.clear();
        assert!(legacy
            .validate_entity_ack_with_head_cas(&ordinary, false)
            .is_ok());
        assert!(evidence(&ordinary, &legacy, false).is_none());
    }

    #[test]
    fn private_proof_retains_mixed_multiplicity_without_content_and_projects_v1() {
        let dir = temp_dir();
        let mut request = proof_request("claude_code", true);
        let first = request.snapshots[0].clone();
        request.snapshots.push(first.clone());
        for n in 2..5 {
            let mut item = first.clone();
            item.snapshot_fingerprint = format!("{n:064x}");
            request.snapshots.push(item);
        }
        let mut ack = proof_response(&request, true);
        ack.accepted = 3;
        ack.accepted_entities[0].occurrence_count = 2;
        let mut unchanged = ack.accepted_entities[0].clone();
        unchanged.snapshot_fingerprint = request.snapshots[2].snapshot_fingerprint.clone();
        unchanged.occurrence_count = 1;
        ack.unchanged_entities.push(unchanged.clone());
        let mut conflict = unchanged;
        conflict.snapshot_fingerprint = request.snapshots[3].snapshot_fingerprint.clone();
        conflict.head_etag = None;
        conflict.head_challenge = Some("c".repeat(64));
        ack.conflict_entities.push(conflict);
        ack.rejected_entities.push(SnapshotEntityRejection {
            source_session_id: first.source_session_id.clone(),
            snapshot_fingerprint: request.snapshots[4].snapshot_fingerprint.clone(),
            occurrence_count: 1,
            reason: "synthetic".into(),
            detail: "must-not-persist".into(),
            permanent: true,
        });
        let proof = evidence(&request, &ack, true).unwrap();
        assert_eq!(proof.requested_occurrences, 5);
        assert_eq!(proof.requested_distinct_entities, 4);
        assert_eq!(proof.outcome_occurrences["accepted"], 2);
        assert_eq!(proof.outcome_occurrences.values().sum::<u64>(), 5);
        assert_eq!(proof.entities.len(), 4);
        assert_eq!(proof.entities[1].request_occurrences, 2);
        assert!(proof.entities[1].uploaded_cache_patch_present);
        assert_eq!(
            proof.entities[1].uploaded_request_count,
            first.request_count
        );
        assert_eq!(
            proof.entities[1].uploaded_output_tokens,
            first.output_tokens
        );
        assert_eq!(proof.entities[1].outcome_occurrences, 2);
        assert_eq!(
            proof
                .entities
                .iter()
                .map(|e| e.outcome.as_str())
                .collect::<Vec<_>>(),
            ["rejected", "accepted", "unchanged", "conflict"]
        );
        assert!(proof.entities[3].accepted_head_hash.is_none());
        assert!(proof.entities[3].conflict_challenge_hash.is_some());
        append_success_with_evidence_context(
            &dir,
            SourceKind::ClaudeCode,
            5,
            200,
            Some("safe-request"),
            &ack,
            &UploadReceiptContext::default(),
            Some((&request, &"a".repeat(64), &"b".repeat(64), true)),
        )
        .unwrap();
        let private = private_rows_for_test(&dir);
        assert!(private[0]["validated_evidence"].is_object());
        let public = read(&dir, 500, None, None).unwrap();
        let public_json = serde_json::to_string(&public).unwrap();
        assert!(!public_json.contains("validated_evidence"));
        assert!(!public_json.contains(&first.snapshot_fingerprint));
        let disk = serde_json::to_string(&private).unwrap();
        assert!(!disk.contains(&first.source_session_id));
        assert!(!disk.contains(&"e".repeat(64)));
        assert!(!disk.contains("must-not-persist"));
        assert_eq!(
            std::fs::metadata(upload_history_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Namespace/API changes identify different destinations; attempts are distinct.
        let other = validated_evidence(
            &request,
            &ack,
            &"d".repeat(64),
            &"f".repeat(64),
            true,
            "2026-10-03T00:00:01Z",
            Some("safe-request"),
        )
        .unwrap();
        assert_ne!(
            proof.destination_namespace_hash,
            other.destination_namespace_hash
        );
        assert_ne!(proof.api_destination_hash, other.api_destination_hash);
        assert_ne!(proof.attempt_identity, other.attempt_identity);
    }

    #[test]
    fn rejected_usage_survives_successful_siblings_and_old_receipts() {
        let mut request = proof_request("claude_code", false);
        let first = request.snapshots[0].clone();
        request.snapshots = (1..=51)
            .map(|n| {
                let mut item = first.clone();
                item.snapshot_fingerprint = format!("{n:064x}");
                item
            })
            .collect();
        let mut ack = proof_response(&request, false);
        let template = ack.accepted_entities[0].clone();
        ack.accepted = 50;
        ack.accepted_entities = request.snapshots[..50]
            .iter()
            .map(|item| {
                let mut entity = template.clone();
                entity.snapshot_fingerprint = item.snapshot_fingerprint.clone();
                entity
            })
            .collect();
        ack.rejected_entities.push(SnapshotEntityRejection {
            source_session_id: first.source_session_id.clone(),
            snapshot_fingerprint: request.snapshots[50].snapshot_fingerprint.clone(),
            occurrence_count: 1,
            reason: "usage_accounting_authority_downgrade".into(),
            detail: "private-server-detail".into(),
            permanent: true,
        });
        let proof = evidence(&request, &ack, false).unwrap();
        assert_eq!(proof.coverage, "truncated");
        assert_eq!(proof.retained_entities, 50);
        assert_eq!(proof.total_entities, 51);
        let failure = &proof.entities[0];
        assert_eq!(failure.outcome, "rejected");
        assert_eq!(
            failure.snapshot_fingerprint,
            request.snapshots[50].snapshot_fingerprint
        );
        assert_eq!(
            failure.rejection_usage.as_ref().unwrap().reason,
            RejectedUsageReason::UsageAccountingAuthorityDowngrade
        );
        // Internal extension is optional: old ring rows decode with no invented evidence.
        let mut old = serde_json::to_value(failure).unwrap();
        old.as_object_mut().unwrap().remove("rejection_usage");
        let old: ValidatedReceiptEntity = serde_json::from_value(old).unwrap();
        assert!(old.rejection_usage.is_none());
    }

    #[test]
    fn unknown_rejection_reasons_still_map_to_other_and_old_other_decodes() {
        assert_eq!(
            RejectedUsageReason::from_wire("future-private-reason"),
            RejectedUsageReason::Other
        );
        let old: RejectedUsageReason = serde_json::from_str("\"other\"").unwrap();
        assert_eq!(old, RejectedUsageReason::Other);
        assert_eq!(serde_json::to_string(&old).unwrap(), "\"other\"");
    }

    #[test]
    fn rejected_usage_is_content_free_and_detects_changed_floors_and_grain() {
        let mut request = proof_request("claude_code", false);
        let item = &mut request.snapshots[0];
        item.input_tokens = 123;
        item.cache_creation_5m_tokens = 456;
        item.cache_creation_1h_tokens = 789;
        item.source_last_activity_at = Some("2026-10-09T01:00:00Z".into());
        item.cost = Some(crate::snapshots::SnapshotCost {
            total_cost_usd: Some("1.234560".into()),
            input_cost_usd: Some("secret-cost".into()),
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
            evidence_source: "secret-cost-source".into(),
        });
        let mut model = item.model_usage[0].clone();
        model.model = "secret-model".into();
        model.account_identifier_hash = Some("secret-account".into());
        item.usage_buckets = vec![crate::snapshots::SnapshotUsageBucket {
            bucket_start: "2026-10-09T01:00:00Z".into(),
            model_usage: vec![model.clone(), model],
            first_activity_at: None,
            last_activity_at: Some("2026-10-09T01:30:00Z".into()),
        }];
        let rejection = SnapshotEntityRejection {
            source_session_id: item.source_session_id.clone(),
            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
            occurrence_count: 1,
            reason: "secret-reason".into(),
            detail: "secret-detail".into(),
            permanent: true,
        };
        let before = rejected_usage_evidence(&request, &request.snapshots[0], &rejection);
        assert_eq!(before.reason, RejectedUsageReason::Other);
        assert_eq!(before.counters[1], 123);
        assert_eq!(&before.counters[4..6], &[456, 789]);
        assert_eq!(before.costs_usd[0].as_deref(), Some("1.234560"));
        assert!(before.costs_usd[1].is_none());
        assert_eq!(before.usage_grain_count, 2);
        assert_eq!(
            before.semantic_activity_unix_nanos,
            Some(
                OffsetDateTime::parse("2026-10-09T01:30:00Z", &Rfc3339)
                    .unwrap()
                    .unix_timestamp_nanos()
            )
        );
        let expected_key = format!(
            "claude_code\x1f{}\x1f{}",
            request.machine_id, request.snapshots[0].source_session_id
        );
        assert_eq!(
            before.entity_ref,
            format!("{:x}", Sha256::digest(expected_key.as_bytes()))[..16]
        );
        let bytes = serde_json::to_string(&before).unwrap();
        assert!(!bytes.contains("secret-"));
        assert!(!bytes.contains(&request.snapshots[0].source_session_id));
        request.snapshots[0].usage_buckets[0].model_usage[0].input_tokens += 1;
        request.snapshots[0].input_tokens += 1;
        let after = rejected_usage_evidence(&request, &request.snapshots[0], &rejection);
        assert_ne!(before.counters, after.counters);
        assert_ne!(before.usage_grain_digest, after.usage_grain_digest);
        request.snapshots[0].usage_buckets[0].model_usage.reverse();
        let reordered = rejected_usage_evidence(&request, &request.snapshots[0], &rejection);
        assert_eq!(after.usage_grain_digest, reordered.usage_grain_digest);
    }

    #[test]
    fn private_proof_truncation_and_old_ring_rows_remain_readable() {
        let dir = temp_dir();
        let mut request = proof_request("codex", false);
        let first = request.snapshots[0].clone();
        request.snapshots.clear();
        for n in 1..=51 {
            let mut item = first.clone();
            item.snapshot_fingerprint = format!("{n:064x}");
            request.snapshots.push(item);
        }
        let mut ack = proof_response(&request, false);
        ack.accepted = 51;
        ack.accepted_entities = (0..51)
            .map(|n| {
                let mut e = ack.accepted_entities[0].clone();
                e.snapshot_fingerprint = request.snapshots[n].snapshot_fingerprint.clone();
                e
            })
            .collect();
        let proof = evidence(&request, &ack, false).unwrap();
        assert_eq!(proof.total_entities, 51);
        assert_eq!(proof.retained_entities, 50);
        assert_eq!(proof.coverage, "truncated");
        assert!(!proof.entities[1].uploaded_cache_patch_present);
        append_success_with_evidence_context(
            &dir,
            SourceKind::Codex,
            51,
            200,
            None,
            &ack,
            &UploadReceiptContext::default(),
            Some((&request, &"a".repeat(64), &"b".repeat(64), false)),
        )
        .unwrap();
        // Rows keep the 50-entity truncation and store the response's total.
        let stored = private_rows_for_test(&dir);
        assert_eq!(stored[0]["accepted_entities"].as_array().unwrap().len(), 50);
        assert_eq!(stored[0]["validated_evidence"]["total_entities"], 51);
        assert_eq!(super::history_tests::entity_counts(&dir), vec![51]);
        // A ring row written before private evidence existed imports as is.
        let old = read(&dir, 1, None, None).unwrap().receipts.remove(0);
        let other = temp_dir();
        std::fs::write(
            upload_receipts_path(&other),
            serde_json::to_vec(&serde_json::json!({"schema_version":1,"receipts":[old]})).unwrap(),
        )
        .unwrap();
        let migrated = private_rows_for_test(&other);
        assert!(migrated[0].get("validated_evidence").is_none());
        assert_eq!(read(&other, 1, None, None).unwrap().receipts[0], old);
        assert!(!upload_receipts_path(&other).exists());
    }

    #[test]
    fn append_is_private_sanitized_and_keeps_every_attempt() {
        let dir = temp_dir();
        let raw_id = "raw-session-id-must-never-be-stored";
        let context = UploadReceiptContext {
            device_label: Some("  Test\nMac  ".to_string()),
            account_binding: Some(LocalAccountState::Connected),
        };
        for _ in 0..=UPLOAD_RECEIPT_PAGE_SIZE {
            append_success_with_context(
                &dir,
                SourceKind::Codex,
                1,
                200,
                Some("request-safe-123"),
                &response(raw_id),
                &context,
            )
            .unwrap();
        }
        let result = read(&dir, 500, None, None).unwrap();
        assert_eq!(result.receipts.len(), UPLOAD_RECEIPT_PAGE_SIZE);
        let older = read_page(&dir, 500, None, None, result.next_before).unwrap();
        assert_eq!(older.receipts.len(), 1, "no attempt is evicted");
        assert_eq!(older.next_before, None);
        assert_eq!(
            result.receipts[0].accepted_entities[0]
                .source_session_id_hash
                .len(),
            12
        );
        assert_eq!(
            result.receipts[0].accepted_entities[0].snapshot_fingerprint_prefix,
            "abcdef012345"
        );
        assert_eq!(result.receipts[0].device_label.as_deref(), Some("TestMac"));
        assert_eq!(
            result.receipts[0].account_binding,
            Some(LocalAccountState::Connected)
        );
        let private = serde_json::to_string(&private_rows_for_test(&dir)).unwrap();
        assert!(!private.contains(raw_id));
        assert_eq!(
            std::fs::metadata(upload_history_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let state_files = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(state_files, vec!["snapshots"]);
    }

    #[test]
    fn an_idle_source_keeps_its_receipt_past_500_newer_attempts() {
        let dir = temp_dir();
        append_transport_error(&dir, SourceKind::Pi, 7).unwrap();
        for n in 0..500 {
            append_transport_error(&dir, SourceKind::Codex, n).unwrap();
        }
        let pi = read(&dir, 500, None, Some(SourceKind::Pi)).unwrap();
        assert_eq!(pi.receipts.len(), 1, "the older Pi attempt must be kept");
        assert_eq!(pi.receipts[0].batch_item_count, 7);
        let codex = read(&dir, 500, None, Some(SourceKind::Codex)).unwrap();
        assert_eq!(codex.receipts.len(), 500);
        assert_eq!(codex.receipts[0].batch_item_count, 499);
    }

    #[test]
    fn corrupt_ring_is_quarantined_and_recovers_on_append() {
        let dir = temp_dir();
        std::fs::write(upload_receipts_path(&dir), b"not json").unwrap();
        let empty = read(&dir, 50, None, None).unwrap();
        assert!(empty.receipts.is_empty());
        assert!(std::fs::read_dir(&dir).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".corrupt.")));
        append_transport_error(&dir, SourceKind::Pi, 3).unwrap();
        assert_eq!(read(&dir, 50, None, None).unwrap().receipts.len(), 1);
    }
}

crate::heap_layout_bound::fields!(UploadReceiptContext; device_label, account_binding);

impl crate::heap_layout_bound::HeapLayoutBound for RejectedUsageReason {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::UsageAccountingAuthorityDowngrade
            | Self::ReservedSessionIdentitySeparator
            | Self::OccurredAtBeyondFutureHorizon
            | Self::HourBucketCountAboveCap
            | Self::DivergentDuplicateLogicalSession
            | Self::AcceptedLogTransactionCap
            | Self::OccurredAtBeyondWriteFenceFuture
            | Self::OccurredAtBeyondJournalRetention
            | Self::BodyExceedsMaxBytes
            | Self::OccurredAtRequiresTimezone
            | Self::OccurredAtUtcNormalizationOutOfRange
            | Self::AcceptedLogStaleOlderUpload
            | Self::Other => counter.add(0),
        }
    }
}
