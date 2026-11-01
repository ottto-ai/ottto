// Complete 0.1.205 progress serde codec from source 562a40128.
// Source-span SHA256 ce35679eecbdd147642ceddab4c037ade617fdcf380d102bd4ddcf1655b4bf8c
use super::*;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SnapshotUploadProgress {
    schema_version: u16,
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
    #[serde(default)]
    accepted_cache_heads: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pending_cache_heads: BTreeMap<String, PendingCacheHeadFile>,
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
