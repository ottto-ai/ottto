// Complete released SnapshotUploadProgress serde codec, identical at:
// 0.1.201 f174d111fbcdfb0ab9c2abeb299c12d50b435c29
// 0.1.202 79488a7297817edfe1eb5cfc34b779408d511726
// 0.1.203 bf4d653b2165a95d04d337be4a058513d3163a18
// Source-span SHA256 b8812ecf2b79cc341acadc8b28f3cc496f0ef3f3a735a06c214cbc10ef592539
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
    /// Admission only: current live incidence plus bounded unsettled ACK debt.
    #[serde(skip, default = "ack_retention::default_ack_capacity")]
    ack_capacity: usize,
    /// ACKs outside known live incidence; includes valid unindexed debt.
    #[serde(skip)]
    retained_stale_ack_count: usize,
    #[serde(default)]
    accepted_cache_states: BTreeMap<String, serde_json::Value>,
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
}
