//! move snapshot upload calls into upload.

use super::anyhow;

use super::conflict_probe_after;
use super::current_unix_seconds;
use super::inplace_retry_failed_after;
use super::inplace_retry_sleep;
use super::quarantine_retry_after;
use super::record_poison_loss_once;
use super::rejection_log;
use super::retain_counted_poison_fingerprints;
use super::server_named_items;
use super::shed_backoff;
use super::BTreeMap;
use super::BTreeSet;
use super::BatchAuthorizationRejected;
use super::BatchRejected;
use super::Duration;
use super::InplaceRetryBudget;
use super::Instant;
use super::Result;
use super::Serialize;
use super::SessionHash;
use super::SnapshotAckRejected;
use super::SnapshotQuarantineDisposition;
use super::SnapshotUploadProgress;
use super::UploadFailureDiagnostics;
use super::UploadShed;
use super::VecDeque;
use super::MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
use super::SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT;
use super::SNAPSHOT_ADAPTIVE_SPLIT_LIMIT;
use super::SNAPSHOT_BATCH_LIMIT;
use super::SNAPSHOT_BATCH_MAX_BYTES;
use super::SNAPSHOT_INPLACE_RETRY_LIMIT;
use super::SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET;

impl std::error::Error for SnapshotBatchPreflightRejected {}

impl std::error::Error for SnapshotLocalStateRejected {}

impl std::error::Error for SourcesFailed {}

impl std::error::Error for SnapshotEntityDeferred {}

use super::collector_version;
use super::reason_reoffer;
use super::snapshot_upload_body_witness;
use super::Digest;
#[cfg(test)]
use super::PermanentSnapshotRejection;
use super::ScanIndex;
use super::Sha256;
use super::SnapshotBatchRequest;
use super::SnapshotItem;
#[cfg(test)]
use super::SnapshotQuarantineRecord;
use super::SnapshotSource;
use super::SnapshotUploadPolicy;
use super::SNAPSHOT_SCHEMA_VERSION;

/// Bootstrap a fresh source page's cache heads under its own in-place resend
/// budget.
#[cfg(test)]
pub(super) fn bootstrap_cache_heads(
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
pub(super) fn bootstrap_cache_heads_with_budget(
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
        // A headless patched body reaches here only when head CAS is optional;
        // otherwise prepare strips it.
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
                ResumableUploadResult::Deferred {
                    count, isolated, ..
                } => {
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

pub(super) fn cache_head_probe(item: &SnapshotItem) -> SnapshotItem {
    let mut probe = item.clone();
    probe.cache_observations = None;
    probe.cache_observations_state = None;
    probe.cache_conflict_answer = None;
    probe
}

/// Exact non-acceptance of these bytes, using the uploader's existing hold
/// predicate. An accepted body without a head is not a quarantine certificate.
pub(super) fn cache_head_probe_held(
    progress: &SnapshotUploadProgress,
    probe: &SnapshotItem,
) -> bool {
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

pub(super) fn held_cache_head_probe(
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
pub(super) fn apply_bootstrapped_cache_heads(
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

pub(super) fn with_bootstrap_deferred(
    mut result: ResumableUploadResult,
    deferred: usize,
) -> ResumableUploadResult {
    if deferred == 0 {
        return result;
    }
    match &mut result {
        ResumableUploadResult::Completed | ResumableUploadResult::Rejected { .. } => {
            result = ResumableUploadResult::Deferred {
                count: deferred,
                isolated: 0,
                identity_503: 0,
            };
        }
        ResumableUploadResult::Deferred { count, .. } => *count = count.saturating_add(deferred),
        _ => {}
    }
    result
}

/// Carry a newer refused-body conflict even when the frozen upload delta is
/// empty. New conflicts were already counted by bootstrap/main upload; this
/// adds only older, untransmitted debt from the current source universe.
/// A later traversal's proven unchanged cooldown is counted and disclosed,
/// but leaves settlement to the normal clean-traversal boundary.
pub(super) fn with_retained_refusal_conflicts(
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

#[derive(Debug)]
pub(super) struct DeferredCacheHeadIdentity {
    pub(super) source_file_fingerprint: Option<String>,
    pub(super) snapshot_fingerprint: String,
    pub(super) session_key: String,
}

pub(super) fn capture_deferred_cache_head_identities(
    source: SnapshotSource,
    items: &[SnapshotItem],
    progress: &SnapshotUploadProgress,
    enabled: bool,
    head_cas_required: bool,
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
            let session_key = cache_session_key(&item.source_session_id);
            (head_cas_required && !progress.accepted_cache_heads.contains_key(&session_key)).then(
                || DeferredCacheHeadIdentity {
                    source_file_fingerprint: item.source_file_fingerprint.clone(),
                    snapshot_fingerprint: fingerprint,
                    session_key,
                },
            )
        })
        .collect()
}

/// Both exact contracts, so Pi (no base cache contract) never marks a patch.
pub(super) fn cache_full_replacement_negotiated(
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
pub(super) fn prepare_snapshot_cache_for_upload(
    snapshot: &mut SnapshotItem,
    progress: &SnapshotUploadProgress,
    enabled: bool,
    head_cas_required: bool,
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
    if head_cas_required && snapshot.cache_base_head_etag.is_none() {
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
/// patch. Missing-head fencing can only remove this projected material.
pub(super) fn identity_cache_wire_reserve(
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
    prepare_snapshot_cache_for_upload(&mut projected, progress, true, false);
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

/// Keep ordinary (0), patched or headed (1), and telemetry-only (3) requests
/// separate: the head-CAS declaration applies to the entire batch. Class 1 is
/// a body with a cache patch (admitted, unchanged or partial-empty) or a saved
/// head; class 0 has neither, sends no CAS contract and cannot conflict with a
/// server head it never claimed.
pub(super) fn snapshot_upload_batch_class(snapshot: &SnapshotItem) -> u8 {
    if snapshot.evidence_basis == Some("otel_only") {
        3
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
pub(super) fn attach_head_conflict_answers(
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

pub(super) fn effective_snapshot_upload_body_witness(
    snapshot: &SnapshotItem,
    progress: &SnapshotUploadProgress,
    enabled: bool,
    head_cas_required: bool,
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
    prepare_snapshot_cache_for_upload(&mut projected, progress, enabled, head_cas_required);
    snapshot_upload_body_witness(
        held_cache_head_probe(progress, &projected)
            .as_ref()
            .unwrap_or(&projected),
    )
}

/// One hash-only group per current file. Duplicate source witnesses are not an
/// exact mapping and are excluded rather than guessed. O(current index files).
pub(super) fn cache_head_file_groups(
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

pub(super) fn cache_head_selection_witness(accepted_head: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("cache_head_selection:v1:{accepted_head}"))
    )
}

pub(super) fn cache_head_index_key(index_key: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("cache_head_file:v1:{index_key}"))
    )
}

pub(crate) fn cache_session_key(session: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(session.as_bytes()))
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
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ResumableUploadResult {
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
    /// pass finishes with them still owed. `identity_503` (also included in
    /// `isolated`) are identity-unavailable 503 deferrals.
    Deferred {
        count: usize,
        isolated: usize,
        identity_503: usize,
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
pub(super) struct SnapshotBatchPreflightRejected {
    pub(super) reason: String,
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

#[derive(Debug)]
pub(super) struct SnapshotLocalStateRejected {
    pub(super) operation: &'static str,
}

impl std::fmt::Display for SnapshotLocalStateRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local snapshot state failed: {}", self.operation)
    }
}

/// A cycle's summary. Each source's cause is on its own "skipped for" line.
#[derive(Debug)]
pub(super) struct SourcesFailed(pub(super) Vec<&'static str>);

impl std::fmt::Display for SourcesFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "local snapshot sync failed for {}",
            self.0.join(", ")
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SnapshotEntityDeferred {
    pub(super) count: usize,
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

pub(super) fn snapshot_entity_deferred(count: usize) -> anyhow::Error {
    anyhow::Error::new(SnapshotEntityDeferred { count })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnapshotUploadErrorClass {
    LocalState,
    BackendResponse,
}

pub(super) fn snapshot_upload_error_class(
    error: &anyhow::Error,
) -> Option<SnapshotUploadErrorClass> {
    if error.downcast_ref::<SnapshotLocalStateRejected>().is_some() {
        Some(SnapshotUploadErrorClass::LocalState)
    } else if error.downcast_ref::<SnapshotAckRejected>().is_some() {
        Some(SnapshotUploadErrorClass::BackendResponse)
    } else {
        None
    }
}

pub(super) fn is_item_specific_local_preflight_failure(error: &anyhow::Error) -> bool {
    item_specific_local_preflight_index(error).is_some()
}

pub(super) fn item_specific_local_preflight_index(error: &anyhow::Error) -> Option<usize> {
    error
        .downcast_ref::<SnapshotBatchPreflightRejected>()
        .and_then(|preflight| preflight.reason.strip_prefix("snapshot["))
        .and_then(|suffix| suffix.split_once(']'))
        .and_then(|(index, _)| index.parse().ok())
}

/// True when the backend shed this request rather than failing it.
pub(super) fn is_shed_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| diagnostics.status_family() == "http_429")
}

/// The server never answered the page: a transport failure, a timeout or a
/// 5xx. A plain shed arrives as `ResumableUploadResult::Shed` instead.
pub(super) fn is_upload_outage(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(UploadFailureDiagnostics::is_outage)
}

pub(super) fn is_snapshot_batch_split_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| {
            diagnostics.is_snapshot_batch_deadline() || diagnostics.is_snapshot_batch_too_large()
        })
}

/// Upload changed snapshots in bounded pages while durably checkpointing every
/// accepted page. Item-specific validation failures are bisected so one poison
/// snapshot cannot replay or block its valid siblings; pages that exceed the
/// client or gateway deadline are also bisected to reduce per-request
/// reconciliation work. Splits are capped so an outage or broad contract
/// mismatch cannot fan out into unbounded calls.
#[cfg(test)]
pub(super) fn upload_resumable_batches<T, Fingerprint, Upload, Persist>(
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
pub(super) fn upload_resumable_batches_with_body_witness<
    T,
    Fingerprint,
    BodyWitness,
    Upload,
    Persist,
>(
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
pub(super) enum SnapshotPageOutcome {
    Settled { conflicted: usize, isolated: usize },
    Disabled(Option<String>),
}

/// Diagnostics only (`change_reason`): an unchanged ACK without a basis
/// (the stored body itself) or with `usage_identical` settles identical
/// usage; an accepted one never does.
pub(super) fn ack_usage_identical(unchanged: bool, basis: Option<&str>) -> bool {
    unchanged && matches!(basis, None | Some("usage_identical"))
}

// Scratch extraction only: the upload callback remains the existing canonical
// preflight/token/ACK-validator/client-report boundary. No inventory pruning.
#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
pub(super) fn attempt_snapshot_page<T, Fingerprint, BodyWitness, SessionId, Upload, Persist>(
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
    if !progress.accepted_identity_scope.is_unset() {
        progress.load_identity(batch.iter().copied().filter_map(session_id))?;
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
    response.require_entity_ack_contract()?;
    let mut head_conflicts_recovered = Vec::new();
    let mut head_conflicts_recorded = Vec::new();
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
    let usage_identical = response
        .unchanged_entities
        .iter()
        .filter(|entity| entity.unchanged_basis.as_deref() == Some("usage_identical"))
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
            // A main-upload ACK of the session's current body pays its
            // identity-503 debt, in this same checkpoint.
            if let (Some(_), Some(pending), Some(session)) = (
                &progress.identity_503_pass,
                progress.identity_503_pending.as_mut(),
                session_id(item),
            ) {
                pending.remove(&cache_session_key(session));
            }

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
                stored_refs
                    .get(item_fingerprint)
                    .map(|entity| (*entity, witness.as_str())),
            )?;
        } else if not_stored.contains(item_fingerprint) {
            progress.hold_unstored_body(
                item_fingerprint,
                &body_witness(item),
                usage_identical.contains(item_fingerprint),
            );
            progress
                .context_resend
                .not_stored
                .insert(item_fingerprint.to_string());
        }
    }
    if !not_stored.is_empty() {
        let usage_identical = usage_identical.len();
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
            progress.quarantine_retryable_body(item_fingerprint, &body_witness(item), retry_after);
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
    let conflicted_entities = response.conflict_entities.len().saturating_add(
        response
            .rejected_entities
            .iter()
            .filter(|entity| !entity.permanent)
            .count(),
    );
    let isolated_entities = response
        .rejected_entities
        .iter()
        .filter(|entity| !entity.permanent && entity.ordinary_retryable())
        .count()
        .saturating_add(response.conflict_entities.len());
    progress.context_resend.counts.server_conflicts += conflicted_entities as u64;
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
    *accepted = accepted.saturating_add(response.accepted);

    Ok(SnapshotPageOutcome::Settled {
        conflicted: conflicted_entities,
        isolated: isolated_entities,
    })
}

// Packing needs encoded lengths, not a retained copy of every pending body.
// Use the same serde JSON encoding without allocating its output. There is no
// early size cap: serializers must still finish or report their original error.
pub(super) struct SnapshotPackingLength {
    pub(super) bytes: usize,
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
pub(super) fn literal_family_groups(
    members: Vec<(usize, usize, u8)>,
) -> Vec<Vec<(usize, usize, u8)>> {
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
pub(super) fn upload_resumable_batches_with_literal_families<
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
    let mut identity_503_entities = 0usize;

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
                let identity_503 = error.downcast_ref::<UploadShed>().is_some_and(|shed| {
                    shed.is_original_identity_unavailable() && shed.status == 503
                });
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
                    // Main upload only: the session owes a later ACK before
                    // its walk can settle; saved with the quarantine below.
                    if let (true, Some(pass), Some(session)) = (
                        identity_503,
                        progress.identity_503_pass.as_mut(),
                        session_id(&items[*index]),
                    ) {
                        let key = cache_session_key(session);
                        pass.insert(key.clone());
                        progress
                            .identity_503_pending
                            .get_or_insert_with(BTreeSet::new)
                            .insert(key);
                    }
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
                if identity_503 {
                    identity_503_entities = identity_503_entities.saturating_add(held.len());
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
            identity_503: identity_503_entities,
        })
    } else if permanent_rejected > 0 {
        Ok(ResumableUploadResult::Rejected {
            count: permanent_rejected,
        })
    } else {
        Ok(ResumableUploadResult::Completed)
    }
}
