//! Codex usage-counting version selection. Local only: no field here reaches
//! the wire. A session's version is a function of one immutable header fact,
//! a compiled cutover and this destination index's existing acknowledgement
//! evidence. Losing local state can only re-derive the same rule, except the
//! disclosed index-loss residual (an old-binary-acknowledged post-cutover
//! session whose index is lost re-derives V2).
use super::*;

/// Compiled V2 cutover, Unix milliseconds, compared with the root origin
/// header's `session_meta.payload.timestamp`. `None` keeps every session on
/// Legacy counting. Activation is a separate reviewed change that freezes one
/// instant after the group parser path is configured; never a moving time.
pub(super) const CODEX_COUNTING_V2_CUTOVER_UNIX_MS: Option<i64> = None;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CountingVersion {
    Legacy,
    V2,
}

/// Acknowledgement evidence already present for a session's index entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AckEvidence {
    /// No writer has published this session to this destination.
    None,
    /// A V2 writer published it; its bool travels with the ACK fields.
    V2Marked,
    /// Some writer that did not mark V2 already published it.
    LegacyAcked,
}

impl AckEvidence {
    /// The session view: the candidate entry plus any twin/alias/member
    /// entries the caller owns. One V2 mark decides; otherwise any ACK fact
    /// keeps the session Legacy.
    pub(super) fn of_view<'a>(entries: impl IntoIterator<Item = &'a ScanIndexEntry>) -> Self {
        let mut acknowledged = false;
        for entry in entries {
            if entry.codex_counting_v2 {
                return Self::V2Marked;
            }
            acknowledged |= entry_has_ack_evidence(entry);
        }
        if acknowledged {
            Self::LegacyAcked
        } else {
            Self::None
        }
    }
}

fn entry_has_ack_evidence(entry: &ScanIndexEntry) -> bool {
    entry.last_snapshot_fingerprint.is_some()
        || entry.last_upload_body_witness.is_some()
        || entry.codex_protected_owner.is_some()
        || entry.codex_joined_member_set.is_some()
        || entry.codex_captured_joined_member_set.is_some()
        || entry.codex_applied_tier_receipt.is_some()
        || entry.codex_applied_tier_receipt_required
        || entry.codex_captured_tier_receipt.is_some()
        || entry.codex_captured_tier_receipt_required
        || entry.codex_captured_uncommitted
}

/// Decided once, on the session's first owned record. Only a root origin
/// header can select V2: a continuation (`history_base`), a header that is
/// not the first owned record, or an unknown/unparseable creation time is
/// Legacy for the parse's whole life.
pub(super) fn decide(
    first_owned_record: &Value,
    evidence: AckEvidence,
    cutover_unix_ms: Option<i64>,
) -> CountingVersion {
    let Some(cutover) = cutover_unix_ms else {
        return CountingVersion::Legacy;
    };
    if !string_eq_at(first_owned_record, &["type"], "session_meta") {
        return CountingVersion::Legacy;
    }
    let Some(meta) = first_owned_record.get("payload") else {
        return CountingVersion::Legacy;
    };
    if meta.get("history_base").is_some_and(|base| !base.is_null()) {
        return CountingVersion::Legacy;
    }
    let Some(created_unix_ms) = meta
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .and_then(|created| i64::try_from(created.unix_timestamp_nanos() / 1_000_000).ok())
    else {
        return CountingVersion::Legacy;
    };
    if created_unix_ms < cutover {
        return CountingVersion::Legacy;
    }
    match evidence {
        AckEvidence::V2Marked | AckEvidence::None => CountingVersion::V2,
        AckEvidence::LegacyAcked => CountingVersion::Legacy,
    }
}

/// Fresh singleton parser. The restored-reduction site must instead refuse a
/// retained reduction whose decided version this evidence would not select
/// (B handoff H4); the group parser configures its own member view (H1).
pub(super) fn configure_singleton(
    parser: &mut OwnedJsonlParser,
    candidate: &CandidateFile,
    index: &ScanIndex,
) {
    // Inactive: no state, so Legacy parses and their heap charge are unchanged.
    if CODEX_COUNTING_V2_CUTOVER_UNIX_MS.is_none() {
        return;
    }
    let evidence = AckEvidence::of_view(index.files.get(&local_index_key(&candidate.path)));
    configure(
        &mut parser.accumulator,
        evidence,
        CODEX_COUNTING_V2_CUTOVER_UNIX_MS,
    );
}

pub(super) fn configure(
    accumulator: &mut SnapshotAccumulator,
    evidence: AckEvidence,
    cutover_unix_ms: Option<i64>,
) {
    accumulator.codex_counting = Some(Box::new(codex_usage_occurrence::CodexCounting::new(
        evidence,
        cutover_unix_ms,
    )));
}

impl crate::heap_layout_bound::HeapLayoutBound for CountingVersion {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for AckEvidence {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
