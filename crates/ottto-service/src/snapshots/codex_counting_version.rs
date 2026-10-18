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

#[cfg(test)]
thread_local! {
    static TEST_CUTOVER_UNIX_MS: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

/// The compiled cutover.
#[cfg(not(test))]
fn cutover_unix_ms() -> Option<i64> {
    CODEX_COUNTING_V2_CUTOVER_UNIX_MS
}

/// Tests may substitute a cutover on their own thread.
#[cfg(test)]
fn cutover_unix_ms() -> Option<i64> {
    TEST_CUTOVER_UNIX_MS
        .with(std::cell::Cell::get)
        .or(CODEX_COUNTING_V2_CUTOVER_UNIX_MS)
}

/// Activates a cutover for scan-level tests on this thread until dropped.
#[cfg(test)]
pub(super) struct TestCutover;
#[cfg(test)]
impl TestCutover {
    pub(super) fn set(cutover_unix_ms: i64) -> Self {
        TEST_CUTOVER_UNIX_MS.with(|cell| cell.set(Some(cutover_unix_ms)));
        Self
    }
}
#[cfg(test)]
impl Drop for TestCutover {
    fn drop(&mut self) {
        TEST_CUTOVER_UNIX_MS.with(|cell| cell.set(None));
    }
}

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
    /// entries the caller owns (COST rule 2). Any Legacy-acknowledged entry
    /// (ACK facts without a V2 mark) forces Legacy, whatever else is marked;
    /// otherwise any V2 mark selects V2; entries without ACK facts are neutral.
    pub(super) fn of_view<'a>(entries: impl IntoIterator<Item = &'a ScanIndexEntry>) -> Self {
        let mut marked = false;
        for entry in entries {
            if entry.codex_counting_v2 {
                marked = true;
            } else if entry_has_ack_evidence(entry) {
                return Self::LegacyAcked;
            }
        }
        if marked {
            Self::V2Marked
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
    // Inactive: no state is allocated and Legacy output is unchanged; the
    // accumulator keeps only its empty 8-byte slot.
    let Some(cutover) = cutover_unix_ms() else {
        return;
    };
    let evidence = AckEvidence::of_view(index.files.get(&local_index_key(&candidate.path)));
    configure(&mut parser.accumulator, evidence, Some(cutover));
}

/// A joined group's member evidence. Inactive, the member view is never
/// traversed, so an inactive group scan allocates nothing for counting.
pub(super) fn group_evidence<'a>(
    entries: impl IntoIterator<Item = &'a ScanIndexEntry>,
) -> AckEvidence {
    if cutover_unix_ms().is_none() {
        return AckEvidence::None;
    }
    AckEvidence::of_view(entries)
}

/// Joined-group replay parser: configured once, from the group's evidence,
/// on its fresh accumulator. The accumulator carried across members is never
/// reconfigured, so no member resets V2 state mid-session.
pub(super) fn configure_group_once(accumulator: &mut SnapshotAccumulator, evidence: AckEvidence) {
    let Some(cutover) = cutover_unix_ms() else {
        return;
    };
    if accumulator.codex_counting.is_none() {
        configure(accumulator, evidence, Some(cutover));
    }
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
