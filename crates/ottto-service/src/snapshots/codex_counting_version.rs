//! Codex usage-counting version selection. Local only: no field here reaches
//! the wire. A session's version is a function of one immutable header fact,
//! a compiled cutover and this destination index's existing acknowledgement
//! evidence. Losing local state can only re-derive the same rule, except the
//! disclosed index-loss residual (an old-binary-acknowledged post-cutover
//! session whose index is lost re-derives V2).
use super::*;

/// Compiled V2 cutover, Unix milliseconds, compared with the root origin
/// header's `session_meta.payload.timestamp`: 2026-10-26T12:00:00Z. Sessions
/// whose root header is at or after it, and that no Legacy writer has already
/// acknowledged, use V2; every earlier session stays Legacy. Frozen once; never
/// move it. `None` would keep every session on Legacy counting.
pub(super) const CODEX_COUNTING_V2_CUTOVER_UNIX_MS: Option<i64> = Some(1_793_016_000_000);

#[cfg(test)]
thread_local! {
    static TEST_CUTOVER_UNIX_MS: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

/// The compiled cutover.
#[cfg(not(test))]
pub(super) fn cutover_unix_ms() -> Option<i64> {
    CODEX_COUNTING_V2_CUTOVER_UNIX_MS
}

/// Tests see only a cutover set on their own thread, never the compiled one,
/// so fixtures stamped with the wall clock cannot switch rule once the
/// compiled instant passes.
#[cfg(test)]
pub(super) fn cutover_unix_ms() -> Option<i64> {
    TEST_CUTOVER_UNIX_MS.with(std::cell::Cell::get)
}

/// Activates a cutover for scan-level tests on this thread until dropped.
#[cfg(test)]
pub(crate) struct TestCutover;
#[cfg(test)]
impl TestCutover {
    pub(crate) fn set(cutover_unix_ms: i64) -> Self {
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
crate::durable_tail_codec::durable_enum!(CountingVersion {
    0 => Legacy,
    1 => V2,
});

/// Acknowledgement evidence already present for a session's index entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AckEvidence {
    /// No writer has published this session to this destination.
    None,
    /// A V2 writer published it; its bool travels with the ACK fields.
    V2Marked,
    /// Some writer that did not mark V2 already published it.
    LegacyAcked,
}
crate::durable_tail_codec::durable_enum!(AckEvidence {
    0 => None,
    1 => V2Marked,
    2 => LegacyAcked,
});

impl AckEvidence {
    pub(super) fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::LegacyAcked, _) | (_, Self::LegacyAcked) => Self::LegacyAcked,
            (Self::V2Marked, _) | (_, Self::V2Marked) => Self::V2Marked,
            _ => Self::None,
        }
    }
    fn view_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::V2Marked => "v2_marked",
            Self::LegacyAcked => "legacy_acked",
        }
    }

    fn of_view_name(name: &str) -> Option<Self> {
        [Self::None, Self::V2Marked, Self::LegacyAcked]
            .into_iter()
            .find(|evidence| evidence.view_name() == name)
    }

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

/// At most this many retired owners keep counting evidence. The conservative
/// `tree_nodes` heap charge is about 1 MiB at capacity (including key/timestamp
/// buffers), not the serialized payload size or a measured RSS bound.
/// Overflow prefers V2-only evidence, then intrinsically Legacy pre-cutover
/// headers, then earlier-generation Legacy evidence. While inactive, known
/// oldest creation times go first within the Legacy class; unknown times are
/// most protected. Generation age alone proves no successful walk or absence.
/// Current-generation Legacy evidence that might be post-cutover is retained:
/// if no safer slot exists, refuse retirement until a later generation.
pub(super) const MAX_COUNTING_TOMBSTONES: usize = 1024;

/// Diagnostic correlation only: newest 256 owners whose Legacy tombstone
/// was removed by a not-provably-pre-cutover cap eviction. Persisted
/// because a moved owner can be parsed on a later scan or after restart. FIFO
/// displacement ages records; a committed live ACK absorbs them. Never read
/// by version selection, reuse, ACK, settlement or dedup logic.
pub(super) const MAX_EVICTED_LEGACY_OWNERS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvictedLegacyOwner {
    owner: String,
    /// A pre-existing V2 ACK cannot absorb an eviction before its resulting
    /// V2 selection has been observed. Diagnostic only, never version evidence.
    #[serde(default)]
    selected_v2: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(transparent)]
pub(super) struct EvictedLegacyOwners {
    owners: VecDeque<EvictedLegacyOwner>,
}

impl EvictedLegacyOwners {
    pub(super) fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    fn remember(&mut self, record: EvictedLegacyOwner) {
        self.owners
            .retain(|previous| previous.owner != record.owner);
        if self.owners.len() == MAX_EVICTED_LEGACY_OWNERS {
            self.owners.pop_front();
        }
        self.owners.push_back(record);
    }
}

impl<'de> Deserialize<'de> for EvictedLegacyOwners {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = VecDeque::<EvictedLegacyOwner>::deserialize(deserializer)?;
        let mut recent = Self::default();
        for record in raw {
            if valid_codex_protected_owner(&record.owner) {
                recent.remember(record);
            }
        }
        Ok(recent)
    }
}

/// A diagnostic observation of an actual V2 decision, correlated with a lost
/// last Legacy carrier. Kept through failed/held parses and repeated until a
/// committed carrier absorbs it or FIFO displacement ages it. Callers publish
/// this receipt only after a successful, non-side-read parse finishes.
pub(super) fn evicted_legacy_selected_v2(
    accumulator: &SnapshotAccumulator,
    index: &ScanIndex,
) -> bool {
    if !accumulator.codex_counting_v2() {
        return false;
    }
    let Some(id) = accumulator.source_session_id.as_deref() else {
        return false;
    };
    let owner = codex_protected_owner(id);
    index
        .codex_counting_evicted_legacy
        .owners
        .iter()
        .any(|record| record.owner == owner)
}

/// Called only when the finished-parse receipt is published, after side-read
/// and failure exits. Keep the record until committed evidence or FIFO aging
/// absorbs it; the bit survives partial checkpoints and restart.
pub(super) fn note_evicted_legacy_v2_selection(index: &mut ScanIndex, owner: &str) {
    if let Some(record) = index
        .codex_counting_evicted_legacy
        .owners
        .iter_mut()
        .find(|record| record.owner == owner)
    {
        record.selected_v2 = true;
    }
}

fn absorbs_evicted_legacy(evidence: AckEvidence, selected_v2: bool) -> bool {
    evidence == AckEvidence::LegacyAcked || (selected_v2 && evidence == AckEvidence::V2Marked)
}

/// Drain this scan's eviction events and add current gauges to the existing
/// local-only receipt block, including scans with bookkeeping but no parse.
pub(super) fn take_local_receipts(
    index: &mut ScanIndex,
    receipts: Option<Box<crate::codex_scan_diagnostics::CountingV2Receipts>>,
) -> Option<Box<crate::codex_scan_diagnostics::CountingV2Receipts>> {
    let counts = std::mem::take(&mut index.codex_counting_evictions);
    if receipts.is_none()
        && cutover_unix_ms().is_none()
        && counts == [0; 3]
        && index.codex_counting_tombstones.is_empty()
        && index.codex_counting_evicted_legacy.is_empty()
    {
        return None;
    }
    let mut receipts = receipts.unwrap_or_default();
    receipts.tombstone_evictions_v2_only = counts[0];
    receipts.tombstone_evictions_pre_cutover_legacy = counts[1];
    receipts.tombstone_evictions_not_provably_pre_cutover_legacy = counts[2];
    receipts.tombstone_count = index.codex_counting_tombstones.len() as u64;
    receipts.tombstone_cap = MAX_COUNTING_TOMBSTONES as u64;
    Some(receipts)
}

/// Counting evidence of a retired, unprotected entry, keyed by its owner hash
/// in `ScanIndex::codex_counting_tombstones`. A watcher remove or census
/// reconciliation can retire a moved session's old entry on an earlier page
/// than the one that parses its new path; this keeps the evidence until the
/// owner's live entry carries it or the owner is proven absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CountingTombstone {
    pub(super) evidence: AckEvidence,
    /// `census_window_end` of the traversal generation that retired the entry.
    pub(super) retired_in: String,
    /// Immutable owning-header timestamp, learned from the existing inventory.
    /// Missing in older state or after a removal before header observation.
    /// Unknown must never count as proof that an owner predates the cutover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) created_unix_ms: Option<i64>,
}

/// The first valid owner a complete parse proved for this entry. An invalid
/// (corrupt or future-format) binding never masks a valid one.
pub(super) fn proven_owner(entry: &ScanIndexEntry) -> Option<&str> {
    [
        entry.codex_counting_owner.as_deref(),
        entry.codex_protected_owner.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|owner| valid_codex_protected_owner(owner))
}

/// Called, whatever the cutover, just before an unprotected entry is retired.
/// Records its counting evidence under its proven owner, or as a Legacy hint
/// under each filename identity, exactly as `prepare_moved_evidence` would
/// read the entry. Returns false when the entry must stay instead: the map is
/// full of this generation's Legacy evidence. Hash-only; no file read.
pub(super) fn tombstone_before_retire(index: &mut ScanIndex, key: &str) -> bool {
    let Some(entry) = index.files.get(key) else {
        return true;
    };
    let evidence = AckEvidence::of_view(Some(entry));
    if evidence == AckEvidence::None {
        return true;
    }
    let retired = match proven_owner(entry) {
        Some(owner) => vec![(owner.to_owned(), evidence)],
        None => codex_session_id_candidates_from_path(Path::new(key))
            .iter()
            .map(|id| (codex_protected_owner(id), AckEvidence::LegacyAcked))
            .collect(),
    };
    let retired_in = index
        .traversal
        .as_ref()
        .map(|traversal| traversal.census_window_end.clone())
        .unwrap_or_default();
    let tombstones = &mut index.codex_counting_tombstones;
    let needed = retired
        .iter()
        .filter(|(owner, _)| !tombstones.contains_key(owner))
        .count();
    let short = (tombstones.len() + needed).saturating_sub(MAX_COUNTING_TOMBSTONES);
    if short > 0 {
        if retired
            .iter()
            .all(|(_, evidence)| *evidence != AckEvidence::LegacyAcked)
        {
            // V2-only evidence never selects a different version.
            return true;
        }
        let cutover = cutover_unix_ms();
        // Order by safety class, then creation time while inactive, then
        // retirement generation and owner for deterministic ties. Unknown
        // timestamps sort last. Rewritten owners cannot free a slot.
        let mut evictable = tombstones
            .iter()
            .filter(|(owner, _)| !retired.iter().any(|(rewritten, _)| rewritten == *owner))
            .filter_map(|(owner, tombstone)| {
                let class = if tombstone.evidence != AckEvidence::LegacyAcked {
                    0
                } else if cutover.is_some_and(|cutover| {
                    tombstone
                        .created_unix_ms
                        .is_some_and(|created| created < cutover)
                }) {
                    1
                } else if tombstone.retired_in != retired_in {
                    2
                } else {
                    return None;
                };
                let created = cutover
                    .is_none()
                    .then_some(tombstone.created_unix_ms)
                    .flatten();
                Some((
                    class,
                    tombstone.created_unix_ms.is_none(),
                    created,
                    &tombstone.retired_in,
                    owner,
                ))
            })
            .collect::<Vec<_>>();
        evictable.sort_unstable();
        if evictable.len() < short {
            return false;
        }
        let evictable = evictable
            .into_iter()
            .take(short)
            .map(|(class, _, _, _, owner)| (class, owner.clone()))
            .collect::<Vec<_>>();
        let mut counts = [0usize; 3];
        for (class, owner) in evictable {
            tombstones.remove(&owner);
            counts[class] += 1;
            index.codex_counting_evictions[class] =
                index.codex_counting_evictions[class].saturating_add(1);
            if class == 2 {
                // Record the loss without walking/hashing the file index per
                // eviction. Surviving ACKs are absorbed in the single existing
                // inventory pass below; any remaining Legacy carrier also
                // forces Legacy through ordinary evidence selection, so only
                // loss of the last carrier can produce a V2 flip receipt.
                index
                    .codex_counting_evicted_legacy
                    .remember(EvictedLegacyOwner {
                        owner,
                        selected_v2: false,
                    });
            }
        }
        eprintln!(
            "ottto-service: Codex counting tombstones full; evicted v2_only={} \
             pre_cutover_legacy={} earlier_generation_legacy={}",
            counts[0], counts[1], counts[2]
        );
    }
    for (owner, evidence) in retired {
        let tombstone = tombstones.entry(owner).or_insert(CountingTombstone {
            evidence: AckEvidence::None,
            retired_in: String::new(),
            created_unix_ms: None,
        });
        tombstone.evidence = tombstone.evidence.combine(evidence);
        tombstone.retired_in.clone_from(&retired_in);
    }
    true
}

/// Header completeness covers the resolved roster, not unresolved configured
/// roots. Reuse the ordinary reconciliation health signal (which includes
/// root-resolution failures) plus current directory witnesses. No re-listing.
pub(super) fn absence_coverage_complete(
    index: &ScanIndex,
    inventory: &codex_file_join::HeaderInventory,
) -> bool {
    inventory.complete
        && index.legacy_unresolved_root_file_witnesses.is_empty()
        && index.traversal.as_ref().is_some_and(|traversal| {
            !traversal.counts.has_errors()
                && !traversal.watcher_hint_seen
                && traversal.pending_directories.is_empty()
                && !traversal.scan_roots.is_empty()
                && traversal
                    .scan_roots
                    .iter()
                    .all(|root| inventory.directories.contains(root))
                && inventory.directories.local_diagnostic_counts().0
                && inventory.directories.moved_directories().is_empty()
        })
}

/// Reuse decoded owning headers for existing retired owners. A missing old
/// path has no timestamp in ScanIndexEntry; keep it unknown until inventoried
/// at its new path. For conflicting aliases the latest timestamp wins, and
/// any unknown header prevents claiming an intrinsically Legacy owner.
pub(super) fn note_inventory_created(
    index: &mut ScanIndex,
    inventory: &codex_file_join::HeaderInventory,
) {
    if !inventory.complete || index.codex_counting_tombstones.is_empty() {
        return;
    }
    let mut created_by_owner = BTreeMap::<String, Option<i64>>::new();
    for header in &inventory.headers {
        let owner = codex_protected_owner(&header.owner);
        if !index.codex_counting_tombstones.contains_key(&owner) {
            continue;
        }
        created_by_owner
            .entry(owner)
            .and_modify(|created| {
                *created = match (*created, header.created_unix_ms) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    _ => None,
                };
            })
            .or_insert(header.created_unix_ms);
    }
    for (owner, created) in created_by_owner {
        let tombstone = index
            .codex_counting_tombstones
            .get_mut(&owner)
            .expect("existing owner");
        tombstone.created_unix_ms = match (tombstone.created_unix_ms, created) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (_, created) => created,
        };
    }
}

/// Free tombstone slots, whatever the cutover, from the index state this page
/// loaded: an owner whose live, proven entry already carries at least the
/// same evidence, or an owner absent from a later traversal generation with
/// explicit complete configured-root coverage and fresh directory witnesses.
/// A rename in flight during the retiring generation cannot prove absence.
fn collect_tombstones(
    index: &mut ScanIndex,
    owners: &BTreeMap<String, String>,
    absence_coverage: bool,
) {
    if index.codex_counting_tombstones.is_empty() {
        return;
    }
    let mut live = BTreeMap::<&str, AckEvidence>::new();
    for entry in index.files.values() {
        let Some(owner) = proven_owner(entry) else {
            continue;
        };
        if index.codex_counting_tombstones.contains_key(owner) {
            let evidence = AckEvidence::of_view(Some(entry));
            let previous = live.entry(owner).or_insert(AckEvidence::None);
            *previous = previous.combine(evidence);
        }
    }
    let present = owners.values().collect::<BTreeSet<_>>();
    let census = index
        .traversal
        .as_ref()
        .map(|traversal| traversal.census_window_end.as_str());
    let retire = index
        .codex_counting_tombstones
        .iter()
        .filter(|(owner, tombstone)| {
            let absorbed = live.get(owner.as_str()).is_some_and(|evidence| {
                *evidence != AckEvidence::None && evidence.combine(tombstone.evidence) == *evidence
            });
            let absent = absence_coverage
                && !present.contains(owner)
                && census.is_some_and(|census| census != tombstone.retired_in);
            absorbed || absent
        })
        .map(|(owner, _)| owner.clone())
        .collect::<Vec<_>>();
    for owner in retire {
        index.codex_counting_tombstones.remove(&owner);
    }
}

/// Reuse the inventory's decoded header owners, without another file read.
/// Index traversal happens once per inventory, with temporary state bounded by
/// that inventory's existing population cap. An old unbound filename is only a
/// conservative Legacy hint, never proof that a V2 mark belongs to this owner.
/// Retired entries' tombstones fold in exactly as their entries would have.
pub(super) fn prepare_moved_evidence(
    index: &mut ScanIndex,
    owners: &BTreeMap<String, String>,
    absence_coverage: bool,
) {
    index.codex_counting_moved_evidence.clear();
    // A restored Legacy carrier absorbs the loss. A V2 carrier absorbs it
    // only after a V2 selection was observed: that carrier might predate the
    // evicted Legacy tombstone. Absence alone proves no flip was observed.
    if !index.codex_counting_evicted_legacy.is_empty() {
        // Borrow at most 256 hashes. Walk the index once, rather than once per
        // diagnostic record, and allocate no copied owner strings.
        let mut pending = index
            .codex_counting_evicted_legacy
            .owners
            .iter()
            .map(|record| (record.owner.as_str(), record.selected_v2))
            .collect::<BTreeMap<_, _>>();
        // A restored tombstone is also a committed carrier. Absorb before
        // absence GC below: losing that restored carrier to GC later must not
        // be attributed to the earlier cap eviction.
        pending.retain(|owner, selected_v2| {
            !index
                .codex_counting_tombstones
                .get(*owner)
                .is_some_and(|tombstone| absorbs_evicted_legacy(tombstone.evidence, *selected_v2))
        });
        for entry in index.files.values() {
            if let Some(owner) = proven_owner(entry) {
                if pending.get(owner).is_some_and(|selected_v2| {
                    absorbs_evicted_legacy(AckEvidence::of_view(Some(entry)), *selected_v2)
                }) {
                    pending.remove(owner);
                }
            }
        }
        let absorbed = index
            .codex_counting_evicted_legacy
            .owners
            .iter()
            .map(|record| !pending.contains_key(record.owner.as_str()))
            .collect::<Vec<_>>();
        drop(pending);
        let mut absorbed = absorbed.into_iter();
        index
            .codex_counting_evicted_legacy
            .owners
            .retain(|_| !absorbed.next().unwrap());
    }
    collect_tombstones(index, owners, absence_coverage);
    if cutover_unix_ms().is_none() {
        return;
    }
    let mut by_owner = owners
        .values()
        .map(|owner| (owner.clone(), AckEvidence::None))
        .collect::<BTreeMap<_, _>>();
    for (path, entry) in &index.files {
        let evidence = group_evidence(Some(entry));
        if evidence == AckEvidence::None {
            continue;
        }
        let binding = proven_owner(entry)
            .or_else(|| owners.get(path).map(String::as_str))
            .filter(|owner| valid_codex_protected_owner(owner));
        if let Some(owner) = binding {
            if let Some(previous) = by_owner.get_mut(owner) {
                *previous = previous.combine(evidence);
            }
        } else {
            for id in codex_session_id_candidates_from_path(Path::new(path)) {
                if let Some(previous) = by_owner.get_mut(&codex_protected_owner(&id)) {
                    *previous = AckEvidence::LegacyAcked;
                }
            }
        }
    }
    for (owner, tombstone) in &index.codex_counting_tombstones {
        if let Some(previous) = by_owner.get_mut(owner) {
            *previous = previous.combine(tombstone.evidence);
        }
    }
    index.codex_counting_moved_evidence = owners
        .iter()
        .filter_map(|(path, owner)| {
            let evidence = by_owner[owner];
            (evidence != AckEvidence::None).then(|| (path.clone(), evidence))
        })
        .collect();
}

fn candidate_evidence(candidate: &CandidateFile, index: &ScanIndex) -> AckEvidence {
    key_evidence(&local_index_key(&candidate.path), index)
}

fn key_evidence(key: &str, index: &ScanIndex) -> AckEvidence {
    AckEvidence::of_view(index.files.get(key)).combine(
        index
            .codex_counting_moved_evidence
            .get(key)
            .copied()
            .unwrap_or(AckEvidence::None),
    )
}

pub(super) fn members_evidence<'a>(
    members: impl IntoIterator<Item = &'a CandidateFile>,
    index: &ScanIndex,
) -> AckEvidence {
    if cutover_unix_ms().is_none() {
        return AckEvidence::None;
    }
    members
        .into_iter()
        .fold(AckEvidence::None, |evidence, member| {
            evidence.combine(candidate_evidence(member, index))
        })
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
    let evidence = candidate_evidence(candidate, index);
    configure(&mut parser.accumulator, evidence, Some(cutover));
}

/// The cursor's view while inactive: no counting state is configured.
const INACTIVE_VIEW: &str = "legacy";

/// The counting view of a singleton's index entry (cursor K8): what
/// `configure_singleton` would configure now, as the cursor job records it.
pub(super) fn singleton_view(candidate: &CandidateFile, index: &ScanIndex) -> String {
    let Some(cutover) = cutover_unix_ms() else {
        return INACTIVE_VIEW.to_owned();
    };
    let evidence = candidate_evidence(candidate, index);
    view(evidence, cutover)
}

/// `singleton_view` by index key: the counting view an M1 durable record
/// binds to (written after a save and checked at restore, without a
/// candidate).
#[cfg(unix)]
pub(super) fn singleton_view_of_key(key: &str, index: &ScanIndex) -> String {
    let Some(cutover) = cutover_unix_ms() else {
        return INACTIVE_VIEW.to_owned();
    };
    view(key_evidence(key, index), cutover)
}

/// The counting view of a joined group (cursor K8): what
/// `configure_group_once` would configure now from every member entry.
pub(super) fn group_view<'a>(
    members: impl IntoIterator<Item = &'a CandidateFile>,
    index: &ScanIndex,
) -> String {
    let Some(cutover) = cutover_unix_ms() else {
        return INACTIVE_VIEW.to_owned();
    };
    view(members_evidence(members, index), cutover)
}

/// The recorded form of an active configuration.
pub(super) fn view(evidence: AckEvidence, cutover_unix_ms: i64) -> String {
    format!("{cutover_unix_ms}:{}", evidence.view_name())
}

/// The one counting reuse predicate for both restore paths, a retained
/// reduction (`old.filter`) and a paused cursor job: the restored state
/// continues only under the rule a parser configured now would select.
/// Both unset while inactive.
pub(super) fn reusable(
    old: Option<&codex_usage_occurrence::CodexCounting>,
    fresh: Option<&codex_usage_occurrence::CodexCounting>,
) -> bool {
    match (old, fresh) {
        (None, None) => true,
        (Some(old), Some(fresh)) => old.reusable_under(fresh),
        _ => false,
    }
}

/// `reusable` against a `singleton_view` instead of a configured parser. An
/// unrecognised view never continues.
pub(super) fn reusable_under_view(accumulator: &SnapshotAccumulator, view: &str) -> bool {
    let fresh = if view == INACTIVE_VIEW {
        None
    } else {
        let Some((cutover, evidence)) = view.split_once(':') else {
            return false;
        };
        let (Ok(cutover), Some(evidence)) =
            (cutover.parse::<i64>(), AckEvidence::of_view_name(evidence))
        else {
            return false;
        };
        Some(codex_usage_occurrence::CodexCounting::new(
            evidence,
            Some(cutover),
        ))
    };
    reusable(accumulator.codex_counting.as_deref(), fresh.as_ref())
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

crate::heap_layout_bound::fields!(EvictedLegacyOwner; owner, selected_v2);
crate::heap_layout_bound::fields!(EvictedLegacyOwners; owners);
crate::heap_layout_bound::fields!(CountingTombstone; evidence, retired_in, created_unix_ms);
