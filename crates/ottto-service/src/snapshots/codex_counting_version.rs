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

/// At most this many retired owners keep counting evidence (at most about 150
/// bytes each in heap and on disk: a 64-byte owner hash, the retiring
/// generation's census timestamp and the evidence; about 150 KiB when full).
/// A full map first drops V2-only evidence, which can change a resumed job's
/// view but never a decision, then the oldest Legacy evidence retired in an
/// earlier traversal generation (disclosed residual: that owner's moved file,
/// if any, has gone a full walk unparsed). Legacy evidence of the current
/// generation is never evicted: the retirement is refused and the entry keeps
/// its own evidence until the next generation frees a slot.
pub(super) const MAX_COUNTING_TOMBSTONES: usize = 1024;

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
}

/// The first valid owner a complete parse proved for this entry. An invalid
/// (corrupt or future-format) binding never masks a valid one.
fn proven_owner(entry: &ScanIndexEntry) -> Option<&String> {
    [
        entry.codex_counting_owner.as_ref(),
        entry.codex_protected_owner.as_ref(),
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
        Some(owner) => vec![(owner.clone(), evidence)],
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
        // V2-only evidence first; then Legacy evidence retired in an earlier
        // traversal generation, oldest first: a full later walk has passed it
        // unabsorbed, so its owner was most likely deleted, not moved.
        let mut earlier = tombstones
            .iter()
            .filter(|(_, tombstone)| {
                tombstone.evidence == AckEvidence::LegacyAcked && tombstone.retired_in != retired_in
            })
            .map(|(owner, tombstone)| (tombstone.retired_in.as_str(), owner.as_str()))
            .collect::<Vec<_>>();
        earlier.sort_unstable();
        let evictable = tombstones
            .iter()
            .filter(|(_, tombstone)| tombstone.evidence != AckEvidence::LegacyAcked)
            .map(|(owner, _)| owner.as_str())
            .chain(earlier.into_iter().map(|(_, owner)| owner))
            // Never an owner this retirement is about to (re)write.
            .filter(|owner| !retired.iter().any(|(rewritten, _)| rewritten == owner))
            .take(short)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if evictable.len() < short {
            // Only this generation's Legacy evidence: a burst still in flight.
            return false;
        }
        let mut legacy_evicted = 0usize;
        for owner in evictable {
            if tombstones
                .remove(&owner)
                .is_some_and(|tombstone| tombstone.evidence == AckEvidence::LegacyAcked)
            {
                legacy_evicted += 1;
            }
        }
        if legacy_evicted > 0 {
            eprintln!(
                "ottto-service: Codex counting tombstones full; evicted {legacy_evicted} \
                 earlier-generation Legacy owner(s)"
            );
        }
    }
    for (owner, evidence) in retired {
        let tombstone = tombstones.entry(owner).or_insert(CountingTombstone {
            evidence: AckEvidence::None,
            retired_in: String::new(),
        });
        tombstone.evidence = tombstone.evidence.combine(evidence);
        tombstone.retired_in.clone_from(&retired_in);
    }
    true
}

/// Free tombstone slots, whatever the cutover, from the index state this page
/// loaded: an owner whose live, proven entry already carries at least the
/// same evidence, or an owner absent from a complete inventory of a later
/// traversal generation than the one that retired it (a fresh full walk, so a
/// rename in flight during the retiring generation's walk cannot drop it).
fn collect_tombstones(index: &mut ScanIndex, owners: &BTreeMap<String, String>, complete: bool) {
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
            let absent = complete
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
    complete: bool,
) {
    index.codex_counting_moved_evidence.clear();
    collect_tombstones(index, owners, complete);
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
            .or_else(|| owners.get(path))
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
    let key = local_index_key(&candidate.path);
    AckEvidence::of_view(index.files.get(&key)).combine(
        index
            .codex_counting_moved_evidence
            .get(&key)
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

crate::heap_layout_bound::fields!(CountingTombstone; evidence, retired_in);
