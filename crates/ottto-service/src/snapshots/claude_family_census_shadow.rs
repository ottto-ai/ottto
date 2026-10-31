//! E7-8a: per-family Claude census completion, in shadow.
//!
//! Each Claude page evaluates, for the families its selection touched, the
//! families a parse attested on the previous page, and a rotating cursor of at
//! most 64 other roots, whether the family would be complete in the current
//! window, and emits counts only. The predicate is pure: it never sets a bit
//! (source `census_complete`, manifest, wire, account window), calls a fold,
//! retires, loads evidence, schedules or reads. It feeds no decisions.
//!
//! Coverage is attestation, not presence (E1 Q-E1-3). A member counts as
//! covered only when this generation recorded a real attestation of its
//! current revision: a completed parse, or the ordinary equality Skip after
//! every selection gate passed on the opened identity. Discovery-only
//! observation, carried non-proof and witness-less context debt are presence
//! only (`evidence/presence_only`). Attestations are runtime-only, so a
//! restart loses them: those families re-derive as `presence_only` until
//! ordinary authorized work attests them again; nothing is inferred.
//!
//! The account proof binds the same revision: each member's finalized
//! `identity_revision` must equal its current source/entity/body tuple, or the
//! family is `evidence` until ordinary finalization catches up. A subagent's
//! rows only gain an account from a prior witness or a family proven at a
//! terminal page, so a fresh multi-member family stays `evidence` mid-walk.
//!
//! Runtime state (rotation cursor, root path counts, attestations, sticky
//! vetoes, `first_pending_at`) is process-local, bounded and charged in
//! `runtime_heap_bytes`; it is never persisted and never used for a decision.
//! Per-page work is counted against the caps below in `cost`, and one page's
//! evaluation is one update under the runtime mutex, so no veto or attestation
//! of another caller is lost: no page visits the whole corpus.
use super::*;
use std::hash::Hasher;
use std::ops::Bound;

/// Families admitted complete per page, shared by every evaluated family.
/// Further complete families count `family_complete_deferred{quantum}`.
pub(super) const FAMILY_QUANTUM: usize = 64;
/// Bound on the families one page's selection names for evaluation.
pub(super) const MAX_TOUCHED_FAMILIES: usize = 1_024;
/// Families a page's parses name for re-evaluation on the next page.
const MAX_FOLLOWUP_FAMILIES: usize = 256;
/// Index keys the rotating cursor may visit per page.
const MAX_ROTATION_KEYS: usize = 4_096;
/// Underlying range advances all of one page's member lookups may make,
/// before filters and dedup. Families it cannot finish are counted
/// `families_unevaluated_member_budget`, not evaluated.
pub(super) const MAX_MEMBER_KEYS_PER_PAGE: usize = 16_384;
/// Range advances one page's uniqueness pass may consume; its lookahead may
/// fetch up to 2 more keys it does not consume. A corpus larger than this is
/// counted across pages, and uniqueness stays unknown until the pass ends.
pub(super) const ROOT_PASS_KEYS_PER_PAGE: usize = 8_192;
/// History gates the page lookup reads; past it every family counts `held`.
pub(super) const MAX_HISTORY_GATES: usize = 16_384;
/// Keys under one family prefix; a larger family is `membership_unknown`.
pub(super) const MAX_FAMILY_KEYS: usize = 1_024;
/// `first_pending_at` entries; the oldest stamp is evicted beyond this.
pub(super) const MAX_FIRST_PENDING: usize = 16_384;
/// Distinct roots the global path-uniqueness index holds before it reports
/// itself overflowed, which keeps every family `path_not_unique`.
pub(super) const MAX_ROOT_COUNTS: usize = 16_384;
/// Attested keys per generation; an evicted one is `presence_only` again.
pub(super) const MAX_ATTESTATIONS: usize = 16_384;
/// Page attestations buffered before they merge into the sorted set.
const ATTESTATION_FLUSH: usize = 1_024;
/// Equality Skips one page may attest. Later ones run no decision and count
/// `attest_capped`; their members stay `presence_only`.
pub(super) const MAX_EQUALITY_ATTESTS_PER_PAGE: u64 = 4_096;
const OVER_24H_SECONDS: u64 = 24 * 60 * 60;

/// First-match reason an evaluated family is incomplete. The order is the
/// match order, so the reason counts partition the incomplete count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Incomplete {
    /// Global directory closure is not proven: the directory queue has not
    /// drained, the watcher overflowed, or the walk lost namespace (an
    /// over-wide directory, a rejected symlink, an unlistable directory or
    /// entry, an unattributed unreadable remainder, an unresolved root),
    /// sticky for the generation. Also an indexed member this generation did
    /// not enumerate (deleted, or outside the window), or a family over
    /// `MAX_FAMILY_KEYS`.
    MembershipUnknown,
    /// A member is queued (census member, re-read hint or carry replay).
    /// Claude growth hints stay current-generation members (Q-E1-4).
    Queued,
    /// A member's read was refused by the size cap (`oversized_discovery`).
    RefusedRead,
    /// Unreadable, disappeared or directory-cap loss the traversal cannot
    /// attribute to a file: every family, sticky for the generation.
    RefusedReadUnattributed,
    /// A member has a deferred ownership hold or a decode hold, or a file of
    /// the root has held history emission. A literal denial is not a hold.
    Held,
    /// The root has an authority quarantine record, or a member an owned-start
    /// census witness.
    Quarantine,
    /// A member is this generation's non-progressing residue.
    Residue,
    /// No valid account proof binds every member at its current revision:
    /// missing or invalid pending, member set mismatch (a new member without
    /// its own proof), an observed member with no index entry, an empty
    /// (changed or re-armed) fingerprint, or an `identity_revision` that is
    /// missing, stale or not yet finalized for the current tuple.
    Evidence,
    /// A member's current revision has no attestation from this generation:
    /// presence (observed key, stored fingerprint) is not coverage.
    #[serde(rename = "evidence/presence_only")]
    EvidencePresenceOnly,
    /// The account proof is old-window carry, not a current-window proof.
    NotCurrentWindow,
    /// A member name maps to more than one path, the family has members
    /// outside its own directory, or global uniqueness is unknown.
    PathNotUnique,
}

/// One family's verdict. 8a only counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Completion {
    Complete,
    Incomplete(Incomplete),
}

/// A family named by the `<dir>/<root>` key prefix its members share.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FamilyRef {
    prefix: String,
    root: String,
}

impl FamilyRef {
    /// The family of a Claude transcript index key, or `None` for a key that
    /// is not a family member path.
    pub(super) fn of_key(key: &str) -> Option<Self> {
        let path = Path::new(key);
        let member = claude_index_path_member_ref(path)?;
        let prefix = match member.subagent_stem {
            None => key.strip_suffix(".jsonl")?,
            Some(_) => claude_family_subagents_dir(path, member.root)?
                .parent()?
                .to_str()?,
        };
        Some(Self {
            prefix: prefix.to_owned(),
            root: member.root.to_owned(),
        })
    }
}

/// The families one page's selection touched, deduplicated and bounded.
#[derive(Debug, Clone, Default)]
pub(super) struct Touched {
    // Immutable after selection: summarize the owned heaps once rather than
    // visiting two strings per family on every parked-frame bound.
    families: crate::owned_heap::OwnedVec<FamilyRef>,
    over_cap: u64,
}

impl Touched {
    pub(super) fn from_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Self {
        Self::from_keys(paths.into_iter().map(local_index_key), MAX_TOUCHED_FAMILIES)
    }

    fn from_keys(keys: impl IntoIterator<Item = impl AsRef<str>>, cap: usize) -> Self {
        let mut families = BTreeSet::new();
        let mut over_cap = 0_u64;
        for key in keys {
            let Some(family) = FamilyRef::of_key(key.as_ref()) else {
                continue;
            };
            if families.contains(&family) {
                continue;
            }
            if families.len() < cap {
                families.insert(family);
            } else {
                over_cap += 1;
            }
        }
        Self {
            families: families.into_iter().collect::<Vec<_>>().into(),
            over_cap,
        }
    }
}

crate::heap_layout_bound::fields!(FamilyRef; prefix, root);
crate::heap_layout_bound::split_fields!(Touched; inline: [over_cap]; heap: [families]);

/// One entry of the per-pass skipped set.
#[derive(Debug, Clone, Copy)]
pub(super) struct Skipped<'a> {
    pub(super) path: &'a ScanTraversalPath,
    /// From stale-carry replay rather than the census-member queue.
    pub(super) replay: bool,
}

/// The per-pass skipped set as a queue+replay view: census members still
/// queued at page end plus stale-carry replay (including work replayed
/// again after a refusal), exactly what `skipped_file_count_due_to_limit`
/// counts. Cap refusals are not in it, and it is not `scan_cap_hit` (which
/// #899 also raises for withheld terminal effects). No stat or read.
pub(super) fn skipped_view(index: &ScanIndex) -> impl Iterator<Item = Skipped<'_>> + '_ {
    index
        .traversal
        .iter()
        .flat_map(|traversal| {
            traversal
                .pending_candidates
                .iter()
                .filter(|candidate| candidate.census_member)
                .map(|path| Skipped {
                    path,
                    replay: false,
                })
        })
        .chain(
            index
                .claude_stale_family_carry
                .replay
                .iter()
                .map(|path| Skipped { path, replay: true }),
        )
}

/// The skipped set's paths alone.
#[cfg(test)]
pub(super) fn skipped_census_members(
    index: &ScanIndex,
) -> impl Iterator<Item = &ScanTraversalPath> + '_ {
    skipped_view(index).map(|skipped| skipped.path)
}

/// Per-family completion counts. `complete + deferred + Σ incomplete ==
/// evaluated` always holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct FamilyCounts {
    #[serde(rename = "family_census_complete")]
    pub(super) complete: u64,
    #[serde(rename = "family_census_incomplete")]
    pub(super) incomplete: BTreeMap<Incomplete, u64>,
    #[serde(rename = "family_complete_deferred")]
    pub(super) deferred: Deferred,
    #[serde(rename = "families_evaluated")]
    pub(super) evaluated: u64,
    /// Evaluated roots with a single member path (included in `evaluated`).
    #[serde(rename = "singleton_families_evaluated")]
    pub(super) singletons: u64,
    /// Families left for a later page because the member budget ran out.
    #[serde(rename = "families_unevaluated_member_budget")]
    pub(super) unevaluated: u64,
    /// Underlying range advances of the member lookups: duplicates, empties
    /// and unrelated keys included.
    #[serde(rename = "member_keys_visited")]
    pub(super) member_keys: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(super) struct Deferred {
    pub(super) quantum: u64,
}

impl FamilyCounts {
    pub(super) fn incomplete_total(&self) -> u64 {
        self.incomplete.values().sum()
    }
}

/// Global count of member paths per root, over the union of indexed and
/// observed keys (confirmed-empty ones too), for the cross-directory uniqueness
/// check.
///
/// Counted by one ordered pass over the union, at most
/// `ROOT_PASS_KEYS_PER_PAGE` advances a page, walking both inventories together
/// so each key is counted once when the cursor passes it. A key that moves from
/// observed-only to indexed stays in the union, on either side of the cursor.
/// Until a pass ends `paths_of` answers unknown: a partial count is never
/// published. A pass stays valid while `Population` holds and no page reports
/// a change that keeps it equal, so an unchanged corpus costs no key visits. A
/// hash collision only merges counts, which fails closed.
#[derive(Debug, Default)]
pub(super) struct RootCounts {
    population: Option<Population>,
    /// Sorted by root hash; partial while `pass` is set.
    counts: Vec<(u64, u32)>,
    pass: Option<RootPass>,
    overflowed: bool,
}

/// What a finished pass counted. The union can only gain a path through
/// `observed_index_keys` (its size moves unless a page also removes, which the
/// page reports) or through a parse outside it (which `evaluate_page` checks).
/// A loss only over-counts, which fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Population {
    generation: u64,
    files: usize,
    observed: usize,
}

/// Where a counting pass resumes: the last union key it counted.
#[derive(Debug, Default)]
struct RootPass {
    after: Option<String>,
}

impl RootCounts {
    const fn new() -> Self {
        Self {
            population: None,
            counts: Vec::new(),
            pass: None,
            overflowed: false,
        }
    }

    /// Forget the count: a page changed the population without moving it.
    fn invalidate(&mut self) {
        self.population = None;
    }

    /// Start over if the population moved, then count up to `budget` range
    /// advances of the union. Returns the advances made and whether the count
    /// restarted.
    pub(super) fn advance(
        &mut self,
        index: &ScanIndex,
        traversal: &ScanTraversalCheckpoint,
        budget: usize,
    ) -> (usize, bool) {
        let population = Population {
            generation: generation_tag(traversal),
            files: index.files.len(),
            observed: traversal.observed_index_keys.len(),
        };
        let restarted = self.population != Some(population);
        if restarted {
            self.population = Some(population);
            self.counts.clear();
            self.overflowed = false;
            self.pass = Some(RootPass::default());
        }
        let Some(mut pass) = self.pass.take() else {
            return (0, restarted);
        };
        let bounds = after(&pass.after);
        let mut files = index
            .files
            .range::<str, _>(bounds)
            .map(|(key, _)| key)
            .peekable();
        let mut observed = traversal
            .observed_index_keys
            .range::<str, _>(bounds)
            .peekable();
        let mut roots = Vec::new();
        let mut last = None;
        let mut visited = 0;
        let finished = loop {
            let key = match (files.peek().copied(), observed.peek().copied()) {
                (None, None) => break true,
                (Some(key), None) | (None, Some(key)) => key,
                (Some(file), Some(seen)) => file.min(seen),
            };
            // A key in both inventories takes two advances.
            if budget - visited < 2 {
                break false;
            }
            visited += usize::from(files.next_if_eq(&key).is_some());
            visited += usize::from(observed.next_if_eq(&key).is_some());
            last = Some(key);
            if let Some(member) = claude_index_path_member_ref(Path::new(key.as_str())) {
                roots.push(hash64(member.root.as_bytes()));
            }
        };
        if let Some(last) = last {
            pass.after = Some(last.clone());
        }
        self.merge(roots);
        self.pass = (!finished && !self.overflowed).then_some(pass);
        (visited, restarted)
    }

    /// Bounded while it merges: past `MAX_ROOT_COUNTS` distinct roots the
    /// count empties and stays overflowed until the population moves.
    fn merge(&mut self, roots: Vec<u64>) {
        let mut fresh = Vec::new();
        for root in roots {
            match self.counts.binary_search_by_key(&root, |(hash, _)| *hash) {
                Ok(position) => {
                    let count = &mut self.counts[position].1;
                    *count = count.saturating_add(1);
                }
                Err(_) => fresh.push(root),
            }
        }
        fresh.sort_unstable();
        self.counts.extend(
            fresh
                .chunk_by(|left, right| left == right)
                .map(|run| (run[0], u32::try_from(run.len()).unwrap_or(u32::MAX))),
        );
        self.counts.sort_unstable();
        self.overflowed = self.counts.len() > MAX_ROOT_COUNTS;
        if self.overflowed {
            self.counts = Vec::new();
        }
        self.counts.shrink_to(MAX_ROOT_COUNTS);
    }

    /// The whole count in one call, for fixtures.
    #[cfg(test)]
    pub(super) fn build(index: &ScanIndex, traversal: &ScanTraversalCheckpoint) -> Self {
        let mut counts = Self::new();
        counts.advance(index, traversal, usize::MAX);
        counts
    }

    /// The root's path count, or `None` while it is unknown.
    pub(super) fn paths_of(&self, root: &str) -> Option<u32> {
        if self.pass.is_some() || self.overflowed || self.population.is_none() {
            return None;
        }
        let hash = hash64(root.as_bytes());
        self.counts
            .binary_search_by_key(&hash, |(hash, _)| *hash)
            .ok()
            .map(|position| self.counts[position].1)
    }

    fn complete(&self) -> bool {
        self.population.is_some() && self.pass.is_none() && !self.overflowed
    }

    fn heap_bytes(&self) -> usize {
        self.counts.capacity() * size_of::<(u64, u32)>()
            + self
                .pass
                .as_ref()
                .and_then(|pass| pass.after.as_ref())
                .map_or(0, String::capacity)
    }
}

/// The range bounds after a resume key.
fn after(key: &Option<String>) -> (Bound<&str>, Bound<&str>) {
    match key.as_deref() {
        Some(key) => (Bound::Excluded(key), Bound::Unbounded),
        None => (Bound::Unbounded, Bound::Unbounded),
    }
}

/// Runtime attestations of member revisions in one generation: a completed
/// parse of the revision, or the ordinary equality Skip of the opened
/// identity after every selection gate. Never persisted; a lost or evicted
/// attestation only leaves its member `presence_only`.
#[derive(Debug, Default)]
pub(super) struct Attestations {
    generation: u64,
    /// (key hash, revision hash), sorted by key, at most `MAX_ATTESTATIONS`.
    entries: Vec<(u64, u64)>,
    /// Recent attestations, merged every `ATTESTATION_FLUSH` and per page.
    recent: Vec<(u64, u64)>,
    /// Keys attested since the last `first_pending_at` pass: only these
    /// resolve a stamp, so an older attestation of a requeued key does not.
    since_observe: Vec<u64>,
    evicted: u64,
}

impl Attestations {
    const fn new() -> Self {
        Self {
            generation: 0,
            entries: Vec::new(),
            recent: Vec::new(),
            since_observe: Vec::new(),
            evicted: 0,
        }
    }

    /// Forget every attestation of another generation.
    fn align(&mut self, generation: u64) {
        if self.generation != generation {
            *self = Self::new();
            self.generation = generation;
        }
    }

    pub(super) fn record(&mut self, generation: u64, key: &str, revision: &str) {
        if revision.is_empty() {
            return;
        }
        self.align(generation);
        let key = hash64(key.as_bytes());
        self.recent.push((key, hash64(revision.as_bytes())));
        // Past the bound a stamp just stays unresolved (it ages too long).
        if self.since_observe.len() < MAX_ATTESTATIONS {
            self.since_observe.push(key);
        }
        if self.recent.len() >= ATTESTATION_FLUSH {
            self.flush();
        }
    }

    pub(super) fn flush(&mut self) {
        if self.recent.is_empty() {
            return;
        }
        // Newest first, so a stable sort and dedup keep the latest revision.
        let mut merged = std::mem::take(&mut self.recent);
        merged.reverse();
        merged.append(&mut self.entries);
        merged.sort_by_key(|(key, _)| *key);
        merged.dedup_by_key(|(key, _)| *key);
        if merged.len() > MAX_ATTESTATIONS {
            self.evicted += (merged.len() - MAX_ATTESTATIONS) as u64;
            merged.truncate(MAX_ATTESTATIONS);
        }
        // `append` may have doubled it; keep the retained bound exact.
        merged.shrink_to(MAX_ATTESTATIONS);
        self.entries = merged;
    }

    fn covers(&self, key: &str, revision: &str) -> bool {
        !revision.is_empty()
            && self.revision_of(hash64(key.as_bytes())) == Some(hash64(revision.as_bytes()))
    }

    fn revision_of(&self, key: u64) -> Option<u64> {
        self.entries
            .binary_search_by_key(&key, |(key, _)| *key)
            .ok()
            .map(|position| self.entries[position].1)
    }

    /// Keys attested since the last call, sorted.
    fn take_since_observe(&mut self) -> Vec<u64> {
        let mut keys = std::mem::take(&mut self.since_observe);
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn heap_bytes(&self) -> usize {
        (self.entries.capacity() + self.recent.capacity()) * size_of::<(u64, u64)>()
            + self.since_observe.capacity() * size_of::<u64>()
    }
}

/// The generation an attestation or sticky veto belongs to.
pub(super) fn generation_tag(traversal: &ScanTraversalCheckpoint) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(traversal.context_fingerprint.as_bytes());
    hasher.write_u8(0);
    hasher.write(traversal.census_window_end.as_bytes());
    hasher.finish()
}

/// True when the page's Skip of `candidate` is the ordinary equality Skip:
/// every selection gate passed and the opened identity equals the stored
/// revision. Re-evaluated against a perturbed revision, that branch alone
/// turns into `SourceChanged`; a hold, quarantine, decode or terminal
/// disposition Skip does not. Witness-less context debt held by its backoff
/// is presence, not attestation. State only; no read. `decision_calls` counts
/// the candidate decisions this runs.
#[inline(never)]
pub(super) fn equality_skip(
    index: &ScanIndex,
    candidate: &CandidateFile,
    now: u64,
    decision_calls: &mut u64,
) -> bool {
    let key = local_index_key(&candidate.path);
    if candidate.source_file_fingerprint.is_empty()
        || index.file_upload_context_requires_adoption(&key)
    {
        return false;
    }
    *decision_calls += 1;
    if index.candidate_decision_with_reason_at(candidate, now) != (CandidateDecision::Skip, None) {
        return false;
    }
    let mut changed = candidate.clone();
    changed.source_file_fingerprint.push_str("\0e7-8a");
    *decision_calls += 1;
    index.candidate_decision_with_reason_at(&changed, now)
        == (
            CandidateDecision::Parse,
            Some(CandidateParseReason::SourceChanged),
        )
}

pub(super) fn hash64(bytes: &[u8]) -> u64 {
    // Fixed keys: deterministic within one process, never persisted.
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

/// SplitMix64 finalizer, so the order-free skipped-set digest mixes bits.
fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Source-wide vetoes of one page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Vetoes {
    /// Enumeration still open: the directory queue or a watcher overflow.
    pub(super) enumeration_open: bool,
    /// The walk lost namespace (directory closure cannot be proven).
    pub(super) namespace_loss: bool,
    /// Unattributed read or namespace loss.
    pub(super) unattributed: bool,
}

impl Vetoes {
    /// From this page's checkpoint alone; `Sticky` keeps the loss vetoes up
    /// for the generation even if a counter later reads zero.
    pub(super) fn current(index: &ScanIndex, traversal: &ScanTraversalCheckpoint) -> Self {
        let counts = &traversal.counts;
        Self {
            enumeration_open: !traversal.pending_directories.is_empty()
                || traversal.watcher_hint_seen,
            namespace_loss: counts.directory_entry_cap_exceeded_count > 0
                || counts.symlink_rejected_count > 0
                || counts
                    .unreadable_causes
                    .walk_loss(counts.unreadable_path_count as u64)
                || !index.legacy_unresolved_root_file_witnesses.is_empty(),
            unattributed: counts
                .unreadable_path_count
                .saturating_add(counts.disappeared_file_count)
                .saturating_add(counts.directory_entry_cap_exceeded_count)
                > 0,
        }
    }

    fn membership_unknown(self) -> bool {
        self.enumeration_open || self.namespace_loss
    }
}

/// Loss vetoes latched for the generation: a counter reset, new page or
/// cadence never heals them; only a new generation does.
#[derive(Debug, Default)]
struct Sticky {
    generation: u64,
    namespace_loss_since: Option<u64>,
    unattributed_since: Option<u64>,
}

/// Ages of the latched vetoes; lower bounds across restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct StickyAges {
    pub(super) namespace_loss_age_s: Option<u64>,
    pub(super) unattributed_age_s: Option<u64>,
}

impl Sticky {
    const fn new() -> Self {
        Self {
            generation: 0,
            namespace_loss_since: None,
            unattributed_since: None,
        }
    }

    fn latch(&mut self, generation: u64, current: Vetoes, now: u64) -> (Vetoes, StickyAges) {
        if self.generation != generation {
            *self = Self::new();
            self.generation = generation;
        }
        if current.namespace_loss {
            self.namespace_loss_since.get_or_insert(now);
        }
        if current.unattributed {
            self.unattributed_since.get_or_insert(now);
        }
        let vetoes = Vetoes {
            enumeration_open: current.enumeration_open,
            namespace_loss: self.namespace_loss_since.is_some(),
            unattributed: self.unattributed_since.is_some(),
        };
        let ages = StickyAges {
            namespace_loss_age_s: self
                .namespace_loss_since
                .map(|since| now.saturating_sub(since)),
            unattributed_age_s: self
                .unattributed_since
                .map(|since| now.saturating_sub(since)),
        };
        (vetoes, ages)
    }
}

/// The page's view of the persisted state and runtime attestations every
/// verdict reads.
pub(super) struct View<'a> {
    index: &'a ScanIndex,
    traversal: &'a ScanTraversalCheckpoint,
    roots: &'a RootCounts,
    attested: &'a Attestations,
    /// The attestations belong to this traversal's generation.
    attested_current: bool,
    vetoes: Vetoes,
    /// Hashes of roots with any queued candidate or carry replay. Past
    /// `MAX_ROOT_COUNTS` distinct roots it overflows and every family counts
    /// queued.
    queued_roots: BTreeSet<u64>,
    queued_roots_overflowed: bool,
    /// Sorted hashes of roots with held history, at the root like the
    /// retirement path: a held new child can be missing from `files`. Past
    /// `MAX_HISTORY_GATES` gates it overflows and every family counts held.
    held_history_roots: Vec<u64>,
    history_gates_overflowed: bool,
}

/// The shared budget of one page's member lookups, in range advances.
struct KeyBudget {
    left: usize,
    used: u64,
}

/// A family's keys under `prefix`.
struct Members<'a> {
    /// Each member once, in key order: confirmed-empty files hold no requests
    /// and are not members, as in `complete_claude_family_members`.
    live: Vec<&'a str>,
    /// Paths of the family, confirmed-empty ones included.
    paths: usize,
}

/// Why a family's key lookup stopped short.
enum Stopped {
    /// Over `MAX_FAMILY_KEYS` members.
    Oversized,
    /// The page's budget ran out first: the keys seen prove nothing.
    OutOfBudget,
}

impl<'a> View<'a> {
    pub(super) fn new(
        index: &'a ScanIndex,
        traversal: &'a ScanTraversalCheckpoint,
        roots: &'a RootCounts,
        attested: &'a Attestations,
        vetoes: Vetoes,
    ) -> Self {
        let mut queued_roots = BTreeSet::new();
        let mut queued_roots_overflowed = false;
        for member in traversal
            .pending_candidates
            .iter()
            .chain(index.claude_stale_family_carry.replay.iter())
            .filter_map(|candidate| claude_index_path_member_ref(&candidate.path))
        {
            let hash = hash64(member.root.as_bytes());
            if queued_roots.len() == MAX_ROOT_COUNTS && !queued_roots.contains(&hash) {
                queued_roots_overflowed = true;
                queued_roots = BTreeSet::new();
                break;
            }
            queued_roots.insert(hash);
        }
        let gates = &index.claude_history_emission.files;
        let history_gates_overflowed = gates.len() > MAX_HISTORY_GATES;
        let mut held_history_roots: Vec<u64> = if history_gates_overflowed {
            Vec::new()
        } else {
            gates
                .values()
                .filter(|gated| gated.held.is_some())
                .filter_map(|gated| claude_index_path_member_ref(Path::new(&gated.index_key)))
                .map(|member| hash64(member.root.as_bytes()))
                .collect()
        };
        held_history_roots.sort_unstable();
        held_history_roots.dedup();
        Self {
            index,
            traversal,
            roots,
            attested,
            attested_current: attested.generation == generation_tag(traversal),
            vetoes,
            queued_roots,
            queued_roots_overflowed,
            held_history_roots,
            history_gates_overflowed,
        }
    }

    /// Indexed and observed keys of `family`, charging `budget` every range
    /// advance before any filter or dedup.
    fn members(&self, family: &FamilyRef, budget: &mut KeyBudget) -> Result<Members<'a>, Stopped> {
        fn scan<'k>(
            mut keys: impl Iterator<Item = &'k str>,
            family: &FamilyRef,
            budget: &mut KeyBudget,
            found: &mut Vec<&'k str>,
        ) -> Result<(), Stopped> {
            let mut matched = 0;
            loop {
                if budget.left == 0 {
                    return Err(Stopped::OutOfBudget);
                }
                let Some(key) = keys.next() else {
                    return Ok(());
                };
                budget.left -= 1;
                budget.used += 1;
                if !key.starts_with(family.prefix.as_str()) {
                    return Ok(());
                }
                let rest = &key[family.prefix.len()..];
                if (rest == ".jsonl" || rest.starts_with('/'))
                    && claude_index_path_member_ref(Path::new(key))
                        .is_some_and(|member| member.root == family.root)
                {
                    matched += 1;
                    if matched > MAX_FAMILY_KEYS {
                        return Err(Stopped::Oversized);
                    }
                    found.push(key);
                }
            }
        }
        let index = self.index;
        let traversal = self.traversal;
        let start = (Bound::Included(family.prefix.as_str()), Bound::Unbounded);
        let mut keys = Vec::new();
        let files = index.files.range::<str, _>(start);
        scan(
            files.map(|(key, _)| key.as_str()),
            family,
            budget,
            &mut keys,
        )?;
        let observed = traversal.observed_index_keys.range::<str, _>(start);
        scan(observed.map(String::as_str), family, budget, &mut keys)?;
        keys.sort_unstable();
        keys.dedup();
        if keys.len() > MAX_FAMILY_KEYS {
            return Err(Stopped::Oversized);
        }
        let paths = keys.len();
        keys.retain(|key| !index.confirmed_empty_files.contains(*key));
        Ok(Members { live: keys, paths })
    }

    /// The checks before `held`, under `vetoes`.
    fn closure(&self, family: &FamilyRef, members: &[&str], vetoes: Vetoes) -> Option<Incomplete> {
        let traversal = self.traversal;
        if vetoes.membership_unknown()
            || members
                .iter()
                .any(|key| !traversal.observed_index_keys.contains(*key))
        {
            return Some(Incomplete::MembershipUnknown);
        }
        if self.queued_roots_overflowed
            || self.queued_roots.contains(&hash64(family.root.as_bytes()))
        {
            return Some(Incomplete::Queued);
        }
        if !traversal.oversized_discovery.is_empty()
            && members.iter().any(|key| {
                traversal
                    .oversized_discovery
                    .contains_key(&oversized_discovery::path_hash(Path::new(key)))
            })
        {
            return Some(Incomplete::RefusedRead);
        }
        vetoes
            .unattributed
            .then_some(Incomplete::RefusedReadUnattributed)
    }

    fn held(&self, family: &FamilyRef, members: &[&str]) -> bool {
        let index = self.index;
        self.history_gates_overflowed
            || self
                .held_history_roots
                .binary_search(&hash64(family.root.as_bytes()))
                .is_ok()
            || members.iter().any(|key| {
                index.claude_account_deferred_holds.contains_key(*key)
                    || index.decode_holds_file(key)
            })
    }

    /// The checks between `held` and the account proof.
    fn custody(
        &self,
        family: &FamilyRef,
        members: &[&str],
        names: &[String],
    ) -> Option<Incomplete> {
        let index = self.index;
        if index
            .claude_usage_authority_quarantine
            .contains_key(&family.root)
            || names
                .iter()
                .any(|member| index.claude_owned_start_census.contains_key(member))
        {
            return Some(Incomplete::Quarantine);
        }
        members
            .iter()
            .any(|key| self.traversal.residue.index_keys.contains(*key))
            .then_some(Incomplete::Residue)
    }

    /// `None` when `family` is complete in the current window, else its
    /// first-match reason. Pure: no stat, open, read or write.
    fn classify(&self, family: &FamilyRef, family_members: &Members) -> Option<Incomplete> {
        let index = self.index;
        let traversal = self.traversal;
        let members = family_members.live.as_slice();
        if let Some(reason) = self.closure(family, members, self.vetoes) {
            return Some(reason);
        }
        if self.held(family, members) {
            return Some(Incomplete::Held);
        }
        let names = member_names(members);
        if let Some(reason) = self.custody(family, members, &names) {
            return Some(reason);
        }
        let name_set = names.iter().map(String::as_str).collect::<BTreeSet<_>>();
        let proven = index
            .claude_account_family_pending
            .get(&family.root)
            .filter(|pending| {
                !pending.invalid
                    && pending
                        .members
                        .keys()
                        .map(String::as_str)
                        .eq(name_set.iter().copied())
                    && pending
                        .member_requests
                        .keys()
                        .map(String::as_str)
                        .eq(name_set.iter().copied())
            });
        // The proof must have finalized this member's current revision.
        let revisions = members
            .iter()
            .zip(&names)
            .map(|(key, member)| {
                let entry = index
                    .files
                    .get(*key)
                    .filter(|entry| !entry.source_file_fingerprint.is_empty())?;
                let finalized = proven?
                    .member_requests
                    .get(member)?
                    .identity_revision
                    .as_ref()?;
                let current = claude_account_identity_revision(
                    &entry.source_file_fingerprint,
                    entry.last_snapshot_fingerprint.as_deref(),
                    entry.last_upload_body_witness.as_deref(),
                )?;
                (current == *finalized).then_some(entry.source_file_fingerprint.as_str())
            })
            .collect::<Option<Vec<_>>>()
            .filter(|revisions| revisions.len() == members.len());
        let (Some(pending), Some(revisions)) = (proven, revisions) else {
            return Some(Incomplete::Evidence);
        };
        if !self.attested_current
            || !members
                .iter()
                .zip(&revisions)
                .all(|(key, revision)| self.attested.covers(key, revision))
        {
            return Some(Incomplete::EvidencePresenceOnly);
        }
        if pending.census_window_end != traversal.census_window_end {
            return Some(Incomplete::NotCurrentWindow);
        }
        if name_set.len() != members.len()
            || self.roots.paths_of(&family.root) != u32::try_from(family_members.paths).ok()
        {
            return Some(Incomplete::PathNotUnique);
        }
        None
    }

    /// Classify `families` in order. The first `FAMILY_QUANTUM` complete
    /// families count complete; later complete ones count deferred. Member
    /// lookups share one page budget.
    pub(super) fn evaluate<'f>(
        &self,
        families: impl IntoIterator<Item = &'f FamilyRef>,
    ) -> FamilyCounts {
        self.evaluate_within(families, MAX_MEMBER_KEYS_PER_PAGE)
    }

    /// `evaluate` with `budget` range advances. A family the budget cannot
    /// finish is unevaluated, whatever its partial keys would have shown.
    pub(super) fn evaluate_within<'f>(
        &self,
        families: impl IntoIterator<Item = &'f FamilyRef>,
        budget: usize,
    ) -> FamilyCounts {
        let mut counts = FamilyCounts::default();
        let mut budget = KeyBudget {
            left: budget,
            used: 0,
        };
        for family in families {
            let completion = match self.members(family, &mut budget) {
                Err(Stopped::OutOfBudget) => {
                    counts.unevaluated += 1;
                    continue;
                }
                Err(Stopped::Oversized) => Completion::Incomplete(Incomplete::MembershipUnknown),
                Ok(members) if members.live.is_empty() => continue,
                Ok(members) => {
                    counts.singletons += u64::from(members.live.len() == 1);
                    let reason = self.classify(family, &members);
                    reason.map_or(Completion::Complete, Completion::Incomplete)
                }
            };
            counts.evaluated += 1;
            match completion {
                Completion::Incomplete(reason) => {
                    *counts.incomplete.entry(reason).or_default() += 1
                }
                Completion::Complete if counts.complete < FAMILY_QUANTUM as u64 => {
                    counts.complete += 1
                }
                Completion::Complete => counts.deferred.quantum += 1,
            }
        }
        counts.member_keys = budget.used;
        counts
    }
}

/// Each key's member name, in key order.
fn member_names(members: &[&str]) -> Vec<String> {
    members
        .iter()
        .filter_map(|key| claude_index_path_family_member(Path::new(key)))
        .map(|(_, member)| member)
        .collect()
}

/// The next families after `cursor` in key order, wrapping once, skipping
/// `exclude`. Visits at most `MAX_ROTATION_KEYS` keys and returns at most
/// `FAMILY_QUANTUM` families; `cursor` moves to the last key visited.
pub(super) fn rotation(
    index: &ScanIndex,
    cursor: &mut Option<String>,
    exclude: &[&FamilyRef],
    visited: &mut u64,
) -> Vec<FamilyRef> {
    let after = cursor.clone();
    let tail = match after.as_deref() {
        Some(after) => index
            .files
            .range::<str, _>((Bound::Excluded(after), Bound::Unbounded)),
        None => index.files.range::<str, _>(..),
    };
    let head = after.as_deref().map(|after| {
        index
            .files
            .range::<str, _>((Bound::Unbounded, Bound::Included(after)))
    });
    let mut seen = BTreeSet::new();
    let mut families = Vec::new();
    let mut last = None;
    for (key, _) in tail
        .chain(head.into_iter().flatten())
        .take(MAX_ROTATION_KEYS)
    {
        if families.len() == FAMILY_QUANTUM {
            break;
        }
        last = Some(key);
        *visited += 1;
        let Some(family) = FamilyRef::of_key(key) else {
            continue;
        };
        if exclude.binary_search(&&family).is_err() && seen.insert(family.clone()) {
            families.push(family);
        }
    }
    if let Some(last) = last {
        *cursor = Some(last.clone());
    }
    families
}

/// `first_pending_at`: when this process first saw each skipped-set path
/// pending, sorted by path hash. A FRESHNESS GAUGE ONLY: never an input to a
/// hold release, read grant or any other decision.
///
/// A stamp survives requeue and re-list and is dropped only once its key is
/// attested after it left the queue (the obligation resolved); an older
/// attestation of a requeued key does not resolve it. It is runtime-only, so after a restart
/// or an eviction every age is a LOWER BOUND. Beyond the bound the oldest
/// stamps are evicted and counted (`pace_evicted`); nothing is refused or
/// dropped for it.
#[derive(Debug, Default)]
pub(super) struct FirstPending {
    stamps: Vec<(u64, u64, super::money_freshness::Metadata)>,
}

/// Freshness of the skipped set. `count` counts entries (queue + replay) as
/// `skipped_file_count_due_to_limit` does; ages are lower bounds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct PendingCensusMembers {
    pub(super) count: u64,
    /// Entries from carry replay (included in `count`).
    pub(super) replay: u64,
    /// Replay entries already pending on an earlier page this process saw:
    /// repeatedly replayed (refused or unserved) work. A lower bound.
    pub(super) replay_repeat: u64,
    pub(super) oldest_age_s: u64,
    pub(super) over_24h: u64,
    /// Stamps held, including unresolved keys no longer queued.
    pub(super) tracked: u64,
    pub(super) unqueued_unresolved: u64,
    pub(super) pace_evicted: u64,
    /// How long this process has stamped this scope: no age exceeds it.
    pub(super) stamped_for_s: u64,
    #[serde(flatten)]
    pub(super) freshness: super::money_freshness::Counts,
}

/// E1's rotation diagnostic: an order-free digest of the skipped entries and
/// how many the previous page already skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct SkippedSet {
    pub(super) digest: String,
    pub(super) retained: u64,
}

impl FirstPending {
    const fn new() -> Self {
        Self { stamps: Vec::new() }
    }

    pub(super) fn observe<'p>(
        &mut self,
        skipped: impl Iterator<Item = Skipped<'p>>,
        resolved: impl Fn(u64) -> bool,
        now: u64,
        index: Option<&ScanIndex>,
        epoch: u64,
    ) -> (PendingCensusMembers, SkippedSet) {
        // One pass, never more than `MAX_FIRST_PENDING + 1` stamps held: a
        // min-heap on stamp evicts the oldest as soon as it overflows.
        let mut kept = std::collections::BinaryHeap::new();
        let mut pending = PendingCensusMembers::default();
        pending.freshness.ages_are_process_local_lower_bounds = true;
        const QUEUED: u8 = 1;
        const UNREAD: u8 = 2;
        const REPLAY: u8 = 4;
        const OBSERVED: u8 = 8;
        const KNOWN: u8 = 16;
        const CHANGED: u8 = 32;
        let mut unread_entries = 0_u64;
        let mut retained = 0_u64;
        let (mut sum, mut xor) = (0_u64, 0_u64);
        // Which held stamps this pass saw (bounded by the stamps themselves),
        // so a stamp evicted from the pass is not carried back.
        let mut seen = vec![(0_u8, 0_u64, 0_u64); self.stamps.len()];
        for entry in skipped {
            pending.count += 1;
            pending.replay += u64::from(entry.replay);
            // The index key's bytes for a UTF-8 path, so an attestation of
            // the key resolves it; a non-UTF-8 path only stays stamped.
            let hash = hash64(entry.path.path.as_os_str().as_encoded_bytes());
            let mixed = mix64(hash);
            sum = sum.wrapping_add(mixed);
            xor ^= mix64(mixed);
            let position = self
                .stamps
                .binary_search_by_key(&hash, |(hash, _, _)| *hash)
                .ok();
            let previous = position.map(|position| self.stamps[position].1);
            retained += u64::from(previous.is_some());
            pending.replay_repeat += u64::from(entry.replay && previous.is_some());
            let metadata = position.map(|p| self.stamps[p].2).unwrap_or_default();
            let indexed =
                index.and_then(|index| index.files.get(entry.path.path.to_string_lossy().as_ref()));
            let unread = indexed.is_none() && !entry.replay;
            unread_entries += u64::from(unread);
            let observed = epoch != 0 && metadata.epoch == epoch;
            let mut flags =
                QUEUED | if unread { UNREAD } else { 0 } | if entry.replay { REPLAY } else { 0 };
            if observed {
                flags |= OBSERVED;
            }
            if let Some(indexed) = indexed.filter(|_| observed) {
                flags |= KNOWN;
                if indexed.size_bytes != metadata.size
                    || indexed.modified_unix_seconds != metadata.seconds
                    || indexed
                        .modified_unix_nanos
                        .is_some_and(|nanos| nanos != metadata.nanos)
                {
                    flags |= CHANGED;
                }
            }
            if let Some(position) = position {
                let observed = &mut seen[position];
                observed.0 |= flags;
                observed.1 += 1;
                observed.2 += u64::from(unread);
            }
            kept.push(std::cmp::Reverse((
                previous.unwrap_or(now),
                hash,
                metadata,
                flags,
                1_u64,
                u64::from(unread),
            )));
            if kept.len() > MAX_FIRST_PENDING {
                kept.pop();
                pending.pace_evicted += 1;
            }
        }
        let mut current = kept
            .into_iter()
            .map(
                |std::cmp::Reverse((stamp, hash, metadata, flags, entries, unread))| {
                    (hash, stamp, metadata, flags, entries, unread)
                },
            )
            .collect::<Vec<_>>();
        current.sort_unstable();
        // A path both queued and in carry replay keeps its oldest stamp.
        current.dedup_by(|a, b| {
            if a.0 != b.0 {
                return false;
            }
            b.3 |= a.3;
            b.4 += a.4;
            b.5 += a.5;
            true
        });
        // Keep stamps of keys that left the queue unresolved.
        let carried = self
            .stamps
            .iter()
            .zip(&seen)
            .filter(|((hash, _, _), seen)| seen.0 == 0 && !resolved(*hash))
            .map(|((hash, since, metadata), _)| (*hash, *since, *metadata, 0_u8, 0_u64, 0_u64))
            .collect::<Vec<_>>();
        current.extend(carried);
        if current.len() > MAX_FIRST_PENDING {
            let excess = current.len() - MAX_FIRST_PENDING;
            current.sort_unstable_by_key(|(hash, stamp, _, _, _, _)| (*stamp, *hash));
            current.drain(..excess);
            pending.pace_evicted += excess as u64;
        }
        current.sort_unstable();
        // The heap's allocation came along; keep the retained bound exact.
        current.shrink_to(MAX_FIRST_PENDING);
        pending.tracked = current.len() as u64;
        let mut queued = 0_u64;
        let mut covered_entries = 0_u64;
        let mut covered_unread_entries = 0_u64;
        self.stamps = current
            .into_iter()
            .map(
                |(hash, since, metadata, mut flags, mut entries, mut unread)| {
                    if flags & QUEUED != 0 {
                        // The cap may discard an occurrence while another one of
                        // its key survives. Reuse the existing stamp-indexed seen
                        // buffer so all occurrences of a retained known key count.
                        if let Ok(position) =
                            self.stamps.binary_search_by_key(&hash, |stamp| stamp.0)
                        {
                            (flags, entries, unread) = seen[position];
                        }
                        queued += 1;
                        covered_entries += entries;
                        covered_unread_entries += unread;
                        let age = now.saturating_sub(since);
                        pending.oldest_age_s = pending.oldest_age_s.max(age);
                        pending.over_24h += u64::from(age > OVER_24H_SECONDS);
                        let row = &mut pending.freshness;
                        if flags & UNREAD != 0 && flags & REPLAY == 0 {
                            row.discovered_unread_tracked_files += 1;
                            row.oldest_discovered_unread_age_seconds =
                                row.oldest_discovered_unread_age_seconds.max(age);
                            row.discovered_unread_over_24h_tracked_files +=
                                u64::from(age > OVER_24H_SECONDS);
                        } else {
                            row.indexed_or_replay_tracked_files += 1;
                        }
                        row.metadata_observed_files += u64::from(flags & OBSERVED != 0);
                        if flags & KNOWN != 0 {
                            row.changed_since_scan_files += u64::from(flags & CHANGED != 0);
                            row.unchanged_since_scan_files += u64::from(flags & CHANGED == 0);
                        } else {
                            row.changed_since_scan_unknown_files += 1;
                        }
                    }
                    (hash, since, metadata)
                },
            )
            .collect();
        // collect may reuse the wider transient allocation; cap retained bytes.
        self.stamps.shrink_to(MAX_FIRST_PENDING);
        pending.unqueued_unresolved = pending.tracked.saturating_sub(queued);
        let row = &mut pending.freshness;
        row.skipped_untracked_entries = pending.count.saturating_sub(covered_entries);
        row.discovered_unread_untracked_entries =
            unread_entries.saturating_sub(covered_unread_entries);
        row.changed_since_scan_complete_count = (row.changed_since_scan_unknown_files == 0
            && row.skipped_untracked_entries == 0)
            .then_some(row.changed_since_scan_files);
        let skipped = SkippedSet {
            digest: format!("{sum:016x}{xor:016x}"),
            retained,
        };
        (pending, skipped)
    }

    pub(super) fn observe_metadata(
        &mut self,
        hash: u64,
        metadata: super::money_freshness::Metadata,
    ) {
        if let Ok(p) = self
            .stamps
            .binary_search_by_key(&hash, |(hash, _, _)| *hash)
        {
            self.stamps[p].2 = metadata;
        }
    }

    fn heap_bytes(&self) -> usize {
        self.stamps.capacity() * size_of::<(u64, u64, super::money_freshness::Metadata)>()
    }
}

/// One page's equality-attestation work, reset at its shadow row.
#[derive(Debug, Clone, Copy, Default)]
struct AttestMeter {
    attempts: u64,
    decision_calls: u64,
    micros: u64,
    capped: u64,
}

/// Process-local shadow state for one Claude index scope.
#[derive(Debug, Default)]
pub(super) struct Runtime {
    /// Hash of the scope, so the state's size depends on no scope string.
    scope: u64,
    scope_since: Option<u64>,
    cursor: Option<String>,
    first_pending: FirstPending,
    freshness: super::money_freshness::Episode,
    metadata_epoch: u64,
    roots: RootCounts,
    attested: Attestations,
    sticky: Sticky,
    meter: AttestMeter,
    /// Families a page's parses attested, evaluated on the next page.
    followup: Vec<FamilyRef>,
}

impl Runtime {
    const fn new() -> Self {
        Self {
            scope: 0,
            scope_since: None,
            cursor: None,
            first_pending: FirstPending::new(),
            freshness: super::money_freshness::Episode::new(),
            metadata_epoch: 1,
            roots: RootCounts::new(),
            attested: Attestations::new(),
            sticky: Sticky::new(),
            meter: AttestMeter {
                attempts: 0,
                decision_calls: 0,
                micros: 0,
                capped: 0,
            },
            followup: Vec::new(),
        }
    }

    /// Another index scope: none of this state applies to it.
    fn align_scope(&mut self, scope: &str) {
        let scope = hash64(scope.as_bytes());
        if self.scope != scope {
            *self = Self::new();
            self.scope = scope;
        }
    }

    pub(super) fn attest(&mut self, generation: u64, key: &str, revision: &str) {
        self.attested.record(generation, key, revision);
    }

    fn heap_bytes(&self) -> usize {
        self.cursor.as_ref().map_or(0, String::capacity)
            + self.first_pending.heap_bytes()
            + self.roots.heap_bytes()
            + self.attested.heap_bytes()
            + self.followup.capacity() * size_of::<FamilyRef>()
            + self
                .followup
                .iter()
                .map(|family| family.prefix.capacity() + family.root.capacity())
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct Cost {
    pub(super) predicate_cpu_us: u64,
    pub(super) families_evaluated: u64,
    /// Keys this page consumed in the uniqueness pass, with one check per
    /// parse. Excludes the pass's lookahead of up to 2 keys.
    pub(super) root_index_keys_processed: u64,
    pub(super) rotation_keys_visited: u64,
    pub(super) queue_entries_visited: u64,
    pub(super) history_gates_visited: u64,
    pub(super) root_index_restarted: bool,
    pub(super) root_index_complete: bool,
    pub(super) root_index_overflowed: bool,
    pub(super) queued_roots_overflowed: bool,
    pub(super) history_gates_overflowed: bool,
    pub(super) attested_keys: u64,
    pub(super) attestations_evicted: u64,
    /// Heap of all runtime shadow state after this page.
    pub(super) runtime_heap_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct PageCounts {
    #[serde(flatten)]
    pub(super) families: FamilyCounts,
    pub(super) touched_families: u64,
    pub(super) touched_families_over_cap: u64,
    pub(super) followup_families: u64,
    pub(super) rotation_families: u64,
    pub(super) sticky_vetoes: StickyAges,
    pub(super) pending_census_members: PendingCensusMembers,
    pub(super) skipped_set: SkippedSet,
    /// Candidate decisions the shadow itself ran for this page's Skips.
    pub(super) shadow_decision_calls: u64,
    /// Thread CPU spent in `attest_equality_skip` for this page's Skips.
    pub(super) shadow_attest_micros: u64,
    /// Equality Skips past `MAX_EQUALITY_ATTESTS_PER_PAGE`, not attested.
    pub(super) attest_capped: u64,
    pub(super) cost: Cost,
}

/// One Claude page's shadow evaluation, against `runtime`. Reads only `index`
/// (persisted state and the page's traversal checkpoint) and this page's
/// `parsed` (key, revision) pairs; writes only `runtime`. `removed_keys` says
/// the page removed observed keys.
#[inline(never)]
pub(super) fn evaluate_page<'p>(
    runtime: &mut Runtime,
    index: &ScanIndex,
    touched: &Touched,
    parsed: impl IntoIterator<Item = (&'p str, &'p str)>,
    removed_keys: bool,
    scope: &str,
    now: u64,
) -> Option<PageCounts> {
    let traversal = index.traversal.as_ref()?;
    let started = crate::context_composition::thread_cpu_micros().unwrap_or(0);
    runtime.align_scope(scope);
    let scope_since = *runtime.scope_since.get_or_insert(now);
    let generation = generation_tag(traversal);
    runtime.attested.align(generation);
    let meter = std::mem::take(&mut runtime.meter);
    let mut parsed_keys = Vec::new();
    let mut population_changed = removed_keys;
    for (key, revision) in parsed {
        runtime.attested.record(generation, key, revision);
        population_changed |= !traversal.observed_index_keys.contains(key);
        parsed_keys.push(key);
    }
    runtime.attested.flush();
    let followup = std::mem::take(&mut runtime.followup);
    let resolved = runtime.attested.take_since_observe();
    let (mut pending_census_members, skipped_set) = runtime.first_pending.observe(
        skipped_view(index),
        |hash| resolved.binary_search(&hash).is_ok(),
        now,
        Some(index),
        runtime.metadata_epoch,
    );
    pending_census_members.stamped_for_s = now.saturating_sub(scope_since);
    runtime
        .freshness
        .update(&mut pending_census_members.freshness, now);
    // Epoch wrap only loses metadata coverage; it never affects selection.
    runtime.metadata_epoch = runtime.metadata_epoch.checked_add(1).unwrap_or(1);
    if runtime.metadata_epoch == 1 {
        for (_, _, metadata) in &mut runtime.first_pending.stamps {
            *metadata = Default::default();
        }
    }
    let (vetoes, sticky_vetoes) =
        runtime
            .sticky
            .latch(generation, Vetoes::current(index, traversal), now);
    if population_changed {
        runtime.roots.invalidate();
    }
    // Unknown membership decides every family before uniqueness matters.
    let (root_keys, root_index_restarted) = if vetoes.membership_unknown() {
        (0, false)
    } else {
        runtime
            .roots
            .advance(index, traversal, ROOT_PASS_KEYS_PER_PAGE)
    };
    let mut excluded = touched.families.iter().chain(&followup).collect::<Vec<_>>();
    excluded.sort_unstable();
    excluded.dedup();
    let mut rotation_keys_visited = 0;
    let rotated = rotation(
        index,
        &mut runtime.cursor,
        &excluded,
        &mut rotation_keys_visited,
    );
    let view = View::new(index, traversal, &runtime.roots, &runtime.attested, vetoes);
    let followup_only = followup
        .iter()
        .filter(|family| touched.families.binary_search(family).is_err());
    let families = view.evaluate(
        touched
            .families
            .iter()
            .chain(followup_only)
            .chain(rotated.iter()),
    );
    debug_assert_eq!(
        families.complete + families.deferred.quantum + families.incomplete_total(),
        families.evaluated,
        "the reasons partition the incomplete count"
    );
    let queued_roots_overflowed = view.queued_roots_overflowed;
    let history_gates_overflowed = view.history_gates_overflowed;
    let queue_entries =
        traversal.pending_candidates.len() + index.claude_stale_family_carry.replay.len();
    let history_gates = index.claude_history_emission.files.len();
    let parsed_count = parsed_keys.len();
    runtime.followup = Touched::from_keys(parsed_keys, MAX_FOLLOWUP_FAMILIES)
        .families
        .into_vec();
    let cost = Cost {
        predicate_cpu_us: crate::context_composition::thread_cpu_micros()
            .unwrap_or(0)
            .saturating_sub(started),
        families_evaluated: families.evaluated,
        root_index_keys_processed: (root_keys + parsed_count) as u64,
        rotation_keys_visited,
        // The combined stamp/freshness pass and queued-root pass.
        queue_entries_visited: 2 * queue_entries as u64,
        history_gates_visited: if history_gates_overflowed {
            0
        } else {
            history_gates as u64
        },
        root_index_restarted,
        root_index_complete: runtime.roots.complete(),
        root_index_overflowed: runtime.roots.overflowed,
        queued_roots_overflowed,
        history_gates_overflowed,
        attested_keys: runtime.attested.len() as u64,
        attestations_evicted: runtime.attested.evicted,
        runtime_heap_bytes: runtime.heap_bytes() as u64,
    };
    Some(PageCounts {
        families,
        touched_families: touched.families.len() as u64,
        touched_families_over_cap: touched.over_cap,
        followup_families: followup.len() as u64,
        rotation_families: rotated.len() as u64,
        sticky_vetoes,
        pending_census_members,
        skipped_set,
        shadow_decision_calls: meter.decision_calls,
        shadow_attest_micros: meter.micros,
        attest_capped: meter.capped,
        cost,
    })
}

/// The retained worst case of one `Runtime`, in bytes, with the key length
/// assumption spelled out. See `RUNTIME`.
#[cfg(test)]
pub(super) const RUNTIME_RETAINED_WORST_BYTES: usize = {
    const LONGEST_KEY: usize = 4_096; // Linux PATH_MAX; macOS is 1,024.
    const LONGEST_ROOT: usize = 255; // One path component.
    const FOLLOWUP: usize = size_of::<FamilyRef>() + LONGEST_KEY + LONGEST_ROOT;
    MAX_FIRST_PENDING * size_of::<(u64, u64, super::money_freshness::Metadata)>()
        + MAX_ATTESTATIONS * size_of::<(u64, u64)>()
        + ATTESTATION_FLUSH * size_of::<(u64, u64)>()
        + MAX_ATTESTATIONS * size_of::<u64>()
        + MAX_ROOT_COUNTS * size_of::<(u64, u32)>()
        + MAX_FOLLOWUP_FAMILIES * FOLLOWUP
        + 2 * LONGEST_KEY
};

/// The shadow's process static. It sits OUTSIDE `heap_layout_bound` admission:
/// no cycle or overlap budget charges it, so its bound is stated here and
/// reported per page as `cost.runtime_heap_bytes`.
///
/// Retained heap, worst case, with every cap full (no maps: sorted vectors
/// only): stamps 16,384 × 48 + attestations 16,384 × 16 + attestation buffer
/// 1,024 × 16 + since-pass keys 16,384 × 8 + root counts 16,384 × 16 = 933,888
/// bytes before R1 metadata (which adds 524,288 bytes), plus follow-up families 256 × (48 + K + R) and the rotation and
/// uniqueness cursors 2K, for key length K and root length R. At K = 4,096
/// (Linux `PATH_MAX`) and R = 255 that is 2,592,512 bytes (2.47 MiB) before
/// allocator rounding; at a typical K = 200, R = 36 it is about 1.0 MiB. Inline:
/// under 512 bytes. A page's transients add at most 1.8 MiB more (1.1 MiB at
/// typical lengths), plus at most 4 MiB for enlarged stamp transients with
/// per-entry classification, outside `runtime_heap_bytes`;
/// no separate gauge-dedup allocation, outside `runtime_heap_bytes`. Counts only, so nothing is
/// refused at the bound.
///
/// `observe_page` holds this lock for its whole evaluation and each equality
/// Skip for its own attestation, so every update is whole: a sticky veto,
/// attestation or cap meter is never overwritten, and one state exists. The
/// hold is bounded by the page budgets (16,384 member advances, 8,192 root
/// advances, 4,096 rotation keys, 16,384 history gates) plus the queue passes, which are O(queue). No I/O runs under it and it nests no other lock.
#[cfg(not(test))]
static RUNTIME: Mutex<Runtime> = Mutex::new(Runtime::new());

#[cfg(test)]
thread_local! {
    static RUNTIME_FOR_TEST: std::cell::RefCell<Runtime> =
        const { std::cell::RefCell::new(Runtime::new()) };
}

#[cfg(not(test))]
fn with_runtime<T>(body: impl FnOnce(&mut Runtime) -> T) -> T {
    // Each critical section is one whole update; a poisoned value is still
    // bounded and only feeds counts.
    let mut runtime = RUNTIME.lock().unwrap_or_else(|poisoned| {
        RUNTIME.clear_poison();
        poisoned.into_inner()
    });
    body(&mut runtime)
}

#[cfg(test)]
fn with_runtime<T>(body: impl FnOnce(&mut Runtime) -> T) -> T {
    RUNTIME_FOR_TEST.with(|runtime| body(&mut runtime.borrow_mut()))
}

fn scope_of(sampling: &Option<sampled_scan::Context>) -> &str {
    sampling
        .as_ref()
        .map_or("", |context| context.namespace.0.as_str())
}

/// Record the page's ordinary equality Skip of `candidate` as an attestation
/// of its current revision, up to `MAX_EQUALITY_ATTESTS_PER_PAGE` per page.
/// Counts only; changes no decision. Called from the scan step, whose debug
/// frame is near the stack limit: it takes references only and keeps its work
/// in this frame.
#[inline(never)]
pub(super) fn attest_equality_skip(
    index: &ScanIndex,
    candidate: &CandidateFile,
    sampling: &Option<sampled_scan::Context>,
    now: u64,
) {
    if !super::money_freshness::enabled() {
        return;
    }
    let Some(traversal) = index.traversal.as_ref() else {
        return;
    };
    with_runtime(|runtime| {
        runtime.align_scope(scope_of(sampling));
        if runtime.meter.attempts >= MAX_EQUALITY_ATTESTS_PER_PAGE {
            runtime.meter.capped += 1;
            return;
        }
        runtime.meter.attempts += 1;
        let started = crate::context_composition::thread_cpu_micros().unwrap_or(0);
        if equality_skip(index, candidate, now, &mut runtime.meter.decision_calls) {
            runtime.attest(
                generation_tag(traversal),
                &local_index_key(&candidate.path),
                &candidate.source_file_fingerprint,
            );
        }
        runtime.meter.micros = runtime.meter.micros.saturating_add(
            crate::context_composition::thread_cpu_micros()
                .unwrap_or(0)
                .saturating_sub(started),
        );
    });
}

/// Evaluate one Claude page's shadow counts under the runtime mutex and emit
/// them after it. Counts only. Called from the scan step, like
/// `attest_equality_skip`.
#[inline(never)]
pub(super) fn observe_page(
    index: &ScanIndex,
    touched: &Option<Box<Touched>>,
    parsed: &[PendingIndexFinalization],
    census: &ScanCensus,
    sampling: &Option<sampled_scan::Context>,
    now: u64,
) {
    if !super::money_freshness::enabled() {
        return;
    }
    let none = Touched::default();
    let touched = touched.as_deref().unwrap_or(&none);
    let scope = scope_of(sampling);
    let parsed = parsed
        .iter()
        .filter(|finalization| finalization.parse_complete)
        .map(|finalization| {
            (
                finalization.index_key.as_str(),
                finalization.source_file_fingerprint.as_str(),
            )
        });
    let removed_keys = !census.removed_index_keys.is_empty();
    let counts = with_runtime(|runtime| {
        evaluate_page(runtime, index, touched, parsed, removed_keys, scope, now)
    });
    if let Some(mut counts) = counts {
        counts.pending_census_members.freshness.tracker_initialized =
            super::money_freshness::first_observation();
        crate::local_resource_diagnostics::claude_family_census_shadow(&counts);
    }
}

/// Reuse only metadata already observed by this pass. New/untracked keys stay
/// unknown until FirstPending admits them; no additional per-file map or stat.
#[inline(never)]
pub(super) fn observe_freshness_metadata(
    candidate: &CandidateFile,
    sampling: &Option<sampled_scan::Context>,
) {
    if !super::money_freshness::enabled() {
        return;
    }
    with_runtime(|runtime| {
        runtime.align_scope(scope_of(sampling));
        runtime.first_pending.observe_metadata(
            hash64(candidate.path.as_os_str().as_encoded_bytes()),
            super::money_freshness::Metadata::new(candidate, runtime.metadata_epoch),
        );
    });
}

#[cfg(test)]
pub(super) fn runtime_pristine_for_test() -> bool {
    with_runtime(|runtime| {
        runtime.scope_since.is_none()
            && runtime.first_pending.stamps.is_empty()
            && runtime.attested.len() == 0
            && runtime.meter.attempts == 0
    })
}
