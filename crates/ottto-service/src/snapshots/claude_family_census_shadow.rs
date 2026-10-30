//! E7-8a: per-family Claude census completion, in shadow.
//!
//! Each Claude page evaluates, for the families its selection touched, the
//! families a parse attested on the previous page, and a rotating cursor of at
//! most 64 other roots, whether the family would be complete in the current
//! window, and emits counts only. The predicate is pure: it never sets a bit
//! (source `census_complete`, manifest, wire, account window), calls a fold,
//! retires, loads evidence, schedules or reads. [`FamilyConsumer`] names the
//! only consumers E7-8b may wire it to; 8a wires none.
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
//! Runtime state (rotation cursor, root path counts, attestations, sticky
//! vetoes, `first_pending_at`) is process-local, bounded and charged in
//! `runtime_heap_bytes`; it is never persisted and never used for a decision.
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
/// Member keys all of one page's lookups may visit. Families past it are
/// counted `families_unevaluated_member_budget`, not evaluated.
pub(super) const MAX_MEMBER_KEYS_PER_PAGE: usize = 16_384;
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
    /// A member has a deferred ownership hold or a decode hold.
    Held,
    /// The root has an authority quarantine record, or a member an owned-start
    /// census witness.
    Quarantine,
    /// A member is this generation's non-progressing residue.
    Residue,
    /// No valid account proof binds every member at its current revision:
    /// missing or invalid pending, member set mismatch (a new member without
    /// its own proof), an observed member with no index entry, or an empty
    /// (changed or re-armed) fingerprint.
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

/// The consumers E7-8b may wire a complete verdict to once Lead B and SOURCE
/// clear them (Q-LB-3, Q-SOURCE-2). Anything not named here, including the
/// source census bit and the existing account/usage folds, never consumes a
/// family verdict. Unused in 8a.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FamilyConsumer {
    /// Mark only that root's current account window.
    AccountWindowMark,
    /// Census record aging through the source-wide keep-overlap rule.
    CensusRecordAging,
    /// Evidence already admitted under the shared strict-cohort allowance.
    ScopedEvidenceLoad,
    /// Per-family retry and held-family scheduling.
    FamilyRetrySchedule,
}

impl Completion {
    /// Whether this verdict may feed `consumer`. 8a enables none.
    #[allow(dead_code)]
    pub(super) fn permits(self, _consumer: FamilyConsumer) -> bool {
        false
    }
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
    families: Vec<FamilyRef>,
    over_cap: u64,
}

impl Touched {
    pub(super) fn from_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Self {
        Self::from_keys(paths.into_iter().map(local_index_key), MAX_TOUCHED_FAMILIES)
    }

    fn from_keys(keys: impl IntoIterator<Item = String>, cap: usize) -> Self {
        let mut families = BTreeSet::new();
        let mut over_cap = 0_u64;
        for key in keys {
            let Some(family) = FamilyRef::of_key(&key) else {
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
            families: families.into_iter().collect(),
            over_cap,
        }
    }
}

crate::heap_layout_bound::fields!(FamilyRef; prefix, root);
crate::heap_layout_bound::fields!(Touched; families, over_cap);

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
    /// Index or observed keys the member lookups visited.
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

/// Global count of member paths per root, over indexed and observed keys,
/// for the cross-directory uniqueness check. Rebuilt only when its key
/// population changed: the cache key digests the key sets themselves (a
/// removal and an addition on one page leave the sizes equal). A hash
/// collision only merges counts, which fails closed.
#[derive(Debug, Default)]
pub(super) struct RootCounts {
    key: Option<RootCountsKey>,
    counts: Vec<(u64, u32)>,
    overflowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootCountsKey {
    generation: u64,
    files: SetDigest,
    observed: SetDigest,
    confirmed_empty: SetDigest,
}

/// Order-free digest of a key set: size, wrapping sum and xor of mixed
/// key hashes. O(n) hashing, no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetDigest(usize, u64, u64);

impl SetDigest {
    fn of<'k>(keys: impl Iterator<Item = &'k String>) -> Self {
        keys.fold(Self(0, 0, 0), |Self(len, sum, xor), key| {
            let mixed = mix64(hash64(key.as_bytes()));
            Self(len + 1, sum.wrapping_add(mixed), xor ^ mix64(mixed))
        })
    }
}

impl RootCounts {
    const fn new() -> Self {
        Self {
            key: None,
            counts: Vec::new(),
            overflowed: false,
        }
    }

    /// Bring the index up to date with `index`. Returns true when it rebuilt.
    fn refresh(&mut self, index: &ScanIndex, traversal: &ScanTraversalCheckpoint) -> bool {
        let key = RootCountsKey {
            generation: generation_tag(traversal),
            files: SetDigest::of(index.files.keys()),
            observed: SetDigest::of(traversal.observed_index_keys.iter()),
            confirmed_empty: SetDigest::of(index.confirmed_empty_files.iter()),
        };
        if self.key.as_ref() == Some(&key) {
            return false;
        }
        *self = Self::build(index, traversal);
        self.key = Some(key);
        true
    }

    /// Bounded while it collects: past `MAX_ROOT_COUNTS` distinct roots it
    /// stops and reports itself overflowed.
    pub(super) fn build(index: &ScanIndex, traversal: &ScanTraversalCheckpoint) -> Self {
        let keys = index
            .files
            .keys()
            .chain(
                traversal
                    .observed_index_keys
                    .iter()
                    .filter(|key| !index.files.contains_key(*key)),
            )
            .filter(|key| !index.confirmed_empty_files.contains(*key))
            .filter_map(|key| claude_index_path_member_ref(Path::new(key.as_str())));
        let mut counts = BTreeMap::<u64, u32>::new();
        for member in keys {
            let hash = hash64(member.root.as_bytes());
            if let Some(count) = counts.get_mut(&hash) {
                *count = count.saturating_add(1);
            } else if counts.len() == MAX_ROOT_COUNTS {
                return Self {
                    key: None,
                    counts: Vec::new(),
                    overflowed: true,
                };
            } else {
                counts.insert(hash, 1);
            }
        }
        Self {
            key: None,
            counts: counts.into_iter().collect(),
            overflowed: false,
        }
    }

    fn paths_of(&self, root: &str) -> Option<u32> {
        if self.overflowed {
            return None;
        }
        let hash = hash64(root.as_bytes());
        self.counts
            .binary_search_by_key(&hash, |(hash, _)| *hash)
            .ok()
            .map(|position| self.counts[position].1)
    }

    fn heap_bytes(&self) -> usize {
        self.counts.capacity() * size_of::<(u64, u32)>()
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
/// is presence, not attestation. State only; no read.
pub(super) fn equality_skip(index: &ScanIndex, candidate: &CandidateFile, now: u64) -> bool {
    let key = local_index_key(&candidate.path);
    if candidate.source_file_fingerprint.is_empty()
        || index.file_upload_context_requires_adoption(&key)
        || index.candidate_decision_with_reason_at(candidate, now)
            != (CandidateDecision::Skip, None)
    {
        return false;
    }
    let mut changed = candidate.clone();
    changed.source_file_fingerprint.push_str("\0e7-8a");
    index.candidate_decision_with_reason_at(&changed, now)
        == (
            CandidateDecision::Parse,
            Some(CandidateParseReason::SourceChanged),
        )
}

fn hash64(bytes: &[u8]) -> u64 {
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
        Self {
            index,
            traversal,
            roots,
            attested,
            attested_current: attested.generation == generation_tag(traversal),
            vetoes,
            queued_roots,
            queued_roots_overflowed,
        }
    }

    /// Indexed and observed keys of `family`, each once, in key order, or
    /// `None` past `MAX_FAMILY_KEYS`. Confirmed-empty files hold no requests
    /// and are not members, as in `complete_claude_family_members`.
    fn members(&self, family: &FamilyRef) -> Option<Vec<&'a str>> {
        fn under<'k, V>(
            keys: impl Iterator<Item = (&'k String, V)>,
            family: &FamilyRef,
        ) -> impl Iterator<Item = &'k str> {
            let bound = family.prefix.clone();
            let prefix = family.prefix.clone();
            let root = family.root.clone();
            keys.map(|(key, _)| key.as_str())
                .take_while(move |key| key.starts_with(bound.as_str()))
                .filter(move |key| {
                    let rest = &key[prefix.len()..];
                    (rest == ".jsonl" || rest.starts_with('/'))
                        && claude_index_path_member_ref(Path::new(key))
                            .is_some_and(|member| member.root == root)
                })
                .take(MAX_FAMILY_KEYS + 1)
        }
        let start = (Bound::Included(family.prefix.as_str()), Bound::Unbounded);
        let mut keys = under(self.index.files.range::<str, _>(start), family)
            .chain(under(
                self.traversal
                    .observed_index_keys
                    .range::<str, _>(start)
                    .map(|key| (key, ())),
                family,
            ))
            .filter(|key| !self.index.confirmed_empty_files.contains(*key))
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        (keys.len() <= MAX_FAMILY_KEYS).then_some(keys)
    }

    /// `None` when `family` is complete in the current window, else its
    /// first-match reason. Pure: no stat, open, read or write.
    pub(super) fn classify(&self, family: &FamilyRef, members: &[&str]) -> Option<Incomplete> {
        let index = self.index;
        let traversal = self.traversal;
        if self.vetoes.membership_unknown()
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
        if self.vetoes.unattributed {
            return Some(Incomplete::RefusedReadUnattributed);
        }
        if members.iter().any(|key| {
            index.claude_account_deferred_holds.contains_key(*key) || index.decode_holds_file(key)
        }) {
            return Some(Incomplete::Held);
        }
        let names = members
            .iter()
            .filter_map(|key| claude_index_path_family_member(Path::new(key)))
            .map(|(_, member)| member)
            .collect::<Vec<_>>();
        if index
            .claude_usage_authority_quarantine
            .contains_key(&family.root)
            || names
                .iter()
                .any(|member| index.claude_owned_start_census.contains_key(member))
        {
            return Some(Incomplete::Quarantine);
        }
        if members
            .iter()
            .any(|key| traversal.residue.index_keys.contains(*key))
        {
            return Some(Incomplete::Residue);
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
        let revisions = members
            .iter()
            .map(|key| {
                index
                    .files
                    .get(*key)
                    .map(|entry| entry.source_file_fingerprint.as_str())
                    .filter(|revision| !revision.is_empty())
            })
            .collect::<Option<Vec<_>>>();
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
            || self.roots.paths_of(&family.root) != u32::try_from(members.len()).ok()
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
        let mut counts = FamilyCounts::default();
        for family in families {
            if counts.member_keys >= MAX_MEMBER_KEYS_PER_PAGE as u64 {
                counts.unevaluated += 1;
                continue;
            }
            let completion = match self.members(family) {
                None => {
                    counts.member_keys += MAX_FAMILY_KEYS as u64;
                    Completion::Incomplete(Incomplete::MembershipUnknown)
                }
                Some(members) if members.is_empty() => continue,
                Some(members) => {
                    counts.member_keys += members.len() as u64;
                    counts.singletons += u64::from(members.len() == 1);
                    self.classify(family, &members)
                        .map_or(Completion::Complete, Completion::Incomplete)
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
        counts
    }
}

/// The next families after `cursor` in key order, wrapping once, skipping
/// `exclude`. Visits at most `MAX_ROTATION_KEYS` keys and returns at most
/// `FAMILY_QUANTUM` families; `cursor` moves to the last key visited.
pub(super) fn rotation(
    index: &ScanIndex,
    cursor: &mut Option<String>,
    exclude: &[FamilyRef],
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
        let Some(family) = FamilyRef::of_key(key) else {
            continue;
        };
        if exclude.binary_search(&family).is_err() && seen.insert(family.clone()) {
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
    stamps: Vec<(u64, u64)>,
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
    ) -> (PendingCensusMembers, SkippedSet) {
        // One pass, never more than `MAX_FIRST_PENDING + 1` stamps held: a
        // min-heap on stamp evicts the oldest as soon as it overflows.
        let mut kept = std::collections::BinaryHeap::new();
        let mut pending = PendingCensusMembers::default();
        let mut retained = 0_u64;
        let (mut sum, mut xor) = (0_u64, 0_u64);
        // Which held stamps this pass saw (bounded by the stamps themselves),
        // so a stamp evicted from the pass is not carried back.
        let mut seen = vec![false; self.stamps.len()];
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
                .binary_search_by_key(&hash, |(hash, _)| *hash)
                .ok();
            if let Some(position) = position {
                seen[position] = true;
            }
            let previous = position.map(|position| self.stamps[position].1);
            retained += u64::from(previous.is_some());
            pending.replay_repeat += u64::from(entry.replay && previous.is_some());
            kept.push(std::cmp::Reverse((previous.unwrap_or(now), hash)));
            if kept.len() > MAX_FIRST_PENDING {
                kept.pop();
                pending.pace_evicted += 1;
            }
        }
        let mut current = kept
            .into_iter()
            .map(|std::cmp::Reverse((stamp, hash))| (hash, stamp))
            .collect::<Vec<_>>();
        current.sort_unstable();
        // A path both queued and in carry replay keeps its oldest stamp.
        current.dedup_by_key(|(hash, _)| *hash);
        let ages = current.iter().map(|(_, stamp)| now.saturating_sub(*stamp));
        pending.oldest_age_s = ages.clone().max().unwrap_or_default();
        pending.over_24h = ages.filter(|age| *age > OVER_24H_SECONDS).count() as u64;
        // Keep stamps of keys that left the queue unresolved.
        let queued = current.len();
        let carried = self
            .stamps
            .iter()
            .zip(&seen)
            .filter(|((hash, _), seen)| !**seen && !resolved(*hash))
            .map(|(stamp, _)| *stamp)
            .collect::<Vec<_>>();
        current.extend(carried);
        if current.len() > MAX_FIRST_PENDING {
            let excess = current.len() - MAX_FIRST_PENDING;
            current.sort_unstable_by_key(|(hash, stamp)| (*stamp, *hash));
            current.drain(..excess);
            pending.pace_evicted += excess as u64;
        }
        current.sort_unstable();
        pending.tracked = current.len() as u64;
        pending.unqueued_unresolved = current.len().saturating_sub(queued) as u64;
        self.stamps = current;
        let skipped = SkippedSet {
            digest: format!("{sum:016x}{xor:016x}"),
            retained,
        };
        (pending, skipped)
    }

    fn heap_bytes(&self) -> usize {
        self.stamps.capacity() * size_of::<(u64, u64)>()
    }
}

/// Process-local shadow state for one Claude index scope.
#[derive(Debug, Default)]
pub(super) struct Runtime {
    scope: String,
    scope_since: Option<u64>,
    cursor: Option<String>,
    first_pending: FirstPending,
    roots: RootCounts,
    attested: Attestations,
    sticky: Sticky,
    /// Families a page's parses attested, evaluated on the next page.
    followup: Vec<FamilyRef>,
}

impl Runtime {
    const fn new() -> Self {
        Self {
            scope: String::new(),
            scope_since: None,
            cursor: None,
            first_pending: FirstPending::new(),
            roots: RootCounts::new(),
            attested: Attestations::new(),
            sticky: Sticky::new(),
            followup: Vec::new(),
        }
    }

    /// Another index scope: none of this state applies to it.
    fn align_scope(&mut self, scope: &str) {
        if self.scope != scope {
            *self = Self::new();
            self.scope = scope.to_owned();
        }
    }

    pub(super) fn attest(&mut self, generation: u64, key: &str, revision: &str) {
        self.attested.record(generation, key, revision);
    }

    fn heap_bytes(&self) -> usize {
        self.scope.capacity()
            + self.cursor.as_ref().map_or(0, String::capacity)
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
    pub(super) root_index_rebuilt: bool,
    pub(super) root_index_overflowed: bool,
    pub(super) queued_roots_overflowed: bool,
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
    pub(super) cost: Cost,
}

/// One Claude page's shadow evaluation, against `runtime`. Reads only `index`
/// (persisted state and the page's traversal checkpoint) and this page's
/// `parsed` (key, revision) pairs; writes only `runtime`.
pub(super) fn evaluate_page<'p>(
    runtime: &mut Runtime,
    index: &ScanIndex,
    touched: &Touched,
    parsed: impl IntoIterator<Item = (&'p str, &'p str)>,
    scope: &str,
    now: u64,
) -> Option<PageCounts> {
    let traversal = index.traversal.as_ref()?;
    let started = super::codex_compressed_input::thread_cpu_micros();
    runtime.align_scope(scope);
    let scope_since = *runtime.scope_since.get_or_insert(now);
    let generation = generation_tag(traversal);
    runtime.attested.align(generation);
    let mut parsed_keys = Vec::new();
    for (key, revision) in parsed {
        runtime.attested.record(generation, key, revision);
        parsed_keys.push(key.to_owned());
    }
    runtime.attested.flush();
    let followup = std::mem::take(&mut runtime.followup);
    let resolved = runtime.attested.take_since_observe();
    let (mut pending_census_members, skipped_set) = runtime.first_pending.observe(
        skipped_view(index),
        |hash| resolved.binary_search(&hash).is_ok(),
        now,
    );
    pending_census_members.stamped_for_s = now.saturating_sub(scope_since);
    let (vetoes, sticky_vetoes) =
        runtime
            .sticky
            .latch(generation, Vetoes::current(index, traversal), now);
    // Unknown membership decides every family before uniqueness matters.
    let root_index_rebuilt =
        !vetoes.membership_unknown() && runtime.roots.refresh(index, traversal);
    let mut excluded = touched.families.clone();
    excluded.extend(followup.iter().cloned());
    excluded.sort_unstable();
    excluded.dedup();
    let rotated = rotation(index, &mut runtime.cursor, &excluded);
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
    runtime.followup = Touched::from_keys(parsed_keys, MAX_FOLLOWUP_FAMILIES).families;
    let cost = Cost {
        predicate_cpu_us: super::codex_compressed_input::thread_cpu_micros()
            .saturating_sub(started),
        families_evaluated: families.evaluated,
        root_index_rebuilt,
        root_index_overflowed: runtime.roots.overflowed,
        queued_roots_overflowed,
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
        cost,
    })
}

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

/// Record the page's ordinary equality Skip of `candidate` as an attestation
/// of its current revision. Counts only; changes no decision.
pub(super) fn attest_equality_skip(
    index: &ScanIndex,
    candidate: &CandidateFile,
    now: u64,
    scope: &str,
) {
    let Some(traversal) = index.traversal.as_ref() else {
        return;
    };
    if !equality_skip(index, candidate, now) {
        return;
    }
    let generation = generation_tag(traversal);
    with_runtime(|runtime| {
        runtime.align_scope(scope);
        runtime.attest(
            generation,
            &local_index_key(&candidate.path),
            &candidate.source_file_fingerprint,
        );
    });
}

/// Evaluate and emit one Claude page's shadow counts. Counts only.
pub(super) fn observe_page(
    index: &ScanIndex,
    touched: &Touched,
    parsed: &[PendingIndexFinalization],
    scope: &str,
    now: u64,
) {
    let parsed = parsed
        .iter()
        .filter(|finalization| finalization.parse_complete)
        .map(|finalization| {
            (
                finalization.index_key.as_str(),
                finalization.source_file_fingerprint.as_str(),
            )
        });
    if let Some(counts) =
        with_runtime(|runtime| evaluate_page(runtime, index, touched, parsed, scope, now))
    {
        crate::local_resource_diagnostics::claude_family_census_shadow(&counts);
    }
}
