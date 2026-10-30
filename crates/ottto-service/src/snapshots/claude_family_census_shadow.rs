//! E7-8a: per-family Claude census completion, in shadow.
//!
//! Each Claude page re-derives, for the families its selection touched plus a
//! rotating cursor of at most 64 other roots, whether the family would be
//! complete in the current window under Lead B's amended Q-LB-1 rule, and
//! emits counts only. Nothing here sets a bit, retires, folds, loads
//! evidence, schedules or reads: the source `census_complete`, the manifest
//! and the wire are never touched, and every input is persisted index state
//! plus the page's traversal checkpoint, so a restart re-derives the same
//! verdicts with zero reads.
//!
//! Runtime state (rotation cursor, root path counts, `first_pending_at`) is
//! process-local and bounded; it is never persisted, and losing it only
//! re-derives the counts or under-reports pending age.
use super::*;
use std::hash::Hasher;
use std::ops::Bound;

/// Families admitted complete per page. Further complete families are
/// counted `family_complete_deferred{quantum}` (the #855 64-root quantum).
pub(super) const FAMILY_QUANTUM: usize = 64;
/// Bound on the families one page's selection names for evaluation.
pub(super) const MAX_TOUCHED_FAMILIES: usize = 1_024;
/// Index keys the rotating cursor may visit per page.
const MAX_ROTATION_KEYS: usize = 4_096;
/// `first_pending_at` entries; the oldest stamp is evicted beyond this.
pub(super) const MAX_FIRST_PENDING: usize = 16_384;
/// Distinct roots the global path-uniqueness index holds before it reports
/// itself overflowed, which keeps every family `path_not_unique`.
pub(super) const MAX_ROOT_COUNTS: usize = 16_384;
const OVER_24H_SECONDS: u64 = 24 * 60 * 60;

/// First-match reason an evaluated family is incomplete. The order is the
/// match order, so the reason counts partition the incomplete count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Incomplete {
    /// Enumeration unhealthy (directory queue not drained, watcher
    /// overflow), or an indexed member this generation did not enumerate
    /// (deleted, or outside the window): deletions never count as covered.
    MembershipUnknown,
    /// A member is queued (census member, re-read hint or carry replay).
    Queued,
    /// A member's read was refused by the size cap (`oversized_discovery`).
    RefusedRead,
    /// The traversal counted unreadable or disappeared paths it cannot
    /// attribute to a file: every family stays incomplete.
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
    /// The account proof is old-window carry, not a current-window proof.
    NotCurrentWindow,
    /// A member name maps to more than one path, the family has members
    /// outside its own directory, or global uniqueness is unknown.
    PathNotUnique,
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
        let mut families = BTreeSet::new();
        let mut over_cap = 0_u64;
        for path in paths {
            let Some(family) = FamilyRef::of_key(&local_index_key(path)) else {
                continue;
            };
            if families.contains(&family) {
                continue;
            }
            if families.len() < MAX_TOUCHED_FAMILIES {
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

/// The per-pass skipped set: census members still queued at page end plus
/// stale-carry replay, exactly what `skipped_file_count_due_to_limit` counts.
/// Cap refusals are not in it. No stat or read.
pub(super) fn skipped_census_members(
    index: &ScanIndex,
) -> impl Iterator<Item = &ScanTraversalPath> + '_ {
    index
        .traversal
        .iter()
        .flat_map(|traversal| {
            traversal
                .pending_candidates
                .iter()
                .filter(|candidate| candidate.census_member)
        })
        .chain(index.claude_stale_family_carry.replay.iter())
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
/// population may have changed; a hash collision only merges counts, which
/// fails closed.
#[derive(Debug, Default)]
pub(super) struct RootCounts {
    key: Option<RootCountsKey>,
    counts: Vec<(u64, u32)>,
    overflowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootCountsKey {
    scope: String,
    context_fingerprint: String,
    census_window_end: String,
    files: usize,
    observed: usize,
    confirmed_empty: usize,
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
    fn refresh(
        &mut self,
        scope: &str,
        index: &ScanIndex,
        traversal: &ScanTraversalCheckpoint,
    ) -> bool {
        let key = RootCountsKey {
            scope: scope.to_owned(),
            context_fingerprint: traversal.context_fingerprint.clone(),
            census_window_end: traversal.census_window_end.clone(),
            files: index.files.len(),
            observed: traversal.observed_index_keys.len(),
            confirmed_empty: index.confirmed_empty_files.len(),
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

    fn len(&self) -> usize {
        self.counts.len()
    }
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

/// Directory enumeration this generation is not known complete: the queue
/// has not drained, the watcher overflowed, or the walk skipped a directory
/// it could not list in full (an over-wide directory, a rejected symlink).
fn enumeration_unknown(traversal: &ScanTraversalCheckpoint) -> bool {
    !traversal.pending_directories.is_empty()
        || traversal.watcher_hint_seen
        || traversal.counts.directory_entry_cap_exceeded_count > 0
        || traversal.counts.symlink_rejected_count > 0
}

/// The page's view of the persisted state every verdict reads.
pub(super) struct View<'a> {
    index: &'a ScanIndex,
    traversal: &'a ScanTraversalCheckpoint,
    roots: &'a RootCounts,
    /// Hashes of roots with any queued candidate or carry replay. Past
    /// `MAX_ROOT_COUNTS` distinct roots it overflows and every family counts
    /// queued.
    queued_roots: BTreeSet<u64>,
    queued_roots_overflowed: bool,
    /// Source-wide reasons, decided once per page.
    enumeration_unknown: bool,
    unattributed_refusal: bool,
}

impl<'a> View<'a> {
    pub(super) fn new(
        index: &'a ScanIndex,
        traversal: &'a ScanTraversalCheckpoint,
        roots: &'a RootCounts,
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
            queued_roots,
            queued_roots_overflowed,
            enumeration_unknown: enumeration_unknown(traversal),
            unattributed_refusal: traversal
                .counts
                .unreadable_path_count
                .saturating_add(traversal.counts.disappeared_file_count)
                > 0,
        }
    }

    /// Indexed and observed keys of `family`, each once, in key order.
    /// Confirmed-empty files hold no requests and are not members, as in
    /// `complete_claude_family_members`.
    fn members(&self, family: &FamilyRef) -> Vec<&'a str> {
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
        keys
    }

    /// `None` when `family` is complete in the current window, else its
    /// first-match reason. Pure over persisted state: no stat, open or read.
    pub(super) fn classify(&self, family: &FamilyRef, members: &[&str]) -> Option<Incomplete> {
        let index = self.index;
        let traversal = self.traversal;
        if self.enumeration_unknown
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
        if self.unattributed_refusal {
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
        let current_revisions = members.iter().all(|key| {
            index
                .files
                .get(*key)
                .is_some_and(|entry| !entry.source_file_fingerprint.is_empty())
        });
        let Some(pending) = proven.filter(|_| current_revisions) else {
            return Some(Incomplete::Evidence);
        };
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
    /// families count complete; later complete ones count deferred.
    pub(super) fn evaluate<'f>(
        &self,
        families: impl IntoIterator<Item = &'f FamilyRef>,
    ) -> FamilyCounts {
        let mut counts = FamilyCounts::default();
        for family in families {
            let members = self.members(family);
            counts.member_keys += members.len() as u64;
            if members.is_empty() {
                continue;
            }
            counts.evaluated += 1;
            counts.singletons += u64::from(members.len() == 1);
            match self.classify(family, &members) {
                Some(reason) => *counts.incomplete.entry(reason).or_default() += 1,
                None if counts.complete < FAMILY_QUANTUM as u64 => counts.complete += 1,
                None => counts.deferred.quantum += 1,
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

/// `first_pending_at` over the skipped set, sorted by path hash. Entries
/// that left the set drop; new ones stamp `now`. Beyond the bound the oldest
/// stamps are evicted and counted (`pace_evicted`): the gauge then
/// under-reports age, and nothing is ever refused or dropped for it.
#[derive(Debug, Default)]
pub(super) struct FirstPending {
    stamps: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct PendingCensusMembers {
    pub(super) count: u64,
    pub(super) oldest_age_s: u64,
    pub(super) over_24h: u64,
    pub(super) tracked: u64,
    pub(super) pace_evicted: u64,
}

/// E1's rotation diagnostic: a digest of the capped (skipped) set and how
/// much of it the previous page already skipped.
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
        skipped: impl Iterator<Item = &'p ScanTraversalPath>,
        now: u64,
    ) -> (PendingCensusMembers, SkippedSet) {
        // One pass, never more than `MAX_FIRST_PENDING + 1` stamps held: a
        // min-heap on stamp evicts the oldest as soon as it overflows.
        let mut kept = std::collections::BinaryHeap::new();
        let (mut count, mut retained, mut pace_evicted) = (0_u64, 0_u64, 0_u64);
        let (mut sum, mut xor) = (0_u64, 0_u64);
        for candidate in skipped {
            count += 1;
            let hash = hash64(candidate.path.as_os_str().as_encoded_bytes());
            let mixed = mix64(hash);
            sum = sum.wrapping_add(mixed);
            xor ^= mix64(mixed);
            let previous = self
                .stamps
                .binary_search_by_key(&hash, |(hash, _)| *hash)
                .ok()
                .map(|position| self.stamps[position].1);
            retained += u64::from(previous.is_some());
            kept.push(std::cmp::Reverse((previous.unwrap_or(now), hash)));
            if kept.len() > MAX_FIRST_PENDING {
                kept.pop();
                pace_evicted += 1;
            }
        }
        let mut stamps = kept
            .into_iter()
            .map(|std::cmp::Reverse((stamp, hash))| (hash, stamp))
            .collect::<Vec<_>>();
        stamps.sort_unstable();
        // A path both queued and in carry replay keeps its oldest stamp.
        stamps.dedup_by_key(|(hash, _)| *hash);
        self.stamps = stamps;
        let ages = self
            .stamps
            .iter()
            .map(|(_, stamp)| now.saturating_sub(*stamp));
        let pending = PendingCensusMembers {
            count,
            oldest_age_s: ages.clone().max().unwrap_or_default(),
            over_24h: ages.filter(|age| *age > OVER_24H_SECONDS).count() as u64,
            tracked: self.stamps.len() as u64,
            pace_evicted,
        };
        let skipped = SkippedSet {
            digest: format!("{sum:016x}{xor:016x}"),
            retained,
        };
        (pending, skipped)
    }
}

/// Process-local shadow state for one Claude index scope.
#[derive(Debug, Default)]
pub(super) struct Runtime {
    scope: String,
    cursor: Option<String>,
    first_pending: FirstPending,
    roots: RootCounts,
}

impl Runtime {
    const fn new() -> Self {
        Self {
            scope: String::new(),
            cursor: None,
            first_pending: FirstPending::new(),
            roots: RootCounts::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct Cost {
    pub(super) predicate_cpu_us: u64,
    pub(super) families_evaluated: u64,
    pub(super) root_index_rebuilt: bool,
    pub(super) root_index_roots: u64,
    pub(super) root_index_overflowed: bool,
    pub(super) queued_roots_overflowed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct PageCounts {
    #[serde(flatten)]
    pub(super) families: FamilyCounts,
    pub(super) touched_families: u64,
    pub(super) touched_families_over_cap: u64,
    pub(super) rotation_families: u64,
    pub(super) pending_census_members: PendingCensusMembers,
    pub(super) skipped_set: SkippedSet,
    pub(super) cost: Cost,
}

/// One Claude page's shadow evaluation, against `runtime`. Reads only `index`
/// (persisted state and the page's traversal checkpoint); writes only
/// `runtime`.
pub(super) fn evaluate_page(
    runtime: &mut Runtime,
    index: &ScanIndex,
    touched: &Touched,
    scope: &str,
    now: u64,
) -> Option<PageCounts> {
    let traversal = index.traversal.as_ref()?;
    let started = super::codex_compressed_input::thread_cpu_micros();
    if runtime.scope != scope {
        // Another index: its cursor and pending stamps do not apply.
        *runtime = Runtime::new();
        runtime.scope = scope.to_owned();
    }
    let (pending_census_members, skipped_set) = runtime
        .first_pending
        .observe(skipped_census_members(index), now);
    // Unknown enumeration decides every family before uniqueness matters.
    let enumeration_known = !enumeration_unknown(traversal);
    let root_index_rebuilt = enumeration_known && runtime.roots.refresh(scope, index, traversal);
    let rotated = rotation(index, &mut runtime.cursor, &touched.families);
    let view = View::new(index, traversal, &runtime.roots);
    let families = view.evaluate(touched.families.iter().chain(rotated.iter()));
    debug_assert_eq!(
        families.complete + families.deferred.quantum + families.incomplete_total(),
        families.evaluated,
        "the reasons partition the incomplete count"
    );
    let cost = Cost {
        predicate_cpu_us: super::codex_compressed_input::thread_cpu_micros()
            .saturating_sub(started),
        families_evaluated: families.evaluated,
        root_index_rebuilt,
        root_index_roots: runtime.roots.len() as u64,
        root_index_overflowed: runtime.roots.overflowed,
        queued_roots_overflowed: view.queued_roots_overflowed,
    };
    Some(PageCounts {
        families,
        touched_families: touched.families.len() as u64,
        touched_families_over_cap: touched.over_cap,
        rotation_families: rotated.len() as u64,
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
    // Each critical section is one whole page update; a poisoned value is
    // still bounded and only feeds counts.
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

/// Evaluate and emit one Claude page's shadow counts. Counts only.
pub(super) fn observe_page(index: &ScanIndex, touched: &Touched, scope: &str, now: u64) {
    if let Some(counts) = with_runtime(|runtime| evaluate_page(runtime, index, touched, scope, now))
    {
        crate::local_resource_diagnostics::claude_family_census_shadow(&counts);
    }
}
