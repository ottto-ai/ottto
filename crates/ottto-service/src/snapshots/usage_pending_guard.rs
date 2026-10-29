//! Runtime-only negative scheduling evidence. Never usage or census authority.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Unknown {
    MissingWitness,
    IncompleteMember,
    CompactedOrigin,
    Decode,
    Resource,
    Dependency,
}
impl crate::heap_layout_bound::HeapLayoutBound for Unknown {
    fn heap_bound(&self, counter: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        counter.add(0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Match,
    Mismatch,
    Unknown(Unknown),
}

#[cfg(test)]
thread_local! {
    static REPLAY_OLD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(super) fn replay_old<T>(run: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            REPLAY_OLD.with(|old| old.set(self.0));
        }
    }
    let _reset = Reset(REPLAY_OLD.with(|old| old.replace(true)));
    run()
}

// Compute summaries from the retained pending facts, not from the expected
// witness. All canonical digest domains and selectors stay unchanged.
pub(super) fn check(
    pending: &ClaudeUsageFamilyPending,
    witness: Option<&ClaudeUsageFamilyWitness>,
    contains_member: impl Fn(&str) -> bool,
) -> Verdict {
    #[cfg(test)]
    if REPLAY_OLD.with(std::cell::Cell::get) {
        let members = pending
            .membership()
            .keys()
            .filter(|key| contains_member(key))
            .cloned()
            .collect();
        return if witness
            .is_some_and(|w| claude_stale_pending_matches_witness(pending, w, &members))
        {
            Verdict::Match
        } else {
            Verdict::Mismatch
        };
    }
    if pending.invalid {
        return Verdict::Mismatch;
    }
    let Some(witness) = witness else {
        return Verdict::Unknown(Unknown::MissingWitness);
    };
    if pending.member_occurrences.is_empty() {
        return Verdict::Unknown(Unknown::CompactedOrigin);
    }
    if !pending
        .membership()
        .keys()
        .all(|member| contains_member(member))
    {
        return Verdict::Unknown(Unknown::IncompleteMember);
    }
    if !pending
        .membership()
        .keys()
        .eq(pending.member_occurrences.keys())
        || !witness
            .member_request_id_fingerprints
            .keys()
            .eq(pending.membership().keys())
        || !witness
            .member_occurrence_fingerprints
            .keys()
            .eq(pending.membership().keys())
    {
        return Verdict::Unknown(Unknown::IncompleteMember);
    }
    for (member, occurrences) in &pending.member_occurrences {
        let Some(hashes) = pending.membership().get(member) else {
            return Verdict::Unknown(Unknown::IncompleteMember);
        };
        let actual_requests = claude_request_hashes_fingerprint(hashes.iter());
        let actual_occurrences = claude_occurrence_map_fingerprint(occurrences);
        if !contains_member(member)
            || !hashes.iter().eq(occurrences.keys())
            || witness.member_request_id_fingerprints.get(member) != Some(&actual_requests)
            || witness.member_occurrence_fingerprints.get(member) != Some(&actual_occurrences)
        {
            return Verdict::Mismatch;
        }
    }
    Verdict::Match
}

pub(super) fn verdict(index: &ScanIndex, root: &str) -> Verdict {
    if index.decode_holds_family(root) || index.decode_has_opaque_file_incidence() {
        return Verdict::Unknown(Unknown::Decode);
    }
    let Some(pending) = index.claude_usage_family_pending.get(root) else {
        return Verdict::Unknown(Unknown::IncompleteMember);
    };
    let witness = index.claude_usage_family_witnesses.get(root);
    check(pending, witness, |member| {
        let expected = ClaudeIndexPathMemberRef::of_family_member(root, member);
        expected.is_some_and(|expected| {
            index
                .files
                .keys()
                .any(|key| claude_index_path_member_ref(Path::new(key)) == Some(expected))
        })
    })
}

#[derive(Clone, Debug, Default)]
pub(super) struct Holds {
    roots: Vec<(String, Unknown)>,
    // Resolution does not revoke age rescue before actual Tail catch-up.
    catchup: Vec<String>,
    global: bool,
    // Built projections answer every root; unbuilt or dirty ones fall back.
    built: bool,
    dirty: bool,
    // Survives projection rebuilds and selected-subset composition.
    runtime: Runtime,
}
crate::heap_layout_bound::fields!(Holds; roots, catchup, global, built, dirty, runtime);

/// Fixed bounds for member growth read while a family is held (Lead B P1-a).
pub(super) const HELD_GROWTH_MAX_MEMBERS: usize = 256;
pub(super) const HELD_GROWTH_MAX_OCCURRENCES: usize = 4096;
/// GUARDRAILS rule 5: at most one withheld Full per key per 6 h, below the
/// one-day discovery window (C3/D2).
pub(super) const WITHHELD_FULL_PACE_SECONDS: u64 = 6 * 60 * 60;
pub(super) const WITHHELD_FULL_PACE_BOUND: usize = 64;
const _: () = assert!(WITHHELD_FULL_PACE_SECONDS < 24 * 60 * 60);

#[derive(Clone, Debug)]
struct HeldSlot {
    root: String,
    window: String,
    occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>,
}
crate::heap_layout_bound::fields!(HeldSlot; root, window, occurrences);

/// Runtime-only custody of the B3 hold. Nothing here is persisted.
#[derive(Clone, Debug, Default)]
pub(super) struct Runtime {
    // A held family's member growth, keyed by member. Never re-windows the
    // family; merged into its pending only after the hold resolves.
    slots: BTreeMap<String, HeldSlot>,
    slot_occurrences: usize,
    // TODO(E7 pace-map): fold into A0-h's shared `retail_full_at` pacing map
    // when this branch integrates with it; that map is not in this base.
    paced: BTreeMap<String, u64>,
    // Keys admitted for a withheld Full during the current candidate visit.
    withheld: BTreeSet<String>,
    // Paced keys whose withheld Full completed: it satisfied every audit due
    // by its pace stamp. The committed entry keeps its audit obligation.
    audited: BTreeSet<String>,
}
crate::heap_layout_bound::fields!(Runtime; slots, slot_occurrences, paced, withheld, audited);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Growth {
    Recorded,
    OverCap,
}

impl Unknown {
    fn label(self) -> &'static str {
        match self {
            Self::MissingWitness => "missing_witness",
            Self::IncompleteMember => "incomplete_member",
            Self::CompactedOrigin => "compacted_origin",
            Self::Decode => "decode",
            Self::Resource => "resource",
            Self::Dependency => "dependency",
        }
    }
}

fn has_root(roots: &[(String, Unknown)], root: &str) -> bool {
    roots
        .binary_search_by(|(key, _)| key.as_str().cmp(root))
        .is_ok()
}
fn insert_root(roots: &mut Vec<(String, Unknown)>, root: &str, reason: Unknown) {
    if let Err(at) = roots.binary_search_by(|(key, _)| key.as_str().cmp(root)) {
        roots.insert(at, (root.to_owned(), reason));
    }
}

impl Holds {
    pub(super) fn reason(&self, root: &str) -> Option<Unknown> {
        self.roots
            .binary_search_by(|(key, _)| key.as_str().cmp(root))
            .ok()
            .map(|at| self.roots[at].1)
            .or(self.global.then_some(Unknown::Resource))
    }
    pub(super) fn invalidate(&mut self) {
        self.dirty = true;
    }
    pub(super) fn global(&self) -> bool {
        self.global
    }
    pub(super) fn holds(&self, root: &str) -> bool {
        self.reason(root).is_some()
    }
    pub(super) fn retains_path(&self, path: &Path) -> bool {
        claude_index_path_member_ref(path).is_some_and(|member| {
            self.global
                || has_root(&self.roots, member.root)
                || self
                    .catchup
                    .binary_search_by(|key| key.as_str().cmp(member.root))
                    .is_ok()
        })
    }
    pub(super) fn holds_path(&self, path: &Path) -> bool {
        claude_index_path_member_ref(path).is_some_and(|member| self.holds(member.root))
    }
    fn fresh(&self) -> bool {
        self.built && !self.dirty
    }
    /// An empty projection that keeps this one's runtime custody.
    pub(super) fn carry_runtime(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            ..Self::default()
        }
    }
    /// Record a held family's member growth in its own bounded slot.
    pub(super) fn record_member_growth(
        &mut self,
        root: &str,
        member: &str,
        window: &str,
        occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>,
    ) -> Growth {
        let runtime = &mut self.runtime;
        // A newer window supersedes slots recorded for an older one.
        if runtime.slots.values().any(|slot| slot.window != window) {
            runtime.slots.retain(|_, slot| slot.window == window);
            runtime.slot_occurrences = runtime
                .slots
                .values()
                .map(|slot| slot.occurrences.len())
                .sum();
        }
        let replaced = runtime
            .slots
            .get(member)
            .map_or(0, |slot| slot.occurrences.len());
        let next = (runtime.slot_occurrences - replaced).saturating_add(occurrences.len());
        if next > HELD_GROWTH_MAX_OCCURRENCES
            || (!runtime.slots.contains_key(member)
                && runtime.slots.len() >= HELD_GROWTH_MAX_MEMBERS)
        {
            crate::local_resource_diagnostics::traversal_point(
                "claude_usage_held_member_growth",
                SnapshotSource::ClaudeCode.api_slug(),
                &json!({"held_member_growth_over_cap":1}),
            );
            return Growth::OverCap;
        }
        let count = occurrences.len();
        runtime.slots.insert(
            member.to_owned(),
            HeldSlot {
                root: root.to_owned(),
                window: window.to_owned(),
                occurrences,
            },
        );
        runtime.slot_occurrences = next;
        crate::local_resource_diagnostics::traversal_point(
            "claude_usage_held_member_growth",
            SnapshotSource::ClaudeCode.api_slug(),
            &json!({"held_member_growth_slots":1,"held_member_growth_occurrences":count}),
        );
        Growth::Recorded
    }
    /// Request keys read while held; they still veto other families while
    /// their family is held.
    pub(super) fn growth_hashes(&self) -> impl Iterator<Item = &String> {
        self.runtime
            .slots
            .values()
            .filter(|slot| self.holds(&slot.root))
            .flat_map(|slot| slot.occurrences.keys())
    }
    /// The family's `window` evidence held in its slots, shaped as pending.
    pub(super) fn growth_pending(&self, root: &str, window: &str) -> ClaudeUsageFamilyPending {
        let mut pending = ClaudeUsageFamilyPending {
            derived_request_members: BTreeSet::new(),
            census_window_end: window.to_owned(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
            idless_revision: None,
        };
        for (member, slot) in &self.runtime.slots {
            if slot.root == root && slot.window == window {
                pending
                    .member_request_id_hashes
                    .insert(member.clone(), BTreeSet::new());
                pending.derived_request_members.insert(member.clone());
                pending
                    .member_occurrences
                    .insert(member.clone(), slot.occurrences.clone());
            }
        }
        pending
    }
    /// Remove a family's slots; those of `window` re-window it after resolution.
    pub(super) fn take_member_growth(
        &mut self,
        root: &str,
        window: &str,
    ) -> Vec<(
        String,
        BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>,
    )> {
        let runtime = &mut self.runtime;
        let members = runtime
            .slots
            .iter()
            .filter(|(_, slot)| slot.root == root)
            .map(|(member, _)| member.clone())
            .collect::<Vec<_>>();
        let mut taken = Vec::new();
        for member in members {
            if let Some(slot) = runtime.slots.remove(&member) {
                runtime.slot_occurrences -= slot.occurrences.len();
                if slot.window == window {
                    taken.push((member, slot.occurrences));
                }
            }
        }
        taken
    }
    // `current` is the census window being accumulated now. Its pending is
    // ordinary current evidence, not a stale token record, and is never held.
    fn build(index: &ScanIndex, current: Option<&str>) -> Option<Self> {
        use crate::heap_layout_bound::Counter;
        let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
        let owners = index
            .claude_usage_family_witnesses
            .values()
            .try_fold(0usize, |n, w| n.checked_add(w.legacy_owner_roots.len()))?;
        let roots = index
            .claude_usage_family_pending
            .len()
            .checked_add(index.claude_usage_family_witnesses.len())?
            .checked_add(index.usage_guard_holds.catchup.len())?
            .checked_add(owners)?;
        // Contiguous metadata only; no unqualified native B-tree assumptions.
        cost.add(roots.checked_mul(
            2 * std::mem::size_of::<(String, Unknown)>() + 2 * std::mem::size_of::<String>(),
        )?)?;
        cost.add(
            index
                .claude_usage_family_pending
                .keys()
                .chain(index.claude_usage_family_witnesses.keys())
                .chain(index.usage_guard_holds.catchup.iter())
                .chain(
                    index
                        .claude_usage_family_witnesses
                        .values()
                        .flat_map(|w| w.legacy_owner_roots.iter()),
                )
                .try_fold(0usize, |n, root| n.checked_add(root.len().checked_mul(4)?))?,
        )?;
        let file_count = index
            .files
            .keys()
            .filter(|key| claude_index_path_member_ref(Path::new(key)).is_some())
            .count();
        cost.add(file_count.checked_mul(std::mem::size_of::<ClaudeIndexPathMemberRef<'_>>())?)?;
        let mut inventory = Vec::new();
        inventory.try_reserve_exact(file_count).ok()?;
        inventory.extend(
            index
                .files
                .keys()
                .filter_map(|key| claude_index_path_member_ref(Path::new(key))),
        );
        inventory.sort_unstable();
        let mut held = Vec::new();
        held.try_reserve_exact(roots).ok()?;
        let is_current = |root: &str| {
            current.is_some_and(|current| {
                index
                    .claude_usage_family_pending
                    .get(root)
                    .is_some_and(|pending| pending.census_window_end == current)
            })
        };
        for root in index.claude_usage_family_pending.keys() {
            if is_current(root) {
                continue;
            }
            let verdict =
                if index.decode_holds_family(root) || index.decode_has_opaque_file_incidence() {
                    Verdict::Unknown(Unknown::Decode)
                } else {
                    check(
                        &index.claude_usage_family_pending[root],
                        index.claude_usage_family_witnesses.get(root),
                        |member| {
                            ClaudeIndexPathMemberRef::of_family_member(root, member)
                                .is_some_and(|member| inventory.binary_search(&member).is_ok())
                        },
                    )
                };
            if let Verdict::Unknown(reason) = verdict {
                insert_root(&mut held, root, reason);
            }
        }
        let mut catchup = Vec::new();
        catchup.try_reserve_exact(roots).ok()?;
        catchup.extend(index.claude_usage_family_pending.keys().cloned());
        catchup.sort_unstable();
        catchup.dedup();
        if held.is_empty() {
            return Some(Self {
                roots: held,
                catchup,
                global: false,
                built: true,
                dirty: false,
                runtime: Runtime::default(),
            });
        }
        // Sorted borrowed incidence, one identity per actual pending request.
        // Do not copy 64-hex strings or introduce a second ownership catalog.
        let count = index
            .claude_usage_family_pending
            .values()
            .try_fold(0usize, |n, pending| {
                n.checked_add(
                    pending
                        .membership()
                        .values()
                        .try_fold(0usize, |n, h| n.checked_add(h.len()))?,
                )
            })?;
        cost.add(count.checked_mul(std::mem::size_of::<(&String, &String)>())?)?;
        let mut incidence = Vec::new();
        incidence.try_reserve_exact(count).ok()?;
        for (root, pending) in &index.claude_usage_family_pending {
            for hash in pending.membership().values().flat_map(|h| h.iter()) {
                incidence.push((hash, root));
            }
            // An occurrence-only malformed record cannot silently erase overlap.
            if pending
                .member_occurrences
                .iter()
                .any(|(member, occurrences)| {
                    pending
                        .membership()
                        .get(member)
                        .map_or(!occurrences.is_empty(), |h| {
                            occurrences.keys().any(|key| !h.contains(key))
                        })
                })
            {
                return None;
            }
        }
        incidence.sort_unstable();
        // Linear worklist over a CSR graph: root nodes, then one node per
        // shared request hash. Hash groups, legacy owner links and excluded
        // prefixes are undirected edges, so every node is visited once.
        let mut names = Vec::new();
        names
            .try_reserve_exact(roots.checked_add(incidence.len())?)
            .ok()?;
        names.extend(index.claude_usage_family_pending.keys().map(String::as_str));
        names.extend(
            index
                .claude_usage_family_witnesses
                .keys()
                .map(String::as_str),
        );
        names.extend(
            index
                .claude_usage_family_witnesses
                .values()
                .flat_map(|w| w.legacy_owner_roots.iter().map(String::as_str)),
        );
        names.extend(incidence.iter().map(|(_, root)| root.as_str()));
        names.sort_unstable();
        names.dedup();
        let node = |root: &str| names.binary_search(&root).ok();
        let mut groups = 0usize;
        let mut group_of = Vec::new();
        group_of.try_reserve_exact(incidence.len()).ok()?;
        for (at, (hash, _)) in incidence.iter().enumerate() {
            if at > 0 && incidence[at - 1].0 != *hash {
                groups += 1;
            }
            group_of.push(groups);
        }
        let excluded = index
            .claude_usage_family_witnesses
            .values()
            .try_fold(0usize, |n, w| {
                n.checked_add(
                    w.legacy_excluded_request_id_hashes
                        .values()
                        .try_fold(0usize, |n, h| n.checked_add(h.len()))?,
                )
            })?;
        let edge_count = incidence
            .len()
            .checked_add(owners)?
            .checked_add(excluded)?
            .checked_mul(2)?;
        cost.add(edge_count.checked_mul(std::mem::size_of::<(usize, usize)>())?)?;
        cost.add(
            names
                .len()
                .checked_add(groups + 1)?
                .checked_mul(2 * std::mem::size_of::<usize>())?,
        )?;
        let mut edges = Vec::new();
        edges.try_reserve_exact(edge_count).ok()?;
        let group_node = |group: usize| names.len() + group;
        for ((_, root), group) in incidence.iter().zip(&group_of) {
            let root = node(root)?;
            edges.push((root, group_node(*group)));
            edges.push((group_node(*group), root));
        }
        // A held root whose excluded prefix has no incidence and no owner list
        // has unknown dependency scope: it is a global hold, never a carry.
        let mut unscopable = Vec::new();
        for (root, witness) in &index.claude_usage_family_witnesses {
            let at_root = node(root)?;
            for owner in &witness.legacy_owner_roots {
                let owner = node(owner)?;
                edges.push((at_root, owner));
                edges.push((owner, at_root));
            }
            for hash in witness
                .legacy_excluded_request_id_hashes
                .values()
                .flat_map(|h| h.iter())
            {
                let at = incidence.partition_point(|(key, _)| *key < hash);
                if at < incidence.len() && incidence[at].0 == hash {
                    edges.push((at_root, group_node(group_of[at])));
                    edges.push((group_node(group_of[at]), at_root));
                } else if witness.legacy_owner_roots.is_empty() {
                    unscopable.push(at_root);
                }
            }
        }
        edges.sort_unstable();
        let nodes = names.len() + groups + 1;
        let mut seen = Vec::new();
        seen.try_reserve_exact(nodes).ok()?;
        seen.resize(nodes, false);
        let mut work = Vec::new();
        work.try_reserve_exact(nodes).ok()?;
        for (root, _) in &held {
            if let Some(at) = node(root) {
                seen[at] = true;
                work.push(at);
            }
        }
        while let Some(at) = work.pop() {
            let from = edges.partition_point(|(u, _)| *u < at);
            for &(_, next) in edges[from..].iter().take_while(|(u, _)| *u == at) {
                if !seen[next] {
                    seen[next] = true;
                    work.push(next);
                }
            }
        }
        if unscopable.iter().any(|at| seen[*at]) {
            return None;
        }
        for (at, name) in names.iter().enumerate() {
            if seen[at] {
                insert_root(&mut held, name, Unknown::Dependency);
            }
        }
        // Closure may pass through a current family; that family itself
        // keeps its ordinary current-window reads.
        held.retain(|(root, _)| !is_current(root));
        Some(Self {
            roots: held,
            catchup,
            global: false,
            built: true,
            dirty: false,
            runtime: Runtime::default(),
        })
    }
}

/// A fresh projection; an unscopable or unaffordable one holds globally.
pub(super) fn projection(index: &ScanIndex, current: Option<&str>) -> Holds {
    #[cfg(test)]
    if REPLAY_OLD.with(std::cell::Cell::get) {
        return Holds::default();
    }
    Holds::build(index, current).unwrap_or(Holds {
        global: true,
        built: true,
        ..Holds::default()
    })
}

impl ScanIndex {
    fn current_census_window(&self) -> Option<String> {
        self.traversal
            .as_ref()
            .map(|traversal| traversal.census_window_end.clone())
    }
    pub(super) fn refresh_usage_guard_holds(&mut self) {
        let current = self.current_census_window();
        self.refresh_usage_guard_holds_at(current.as_deref());
    }
    /// A traversal start passes its new window before the checkpoint exists.
    pub(super) fn refresh_usage_guard_holds_at(&mut self, current: Option<&str>) {
        let holds = projection(self, current);
        self.install_usage_guard_holds(holds);
    }
    /// Install a rebuilt projection without losing runtime custody.
    pub(super) fn install_usage_guard_holds(&mut self, mut holds: Holds) {
        let mut runtime = std::mem::take(&mut self.usage_guard_holds.runtime);
        // A family whose pending proof is gone (retired or vanished) has no
        // window left to rejoin; its held growth goes with it.
        let pending = &self.claude_usage_family_pending;
        if runtime
            .slots
            .values()
            .any(|slot| !pending.contains_key(&slot.root))
        {
            runtime
                .slots
                .retain(|_, slot| pending.contains_key(&slot.root));
            runtime.slot_occurrences = runtime
                .slots
                .values()
                .map(|slot| slot.occurrences.len())
                .sum();
        }
        holds.runtime = runtime;
        self.usage_guard_holds = holds;
    }
    pub(super) fn refresh_usage_guard_after_native_completion(&mut self) {
        if self.usage_guard_holds.dirty {
            self.refresh_usage_guard_holds();
        }
    }
    pub(super) fn refresh_usage_guard_holds_if_stale(&mut self) {
        if !self.usage_guard_holds.fresh() {
            self.refresh_usage_guard_holds();
        }
    }
    pub(super) fn usage_guard_reason(&self, root: &str) -> Option<Unknown> {
        #[cfg(test)]
        if REPLAY_OLD.with(std::cell::Cell::get) {
            return None;
        }
        let holds = &self.usage_guard_holds;
        if holds.fresh() {
            // The sorted projection already classified every pending root.
            return holds.reason(root);
        }
        // Unbuilt or dirty: conservative dynamic verdict for this root.
        holds.reason(root).or_else(|| match verdict(self, root) {
            Verdict::Unknown(reason) => Some(reason),
            _ => None,
        })
    }
    pub(super) fn usage_guard_observe_growth(&self, candidate: &CandidateFile) {
        if self.usage_guard_holds.holds_path(&candidate.path) {
            let growth = self
                .files
                .get(&local_index_key(&candidate.path))
                .map_or(0, |entry| {
                    candidate.size_bytes.saturating_sub(entry.size_bytes)
                });
            crate::local_resource_diagnostics::traversal_point(
                "claude_usage_unknown_growth",
                SnapshotSource::ClaudeCode.api_slug(),
                &json!({"unknown_growth_observations":1,"unknown_growth_bytes_observed":growth}),
            );
        }
    }
    pub(super) fn usage_guard_note_tail(&mut self, path: &Path, native_bytes: u64) {
        let Some(member) = claude_index_path_member_ref(path) else {
            return;
        };
        let held = self.usage_guard_holds.holds(member.root);
        if held {
            crate::local_resource_diagnostics::traversal_point(
                "claude_usage_held_member_growth",
                SnapshotSource::ClaudeCode.api_slug(),
                &json!({"held_member_growth_members":1,"held_member_growth_bytes":native_bytes}),
            );
        }
        // Retain the family's age fence: one completed member cannot prove
        // that every sibling suffix caught up. Pending custody is the
        // restart-reconstructible fence until its existing owner retires it.
        let resolving = !held
            && self
                .usage_guard_holds
                .catchup
                .binary_search_by(|root| root.as_str().cmp(member.root))
                .is_ok();
        if held || resolving {
            crate::local_resource_diagnostics::traversal_point(
                "claude_usage_unknown_tail",
                SnapshotSource::ClaudeCode.api_slug(),
                &json!({"unknown_held_tail":u64::from(held),"retained_proof_catchup_tail":u64::from(resolving)}),
            );
        }
    }
}

/// Scoped residue exit (Lead B 4d): the refused held read is counted per
/// family and leaves the census otherwise unaffected. Terminal cleanup keeps
/// the held pending, so the hold stays reconstructible.
pub(super) fn full_blocked(path: &Path) {
    let families = u64::from(claude_index_path_member_ref(path).is_some());
    crate::local_resource_diagnostics::traversal_point(
        "claude_usage_unknown_acquisition",
        SnapshotSource::ClaudeCode.api_slug(),
        &json!({"unknown_full_blocked":1,"held_read_refused_families":families}),
    );
}

/// The exact occurrence map the pending accumulator would record for `item`,
/// or None where it would invalidate the family instead.
pub(super) fn item_occurrences(
    item: &SnapshotItem,
) -> Option<BTreeMap<String, ClaudeTranscriptUsageOccurrenceWitness>> {
    let hashes = claude_snapshot_request_id_hashes(item)
        .filter(|_| item.claude_usage_occurrences.len() == item.claude_usage_request_ids.len())?;
    let occurrences = item
        .claude_usage_occurrences
        .iter()
        .map(|(request_id, occurrence)| {
            (
                format!("{:x}", Sha256::digest(request_id.as_bytes())),
                ClaudeTranscriptUsageOccurrenceWitness::from(occurrence),
            )
        })
        .collect::<BTreeMap<_, _>>();
    occurrences.keys().eq(hashes.iter()).then_some(occurrences)
}

impl ScanIndex {
    /// GUARDRAILS rule 5 (Lead B P1-b): a held, indexed file with real growth
    /// and no usable Tail takes ONE withheld Full that publishes nothing,
    /// paced to one per key per 6 h. A full pace map evicts its oldest stamp
    /// and lets the read happen (rule 7). Counted under the hold reason.
    pub(super) fn usage_guard_admit_withheld_full(&mut self, candidate: &CandidateFile) -> bool {
        let key = local_index_key(&candidate.path);
        let Some(reason) = claude_index_path_member_ref(&candidate.path)
            .and_then(|member| self.usage_guard_holds.reason(member.root))
        else {
            return false;
        };
        // Real growth only: the opened length past the committed index end.
        if !self
            .files
            .get(&key)
            .is_some_and(|entry| candidate.size_bytes > entry.size_bytes)
        {
            return false;
        }
        let now = sampled_scan::now_seconds();
        let runtime = &mut self.usage_guard_holds.runtime;
        if runtime
            .paced
            .get(&key)
            .is_some_and(|at| now.saturating_sub(*at) < WITHHELD_FULL_PACE_SECONDS)
        {
            crate::local_resource_diagnostics::traversal_point(
                "claude_usage_withheld_full",
                SnapshotSource::ClaudeCode.api_slug(),
                &json!({"withheld_full_paced":1}),
            );
            return false;
        }
        let mut pace_evicted = 0_u64;
        if !runtime.paced.contains_key(&key) && runtime.paced.len() >= WITHHELD_FULL_PACE_BOUND {
            let oldest = runtime
                .paced
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                runtime.paced.remove(&oldest);
                runtime.audited.remove(&oldest);
                pace_evicted = 1;
            }
        }
        runtime.paced.insert(key.clone(), now);
        runtime.audited.remove(&key);
        runtime.withheld.insert(key);
        let mut counts = serde_json::Map::new();
        counts.insert("withheld_full".into(), json!(1));
        counts.insert(format!("withheld_full_{}", reason.label()), json!(1));
        counts.insert("pace_evicted".into(), json!(pace_evicted));
        crate::local_resource_diagnostics::traversal_point(
            "claude_usage_withheld_full",
            SnapshotSource::ClaudeCode.api_slug(),
            &Value::Object(counts),
        );
        true
    }
    /// Replace the pace map with `keys` stamped at the epoch (oldest).
    #[cfg(test)]
    pub(super) fn usage_guard_pace_for_test(&mut self, keys: impl IntoIterator<Item = String>) {
        self.usage_guard_holds.runtime.paced = keys.into_iter().map(|key| (key, 0)).collect();
    }
    /// A completed withheld Full read the whole file: audits due by its pace
    /// stamp are satisfied for this process, so the next visit can Tail.
    pub(super) fn usage_guard_mark_audited(&mut self, key: &str) {
        let runtime = &mut self.usage_guard_holds.runtime;
        if runtime.paced.contains_key(key) {
            runtime.audited.insert(key.to_owned());
        }
    }
    pub(super) fn usage_guard_audit_satisfied(&self, key: &str, due_unix_seconds: u64) -> bool {
        let runtime = &self.usage_guard_holds.runtime;
        runtime.audited.contains(key)
            && runtime
                .paced
                .get(key)
                .is_some_and(|at| due_unix_seconds <= *at)
    }
    pub(super) fn usage_guard_is_withheld(&self, key: &str) -> bool {
        self.usage_guard_holds.runtime.withheld.contains(key)
    }
    pub(super) fn usage_guard_take_withheld(&mut self, key: &str) -> bool {
        self.usage_guard_holds.runtime.withheld.remove(key)
    }
    /// The withheld Full's parse rebuilds the members' evidence in their held
    /// growth slots; nothing reaches the page's published snapshots.
    pub(super) fn usage_guard_record_withheld(&mut self, items: &[SnapshotItem], window: &str) {
        let mut members = 0_u64;
        for item in items {
            let root = claude_snapshot_family_root(item);
            let Some(occurrences) = item_occurrences(item) else {
                crate::local_resource_diagnostics::traversal_point(
                    "claude_usage_withheld_full",
                    SnapshotSource::ClaudeCode.api_slug(),
                    &json!({"withheld_full_unrecordable":1}),
                );
                continue;
            };
            if self.usage_guard_holds.record_member_growth(
                &root,
                &item.source_session_id,
                window,
                occurrences,
            ) == Growth::Recorded
            {
                members += 1;
            }
        }
        crate::local_resource_diagnostics::traversal_point(
            "claude_usage_held_member_growth",
            SnapshotSource::ClaudeCode.api_slug(),
            &json!({"held_member_growth_members":members}),
        );
    }
}

/// Native bytes a withheld Full read for its held member.
pub(super) fn withheld_read(native_bytes: u64) {
    crate::local_resource_diagnostics::traversal_point(
        "claude_usage_held_member_growth",
        SnapshotSource::ClaudeCode.api_slug(),
        &json!({"held_member_growth_bytes":native_bytes,"withheld_full_bytes":native_bytes}),
    );
}

pub(super) fn withheld_incomplete() {
    crate::local_resource_diagnostics::traversal_point(
        "claude_usage_withheld_full",
        SnapshotSource::ClaudeCode.api_slug(),
        &json!({"withheld_full_incomplete":1}),
    );
}

pub(super) fn withheld_checkpoint(retained: bool) {
    crate::local_resource_diagnostics::traversal_point(
        "claude_usage_withheld_full",
        SnapshotSource::ClaudeCode.api_slug(),
        &json!({"withheld_full_checkpoint_retained":u64::from(retained),"withheld_full_checkpoint_refused":u64::from(!retained)}),
    );
}
