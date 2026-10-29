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
}
crate::heap_layout_bound::fields!(Holds; roots, catchup, global, built, dirty);

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
        loop {
            let before = held.len();
            let mut at = 0;
            while at < incidence.len() {
                let end =
                    at + incidence[at..].partition_point(|(hash, _)| *hash == incidence[at].0);
                if incidence[at..end]
                    .iter()
                    .any(|(_, root)| has_root(&held, root))
                {
                    for (_, root) in &incidence[at..end] {
                        insert_root(&mut held, root, Unknown::Dependency);
                    }
                }
                at = end;
            }
            for (root, witness) in &index.claude_usage_family_witnesses {
                if has_root(&held, root)
                    || witness
                        .legacy_owner_roots
                        .iter()
                        .any(|owner| has_root(&held, owner))
                {
                    insert_root(&mut held, root, Unknown::Dependency);
                    for owner in &witness.legacy_owner_roots {
                        insert_root(&mut held, owner, Unknown::Dependency);
                    }
                }
                for hash in witness
                    .legacy_excluded_request_id_hashes
                    .values()
                    .flat_map(|h| h.iter())
                {
                    let at = incidence.partition_point(|(key, _)| *key < hash);
                    let end = at + incidence[at..].partition_point(|(key, _)| *key == hash);
                    if has_root(&held, root)
                        || incidence[at..end]
                            .iter()
                            .any(|(_, owner)| has_root(&held, owner))
                    {
                        insert_root(&mut held, root, Unknown::Dependency);
                        for (_, owner) in &incidence[at..end] {
                            insert_root(&mut held, owner, Unknown::Dependency);
                        }
                        if at == end && witness.legacy_owner_roots.is_empty() {
                            return None; // unknown dependency scope, never a carry
                        }
                    }
                }
            }
            if held.len() == before {
                break;
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
        })
    }
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
        #[cfg(test)]
        if REPLAY_OLD.with(std::cell::Cell::get) {
            self.usage_guard_holds = Holds::default();
            return;
        }
        match Holds::build(self, current) {
            Some(holds) => self.usage_guard_holds = holds,
            None => {
                self.usage_guard_holds.global = true;
                self.usage_guard_holds.built = true;
                self.usage_guard_holds.dirty = false;
            }
        }
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
    pub(super) fn usage_guard_note_tail(&mut self, path: &Path) {
        let Some(member) = claude_index_path_member_ref(path) else {
            return;
        };
        let held = self.usage_guard_holds.holds(member.root);
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

/// The refused read keeps the census incomplete, so terminal cleanup cannot
/// retire the held pending proof and a later walk cannot take the Full read.
pub(super) fn full_blocked(census: &mut ScanCensus) {
    census.record_unreadable(UnreadableCause::Reduction, 1);
    crate::local_resource_diagnostics::traversal_point(
        "claude_usage_unknown_acquisition",
        SnapshotSource::ClaudeCode.api_slug(),
        &json!({"unknown_full_blocked":1}),
    );
}
