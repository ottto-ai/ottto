//! The complete Claude terminal's cross-family facts, built by streaming the
//! usage-pending families instead of loading them all. Sweep 1 visits every
//! family once, in root order and in slices, and keeps per family only what
//! the terminal decides from: its request keys with their (root, member)
//! owner and hash / occurrence / current-window flags (the join), its root
//! sequence's first request, the other roots that own its root member's
//! requests, and its proof. One targeted visit then reads only the families
//! the cross-family joins name: the owners of each request two current
//! families share (to name it again), and the families that may share a
//! legacy fork prefix with a candidate (proved with their exclusions). The
//! join is consulted only once every family is in it.
//!
//! Every slice must read under the first slice's token and the slices must
//! cover every family once; an Unknown row, a changed token or a short sweep
//! refuses the whole terminal before the fold changes anything. The fold is
//! the only writer, and one save commits what it decides.
use super::state_v2::{self, SliceBudget, SliceEnd, UsageToken};
use super::*;

/// A request id hash as its 256-bit key (`lenient_decode::repair_key`), so
/// the join keeps no hash strings.
type RequestKey = [u8; 32];

const HASH: u8 = 1;
const OCCURRENCE: u8 = 2;
const CURRENT: u8 = 4;

/// One slice of the terminal visit: a short read transaction over at most
/// this many families or decoded bytes.
const TERMINAL_SLICE: SliceBudget = SliceBudget {
    families: 256,
    bytes: 16 << 20,
};

#[cfg(test)]
thread_local! {
    static SLICE_BUDGET: std::cell::Cell<Option<SliceBudget>> =
        const { std::cell::Cell::new(None) };
}

fn slice_budget() -> SliceBudget {
    #[cfg(test)]
    if let Some(budget) = SLICE_BUDGET.with(std::cell::Cell::get) {
        return budget;
    }
    TERMINAL_SLICE
}

/// Run `f` with every terminal visit sliced under `budget`.
#[cfg(test)]
pub(super) fn with_slice_budget<T>(budget: SliceBudget, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<SliceBudget>);
    impl Drop for Reset {
        fn drop(&mut self) {
            SLICE_BUDGET.with(|cell| cell.set(self.0));
        }
    }
    let _reset = Reset(SLICE_BUDGET.with(|cell| cell.replace(Some(budget))));
    f()
}

/// The terminal could not read every family under one token. Nothing was
/// decided; the page is refused whole and the census stays incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refused;

/// What the sweep needs from the fold, all fixed before it starts.
pub(super) struct TerminalInputs<'a> {
    pub(super) census_window_end: &'a str,
    pub(super) complete_families: &'a BTreeMap<String, BTreeSet<String>>,
    /// Roots of this page's items: only their proofs keep provider rows.
    pub(super) item_roots: &'a BTreeSet<String>,
    pub(super) legacy_request_owners: Option<&'a ClaudeLegacyRequestOwners>,
    /// Healthy reports only: the family proof's inputs.
    pub(super) proof: Option<ProofInputs<'a>>,
}

pub(super) struct ProofInputs<'a> {
    pub(super) api_report: &'a crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    pub(super) trace_report: &'a crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    /// Where a root outside the reports finds its rows (a strict reread).
    pub(super) evidence_rows: ClaudeEvidenceRows<'a>,
    /// Uncertified or owed roots: proven by nothing this terminal.
    pub(super) skipped: BTreeSet<String>,
}

/// The terminal's facts over every family.
#[derive(Default)]
pub(super) struct TerminalJoin {
    /// (key, owner, flags), sorted, one entry per key and owner.
    entries: Vec<(RequestKey, u32, u8)>,
    /// Owner ids: (root, member), each family's members contiguous and sorted.
    owners: Vec<(String, String)>,
    /// Root -> its first owner id and member count.
    families: BTreeMap<String, (u32, u32)>,
    /// Root -> the other roots the legacy request owners name for its root
    /// member's occurrences (none without healthy owners).
    foreign_owner_roots: BTreeMap<String, BTreeSet<String>>,
    /// Families with a valid root sequence: its first request.
    first_keys: BTreeMap<String, RequestKey>,
    /// Families whose first root request another root owns: their proof
    /// waits for the legacy-prefix join.
    candidates: BTreeSet<String>,
    pub(super) proven: BTreeMap<String, ProvenClaudeUsageFamily>,
    /// Why families with rows were not proven (`IgnoredVeto` bits).
    pub(super) ignored_vetoes: u16,
    /// Requests two current-window owners' occurrences share, by hash.
    pub(super) native_duplicate_request_owners:
        BTreeMap<String, BTreeSet<ClaudeDuplicateRequestOwner>>,
    /// Visitor slices this terminal read, both visits.
    pub(super) slices: usize,
    /// The most stored-row bytes one slice decoded.
    pub(super) peak_slice_bytes: usize,
    /// The most usage families the graph held installed at a slice's end
    /// (a resident graph holds all of them).
    pub(super) installed_families: usize,
}

/// Sweep every family and join them, or refuse the terminal. One token
/// covers every slice of both visits: a store changed between slices, or a
/// sweep that missed a family, refuses.
pub(super) fn sweep(
    index: &ScanIndex,
    inputs: &TerminalInputs<'_>,
) -> Result<TerminalJoin, Refused> {
    let mut join = TerminalJoin::default();
    let mut after: Option<String> = None;
    let mut token: Option<UsageToken> = None;
    let mut visited = 0_usize;
    loop {
        let end: SliceEnd = state_v2::visit_usage_ordered(
            index,
            None,
            after.as_deref(),
            slice_budget(),
            &mut |root, family| join.add(index, inputs, root, family),
        )
        .map_err(|_| Refused)?;
        join.note_slice(index, &end);
        visited = visited.saturating_add(end.visited);
        if *token.get_or_insert(end.token) != end.token {
            return Err(Refused);
        }
        after = end.last_root;
        if after.is_none() {
            break;
        }
    }
    let token = token.ok_or(Refused)?;
    if token.families != visited {
        return Err(Refused);
    }
    join.entries.sort_unstable();
    // Requests in two or more current-window owners' occurrences.
    let both = OCCURRENCE | CURRENT;
    let duplicated = join
        .entries
        .chunk_by(|a, b| a.0 == b.0)
        .filter_map(|run| {
            let owners = run
                .iter()
                .filter(|(_, _, flags)| flags & both == both)
                .map(|(_, owner, _)| *owner)
                .collect::<Vec<_>>();
            (owners.len() > 1).then(|| (run[0].0, owners))
        })
        .collect::<BTreeMap<_, _>>();
    let duplicate_roots = duplicated
        .values()
        .flatten()
        .map(|owner| join.owners[*owner as usize].0.clone())
        .collect::<BTreeSet<_>>();
    // A legacy fork prefix is shared only by families whose root
    // sequences start with the same request.
    let candidate_first_keys = join
        .candidates
        .iter()
        .filter_map(|root| join.first_keys.get(root))
        .copied()
        .collect::<BTreeSet<_>>();
    let group = join
        .first_keys
        .iter()
        .filter(|(_, key)| candidate_first_keys.contains(*key))
        .map(|(root, _)| root.clone())
        .collect::<BTreeSet<_>>();
    let targeted = group
        .union(&duplicate_roots)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut names = BTreeMap::<RequestKey, String>::new();
    let mut group_pending = BTreeMap::<String, ClaudeUsageFamilyPending>::new();
    let mut after: Option<String> = None;
    while !targeted.is_empty() {
        let end: SliceEnd = state_v2::visit_usage_ordered(
            index,
            Some(&targeted),
            after.as_deref(),
            slice_budget(),
            &mut |root, family| {
                if group.contains(root) {
                    group_pending.insert(root.to_owned(), family.clone());
                }
                if duplicate_roots.contains(root) {
                    for hash in family.member_occurrences.values().flat_map(BTreeMap::keys) {
                        let key = lenient_decode::repair_key(hash);
                        if duplicated.contains_key(&key) && !names.contains_key(&key) {
                            names.insert(key, hash.clone());
                        }
                    }
                }
            },
        )
        .map_err(|_| Refused)?;
        join.note_slice(index, &end);
        if end.token != token {
            return Err(Refused);
        }
        after = end.last_root;
        if after.is_none() {
            break;
        }
    }
    for (key, owners) in duplicated {
        let hash = names.remove(&key).ok_or(Refused)?;
        let owners = owners
            .into_iter()
            .map(|owner| {
                let (root, member) = &join.owners[owner as usize];
                claude_duplicate_request_owner(root, member)
            })
            .collect();
        join.native_duplicate_request_owners.insert(hash, owners);
    }
    // Each candidate proves with the exclusion the whole-load join gives
    // it: another sequence sharing its prefix is in its group.
    let exclusions = derive_claude_legacy_usage_exclusions(
        inputs.complete_families,
        &group_pending,
        inputs.legacy_request_owners,
    );
    for root in std::mem::take(&mut join.candidates) {
        if let (Some(members), Some(pending)) = (
            inputs.complete_families.get(&root),
            group_pending.get(&root),
        ) {
            join.prove(
                index,
                inputs,
                &root,
                members,
                pending,
                exclusions.get(&root),
            );
        }
    }
    Ok(join)
}

impl TerminalJoin {
    fn note_slice(&mut self, index: &ScanIndex, end: &SliceEnd) {
        let usage = &index.claude_usage_family_pending;
        let installed = usage.cold().map_or(usage.len(), |cold| cold.loaded().len());
        self.slices += 1;
        self.peak_slice_bytes = self.peak_slice_bytes.max(end.decoded_bytes);
        self.installed_families = self.installed_families.max(installed);
    }

    /// Sweep 1 for one family: pure in the family and the fixed inputs.
    fn add(
        &mut self,
        index: &ScanIndex,
        inputs: &TerminalInputs<'_>,
        root: &str,
        family: &ClaudeUsageFamilyPending,
    ) {
        let current = if family.census_window_end == inputs.census_window_end {
            CURRENT
        } else {
            0
        };
        let members = family
            .member_request_id_hashes
            .keys()
            .chain(family.member_occurrences.keys())
            .collect::<BTreeSet<_>>();
        let first = u32::try_from(self.owners.len()).unwrap_or(u32::MAX);
        let mut entries = Vec::new();
        for (owner, member) in (first..).zip(&members) {
            let hashes = family.member_request_id_hashes.get(*member);
            entries.extend(
                hashes
                    .into_iter()
                    .flatten()
                    .map(|hash| (lenient_decode::repair_key(hash), owner, HASH | current)),
            );
            let occurrences = family.member_occurrences.get(*member);
            entries.extend(
                occurrences
                    .into_iter()
                    .flat_map(BTreeMap::keys)
                    .map(|hash| {
                        (
                            lenient_decode::repair_key(hash),
                            owner,
                            OCCURRENCE | current,
                        )
                    }),
            );
            self.owners.push((root.to_owned(), (*member).clone()));
        }
        // One entry per key and owner, its flags merged.
        entries.sort_unstable();
        for (key, owner, flags) in entries {
            match self.entries.last_mut() {
                Some(last) if last.0 == key && last.1 == owner => last.2 |= flags,
                _ => self.entries.push((key, owner, flags)),
            }
        }
        let count = u32::try_from(members.len()).unwrap_or(u32::MAX);
        self.families.insert(root.to_owned(), (first, count));

        let root_occurrences = family.member_occurrences.get(root);
        if let (Some(request_owners), Some(occurrences)) =
            (inputs.legacy_request_owners, root_occurrences)
        {
            let foreign = occurrences
                .keys()
                .filter_map(|hash| request_owners.get(hash))
                .filter(|owner| owner.root_session_id != root)
                .map(|owner| owner.root_session_id.to_owned())
                .collect::<BTreeSet<_>>();
            if !foreign.is_empty() {
                self.foreign_owner_roots.insert(root.to_owned(), foreign);
            }
        }
        let Some(members) = inputs.complete_families.get(root) else {
            return;
        };
        // The root sequence `derive_claude_legacy_usage_exclusions` reads.
        let mut candidate = false;
        if let Some(sequence) = claude_root_request_sequence(root, family) {
            let head = sequence[0];
            self.first_keys
                .insert(root.to_owned(), lenient_decode::repair_key(head));
            candidate = inputs.legacy_request_owners.is_some_and(|owners| {
                owners
                    .get(head)
                    .is_some_and(|owner| owner.root_session_id != root)
            });
        }
        if candidate {
            self.candidates.insert(root.to_owned());
        } else {
            self.prove(index, inputs, root, members, family, None);
        }
    }

    /// The terminal's family proof, as the whole-load fold ran it (healthy
    /// reports only).
    fn prove(
        &mut self,
        index: &ScanIndex,
        inputs: &TerminalInputs<'_>,
        root: &str,
        members: &BTreeSet<String>,
        base: &ClaudeUsageFamilyPending,
        exclusion: Option<&ClaudeLegacyUsageExclusion>,
    ) {
        let Some(proof) = inputs
            .proof
            .as_ref()
            .filter(|proof| !proof.skipped.contains(root))
        else {
            return;
        };
        let mut pending = base.clone();
        for member in confirmed_empty_claude_family_members(index, root) {
            pending
                .member_request_id_hashes
                .entry(member.clone())
                .or_default();
            pending.member_occurrences.entry(member).or_default();
        }
        if pending.invalid
            || pending.census_window_end != inputs.census_window_end
            || !pending.member_request_id_hashes.keys().eq(members.iter())
            || !pending.member_occurrences.keys().eq(members.iter())
        {
            return;
        }
        let (api_rows, trace_rows) =
            match proof
                .evidence_rows
                .proof_rows(root, proof.api_report, proof.trace_report)
            {
                Ok(pair) => pair,
                Err(refusal) => {
                    self.ignored_vetoes |= refusal.bit();
                    return;
                }
            };
        let Some(mut family) = prove_claude_usage_family(
            root,
            members,
            &pending,
            api_rows.as_deref(),
            trace_rows.as_deref(),
            exclusion,
        ) else {
            if api_rows.is_some() || trace_rows.is_some() {
                self.ignored_vetoes |= IgnoredVeto::ProofFailure.bit();
            }
            return;
        };
        // Only page-item roots consume these rows. Keep every proven key and
        // witness for rebind, retention and rearm.
        if !inputs.item_roots.contains(root) {
            family.rows_by_member = BTreeMap::new();
        }
        self.proven.insert(root.to_owned(), family);
    }

    fn owner(&self, root: &str, member: &str) -> Option<u32> {
        let (first, count) = *self.families.get(root)?;
        let members = self.owners.get(first as usize..(first + count) as usize)?;
        let at = members
            .binary_search_by(|(_, candidate)| candidate.as_str().cmp(member))
            .ok()?;
        Some(first + at as u32)
    }

    fn runs<'k>(
        &'k self,
        keys: &'k BTreeSet<RequestKey>,
    ) -> impl Iterator<Item = &'k (RequestKey, u32, u8)> + 'k {
        keys.iter().flat_map(move |key| {
            let from = self.entries.partition_point(|entry| entry.0 < *key);
            self.entries[from..]
                .iter()
                .take_while(move |entry| entry.0 == *key)
        })
    }

    /// Whether `member` of `root` holds any of `keys` among its request
    /// hashes, in any window.
    pub(super) fn member_hashes_meet(
        &self,
        root: &str,
        member: &str,
        keys: &BTreeSet<RequestKey>,
    ) -> bool {
        let Some(owner) = self.owner(root, member) else {
            return false;
        };
        self.runs(keys)
            .any(|(_, other, flags)| *other == owner && flags & HASH != 0)
    }

    /// Roots with a member whose request hashes hold any of `keys`.
    pub(super) fn roots_with_hashes(&self, keys: &BTreeSet<RequestKey>) -> BTreeSet<&str> {
        self.runs(keys)
            .filter(|(_, _, flags)| flags & HASH != 0)
            .map(|(_, owner, _)| self.owners[*owner as usize].0.as_str())
            .collect()
    }

    /// The other roots that own `root`'s root-member occurrences.
    pub(super) fn foreign_owner_roots(&self, root: &str) -> impl Iterator<Item = &String> + '_ {
        self.foreign_owner_roots.get(root).into_iter().flatten()
    }
}

/// Request hashes as join keys.
pub(super) fn keys<'h>(hashes: impl IntoIterator<Item = &'h String>) -> BTreeSet<RequestKey> {
    hashes
        .into_iter()
        .map(|hash| lenient_decode::repair_key(hash))
        .collect()
}

/// The join a complete census in `census_window_end` builds over `index`,
/// without report proofs or request owners.
#[cfg(test)]
pub(super) fn swept(index: &ScanIndex, census_window_end: &str) -> TerminalJoin {
    let complete_families = complete_claude_usage_family_members(index);
    let item_roots = BTreeSet::new();
    let inputs = TerminalInputs {
        census_window_end,
        complete_families: &complete_families,
        item_roots: &item_roots,
        legacy_request_owners: None,
        proof: None,
    };
    sweep(index, &inputs).expect("every family is readable")
}
