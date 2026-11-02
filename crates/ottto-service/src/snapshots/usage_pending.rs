//! Claude usage-pending families. v1, import, raw holds and CAS custody keep
//! them `Resident`. A complete v2 hydrate keeps them `Cold`: each family's
//! row stays in the store and RAM keeps its head (window, flags, member names
//! with counts, row digest). A page loads its own families before it
//! accumulates; a terminal decision that joins every family loads them all
//! first, and the traversal-start carry streams them one at a time. A
//! family with a head and no loaded value is Unknown, never absent.
use super::evidence_owed::EvidenceContract;
use super::ClaudeUsageFamilyPending;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) type Families = BTreeMap<String, ClaudeUsageFamilyPending>;

/// A cold family's evidence is in the store only; it was not loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Unknown;
impl std::fmt::Display for Unknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("state_v2_usage_pending_unknown")
    }
}
impl std::error::Error for Unknown {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum UsagePending {
    Resident(Families),
    Cold(Box<ColdUsage>),
}
impl Default for UsagePending {
    fn default() -> Self {
        Self::Resident(BTreeMap::new())
    }
}
impl From<Families> for UsagePending {
    fn from(families: Families) -> Self {
        Self::Resident(families)
    }
}
impl Serialize for UsagePending {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Resident(families) => families.serialize(serializer),
            // Only the store holds these families. An image without them
            // would drop their custody, so no encoder may write one.
            Self::Cold(_) => Err(serde::ser::Error::custom("usage_pending_cold")),
        }
    }
}
impl<'de> Deserialize<'de> for UsagePending {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Families::deserialize(deserializer).map(Self::Resident)
    }
}
impl HeapLayoutBound for UsagePending {
    fn stable_heap(&self) -> bool {
        match self {
            Self::Resident(families) => families.stable_heap(),
            Self::Cold(cold) => cold.stable_heap(),
        }
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Resident(families) => families.heap_bound(c),
            Self::Cold(cold) => cold.heap_bound(c),
        }
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Resident(families) => families.completed_heap_bound(c),
            Self::Cold(cold) => cold.completed_heap_bound(c),
        }
    }
}
/// Test fixtures build and read resident families directly.
#[cfg(test)]
impl std::ops::Deref for UsagePending {
    type Target = Families;
    fn deref(&self) -> &Families {
        self.resident().expect("usage_pending_cold")
    }
}
#[cfg(test)]
impl std::ops::DerefMut for UsagePending {
    fn deref_mut(&mut self) -> &mut Families {
        self.resident_mut().expect("usage_pending_cold")
    }
}

/// Everything a summary reader may see of a stored family: its row's digest
/// and what the row says without its request hashes and occurrences.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct UsageHead {
    window: String,
    invalid: bool,
    idless_revision: Option<[u8; 32]>,
    identity_contract: Option<EvidenceContract>,
    contract_unproven: bool,
    /// Per member: request-hash count and occurrence count, each present only
    /// where the row has that member's entry.
    members: BTreeMap<String, (Option<u32>, Option<u32>)>,
    occurrences: usize,
    pub(super) digest: [u8; 32],
}
crate::heap_layout_bound::fields!(UsageHead; window, invalid, idless_revision, identity_contract, contract_unproven, members, occurrences, digest);
impl std::fmt::Debug for UsageHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageHead")
            .field("members", &self.members.len())
            .field("occurrences", &self.occurrences)
            .finish_non_exhaustive()
    }
}
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
impl UsageHead {
    pub(super) fn of(family: &ClaudeUsageFamilyPending, digest: [u8; 32]) -> Self {
        let mut members = BTreeMap::<String, (Option<u32>, Option<u32>)>::new();
        for (member, hashes) in &family.member_request_id_hashes {
            members.entry(member.clone()).or_default().0 = Some(count(hashes.len()));
        }
        for (member, occurrences) in &family.member_occurrences {
            members.entry(member.clone()).or_default().1 = Some(count(occurrences.len()));
        }
        Self {
            window: family.census_window_end.clone(),
            invalid: family.invalid,
            idless_revision: family.idless_revision,
            identity_contract: family.identity_contract,
            contract_unproven: family.contract_unproven,
            members,
            occurrences: family.occurrences(),
            digest,
        }
    }
}

/// A family as summary readers see it: the loaded value when there is one,
/// else its head. Neither exposes request hashes or occurrences.
#[derive(Clone, Copy)]
pub(super) enum UsageView<'a> {
    Full(&'a ClaudeUsageFamilyPending),
    Head(&'a UsageHead),
}
impl<'a> UsageView<'a> {
    pub(super) fn window(self) -> &'a str {
        match self {
            Self::Full(f) => &f.census_window_end,
            Self::Head(h) => &h.window,
        }
    }
    pub(super) fn invalid(self) -> bool {
        match self {
            Self::Full(f) => f.invalid,
            Self::Head(h) => h.invalid,
        }
    }
    pub(super) fn idless_revision(self) -> Option<[u8; 32]> {
        match self {
            Self::Full(f) => f.idless_revision,
            Self::Head(h) => h.idless_revision,
        }
    }
    pub(super) fn identity_contract(self) -> Option<EvidenceContract> {
        match self {
            Self::Full(f) => f.identity_contract,
            Self::Head(h) => h.identity_contract,
        }
    }
    pub(super) fn contract_unproven(self) -> bool {
        match self {
            Self::Full(f) => f.contract_unproven,
            Self::Head(h) => h.contract_unproven,
        }
    }
    /// Members with a request-hash entry.
    pub(super) fn hash_members(self) -> Box<dyn Iterator<Item = &'a String> + 'a> {
        match self {
            Self::Full(f) => Box::new(f.member_request_id_hashes.keys()),
            Self::Head(h) => Box::new(h.members.iter().filter(|m| m.1 .0.is_some()).map(|m| m.0)),
        }
    }
    /// Members with an occurrence entry.
    pub(super) fn occurrence_members(self) -> Box<dyn Iterator<Item = &'a String> + 'a> {
        match self {
            Self::Full(f) => Box::new(f.member_occurrences.keys()),
            Self::Head(h) => Box::new(h.members.iter().filter(|m| m.1 .1.is_some()).map(|m| m.0)),
        }
    }
    pub(super) fn has_occurrence_member(self, member: &str) -> bool {
        match self {
            Self::Full(f) => f.member_occurrences.contains_key(member),
            Self::Head(h) => h.members.get(member).is_some_and(|m| m.1.is_some()),
        }
    }
    pub(super) fn hash_member_count(self) -> usize {
        match self {
            Self::Full(f) => f.member_request_id_hashes.len(),
            Self::Head(h) => h.members.values().filter(|m| m.0.is_some()).count(),
        }
    }
    /// Request hashes summed over members.
    pub(super) fn request_hash_count(self) -> usize {
        match self {
            Self::Full(f) => f
                .member_request_id_hashes
                .values()
                .map(std::collections::BTreeSet::len)
                .fold(0, usize::saturating_add),
            Self::Head(h) => h
                .members
                .values()
                .map(|m| m.0.unwrap_or(0) as usize)
                .fold(0, usize::saturating_add),
        }
    }
    pub(super) fn occurrences(self) -> usize {
        match self {
            Self::Full(f) => f.occurrences(),
            Self::Head(h) => h.occurrences,
        }
    }
    /// No occurrence entry and no request hash.
    pub(super) fn evidence_free(self) -> bool {
        match self {
            Self::Full(f) => {
                f.member_occurrences.is_empty()
                    && f.member_request_id_hashes
                        .values()
                        .all(std::collections::BTreeSet::is_empty)
            }
            Self::Head(h) => h
                .members
                .values()
                .all(|(hashes, occurrences)| occurrences.is_none() && hashes.unwrap_or(0) == 0),
        }
    }
}

/// Heads of every stored family plus the families loaded this pass. A loaded
/// value overrides its head and is always rewritten at save. `complete`: a
/// decision loaded every family, so `loaded` alone is the family set until
/// `settle` returns to heads.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct ColdUsage {
    heads: BTreeMap<String, UsageHead>,
    loaded: Families,
    complete: bool,
    /// Occurrences summed over every head.
    head_occurrences: usize,
}
crate::heap_layout_bound::fields!(ColdUsage; heads, loaded, complete, head_occurrences);
impl std::fmt::Debug for ColdUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdUsage")
            .field("heads", &self.heads.len())
            .field("loaded", &self.loaded.len())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}
impl ColdUsage {
    /// Fold one stored row into its head; the value is dropped by the caller.
    pub(super) fn fold(&mut self, root: &str, family: &ClaudeUsageFamilyPending, digest: [u8; 32]) {
        self.set_head(root, UsageHead::of(family, digest));
    }
    pub(super) fn head(&self, root: &str) -> Option<&UsageHead> {
        self.heads.get(root)
    }
    pub(super) fn loaded(&self) -> &Families {
        &self.loaded
    }
    pub(super) fn head_roots(&self) -> impl Iterator<Item = &String> + '_ {
        self.heads.keys()
    }
    fn set_head(&mut self, root: &str, head: UsageHead) {
        self.head_occurrences = self.head_occurrences.saturating_add(head.occurrences);
        if let Some(old) = self.heads.insert(root.to_owned(), head) {
            self.head_occurrences = self.head_occurrences.saturating_sub(old.occurrences);
        }
    }
    fn drop_head(&mut self, root: &str) {
        if let Some(old) = self.heads.remove(root) {
            self.head_occurrences = self.head_occurrences.saturating_sub(old.occurrences);
        }
    }
    /// Install a stored value read for this pass. Its digest must be the
    /// head's: anything else is a row this graph does not know (Unknown).
    pub(super) fn install(
        &mut self,
        root: String,
        family: ClaudeUsageFamilyPending,
        digest: [u8; 32],
    ) -> Result<(), Unknown> {
        self.admits(&root, digest)?;
        if !self.loaded.contains_key(&root) && self.heads.contains_key(&root) {
            self.loaded.insert(root, family);
        }
        Ok(())
    }
    /// Whether `install` would accept this row: its digest is the head's, or
    /// the family is loaded already or was removed by this graph.
    pub(super) fn admits(&self, root: &str, digest: [u8; 32]) -> Result<(), Unknown> {
        if self.loaded.contains_key(root) {
            return Ok(());
        }
        match self.heads.get(root) {
            Some(head) if head.digest == digest => Ok(()),
            // A row this graph removed stays removed.
            None if !self.complete => Ok(()),
            _ => Err(Unknown),
        }
    }
    /// After a whole-kind load: every head must be loaded.
    pub(super) fn complete(&mut self) -> Result<(), Unknown> {
        if self
            .heads
            .keys()
            .any(|root| !self.loaded.contains_key(root))
        {
            return Err(Unknown);
        }
        self.complete = true;
        Ok(())
    }
    /// End a decision that loaded every family: heads of removed families go,
    /// and loaded values still equal to their row return to heads, except
    /// the `keep` families the caller's page still reads.
    pub(super) fn settle(
        &mut self,
        keep: &std::collections::BTreeSet<String>,
        digest: impl Fn(&ClaudeUsageFamilyPending) -> Option<[u8; 32]>,
    ) {
        if self.complete {
            let removed: Vec<String> = self
                .heads
                .keys()
                .filter(|root| !self.loaded.contains_key(*root))
                .cloned()
                .collect();
            for root in removed {
                self.drop_head(&root);
            }
            self.complete = false;
        }
        let heads = &self.heads;
        self.loaded.retain(|root, family| {
            keep.contains(root)
                || !heads
                    .get(root)
                    .is_some_and(|head| digest(family) == Some(head.digest))
        });
    }
    /// After this graph's committed save: each loaded family's head is the
    /// row the save left, so it matches the committed baseline again.
    pub(super) fn saved(&mut self, committed: impl Fn(&str) -> Option<[u8; 32]>) {
        if self.complete {
            let removed: Vec<String> = self
                .heads
                .keys()
                .filter(|root| !self.loaded.contains_key(*root))
                .cloned()
                .collect();
            for root in removed {
                self.drop_head(&root);
            }
        }
        let heads: Vec<(String, UsageHead)> = self
            .loaded
            .iter()
            .filter_map(|(root, family)| {
                Some((root.clone(), UsageHead::of(family, committed(root)?)))
            })
            .collect();
        for (root, head) in heads {
            self.set_head(&root, head);
        }
    }
}

/// Sorted merge of the head and loaded keys; a loaded value wins.
fn merged<'a>(cold: &'a ColdUsage) -> impl Iterator<Item = (&'a String, UsageView<'a>)> + 'a {
    let mut heads = cold.heads.iter().filter(|_| !cold.complete).peekable();
    let mut loaded = cold.loaded.iter().peekable();
    std::iter::from_fn(move || match (heads.peek(), loaded.peek()) {
        (None, None) => None,
        (Some(_), None) => heads.next().map(|(r, h)| (r, UsageView::Head(h))),
        (None, Some(_)) => loaded.next().map(|(r, f)| (r, UsageView::Full(f))),
        (Some((hr, _)), Some((lr, _))) => match hr.cmp(lr) {
            std::cmp::Ordering::Less => heads.next().map(|(r, h)| (r, UsageView::Head(h))),
            std::cmp::Ordering::Greater => loaded.next().map(|(r, f)| (r, UsageView::Full(f))),
            std::cmp::Ordering::Equal => {
                heads.next();
                loaded.next().map(|(r, f)| (r, UsageView::Full(f)))
            }
        },
    })
}

impl UsagePending {
    pub(super) fn resident(&self) -> Option<&Families> {
        match self {
            Self::Resident(families) => Some(families),
            Self::Cold(_) => None,
        }
    }
    pub(super) fn resident_mut(&mut self) -> Option<&mut Families> {
        match self {
            Self::Resident(families) => Some(families),
            Self::Cold(_) => None,
        }
    }
    pub(super) fn cold(&self) -> Option<&ColdUsage> {
        match self {
            Self::Resident(_) => None,
            Self::Cold(cold) => Some(cold),
        }
    }
    pub(super) fn cold_mut(&mut self) -> Option<&mut ColdUsage> {
        match self {
            Self::Resident(_) => None,
            Self::Cold(cold) => Some(cold),
        }
    }
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Resident(families) => families.len(),
            Self::Cold(_) => self.views().count(),
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.views().next().is_none()
    }
    pub(super) fn contains_key(&self, root: &str) -> bool {
        self.view(root).is_some()
    }
    pub(super) fn roots(&self) -> impl Iterator<Item = &String> + '_ {
        self.views().map(|(root, _)| root)
    }
    pub(super) fn view(&self, root: &str) -> Option<UsageView<'_>> {
        match self {
            Self::Resident(families) => families.get(root).map(UsageView::Full),
            Self::Cold(cold) => match cold.loaded.get(root) {
                Some(family) => Some(UsageView::Full(family)),
                None if cold.complete => None,
                None => cold.heads.get(root).map(UsageView::Head),
            },
        }
    }
    /// Every family in root order, as summary readers see it.
    pub(super) fn views(&self) -> Box<dyn Iterator<Item = (&String, UsageView<'_>)> + '_> {
        match self {
            Self::Resident(families) => {
                Box::new(families.iter().map(|(root, f)| (root, UsageView::Full(f))))
            }
            Self::Cold(cold) => Box::new(merged(cold)),
        }
    }
    /// A family's evidence. Cold: Unknown while it has a head but was not
    /// loaded.
    pub(super) fn family(&self, root: &str) -> Result<Option<&ClaudeUsageFamilyPending>, Unknown> {
        match self.view(root) {
            None => Ok(None),
            Some(UsageView::Full(family)) => Ok(Some(family)),
            Some(UsageView::Head(_)) => Err(Unknown),
        }
    }
    pub(super) fn family_mut(
        &mut self,
        root: &str,
    ) -> Result<Option<&mut ClaudeUsageFamilyPending>, Unknown> {
        match self {
            Self::Resident(families) => Ok(families.get_mut(root)),
            Self::Cold(cold) => {
                if !cold.loaded.contains_key(root)
                    && !cold.complete
                    && cold.heads.contains_key(root)
                {
                    return Err(Unknown);
                }
                Ok(cold.loaded.get_mut(root))
            }
        }
    }
    /// Every family's evidence, for decisions that join across families.
    /// Cold: only after a whole-kind load in this decision.
    pub(super) fn all(&self) -> Result<&Families, Unknown> {
        match self {
            Self::Resident(families) => Ok(families),
            Self::Cold(cold) if cold.complete => Ok(&cold.loaded),
            Self::Cold(_) => Err(Unknown),
        }
    }
    pub(super) fn all_mut(&mut self) -> Result<&mut Families, Unknown> {
        match self {
            Self::Resident(families) => Ok(families),
            Self::Cold(cold) if cold.complete => Ok(&mut cold.loaded),
            Self::Cold(_) => Err(Unknown),
        }
    }
    /// `all` inside a decision that loaded every family before it began (a
    /// terminal page): a cold graph refused that page when the load failed,
    /// so this cannot see Unknown.
    pub(super) fn loaded_all(&self) -> &Families {
        self.all().expect("usage_pending_loaded_before_join")
    }
    pub(super) fn loaded_all_mut(&mut self) -> &mut Families {
        self.all_mut().expect("usage_pending_loaded_before_join")
    }
    /// The families a page accumulates into: every root it names that has a
    /// head must be loaded. New families are added to the loaded set.
    pub(super) fn page_mut<'r>(
        &mut self,
        roots: impl IntoIterator<Item = &'r str>,
    ) -> Result<&mut Families, Unknown> {
        match self {
            Self::Resident(families) => Ok(families),
            Self::Cold(cold) => {
                if !cold.complete
                    && roots.into_iter().any(|root| {
                        cold.heads.contains_key(root) && !cold.loaded.contains_key(root)
                    })
                {
                    return Err(Unknown);
                }
                Ok(&mut cold.loaded)
            }
        }
    }
    /// Roots with a head and no loaded value: what a page must load first.
    pub(super) fn unloaded<'r>(
        &self,
        roots: impl IntoIterator<Item = &'r str>,
    ) -> std::collections::BTreeSet<String> {
        match self {
            Self::Resident(_) => Default::default(),
            Self::Cold(cold) if cold.complete => Default::default(),
            Self::Cold(cold) => roots
                .into_iter()
                .filter(|root| cold.heads.contains_key(*root) && !cold.loaded.contains_key(*root))
                .map(str::to_owned)
                .collect(),
        }
    }
    /// Insert or replace a family's whole value.
    pub(super) fn add(&mut self, root: String, family: ClaudeUsageFamilyPending) {
        match self {
            Self::Resident(families) => {
                families.insert(root, family);
            }
            Self::Cold(cold) => {
                cold.loaded.insert(root, family);
            }
        }
    }
    /// Insert only where no family exists, stored or loaded.
    pub(super) fn add_absent(&mut self, root: String, family: ClaudeUsageFamilyPending) {
        if !self.contains_key(&root) {
            self.add(root, family);
        }
    }
    /// Remove a whole family; the next save deletes its row.
    pub(super) fn discard(&mut self, root: &str) {
        match self {
            Self::Resident(families) => {
                families.remove(root);
            }
            Self::Cold(cold) => {
                cold.loaded.remove(root);
                cold.drop_head(root);
            }
        }
    }
    /// Retained occurrences over every family: the pending-occurrence cap's
    /// running total.
    pub(super) fn total_occurrences(&self) -> usize {
        match self {
            Self::Resident(families) => families
                .values()
                .map(ClaudeUsageFamilyPending::occurrences)
                .fold(0_usize, usize::saturating_add),
            Self::Cold(cold) if cold.complete => cold
                .loaded
                .values()
                .map(ClaudeUsageFamilyPending::occurrences)
                .fold(0_usize, usize::saturating_add),
            Self::Cold(cold) => {
                let mut total = cold.head_occurrences;
                for (root, family) in &cold.loaded {
                    if let Some(head) = cold.heads.get(root) {
                        total = total.saturating_sub(head.occurrences);
                    }
                    total = total.saturating_add(family.occurrences());
                }
                total
            }
        }
    }
}

#[cfg(test)]
#[path = "usage_pending_tests.rs"]
pub(super) mod tests;
