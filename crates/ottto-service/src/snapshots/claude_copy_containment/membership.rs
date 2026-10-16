//! Negative-only process cache. No ACK membership or upload permission.
//! Forward and reverse links share immutable ID strings. Reverse links make
//! removing one held revision proportional to that revision, not the pool.
use crate::heap_layout_bound::{self, Counter};
use std::collections::{BTreeMap, BTreeSet};
use std::mem::{align_of, size_of};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ScopedSession {
    destination: [u8; 32],
    session: [u8; 32],
}

impl ScopedSession {
    pub(super) fn new(destination: [u8; 32], session: [u8; 32]) -> Self {
        Self {
            destination,
            session,
        }
    }
}

#[derive(Default)]
struct HeldMembership {
    ids: BTreeSet<Arc<String>>,
    seen_peers: BTreeMap<ScopedSession, [u8; 32]>,
    preflight_epoch: u64,
    applied_epoch: u64,
}

#[derive(Default)]
pub(super) struct MembershipIndex {
    by_id: BTreeMap<Arc<String>, BTreeSet<ScopedSession>>,
    by_held: BTreeMap<ScopedSession, HeldMembership>,
    memberships: usize,
    peer_witnesses: usize,
    query_epoch: u64,
    // Monotone conservative charge. Removal never invents reclaimed budget.
    // All mutators are private to this module and update it before allocation.
    charged_heap_upper_bound: usize,
}

impl std::fmt::Debug for MembershipIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MembershipIndex")
            .field("held_count", &self.by_held.len())
            .field("native_membership_count", &self.memberships)
            .field("peer_witness_count", &self.peer_witnesses)
            .field("charged_heap_upper_bound", &self.charged_heap_upper_bound)
            .finish_non_exhaustive()
    }
}

/// The caller must subtract all other owners/holds and retained sibling/frame
/// graphs from the EXISTING shared allowances first. These are not new caps.
/// `heap_bytes` bounds this pool PLUS the still-owned incoming input and all
/// transient insertion allocations, not just the final graph.
pub(super) struct Allowance {
    pub(super) owner_slots: usize,
    pub(super) held_slots: usize,
    pub(super) heap_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    UnavailableLayout,
    OwnerBudget,
    HeapBudget,
    ExistingHeldRevision,
    EmptyInput,
}

impl MembershipIndex {
    /// A borrowed negative lookup only. Empty output is NOT proof of absence
    /// and callbacks may repeat a held key for multiple matching native IDs.
    pub(super) fn for_each_cached_native_link(
        &self,
        ids: &BTreeSet<String>,
        mut visit: impl FnMut(ScopedSession),
    ) -> usize {
        let mut links = 0;
        for id in ids {
            if let Some(owners) = self.by_id.get(id) {
                for held in owners {
                    links += 1;
                    visit(*held);
                }
            }
        }
        links
    }

    /// Fail BEFORE mutating or allocating the index. Conservative future-node
    /// charges include old nodes during splits; shared Arc payloads are charged
    /// twice, and incoming strings remain charged even after they are moved.
    fn insertion_preflight(
        &self,
        held: ScopedSession,
        ids: &BTreeSet<String>,
        allowance: &Allowance,
    ) -> Result<usize, Refused> {
        if !heap_layout_bound::layout_supported() {
            return Err(Refused::UnavailableLayout);
        }
        if self.by_held.contains_key(&held) {
            return Err(Refused::ExistingHeldRevision);
        }
        if ids.is_empty() {
            return Err(Refused::EmptyInput);
        }
        if self.by_held.len() >= allowance.held_slots
            || self
                .memberships
                .checked_add(self.peer_witnesses)
                .and_then(|count| count.checked_add(ids.len()))
                .is_none_or(|count| count > allowance.owner_slots)
        {
            return Err(Refused::OwnerBudget);
        }
        let old = self
            .current_charge(allowance.heap_bytes)
            .ok_or(Refused::HeapBudget)?;
        let input = heap_layout_bound::completed_bound(ids, allowance.heap_bytes)
            .ok_or(Refused::HeapBudget)?;
        let mut charge = Counter::new(allowance.heap_bytes);
        charge
            .add(old)
            .and_then(|_| charge.add(input))
            .ok_or(Refused::HeapBudget)?;
        heap_layout_bound::tree_nodes::<Arc<String>, BTreeSet<ScopedSession>>(
            self.by_id
                .len()
                .checked_add(ids.len())
                .ok_or(Refused::HeapBudget)?,
            &mut charge,
        )
        .ok_or(Refused::HeapBudget)?;
        heap_layout_bound::tree_nodes::<ScopedSession, HeldMembership>(
            self.by_held
                .len()
                .checked_add(1)
                .ok_or(Refused::HeapBudget)?,
            &mut charge,
        )
        .ok_or(Refused::HeapBudget)?;
        heap_layout_bound::tree_nodes::<Arc<String>, ()>(ids.len(), &mut charge)
            .ok_or(Refused::HeapBudget)?;
        // Keep traversal visits local per completed element, as the ordinary
        // completed graph accounting does. All bytes still share ONE limit.
        let mut additions = 0usize;
        for id in ids {
            let mut element = Counter::new(allowance.heap_bytes);
            let owners = self.by_id.get(id).map_or(0, BTreeSet::len);
            heap_layout_bound::tree_nodes::<ScopedSession, ()>(
                owners.checked_add(1).ok_or(Refused::HeapBudget)?,
                &mut element,
            )
            .ok_or(Refused::HeapBudget)?;
            let arc = size_of::<String>()
                .checked_add(align_of::<String>())
                .and_then(|n| n.checked_add(2 * size_of::<usize>()))
                .and_then(|n| n.checked_add(id.capacity()))
                .and_then(|n| n.checked_mul(2))
                .ok_or(Refused::HeapBudget)?;
            element.add(arc).ok_or(Refused::HeapBudget)?;
            additions = additions
                .checked_add(element.bytes)
                .ok_or(Refused::HeapBudget)?;
        }
        // An empty peer map may own an empty root after future removals.
        heap_layout_bound::tree_nodes::<ScopedSession, [u8; 32]>(0, &mut charge)
            .ok_or(Refused::HeapBudget)?;
        charge.add(additions).ok_or(Refused::HeapBudget)?;
        Ok(charge.bytes)
    }

    pub(super) fn insert(
        &mut self,
        held: ScopedSession,
        ids: BTreeSet<String>,
        allowance: &Allowance,
    ) -> Result<usize, Refused> {
        let peak_bound = self.insertion_preflight(held, &ids, allowance)?;
        self.charged_heap_upper_bound = peak_bound;
        let mut reverse = HeldMembership::default();
        for id in ids {
            let shared = self
                .by_id
                .get_key_value(&id)
                .map(|(key, _)| key.clone())
                .unwrap_or_else(|| Arc::new(id));
            self.by_id.entry(shared.clone()).or_default().insert(held);
            reverse.ids.insert(shared);
        }
        self.memberships += reverse.ids.len(); // Preflight checked this sum.
        self.by_held.insert(held, reverse);
        Ok(peak_bound)
    }

    fn current_charge(&self, limit: usize) -> Option<usize> {
        if self.charged_heap_upper_bound != 0 {
            return (self.charged_heap_upper_bound <= limit)
                .then_some(self.charged_heap_upper_bound);
        }
        // The only uncharged state is the empty, never-admitted pool.
        (self.by_id.is_empty() && self.by_held.is_empty())
            .then(|| heap_layout_bound::completed_bound(self, limit))
            .flatten()
    }

    /// Visit only this held revision's reverse links. No full-pool removal walk.
    /// Returns the number of retired native membership links for cost receipts.
    pub(super) fn remove(&mut self, held: ScopedSession) -> usize {
        let Some(old) = self.by_held.remove(&held) else {
            return 0;
        };
        self.memberships -= old.ids.len();
        self.peer_witnesses -= old.seen_peers.len();
        let count = old.ids.len();
        for id in old.ids {
            if let Some(owners) = self.by_id.get_mut(&id) {
                owners.remove(&held);
                if owners.is_empty() {
                    self.by_id.remove(&id);
                }
            }
        }
        count
    }

    /// Borrow current native IDs. Callbacks name newly observed peer events,
    /// never perform a read/upload directly. A same peer/revision is emitted
    /// once even if many IDs match or base re-parses the peer repeatedly.
    /// Refusal leaves that event UNKNOWN/parked; no eligibility is returned.
    pub(super) fn observe_peer(
        &mut self,
        peer: ScopedSession,
        revision: [u8; 32],
        ids: &BTreeSet<String>,
        allowance: &Allowance,
        mut event: impl FnMut(ScopedSession),
    ) -> Result<usize, Refused> {
        if !heap_layout_bound::layout_supported() {
            return Err(Refused::UnavailableLayout);
        }
        let epoch = self
            .query_epoch
            .checked_add(1)
            .ok_or(Refused::OwnerBudget)?;
        self.query_epoch = epoch;
        let old = self
            .current_charge(allowance.heap_bytes)
            .ok_or(Refused::HeapBudget)?;
        let input = heap_layout_bound::completed_bound(ids, allowance.heap_bytes)
            .ok_or(Refused::HeapBudget)?;
        let mut additions = 0usize;
        let mut new_witnesses = 0usize;
        // First pass mutates only fixed-size scratch epochs. No event witness,
        // callback or allocation occurs until ALL affected insertions fit.
        // Matching many IDs never charges/schedules a held key more than once.
        for id in ids {
            let Some(owners) = self.by_id.get(id) else {
                continue;
            };
            for held in owners {
                if *held == peer {
                    continue;
                }
                let Some(record) = self.by_held.get_mut(held) else {
                    continue;
                };
                if record.preflight_epoch == epoch
                    || record.seen_peers.get(&peer) == Some(&revision)
                {
                    continue;
                }
                record.preflight_epoch = epoch;
                if !record.seen_peers.contains_key(&peer) {
                    new_witnesses = new_witnesses.checked_add(1).ok_or(Refused::OwnerBudget)?;
                    let mut child = Counter::new(allowance.heap_bytes);
                    heap_layout_bound::tree_nodes::<ScopedSession, [u8; 32]>(
                        record
                            .seen_peers
                            .len()
                            .checked_add(1)
                            .ok_or(Refused::HeapBudget)?,
                        &mut child,
                    )
                    .ok_or(Refused::HeapBudget)?;
                    additions = additions
                        .checked_add(child.bytes)
                        .ok_or(Refused::HeapBudget)?;
                }
            }
        }
        if self
            .memberships
            .checked_add(self.peer_witnesses)
            .and_then(|n| n.checked_add(new_witnesses))
            .is_none_or(|n| n > allowance.owner_slots)
        {
            return Err(Refused::OwnerBudget);
        }
        let final_bound = old.checked_add(additions).ok_or(Refused::HeapBudget)?;
        if final_bound
            .checked_add(input)
            .is_none_or(|n| n > allowance.heap_bytes)
        {
            return Err(Refused::HeapBudget);
        }
        self.charged_heap_upper_bound = final_bound;
        let mut emitted = 0;
        for id in ids {
            let Some(owners) = self.by_id.get(id) else {
                continue;
            };
            for held in owners {
                if *held == peer {
                    continue;
                }
                let record = self
                    .by_held
                    .get_mut(held)
                    .expect("forward/reverse membership");
                if record.preflight_epoch != epoch || record.applied_epoch == epoch {
                    continue;
                }
                record.applied_epoch = epoch;
                if record.seen_peers.insert(peer, revision).is_none() {
                    self.peer_witnesses += 1;
                }
                emitted += 1;
                event(*held);
            }
        }
        Ok(emitted)
    }
}

crate::heap_layout_bound::fields!(ScopedSession; destination, session);
crate::heap_layout_bound::fields!(HeldMembership; ids, seen_peers, preflight_epoch, applied_epoch);
crate::heap_layout_bound::fields!(MembershipIndex; by_id, by_held, memberships, peer_witnesses, query_epoch, charged_heap_upper_bound);

#[cfg(test)]
mod tests;
