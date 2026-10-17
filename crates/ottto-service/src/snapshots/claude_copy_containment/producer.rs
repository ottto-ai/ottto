//! Pre-offer producer custody. This pays only new physical owners; it neither
//! admits native capture nor changes overlap, settlement or ACK rules.
use super::pipeline::HeldFile;
use super::required_budget::{prospective_nodes, Unavailable, LIMIT};
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use crate::snapshots::sampled_scan::CopyReservation;
use crate::snapshots::{PendingIndexFinalization, ScanIndex, SnapshotItem};
use sha2::{Digest, Sha256};
use std::alloc::Layout;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Repeated borrowed traversal replaces the formerly unreserved opened Vec.
/// These are this page's opened inputs, never restored index fingerprints.
#[derive(Clone, Copy)]
pub(crate) struct OpenedFiles<'a> {
    pairs: &'a [(&'a str, &'a str)],
    pending: &'a [PendingIndexFinalization],
}
impl<'a> OpenedFiles<'a> {
    pub(in crate::snapshots) fn pairs(pairs: &'a [(&'a str, &'a str)]) -> Self {
        Self {
            pairs,
            pending: &[],
        }
    }
    pub(in crate::snapshots) fn pending(pending: &'a [PendingIndexFinalization]) -> Self {
        Self {
            pairs: &[],
            pending,
        }
    }
    pub(super) fn iter(self) -> impl Iterator<Item = (&'a str, &'a str)> + Clone {
        self.pairs.iter().copied().chain(
            self.pending
                .iter()
                .map(|p| (p.index_key.as_str(), p.source_file_fingerprint.as_str())),
        )
    }
    fn len(self) -> Option<usize> {
        self.pairs.len().checked_add(self.pending.len())
    }
}

#[derive(Default)]
enum Kind {
    #[default]
    Empty,
    Ordinary(BTreeSet<String>),
    Paid(Arc<PaidSet>),
    Refused,
}
struct PaidSet {
    ids: BTreeSet<String>,
    bytes: usize,
    // Last: ids retire before their reservation. Arc header is freed by the
    // wrapper's into_inner before this reservation can return to the pool.
    _reservation: CopyReservation,
}
/// Only this PRIVATE field's cloning changes: required clones share immutable
/// storage and its credit. Public disposition/Clone signatures stay unchanged.
#[derive(Default)]
pub(crate) struct WithheldSessions {
    kind: Kind,
}
impl Clone for WithheldSessions {
    fn clone(&self) -> Self {
        Self {
            kind: match &self.kind {
                Kind::Empty => Kind::Empty,
                Kind::Ordinary(ids) => Kind::Ordinary(ids.clone()),
                Kind::Paid(ids) => Kind::Paid(Arc::clone(ids)),
                Kind::Refused => Kind::Refused,
            },
        }
    }
}
impl Drop for WithheldSessions {
    fn drop(&mut self) {
        if let Kind::Paid(arc) = std::mem::take(&mut self.kind) {
            if let Some(paid) = Arc::into_inner(arc) {
                drop(paid);
            }
        }
    }
}
impl std::fmt::Debug for WithheldSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ensure_available().is_err() {
            return f.write_str("CopyPreparationResourceRefused");
        }
        std::fmt::Debug::fmt(&self.ids(), f)
    }
}
impl PartialEq for WithheldSessions {
    fn eq(&self, other: &Self) -> bool {
        match (&self.kind, &other.kind) {
            (Kind::Refused, Kind::Refused) => true,
            (Kind::Refused, _) | (_, Kind::Refused) => false,
            _ => (self.is_empty() && other.is_empty()) || self.ids() == other.ids(),
        }
    }
}
impl Eq for WithheldSessions {}
impl PartialEq<BTreeSet<String>> for WithheldSessions {
    fn eq(&self, other: &BTreeSet<String>) -> bool {
        self.ensure_available().is_ok()
            && ((self.is_empty() && other.is_empty()) || self.ids() == Some(other))
    }
}
impl From<BTreeSet<String>> for WithheldSessions {
    fn from(ids: BTreeSet<String>) -> Self {
        Self {
            kind: Kind::Ordinary(ids),
        }
    }
}
impl WithheldSessions {
    pub(super) fn refused() -> Self {
        Self {
            kind: Kind::Refused,
        }
    }
    fn ids(&self) -> Option<&BTreeSet<String>> {
        match &self.kind {
            Kind::Ordinary(ids) => Some(ids),
            Kind::Paid(paid) => Some(&paid.ids),
            Kind::Empty | Kind::Refused => None,
        }
    }
    pub(crate) fn ensure_available(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !matches!(self.kind, Kind::Refused),
            "copied-request preparation resource refused before offer"
        );
        Ok(())
    }
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.ids().is_some_and(|ids| ids.contains(id))
    }
    pub(crate) fn is_empty(&self) -> bool {
        // Refusal can never masquerade as settled/empty overlap evidence.
        !matches!(self.kind, Kind::Refused) && self.ids().map_or(true, BTreeSet::is_empty)
    }
    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        match &self.kind {
            Kind::Empty => c.add(0),
            Kind::Ordinary(ids) => ids.completed_heap_bound(c),
            Kind::Paid(paid) => c.add(paid.bytes),
            Kind::Refused => None,
        }
    }
}

pub(super) fn hash(domain: Option<&[u8]>, value: &str) -> [u8; 64] {
    let mut digest = Sha256::new();
    if let Some(domain) = domain {
        digest.update(domain);
        digest.update(b"\0");
    }
    digest.update(value.as_bytes());
    let mut result = [0; 64];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in digest.finalize().iter().enumerate() {
        result[2 * i] = HEX[usize::from(byte >> 4)];
        result[2 * i + 1] = HEX[usize::from(byte & 15)];
    }
    result
}
pub(in crate::snapshots) fn root(item: &SnapshotItem) -> &str {
    item.attribution_facts
        .iter()
        .find(|f| f.field == "root_session_ref")
        .map(|f| f.value.as_str())
        .or_else(|| {
            item.source_session_id
                .split_once("_agent-")
                .map(|(root, _)| root)
        })
        .unwrap_or(&item.source_session_id)
}
fn collector<K, V>(count: usize, c: &mut Counter) -> Option<()> {
    // Same pinned collector envelope as selective restore: covers insertion,
    // bulk/clone implementations, Vec staging and a coexisting split/root.
    c.add(
        count
            .max(48)
            .checked_mul(4)?
            .checked_mul(std::mem::size_of::<(K, V)>())?,
    )?;
    let mut nodes = Counter::new(LIMIT);
    heap_layout_bound::tree_nodes::<K, V>(count, &mut nodes)?;
    c.add(nodes.bytes.checked_mul(2)?)
}
fn metadata() -> Option<usize> {
    Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<PaidSet>())
        .ok()
        .map(|(l, _)| l.pad_to_align().size())
}
pub(super) struct Plan {
    pub(super) temporary: usize,
    pub(super) ledger: usize,
    pub(super) returned: usize,
}
impl Plan {
    /// No heap allocations or index writes. Exact semantics are still decided
    /// by the one existing native fold/producer. Repeated peer occurrences may
    /// overcharge; a refusal aborts this preparation, never permits an upload.
    pub(super) fn borrowed(
        index: &ScanIndex,
        items: &[SnapshotItem],
        opened: OpenedFiles<'_>,
    ) -> Option<Self> {
        let mut ledger = Counter::new(LIMIT);
        let mut returned = Counter::new(LIMIT);
        let mut files = Counter::new(LIMIT);
        let count = opened.len()?;
        collector::<&str, Vec<&str>>(count, &mut files)?;
        // Each per-revision Vec may start at four slots; doubling is bounded
        // by four slots per input, including repeated revisions.
        files.add(
            count
                .checked_mul(4)?
                .checked_mul(std::mem::size_of::<&str>())?,
        )?;
        let mut item_peak = 0usize;
        let mut new_keys = 0usize;
        let mut returned_insertions = 0usize;
        for item in items {
            let Some(revision) = item.source_file_fingerprint.as_deref() else {
                continue;
            };
            let keys = || {
                opened
                    .iter()
                    .filter(|(_, fp)| *fp == revision)
                    .map(|(key, _)| key)
            };
            if keys().next().is_none() {
                continue;
            }
            let held = keys().any(|key| index.claude_copy_holds.entries.contains_key(key));
            if index.active_copy_scan.is_none() {
                if held {
                    returned.add(item.source_session_id.len())?;
                    returned_insertions = returned_insertions.checked_add(1)?;
                }
                continue;
            }
            let own = hash(Some(b"claude_duplicate_source:v1"), &item.source_session_id);
            let own = std::str::from_utf8(&own).ok()?;
            let mut peers = 0usize;
            let mut peer_bytes = 0usize;
            for id in &item.claude_usage_request_ids {
                let digest = hash(None, id);
                let digest = std::str::from_utf8(&digest).ok()?;
                if let Some(owners) = index.claude_duplicate_request_owners.get(digest) {
                    for peer in owners.iter().filter(|o| o.source_session_id_hash != own) {
                        peers = peers.checked_add(1)?;
                        peer_bytes = peer_bytes.checked_add(peer.source_session_id_hash.len())?;
                    }
                }
            }
            let mut scratch = Counter::new(LIMIT);
            collector::<String, ()>(peers, &mut scratch)?;
            scratch.add(peer_bytes)?;
            // Owned family root, both owner hashes, current request digest,
            // plus the exclusion callback's simultaneous family-root clone.
            scratch.add(root(item).len().checked_mul(2)?.checked_add(192)?)?;
            item_peak = item_peak.max(scratch.bytes);
            if !held && peers == 0 {
                continue;
            }
            returned.add(item.source_session_id.len())?;
            returned_insertions = returned_insertions.checked_add(1)?;
            for key in keys() {
                let already_recorded = index.claude_copy_holds.entries.contains_key(key);
                // The existing record cap can conclusively prohibit any new
                // insertion. Keep its output/temporary costs, but do not charge
                // a nonexistent ledger write and unnecessarily block siblings.
                if !already_recorded
                    && index
                        .claude_copy_holds
                        .entries
                        .len()
                        .saturating_add(index.claude_account_deferred_holds.len())
                        >= crate::snapshots::MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
                {
                    continue;
                }
                // Old revision remains paid by the existing ledger until the
                // new 2x64 revision/context strings replace it. Clones below
                // copy exact len, not spare baseline String capacity.
                ledger.add(128)?;
                if !already_recorded {
                    ledger.add(key.len())?;
                    ledger.add(peer_bytes)?;
                    collector::<String, ()>(peers, &mut ledger)?;
                    new_keys = new_keys.checked_add(1)?;
                }
            }
        }
        prospective_nodes::<String, HeldFile>(
            index.claude_copy_holds.entries.len(),
            new_keys,
            &mut ledger,
        )?;
        prospective_nodes::<String, ()>(0, returned_insertions, &mut returned)?;
        returned.add(metadata()?)?;
        Some(Self {
            temporary: files.bytes.checked_add(item_peak)?,
            ledger: ledger.bytes,
            returned: returned.bytes,
        })
    }
}
impl ScanIndex {
    pub(in crate::snapshots) fn try_record_known_copy_holds(
        &mut self,
        items: &[SnapshotItem],
        opened: OpenedFiles<'_>,
        excluded: impl Fn(&SnapshotItem, &str) -> bool,
    ) -> WithheldSessions {
        if !self.copy_debt_budget.required() {
            return self.record_known_copy_holds(items, opened, excluded).into();
        }
        match self.record_paid_copy_holds(items, opened, excluded) {
            Ok(withheld) => withheld,
            Err(_) => WithheldSessions::refused(),
        }
    }
    fn record_paid_copy_holds(
        &mut self,
        items: &[SnapshotItem],
        opened: OpenedFiles<'_>,
        excluded: impl Fn(&SnapshotItem, &str) -> bool,
    ) -> Result<WithheldSessions, Unavailable> {
        // Real profile/paid owner first; no graph sizing can bless an unpaid
        // required Clone or run ahead of the unsupported-layout gate.
        let owner = self.required_copy_owner()?.ok_or(Unavailable)?.clone();
        let plan = Plan::borrowed(self, items, opened).ok_or(Unavailable)?;
        let temporary = owner
            .reserve_copy_bytes(plan.temporary)
            .ok_or(Unavailable)?;
        let returned = owner.reserve_copy_bytes(plan.returned).ok_or(Unavailable)?;
        self.copy_debt_budget.append(plan.ledger, 0)?;
        // No fallible branch remains after the first ledger mutation. Temporary
        // reservation outlives file-map/peer/root/hash/exclusion scratch. The
        // returned immutable set has its own credit independent of index drop.
        let ids = self.record_known_copy_holds(items, opened, excluded);
        let result = WithheldSessions {
            kind: Kind::Paid(Arc::new(PaidSet {
                ids,
                bytes: plan.returned,
                _reservation: returned,
            })),
        };
        drop(temporary);
        Ok(result)
    }
}
