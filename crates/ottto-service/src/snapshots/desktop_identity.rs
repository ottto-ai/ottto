//! Per-child Desktop identity re-offer latch (SOURCE Addenda 7+8, E1 design,
//! Lead B 2026-10-30). Class L, root metadata keyed by the local file index
//! key (that key keeps its own class). The value is a closed state only: no
//! account, identity digest or money. Selection history, never owner,
//! account, request, ACK or money authority: live evidence alone is emitted.
use super::desktop_lineage::{
    committable_selector, insert_selector, selector_admits, selector_bytes, EDGE_RECORD_BYTES,
    MAX_EDGES,
};
use super::*;
use serde::de::{MapAccess, Visitor};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum IdentityLatch {
    /// This child's own disposition was missing at a stored-body ACK.
    #[serde(rename = "identity_pending")]
    Pending,
    /// A complete disposition, or a re-offer, settled at a stored-body ACK.
    #[serde(rename = "settled")]
    Settled,
}
impl crate::heap_layout_bound::HeapLayoutBound for IdentityLatch {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
// Quotes, colon, the widest value ("identity_pending" quoted) and a comma.
const LATCH_RECORD_BYTES: usize = 2 + 1 + 18 + 1;

/// E1 option (A): a refused attempt is RAM history, never a persisted value.
/// Keyed by SHA-256 of the file key, so the bound is fixed and no path is held.
/// An eviction or a new process costs at most one more counted refused re-offer.
/// Selection history only: never authority, never a payload input.
const REFUSED_MEMO_CAP: usize = MAX_EDGES;
struct BoundedMemo<V> {
    values: BTreeMap<[u8; 32], V>,
    order: VecDeque<[u8; 32]>,
    cap: usize,
}
impl<V> BoundedMemo<V> {
    const fn new(cap: usize) -> Self {
        Self {
            values: BTreeMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }
    /// True when the cap evicted the oldest entry.
    fn record(&mut self, key: [u8; 32], value: V) -> bool {
        if self.values.insert(key, value).is_none() {
            self.order.push_back(key);
        }
        if self.order.len() <= self.cap {
            return false;
        }
        if let Some(oldest) = self.order.pop_front() {
            self.values.remove(&oldest);
        }
        true
    }
    fn take(&mut self, key: &[u8; 32]) -> Option<V> {
        let value = self.values.remove(key)?;
        self.order.retain(|entry| entry != key);
        Some(value)
    }
}
impl BoundedMemo<[u8; 32]> {
    fn holds(&self, key: &[u8; 32], evidence: &[u8; 32]) -> bool {
        self.values.get(key) == Some(evidence)
    }
}
/// `posted` holds a re-offer on its way to the backend, keyed by SHA-256 of
/// its body's fingerprint, until a response names that body. An eviction or a
/// new process loses at most that count. `unstored` maps a fingerprint to the
/// exact body answered unchanged with nothing stored, which leaves no ACK in
/// the upload ledger.
struct ReofferMemos {
    refused: BoundedMemo<[u8; 32]>,
    posted: BoundedMemo<(IdentityReoffer, u64)>,
    unstored: BoundedMemo<[u8; 32]>,
}
impl ReofferMemos {
    const fn new() -> Self {
        Self {
            refused: BoundedMemo::new(REFUSED_MEMO_CAP),
            posted: BoundedMemo::new(REFUSED_MEMO_CAP),
            unstored: BoundedMemo::new(REFUSED_MEMO_CAP),
        }
    }
}
#[cfg(not(test))]
static REOFFER_MEMOS: std::sync::Mutex<ReofferMemos> = std::sync::Mutex::new(ReofferMemos::new());
#[cfg(test)]
thread_local! {
    static REOFFER_MEMOS: std::cell::RefCell<ReofferMemos> =
        const { std::cell::RefCell::new(ReofferMemos::new()) };
}
/// A leaf lock: `run` never takes another lock or re-enters.
fn with_reoffer_memos<T>(run: impl FnOnce(&mut ReofferMemos) -> T) -> T {
    #[cfg(not(test))]
    {
        run(&mut REOFFER_MEMOS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    #[cfg(test)]
    REOFFER_MEMOS.with(|memos| run(&mut memos.borrow_mut()))
}
fn memo_key(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}
fn remember_refused(key: &str, evidence: [u8; 32]) {
    if with_reoffer_memos(|memos| memos.refused.record(memo_key(key), evidence)) {
        crate::local_resource_diagnostics::claude_reread::desktop_identity_reoffer_memo_evicted();
    }
}
/// A new process: the memos are RAM only.
#[cfg(test)]
pub(super) fn reset_refused_memo_for_test() {
    with_reoffer_memos(|memos| *memos = ReofferMemos::new());
}
/// Real cap eviction of everything older, then `extra` more.
#[cfg(test)]
pub(super) fn fill_refused_memo_for_test(extra: usize) {
    for n in 0..REFUSED_MEMO_CAP + extra {
        remember_refused(&format!("/synthetic/memo/{n}"), [0; 32]);
    }
}
/// Evidence no live digest can match, on an unchanged source fingerprint.
#[cfg(test)]
pub(super) fn remember_other_evidence_for_test(key: &str) {
    remember_refused(key, [7; 32]);
}

/// Digest of the child's own live evidence, only while it resolves complete.
/// The source fingerprint carries what a downgrade reads besides the Desktop
/// carrier (transcript and sidecar revision), so a changed cause is a new digest.
pub(super) fn identity_evidence(
    metadata: &ClaudeTitleMetadata,
    path: &Path,
    source_file_fingerprint: &str,
) -> Option<[u8; 32]> {
    let evidence = metadata.session_account_evidence(path.file_stem()?.to_str()?);
    (evidence.identity_disposition == Some("complete")).then(|| {
        let mut digest = Sha256::new();
        for part in [
            Some(source_file_fingerprint),
            evidence.account_identifier_hash.as_deref(),
            evidence.provider_workspace_hash.as_deref(),
            evidence.source_created_at.as_deref(),
        ] {
            let part = part.unwrap_or_default().as_bytes();
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        digest.finalize().into()
    })
}

/// Which latch state selected an unchanged child's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdentityReoffer {
    /// Pending → the child's own disposition now resolves complete.
    Recovered,
    /// No entry (legacy, old-reader loss or decode damage): adopt once.
    Adoption,
}
impl crate::heap_layout_bound::HeapLayoutBound for IdentityReoffer {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Default, Deserialize)]
pub(super) struct IdentityLatches(
    #[serde(deserialize_with = "deserialize_identity_latches")]
    pub(super)  BTreeMap<String, IdentityLatch>,
);

pub(super) fn deserialize_identity_latches<'de, D>(
    d: D,
) -> std::result::Result<BTreeMap<String, IdentityLatch>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Latches;
    impl<'de> Visitor<'de> for Latches {
        type Value = BTreeMap<String, IdentityLatch>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded closed-state Desktop identity latches")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut a: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut latches = BTreeMap::new();
            while let Some((key, latch)) = a.next_entry::<String, IdentityLatch>()? {
                if latches.len() >= MAX_EDGES
                    || key.len() > 8192
                    || latches.insert(key, latch).is_some()
                {
                    return Err(serde::de::Error::custom("invalid Desktop identity latch"));
                }
            }
            Ok(latches)
        }
    }
    d.deserialize_map(Latches)
}

/// Compact bytes this map occupies in the joint selector budget. An empty map
/// is omitted from the root, so it costs nothing.
pub(super) fn latch_bytes(latches: &BTreeMap<String, IdentityLatch>) -> usize {
    if latches.is_empty() {
        0
    } else {
        selector_bytes(latches, LATCH_RECORD_BYTES)
    }
}
fn edge_bytes(edges: &BTreeMap<String, String>) -> usize {
    if edges.is_empty() {
        0
    } else {
        selector_bytes(edges, EDGE_RECORD_BYTES)
    }
}

/// Counts each posted re-offer from the backend's per-entity lists, once. Never
/// from `response.accepted`, which sums accepted and unchanged. A conflict
/// settles with the upload ledger; a count-only ACK names no entity and counts
/// nothing.
pub(crate) fn classify_desktop_identity_reoffers(
    sent: &[SnapshotItem],
    response: &crate::snapshot_client::SnapshotBatchResponse,
) {
    use crate::local_resource_diagnostics::claude_reread::{
        desktop_identity_reoffer, IdentityReoffered,
    };
    let accepted = response
        .accepted_entities
        .iter()
        .map(|entity| (&entity.snapshot_fingerprint, IdentityReoffered::Posted));
    let unchanged = response
        .unchanged_entities
        .iter()
        .map(|entity| (&entity.snapshot_fingerprint, IdentityReoffered::Unchanged));
    let rejected = response
        .rejected_entities
        .iter()
        .map(|entity| (&entity.snapshot_fingerprint, IdentityReoffered::Refused));
    for (fingerprint, outcome) in accepted.chain(unchanged).chain(rejected) {
        let key = memo_key(fingerprint);
        if let Some((kind, bytes)) = with_reoffer_memos(|memos| memos.posted.take(&key)) {
            desktop_identity_reoffer(kind == IdentityReoffer::Adoption, outcome, bytes);
        }
    }
    let unstored = response
        .unchanged_entities
        .iter()
        .filter(|entity| entity.unchanged_basis.is_some());
    for entity in unstored {
        let body = sent
            .iter()
            .find(|item| item.snapshot_fingerprint == entity.snapshot_fingerprint);
        if let Some(body) = body {
            let key = memo_key(&entity.snapshot_fingerprint);
            let witness = memo_key(&snapshot_upload_body_witness(body));
            with_reoffer_memos(|memos| memos.unstored.record(key, witness));
        }
    }
}

fn own_bodies<'a>(
    items: &'a [SnapshotItem],
    source_file_fingerprint: &'a str,
    session: &'a str,
) -> impl Iterator<Item = &'a SnapshotItem> {
    items.iter().filter(move |item| {
        item.source_file_fingerprint.as_deref() == Some(source_file_fingerprint)
            && item.source_session_id == session
    })
}

/// The child's own emitted disposition across its bodies in this file:
/// complete only when every own body says complete; None without a body.
/// `pair` is whether every body carried this child's own account and org.
fn emitted_disposition(
    items: &[SnapshotItem],
    source_file_fingerprint: &str,
    session: &str,
) -> (Option<&'static str>, bool) {
    let mut disposition = None;
    let mut pair = true;
    for item in own_bodies(items, source_file_fingerprint, session) {
        let evidence = item
            .session_account_evidence
            .as_ref()
            .filter(|evidence| evidence.provider == "anthropic");
        pair &= evidence.is_some_and(|evidence| {
            evidence.account_identifier_hash.is_some() && evidence.provider_workspace_hash.is_some()
        });
        disposition = match (disposition, evidence.and_then(|e| e.identity_disposition)) {
            (Some("missing"), _) | (_, Some("missing")) => Some("missing"),
            (Some("conflict"), _) | (_, Some("conflict")) | (_, None) => Some("conflict"),
            (None | Some("complete"), Some("complete")) => Some("complete"),
            (_, Some(_)) => Some("conflict"),
        };
    }
    (disposition, pair)
}

fn emitted_complete(pending: &PendingIndexFinalization, items: &[SnapshotItem]) -> bool {
    let session = Path::new(&pending.index_key)
        .file_stem()
        .and_then(|value| value.to_str());
    session.is_some_and(|session| {
        emitted_disposition(items, &pending.source_file_fingerprint, session).0 == Some("complete")
    })
}

/// A pending child has no ACK for its complete body, even when the working
/// entry already names that body: its fingerprint can outlive the missing one
/// in the upload ledger, so an unACKed upload can advance the entry. The
/// backend answers an exact repeat with unchanged.
pub(super) fn recovery_must_send(
    pending: &PendingIndexFinalization,
    items: &[SnapshotItem],
) -> bool {
    matches!(
        pending.desktop_identity_reoffer,
        Some((IdentityReoffer::Recovered, _))
    ) && emitted_complete(pending, items)
}

impl ScanIndex {
    /// An unchanged Desktop child with a stored body whose OWN live
    /// disposition resolves complete and which has not settled. Census
    /// flaps resolve missing here and select nothing. One-way: a settled
    /// child is never selected again by this latch. Refused evidence is not
    /// offered twice in one process; only a changed digest is new.
    pub(super) fn desktop_identity_reoffer(
        &self,
        candidate: &CandidateFile,
        metadata: &ClaudeTitleMetadata,
    ) -> Option<IdentityReoffer> {
        if claude_subagent_identity(&candidate.path).is_some() {
            return None;
        }
        let key = local_index_key(&candidate.path);
        let latch = self.claude_desktop_identity_latches.get(&key);
        if latch == Some(&IdentityLatch::Settled) {
            return None;
        }
        let entry = self.files.get(&key)?;
        if entry.last_snapshot_fingerprint.is_none()
            || entry.source_file_fingerprint != candidate.source_file_fingerprint
            || self.decode_holds_file(&key)
            || self.terminal_jsonl_dispositions.contains_key(&key)
            || self.claude_reemission_excluded(candidate)
            || claude_index_path_family_member(&candidate.path)
                .is_some_and(|(root, _)| self.claude_usage_authority_quarantine.contains_key(&root))
        {
            return None;
        }
        let evidence = identity_evidence(
            metadata,
            &candidate.path,
            &candidate.source_file_fingerprint,
        )?;
        if with_reoffer_memos(|memos| memos.refused.holds(&memo_key(&key), &evidence)) {
            return None;
        }
        match latch {
            Some(_) => Some(IdentityReoffer::Recovered),
            // A full joint budget could not record the settlement: never select.
            None => selector_admits(
                &self.claude_desktop_identity_latches,
                LATCH_RECORD_BYTES,
                edge_bytes(&self.claude_desktop_lineage_file_edges),
                &key,
            )
            .then_some(IdentityReoffer::Adoption),
        }
    }

    /// Working-index update at finalization, committed only for ACK-settled
    /// keys. The latch settles on a complete emission only (E1), and a sent
    /// re-offer settles only in `settle_desktop_identity_reoffers`. A refused
    /// attempt or a natural downgrade of an already complete own disposition
    /// goes to the RAM memo, so the same evidence is not offered again and a
    /// later complete disposition still recovers. An unsettled upload retries.
    pub(super) fn note_desktop_identity_emission(
        &mut self,
        pending: &PendingIndexFinalization,
        items: &[SnapshotItem],
        unchanged: bool,
        carried: &BTreeSet<String>,
    ) {
        let path = Path::new(&pending.index_key);
        if claude_subagent_identity(path).is_some() {
            return;
        }
        let Some(session) = path.file_stem().and_then(|value| value.to_str()) else {
            return;
        };
        let (emitted, pair) = emitted_disposition(items, &pending.source_file_fingerprint, session);
        let complete = emitted == Some("complete");
        let next = if let Some((kind, bytes)) = pending.desktop_identity_reoffer {
            use crate::local_resource_diagnostics::claude_reread::IdentityReoffered;
            let body = own_bodies(items, &pending.source_file_fingerprint, session)
                .next()
                .map(|item| item.snapshot_fingerprint.as_str());
            // Only a body that is not sent has a local outcome. A sent body
            // waits for the backend's lists: its first body stands for it.
            let local = if !complete {
                Some(IdentityReoffered::Refused)
            } else if unchanged || body.is_some_and(|body| carried.contains(body)) {
                Some(IdentityReoffered::Unchanged)
            } else {
                None
            };
            match (local, body) {
                (Some(outcome), _) => {
                    crate::local_resource_diagnostics::claude_reread::desktop_identity_reoffer(
                        kind == IdentityReoffer::Adoption,
                        outcome,
                        bytes,
                    );
                }
                (None, Some(body)) => with_reoffer_memos(|memos| {
                    memos.posted.record(memo_key(body), (kind, bytes));
                }),
                (None, None) => {}
            }
            if complete && unchanged {
                Some(IdentityLatch::Settled)
            } else if local.is_none() && kind == IdentityReoffer::Adoption {
                // If an unACKed upload advances the entry, the retry must send.
                Some(IdentityLatch::Pending)
            } else {
                None
            }
        } else {
            match emitted {
                // A pending child settles only on this body's own ACK.
                Some("complete")
                    if self.claude_desktop_identity_latches.get(&pending.index_key)
                        == Some(&IdentityLatch::Pending) =>
                {
                    None
                }
                // After the creation-proof, ownership and request downgrades.
                Some("complete") => Some(IdentityLatch::Settled),
                // Only a Desktop child carrying its own pair can later
                // resolve complete from the same metadata; other Claude
                // sessions never enter the map. A downgrade of a resolved
                // disposition is not census-caused: no latch (E1).
                Some("missing")
                    if pair
                        && pending.desktop_identity_evidence.is_none()
                        && self.claude_desktop_identity_latches.get(&pending.index_key)
                            != Some(&IdentityLatch::Settled) =>
                {
                    Some(IdentityLatch::Pending)
                }
                _ => None,
            }
        };
        if !complete && (emitted.is_some() || pending.desktop_identity_reoffer.is_some()) {
            if let Some(evidence) = pending.desktop_identity_evidence {
                remember_refused(&pending.index_key, evidence);
            }
        }
        if let Some(latch) = next {
            self.record_desktop_identity_latch(&pending.index_key, latch);
        }
    }

    /// The only way a sent body settles: every own body is ACKed with these
    /// exact bytes, never by a fingerprint an older body left in the ledger.
    /// A body the upload holds in quarantine got a verdict that is no ACK, so
    /// it stays pending and its evidence is not offered again in this process.
    /// Anything else (no response, no attempt) retries.
    pub(crate) fn settle_desktop_identity_reoffers(
        &mut self,
        scan: &SourceScanResult,
        accepted_bodies: &BTreeMap<String, String>,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) {
        for pending in &scan.pending_finalization {
            let latch = self.claude_desktop_identity_latches.get(&pending.index_key);
            if latch == Some(&IdentityLatch::Settled)
                || (pending.desktop_identity_reoffer.is_none()
                    && latch != Some(&IdentityLatch::Pending))
                || !emitted_complete(pending, &scan.snapshots)
            {
                continue;
            }
            let Some(session) = Path::new(&pending.index_key)
                .file_stem()
                .and_then(|value| value.to_str())
            else {
                continue;
            };
            let own = own_bodies(&scan.snapshots, &pending.source_file_fingerprint, session)
                .map(|item| {
                    (
                        &item.snapshot_fingerprint,
                        snapshot_upload_body_witness(item),
                    )
                })
                .collect::<Vec<_>>();
            if own.iter().all(|(fingerprint, witness)| {
                accepted_bodies.get(*fingerprint) == Some(witness)
                    || with_reoffer_memos(|memos| {
                        memos
                            .unstored
                            .holds(&memo_key(fingerprint), &memo_key(witness))
                    })
            }) {
                self.record_desktop_identity_latch(&pending.index_key, IdentityLatch::Settled);
                continue;
            }
            let held = own.iter().find(|(fingerprint, witness)| {
                quarantined.get(*fingerprint).is_some_and(|record| {
                    record.upload_body_witness.as_deref() == Some(witness.as_str())
                })
            });
            let Some((fingerprint, _)) = held else {
                continue;
            };
            let key = memo_key(fingerprint);
            if let Some((kind, bytes)) = with_reoffer_memos(|memos| memos.posted.take(&key)) {
                crate::local_resource_diagnostics::claude_reread::desktop_identity_reoffer(
                    kind == IdentityReoffer::Adoption,
                    crate::local_resource_diagnostics::claude_reread::IdentityReoffered::Refused,
                    bytes,
                );
            }
            if let Some(evidence) = pending.desktop_identity_evidence {
                remember_refused(&pending.index_key, evidence);
            }
        }
    }

    pub(super) fn record_desktop_identity_latch(&mut self, key: &str, latch: IdentityLatch) {
        if self.claude_desktop_identity_latches.get(key) == Some(&latch) {
            return;
        }
        // Erasure follows the file entry, as for the lineage baselines.
        self.claude_desktop_identity_latches
            .retain(|key, _| self.files.contains_key(key));
        let others = edge_bytes(&self.claude_desktop_lineage_file_edges);
        insert_selector(
            &mut self.claude_desktop_identity_latches,
            LATCH_RECORD_BYTES,
            others,
            key,
            latch,
        );
    }
}

/// Committed after the lineage baselines, against their committed size, so
/// both maps stay inside one decode-span budget.
pub(super) fn committable_identity_latches(
    working: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
    committed_edges: &BTreeMap<String, String>,
) -> BTreeMap<String, IdentityLatch> {
    committable_selector(
        &working.claude_desktop_identity_latches,
        &previous.claude_desktop_identity_latches,
        safe,
        LATCH_RECORD_BYTES,
        edge_bytes(committed_edges),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_identity_refused_memo_is_keyed_by_evidence_and_evicts_oldest_first() {
        let (first, second, third) = ([1; 32], [2; 32], [3; 32]);
        let (evidence, changed) = ([8; 32], [9; 32]);
        let mut memo = BoundedMemo::new(2);
        memo.record(first, evidence);
        assert!(memo.holds(&first, &evidence));
        assert!(!memo.holds(&first, &changed), "new evidence is a new offer");
        memo.record(first, changed);
        assert!(memo.holds(&first, &changed));
        assert_eq!(memo.order.len(), 1, "same child, one slot");
        memo.record(second, evidence);
        memo.record(third, evidence);
        assert_eq!((memo.values.len(), memo.order.len()), (2, 2));
        assert!(!memo.holds(&first, &changed), "the oldest child is evicted");
        assert!(memo.holds(&second, &evidence) && memo.holds(&third, &evidence));
        assert_eq!(memo.take(&second), Some(evidence));
        assert_eq!(memo.take(&second), None, "taken once");
        assert_eq!((memo.values.len(), memo.order.len()), (1, 1));
    }
}
