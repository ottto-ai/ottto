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
struct RefusedMemo {
    evidence: BTreeMap<[u8; 32], [u8; 32]>,
    order: VecDeque<[u8; 32]>,
    cap: usize,
}
impl RefusedMemo {
    const fn new(cap: usize) -> Self {
        Self {
            evidence: BTreeMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }
    fn holds(&self, key: &[u8; 32], evidence: &[u8; 32]) -> bool {
        self.evidence.get(key) == Some(evidence)
    }
    fn record(&mut self, key: [u8; 32], evidence: [u8; 32]) {
        if self.evidence.insert(key, evidence).is_none() {
            self.order.push_back(key);
        }
        if self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.evidence.remove(&oldest);
            }
        }
    }
}
#[cfg(not(test))]
static REFUSED_MEMO: std::sync::Mutex<RefusedMemo> =
    std::sync::Mutex::new(RefusedMemo::new(REFUSED_MEMO_CAP));
#[cfg(test)]
thread_local! {
    static REFUSED_MEMO: std::cell::RefCell<RefusedMemo> =
        const { std::cell::RefCell::new(RefusedMemo::new(REFUSED_MEMO_CAP)) };
}
/// A leaf lock: `run` never takes another lock or re-enters.
fn with_refused_memo<T>(run: impl FnOnce(&mut RefusedMemo) -> T) -> T {
    #[cfg(not(test))]
    {
        run(&mut REFUSED_MEMO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    #[cfg(test)]
    REFUSED_MEMO.with(|memo| run(&mut memo.borrow_mut()))
}
fn memo_key(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}
fn remember_refused(key: &str, evidence: [u8; 32]) {
    with_refused_memo(|memo| memo.record(memo_key(key), evidence));
}
/// A new process: the memo is RAM only.
#[cfg(test)]
pub(super) fn reset_refused_memo_for_test() {
    with_refused_memo(|memo| *memo = RefusedMemo::new(REFUSED_MEMO_CAP));
}
/// Real cap eviction of everything older.
#[cfg(test)]
pub(super) fn fill_refused_memo_for_test() {
    for n in 0..REFUSED_MEMO_CAP {
        remember_refused(&format!("/synthetic/memo/{n}"), [0; 32]);
    }
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

/// The child's own emitted disposition across its bodies in this file:
/// complete only when every own body says complete; None without a body.
/// `pair` is whether every body carried this child's own account and org.
fn emitted_disposition(
    items: &[SnapshotItem],
    source_file_fingerprint: &str,
    session: &str,
) -> (Option<&'static str>, bool) {
    let own = items.iter().filter(|item| {
        item.source_file_fingerprint.as_deref() == Some(source_file_fingerprint)
            && item.source_session_id == session
    });
    let mut disposition = None;
    let mut pair = true;
    for item in own {
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
        if with_refused_memo(|memo| memo.holds(&memo_key(&key), &evidence)) {
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
    /// keys. The latch settles on a complete emission only (E1). A refused
    /// attempt or a natural downgrade of an already complete own disposition
    /// goes to the RAM memo, so the same evidence is not offered again and a
    /// later complete disposition still recovers. An unsettled upload retries.
    pub(super) fn note_desktop_identity_emission(
        &mut self,
        pending: &PendingIndexFinalization,
        items: &[SnapshotItem],
        unchanged: bool,
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
            let outcome = if !complete {
                IdentityReoffered::Refused
            } else if unchanged {
                IdentityReoffered::Unchanged
            } else {
                IdentityReoffered::Posted
            };
            crate::local_resource_diagnostics::claude_reread::desktop_identity_reoffer(
                kind == IdentityReoffer::Adoption,
                outcome,
                bytes,
            );
            complete.then_some(IdentityLatch::Settled)
        } else {
            match emitted {
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
        let mut memo = RefusedMemo::new(2);
        memo.record(first, evidence);
        assert!(memo.holds(&first, &evidence));
        assert!(!memo.holds(&first, &changed), "new evidence is a new offer");
        memo.record(first, changed);
        assert!(memo.holds(&first, &changed));
        assert_eq!(memo.order.len(), 1, "same child, one slot");
        memo.record(second, evidence);
        memo.record(third, evidence);
        assert_eq!((memo.evidence.len(), memo.order.len()), (2, 2));
        assert!(!memo.holds(&first, &changed), "the oldest child is evicted");
        assert!(memo.holds(&second, &evidence) && memo.holds(&third, &evidence));
    }
}
