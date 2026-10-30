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
    /// child is never selected again by this latch.
    pub(super) fn desktop_identity_reoffer(
        &self,
        candidate: &CandidateFile,
        metadata: &ClaudeTitleMetadata,
    ) -> Option<IdentityReoffer> {
        if claude_subagent_identity(&candidate.path).is_some() {
            return None;
        }
        let session = candidate.path.file_stem()?.to_str()?;
        let key = local_index_key(&candidate.path);
        let entry = self.files.get(&key)?;
        if entry.last_snapshot_fingerprint.is_none()
            || entry.source_file_fingerprint != candidate.source_file_fingerprint
            || self.decode_holds_file(&key)
            || self.terminal_jsonl_dispositions.contains_key(&key)
            || self.claude_reemission_excluded(candidate)
            || claude_index_path_family_member(&candidate.path)
                .is_some_and(|(root, _)| self.claude_usage_authority_quarantine.contains_key(&root))
            || metadata
                .session_account_evidence(session)
                .identity_disposition
                != Some("complete")
        {
            return None;
        }
        match self.claude_desktop_identity_latches.get(&key) {
            Some(IdentityLatch::Settled) => None,
            Some(IdentityLatch::Pending) => Some(IdentityReoffer::Recovered),
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
    /// keys. Lead B: a re-offer settles whether posted, unchanged or refused;
    /// only an unsettled upload (transport failure, partial save) retries.
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
        let next = if let Some((kind, bytes)) = pending.desktop_identity_reoffer {
            use crate::local_resource_diagnostics::claude_reread::IdentityReoffered;
            let outcome = if emitted != Some("complete") {
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
            Some(IdentityLatch::Settled)
        } else {
            match emitted {
                // After the creation-proof, ownership and request downgrades.
                Some("complete") => Some(IdentityLatch::Settled),
                // E1: a downgrade of an already complete own disposition is
                // not census-caused; a re-offer would emit the same body.
                Some(_) if pair && pending.desktop_identity_resolved => {
                    Some(IdentityLatch::Settled)
                }
                // Only a Desktop child carrying its own pair can later
                // resolve complete from the same metadata; other Claude
                // sessions never enter the map.
                Some("missing")
                    if pair
                        && self.claude_desktop_identity_latches.get(&pending.index_key)
                            != Some(&IdentityLatch::Settled) =>
                {
                    Some(IdentityLatch::Pending)
                }
                _ => None,
            }
        };
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
