//! Per-child Desktop identity re-offer latch (SOURCE Addenda 7+8, E1 design,
//! Lead B 2026-10-30). Class L, root metadata keyed by the local file index
//! key (that key keeps its own class). The value is a closed state (class N),
//! plus, for a refusal only, an 8-byte digest of the child's own evidence
//! (class H, SOURCE 2026-10-31): no account or money. Selection history, never
//! owner, account, request, ACK or money authority, never uploaded or logged:
//! live evidence alone is emitted.
use super::desktop_lineage::{
    committable_selector, insert_selector, selector_admits, selector_bytes, EDGE_RECORD_BYTES,
    MAX_EDGES,
};
use super::*;
use crate::local_resource_diagnostics::claude_reread::{
    desktop_identity_reoffer as count_reoffer, IdentityReoffered,
};
use serde::de::{MapAccess, Visitor};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdentityLatch {
    /// This child's own disposition was missing at a stored-body ACK.
    Pending,
    /// This destination ACKed the exact complete body.
    Settled,
    /// The child's own evidence with this digest emitted no complete body (a
    /// refusal or a natural downgrade), or its re-offer sent nothing new. Only
    /// a changed digest selects it again (Ron: content-only re-reads).
    Refused(EvidenceDigest),
}
/// The first 8 bytes of SHA-256 over the child's own evidence. Local only.
pub(super) type EvidenceDigest = u64;
const PENDING: &str = "identity_pending";
const SETTLED: &str = "settled";
const REFUSED: &str = "refused:";
impl IdentityLatch {
    fn parse(value: &str) -> Option<Self> {
        match value {
            PENDING => Some(Self::Pending),
            SETTLED => Some(Self::Settled),
            _ => {
                // Exactly the 16 lowercase hex digits this writer emits.
                let digest = value.strip_prefix(REFUSED)?;
                let lower_hex = digest.len() == 16
                    && digest
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                lower_hex
                    .then(|| u64::from_str_radix(digest, 16).ok())
                    .flatten()
                    .map(Self::Refused)
            }
        }
    }
}
// Every value is one JSON string. Released 0.1.205 never reads this map: its
// decoder skips root keys outside its FIELDS list (lenient_decode.rs:1597-1608
// at 562a40128) and `ScanIndex` has no deny_unknown_fields (snapshots.rs:3438),
// so a downgrade drops the map and later sees legacy (no entry) children.
impl Serialize for IdentityLatch {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Pending => s.serialize_str(PENDING),
            Self::Settled => s.serialize_str(SETTLED),
            Self::Refused(digest) => s.serialize_str(&format!("{REFUSED}{digest:016x}")),
        }
    }
}
impl<'de> Deserialize<'de> for IdentityLatch {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Latch;
        impl Visitor<'_> for Latch {
            type Value = IdentityLatch;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a Desktop identity latch")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                IdentityLatch::parse(value)
                    .ok_or_else(|| E::custom("invalid Desktop identity latch"))
            }
        }
        d.deserialize_str(Latch)
    }
}
// Inline only: the digest is a u64, so the map's heap is its keys and nodes,
// already counted under `claude_desktop_identity_latches` in ScanIndex.
impl crate::heap_layout_bound::HeapLayoutBound for IdentityLatch {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
// Quotes, colon, the widest value ("refused:" and 16 hex digits, quoted) and a
// comma. Every record is charged this width, so a value change never grows it.
const LATCH_RECORD_BYTES: usize = 2 + 1 + (2 + REFUSED.len() + 16) + 1;

/// `posted` holds a re-offer on its way to the backend, keyed by SHA-256 of
/// its body's fingerprint, until a response names that body. An eviction or a
/// new process loses at most that count. Counts only: never a selection input,
/// and ACK evidence never lives here (an unstored verdict belongs only to the
/// validated upload invocation).
const POSTED_MEMO_CAP: usize = MAX_EDGES;
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
    fn record(&mut self, key: [u8; 32], value: V) {
        if self.values.insert(key, value).is_none() {
            self.order.push_back(key);
        }
        if self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.values.remove(&oldest);
            }
        }
    }
    fn take(&mut self, key: &[u8; 32]) -> Option<V> {
        let value = self.values.remove(key)?;
        self.order.retain(|entry| entry != key);
        Some(value)
    }
}
type PostedMemo = BoundedMemo<(IdentityReoffer, u64)>;
#[cfg(not(test))]
static POSTED: std::sync::Mutex<PostedMemo> =
    std::sync::Mutex::new(BoundedMemo::new(POSTED_MEMO_CAP));
#[cfg(test)]
thread_local! {
    static POSTED: std::cell::RefCell<PostedMemo> =
        const { std::cell::RefCell::new(BoundedMemo::new(POSTED_MEMO_CAP)) };
}
/// A leaf lock: `run` never takes another lock or re-enters.
fn with_posted<T>(run: impl FnOnce(&mut PostedMemo) -> T) -> T {
    #[cfg(not(test))]
    {
        run(&mut POSTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    #[cfg(test)]
    POSTED.with(|memo| run(&mut memo.borrow_mut()))
}
fn memo_key(fingerprint: &str) -> [u8; 32] {
    Sha256::digest(fingerprint.as_bytes()).into()
}
fn count(kind: IdentityReoffer, outcome: IdentityReoffered, bytes: u64) {
    count_reoffer(kind == IdentityReoffer::Adoption, outcome, bytes);
}
/// Counts a posted re-offer once, when a verdict first names its body.
fn count_posted(fingerprint: &str, outcome: IdentityReoffered) {
    if let Some((kind, bytes)) = with_posted(|memo| memo.take(&memo_key(fingerprint))) {
        count(kind, outcome, bytes);
    }
}

/// The session a file key names, from its file name.
fn own_session(path: &Path) -> Option<&str> {
    path.file_stem()?.to_str()
}

/// Digest of the child's own live evidence, only while it resolves complete.
/// The source fingerprint carries what a downgrade reads besides the Desktop
/// carrier (transcript and sidecar revision), so a changed cause is a new digest.
pub(super) fn identity_evidence(
    source: SnapshotSource,
    metadata: &ClaudeTitleMetadata,
    path: &Path,
    source_file_fingerprint: &str,
) -> Option<EvidenceDigest> {
    if source != SnapshotSource::ClaudeCode {
        return None;
    }
    let evidence = metadata.session_account_evidence(own_session(path)?);
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
        let mut head = [0; 8];
        head.copy_from_slice(&digest.finalize()[..8]);
        u64::from_be_bytes(head)
    })
}

/// Which latch state selected an unchanged child's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdentityReoffer {
    /// Pending (or Refused at an older digest) → the child's own disposition
    /// now resolves complete.
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
/// Returns exact unstored ACK witnesses for the caller's validated upload
/// invocation only; never reuse this map for another destination or replay.
pub(crate) fn classify_desktop_identity_reoffers(
    sent: &[SnapshotItem],
    response: &crate::snapshot_client::SnapshotBatchResponse,
) -> BTreeMap<String, String> {
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
        count_posted(fingerprint, outcome);
    }
    let unstored = response
        .unchanged_entities
        .iter()
        .filter(|entity| entity.unchanged_basis.is_some());
    let mut unstored_bodies = BTreeMap::new();
    for entity in unstored {
        let body = sent
            .iter()
            .find(|item| item.snapshot_fingerprint == entity.snapshot_fingerprint);
        if let Some(body) = body {
            unstored_bodies.insert(
                entity.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(body),
            );
        }
    }
    unstored_bodies
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
    own_session(Path::new(&pending.index_key)).is_some_and(|session| {
        emitted_disposition(items, &pending.source_file_fingerprint, session).0 == Some("complete")
    })
}

/// An unsettled child has no ACK for its complete body, even when the working
/// entry already names that body: its fingerprint can outlive the missing one
/// in the upload ledger, so an unACKed upload can advance the entry. The
/// backend answers an exact repeat with unchanged.
pub(super) fn recovery_must_send(
    index: &ScanIndex,
    pending: &PendingIndexFinalization,
    items: &[SnapshotItem],
) -> bool {
    !index.desktop_identity_settled(&pending.index_key)
        && !matches!(
            pending.desktop_identity_reoffer,
            Some((IdentityReoffer::Adoption, _))
        )
        && emitted_complete(pending, items)
}

impl ScanIndex {
    fn desktop_identity_settled(&self, key: &str) -> bool {
        self.claude_desktop_identity_latches.get(key) == Some(&IdentityLatch::Settled)
    }

    /// An unchanged Desktop child with a stored body whose OWN live
    /// disposition resolves complete and which has not settled. Census
    /// flaps resolve missing here and select nothing. A settled child is
    /// selected again only after a natural ACKed missing revision re-arms it.
    /// Refused evidence is never offered again; only a changed digest is new.
    pub(super) fn desktop_identity_reoffer(
        &self,
        candidate: &CandidateFile,
        metadata: &ClaudeTitleMetadata,
    ) -> Option<IdentityReoffer> {
        if claude_subagent_identity(&candidate.path).is_some() {
            return None;
        }
        let key = local_index_key(&candidate.path);
        if self.desktop_identity_settled(&key) {
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
            SnapshotSource::ClaudeCode,
            metadata,
            &candidate.path,
            &candidate.source_file_fingerprint,
        )?;
        match self.claude_desktop_identity_latches.get(&key) {
            Some(IdentityLatch::Refused(refused)) if *refused == evidence => None,
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
    /// keys. A complete emission waits for its exact-body ACK (Pending) and
    /// settles only in `settle_desktop_identity_reoffers`. Census-caused
    /// missing with the child's own pair (re-)arms Pending, even after a
    /// settlement: the backend keeps the latest body. Own evidence that
    /// resolves complete but emits no complete body, or whose complete body
    /// is withheld from the upload, is Refused at that evidence digest.
    /// Returns whether an own body is withheld (N1: this pass cannot settle).
    pub(super) fn note_desktop_identity_emission(
        &mut self,
        pending: &PendingIndexFinalization,
        items: &[SnapshotItem],
        unchanged: bool,
        carried: &BTreeSet<String>,
    ) -> bool {
        let path = Path::new(&pending.index_key);
        if claude_subagent_identity(path).is_some() {
            return false;
        }
        let Some(session) = own_session(path) else {
            return false;
        };
        let (emitted, pair) = emitted_disposition(items, &pending.source_file_fingerprint, session);
        let complete = emitted == Some("complete");
        // A carried fingerprint certifies the old body only: it is not sent.
        let carried_own = |item: &SnapshotItem| carried.contains(&item.snapshot_fingerprint);
        let mut own = own_bodies(items, &pending.source_file_fingerprint, session);
        let body = own.next();
        let unsent = unchanged || body.is_some_and(carried_own);
        let withheld = unsent || own.any(carried_own);
        let body = body.map(|item| item.snapshot_fingerprint.as_str());
        if let Some((kind, bytes)) = pending.desktop_identity_reoffer {
            // Only a body that is not sent has a local outcome. A sent body
            // waits for the backend's lists: its first body stands for it.
            match (complete, unsent, body) {
                (false, _, _) => count(kind, IdentityReoffered::Refused, bytes),
                (true, true, _) => count(kind, IdentityReoffered::Unchanged, bytes),
                (true, false, Some(body)) => {
                    with_posted(|memo| memo.record(memo_key(body), (kind, bytes)))
                }
                (true, false, None) => {}
            }
        }
        let reoffered = pending.desktop_identity_reoffer.is_some();
        let settled = self.desktop_identity_settled(&pending.index_key);
        let next = match (emitted, pending.desktop_identity_evidence) {
            (Some("complete"), _) if settled => None,
            // Its old ACK still stands for a withheld body: wait for new evidence.
            (Some("complete"), Some(evidence)) if withheld => {
                Some(IdentityLatch::Refused(evidence))
            }
            // Natural emissions owe the same exact-body ACK as re-offers.
            (Some("complete"), _) => Some(IdentityLatch::Pending),
            // Only a Desktop child carrying its own pair can later resolve
            // complete from the same metadata; other Claude sessions never
            // enter the map. Each re-arm needs a new natural missing revision.
            (Some("missing"), None) if pair => Some(IdentityLatch::Pending),
            // A downgrade of a resolved disposition is not census-caused (E1).
            (Some(_), Some(evidence)) if !settled => Some(IdentityLatch::Refused(evidence)),
            (None, Some(evidence)) if reoffered && !settled => {
                Some(IdentityLatch::Refused(evidence))
            }
            _ => None,
        };
        if let Some(latch) = next {
            self.record_desktop_identity_latch(&pending.index_key, latch);
        }
        withheld
    }

    /// The only way a sent body settles: every own body is sent (N1) and ACKed
    /// with these exact bytes, never by a fingerprint an older body left in
    /// the ledger.
    /// A body the upload holds in quarantine got a verdict that is no ACK, so
    /// its evidence is Refused. Anything else (no response, no attempt) retries.
    pub(crate) fn settle_desktop_identity_reoffers(
        &mut self,
        scan: &SourceScanResult,
        accepted_bodies: &BTreeMap<String, String>,
        invocation_unstored_bodies: &BTreeMap<String, String>,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) {
        for pending in &scan.pending_finalization {
            if pending.desktop_identity_withheld
                || self.desktop_identity_settled(&pending.index_key)
                || !emitted_complete(pending, &scan.snapshots)
            {
                continue;
            }
            let Some(session) = own_session(Path::new(&pending.index_key)) else {
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
                    || invocation_unstored_bodies.get(*fingerprint) == Some(witness)
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
            count_posted(fingerprint, IdentityReoffered::Refused);
            if let Some(evidence) = pending.desktop_identity_evidence {
                self.record_desktop_identity_latch(
                    &pending.index_key,
                    IdentityLatch::Refused(evidence),
                );
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

/// What a Claude file's retained reduction scope depends on.
pub(super) struct ReductionInputs<'a> {
    pub(super) codex: &'a CodexTitleMetadata,
    pub(super) claude: &'a ClaudeTitleMetadata,
    pub(super) support: Option<&'a Path>,
    pub(super) artifacts: bool,
    pub(super) context_curve: bool,
}

/// SOURCE: adoption never reads. Only a retained reduction that acquisition
/// reuses as Unchanged (0 native bytes) qualifies, and never an E2 path twin
/// whose absent sibling would withhold it. Otherwise it waits for a natural read.
pub(super) fn adoption_reads_nothing(
    index: &ScanIndex,
    candidate: &CandidateFile,
    file: &File,
    sampling: Option<&sampled_scan::Context>,
    history_upgrade: &HistoryPage,
    state_census_complete: bool,
    inputs: ReductionInputs<'_>,
) -> bool {
    let source = SnapshotSource::ClaudeCode;
    let twin = claude_request_money::e2::enabled()
        && history_upgrade.twin_groups().get().map_or(true, |groups| {
            !claude_request_money::e2::selected_twin_roots(
                std::iter::once(candidate.path.as_path()),
                groups,
            )
            .is_empty()
        });
    let Some(context) = sampling.filter(|_| !twin && state_census_complete) else {
        return false;
    };
    let key = local_index_key(&candidate.path);
    let now = sampled_scan::now_seconds();
    let debt = sampled_audit::debt_for_key(index, &key, now);
    context.audit_metadata_supported
        && (debt.is_some() || context.audit_slots > 0)
        && sampled_scan::reduction_dependencies(
            source,
            candidate,
            inputs.codex,
            inputs.claude,
            inputs.support,
        )
        .is_some_and(|sidecar| {
            let scope = context.file_scope(
                source,
                candidate,
                &sidecar,
                inputs.artifacts,
                inputs.context_curve,
                index,
            );
            context
                .cache
                .reuses_unchanged(&key, file, &scope, debt, now)
        })
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
    fn desktop_identity_latch_values_fit_the_record_width_and_refuse_malformed_digests() {
        let widest = serde_json::to_string(&IdentityLatch::Refused(u64::MAX)).unwrap();
        assert_eq!(widest.len() + 4, LATCH_RECORD_BYTES);
        for bad in [
            "\"refused:\"",
            "\"refused:ABCDEF0123456789\"",
            "\"refused:+bcdef0123456789\"",
            "\"refused:0123456789abcdef0\"",
            "\"other\"",
            "1",
        ] {
            assert!(serde_json::from_str::<IdentityLatch>(bad).is_err(), "{bad}");
        }
    }
}
