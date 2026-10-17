//! Private paid provenance from the actual parser to its F1 completion.
//! No native IDs, raw paths, persistent state or admission permission.
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshots::{
    sampled_scan::{CopyReservation, SharedCache},
    CandidateFile, ScanIndex, SnapshotItem, SnapshotSource, SourceScanResult,
    MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
};
use sha2::{Digest, Sha256};
use std::{
    alloc::Layout,
    num::NonZeroU64,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

mod escrow;
pub(crate) use escrow::HeldNativeCompletion;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
fn hash(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in std::iter::once(domain.as_bytes()).chain(parts.iter().copied()) {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}
/// SourceScanResult clones deliberately lose the single source-completion
/// capability. An index clone alone cannot reissue it or upgrade completeness.
#[derive(Debug, Default)]
pub(in crate::snapshots) struct SourceToken(Option<NonZeroU64>);
impl Clone for SourceToken {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl HeapLayoutBound for SourceToken {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}
#[derive(Debug, Clone, Copy)]
struct Marker {
    root: [u8; 32],
    path: [u8; 32],
    revision: [u8; 32],
    session: [u8; 32],
}
struct Storage {
    generation: NonZeroU64,
    scope: [u8; 32],
    window: Option<[u8; 32]>,
    records: Vec<Marker>,
    // Last: all record backing retires before returning the credit.
    reservation: CopyReservation,
}
/// Only the original source context writes/seals. Clones share immutable paid
/// storage; a later append reserves a real fixed-digest copy before allocation.
#[derive(Default)]
pub(in crate::snapshots) struct Provenance {
    storage: Option<Arc<Storage>>,
    writer: bool,
    can_complete: bool,
}
impl Clone for Provenance {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            writer: false,
            can_complete: false,
        }
    }
}
impl std::fmt::Debug for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequiredCompletionProvenance")
            .field("available", &self.storage.is_some())
            .finish_non_exhaustive()
    }
}
impl Drop for Provenance {
    fn drop(&mut self) {
        if let Some(arc) = self.storage.take() {
            // All strong handles use this wrapper; no Weak is exposed. Header
            // allocation dies before payload data and its reservation retire.
            if let Some(storage) = Arc::into_inner(arc) {
                drop(storage);
            }
        }
    }
}
impl HeapLayoutBound for Provenance {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.storage.as_ref().map_or(0, |s| s.reservation.bytes()))
    }
}
fn storage_bytes(capacity: usize) -> Option<usize> {
    let block = Layout::new::<[usize; 2]>()
        .extend(Layout::new::<Storage>())
        .ok()?
        .0
        .pad_to_align()
        .size();
    // Exact Vec reservation on the pinned profile, including old/new backing
    // overlap during reserve. Old shared stores have independent live credit.
    block.checked_add(
        capacity
            .checked_mul(std::mem::size_of::<Marker>())?
            .checked_mul(2)?,
    )
}
impl Provenance {
    fn new(owner: &Arc<SharedCache>, scope: [u8; 32]) -> Option<Self> {
        let generation = NEXT_GENERATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()
            .and_then(NonZeroU64::new)?;
        let reservation = owner.reserve_copy_bytes(storage_bytes(0)?)?;
        Some(Self {
            storage: Some(Arc::new(Storage {
                generation,
                scope,
                window: None,
                records: Vec::new(),
                reservation,
            })),
            writer: true,
            can_complete: true,
        })
    }
    fn invalidate(&mut self) {
        *self = Self::default();
    }
    fn record(
        &mut self,
        candidate: &CandidateFile,
        opened_revision: &str,
        window: &str,
        items: &[SnapshotItem],
        file_limit: usize,
    ) -> Option<()> {
        if !self.writer {
            return None;
        }
        let old = self.storage.as_ref()?;
        let window = hash("copy_native_window:v1", &[window.as_bytes()]);
        if opened_revision != candidate.source_file_fingerprint
            || old.window.is_some_and(|prior| prior != window)
            || items.is_empty()
        {
            return None;
        }
        let root = hash(
            "copy_native_root:v1",
            &[candidate.scan_root.to_str()?.as_bytes()],
        );
        let path = hash(
            "copy_native_path:v1",
            &[candidate.path.to_str()?.as_bytes()],
        );
        let revision = hash("copy_native_revision:v1", &[opened_revision.as_bytes()]);
        let length = old.records.len().checked_add(items.len())?;
        if length > MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS || length > file_limit {
            return None;
        }
        let capacity = if length <= old.records.capacity() {
            old.records.capacity()
        } else {
            old.records.capacity().max(4).checked_mul(2)?.max(length)
        };
        if Arc::strong_count(old) == 1 {
            let storage = Arc::get_mut(self.storage.as_mut()?)?;
            storage.reservation.resize(storage_bytes(capacity)?)?;
            if storage.records.capacity() < capacity {
                storage
                    .records
                    .reserve_exact(capacity.checked_sub(storage.records.len())?);
            }
            if storage.records.capacity() > capacity {
                return None;
            }
        } else {
            let reservation = old
                .reservation
                .owner()
                .reserve_copy_bytes(storage_bytes(capacity)?)?;
            let mut records = Vec::with_capacity(capacity);
            records.extend_from_slice(&old.records);
            let storage = Storage {
                generation: old.generation,
                scope: old.scope,
                window: old.window,
                records,
                reservation,
            };
            // Never directly drop an Arc handle: a concurrent last clone may
            // retire here. Free its header via into_inner before credit.
            let previous = self.storage.take();
            self.storage = Some(Arc::new(storage));
            if let Some(arc) = previous {
                if let Some(storage) = Arc::into_inner(arc) {
                    drop(storage);
                }
            }
        }
        let storage = Arc::get_mut(self.storage.as_mut()?)?;
        storage.window = Some(window);
        for item in items {
            storage.records.push(Marker {
                root,
                path,
                revision,
                session: hash(
                    "copy_native_session:v1",
                    &[item.source_session_id.as_bytes()],
                ),
            });
        }
        Some(())
    }
    fn seal(&mut self, window: &str) -> SourceToken {
        if !self.writer {
            return SourceToken::default();
        }
        self.writer = false;
        // The read-only cloned context never seals. If a live immutable copy
        // prevents exclusive sorting, conservatively lose the optional token.
        let Some(storage) = self.storage.as_mut().and_then(Arc::get_mut) else {
            return SourceToken::default();
        };
        if storage.window != Some(hash("copy_native_window:v1", &[window.as_bytes()])) {
            return SourceToken::default();
        }
        storage
            .records
            .sort_unstable_by_key(|m| (m.session, m.revision));
        SourceToken(Some(storage.generation))
    }
    fn valid_header(
        &self,
        scan: &SourceScanResult,
        scope: [u8; 32],
        generation: NonZeroU64,
    ) -> bool {
        if !self.can_complete {
            return false;
        }
        let Some(storage) = &self.storage else {
            return false;
        };
        if storage.generation != generation
            || storage.scope != scope
            || storage.window
                != Some(hash(
                    "copy_native_window:v1",
                    &[scan.census_window_end.as_bytes()],
                ))
        {
            return false;
        }
        true
    }
    fn visit_matches(
        &self,
        scan: &SourceScanResult,
        scope: [u8; 32],
        generation: NonZeroU64,
        mut visit: impl FnMut(usize, &Marker),
    ) -> usize {
        if !self.valid_header(scan, scope, generation) {
            return 0;
        }
        let Some(storage) = &self.storage else {
            return 0;
        };
        let count = scan
            .pending_finalization
            .len()
            .checked_add(scan.snapshots.len());
        let Some(bytes) = count
            .filter(|count| *count <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
            .and_then(|_| {
                scan.pending_finalization
                    .len()
                    .checked_mul(std::mem::size_of::<
                        &crate::snapshots::PendingIndexFinalization,
                    >())
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    scan.snapshots
                        .len()
                        .checked_mul(std::mem::size_of::<(usize, &SnapshotItem)>())?,
                )
            })
            .and_then(|bytes| bytes.checked_mul(2))
        else {
            return 0;
        };
        // Borrowed reference collectors only, paid before backing allocation.
        // Native IDs and row payloads are neither cloned nor walked here.
        let Some(_scratch) = storage.reservation.owner().reserve_copy_bytes(bytes) else {
            return 0;
        };
        let mut pending = Vec::with_capacity(scan.pending_finalization.len());
        pending.extend(scan.pending_finalization.iter());
        pending.sort_unstable_by(|a, b| a.source_file_fingerprint.cmp(&b.source_file_fingerprint));
        let mut items = Vec::with_capacity(scan.snapshots.len());
        items.extend(scan.snapshots.iter().enumerate());
        items.sort_unstable_by(|a, b| {
            (&a.1.source_session_id, &a.1.source_file_fingerprint)
                .cmp(&(&b.1.source_session_id, &b.1.source_file_fingerprint))
        });
        let mut matched = 0;
        for (position, (source_position, item)) in items.iter().enumerate() {
            let Some(revision) = item.source_file_fingerprint.as_deref() else {
                continue;
            };
            let duplicate = position
                .checked_sub(1)
                .and_then(|p| items.get(p))
                .is_some_and(|other| {
                    other.1.source_session_id == item.source_session_id
                        && other.1.source_file_fingerprint == item.source_file_fingerprint
                })
                || items.get(position + 1).is_some_and(|other| {
                    other.1.source_session_id == item.source_session_id
                        && other.1.source_file_fingerprint == item.source_file_fingerprint
                });
            if duplicate {
                continue;
            }
            let Ok(p) =
                pending.binary_search_by(|p| p.source_file_fingerprint.as_str().cmp(revision))
            else {
                continue;
            };
            let opened = pending[p];
            if !opened.parse_complete
                || opened.parsed_snapshot_count != 1
                || p.checked_sub(1)
                    .and_then(|p| pending.get(p))
                    .is_some_and(|p| p.source_file_fingerprint == revision)
                || pending
                    .get(p + 1)
                    .is_some_and(|p| p.source_file_fingerprint == revision)
            {
                continue;
            }
            let path = hash("copy_native_path:v1", &[opened.index_key.as_bytes()]);
            let revision = hash("copy_native_revision:v1", &[revision.as_bytes()]);
            let session = hash(
                "copy_native_session:v1",
                &[item.source_session_id.as_bytes()],
            );
            let key = (session, revision);
            let Ok(m) = storage
                .records
                .binary_search_by_key(&key, |m| (m.session, m.revision))
            else {
                continue;
            };
            let marker = &storage.records[m];
            if m.checked_sub(1)
                .and_then(|m| storage.records.get(m))
                .is_some_and(|m| (m.session, m.revision) == key)
                || storage
                    .records
                    .get(m + 1)
                    .is_some_and(|m| (m.session, m.revision) == key)
            {
                continue;
            }
            // Root remains the exact parser-candidate digest in this uniquely
            // joined record, never reconstructed from the index path/settings.
            if marker.path == path && marker.root != [0; 32] {
                matched += 1;
                visit(*source_position, marker);
            }
        }
        matched
    }
}
impl ScanIndex {
    pub(in crate::snapshots) fn begin_copy_completion_provenance(&mut self) {
        let provenance = (|| {
            let owner = self.required_copy_owner().ok()??;
            let (scope, attempt) = self.copy_native_completion_scope()?;
            Provenance::new(
                owner,
                hash(
                    "copy_native_scope:v1",
                    &[scope.as_bytes(), attempt.as_bytes(), b"claude_code"],
                ),
            )
        })()
        .unwrap_or_default();
        if let Some(context) = self.active_copy_scan.as_mut() {
            context.provenance = provenance;
        }
    }
    pub(in crate::snapshots) fn record_copy_complete_native_input(
        &mut self,
        candidate: &CandidateFile,
        opened_revision: &str,
        window: &str,
        items: &[SnapshotItem],
        file_limit: usize,
    ) {
        if let Some(context) = self.active_copy_scan.as_mut() {
            if context
                .provenance
                .record(candidate, opened_revision, window, items, file_limit)
                .is_none()
            {
                context.provenance.invalidate();
            }
        }
    }
    pub(in crate::snapshots) fn seal_copy_completion_provenance(
        &mut self,
        window: &str,
    ) -> SourceToken {
        self.active_copy_scan
            .as_mut()
            .map_or_else(SourceToken::default, |context| {
                context.provenance.seal(window)
            })
    }
    fn take_source_provenance(&mut self, scan: &mut SourceScanResult) -> Option<PendingCompletion> {
        let scope = self.copy_native_completion_scope().map(|(scope, attempt)| {
            hash(
                "copy_native_scope:v1",
                &[scope.as_bytes(), attempt.as_bytes(), b"claude_code"],
            )
        });
        let provenance = self
            .active_copy_scan
            .as_mut()
            .map(|context| std::mem::take(&mut context.provenance));
        let generation = scan.copy_completion_token.0.take();
        let ((provenance, scope), generation) = provenance.zip(scope).zip(generation)?;
        if scan.source != SnapshotSource::ClaudeCode
            || !provenance.valid_header(scan, scope, generation)
        {
            return None;
        }
        Some(PendingCompletion {
            provenance,
            scope,
            generation,
        })
    }
    /// Observation/test consumer of the same real source token and matcher.
    /// It retains no IDs and cannot grant any cache/read permission.
    pub(crate) fn consume_copy_completion_provenance(
        &mut self,
        scan: &mut SourceScanResult,
    ) -> impl Sized {
        let completion = self.take_source_provenance(scan);
        let matched = completion
            .as_ref()
            .map_or(0, |completion| completion.visit_matches(scan, |_, _| {}));
        record_f1_receipt(matched);
        completion
    }
}
struct PendingCompletion {
    provenance: Provenance,
    scope: [u8; 32],
    generation: NonZeroU64,
}
impl PendingCompletion {
    fn visit_matches(&self, scan: &SourceScanResult, visit: impl FnMut(usize, &Marker)) -> usize {
        self.provenance
            .visit_matches(scan, self.scope, self.generation, visit)
    }
    fn owner(&self) -> Option<&Arc<SharedCache>> {
        Some(self.provenance.storage.as_ref()?.reservation.owner())
    }
}
fn record_f1_receipt(matched: usize) {
    #[cfg(test)]
    F1_RECEIPT.with(|value| value.set(matched));
    let _ = matched;
}
#[cfg(test)]
thread_local! { static F1_RECEIPT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
impl ScanIndex {
    pub(crate) fn copy_f1_provenance_receipt_for_test() -> usize {
        F1_RECEIPT.with(std::cell::Cell::get)
    }
    pub(crate) fn copy_provenance_marker_count_for_test(&self) -> usize {
        self.active_copy_scan
            .as_ref()
            .and_then(|context| context.provenance.storage.as_ref())
            .map_or(0, |s| s.records.len())
    }
    pub(crate) fn copy_provenance_root_bound_for_test(
        &self,
        root: &std::path::Path,
        path: &str,
        session: &str,
        revision: &str,
    ) -> bool {
        let Some(root) = root.to_str() else {
            return false;
        };
        self.active_copy_scan
            .as_ref()
            .and_then(|context| context.provenance.storage.as_ref())
            .is_some_and(|storage| {
                storage.records.iter().any(|marker| {
                    marker.root == hash("copy_native_root:v1", &[root.as_bytes()])
                        && marker.path == hash("copy_native_path:v1", &[path.as_bytes()])
                        && marker.session == hash("copy_native_session:v1", &[session.as_bytes()])
                        && marker.revision
                            == hash("copy_native_revision:v1", &[revision.as_bytes()])
                })
            })
    }
    pub(crate) fn reset_copy_provenance_for_test(&mut self) {
        self.begin_copy_completion_provenance();
    }
    pub(crate) fn copy_provenance_negative_for_test(scan: &mut SourceScanResult, case: &str) {
        let Some(first) = scan.pending_finalization.first_mut() else {
            return;
        };
        match case {
            "partial" => first.parse_complete = false,
            "revision" => first.source_file_fingerprint = "e".repeat(64),
            "ambiguous" => {
                let extra = first.clone();
                scan.pending_finalization.push(extra);
            }
            "missing" => {
                scan.pending_finalization.clear();
            }
            "window" => scan.census_window_end.push('x'),
            _ => panic!("unknown negative fixture"),
        }
    }
}
