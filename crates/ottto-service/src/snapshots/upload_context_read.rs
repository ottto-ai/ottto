//! Admit context-only body reads before constructing a parser. No durable queue.
use super::*;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalCounts {
    pub files: u64,
    pub local_bytes: u64,
    pub transport_reservation_refused: bool,
    /// This page's admitted reads by index key, with their selection flags
    /// (RAM-only), so a file whose context ACK set split can be re-queued.
    read_paths: BTreeMap<String, ScanTraversalPath>,
}
#[derive(Debug)]
pub(super) struct Budget {
    native_limit: u64,
    native_read: u64,
    native_reserved: u64,
    /// (bodies measured, their wire bytes) for this page.
    page_wire_counted: (usize, usize),
    admitted: BTreeSet<String>,
    read_files: BTreeSet<String>,
    cursor_ordinary_charged: bool,
    deferred: Vec<CandidateFile>,
}
impl Budget {
    pub(super) fn new(source: SnapshotSource) -> Self {
        let native_limit = match source {
            SnapshotSource::Codex => sampled_scan::codex_cursor::Limits::current().singleton(),
            _ => claude_history_upgrade::HISTORY_UPGRADE_BYTES_PER_PAGE,
        };
        #[cfg(test)]
        let native_limit = TEST_READ_LIMIT.with(|limit| limit.get().unwrap_or(native_limit));
        Self {
            native_limit,
            native_read: 0,
            native_reserved: 0,
            page_wire_counted: (0, 0),
            admitted: BTreeSet::new(),
            read_files: BTreeSet::new(),
            cursor_ordinary_charged: false,
            deferred: Vec::new(),
        }
    }
    pub(super) fn admit(
        &mut self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
        ordinary: &[SnapshotItem],
    ) -> bool {
        self.admit_unit(source, index, std::slice::from_ref(candidate), ordinary)
    }
    pub(super) fn admit_unit(
        &mut self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        candidates: &[CandidateFile],
        ordinary: &[SnapshotItem],
    ) -> bool {
        let keys = candidates
            .iter()
            .map(|candidate| local_index_key(&candidate.path))
            .collect::<BTreeSet<_>>();
        if keys.iter().all(|key| self.admitted.contains(key)) {
            return true;
        }
        // Lead B Q1 (2026-10-31): a file's context ACKs may split across
        // passes, so reserve real bytes only (this page's parsed bodies). A
        // file's own bodies are unknown before its parse: admit it while one
        // more legal body (sent once) still fits. A tail the pass allowance
        // defers stays owed.
        if self
            .page_wire(ordinary)
            .saturating_add(MAX_SNAPSHOT_ITEM_CLEAR_WIRE_BYTES.saturating_add(3))
            > crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES
        {
            index.context_read_counts.transport_reservation_refused = true;
            return false;
        }
        // Oversized Codex singletons keep their resumable cursor: each page's
        // chunk is bounded by the cursor's own page allowance, never by this
        // room, on its start and resume pages alike (`PageBudget`, B_s = B).
        // Claude legal files fit 1GiB.
        let size = candidates.iter().fold(0u64, |sum, candidate| {
            sum.saturating_add(candidate.size_bytes)
        });
        if source != SnapshotSource::Codex
            || size <= sampled_scan::codex_cursor::Limits::current().singleton()
        {
            let available = self
                .native_limit
                .saturating_sub(self.native_read)
                .saturating_sub(self.native_reserved);
            if size == 0 || size > available {
                return false;
            }
            self.native_reserved = self.native_reserved.saturating_add(size);
        }
        for candidate in candidates {
            let key = local_index_key(&candidate.path);
            if self.admitted.insert(key.clone()) {
                index.context_read_counts.read_paths.insert(
                    key,
                    ScanTraversalPath {
                        scan_root: candidate.scan_root.clone(),
                        path: candidate.path.clone(),
                        census_member: true,
                        watcher_hint: false,
                    },
                );
            }
        }
        true
    }
    /// Wire bytes of this page's parsed bodies, each with both optional
    /// head-bootstrap stages and separators. A page only appends bodies, so
    /// each is measured once.
    fn page_wire(&mut self, ordinary: &[SnapshotItem]) -> usize {
        let (counted, bytes) = if ordinary.len() >= self.page_wire_counted.0 {
            self.page_wire_counted
        } else {
            (0, 0)
        };
        let bytes = ordinary[counted..].iter().fold(bytes, |sum, item| {
            sum.saturating_add(
                crate::snapshot_sync::snapshot_packing_json_length(item)
                    .unwrap_or(usize::MAX)
                    .saturating_add(3)
                    .saturating_mul(3),
            )
        });
        self.page_wire_counted = (ordinary.len(), bytes);
        bytes
    }
    pub(super) fn is_admitted(&self, candidate: &CandidateFile) -> bool {
        self.admitted.contains(&local_index_key(&candidate.path))
    }
    pub(super) fn defer(&mut self, candidate: CandidateFile) {
        self.deferred.push(candidate);
    }
    pub(super) fn flush(&mut self, index: &mut ScanIndex, flags: &BTreeMap<String, (bool, bool)>) {
        // One pending-queue walk per page, not one walk per deferred file.
        sampled_scan::codex_cursor::requeue_members(index, flags, &self.deferred);
        self.deferred.clear();
        for (key, read) in &mut index.context_read_counts.read_paths {
            if let Some(&(census_member, watcher_hint)) = flags.get(key) {
                read.census_member = census_member;
                read.watcher_hint = watcher_hint;
            }
        }
    }
    /// A cursor job's bytes are bounded by its own cursor allowance and never
    /// charge this page's room.
    pub(super) fn record(
        &mut self,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
        cursor: bool,
        bytes: u64,
    ) {
        if bytes == 0 || !index.file_upload_context_enabled {
            return;
        }
        let key = local_index_key(&candidate.path);
        let first = self.read_files.insert(key.clone());
        #[cfg(test)]
        if first {
            TEST_READ_ORDER.with(|order| {
                if let Some(order) = order.borrow_mut().as_mut() {
                    order.push(candidate.path.clone());
                }
            });
        }
        let admitted = self.admitted.contains(&key);
        if admitted {
            if first {
                index.context_read_counts.files += 1;
            }
            index.context_read_counts.local_bytes =
                index.context_read_counts.local_bytes.saturating_add(bytes);
        }
        if !cursor {
            if admitted {
                self.native_reserved = self.native_reserved.saturating_sub(bytes);
            }
            self.native_read = self.native_read.saturating_add(bytes);
        }
    }
    pub(super) fn charge_cursor_ordinary(
        &mut self,
        page: &mut sampled_scan::codex_cursor::PageBudget,
    ) {
        if !self.cursor_ordinary_charged {
            page.charge(true, self.native_read);
            self.cursor_ordinary_charged = true;
        }
    }
}
impl ScanIndex {
    /// Lead B Q1: return split files read on this page to their generation's
    /// queue in one pending pass; each next read resends only unACKed bodies.
    pub(super) fn requeue_split_context_reads<'a>(&mut self, keys: impl Iterator<Item = &'a str>) {
        let Some(traversal) = self.traversal.as_mut() else {
            return;
        };
        let mut absent = keys
            .filter_map(|key| self.context_read_counts.read_paths.get(key))
            .map(|read| (read.path.as_path(), read))
            .collect::<BTreeMap<_, _>>();
        for pending in &traversal.pending_candidates {
            absent.remove(pending.path.as_path());
        }
        traversal
            .pending_candidates
            .extend(absent.into_values().cloned());
    }
    pub(super) fn context_only_read(&self, candidate: &CandidateFile, audit_now: u64) -> bool {
        if !self.file_upload_context_enabled {
            return false;
        }
        let key = local_index_key(&candidate.path);
        self.files.get(&key).is_some_and(|entry| {
            entry.size_bytes == candidate.size_bytes
                && entry.modified_unix_seconds == candidate.modified_unix_seconds
                && entry
                    .modified_unix_nanos
                    .map_or(true, |n| n == candidate.modified_unix_nanos)
                && !entry.rearmed()
        }) && self
            .file_snapshot_fingerprints
            .get(&key)
            .is_some_and(|entities| !entities.is_empty())
            && self
                .candidate_decision_with_reason_at(candidate, terminal_off_decision_now(audit_now))
                .1
                == Some(CandidateParseReason::UploadContext)
    }
}
#[cfg(test)]
thread_local! { static TEST_READ_LIMIT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
thread_local! { static TEST_READ_ORDER: std::cell::RefCell<Option<Vec<PathBuf>>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(super) fn with_read_limit<T>(limit: u64, f: impl FnOnce() -> T) -> (T, Vec<PathBuf>) {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_READ_LIMIT.with(|value| value.set(self.0));
            TEST_READ_ORDER.with(|order| {
                order.replace(None);
            });
        }
    }
    let _reset = Reset(TEST_READ_LIMIT.with(|value| value.replace(Some(limit))));
    TEST_READ_ORDER.with(|order| {
        assert!(order.replace(Some(Vec::new())).is_none());
    });
    let result = f();
    let order = TEST_READ_ORDER.with(|order| order.replace(None).unwrap());
    (result, order)
}
crate::heap_layout_bound::fields!(LocalCounts; files, local_bytes, transport_reservation_refused, read_paths);
crate::heap_layout_bound::fields!(Budget; native_limit, native_read, native_reserved, page_wire_counted, admitted, read_files, cursor_ordinary_charged, deferred);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_cursor_room_excludes_prior_ordinary_native_bytes() {
        let mut budget = Budget::new(SnapshotSource::Codex);
        budget.native_read = 1024;
        let mut page = sampled_scan::codex_cursor::PageBudget::default();
        budget.charge_cursor_ordinary(&mut page);
        let limits = sampled_scan::codex_cursor::Limits::current();
        page.charge(true, limits.singleton() - 1025);
        assert!(!page.cursor_exhausted(limits));
        page.charge(true, 1);
        assert!(page.cursor_exhausted(limits));
        budget.charge_cursor_ordinary(&mut page); // charged only once
    }
}
