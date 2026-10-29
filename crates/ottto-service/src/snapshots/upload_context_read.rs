//! Admit context-only body reads before constructing a parser. No durable queue.
use super::*;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalCounts {
    pub files: u64,
    pub local_bytes: u64,
}
#[derive(Debug)]
pub(super) struct Budget {
    native_limit: u64,
    native_read: u64,
    native_reserved: u64,
    wire_reserved: usize,
    admitted: BTreeSet<String>,
    read_files: BTreeSet<String>,
    cursor_ordinary_charged: bool,
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
            wire_reserved: 0,
            admitted: BTreeSet::new(),
            read_files: BTreeSet::new(),
            cursor_ordinary_charged: false,
        }
    }
    pub(super) fn admit(
        &mut self,
        source: SnapshotSource,
        index: &ScanIndex,
        candidate: &CandidateFile,
        ordinary: &[SnapshotItem],
    ) -> bool {
        let key = local_index_key(&candidate.path);
        if self.admitted.contains(&key) {
            return true;
        }
        let entities = index
            .file_snapshot_fingerprints
            .get(&key)
            .map_or(1, BTreeSet::len)
            .max(1);
        // Three legal item bodies reserve both optional head-bootstrap stages
        // and the final POST, including separators. No persisted size field.
        let wire = entities
            .saturating_mul(MAX_SNAPSHOT_ITEM_CLEAR_WIRE_BYTES.saturating_add(3))
            .saturating_mul(3);
        let ordinary_wire = ordinary
            .iter()
            .filter(|item| {
                !item.source_file_fingerprint.as_ref().is_some_and(|fp| {
                    self.admitted.iter().any(|key| {
                        index
                            .files
                            .get(key)
                            .is_some_and(|entry| &entry.source_file_fingerprint == fp)
                    })
                })
            })
            .fold(0usize, |sum, item| {
                sum.saturating_add(
                    crate::snapshot_sync::snapshot_packing_json_length(item)
                        .unwrap_or(usize::MAX)
                        .saturating_add(3)
                        .saturating_mul(3),
                )
            });
        let wire_left = crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES
            .saturating_sub(ordinary_wire)
            .saturating_sub(self.wire_reserved);
        // Oversized Codex singletons keep their existing resumable cursor;
        // each page pays only its bounded chunk. Claude legal files fit 1GiB.
        let read = if source == SnapshotSource::Codex {
            candidate.size_bytes.min(self.native_limit)
        } else {
            candidate.size_bytes
        };
        if read
            > self
                .native_limit
                .saturating_sub(self.native_read)
                .saturating_sub(self.native_reserved)
        {
            return false;
        }
        let alone = ordinary.is_empty() && self.admitted.is_empty();
        if wire > wire_left && !(alone && wire > crate::snapshot_sync::SNAPSHOT_BATCH_MAX_BYTES) {
            return false;
        }
        self.wire_reserved = self.wire_reserved.saturating_add(wire);
        self.native_reserved = self.native_reserved.saturating_add(read);
        self.admitted.insert(key);
        true
    }
    pub(super) fn record(&mut self, index: &mut ScanIndex, candidate: &CandidateFile, bytes: u64) {
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
        if self.admitted.contains(&key) || index.context_only_read(candidate) {
            if first {
                index.context_read_counts.files += 1;
            }
            index.context_read_counts.local_bytes =
                index.context_read_counts.local_bytes.saturating_add(bytes);
            self.native_reserved = self.native_reserved.saturating_sub(bytes);
        }
        self.native_read = self.native_read.saturating_add(bytes);
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
    pub(super) fn context_only_read(&self, candidate: &CandidateFile) -> bool {
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
                && !entry.source_file_fingerprint.is_empty()
        }) && self
            .file_snapshot_fingerprints
            .get(&key)
            .is_some_and(|entities| !entities.is_empty())
            && self.candidate_decision_with_reason(candidate).1
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
crate::heap_layout_bound::fields!(LocalCounts; files, local_bytes);
crate::heap_layout_bound::fields!(Budget; native_limit, native_read, native_reserved, wire_reserved, admitted, read_files, cursor_ordinary_charged);
