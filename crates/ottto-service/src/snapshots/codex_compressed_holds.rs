//! Dedicated non-red custody; no acquisition or ACK authority.
use super::*;

pub(super) const OWNER_LOOKUP_SLACK: usize = 16384 + 2 * codex_file_join::MAX_HEADER_BYTES;

/// Called with existing walk metadata; repeated observations are not unique bytes.
pub(super) fn observe_growth(
    source: SnapshotSource,
    files: &BTreeMap<String, ScanIndexEntry>,
    path: &Path,
    length: u64,
) {
    let Some(entry) = files
        .get(&local_index_key(path))
        .filter(|entry| source == SnapshotSource::Codex && entry.codex_compressed_hold.is_some())
    else {
        return;
    };
    if !is_compressed_codex_rollout(Some(path), None) {
        let bytes = length.saturating_sub(entry.size_bytes);
        let over_cap = u64::from(length > max_jsonl_file_bytes(source));
        if bytes != 0 || over_cap != 0 {
            crate::local_resource_diagnostics::codex_held_growth(bytes, over_cap);
        }
    }
}

pub(super) fn deserialize_hold<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<CodexZstCause>, D::Error> {
    struct Hold;
    fn unsupported() -> Option<CodexZstCause> {
        crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::OwnerUnproven);
        Some(CodexZstCause::OwnerUnproven)
    }
    impl<'de> serde::de::Visitor<'de> for Hold {
        type Value = Option<CodexZstCause>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an optional closed custody cause")
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.len() > 64 {
                return Ok(unsupported());
            }
            Ok(
                CodexZstCause::deserialize(serde::de::value::StrDeserializer::<E>::new(value))
                    .ok()
                    .or_else(unsupported),
            )
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(unsupported())
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            while map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(unsupported())
        }
    }
    de.deserialize_any(Hold)
}

impl ScanIndex {
    pub(super) fn hold_compressed(
        &mut self,
        path: &Path,
        owners: BTreeSet<String>,
        cause: CodexZstCause,
    ) {
        let key = local_index_key(path);
        let entry = self.files.entry(key.clone()).or_default();
        let cause = if entry.codex_compressed_hold == Some(CodexZstCause::ParentLedgerUnbound) {
            CodexZstCause::ParentLedgerUnbound
        } else {
            cause
        };
        let changed = entry.codex_compressed_hold != Some(cause);
        entry.codex_compressed_hold = Some(cause);
        self.codex_state_only_blocked_session_ids
            .extend(owners.iter().cloned());
        self.extend_codex_blocked_attribution(&key, owners);
        if changed {
            crate::local_resource_diagnostics::codex_zst_held(cause);
        }
    }
}
impl codex_file_join::HeaderInventory {
    pub(super) fn prepare_custody(&mut self, index: &ScanIndex) -> bool {
        use std::ops::Bound::{Excluded, Unbounded};
        if self.custody_done {
            return true;
        }
        if self.custody_after.is_none() && self.custody_next == 0 {
            self.headers.sort_unstable_by(|a, b| a.owner.cmp(&b.owner));
            // Fixed cursor/temporary slack: no historical population allocation.
            let mut cost =
                crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
            if cost.add(OWNER_LOOKUP_SLACK).is_none() {
                self.refuse_custody();
            }
            if index.codex_counting_tombstones.len()
                > codex_counting_version::MAX_COUNTING_TOMBSTONES
            {
                self.refuse_custody();
            } else if !index.codex_counting_tombstones.is_empty() {
                if crate::heap_layout_bound::tree_nodes::<String, ()>(
                    index.codex_counting_tombstones.len(),
                    &mut cost,
                )
                .is_none()
                    || cost
                        .add(index.codex_counting_tombstones.len().saturating_mul(128))
                        .is_none()
                {
                    self.refuse_custody();
                }
            }
            self.custody_peak = cost.bytes;
            if !self.custody_refused {
                for owner in &self.held_owners {
                    let protected = codex_protected_owner(owner);
                    if index.codex_counting_tombstones.contains_key(&protected) {
                        self.absence_held.insert(protected);
                    }
                }
            }
            self.classify_compressed_families();
        }
        let after = self.custody_after.as_ref().map_or(Unbounded, Excluded);
        if let Some((key, entry)) = index.files.range((after, Unbounded)).next() {
            if let Some(cause) = entry.codex_compressed_hold {
                let owners = index.codex_state_only_blocked_by_file.get(key);
                if let Some(binding) = entry.codex_counting_owner.as_deref().filter(|binding| {
                    valid_codex_protected_owner(binding)
                        && !owners.into_iter().flatten().any(|owner| {
                            owner.len() <= codex_file_join::MAX_HEADER_BYTES
                                && codex_protected_owner(owner) == *binding
                        })
                }) {
                    // Negative accepted-owner scope, one current owner per step;
                    // no retained-roster rescan, new map or fresh proof/ACK.
                    let first = self.custody_next;
                    if first < self.headers.len() {
                        let last = first
                            + self.headers[first..]
                                .partition_point(|h| h.owner == self.headers[first].owner);
                        self.custody_next = last;
                        if codex_protected_owner(&self.headers[first].owner) == binding {
                            self.mark_custody_range(first, last, cause);
                        }
                        return false;
                    }
                }
                if !owners.is_some_and(|owners| !owners.is_empty()) {
                    self.custody_unknown = true;
                    // Path ids are negative scope only, never ownership proof.
                    // Truly unlocated custody still cannot fence plain work.
                    let path = Path::new(key);
                    let logical = if is_compressed_codex_rollout(Some(path), None) {
                        path.with_extension("")
                    } else {
                        path.to_owned()
                    };
                    for owner in codex_session_id_candidates_from_path(&logical) {
                        self.mark_custody_owner(&owner, cause);
                    }
                }
                for owner in owners.into_iter().flatten() {
                    if !self.custody_refused {
                        let protected = codex_protected_owner(owner);
                        if index.codex_counting_tombstones.contains_key(&protected) {
                            self.absence_held.insert(protected);
                        }
                    }
                    self.mark_custody_owner(owner, cause);
                }
            }
            self.custody_next = 0;
            self.custody_after = Some(key.clone());
            return false;
        }
        self.headers.sort_unstable_by(|a, b| {
            a.candidate
                .path
                .as_os_str()
                .cmp(b.candidate.path.as_os_str())
        });
        self.refresh_custody(index);
        self.custody_done = true;
        true
    }
    pub(super) fn mark_custody_owner(&mut self, owner: &str, cause: CodexZstCause) {
        let first = self.headers.partition_point(|h| h.owner.as_str() < owner);
        let last = self.headers.partition_point(|h| h.owner.as_str() <= owner);
        self.mark_custody_range(first, last, cause);
    }
    fn mark_custody_range(&mut self, first: usize, last: usize, cause: CodexZstCause) {
        if first == last
            || (cause == CodexZstCause::FamilyUnproven
                && self.headers[first..last]
                    .iter()
                    .all(|h| !is_compressed_codex_rollout(Some(&h.candidate.path), None)))
        {
            return;
        }
        if self.headers[first..last]
            .iter()
            .all(|h| h.custody_cause.is_none())
            && !self.custody_refused
        {
            match self.owner_peak(first, last, &self.headers[first].owner) {
                Some(peak) => self.custody_peak = peak,
                None => self.refuse_custody(),
            }
        }
        for header in &mut self.headers[first..last] {
            if header.custody_cause != Some(CodexZstCause::ParentLedgerUnbound)
                && (cause != CodexZstCause::FamilyUnproven
                    || is_compressed_codex_rollout(Some(&header.candidate.path), None))
            {
                header.custody_cause = Some(cause);
            }
        }
    }
    fn owner_peak(&self, first: usize, last: usize, owner: &str) -> Option<usize> {
        if self.headers.len() > codex_file_join::MAX_HEADER_FILES {
            return None;
        }
        let paths = self.headers[first..last]
            .iter()
            .try_fold(0usize, |sum, h| {
                sum.checked_add(h.candidate.path.as_os_str().len().checked_mul(3)?)
            })?;
        // Includes index-entry nodes, attribution map/set, global owner and
        // temporary key/set clones before any sibling mutation/allocation.
        let node = crate::heap_layout_bound::tree_node_bytes::<String, ScanIndexEntry>()?
            .checked_add(
                crate::heap_layout_bound::tree_node_bytes::<String, ()>()?.checked_mul(4)?,
            )?;
        let peak = self
            .custody_peak
            .checked_add(node.checked_mul(last - first + 1)?)?
            .checked_add(paths)?
            .checked_add(owner.len().checked_mul(4)?.checked_mul(last - first + 1)?)?;
        let mut cost =
            crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
        cost.add(peak)?;
        Some(cost.bytes)
    }
    fn refuse_custody(&mut self) {
        if !self.custody_refused {
            self.custody_refused = true;
            crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::AdmissionRefused);
            crate::local_resource_diagnostics::custody_overflow();
        }
    }
    pub(super) fn hold_custodied_siblings(&mut self, index: &mut ScanIndex) -> bool {
        let Some(header) = self.headers.get(self.custody_next) else {
            return true;
        };
        if let Some(cause) = header.custody_cause {
            if !index
                .files
                .get(&local_index_key(&header.candidate.path))
                .is_some_and(|e| e.codex_compressed_hold.is_some())
                && !header.custody_current()
            {
                self.retry_custody_header(self.custody_next);
                return false;
            }
            if !self.custody_refused && !self.custody_unknown {
                index.hold_compressed(
                    &header.candidate.path,
                    BTreeSet::from([header.owner.clone()]),
                    cause,
                );
                self.custody_next += 1;
                return false;
            }
            // One durable obligation per continuation, even when optional owner
            // fan-out scratch refused. No owner/map clones on this fallback.
            // Earlier committed entries are the retained index baseline.
            let peak = crate::heap_layout_bound::tree_node_bytes::<String, ScanIndexEntry>()
                .and_then(|node| node.checked_add(16384))
                .and_then(|node| {
                    header
                        .candidate
                        .path
                        .as_os_str()
                        .len()
                        .checked_mul(2)
                        .and_then(|keys| node.checked_add(keys))
                });
            let mut cost =
                crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
            if peak.and_then(|bytes| cost.add(bytes)).is_none() {
                self.refuse_custody();
                return false;
            }
            let key = local_index_key(&header.candidate.path);
            let entry = index.files.entry(key).or_default();
            let changed = entry.codex_compressed_hold != Some(cause);
            entry.codex_compressed_hold = Some(cause);
            if changed {
                crate::local_resource_diagnostics::codex_zst_held(cause);
            }
        }
        self.custody_next += 1;
        false
    }
    pub(super) fn member_held(&self, path: &Path) -> bool {
        // Unattributed custody cannot establish a hold on unrelated plain work.
        ((self.custody_unknown || self.custody_refused)
            && is_compressed_codex_rollout(Some(path), None))
            || self
                .headers
                .binary_search_by(|h| h.candidate.path.as_os_str().cmp(path.as_os_str()))
                .is_ok_and(|at| {
                    self.headers[at].custody_cause.is_some() || self.headers[at].plain_twin
                })
    }
}

pub(super) fn parent_unbound(
    parent: &str,
    census: CodexParentCensus<'_>,
    metadata: &CodexTitleMetadata,
) -> bool {
    let parent = resolve_codex_identity(parent);
    let mut archive = false;
    for key in census.paths.iter().take(codex_file_join::MAX_HEADER_FILES) {
        let path = Path::new(key);
        let compressed = is_compressed_codex_rollout(Some(path), None);
        let logical = if compressed {
            path.with_extension("")
        } else {
            path.to_owned()
        };
        if codex_session_id_candidates_from_path(&logical).contains(&parent) {
            if !compressed {
                return false;
            }
            archive = true;
        }
    }
    if archive {
        return true;
    }
    // State metadata can locate a compressed parent before archive discovery.
    // Only lstat: this cannot create an archive candidate or decoder permission.
    metadata
        .state_threads
        .get(&parent)
        .and_then(|thread| thread.rollout_path.as_deref())
        .is_some_and(|key| {
            let path = Path::new(key);
            let compressed = is_compressed_codex_rollout(Some(path), None);
            let plain = if compressed {
                path.with_extension("")
            } else {
                path.to_owned()
            };
            let archive = if compressed {
                path.to_owned()
            } else {
                PathBuf::from(format!("{key}.zst"))
            };
            census
                .scan_roots
                .iter()
                .any(|root| archive.starts_with(root))
                && fs::symlink_metadata(plain).is_err()
                && fs::symlink_metadata(archive)
                    .is_ok_and(|stat| stat.is_file() && !stat.file_type().is_symlink())
        })
}

impl codex_file_join::HeaderInventory {
    pub(super) fn classify_compressed_families(&mut self) {
        fn logical(path: &Path) -> &str {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            name.strip_suffix(".zst").unwrap_or(name)
        }
        self.headers.sort_unstable_by(|a, b| {
            a.owner
                .cmp(&b.owner)
                .then_with(|| logical(&a.candidate.path).cmp(logical(&b.candidate.path)))
                .then_with(|| {
                    is_compressed_codex_rollout(Some(&a.candidate.path), None)
                        .cmp(&is_compressed_codex_rollout(Some(&b.candidate.path), None))
                })
        });
        let mut start = 0;
        while start < self.headers.len() {
            let end = start
                + self.headers[start..].partition_point(|h| h.owner == self.headers[start].owner);
            let mut at = start;
            let mut members = 0;
            let mut archive = false;
            while at < end {
                let next = at
                    + self.headers[at..end].partition_point(|h| {
                        logical(&h.candidate.path) == logical(&self.headers[at].candidate.path)
                    });
                let plain =
                    !is_compressed_codex_rollout(Some(&self.headers[at].candidate.path), None);
                for i in at..next {
                    let compressed =
                        is_compressed_codex_rollout(Some(&self.headers[i].candidate.path), None);
                    self.headers[i].plain_twin = plain && compressed;
                    archive |= compressed;
                    members += usize::from(!self.headers[i].plain_twin);
                }
                at = next;
            }
            if archive && members > 1 {
                self.mark_custody_range(start, end, CodexZstCause::FamilyUnproven);
            }
            start = end;
        }
    }

    pub(super) fn plain_twin(&self, path: &Path) -> bool {
        self.headers
            .binary_search_by(|h| h.candidate.path.as_os_str().cmp(path.as_os_str()))
            .is_ok_and(|at| self.headers[at].plain_twin)
    }
}
