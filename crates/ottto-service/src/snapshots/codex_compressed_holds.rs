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

impl ScanIndexEntry {
    /// Metadata permits only a paced attempt, never publication or an ACK.
    pub(super) fn custody_retry_due(&self, path: &Path) -> bool {
        codex_archive_path(path)
            && self
                .archive
                .as_ref()
                .map_or(true, |a| !a.user_change || a.user_correction_available())
            && (self.codex_compressed_hold.is_some()
                || self
                    .archive
                    .as_ref()
                    .and_then(|a| a.terminal_cause())
                    .is_some())
            && matches!(
                self.codex_compressed_hold
                    .or_else(|| self.archive.as_ref().and_then(|a| a.terminal_cause())),
                Some(
                    CodexZstCause::FamilyUnproven
                        | CodexZstCause::ArchiveEquivalenceUnproven
                        | CodexZstCause::ParentLedgerUnbound
                        | CodexZstCause::OwnerUnproven
                        | CodexZstCause::OutputHeld
                        | CodexZstCause::DecodeFailed
                        | CodexZstCause::HeaderInvalid
                        | CodexZstCause::DecodedOverLimit
                        | CodexZstCause::DecodeBudget
                        | CodexZstCause::SettlementStuck
                        | CodexZstCause::CatchupTooLarge
                        | CodexZstCause::AdmissionRefused
                )
            )
            && self.archive.as_ref().map_or(true, |a| match a.disposition {
                ArchiveDisposition::Pending { retry_after, .. } => {
                    sampled_scan::now_seconds() >= retry_after
                }
                ArchiveDisposition::Acquired | ArchiveDisposition::Empty => false,
                _ => true,
            })
    }
}

impl ScanIndex {
    pub(super) fn release_compressed_hold(&mut self, key: &str) {
        if let Some(cause) = self
            .files
            .get_mut(key)
            .and_then(|e| e.codex_compressed_hold.take())
        {
            self.attribute_codex_blocked(key, BTreeSet::new());
            crate::local_resource_diagnostics::traversal_point(
                "codex_archive_hold_released",
                "codex",
                &BTreeMap::from([(
                    "codex_archive_hold_released",
                    BTreeMap::from([(cause, 1_u64)]),
                )]),
            );
        }
    }
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
        if changed {
            if let Some(archive) = entry.archive.as_mut().filter(|a| {
                matches!(
                    a.disposition,
                    codex_compressed_input::ArchiveDisposition::HeaderValidated
                )
            }) {
                // A newly held header must wait before its first custody retry.
                archive.defer_custody(cause);
            }
        }
        self.codex_state_only_blocked_session_ids
            .extend(owners.iter().cloned());
        self.extend_codex_blocked_attribution(&key, owners);
        if changed {
            crate::local_resource_diagnostics::codex_zst_held(cause);
        }
    }
}
impl codex_file_join::HeaderInventory {
    /// Whole retained roster, paged before the F3 filter. Hashes here are only
    /// negative scope; they never certify membership, ownership or an ACK.
    pub(super) fn prepare_feed_custody(&mut self, index: &ScanIndex) -> bool {
        if !self.prepare_decode_custody(index) {
            return false;
        }
        use std::ops::Bound::{Excluded, Unbounded};
        let after = self.feed_after.as_ref().map_or(Unbounded, Excluded);
        let Some((key, entry)) = index.files.range::<String, _>((after, Unbounded)).next() else {
            return true;
        };
        if entry.codex_compressed_hold.is_some() {
            let owners = index.codex_state_only_blocked_by_file.get(key);
            let binding = entry
                .codex_counting_owner
                .as_deref()
                .filter(|owner| valid_codex_protected_owner(owner));
            if !owners.is_some_and(|owners| !owners.is_empty()) && binding.is_none() {
                self.custody_unknown = true;
            }
            for owner in owners
                .into_iter()
                .flatten()
                .map(|owner| codex_protected_owner(owner))
                .chain(binding.map(str::to_owned))
            {
                if self.absence_held.contains(&owner) {
                    continue;
                }
                let Some(cost) = crate::heap_layout_bound::tree_node_bytes::<String, ()>()
                    .and_then(|cost| cost.checked_add(owner.capacity()))
                    .and_then(|cost| self.feed_peak.checked_add(cost))
                    .filter(|cost| {
                        self.decode_peak
                            .checked_add(*cost)
                            .is_some_and(|total| total <= crate::source_rotation::PARKED_BUDGET / 2)
                    })
                else {
                    self.refuse_custody();
                    break;
                };
                self.feed_peak = cost;
                self.absence_held.insert(owner);
            }
        }
        self.feed_after = Some(key.clone());
        false
    }
    pub(super) fn feed_member_held(&self, path: &Path) -> bool {
        self.feed_member_carrier(path)
            || (self.custody_unknown && is_compressed_codex_rollout(Some(path), None))
    }
    /// GR3 handover: only a known old carrier (or refused custody scratch)
    /// becomes a lasting hold. Unknown-owner raw custody stays fenced and
    /// waits under the existing pending retry instead.
    pub(super) fn feed_member_carrier(&self, path: &Path) -> bool {
        is_compressed_codex_rollout(Some(path), None)
            && (self.custody_refused
                || codex_session_id_candidates_from_path(path)
                    .iter()
                    .any(|owner| self.absence_held.contains(&codex_protected_owner(owner))))
    }
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
            if cost
                .add(OWNER_LOOKUP_SLACK)
                .and_then(|_| cost.add(self.feed_peak))
                .and_then(|_| cost.add(self.decode_peak))
                .is_none()
            {
                self.refuse_custody();
            }
            if index.codex_counting_tombstones.len()
                > codex_counting_version::MAX_COUNTING_TOMBSTONES
                || (!index.codex_counting_tombstones.is_empty()
                    && (crate::heap_layout_bound::tree_nodes::<String, ()>(
                        index.codex_counting_tombstones.len(),
                        &mut cost,
                    )
                    .is_none()
                        || cost
                            .add(index.codex_counting_tombstones.len().saturating_mul(128))
                            .is_none()))
            {
                self.refuse_custody();
            }
            self.custody_peak = cost.bytes;
            if !self.custody_refused {
                for owner in self.held_owners.iter() {
                    let protected = codex_protected_owner(owner);
                    if index.codex_counting_tombstones.contains_key(&protected) {
                        self.absence_held.insert(protected);
                    }
                }
            }
            self.prepare_archive_classification(index);
            self.custody_peak = self.custody_peak.max(self.family_allocation_peak());
            self.mark_validated_families();
        }
        let after = self.custody_after.as_ref().map_or(Unbounded, Excluded);
        if let Some((key, entry)) = index.files.range::<String, _>((after, Unbounded)).next() {
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
    /// A disappeared negative locator can release an unread archive stub.
    /// Accepted carriers and parent debt require an equivalence/parent proof;
    /// neither a name nor an absent file is such proof.
    pub(super) fn release_resolved_archive_holds(&mut self, index: &mut ScanIndex) -> bool {
        if !self.complete
            || !self.classification_ready()
            || self.custody_unknown
            || self.custody_refused
        {
            return false;
        }
        let mut released = false;
        for key in &self.held_archives {
            let Some(entry) = index.files.get(key) else {
                continue;
            };
            let Some(
                CodexZstCause::FamilyUnproven
                | CodexZstCause::ArchiveEquivalenceUnproven
                | CodexZstCause::OwnerUnproven,
            ) = entry.codex_compressed_hold
            else {
                continue;
            };
            if entry.archive.is_some()
                || entry.codex_history_is_protected()
                || entry.last_upload_body_witness.is_some()
                || entry.last_snapshot_fingerprint.is_some()
                || index
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|f| !f.is_empty())
                || index.decode_holds_file(key)
                || self.old_carrier(key)
                || self.archive_class(key).sibling
            {
                continue;
            }
            index.release_compressed_hold(key);
            if let Some(traversal) = index.traversal.as_mut() {
                if let Some(root) = traversal
                    .scan_roots
                    .iter()
                    .filter(|root| Path::new(key).starts_with(root))
                    .max_by_key(|root| root.components().count())
                {
                    traversal.pending_candidates.push_back(ScanTraversalPath {
                        order_modified: None,
                        scan_root: root.clone(),
                        path: PathBuf::from(key),
                        census_member: true,
                        watcher_hint: false,
                    });
                }
            }
            index.mark_bounded_sweep_unsettled();
            released = true;
        }
        if released {
            // The index revision changed: rebuild its negative projections before
            // any parser/cache use. Raw custody and read/attempt budgets survive.
            self.held_archives.retain(|key| {
                index.files.get(key).is_some_and(|e| {
                    e.codex_compressed_hold.is_some()
                        || e.archive.as_ref().is_some_and(|a| {
                            matches!(a.disposition, ArchiveDisposition::Held { .. })
                        })
                })
            });
            self.absence_held = BTreeSet::new();
            self.feed_peak = 0;
            self.held_owners.clear();
            self.custody_unknown = false;
            self.feed_after = None;
            self.feed_prepared = false;
            self.custody_after = None;
            self.custody_next = 0;
            self.custody_peak = 0;
            self.custody_done = false;
            for h in &mut self.headers {
                h.custody_cause = None;
            }
        }
        released
    }

    pub(super) fn mark_custody_owner(&mut self, owner: &str, cause: CodexZstCause) {
        let first = self.headers.partition_point(|h| h.owner.as_str() < owner);
        let last = self.headers.partition_point(|h| h.owner.as_str() <= owner);
        self.mark_custody_range(first, last, cause);
    }
    pub(super) fn mark_custody_range(&mut self, first: usize, last: usize, cause: CodexZstCause) {
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
    pub(super) fn refuse_custody(&mut self) {
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
            // GR3: unknown-owner raw (archive) custody never mints a lasting
            // hold; it stays fenced (`member_held`) and waits for a retry.
            if !self.custody_refused
                && is_compressed_codex_rollout(Some(&header.candidate.path), None)
            {
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
        self.feed_member_held(path)
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
    pub(super) fn plain_twin(&self, path: &Path) -> bool {
        self.headers
            .binary_search_by(|h| h.candidate.path.as_os_str().cmp(path.as_os_str()))
            .is_ok_and(|at| self.headers[at].plain_twin)
    }
}

impl OwnedSourceScan {
    /// Save only negative decisions for the current paused job before another
    /// byte can be read. Never advances accepted extent, fingerprint or ACK.
    pub(crate) fn persist_custody_decisions(
        &mut self,
        committed: &mut ScanIndex,
        path: &Path,
    ) -> Result<()> {
        let _held_counts = crate::local_resource_diagnostics::CodexHeldScope;
        if self.source != SnapshotSource::Codex {
            return Ok(());
        }
        let Some(context) = self.sampling.as_ref() else {
            return Ok(());
        };
        while let Some(transaction) = context.cache.custody_decision_to_save(
            &context.namespace,
            &mut self.index,
            committed,
            path,
        )? {
            let d = transaction.decision.as_ref().expect("owned decision");
            // Charge resident escrow + every staging/rollback/working-copy
            // key, set and node BEFORE cloning or mutating either index.
            use crate::heap_layout_bound::{Counter, HeapLayoutBound};
            let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
            let peak = (|| {
                d.heap_bound(&mut cost)?;
                for _ in 0..4 {
                    d.owners.heap_bound(&mut cost)?;
                    d.veto.heap_bound(&mut cost)?;
                    if let Some(owners) = committed.codex_state_only_blocked_by_file.get(&d.key) {
                        owners.heap_bound(&mut cost)?;
                    }
                    cost.add(d.key.len())?;
                    cost.add(crate::heap_layout_bound::tree_node_bytes::<
                        String,
                        ScanIndexEntry,
                    >()?)?;
                    cost.add(crate::heap_layout_bound::tree_node_bytes::<
                        String,
                        BTreeSet<String>,
                    >()?)?;
                }
                cost.add(16384)?;
                Some(cost.bytes)
            })();
            let _funding = peak
                .and_then(|bytes| transaction.fund(bytes))
                .ok_or_else(|| anyhow::anyhow!("custody negative transaction unfunded"))?;
            let mut owners = committed
                .codex_state_only_blocked_by_file
                .get(&d.key)
                .cloned()
                .unwrap_or_default();
            owners.extend(d.owners.iter().cloned());
            let mut added_veto = BTreeSet::new();
            for owner in d.veto.iter().chain(&d.owners) {
                if !committed
                    .codex_state_only_blocked_session_ids
                    .contains(owner)
                {
                    added_veto.insert(owner.clone());
                }
            }
            let existed = committed.files.contains_key(&d.key);
            let previous = committed
                .files
                .entry(d.key.clone())
                .or_default()
                .codex_compressed_hold;
            committed
                .files
                .get_mut(&d.key)
                .expect("present decision")
                .codex_compressed_hold = Some(d.cause);
            let previous_owners = committed
                .codex_state_only_blocked_by_file
                .insert(d.key.clone(), owners);
            committed
                .codex_state_only_blocked_session_ids
                .extend(added_veto.iter().cloned());
            if let Err(error) = committed.save(path) {
                if existed {
                    committed
                        .files
                        .get_mut(&d.key)
                        .expect("present decision")
                        .codex_compressed_hold = previous;
                } else {
                    committed.files.remove(&d.key);
                }
                if let Some(owners) = previous_owners {
                    committed
                        .codex_state_only_blocked_by_file
                        .insert(d.key.clone(), owners);
                } else {
                    committed.codex_state_only_blocked_by_file.remove(&d.key);
                }
                for owner in &added_veto {
                    committed.codex_state_only_blocked_session_ids.remove(owner);
                }
                // Drop restores the entire pending payload, including owner
                // scope, even if this preparation and its job are then lost.
                return Err(error);
            }
            self.index.generation = committed.generation;
            transaction.complete(&mut self.index);
        }
        Ok(())
    }
}
