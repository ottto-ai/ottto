//! Dedicated non-red custody; no acquisition or ACK authority.
use super::*;

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
        if self.custody_after.is_none() {
            self.headers.sort_unstable_by(|a, b| a.owner.cmp(&b.owner));
            // Fixed cursor/temporary slack: no historical population allocation.
            let mut cost =
                crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
            if cost.add(16384).is_none() {
                self.refuse_custody();
            }
            self.custody_peak = cost.bytes;
        }
        let after = self.custody_after.as_ref().map_or(Unbounded, Excluded);
        if let Some((key, entry)) = index.files.range((after, Unbounded)).next() {
            if let Some(cause) = entry.codex_compressed_hold {
                let owners = index.codex_state_only_blocked_by_file.get(key);
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
                    self.mark_custody_owner(owner, cause);
                }
            }
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
        if first == last {
            return;
        }
        if self.headers[first].custody_cause.is_none() && !self.custody_refused {
            match self.owner_peak(first, last, owner) {
                Some(peak) => self.custody_peak = peak,
                None => self.refuse_custody(),
            }
        }
        for header in &mut self.headers[first..last] {
            header.custody_cause = Some(cause);
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
        }
    }
    pub(super) fn hold_custodied_siblings(&mut self, index: &mut ScanIndex) -> bool {
        let Some(header) = self.headers.get(self.custody_next) else {
            return true;
        };
        if let Some(cause) = header.custody_cause {
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
                .is_ok_and(|at| self.headers[at].custody_cause.is_some())
    }
}
