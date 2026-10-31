//! Compact, exclusively owned comparison descriptors. No mutable value handles
//! escape: each insert/remove accounts the changed leaf, and moves transfer the
//! one buffer and its charge. This is not a summary of an arbitrary scan graph.
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use std::mem::size_of;

// Closed list: adding a descriptor requires its exhaustive HeapLayoutBound
// implementation. A leaf is bounded independently BEFORE a container mutation;
// nested descriptor maps supply their own exclusively owned allocation charge.
pub(super) trait Leaf: HeapLayoutBound {
    fn leaf_bytes(&self) -> Option<usize> {
        let mut counter = Counter::new(usize::MAX);
        self.heap_bound(&mut counter)?;
        Some(counter.bytes)
    }
}
impl Leaf for () {}
impl Leaf for String {}
impl Leaf for super::NormalSkip {}
impl Leaf for super::NativeCorrection {}
impl Leaf for super::WindowRoot {
    fn leaf_bytes(&self) -> Option<usize> {
        let Self { proof, certified } = self;
        proof.capacity().checked_add(certified.owned_bytes()?)
    }
}

#[derive(Debug)]
pub(super) struct Map<V: Leaf> {
    entries: Vec<(String, V)>,
    leaf_bytes: Option<usize>,
}
impl<V: Leaf> Default for Map<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            leaf_bytes: Some(0),
        }
    }
}
impl<V: Leaf> Map<V> {
    pub(super) fn accounted(&self) -> bool {
        self.owned_bytes().is_some()
    }
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn position(&self, key: &str) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|(saved, _)| saved.as_str().cmp(key))
    }
    pub(super) fn get<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<&V> {
        self.position(key.as_ref()).ok().map(|i| &self.entries[i].1)
    }
    pub(super) fn contains_key<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> bool {
        self.position(key.as_ref()).is_ok()
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&String, &V)> + Clone {
        self.entries.iter().map(|(key, value)| (key, value))
    }
    pub(super) fn keys(&self) -> impl Iterator<Item = &String> + Clone {
        self.entries.iter().map(|(key, _)| key)
    }
    pub(super) fn into_values(self) -> impl Iterator<Item = V> {
        self.entries.into_iter().map(|(_, value)| value)
    }
    /// Consume the summary together with its one owned buffer. Mutable leaves
    /// cannot invalidate a surviving cached charge because this map is moved.
    pub(super) fn into_entries(self) -> Vec<(String, V)> {
        self.entries
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &V> + Clone {
        self.entries.iter().map(|(_, value)| value)
    }
    fn leaf(key: &String, value: &V) -> Option<usize> {
        let mut c = Counter::new(usize::MAX);
        key.heap_bound(&mut c)?;
        c.add(value.leaf_bytes()?)?;
        Some(c.bytes)
    }
    fn next_capacity(&self) -> Option<usize> {
        if self.entries.len() < self.entries.capacity() {
            return Some(self.entries.capacity());
        }
        if self.entries.capacity() == 0 {
            // Most retained families have one certified transcript. Do not
            // reserve four complete path/stat descriptors for a singleton.
            Some(1)
        } else {
            self.entries.capacity().checked_mul(2)
        }
    }
    /// Additional simultaneous buffer while the old buffer remains live. Leaf
    /// strings/candidate clones are paid separately by the producing caller.
    pub(super) fn growth_peak(&self) -> Option<usize> {
        self.leaf_bytes?;
        if self.entries.len() < self.entries.capacity() {
            return Some(0);
        }
        self.next_capacity()?.checked_mul(size_of::<(String, V)>())
    }
    pub(super) fn merge_buffer_peak(&self, additional: usize) -> Option<usize> {
        self.leaf_bytes?;
        let length = self.len().checked_add(additional)?;
        if length <= self.entries.capacity() {
            return Some(0);
        }
        length.checked_mul(size_of::<(String, V)>())
    }
    /// Caller has paid merge_buffer_peak while the old buffer is live. Leaves
    /// move from the imported owner; this reserves only destination slots.
    pub(super) fn reserve_merge(&mut self, additional: usize) -> Option<()> {
        self.leaf_bytes?;
        let length = self.len().checked_add(additional)?;
        if length > self.entries.capacity() {
            self.entries.try_reserve_exact(additional).ok()?;
        }
        Some(())
    }
    pub(super) fn insert(&mut self, key: String, value: V) -> Option<V> {
        let position = self.position(&key);
        let charge = Self::leaf(&key, &value);
        let old = position
            .ok()
            .and_then(|i| Self::leaf(&self.entries[i].0, &self.entries[i].1));
        let next = self
            .leaf_bytes
            .and_then(|bytes| bytes.checked_sub(old.unwrap_or(0))?.checked_add(charge?));
        // Unknown/overflow is sticky. No descriptor is exposed from an
        // unaccounted insertion; the enclosing admission then refuses it.
        if next.is_none() {
            self.leaf_bytes = None;
            return None;
        }
        match position {
            Ok(i) => {
                let (_, previous) = std::mem::replace(&mut self.entries[i], (key, value));
                self.leaf_bytes = next;
                Some(previous)
            }
            Err(i) => {
                if self.entries.len() == self.entries.capacity() {
                    let Some(capacity) = self.next_capacity() else {
                        self.leaf_bytes = None;
                        return None;
                    };
                    if self
                        .entries
                        .try_reserve_exact(capacity - self.entries.len())
                        .is_err()
                    {
                        self.leaf_bytes = None;
                        return None;
                    }
                }
                self.entries.insert(i, (key, value));
                self.leaf_bytes = next;
                None
            }
        }
    }
    pub(super) fn remove<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<V> {
        let i = self.position(key.as_ref()).ok()?;
        let (key, value) = self.entries.remove(i);
        self.leaf_bytes = self
            .leaf_bytes
            .and_then(|bytes| bytes.checked_sub(Self::leaf(&key, &value)?));
        Some(value)
    }
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&String, &V) -> bool) {
        self.entries.retain(|(key, value)| {
            if keep(key, value) {
                return true;
            }
            self.leaf_bytes = self
                .leaf_bytes
                .and_then(|bytes| bytes.checked_sub(Self::leaf(key, value)?));
            false
        });
    }
    pub(super) fn clear(&mut self) {
        // The previous tree clear released its nodes. Release the compact
        // buffer too when qualification takes ownership of the descriptors.
        self.entries = Vec::new();
        // Refusal is sticky until this entire owner is dropped/replaced.
        self.leaf_bytes = self.leaf_bytes.map(|_| 0);
    }
    pub(super) fn extend(&mut self, values: impl IntoIterator<Item = (String, V)>) {
        for (key, value) in values {
            self.insert(key, value);
        }
    }
    fn owned_bytes(&self) -> Option<usize> {
        self.entries
            .capacity()
            .checked_mul(size_of::<(String, V)>())?
            .checked_add(self.leaf_bytes?)
    }
    #[cfg(test)]
    fn diagnostic_bytes(&self) -> Option<usize> {
        // Independent full reference walk, never used for admission. Each leaf
        // gets the ordinary bounded walk; no lookup of cached leaf_bytes.
        self.entries.iter().try_fold(
            self.entries
                .capacity()
                .checked_mul(size_of::<(String, V)>())?,
            |bytes, (key, value)| bytes.checked_add(Self::leaf(key, value)?),
        )
    }
}
impl<V: Leaf + Clone> Clone for Map<V> {
    fn clone(&self) -> Self {
        let mut result: Self = self
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if self.leaf_bytes.is_none() {
            result.leaf_bytes = None;
        }
        result
    }
}
impl<V: Leaf> FromIterator<(String, V)> for Map<V> {
    fn from_iter<T: IntoIterator<Item = (String, V)>>(items: T) -> Self {
        let mut result = Self::default();
        result.extend(items);
        result
    }
}
impl<V: Leaf> IntoIterator for Map<V> {
    type Item = (String, V);
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
impl<'a, V: Leaf> IntoIterator for &'a Map<V> {
    type Item = (&'a String, &'a V);
    type IntoIter =
        std::iter::Map<std::slice::Iter<'a, (String, V)>, fn(&'a (String, V)) -> Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(key, value)| (key, value))
    }
}
impl<V: Leaf> HeapLayoutBound for Map<V> {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        if !heap_layout_bound::layout_supported() {
            return None;
        }
        c.add(self.owned_bytes()?)
    }
}

#[derive(Debug, Default, Clone)]
pub(super) struct Set(Map<()>);
impl Set {
    pub(super) fn accounted(&self) -> bool {
        self.0.accounted()
    }
    pub(super) fn insert(&mut self, key: String) -> bool {
        let fresh = !self.contains(&key);
        self.0.insert(key, ());
        fresh
    }
    pub(super) fn contains<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> bool {
        self.0.contains_key(key)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = &String> + Clone {
        self.0.keys()
    }
    pub(super) fn extend(&mut self, items: impl IntoIterator<Item = String>) {
        for key in items {
            self.insert(key);
        }
    }
    pub(super) fn growth_peak(&self) -> Option<usize> {
        self.0.growth_peak()
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
    pub(super) fn merge_buffer_peak(&self, additional: usize) -> Option<usize> {
        self.0.merge_buffer_peak(additional)
    }
    pub(super) fn reserve_merge(&mut self, additional: usize) -> Option<()> {
        self.0.reserve_merge(additional)
    }
}
impl FromIterator<String> for Set {
    fn from_iter<T: IntoIterator<Item = String>>(items: T) -> Self {
        let mut result = Self::default();
        result.extend(items);
        result
    }
}
impl IntoIterator for Set {
    type Item = String;
    type IntoIter = std::iter::Map<std::vec::IntoIter<(String, ())>, fn((String, ())) -> String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter().map(|(key, ())| key)
    }
}
impl HeapLayoutBound for Set {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.heap_bound(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn assert_reference<V: Leaf>(map: &Map<V>) {
        assert_eq!(map.owned_bytes(), map.diagnostic_bytes());
        let charged = heap_layout_bound::bound(map, usize::MAX);
        if heap_layout_bound::layout_supported() {
            assert_eq!(
                charged,
                map.diagnostic_bytes()
                    .and_then(|bytes| bytes.checked_add(size_of::<Map<V>>()))
            );
        } else {
            assert!(charged.is_none());
        }
    }
    #[test]
    fn native_comparison_metadata_mutations_move_restore_and_refusal_match_reference() {
        let mut map = Map::<String>::default();
        for i in 0..2043 {
            let mut key = String::with_capacity(48);
            key.push_str(&format!("key-{i:05}"));
            let mut value = String::with_capacity(96);
            value.push_str("revision");
            map.insert(key, value);
            assert_reference(&map);
        }
        let peak = map.growth_peak().unwrap();
        assert_eq!(peak, 0); // spare capacity is still charged
        let clone = map.clone();
        assert_reference(&clone);
        assert!(clone.owned_bytes().unwrap() < map.owned_bytes().unwrap());
        map.insert("key-00003".into(), "replacement".repeat(24));
        map.remove("key-00004");
        assert_reference(&map);
        map.retain(|key, _| key.ends_with('0'));
        assert_reference(&map);
        let restored = std::mem::take(&mut map);
        assert_reference(&map);
        assert_reference(&restored);
        let mut restored = restored;
        restored.clear();
        assert_reference(&restored);
        assert_eq!(restored.owned_bytes(), Some(0)); // no dead buffer after resume
        restored.leaf_bytes = Some(usize::MAX);
        restored.insert("overflow".into(), "not installed".into());
        assert!(restored.leaf_bytes.is_none());
        assert!(restored.get("overflow").is_none());
        assert!(heap_layout_bound::bound(&restored, usize::MAX).is_none());
        restored.clear();
        assert!(restored.leaf_bytes.is_none());
    }
    #[test]
    fn native_comparison_metadata_unknown_revocation_cannot_leave_active_eligibility() {
        let mut phase = super::super::NativePhase::default();
        assert!(phase.capture_active());
        phase.correction_revoked_keys.0.leaf_bytes = None;
        assert!(!phase.capture_active());
        assert!(!phase.pause_before_finalization());
        let mut window = super::super::WindowEligibility {
            census_window_end: "window".into(),
            roots: Map::default(),
            revoked_roots: Set::default(),
            native_corrections: Map::default(),
            correction_revoked_keys: Set::default(),
            correction_forbidden_roots: Set::default(),
        };
        assert!(window.accounted());
        window.revoked_roots.0.leaf_bytes = None;
        assert!(!window.accounted());
        assert!(!super::super::NativePhase::default().import_window(
            Some(Box::new(window)),
            &Default::default(),
            "window"
        ));
    }
    #[test]
    fn native_comparison_metadata_retained_nested_window_has_independent_full_charge() {
        use super::super::{CandidateFile, NormalSkip, WindowRoot};
        use std::path::PathBuf;
        let mut roots = Map::<WindowRoot>::default();
        for i in 0..2043 {
            let root = format!("family-{i:05}");
            let path = PathBuf::from(format!("/synthetic/{root}.jsonl"));
            let candidate = CandidateFile {
                physical_identity: None,
                scan_root: PathBuf::from("/synthetic"),
                path: path.clone(),
                size_bytes: 1,
                modified_unix_seconds: 2,
                modified_unix_nanos: 3,
                source_file_fingerprint: "revision".into(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: "descriptor-only".into(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
                fingerprint_opened_identity: String::new(),
                withheld_content_stamp: None,
            };
            roots.insert(
                root.clone(),
                WindowRoot {
                    proof: "proof".into(),
                    certified: std::iter::once((
                        path.to_str().unwrap().to_owned(),
                        NormalSkip {
                            root: root.clone(),
                            member: root,
                            revision: "revision".into(),
                            census_window_end: "window".into(),
                            upload_context: Some("context".into()),
                            candidate,
                        },
                    ))
                    .collect(),
                },
            );
        }
        // Walk every nested string, candidate and leaf independently. This
        // intentionally exceeds 4096 total visits, is test-only, and cannot
        // grant admission. No cached nested-map charge is used here.
        let mut reference = roots.entries.capacity() * size_of::<(String, WindowRoot)>();
        for (key, value) in roots.iter() {
            reference += key.capacity() + value.proof.capacity();
            reference += value.certified.entries.capacity() * size_of::<(String, NormalSkip)>();
            for (key, skip) in value.certified.iter() {
                let mut leaf = Counter::new(usize::MAX);
                key.heap_bound(&mut leaf).unwrap();
                skip.heap_bound(&mut leaf).unwrap();
                reference += leaf.bytes;
            }
        }
        assert_eq!(roots.owned_bytes(), Some(reference));
        if heap_layout_bound::layout_supported() {
            assert_eq!(
                heap_layout_bound::bound(&roots, usize::MAX),
                Some(reference + size_of::<Map<WindowRoot>>())
            );
        } else {
            assert!(heap_layout_bound::bound(&roots, usize::MAX).is_none());
        }
        let moved = std::mem::take(&mut roots);
        assert!(roots.is_empty());
        assert_eq!(moved.owned_bytes(), Some(reference));
        eprintln!("native metadata independent nested reference: roots=2043 heap_bytes={reference} moved_once=true diagnostic_only=true");
    }
    #[test]
    fn native_comparison_metadata_growth_accounts_old_and_new_buffers_before_allocation() {
        let mut map = Map::<String>::default();
        let peak = map.growth_peak().unwrap();
        assert_eq!(peak, size_of::<(String, String)>());
        let before = map.owned_bytes().unwrap();
        let budget = before + peak - 1;
        assert!(before.checked_add(peak).unwrap() > budget);
        assert!(map.is_empty()); // producer refuses before insert/reserve
        for i in 0..4 {
            map.insert(i.to_string(), "v".into());
        }
        let before = map.owned_bytes().unwrap();
        let growth = map.growth_peak().unwrap();
        assert_eq!(growth, 8 * size_of::<(String, String)>());
        map.insert("4".into(), "v".into());
        assert_reference(&map);
        assert!(before + growth >= map.owned_bytes().unwrap());
    }
}
