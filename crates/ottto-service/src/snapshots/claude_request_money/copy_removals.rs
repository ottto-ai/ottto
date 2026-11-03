//! Stored copy removals (copy-family fix): per Claude
//! file, the request hashes it once removed as copies on an earlier holder's
//! CURRENT census proof, grouped by that holder. A later re-read whose holder
//! proof list has since retired rebuilds the same deduped body instead of
//! restoring the prefix. A holder no longer indexed cannot disprove anything:
//! its group stands, counted (`copy_removal_holder_absent_kept`);
//! only an indexed holder whose census lacks a hash reverts it. Local state
//! (class L): never uploaded, never a wire field.
//!
//! Every decision is stored whole, whatever its size; recorded decisions are
//! never evicted and leave only with their file. Prefix retry debt expires on
//! its third decision pass, across restart.
use crate::snapshots::claude_money_birth_store::LocationKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const HOLD_PASSES: u64 = 3;

/// One file's stored removals: (holder, sorted unique hashes), by holder.
type Groups = Box<[(LocationKey, Box<[u64]>)]>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CopyRemovals {
    /// (file, prefix hold attempts, groups), sorted by key. Empty groups are
    /// allowed only for retry debt. Recorded decisions are never evicted.
    files: Vec<(LocationKey, u64, Groups)>,
    metadata_lost: bool,
}

impl CopyRemovals {
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
    /// Only an empty undamaged store is omitted from the index: an absent
    /// field then reads back as exactly that.
    pub(crate) fn is_unwritten(&self) -> bool {
        self.is_empty() && !self.metadata_lost
    }

    /// Damaged metadata is uncertainty, never fresh ownership; it is written
    /// back even when empty. An absent field is an empty store.
    pub(crate) fn missing() -> Self {
        Self {
            metadata_lost: true,
            ..Self::default()
        }
    }
    pub(crate) fn metadata_lost(&self) -> bool {
        self.metadata_lost
    }
    pub(crate) fn deserialize_lenient<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(serde_json::from_value(value).unwrap_or_else(|_| Self::missing()))
    }
    pub(crate) fn pending(&self, file: LocationKey) -> bool {
        self.files
            .binary_search_by_key(&file, |f| f.0)
            .is_ok_and(|i| self.files[i].1 > 0)
    }
    /// Hold at most two passes; the third emits flagged. No unbounded or
    /// non-discoverable hold is created.
    pub(crate) fn advance_hold(&mut self, file: LocationKey) -> bool {
        match self.files.binary_search_by_key(&file, |f| f.0) {
            Ok(i) => {
                self.files[i].1 = self.files[i].1.saturating_add(1);
                if self.files[i].1 < HOLD_PASSES {
                    return true;
                }
                self.clear_hold(file);
                false
            }
            Err(i) => {
                self.files.insert(i, (file, 1, Box::new([])));
                true
            }
        }
    }
    pub(crate) fn clear_hold(&mut self, file: LocationKey) {
        if let Ok(i) = self.files.binary_search_by_key(&file, |f| f.0) {
            if self.files[i].2.is_empty() {
                self.forget(file);
            } else {
                self.files[i].1 = 0;
            }
        }
    }

    /// `file`'s stored (holder, hashes) groups.
    pub(crate) fn get(&self, file: LocationKey) -> &[(LocationKey, Box<[u64]>)] {
        self.files
            .binary_search_by_key(&file, |f| f.0)
            .map_or(&[], |i| &*self.files[i].2)
    }

    /// Store `file`'s decision whole; returns the hashes newly recorded.
    pub(crate) fn store(
        &mut self,
        file: LocationKey,
        groups: BTreeMap<LocationKey, BTreeSet<u64>>,
    ) -> u64 {
        let groups: Groups = groups
            .into_iter()
            .filter(|(_, h)| !h.is_empty())
            .map(|(holder, hashes)| (holder, hashes.into_iter().collect()))
            .collect();
        let old = self.get(file);
        if *old == *groups {
            return 0;
        }
        let added = groups
            .iter()
            .map(|(holder, hashes)| {
                let prior = old
                    .binary_search_by_key(holder, |(known, _)| *known)
                    .ok()
                    .map(|at| &old[at]);
                hashes
                    .iter()
                    .filter(|hash| !prior.is_some_and(|(_, held)| held.binary_search(hash).is_ok()))
                    .count() as u64
            })
            .sum::<u64>();
        let attempts = self
            .files
            .binary_search_by_key(&file, |f| f.0)
            .map_or(0, |i| self.files[i].1);
        self.replace(file, attempts, groups);
        added
    }

    fn replace(&mut self, file: LocationKey, attempts: u64, groups: Groups) {
        self.forget(file);
        if !groups.is_empty() || attempts > 0 {
            let at = self.files.binary_search_by_key(&file, |f| f.0).unwrap_err();
            self.files.insert(at, (file, attempts, groups));
        }
    }

    /// A proven physical move preserves removed-copy proofs and retry age.
    pub(in crate::snapshots) fn rekey(&mut self, from: LocationKey, to: LocationKey) {
        if from == to {
            return;
        }
        if let Ok(i) = self.files.binary_search_by_key(&from, |f| f.0) {
            let (_, attempts, groups) = self.files.remove(i);
            let mut merged = self
                .get(to)
                .iter()
                .map(|(holder, hashes)| (*holder, hashes.iter().copied().collect::<BTreeSet<_>>()))
                .collect::<BTreeMap<_, _>>();
            for (holder, hashes) in &groups {
                merged
                    .entry(*holder)
                    .or_default()
                    .extend(hashes.iter().copied());
            }
            let attempts = self
                .files
                .binary_search_by_key(&to, |f| f.0)
                .map_or(attempts, |j| attempts.max(self.files[j].1));
            self.replace(
                to,
                attempts,
                merged
                    .into_iter()
                    .map(|(holder, hashes)| (holder, hashes.into_iter().collect()))
                    .collect(),
            );
        }
        // The moved file may also be another copy's holder. Preserve that
        // proof's indexed owner under the new key.
        for (_, _, groups) in &mut self.files {
            if groups.binary_search_by_key(&from, |g| g.0).is_ok() {
                let mut merged = groups
                    .iter()
                    .map(|(holder, hashes)| {
                        (*holder, hashes.iter().copied().collect::<BTreeSet<_>>())
                    })
                    .collect::<BTreeMap<_, _>>();
                let hashes = merged.remove(&from).expect("known holder");
                merged.entry(to).or_default().extend(hashes);
                *groups = merged
                    .into_iter()
                    .map(|(holder, hashes)| (holder, hashes.into_iter().collect()))
                    .collect();
            }
        }
    }

    /// The file left the index: its removals go with it. The one owner is
    /// `ScanIndex::drop_file_entry`; nothing else sweeps stored removals.
    pub(crate) fn forget(&mut self, file: LocationKey) {
        if let Ok(i) = self.files.binary_search_by_key(&file, |f| f.0) {
            self.files.remove(i);
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for CopyRemovals {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let entry = std::mem::size_of::<(LocationKey, u64, Groups)>();
        let group = std::mem::size_of::<(LocationKey, Box<[u64]>)>();
        let mut bytes = self
            .files
            .capacity()
            .checked_mul(entry)?
            .checked_add(std::mem::align_of::<(LocationKey, u64, Groups)>())?;
        for (_, _, groups) in &self.files {
            bytes = bytes.checked_add(groups.len().checked_mul(group)?)?;
            for (_, hashes) in groups.iter() {
                bytes = bytes.checked_add(std::mem::size_of_val(&**hashes))?;
            }
        }
        c.add(bytes)
    }
}

// One versioned binary string, like the birth table: CCR1, file count u32,
// then per file: key 16, store sequence u64, group count u32; per group: holder 16, count u32,
// hashes u64 each. Little endian.
impl Serialize for CopyRemovals {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"CCR2");
        bytes.push(u8::from(self.metadata_lost));
        bytes.extend_from_slice(&(self.files.len() as u32).to_le_bytes());
        for (file, seq, groups) in &self.files {
            bytes.extend_from_slice(&file.to_bytes());
            bytes.extend_from_slice(&seq.to_le_bytes());
            bytes.extend_from_slice(&(groups.len() as u32).to_le_bytes());
            for (holder, hashes) in groups.iter() {
                bytes.extend_from_slice(&holder.to_bytes());
                bytes.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
                for hash in hashes.iter() {
                    bytes.extend_from_slice(&hash.to_le_bytes());
                }
            }
        }
        serializer.collect_str(&base64::display::Base64Display::new(
            &bytes,
            &URL_SAFE_NO_PAD,
        ))
    }
}

impl<'de> Deserialize<'de> for CopyRemovals {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        decode(&encoded).ok_or_else(|| serde::de::Error::custom("invalid copy removals"))
    }
}

fn decode(encoded: &str) -> Option<CopyRemovals> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let mut input = bytes.as_slice();
    fn take<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
        let value = input.get(..N)?.try_into().ok()?;
        *input = &input[N..];
        Some(value)
    }
    let count = |input: &mut &[u8], unit: usize| {
        let n = u32::from_le_bytes(take(input)?) as usize;
        (n > 0 && n <= input.len() / unit).then_some(n)
    };
    let version = take::<4>(&mut input)?;
    if &version != b"CCR1" && &version != b"CCR2" {
        return None;
    }
    let metadata_lost = if &version == b"CCR2" {
        match take::<1>(&mut input)?[0] {
            0 => false,
            1 => true,
            _ => return None,
        }
    } else {
        false
    };
    let files = u32::from_le_bytes(take(&mut input)?) as usize;
    if files > input.len() / 28 {
        return None;
    }
    let mut removals = CopyRemovals {
        files: Vec::with_capacity(files),
        metadata_lost,
    };
    for _ in 0..files {
        let file = LocationKey::from_bytes(take(&mut input)?);
        let seq = u64::from_le_bytes(take(&mut input)?);
        let seq = if &version == b"CCR1" { 0 } else { seq };
        if seq >= HOLD_PASSES {
            return None;
        }
        let group_count = u32::from_le_bytes(take(&mut input)?) as usize;
        if group_count > input.len() / 28 || (group_count == 0 && seq == 0) {
            return None;
        }
        let mut groups = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            let holder = LocationKey::from_bytes(take(&mut input)?);
            let n = count(&mut input, 8)?;
            let hashes = (0..n)
                .map(|_| take(&mut input).map(u64::from_le_bytes))
                .collect::<Option<Box<[u64]>>>()?;
            if !hashes.windows(2).all(|w| w[0] < w[1]) {
                return None;
            }
            groups.push((holder, hashes));
        }
        if !groups.windows(2).all(|w| w[0].0 < w[1].0)
            || removals.files.last().is_some_and(|last| last.0 >= file)
        {
            return None;
        }
        removals.files.push((file, seq, groups.into_boxed_slice()));
    }
    input.is_empty().then_some(removals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::claude_money_birth_store::location_key;

    fn groups(entries: &[(&str, &[u64])]) -> BTreeMap<LocationKey, BTreeSet<u64>> {
        entries
            .iter()
            .map(|(holder, hashes)| (location_key(holder), hashes.iter().copied().collect()))
            .collect()
    }

    fn reload(state: &CopyRemovals) -> CopyRemovals {
        serde_json::from_str(&serde_json::to_string(state).unwrap()).unwrap()
    }

    #[test]
    fn copy_removals_round_trip_and_replace() {
        let mut removals = CopyRemovals::default();
        let file = location_key("copy");
        assert_eq!(
            removals.store(file, groups(&[("h1", &[3, 1]), ("h2", &[9])])),
            3
        );
        // The same decision again changes nothing and adds nothing.
        assert_eq!(
            removals.store(file, groups(&[("h1", &[1, 3]), ("h2", &[9])])),
            0
        );
        let back = reload(&removals);
        assert_eq!(back, removals);
        assert_eq!(back.get(file)[0].1.as_ref(), &[1, 3]);
        // A replacement adds only hashes not held before.
        assert_eq!(removals.store(file, groups(&[("h1", &[1, 3, 4])])), 1);
        removals.forget(file);
        assert!(removals.is_empty());
    }

    /// [money] A decision past the former 4 MiB store bound is stored whole
    /// and survives restart; nothing is left unrecorded, and a later
    /// disproof still removes exactly the disproven hashes.
    #[test]
    fn copy_removal_past_4mib_is_stored() {
        let mut removals = CopyRemovals::default();
        let (first, second) = (location_key("first"), location_key("second"));
        // 4 MiB of 8-byte hashes, plus one: past the deleted bound alone.
        let huge = (0..(4 * 1024 * 1024 / 8 + 1) as u64).collect::<Vec<_>>();
        assert_eq!(
            removals.store(first, groups(&[("h", &huge)])),
            huge.len() as u64
        );
        assert_eq!(
            removals.store(second, groups(&[("h", &huge)])),
            huge.len() as u64
        );
        let mut state = reload(&removals);
        assert_eq!(state, removals);
        assert_eq!(state.get(first)[0].1.as_ref(), huge.as_slice());
        assert_eq!(state.get(second)[0].1.as_ref(), huge.as_slice());
        assert_eq!(state.store(first, groups(&[("h", &huge[1..])])), 0);
        let state = reload(&state);
        assert_eq!(state.get(first)[0].1.as_ref(), &huge[1..]);
        assert_eq!(state.get(second)[0].1.len(), huge.len());
    }

    #[test]
    fn prefix_hold_attempts_survive_restart_and_expire_on_third_pass() {
        let file = location_key("copy");
        let mut state = CopyRemovals::missing();
        for pass in 1..=HOLD_PASSES {
            assert_eq!(state.advance_hold(file), pass < HOLD_PASSES);
            assert_eq!(state.pending(file), pass < HOLD_PASSES);
            state = reload(&state);
            assert!(state.metadata_lost());
        }
        assert!(state.is_empty());
    }

    /// [money] A whole-body-held new file's hold debt survives pages and
    /// restarts until it expires or its source is removed (`forget`).
    #[test]
    fn held_new_file_debt_survives_pages_and_restart() {
        let file = location_key("new-held-file");
        let mut state = CopyRemovals::default();
        for pass in 1..=HOLD_PASSES {
            assert_eq!(state.advance_hold(file), pass < HOLD_PASSES);
            // A page without a settled entry for the whole-body-held new file
            // does not touch its debt: no sweep exists.
            state = reload(&state);
            assert_eq!(state.pending(file), pass < HOLD_PASSES);
        }
        assert!(state.is_empty());
        assert!(state.advance_hold(file));
        state.forget(file); // ordinary confirmed source-removal path
        assert!(!state.pending(file));
        assert!(state.is_empty());
    }

    #[test]
    fn many_holder_groups_allow_a_small_update() {
        let file = location_key("many-holder-file");
        let mut groups = (0..65_000u64)
            .map(|n| (location_key(&format!("holder-{n}")), BTreeSet::from([n])))
            .collect::<BTreeMap<_, _>>();
        let mut state = CopyRemovals::default();
        assert_eq!(state.store(file, groups.clone()), 65_000);
        groups.values_mut().next().unwrap().insert(65_001);
        assert_eq!(state.store(file, groups), 1);
        assert_eq!(state.get(file).len(), 65_000);
    }

    #[test]
    fn copy_removals_reject_damaged_text() {
        for text in ["\"\"", "\"Q0NSMg\"", "1"] {
            assert!(
                serde_json::from_str::<CopyRemovals>(text).is_err(),
                "{text}"
            );
        }
        let mut removals = CopyRemovals::default();
        removals.store(location_key("copy"), groups(&[("h", &[1, 2])]));
        let mut bytes = URL_SAFE_NO_PAD
            .decode(serde_json::to_string(&removals).unwrap().trim_matches('"'))
            .unwrap();
        bytes.push(0);
        let trailing = format!("\"{}\"", URL_SAFE_NO_PAD.encode(&bytes));
        assert!(serde_json::from_str::<CopyRemovals>(&trailing).is_err());
    }
}
