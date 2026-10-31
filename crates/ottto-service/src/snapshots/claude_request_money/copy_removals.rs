//! Stored copy removals (copy-family fix, Lead B Addendum 1): per Claude
//! file, the request hashes it once removed as copies on an earlier holder's
//! CURRENT census proof, grouped by that holder. A later re-read whose holder
//! proof list has since retired rebuilds the same deduped body instead of
//! restoring the prefix. A holder no longer indexed cannot disprove anything:
//! its group stands, counted (`copy_removal_holder_absent_kept`, Lead B F5);
//! only an indexed holder whose census lacks a hash reverts it. Local state
//! (class L): never uploaded, never a wire field.
//!
//! Bounded by `MAX_BYTES` of charged state: 40 bytes per file, 32 per holder
//! group and 8 per hash (about 520k hashes when dense; the encoded index text
//! is at most 4/3 of the raw bytes, which are smaller than the charge). A
//! decision past the cap is not stored and is counted
//! (`copy_removed_unrecorded`, alarmed); proof still removes the copy.
//! Recorded decisions are never evicted. Prefix retry debt shares the cap
//! (40 bytes/file) and expires on its third decision pass, across restart.
use crate::snapshots::claude_money_birth_store::LocationKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_BYTES: usize = 4 * 1024 * 1024;
const FILE_BYTES: usize = 40;
pub(crate) const HOLD_PASSES: u64 = 3;
const GROUP_BYTES: usize = 32;
const HASH_BYTES: usize = 8;

/// One file's stored removals: (holder, sorted unique hashes), by holder.
type Groups = Box<[(LocationKey, Box<[u64]>)]>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CopyRemovals {
    /// (file, prefix hold attempts, groups), sorted by key. Empty groups are
    /// allowed only for retry debt. Recorded decisions are never evicted.
    files: Vec<(LocationKey, u64, Groups)>,
    /// The charged bytes of `files` (see `charge`).
    bytes: usize,
    metadata_lost: bool,
}

/// What one `store` did, in hashes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stored {
    /// Hashes newly recorded for the file.
    pub(crate) added: u64,
    /// Hashes of the new decision refused by the cap. Existing decisions
    /// stay recorded; current proof still removes the unrecorded copies.
    pub(crate) overflow: u64,
}

fn charge(groups: &[(LocationKey, Box<[u64]>)]) -> usize {
    if groups.is_empty() {
        return 0;
    }
    groups.iter().fold(FILE_BYTES, |bytes, (_, hashes)| {
        bytes + GROUP_BYTES + HASH_BYTES * hashes.len()
    })
}

impl CopyRemovals {
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
    /// Only an empty undamaged store is omitted from the index: an absent
    /// field then reads back as exactly that (Lead B F4). Switch off keeps
    /// the released bytes: an empty store is never written.
    pub(crate) fn is_unwritten(&self) -> bool {
        self.is_empty() && (!self.metadata_lost || !super::e2::resumed_prefix_enabled())
    }

    /// The charged bytes held now (at most `MAX_BYTES`).
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Damaged metadata is uncertainty, never fresh ownership; it is written
    /// back even when empty. An absent field is an empty store (Lead B F4).
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
    /// Hold at most two passes; the third emits flagged. A full debt store
    /// expires immediately. No unbounded or non-discoverable hold is created.
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
            Err(i) if self.bytes + FILE_BYTES <= MAX_BYTES => {
                self.files.insert(i, (file, 1, Box::new([])));
                self.bytes += FILE_BYTES;
                true
            }
            Err(_) => false,
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

    /// Refuse new durable decisions past the shared cap; never evict an
    /// existing decision. A refusal is a counted/alarmed unrecorded removal.
    pub(crate) fn store(
        &mut self,
        file: LocationKey,
        groups: BTreeMap<LocationKey, BTreeSet<u64>>,
    ) -> Stored {
        let groups: Groups = groups
            .into_iter()
            .filter(|(_, h)| !h.is_empty())
            .map(|(holder, hashes)| (holder, hashes.into_iter().collect()))
            .collect();
        let old = self.get(file);
        if *old == *groups {
            return Stored::default();
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
        let old_bytes = charge(old).max(if attempts > 0 { FILE_BYTES } else { 0 });
        let new_bytes = charge(&groups).max(if attempts > 0 { FILE_BYTES } else { 0 });
        if self.bytes - old_bytes + new_bytes > MAX_BYTES {
            // Disproof is not admission: persist deletions even if the new
            // proofs cannot fit. Keep only exact validated holder/hash pairs,
            // so a transferred hash never keeps its obsolete holder as proof.
            let kept: Groups = old
                .iter()
                .filter_map(|(holder, hashes)| {
                    let desired = &groups[groups
                        .binary_search_by_key(holder, |(known, _)| *known)
                        .ok()?];
                    let kept = hashes
                        .iter()
                        .copied()
                        .filter(|hash| desired.1.binary_search(hash).is_ok())
                        .collect::<Box<[u64]>>();
                    (!kept.is_empty()).then_some((*holder, kept))
                })
                .collect();
            self.replace(file, attempts, kept);
            return Stored {
                added: 0,
                overflow: added,
            };
        }
        self.replace(file, attempts, groups);
        Stored { added, overflow: 0 }
    }

    fn replace(&mut self, file: LocationKey, attempts: u64, groups: Groups) {
        let bytes = charge(&groups).max(if attempts > 0 { FILE_BYTES } else { 0 });
        self.forget(file);
        if !groups.is_empty() || attempts > 0 {
            let at = self.files.binary_search_by_key(&file, |f| f.0).unwrap_err();
            self.files.insert(at, (file, attempts, groups));
            self.bytes += bytes;
        }
    }

    /// A proven physical move preserves removed-copy proofs and retry age.
    /// Combining two existing entries cannot exceed their already admitted charge.
    pub(in crate::snapshots) fn rekey(&mut self, from: LocationKey, to: LocationKey) {
        if from == to {
            return;
        }
        if let Ok(i) = self.files.binary_search_by_key(&from, |f| f.0) {
            let (_, attempts, groups) = self.files.remove(i);
            self.bytes -= charge(&groups).max(FILE_BYTES);
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
        // proof's indexed owner instead of letting retain_files orphan it.
        for (_, _, groups) in &mut self.files {
            if groups.binary_search_by_key(&from, |g| g.0).is_ok() {
                let before = charge(groups);
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
                self.bytes -= before - charge(groups);
            }
        }
    }

    /// The file is no longer indexed: its removals go with it.
    pub(crate) fn forget(&mut self, file: LocationKey) {
        if let Ok(i) = self.files.binary_search_by_key(&file, |f| f.0) {
            self.bytes -= charge(&self.files[i].2).max(FILE_BYTES);
            self.files.remove(i);
        }
    }

    /// Keep only files `live` still indexes (every removal path included).
    pub(crate) fn retain_files(&mut self, live: impl Fn(LocationKey) -> bool) {
        let mut bytes = self.bytes;
        self.files.retain(|(file, attempts, groups)| {
            // Whole-body-held new files are absent from the settled files
            // map. Their debt is not absence evidence; only explicit source
            // removal (`forget`) or a decision may clear their attempts.
            let keep = *attempts > 0 || live(*file);
            if !keep {
                bytes -= charge(groups).max(FILE_BYTES);
            }
            keep
        });
        self.bytes = bytes;
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
        let mut bytes = Vec::with_capacity(8 + self.bytes);
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
    // The raw bytes never exceed the charge, so the cap bounds the text too.
    if encoded.len() > (8 + MAX_BYTES) / 3 * 4 + 4 {
        return None;
    }
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
        bytes: 0,
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
        removals.bytes += charge(&groups).max(FILE_BYTES);
        if removals.bytes > MAX_BYTES {
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

    #[test]
    fn copy_removals_round_trip_and_replace() {
        let mut removals = CopyRemovals::default();
        let file = location_key("copy");
        let first = removals.store(file, groups(&[("h1", &[3, 1]), ("h2", &[9])]));
        assert_eq!(
            first,
            Stored {
                added: 3,
                overflow: 0
            }
        );
        assert_eq!(
            removals.bytes(),
            FILE_BYTES + 2 * GROUP_BYTES + 3 * HASH_BYTES
        );
        // The same decision again changes nothing and adds nothing.
        let again = removals.store(file, groups(&[("h1", &[1, 3]), ("h2", &[9])]));
        assert_eq!(again, Stored::default());
        let text = serde_json::to_string(&removals).unwrap();
        let back: CopyRemovals = serde_json::from_str(&text).unwrap();
        assert_eq!(back, removals);
        assert_eq!(back.get(file)[0].1.as_ref(), &[1, 3]);
        // A replacement adds only hashes not held before.
        let next = removals.store(file, groups(&[("h1", &[1, 3, 4])]));
        assert_eq!(
            next,
            Stored {
                added: 1,
                overflow: 0
            }
        );
        removals.forget(file);
        assert!(removals.is_empty());
        assert_eq!(removals.bytes(), 0);
    }

    #[test]
    fn copy_removals_over_the_cap_keep_the_old_entry_and_count_overflow() {
        let mut removals = CopyRemovals::default();
        let file = location_key("copy");
        removals.store(file, groups(&[("h", &[1])]));
        let huge = (0..(MAX_BYTES / HASH_BYTES) as u64).collect::<Vec<_>>();
        let refused = removals.store(file, groups(&[("h", &huge)]));
        assert_eq!(refused.added, 0);
        assert_eq!(refused.overflow, huge.len() as u64 - 1);
        assert_eq!(removals.get(file)[0].1.as_ref(), &[1]);
    }

    #[test]
    fn copy_removals_refuse_new_files_without_evicting_recorded_removals() {
        let half = (0..(MAX_BYTES / HASH_BYTES / 2) as u64).collect::<Vec<_>>();
        let run = || {
            let mut removals = CopyRemovals::default();
            let (first, second, third) = (
                location_key("first"),
                location_key("second"),
                location_key("third"),
            );
            assert_eq!(removals.store(first, groups(&[("h", &half)])).overflow, 0);
            assert_eq!(
                removals.store(second, groups(&[("h", &[1, 2])])).overflow,
                0
            );
            let stored = removals.store(third, groups(&[("h", &half)]));
            assert_eq!(
                stored.overflow,
                half.len() as u64,
                "the new decision is refused and counted"
            );
            assert_eq!(removals.get(first)[0].1.as_ref(), half.as_slice());
            assert!(removals.get(third).is_empty());
            assert_eq!(removals.get(second)[0].1.as_ref(), &[1, 2]);
            assert!(removals.bytes() <= MAX_BYTES);
            removals
        };
        // Deterministic: the same decisions give the same state.
        assert_eq!(run(), run());
    }

    #[test]
    fn copy_removals_keep_only_indexed_files() {
        let mut removals = CopyRemovals::default();
        let (kept, gone) = (location_key("kept"), location_key("gone"));
        removals.store(kept, groups(&[("h", &[1])]));
        removals.store(gone, groups(&[("h", &[2, 3])]));
        removals.retain_files(|file| file == kept);
        assert!(removals.get(gone).is_empty());
        assert_eq!(removals.bytes(), FILE_BYTES + GROUP_BYTES + HASH_BYTES);
    }

    #[test]
    fn capacity_refusal_never_preserves_a_disproven_removal() {
        let mut state = CopyRemovals::default();
        let file = location_key("copy");
        state.store(file, groups(&[("holder", &[1])]));
        let filler =
            (0..((MAX_BYTES - (FILE_BYTES + GROUP_BYTES + HASH_BYTES) - FILE_BYTES - GROUP_BYTES)
                / HASH_BYTES) as u64)
                .collect::<Vec<_>>();
        state.store(
            location_key("other-file"),
            groups(&[("other-holder", &filler)]),
        );
        assert_eq!(state.bytes(), MAX_BYTES);
        let refused = state.store(file, groups(&[("holder", &[2, 3])]));
        assert_eq!(
            refused,
            Stored {
                added: 0,
                overflow: 2
            }
        );
        // 1 was disproven; 2/3 are removed without record. Neither the failed
        // admission nor a later restart may restore 1's obsolete decision.
        let state: CopyRemovals =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert!(state.get(file).is_empty());
    }

    #[test]
    fn prefix_hold_attempts_survive_restart_and_expire_on_third_pass() {
        let file = location_key("copy");
        let mut state = CopyRemovals::missing();
        for pass in 1..=HOLD_PASSES {
            assert_eq!(state.advance_hold(file), pass < HOLD_PASSES);
            assert_eq!(state.pending(file), pass < HOLD_PASSES);
            state = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
            assert!(state.metadata_lost());
        }
        assert_eq!(state.bytes(), 0);
    }

    #[test]
    fn held_new_file_debt_survives_intervening_page_pruning() {
        let file = location_key("new-held-file");
        let mut state = CopyRemovals::default();
        for pass in 1..=HOLD_PASSES {
            assert_eq!(state.advance_hold(file), pass < HOLD_PASSES);
            // A different page sees no settled entry for the whole-body-held
            // new file. This is not proof that its source disappeared.
            state.retain_files(|_| false);
            state = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
            assert_eq!(state.pending(file), pass < HOLD_PASSES);
        }
        assert_eq!(state.bytes(), 0);
        assert!(state.advance_hold(file));
        state.forget(file); // ordinary confirmed source-removal path
        assert!(!state.pending(file));
        assert_eq!(state.bytes(), 0);
    }

    #[test]
    fn many_holder_groups_allow_a_small_update_within_the_cap() {
        let file = location_key("many-holder-file");
        let mut groups = (0..65_000u64)
            .map(|n| (location_key(&format!("holder-{n}")), BTreeSet::from([n])))
            .collect::<BTreeMap<_, _>>();
        let mut state = CopyRemovals::default();
        assert_eq!(state.store(file, groups.clone()).added, 65_000);
        groups.values_mut().next().unwrap().insert(65_001);
        assert_eq!(
            state.store(file, groups),
            Stored {
                added: 1,
                overflow: 0
            }
        );
        assert_eq!(state.get(file).len(), 65_000);
        assert_eq!(
            state.bytes(),
            FILE_BYTES + 65_000 * (GROUP_BYTES + HASH_BYTES) + HASH_BYTES
        );
        assert!(state.bytes() < MAX_BYTES);
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
