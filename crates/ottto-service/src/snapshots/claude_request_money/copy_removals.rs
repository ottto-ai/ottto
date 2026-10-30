//! Stored copy removals (copy-family fix, Lead B Addendum 1): per Claude
//! file, the request hashes it once removed as copies on an earlier holder's
//! CURRENT census proof, grouped by that holder. A later re-read whose holder
//! proof list has since retired rebuilds the same deduped body instead of
//! restoring the prefix. A holder no longer indexed proves nothing: its group
//! is ignored, and dropped at the file's next store. Local state (class L):
//! never uploaded, never a wire field.
//!
//! Bounded by `MAX_BYTES` of charged state: 32 bytes per file, 32 per holder
//! group and 8 per hash (about 520k hashes when dense; the encoded index text
//! is at most 4/3 of the raw bytes, which are smaller than the charge). A
//! decision past the cap is not stored and is counted
//! (`copy_removal_store_overflow`); a later re-read without proof then counts
//! the copies, flagged: never silently fresh.
use crate::snapshots::claude_money_birth_store::LocationKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_BYTES: usize = 4 * 1024 * 1024;
const FILE_BYTES: usize = 32;
const GROUP_BYTES: usize = 32;
const HASH_BYTES: usize = 8;

/// One file's stored removals: (holder, sorted unique hashes), by holder.
type Groups = Box<[(LocationKey, Box<[u64]>)]>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CopyRemovals {
    /// (file, store sequence, groups), sorted by file key; never an empty
    /// group list or an empty group. The sequence orders eviction.
    files: Vec<(LocationKey, u64, Groups)>,
    /// The charged bytes of `files` (see `charge`).
    bytes: usize,
}

/// What one `store` did, in hashes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stored {
    /// Hashes newly recorded for the file.
    pub(crate) added: u64,
    /// Hashes of decisions lost to the cap: older files' entries evicted
    /// (oldest stored first) or, when even that cannot fit it, this one.
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
fn hash_count(groups: &[(LocationKey, Box<[u64]>)]) -> u64 {
    groups.iter().map(|(_, hashes)| hashes.len() as u64).sum()
}

impl CopyRemovals {
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The charged bytes held now (at most `MAX_BYTES`).
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// `file`'s stored (holder, hashes) groups.
    pub(crate) fn get(&self, file: LocationKey) -> &[(LocationKey, Box<[u64]>)] {
        self.files
            .binary_search_by_key(&file, |f| f.0)
            .map_or(&[], |i| &*self.files[i].2)
    }

    /// Replace `file`'s removals with `groups` (empty forgets it). Past the
    /// cap, other files' entries are evicted oldest stored first; a decision
    /// that cannot fit even alone keeps the old entry. Lost hashes are
    /// returned as overflow. The same state and decisions give the same result.
    pub(crate) fn store(
        &mut self,
        file: LocationKey,
        groups: BTreeMap<LocationKey, BTreeSet<u64>>,
    ) -> Stored {
        let groups: Groups = groups
            .into_iter()
            .filter(|(_, hashes)| !hashes.is_empty())
            .map(|(holder, hashes)| (holder, hashes.into_iter().collect()))
            .collect();
        let old = self.get(file);
        if *old == *groups {
            return Stored::default();
        }
        let new_bytes = charge(&groups);
        if new_bytes > MAX_BYTES {
            return Stored {
                added: 0,
                overflow: hash_count(&groups),
            };
        }
        let held = |hash: &u64| old.iter().any(|(_, h)| h.binary_search(hash).is_ok());
        let added = groups
            .iter()
            .flat_map(|(_, hashes)| hashes.iter())
            .filter(|hash| !held(hash))
            .count() as u64;
        self.forget(file);
        let mut overflow = 0;
        while self.bytes + new_bytes > MAX_BYTES {
            let oldest = (0..self.files.len())
                .min_by_key(|&i| (self.files[i].1, self.files[i].0))
                .expect("over the cap with no entry");
            overflow += hash_count(&self.files[oldest].2);
            self.bytes -= charge(&self.files[oldest].2);
            self.files.remove(oldest);
        }
        if !groups.is_empty() {
            let seq = self.files.iter().map(|f| f.1 + 1).max().unwrap_or(1);
            let at = self.files.binary_search_by_key(&file, |f| f.0).unwrap_err();
            self.files.insert(at, (file, seq, groups));
            self.bytes += new_bytes;
        }
        Stored { added, overflow }
    }

    /// The file is no longer indexed: its removals go with it.
    pub(crate) fn forget(&mut self, file: LocationKey) {
        if let Ok(i) = self.files.binary_search_by_key(&file, |f| f.0) {
            self.bytes -= charge(&self.files[i].2);
            self.files.remove(i);
        }
    }

    /// Keep only files `live` still indexes (every removal path included).
    pub(crate) fn retain_files(&mut self, live: impl Fn(LocationKey) -> bool) {
        let mut bytes = self.bytes;
        self.files.retain(|(file, _, groups)| {
            let keep = live(*file);
            if !keep {
                bytes -= charge(groups);
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
        bytes.extend_from_slice(b"CCR1");
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
    if &take::<4>(&mut input)? != b"CCR1" {
        return None;
    }
    let files = u32::from_le_bytes(take(&mut input)?) as usize;
    if files > input.len() / 56 {
        return None;
    }
    let mut removals = CopyRemovals {
        files: Vec::with_capacity(files),
        bytes: 0,
    };
    for _ in 0..files {
        let file = LocationKey::from_bytes(take(&mut input)?);
        let seq = u64::from_le_bytes(take(&mut input)?);
        let group_count = count(&mut input, 28)?;
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
        removals.bytes += charge(&groups);
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
        assert_eq!(refused.overflow, huge.len() as u64);
        assert_eq!(removals.get(file)[0].1.as_ref(), &[1]);
    }

    #[test]
    fn copy_removals_evict_the_oldest_stored_file_first_and_count_it() {
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
                "the oldest entry is evicted, counted"
            );
            assert!(removals.get(first).is_empty());
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
