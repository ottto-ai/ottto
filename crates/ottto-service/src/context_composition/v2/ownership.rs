//! Which Claude records a scope already counted.
//!
//! A resumed or forked Claude transcript copies earlier records with their
//! uuids; the copy entered context where it was first written, so here it
//! only adds residency. The record ids a scope counted live in one log per
//! UTC day of reading: 12-byte entries (a stable 64-bit hash of the uuid and
//! the id of the file that counted it). The scope state records each log's
//! committed length, so bytes appended by a run that did not commit are
//! ignored. The file id lets a full re-read of a file ignore its own ids.
//! Logs older than `OWNERSHIP_DAYS` are dropped.

use super::aggregate::{Day, Window};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const ENTRY_BYTES: usize = 12;

/// FNV-1a 64: stable across builds and platforms (state is persisted).
pub(super) fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[derive(Default)]
pub(super) struct Ownership {
    /// Committed entries, sorted by hash.
    known: Vec<(u64, u32)>,
    /// Entries added in this run (not yet in a log).
    added: Vec<(u64, u32)>,
    added_index: HashMap<u64, Vec<u32>>,
    /// Logs whose committed bytes were missing or short.
    pub(super) lost_entries: u64,
}

impl Ownership {
    /// Load the committed part of each log.
    pub(super) fn load(dir: &Path, committed: &BTreeMap<Day, u64>) -> Self {
        let mut ownership = Ownership::default();
        for (day, length) in committed {
            let path = log_path(dir, *day);
            let mut bytes = Vec::new();
            let read = File::open(&path)
                .and_then(|file| (&file).take(*length).read_to_end(&mut bytes).map(|_| ()));
            if read.is_err() || (bytes.len() as u64) < *length {
                ownership.lost_entries += (*length - bytes.len() as u64) / ENTRY_BYTES as u64;
            }
            for entry in bytes.chunks_exact(ENTRY_BYTES) {
                let hash = u64::from_le_bytes(entry[..8].try_into().unwrap_or_default());
                let file = u32::from_le_bytes(entry[8..].try_into().unwrap_or_default());
                ownership.known.push((hash, file));
            }
        }
        ownership.known.sort_unstable();
        ownership
    }

    /// Whether another file of the scope already counted this record.
    pub(super) fn counted_elsewhere(&self, hash: u64, file: u32) -> bool {
        let start = self.known.partition_point(|(entry, _)| *entry < hash);
        self.known[start..]
            .iter()
            .take_while(|(entry, _)| *entry == hash)
            .any(|(_, owner)| *owner != file)
            || self
                .added_index
                .get(&hash)
                .is_some_and(|owners| owners.iter().any(|owner| *owner != file))
    }

    /// Record a record this file counted.
    pub(super) fn add(&mut self, hash: u64, file: u32) {
        let owners = self.added_index.entry(hash).or_default();
        if !owners.contains(&file) {
            owners.push(file);
            self.added.push((hash, file));
        }
    }

    pub(super) fn accounted_bytes(&self) -> usize {
        self.known.capacity() * 16 + self.added.capacity() * 16 + self.added_index.len() * 48
    }

    /// Append this run's entries to today's log (fsync'd) and return the new
    /// committed lengths, without logs that fell out of retention. The
    /// caller commits the lengths with the scope state.
    pub(super) fn write(
        &self,
        dir: &Path,
        committed: &BTreeMap<Day, u64>,
        window: Window,
    ) -> std::io::Result<BTreeMap<Day, u64>> {
        let mut lengths: BTreeMap<Day, u64> = committed
            .iter()
            .filter(|(day, _)| **day >= window.ownership_floor())
            .map(|(day, length)| (*day, *length))
            .collect();
        if self.added.is_empty() {
            return Ok(lengths);
        }
        fs::create_dir_all(dir)?;
        let path = log_path(dir, window.today);
        let committed_today = lengths.get(&window.today).copied().unwrap_or(0);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        // Bytes past the committed length came from a run that never
        // committed; overwrite them.
        file.set_len(committed_today)?;
        let mut bytes = Vec::with_capacity(self.added.len() * ENTRY_BYTES);
        for (hash, owner) in &self.added {
            bytes.extend_from_slice(&hash.to_le_bytes());
            bytes.extend_from_slice(&owner.to_le_bytes());
        }
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(committed_today))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        lengths.insert(window.today, committed_today + bytes.len() as u64);
        Ok(lengths)
    }
}

pub(super) fn log_path(dir: &Path, day: Day) -> PathBuf {
    dir.join(format!("{day}.log"))
}

/// Remove logs no longer referenced (after the scope state committed).
pub(super) fn remove_unreferenced(dir: &Path, committed: &BTreeMap<Day, u64>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(day) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".log"))
            .and_then(|day| day.parse::<Day>().ok())
        else {
            continue;
        };
        if !committed.contains_key(&day) {
            let _ = fs::remove_file(entry.path());
        }
    }
}
