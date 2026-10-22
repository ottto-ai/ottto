//! Content-free bridge from final snapshot uploads to a short-lived reader.
//! The scan index and upload receipts retain hashes, not recoverable start
//! fields. This log therefore records only verdict changes, keyed by a hash
//! of the destination, source and snapshot session id. No transcript is opened here.

use super::{session_start_verdict, SnapshotItem, StartVerdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const FILE_NAME: &str = "composition-start-verdicts.jsonl";
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SESSIONS: usize = 50_000;
const KEEP_SECONDS: i64 = 92 * 86_400;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    key: String,
    measured: bool,
    at: i64,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Verdicts(BTreeMap<String, Entry>, String);

fn key(destination: &str, source: &str, id: &str) -> String {
    let source = if source == "claude-code" {
        "claude_code"
    } else {
        source
    };
    let mut hash = Sha256::new();
    hash.update(destination.as_bytes());
    hash.update([0]);
    hash.update(source.as_bytes());
    hash.update([0]);
    hash.update(id.as_bytes());
    format!("{:x}", hash.finalize())
}

impl Verdicts {
    pub(crate) fn get(&self, source: &str, id: &str, now: i64) -> StartVerdict {
        match self.0.get(&key(&self.1, source, id)) {
            Some(entry) if entry.measured && entry.at >= now - KEEP_SECONDS && entry.at <= now => {
                StartVerdict::Measured
            }
            _ => StartVerdict::NotMeasured,
        }
    }
}

/// Read once per composition process, independently of the daemon's cache.
/// Missing, corrupt or oversized state is unmeasured, never a held file.
pub(crate) fn load(support: &Path, destination: &str, _now: i64) -> Verdicts {
    let mut verdicts = read(support).unwrap_or_default();
    verdicts.1 = destination.to_string();
    verdicts
}

/// Same relay authority fence as snapshot delivery, additionally bound to
/// the endpoint and machine. Neither credentials nor raw ids enter the log.
pub(crate) fn destination(namespace: &str, endpoint: &str, machine: &str) -> String {
    let mut hash = Sha256::new();
    for value in [namespace, endpoint, machine] {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    format!("{:x}", hash.finalize())
}

fn read(support: &Path) -> std::io::Result<Verdicts> {
    let file = match File::open(support.join(FILE_NAME)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Verdicts::default())
        }
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > MAX_BYTES {
        return Err(std::io::Error::other("verdict log oversized"));
    }
    let mut out = Verdicts::default();
    for line in BufReader::new(file.take(MAX_BYTES)).lines() {
        let line = line?;
        // A corrupt or torn change might supersede a measured verdict.
        // Treat the whole bridge as unmeasured until the writer repairs it.
        let entry: Entry = serde_json::from_str(&line)?;
        if entry.key.len() != 64 || !entry.key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(std::io::Error::other("invalid verdict key"));
        }
        out.0.insert(entry.key.clone(), entry);
        if out.0.len() > MAX_SESSIONS {
            return Err(std::io::Error::other("verdict session cap exceeded"));
        }
    }
    Ok(out)
}

struct Cached {
    support: PathBuf,
    day: i64,
    verdicts: Verdicts,
    bytes: u64,
}

/// Append only a change in the final wire item's verdict, after a valid ACK.
/// The single daemon writer serializes with itself; readers see complete rows.
/// Daily pruning rewrites only retained latest entries (also enforcing hard
/// byte/session caps). No snapshot format or upload bytes change.
pub(crate) fn record<'a>(
    support: &Path,
    destination: &str,
    source: &str,
    items: impl IntoIterator<Item = &'a SnapshotItem>,
    now: i64,
) -> std::io::Result<u64> {
    static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();
    let mut guard = CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| std::io::Error::other("verdict cache unavailable"))?;
    if guard.as_ref().map_or(true, |c| c.support != support) {
        let (verdicts, bytes) = match read(support) {
            Ok(verdicts) => (
                verdicts,
                fs::metadata(support.join(FILE_NAME)).map_or(0, |m| m.len()),
            ),
            Err(_) => (Verdicts::default(), MAX_BYTES),
        };
        *guard = Some(Cached {
            support: support.to_path_buf(),
            day: -1,
            verdicts,
            bytes,
        });
    }

    let cache = guard.as_mut().expect("initialized");
    let path = support.join(FILE_NAME);
    let full = cache.bytes >= MAX_BYTES - 64 * 1024 || cache.verdicts.0.len() >= MAX_SESSIONS;
    if cache.day != now / 86_400 || full {
        let old_len = cache.verdicts.0.len();
        cache
            .verdicts
            .0
            .retain(|_, e| e.at >= now - KEEP_SECONDS && e.at <= now);
        if full && cache.verdicts.0.len() > MAX_SESSIONS / 2 {
            evict_oldest(cache);
        }
        if full || cache.verdicts.0.len() != old_len {
            compact(cache, &path, support)?;
        }
        cache.day = now / 86_400;
    }
    let mut written = 0u64;
    let mut file: Option<File> = None;
    for item in items {
        let id = key(destination, source, &item.source_session_id);
        let measured = session_start_verdict(item) == StartVerdict::Measured;
        if cache
            .verdicts
            .0
            .get(&id)
            .is_some_and(|e| e.measured == measured)
        {
            continue;
        }
        let entry = Entry {
            key: id.clone(),
            measured,
            at: now,
        };
        let mut row = serde_json::to_vec(&entry)?;
        row.push(b'\n');
        let new_at_cap =
            !cache.verdicts.0.contains_key(&id) && cache.verdicts.0.len() >= MAX_SESSIONS;
        if cache.bytes + row.len() as u64 > MAX_BYTES || new_at_cap {
            // Compact during the batch too. Existing clears must never be
            // dropped just because a preceding new session reached a cap.
            if let Some(open) = file.take() {
                open.sync_data()?;
            }
            if new_at_cap {
                evict_oldest(cache);
            }
            compact(cache, &path, support)?;
        }
        if file.is_none() {
            file = Some(OpenOptions::new().create(true).append(true).open(&path)?);
        }
        if let Err(error) = file.as_mut().expect("opened").write_all(&row) {
            // A partial append must be compacted before another write.
            cache.bytes = MAX_BYTES;
            return Err(error);
        }
        written += row.len() as u64;
        cache.bytes += row.len() as u64;
        cache.verdicts.0.insert(id, entry);
    }
    if let Some(file) = file {
        file.sync_data()?;
        File::open(support)?.sync_all()?;
    }
    Ok(written)
}

fn evict_oldest(cache: &mut Cached) {
    let mut oldest: Vec<_> = cache
        .verdicts
        .0
        .values()
        .map(|e| (e.at, e.key.clone()))
        .collect();
    oldest.sort();
    for (_, key) in oldest
        .into_iter()
        .take(cache.verdicts.0.len().saturating_sub(MAX_SESSIONS / 2))
    {
        cache.verdicts.0.remove(&key);
    }
}

fn compact(cache: &mut Cached, path: &Path, support: &Path) -> std::io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = BufWriter::new(File::create(&temp)?);
    for entry in cache.verdicts.0.values() {
        serde_json::to_writer(&mut file, entry)?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    file.get_ref().sync_all()?;
    fs::rename(temp, path)?;
    File::open(support)?.sync_all()?;
    cache.bytes = fs::metadata(path)?.len();
    eprintln!(
        "ottto-service: composition_start_verdict bytes_compacted={}",
        cache.bytes
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::SnapshotSessionStart;

    fn item(id: &str, measured: bool) -> SnapshotItem {
        let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        item.source_session_id = id.into();
        item.session_start = Some(Box::new(SnapshotSessionStart {
            user_turn_count: measured.then_some(1),
            ..Default::default()
        }));
        item
    }

    #[test]
    fn start_verdict_isolated_by_relay_endpoint_and_machine() {
        let support = crate::test_scratch::private_dir("verdict-destination-isolation");
        let now = 1_790_000_000;
        let current = destination("relay-a", "https://one.invalid", "machine-a");
        record(&support, &current, "codex", [&item("s", true)], now).unwrap();
        assert_eq!(
            load(&support, &current, now).get("codex", "s", now),
            StartVerdict::Measured
        );
        for other in [
            destination("relay-b", "https://one.invalid", "machine-a"),
            destination("relay-a", "https://two.invalid", "machine-a"),
            destination("relay-a", "https://one.invalid", "machine-b"),
        ] {
            assert_eq!(
                load(&support, &other, now).get("codex", "s", now),
                StartVerdict::NotMeasured
            );
        }
        fs::remove_dir_all(support).unwrap();
    }

    #[test]
    fn start_verdict_clear_survives_reaching_cap_mid_batch() {
        let support = crate::test_scratch::private_dir("verdict-cap-clears");
        let now = 1_790_000_000;
        let current = "synthetic-destination";
        let mut file = BufWriter::new(File::create(support.join(FILE_NAME)).unwrap());
        for i in 0..MAX_SESSIONS - 2 {
            let entry = Entry {
                key: format!("{i:064x}"),
                measured: true,
                at: now,
            };
            serde_json::to_writer(&mut file, &entry).unwrap();
            file.write_all(b"\n").unwrap();
        }
        let entry = Entry {
            key: key(current, "codex", "existing"),
            measured: true,
            at: now,
        };
        serde_json::to_writer(&mut file, &entry).unwrap();
        file.write_all(b"\n").unwrap();
        file.flush().unwrap();
        drop(file);
        let new = item("new", true);
        let clear = item("existing", false);
        // The first row reaches exactly MAX_SESSIONS. The next row must
        // still record its clear, even though the batch is now at the cap.
        record(&support, current, "codex", [&new, &clear], now).unwrap();
        assert_eq!(
            load(&support, current, now).get("codex", "existing", now),
            StartVerdict::NotMeasured
        );
        assert!(load(&support, current, now).0.len() <= MAX_SESSIONS);
        assert!(fs::metadata(support.join(FILE_NAME)).unwrap().len() <= MAX_BYTES);
        fs::remove_dir_all(support).unwrap();
    }
}
