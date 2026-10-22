//! Per-file checkpoints, file pins and the run record, and the atomic writes
//! that keep them.
//!
//! A checkpoint is keyed by the transcript copy key (the session-named file
//! name) and remembers the file's identity (device, inode), the offset of the
//! first unread byte, fingerprints of the bytes before it, and the parse
//! state at that offset. Immutable checkpoint shards and totals commit
//! together through the scope manifest written last.
//!
//! Pins (`index-<agent>.json`, compressed) map transcripts to their scope and
//! starting offset. They are written once at the end of a run. Committed
//! manifests recover missing or stale pins after a crash; checkpoint shards
//! remain the authority for offsets. The first run also saves its discovery
//! (`install-<agent>.json`) before any scope commits, until its pins exist.

use super::aggregate::{stable_hash, Day, Slot, StoredContribution};
use super::scope::ScopeInfo;
use super::{MAX_OPEN_CALLS, STATE_SCHEMA};
use crate::composition_kinds::{CallClass, CallShare, ToolKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

#[cfg(test)]
thread_local! { pub(super) static IO_BYTES: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) }; }
#[cfg(test)]
pub(super) fn record_read(bytes: u64) {
    IO_BYTES.with(|io| {
        let (read, write) = io.get();
        io.set((read + bytes, write));
    });
}

// -------------------------------------------------------------------------
// Atomic writes.
// -------------------------------------------------------------------------

/// Write a file atomically: `write` fills a temp file, then fsync, rename,
/// directory fsync.
pub(super) fn write_atomic<T>(
    path: &Path,
    write: impl FnOnce(&mut File) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("state path has no folder"))?;
    create_dir_durable(dir)?;
    let mut temp_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("state path has no name"))?
        .to_os_string();
    static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    temp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let temp = dir.join(temp_name);
    let written = {
        let mut file = File::create(&temp)?;
        let written = write(&mut file)?;
        file.sync_all()?;
        #[cfg(test)]
        IO_BYTES.with(|io| {
            let (read, write) = io.get();
            io.set((read, write + file.metadata().map_or(0, |m| m.len())));
        });
        written
    };
    fs::rename(&temp, path)?;
    sync_dir(dir)?;
    Ok(written)
}

/// Flush a folder's entries to disk.
pub(super) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    SYNCED_DIRS.with(|dirs| dirs.borrow_mut().push(dir.to_path_buf()));
    File::open(dir)?.sync_all()
}

#[cfg(test)]
thread_local! { pub(super) static SYNCED_DIRS: std::cell::RefCell<Vec<std::path::PathBuf>> = const { std::cell::RefCell::new(Vec::new()) }; }

/// Create a folder and any missing parents, each flushed into its parent
/// before anything is committed inside it: a power loss can otherwise drop
/// a new folder's entry even though the files in it were synced.
pub(super) fn create_dir_durable(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let parent = dir.parent().filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        create_dir_durable(parent)?;
    }
    match fs::create_dir(dir) {
        Ok(()) => {}
        // Created meanwhile by someone else: still make its entry durable.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(error) => return Err(error),
    }
    match parent {
        Some(parent) => sync_dir(parent),
        None => Ok(()),
    }
}

/// Write `value` as JSON, streamed to the file (never one buffer of the
/// whole state); returns the bytes written.
pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<u64> {
    if path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with("index-"))
    {
        return write_packed(path, value);
    }
    write_atomic(path, |file| {
        let mut out = Counting {
            inner: BufWriter::new(file),
            bytes: 0,
        };
        serde_json::to_writer(&mut out, value).map_err(std::io::Error::other)?;
        out.inner.flush()?;
        Ok(out.bytes)
    })
}

/// Stream local state through a bounded compressor, then fsync and rename.
pub(super) fn write_packed<T: Serialize>(path: &Path, value: &T) -> std::io::Result<u64> {
    write_atomic(path, |file| {
        let out = Counting {
            inner: BufWriter::new(file),
            bytes: 0,
        };
        let encoder = zstd::stream::write::Encoder::new(out, 1)?;
        let mut buffer = BufWriter::new(encoder);
        serde_json::to_writer(&mut buffer, value).map_err(std::io::Error::other)?;
        let encoder = buffer.into_inner().map_err(|error| error.into_error())?;
        let mut out = encoder.finish()?;
        out.inner.flush()?;
        Ok(out.bytes)
    })
}

struct Counting<W> {
    inner: W,
    bytes: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Read a state file, streamed (the whole file is never held next to what
/// it decodes to). `Err` means the file exists but cannot be used (bad
/// state); `Ok(None)` means there is none.
pub(super) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, ()> {
    match File::open(path) {
        Ok(mut file) => {
            #[cfg(test)]
            record_read(file.metadata().map_or(0, |m| m.len()));
            use std::io::{Read, Seek};
            let mut magic = [0; 4];
            let size = file.read(&mut magic).map_err(|_| ())?;
            #[cfg(test)]
            record_read(size as u64);
            file.rewind().map_err(|_| ())?;
            if size == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
                let decoder = zstd::stream::read::Decoder::new(file).map_err(|_| ())?;
                serde_json::from_reader(std::io::BufReader::new(decoder))
                    .map(Some)
                    .map_err(|_| ())
            } else {
                serde_json::from_reader(std::io::BufReader::new(file))
                    .map(Some)
                    .map_err(|_| ())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

// -------------------------------------------------------------------------
// Run record and pins.
// -------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct RunRecord {
    pub(super) schema: u32,
    /// The UTC day of the last run, saved when the run starts.
    pub(super) last_run_day: Option<Day>,
    pub(super) last_run_started: Option<i64>,
    /// Full-read bytes spent on `repair_day`.
    pub(super) repair_day: Day,
    pub(super) repair_used: u64,
}

/// Modification time as (seconds, nanoseconds) since the epoch.
pub(super) type Stamp = (i64, u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Pin {
    pub(super) path: String,
    pub(super) dev: u64,
    pub(super) ino: u64,
    /// The scope the file is pinned to once first read.
    #[serde(default)]
    pub(super) scope: Option<String>,
    /// Where reading starts when the scope has no checkpoint for it.
    pub(super) start: u64,
    /// Size and modification time when last committed.
    pub(super) size: u64,
    pub(super) mtime: Stamp,
    /// Needs a full read within the repair budget.
    #[serde(default)]
    pub(super) waiting: bool,
    /// A compressed archive copy replaced the file: nothing more to read.
    #[serde(default)]
    pub(super) done: bool,
    pub(super) last_seen: Day,
    /// When the pins first saw the file (unix seconds).
    #[serde(default)]
    pub(super) first_seen: i64,
    /// Its first lines name no folder that exists or is known: scanned again
    /// only when the file changes.
    #[serde(default)]
    pub(super) unscoped: bool,
    /// Reads that failed in a row; the second one quarantines the file.
    #[serde(default)]
    pub(super) failures: u8,
    /// Failed twice in a row: never read again (counted), until another file
    /// takes its place.
    #[serde(default)]
    pub(super) quarantined: bool,
    /// A reset remains pending until this file commits a current-end checkpoint.
    #[serde(default)]
    pub(super) restart_at_end: bool,
    /// Fingerprints of the bytes before `start` (as the checkpoint's), so a
    /// larger copy of the same transcript can take over.
    #[serde(default)]
    pub(super) head: Fingerprint,
    #[serde(default)]
    pub(super) tail: Fingerprint,
    /// Where the file's first read started (`start` moves on with each commit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) origin: Option<u64>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct Index {
    pub(super) schema: u32,
    /// When this agent's state started (the install run), unix seconds.
    pub(super) created: i64,
    /// Start of the previous run, unix seconds: files born later are new.
    pub(super) last_scan_started: Option<i64>,
    pub(super) files: BTreeMap<String, Pin>,
    /// Folder -> scope id: folders resolved by a read, and the linked
    /// worktrees of each repository scope (recorded hourly while they exist,
    /// so a transcript whose worktree is gone by its first read still finds
    /// its scope).
    pub(super) cwd_scopes: BTreeMap<String, String>,
    /// Each scope as first seen (its upload key never changes).
    pub(super) scope_info: BTreeMap<String, ScopeInfo>,
    /// Each scope's last committed generation, for uploads of scopes not
    /// read in a run.
    pub(super) scope_generations: BTreeMap<String, u64>,
    /// The last day a pin named each scope. A scope no pin named for
    /// `KEEP_DAYS` is no longer refreshed.
    pub(super) scope_last_pinned: BTreeMap<String, Day>,
    /// Scopes awaiting a forward-only reset, with the date history was reset.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) quarantined_scopes: BTreeMap<String, Day>,
}

/// The first run's discovery, saved before any scope commits, so a crash
/// part way through the first run resumes with the same cutoff and starting
/// offsets instead of treating uncommitted files as found later.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct InstallRecord {
    pub(super) schema: u32,
    /// The first run's start (unix seconds): files born later are new.
    pub(super) cutoff: i64,
    /// Starting offset of each file the first run found.
    pub(super) starts: BTreeMap<String, u64>,
    /// Files live at install, read from their start within the repair budget.
    pub(super) live: std::collections::BTreeSet<String>,
}

pub(super) fn install_path(dir: &Path, source_label: &str) -> std::path::PathBuf {
    dir.join(format!("install-{source_label}.json"))
}

impl Index {
    pub(super) fn new(created: i64) -> Self {
        Self {
            schema: STATE_SCHEMA,
            created,
            ..Self::default()
        }
    }
}

// -------------------------------------------------------------------------
// Checkpoints.
// -------------------------------------------------------------------------

/// A hash of `len` bytes of the file (at its start, or before the offset).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Fingerprint {
    pub(super) len: u32,
    pub(super) hash: u64,
}

pub(super) const FINGERPRINT_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Status {
    /// Read forward as it grows.
    Live,
    /// Archived (compressed) or abandoned: never read again.
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Checkpoint {
    pub(super) path: String,
    pub(super) dev: u64,
    pub(super) ino: u64,
    /// Birth time, or first sight when earlier (unix seconds). Claude
    /// records dated well before it are copied history.
    pub(super) created: i64,
    pub(super) offset: u64,
    /// Stopped inside a line over the line guard.
    #[serde(default)]
    pub(super) skipping: bool,
    pub(super) head: Fingerprint,
    pub(super) tail: Fingerprint,
    pub(super) size: u64,
    pub(super) mtime: Stamp,
    /// Parser identity at the file's first read.
    pub(super) parser_version: String,
    pub(super) status: Status,
    pub(super) parse: StoredParse,
    /// This file's share of the scope totals.
    #[serde(default)]
    pub(super) contribution: StoredContribution,
    pub(super) last_seen: Day,
    /// Set once the file has been idle for `COLD_AFTER_SECS`: see
    /// `compact`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cold: Option<Cold>,
    /// Where the file's first read started, kept so pins rebuilt from this
    /// checkpoint still know it (see `Pin::origin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) origin: Option<u64>,
}

/// A file unchanged this long is cold.
pub(super) const COLD_AFTER_SECS: i64 = 2 * 86_400;

/// What a cold checkpoint keeps of the per-day file rows: the last day each
/// file was read, by a short hash of its name (for the per-file session
/// counts), grouped by that day.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct Cold {
    files: Vec<(Day, Vec<u32>)>,
}

impl Cold {
    /// (name hash, last day read) of each file the transcript read.
    pub(super) fn files(&self) -> impl Iterator<Item = (u32, Day)> + '_ {
        self.files
            .iter()
            .flat_map(|(day, hashes)| hashes.iter().map(move |hash| (*hash, *day)))
    }

    fn rows(&self) -> usize {
        self.files.iter().map(|(_, hashes)| 1 + hashes.len()).sum()
    }
}

/// The hash a cold checkpoint keeps of a file name. 32 bits: the session
/// counts only look up the few top file names, so a rare collision can add
/// one session to one count, never move tokens.
pub(super) fn name_hash(name: &str) -> u32 {
    stable_hash(name.as_bytes()) as u32
}

impl Checkpoint {
    /// Bytes held in memory, approximately (the run's memory figure).
    pub(super) fn accounted_bytes(&self) -> usize {
        256 + self.path.len()
            + self.parser_version.len()
            + self.parse.accounted_bytes()
            + self.contribution.accounted_bytes()
            + self.cold.as_ref().map_or(0, |cold| cold.rows() * 8)
    }

    /// Keep an idle file's checkpoint small: its offset, fingerprints and
    /// parse state stay; its share of the totals is dropped (only the
    /// session is kept), the open tokens are kept per day and kind (on the
    /// largest part of each), and the file rows become the last day each
    /// file was read. A cold file is never read again in full, since its
    /// share could not be replaced: a rewrite restarts it at its end.
    /// Returns whether anything was dropped.
    pub(super) fn compact(&mut self) -> bool {
        let was_cold = self.cold.is_some();
        let cold = self.cold.get_or_insert_with(Cold::default);
        let mut last: BTreeMap<u32, Day> = cold.files().collect();
        for (day, name) in self.contribution.file_days() {
            let entry = last.entry(name_hash(name)).or_insert(day);
            *entry = (*entry).max(day);
        }
        let mut by_day: BTreeMap<Day, Vec<u32>> = BTreeMap::new();
        for (hash, day) in last {
            by_day.entry(day).or_default().push(hash);
        }
        cold.files = by_day.into_iter().collect();
        let dropped = self.contribution.keep_session_only();
        let folded = self.parse.fold_open_by_kind();
        !was_cold || dropped || folded
    }

    /// Every stored kind and part id is known to this build: the parse
    /// state, its open calls and their shares, and the contribution's part,
    /// file and session rows. A checkpoint failing this is never used.
    pub(super) fn ids_known(&self) -> bool {
        self.parse.ids_known() && self.contribution.ids_known()
    }

    /// Drop days before `floor`.
    pub(super) fn prune(&mut self, floor: Day) {
        self.contribution.prune(floor);
        if let Some(cold) = &mut self.cold {
            cold.files.retain(|(day, _)| *day >= floor);
        }
    }
}

// -------------------------------------------------------------------------
// Parse state.
// -------------------------------------------------------------------------

/// How a Codex rollout marks copied parent history.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum CopiedMode {
    /// Every record is the session's own.
    #[default]
    Own,
    /// Records with an ordinal below this (or none) are copied.
    BeforeOrdinal(u64),
    /// A legacy subagent fork: copied until the trigger turn arrives.
    UntilTrigger,
    /// A legacy user fork: its copied part has no boundary, so nothing in
    /// the file counts.
    Excluded,
}

/// The last assistant message id seen (`Sentinel` before any).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum LastAssistant {
    #[default]
    Sentinel,
    Id(Option<Box<str>>),
}

/// An inner item Codex wrote while a call ran (owned, so it can wait in a
/// checkpoint for the call's output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum SavedItem {
    Command {
        cwd: Option<String>,
        command: String,
        parsed: Vec<(String, Option<String>)>,
        output_chars: u64,
    },
    Mcp {
        server: String,
        tool: String,
        output_chars: u64,
    },
    Extension {
        name: String,
        output_chars: u64,
    },
    WebSearch {
        output_chars: u64,
    },
}

#[derive(Debug, Clone)]
pub(super) struct OpenCall {
    pub(super) class: CallClass,
    pub(super) items: Vec<SavedItem>,
    /// Order of arrival, so the oldest open call is the one evicted.
    pub(super) seq: u64,
}

/// The parse state at a checkpoint's offset.
#[derive(Debug, Default, Clone)]
pub(super) struct ParseState {
    /// Session id, fixed when the checkpoint is created.
    pub(super) session: Box<str>,
    /// The transcript is written by an agent (sidechain, subagent thread).
    pub(super) agent_author: bool,
    pub(super) last_assistant: LastAssistant,
    pub(super) open_calls: BTreeMap<Box<str>, OpenCall>,
    /// The next open call's arrival number.
    pub(super) call_seq: u64,
    /// The most recent call still open (inner items attach to it).
    pub(super) last_call: Option<Box<str>>,
    /// Tokens of lines entered since the last compaction, per day and slot.
    pub(super) open: Vec<(Day, Slot, u64)>,
    pub(super) copied: CopiedMode,
    pub(super) copied_lines: u64,
    pub(super) own_lines: u64,
    /// Earliest line timestamp, unix seconds.
    pub(super) min_ts: Option<i64>,
    pub(super) has_rendered: bool,
    /// The first model response closed request 1. Old checkpoints infer this
    /// from their saved response/call state instead of re-reading history.
    pub(super) request1_closed: bool,
    /// Latest final snapshot verdict, refreshed without reading transcripts.
    pub(super) start_measured: bool,
    pub(super) compactions: crate::snapshots::CompositionCompactions,
    pub(super) cwd: Option<Box<str>>,
}

impl ParseState {
    pub(super) fn add_open(&mut self, day: Day, slot: &Slot, tokens: u64) {
        if tokens == 0 {
            return;
        }
        match self
            .open
            .iter_mut()
            .find(|(open_day, open_slot, _)| *open_day == day && open_slot == slot)
        {
            Some((_, _, open)) => *open += tokens,
            None => self.open.push((day, slot.clone(), tokens)),
        }
    }

    /// Open a call; at `MAX_OPEN_CALLS` the oldest open call is dropped
    /// first. Returns whether one was dropped.
    pub(super) fn open_call(&mut self, id: Box<str>, class: CallClass) -> bool {
        let mut evicted = false;
        if self.open_calls.len() >= MAX_OPEN_CALLS && !self.open_calls.contains_key(&id) {
            let oldest = self
                .open_calls
                .iter()
                .min_by_key(|(_, call)| call.seq)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                self.open_calls.remove(&oldest);
                evicted = true;
            }
        }
        let seq = self.call_seq;
        self.call_seq += 1;
        self.open_calls.insert(
            id,
            OpenCall {
                class,
                items: Vec::new(),
                seq,
            },
        );
        evicted
    }

    pub(super) fn note_ts(&mut self, ts: Option<i64>) {
        if let Some(ts) = ts {
            self.min_ts = Some(self.min_ts.map_or(ts, |min| min.min(ts)));
        }
    }

    pub(super) fn accounted_bytes(&self) -> usize {
        64 + self.open.len() * 48 + self.open_calls.len() * 160 + self.compactions.accounted_bytes()
    }
}

/// Open tokens of one day and slot: day, kind, part, add-on server, tokens.
type OpenRow = (Day, String, String, Option<Box<str>>, u64);

/// A call share as stored: kind, part, weight, file and add-on tool.
type StoredShare = (String, String, u32, Option<String>, Option<String>);

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct StoredCall {
    id: String,
    kind: String,
    part: String,
    tool: String,
    file: Option<String>,
    /// Every share of a call whose result splits (empty when it does not),
    /// so a call open across a checkpoint splits as in one read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    shares: Vec<StoredShare>,
    items: Vec<SavedItem>,
    seq: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct StoredParse {
    session: String,
    agent_author: bool,
    /// Absent before any assistant message; `Some(None)` after one with no id.
    last_assistant: Option<Option<String>>,
    open_calls: Vec<StoredCall>,
    call_seq: u64,
    last_call: Option<String>,
    /// Open tokens per day and slot (kind, part, add-on server).
    open: Vec<OpenRow>,
    copied: CopiedMode,
    copied_lines: u64,
    own_lines: u64,
    min_ts: Option<i64>,
    has_rendered: bool,
    request1_closed: bool,
    #[serde(skip_serializing_if = "crate::snapshots::CompositionCompactions::is_empty")]
    compactions: crate::snapshots::CompositionCompactions,
    cwd: Option<String>,
}

impl StoredParse {
    /// A malformed open row only abandons this file's parse state. Keep its
    /// identity and earlier totals without reading its prefix again.
    pub(super) fn restart_state(&self) -> ParseState {
        ParseState {
            session: self.session.as_str().into(),
            agent_author: self.agent_author,
            request1_closed: true,
            cwd: self.cwd.as_deref().map(Into::into),
            copied: self.copied,
            ..ParseState::default()
        }
    }

    fn ids_known(&self) -> bool {
        use super::aggregate::{kind_from_str, part_from_str};
        let known =
            |kind: &str, part: &str| kind_from_str(kind).is_some() && part_from_str(part).is_some();
        self.open_calls.iter().all(|call| {
            known(&call.kind, &call.part)
                && call.shares.iter().all(|(kind, part, ..)| known(kind, part))
        }) && self
            .open
            .iter()
            .all(|(_, kind, part, ..)| known(kind, part))
    }

    /// Bytes held in memory, approximately.
    pub(super) fn accounted_bytes(&self) -> usize {
        160 + self.compactions.accounted_bytes()
            + self.session.len()
            + self.cwd.as_ref().map_or(0, String::len)
            + self.open.len() * 40
            + self
                .open_calls
                .iter()
                .map(|call| 192 + call.shares.len() * 96 + call.items.len() * 128)
                .sum::<usize>()
    }

    /// Keep one open row per day and kind, on the part holding the most
    /// tokens (later residency then lands on that part). Returns whether
    /// rows were merged.
    fn fold_open_by_kind(&mut self) -> bool {
        type Folded = (String, Option<Box<str>>, u64, u64);
        let before = self.open.len();
        let mut by_kind: BTreeMap<(Day, String), Folded> = BTreeMap::new();
        for (day, kind, part, server, tokens) in std::mem::take(&mut self.open) {
            let entry = by_kind
                .entry((day, kind))
                .or_insert_with(|| (part.clone(), server.clone(), tokens, 0));
            if tokens > entry.2 {
                (entry.0, entry.1, entry.2) = (part, server, tokens);
            }
            entry.3 += tokens;
        }
        self.open = by_kind
            .into_iter()
            .map(|((day, kind), (part, server, _, total))| (day, kind, part, server, total))
            .collect();
        self.open.len() != before
    }

    pub(super) fn from_state(state: &ParseState) -> Self {
        Self {
            session: state.session.to_string(),
            agent_author: state.agent_author,
            last_assistant: match &state.last_assistant {
                LastAssistant::Sentinel => None,
                LastAssistant::Id(id) => Some(id.as_deref().map(str::to_string)),
            },
            open_calls: state
                .open_calls
                .iter()
                .map(|(id, call)| StoredCall {
                    id: id.to_string(),
                    kind: call.class.kind.as_str().to_string(),
                    part: call.class.part.as_str().to_string(),
                    tool: call.class.tool.as_str().to_string(),
                    file: call.class.file.as_deref().map(str::to_string),
                    shares: call
                        .class
                        .shares
                        .iter()
                        .map(|share| {
                            (
                                share.kind.as_str().to_string(),
                                share.part.as_str().to_string(),
                                share.weight,
                                share.file.as_deref().map(str::to_string),
                                share.tool.as_ref().map(|tool| tool.as_str().to_string()),
                            )
                        })
                        .collect(),
                    items: call.items.clone(),
                    seq: call.seq,
                })
                .collect(),
            call_seq: state.call_seq,
            last_call: state.last_call.as_deref().map(str::to_string),
            open: state
                .open
                .iter()
                .map(|(day, slot, tokens)| {
                    (
                        *day,
                        slot.kind.as_str().to_string(),
                        slot.part.as_str().to_string(),
                        slot.server.clone(),
                        *tokens,
                    )
                })
                .collect(),
            copied: state.copied,
            copied_lines: state.copied_lines,
            own_lines: state.own_lines,
            min_ts: state.min_ts,
            has_rendered: state.has_rendered,
            request1_closed: state.request1_closed,
            compactions: state.compactions.clone(),
            cwd: state.cwd.as_deref().map(str::to_string),
        }
    }

    /// `None` when a stored kind or part is unknown (bad state).
    pub(super) fn into_state(self) -> Option<ParseState> {
        use super::aggregate::{kind_from_str, part_from_str};
        let mut open_calls = BTreeMap::new();
        for call in self.open_calls {
            let mut shares = Vec::with_capacity(call.shares.len());
            for (kind, part, weight, file, tool) in call.shares {
                shares.push(CallShare {
                    kind: kind_from_str(&kind)?,
                    part: part_from_str(&part)?,
                    weight,
                    file: file.map(Into::into),
                    tool: tool.as_deref().map(ToolKey::new),
                });
            }
            let class = CallClass {
                kind: kind_from_str(&call.kind)?,
                part: part_from_str(&call.part)?,
                tool: ToolKey::new(&call.tool),
                file: call.file.map(Into::into),
                shares: shares.into_boxed_slice(),
            };
            open_calls.insert(
                call.id.into(),
                OpenCall {
                    class,
                    items: call.items,
                    seq: call.seq,
                },
            );
        }
        let open = self
            .open
            .into_iter()
            .map(|(day, kind, part, server, tokens)| {
                Some((
                    day,
                    Slot {
                        kind: kind_from_str(&kind)?,
                        part: part_from_str(&part)?,
                        server,
                    },
                    tokens,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let request1_closed =
            self.request1_closed || self.last_assistant.is_some() || self.call_seq > 0;
        Some(ParseState {
            session: self.session.into(),
            agent_author: self.agent_author,
            last_assistant: match self.last_assistant {
                None => LastAssistant::Sentinel,
                Some(id) => LastAssistant::Id(id.map(Into::into)),
            },
            open_calls,
            call_seq: self.call_seq,
            last_call: self.last_call.map(Into::into),
            open,
            copied: self.copied,
            copied_lines: self.copied_lines,
            own_lines: self.own_lines,
            min_ts: self.min_ts,
            has_rendered: self.has_rendered,
            request1_closed,
            start_measured: false,
            compactions: self.compactions,
            cwd: self.cwd.map(Into::into),
        })
    }
}

/// Modification time of `metadata` as a stamp.
pub(super) fn stamp(metadata: &fs::Metadata) -> Stamp {
    metadata
        .modified()
        .ok()
        .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or((0, 0), |since| {
            (since.as_secs() as i64, since.subsec_nanos())
        })
}

/// (device, inode) of `metadata`; (0, 0) where the platform has none.
pub(super) fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        (0, 0)
    }
}

/// Birth time (unix seconds), else modification time.
pub(super) fn birth_secs(metadata: &fs::Metadata) -> i64 {
    born_secs(metadata)
        .or_else(|| {
            metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|since| since.as_secs() as i64)
        })
        .unwrap_or(0)
}

/// Birth time (unix seconds) where the file system records one.
pub(super) fn born_secs(metadata: &fs::Metadata) -> Option<i64> {
    metadata
        .created()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|since| since.as_secs() as i64)
}

/// Fingerprint of `len` bytes at `at` (fewer when the file is shorter).
pub(super) fn fingerprint(file: &File, at: u64, len: u64) -> std::io::Result<Fingerprint> {
    let mut bytes = vec![0u8; len as usize];
    let mut read = 0usize;
    while read < bytes.len() {
        let count = read_at(file, &mut bytes[read..], at + read as u64)?;
        if count == 0 {
            break;
        }
        read += count;
        #[cfg(test)]
        record_read(count as u64);
    }
    bytes.truncate(read);
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&bytes);
    Ok(Fingerprint {
        len: read as u32,
        hash: u64::from_le_bytes(digest[..8].try_into().unwrap_or_default()),
    })
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

#[cfg(not(unix))]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = file;
    file.seek(SeekFrom::Start(offset))?;
    file.read(buf)
}

/// Head and tail fingerprints for a file read up to `offset`.
pub(super) fn fingerprints(
    file: &File,
    offset: u64,
) -> std::io::Result<(Fingerprint, Fingerprint)> {
    let head = fingerprint(file, 0, offset.min(FINGERPRINT_BYTES))?;
    let tail_len = offset.min(FINGERPRINT_BYTES);
    let tail = fingerprint(file, offset - tail_len, tail_len)?;
    Ok((head, tail))
}

/// Whether the file still holds the bytes a checkpoint read.
pub(super) fn fingerprints_match(file: &File, checkpoint: &Checkpoint) -> bool {
    prefix_matches(file, checkpoint.offset, checkpoint.head, checkpoint.tail)
}

/// Whether the file's bytes before `offset` have these fingerprints.
pub(super) fn prefix_matches(
    file: &File,
    offset: u64,
    expected_head: Fingerprint,
    expected_tail: Fingerprint,
) -> bool {
    let head = fingerprint(file, 0, u64::from(expected_head.len));
    let tail_len = u64::from(expected_tail.len);
    let tail = fingerprint(file, offset.saturating_sub(tail_len), tail_len);
    matches!((head, tail), (Ok(head), Ok(tail)) if head == expected_head && tail == expected_tail)
}
