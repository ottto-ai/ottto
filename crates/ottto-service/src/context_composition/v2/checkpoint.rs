//! Per-file checkpoints, file pins and the run record, and the atomic writes
//! that keep them.
//!
//! A checkpoint is keyed by the transcript copy key (the session-named file
//! name) and remembers the file's identity (device, inode), the offset of the
//! first unread byte, fingerprints of the bytes before it, and the parse
//! state at that offset. Checkpoints live in their scope's state file, so a
//! scope's totals and its files' offsets always commit together.
//!
//! Pins (`index-<agent>.json`) map every transcript seen to its scope and
//! where reading starts. They are written before a scope commits, so a crash
//! never lets one file count in two scopes; the scope state stays the truth
//! for offsets.

use super::aggregate::{Day, Slot, StoredContribution};
use super::scope::ScopeInfo;
use super::{MAX_OPEN_CALLS, STATE_SCHEMA};
use crate::composition_kinds::{CallClass, CallShare, Kind, Part, ToolKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

// -------------------------------------------------------------------------
// Atomic writes.
// -------------------------------------------------------------------------

/// Write `bytes` to `path`: temp file, fsync, rename, directory fsync.
pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("state path has no folder"))?;
    fs::create_dir_all(dir)?;
    let mut temp_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("state path has no name"))?
        .to_os_string();
    temp_name.push(".tmp");
    let temp = dir.join(temp_name);
    {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, path)?;
    File::open(dir)?.sync_all()
}

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<u64> {
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    write_atomic(path, &bytes)?;
    Ok(bytes.len() as u64)
}

/// Read a state file. `Err` means the file exists but cannot be used (bad
/// state); `Ok(None)` means there is none.
pub(super) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, ()> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| ()),
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
    /// Fingerprints of the bytes before `start` (as the checkpoint's), so a
    /// larger copy of the same transcript can take over.
    #[serde(default)]
    pub(super) head: Fingerprint,
    #[serde(default)]
    pub(super) tail: Fingerprint,
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
}

impl Checkpoint {
    /// Bytes held in memory, approximately (the run's memory figure).
    pub(super) fn accounted_bytes(&self) -> usize {
        256 + self.path.len()
            + self.parser_version.len()
            + self.parse.accounted_bytes()
            + self.contribution.accounted_bytes()
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
        64 + self.open.len() * 48 + self.open_calls.len() * 160
    }
}

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
    open: Vec<(Day, String, String, Option<String>, u64)>,
    copied: CopiedMode,
    copied_lines: u64,
    own_lines: u64,
    min_ts: Option<i64>,
    has_rendered: bool,
    cwd: Option<String>,
}

impl StoredParse {
    /// Bytes held in memory, approximately.
    pub(super) fn accounted_bytes(&self) -> usize {
        160 + self.session.len()
            + self.cwd.as_ref().map_or(0, String::len)
            + self.open.len() * 96
            + self
                .open_calls
                .iter()
                .map(|call| 192 + call.shares.len() * 96 + call.items.len() * 128)
                .sum::<usize>()
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
                        slot.server.as_deref().map(str::to_string),
                        *tokens,
                    )
                })
                .collect(),
            copied: state.copied,
            copied_lines: state.copied_lines,
            own_lines: state.own_lines,
            min_ts: state.min_ts,
            has_rendered: state.has_rendered,
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
        let mut open = Vec::new();
        for (day, kind, part, server, tokens) in self.open {
            let kind: Kind = kind_from_str(&kind)?;
            let part: Part = part_from_str(&part)?;
            open.push((
                day,
                Slot {
                    kind,
                    part,
                    server: server.map(Into::into),
                },
                tokens,
            ));
        }
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
