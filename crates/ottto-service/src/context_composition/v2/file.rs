//! Reading one transcript from its checkpoint: the line loop, the sink the
//! line handlers write to, and the head scan that fixes a new checkpoint's
//! identity.

use super::aggregate::{Day, Entered, Sink, Slot};
use super::checkpoint::ParseState;
use super::reader::{LineEvent, LineReader};
use super::{claude, codex};
use crate::composition_kinds::Kind;
use std::fs::File;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Source {
    Claude,
    Codex,
}

impl Source {
    pub(super) fn label(self) -> &'static str {
        match self {
            Source::Claude => "claude-code",
            Source::Codex => "codex",
        }
    }
}

/// Line counters for one run.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct LineStats {
    pub(super) lines: u64,
    pub(super) prefix_skipped: u64,
    pub(super) bad_lines: u64,
    pub(super) too_long: u64,
    pub(super) classifier_skipped: u64,
    pub(super) dropped_calls: u64,
    pub(super) dropped_items: u64,
}

/// What line handlers write to: the scope's totals and the counters.
pub(super) struct LineSink<'a> {
    pub(super) sink: Sink<'a>,
    /// Claude records dated before this (unix seconds) are copied history.
    pub(super) copied_before: Option<i64>,
    /// Day for lines without a timestamp: the day they are read.
    pub(super) fallback_day: Day,
    pub(super) stats: &'a mut LineStats,
}

impl LineSink<'_> {
    /// A counted request: every open line stays in context for it.
    pub(super) fn request(&mut self, state: &ParseState) {
        for (day, slot, tokens) in &state.open {
            self.sink.residency(*day, slot, *tokens);
        }
    }

    /// One entered item. A copied line only stays resident for this
    /// session's own requests: it adds residency, nothing else.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record(
        &mut self,
        state: &mut ParseState,
        day: Day,
        slot: Slot,
        tokens: u64,
        images: u64,
        file: Option<&str>,
        ts: Option<i64>,
        copied: bool,
    ) {
        if !self.sink.window.contains(day) {
            return;
        }
        if !copied {
            self.sink.entered(&Entered {
                day,
                slot: slot.clone(),
                tokens,
                images,
                file,
                session: &state.session,
                ts,
            });
        }
        state.add_open(day, &slot, tokens);
    }

    pub(super) fn tool(
        &mut self,
        day: Day,
        tool: &str,
        kind: Kind,
        session: &str,
        tokens: u64,
        call: bool,
    ) {
        self.sink.tool(day, tool, kind, session, tokens, call);
    }
}

/// Where a read stopped.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReadEnd {
    pub(super) offset: u64,
    pub(super) skipping: bool,
    pub(super) bytes: u64,
    /// Stopped by the run's wall cap before the length at open.
    pub(super) cut: bool,
    pub(super) buffer_bytes: usize,
}

/// A read that failed part way, and the bytes it read before failing.
#[derive(Debug)]
pub(super) struct ReadError {
    pub(super) bytes: u64,
}

/// Read complete lines from `offset` to `end` (the length at open).
#[allow(clippy::too_many_arguments)]
pub(super) fn read_lines(
    file: File,
    offset: u64,
    end: u64,
    skipping: bool,
    source: Source,
    state: &mut ParseState,
    out: &mut LineSink,
    deadline: Instant,
) -> Result<ReadEnd, ReadError> {
    let mut reader =
        LineReader::open(file, offset, end, skipping).map_err(|_| ReadError { bytes: 0 })?;
    let mut cut = false;
    let mut count = 0u64;
    let mut buffer_bytes = 0usize;
    loop {
        if count % 512 == 0 && Instant::now() >= deadline {
            cut = true;
            break;
        }
        count += 1;
        let event = match reader.next_event() {
            Ok(event) => event,
            Err(_) => {
                return Err(ReadError {
                    bytes: reader.position() - offset,
                })
            }
        };
        match event {
            None => break,
            Some(LineEvent::TooLong) => out.stats.too_long += 1,
            Some(LineEvent::Line(line)) => match source {
                Source::Claude => claude::handle_line(out, state, line),
                Source::Codex => codex::handle_line(out, state, line),
            },
        }
        buffer_bytes = buffer_bytes.max(reader.buffer_bytes());
    }
    Ok(ReadEnd {
        offset: reader.position(),
        skipping: reader.skipping(),
        bytes: reader.position() - offset,
        cut: cut && reader.position() < end,
        buffer_bytes,
    })
}

const HEAD_LINES: usize = 64;
const HEAD_BYTES: u64 = 8 * 1024 * 1024;
const HEAD_LINE_GUARD: usize = 4 * 1024 * 1024;

/// The first complete lines of a transcript (at most `HEAD_LINES` within
/// `HEAD_BYTES`), each handed to `each` until it returns false, and the bytes
/// read.
fn head_scan(
    path: &Path,
    deadline: Option<Instant>,
    mut each: impl FnMut(&str) -> bool,
) -> std::io::Result<u64> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut reader = LineReader::with_guard(file, 0, len.min(HEAD_BYTES), false, HEAD_LINE_GUARD)?;
    let mut lines = 0usize;
    while lines < HEAD_LINES {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "run wall cap reached",
            ));
        }
        match reader.next_event()? {
            None => break,
            Some(LineEvent::TooLong) => continue,
            Some(LineEvent::Line(line)) => {
                if let Ok(text) = std::str::from_utf8(line) {
                    let text = text.trim();
                    if !text.is_empty() {
                        lines += 1;
                        if !each(text) {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(reader.position())
}

/// The first complete lines of a transcript (bounded), for its identity,
/// and the bytes read.
pub(super) fn head_lines(path: &Path) -> std::io::Result<(Vec<String>, u64)> {
    let mut lines = Vec::new();
    let bytes = head_scan(path, None, |text| {
        lines.push(text.to_string());
        true
    })?;
    Ok((lines, bytes))
}

/// The folders a transcript's first lines name (bounded like
/// `head_lines`), in order and without repeats, and the bytes read.
pub(super) fn head_cwds(path: &Path, deadline: Instant) -> std::io::Result<(Vec<String>, u64)> {
    let mut cwds: Vec<String> = Vec::new();
    let bytes = head_scan(path, Some(deadline), |text| {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return true;
        };
        let cwd = value
            .get("cwd")
            .or_else(|| value.get("payload").and_then(|payload| payload.get("cwd")))
            .or_else(|| {
                value
                    .get("turn_context")
                    .and_then(|context| context.get("payload"))
                    .and_then(|payload| payload.get("cwd"))
            })
            .and_then(serde_json::Value::as_str);
        if let Some(cwd) = cwd.filter(|cwd| !cwd.is_empty()) {
            if !cwds.iter().any(|seen| seen == cwd) {
                cwds.push(cwd.to_string());
            }
        }
        true
    })?;
    Ok((cwds, bytes))
}

/// A fresh parse state for a transcript first read at `offset` (0 for a
/// full read), and the head bytes read to build it.
pub(super) fn new_parse_state(source: Source, path: &Path, offset: u64) -> (ParseState, u64) {
    let (lines, bytes) = head_lines(path).unwrap_or_default();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let mut state = ParseState::default();
    match source {
        Source::Claude => {
            let (session, sidechain) = claude::head_identity(&refs, path);
            state.session = session.into();
            state.agent_author = sidechain;
        }
        Source::Codex => {
            let identity = codex::head_identity(&refs, path);
            state.session = identity.session.into();
            state.agent_author = identity.agent_author;
            state.cwd = identity.cwd.map(Into::into);
            state.copied = identity.copied;
            if offset > 0 && state.copied == super::checkpoint::CopiedMode::UntilTrigger {
                // Read from the middle: the trigger turn is behind us.
                state.copied = super::checkpoint::CopiedMode::Own;
            }
        }
    }
    (state, bytes)
}
