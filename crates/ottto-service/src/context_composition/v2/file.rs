//! Reading one transcript from its checkpoint: the line loop, the sink the
//! line handlers write to, and the head scan that fixes a new checkpoint's
//! identity.

use super::aggregate::{Day, Entered, Sink, Slot};
use super::checkpoint::ParseState;
use super::reader::{LineEvent, LineReader};
use super::upload::safe_file_name;
use super::{claude, codex};
use crate::composition_kinds::{
    self as kinds, Author, CallClass, CellShare, GitRootCache, Kind, KindsVersion, LineCtx,
    Request1,
};
use std::fs::File;
use std::path::Path;
use std::time::Instant;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
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
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub(super) struct LineStats {
    pub(super) lines: u64,
    pub(super) prefix_skipped: u64,
    pub(super) bad_lines: u64,
    pub(super) too_long: u64,
    pub(super) classifier_skipped: u64,
    pub(super) dropped_calls: u64,
    pub(super) dropped_items: u64,
    /// File names left out of the totals: not display-safe (the tokens
    /// still count, under no file).
    pub(super) unnamed_files: u64,
    /// Codex `web_search_end` events inside an open call: the call's output
    /// holds the search, so it counts once, there.
    pub(super) web_search_in_call: u64,
}

/// How the file paths a transcript names become the names kept in state:
/// repo-relative within the scope's repository (any checkout of it), else
/// the basename, resolved when the line is read (a worktree removed later
/// can no longer be looked up). State never keeps an absolute path.
pub(super) enum Names<'a> {
    Resolve {
        /// One per scan, shared by every scope.
        cache: &'a mut GitRootCache,
        workspace: &'a Path,
        repository_hash: Option<&'a str>,
    },
    /// Paths as written (the kinds_version 1 parity tests compare with the
    /// kinds_version 1 reader, which keeps them so).
    #[cfg(test)]
    Raw,
}

impl Names<'_> {
    fn name(&mut self, raw: &str) -> Option<String> {
        match self {
            Names::Resolve {
                cache,
                workspace,
                repository_hash,
            } => kinds::repo_relative(raw, workspace, *repository_hash, cache)
                .and_then(|name| safe_file_name(&name)),
            #[cfg(test)]
            Names::Raw => Some(raw.to_string()),
        }
    }
}

/// What line handlers write to: the scope's totals and the counters.
pub(super) struct LineSink<'a> {
    pub(super) sink: Sink<'a>,
    /// Claude records dated before this (unix seconds) are copied history.
    pub(super) copied_before: Option<i64>,
    /// Day for lines without a timestamp: the day they are read.
    pub(super) fallback_day: Day,
    pub(super) stats: &'a mut LineStats,
    /// The methodology lines are classified with: kinds_version 2, except
    /// in the tests that compare with the kinds_version 1 reader.
    pub(super) kinds: KindsVersion,
    pub(super) names: Names<'a>,
}

impl LineSink<'_> {
    /// The classifier's context for one line.
    pub(super) fn ctx<'p>(
        &self,
        state: &ParseState,
        cwd: Option<&'p Path>,
        file_has_rendered: bool,
        author: Author,
    ) -> LineCtx<'p> {
        match self.kinds {
            KindsVersion::V1 => LineCtx::v1(),
            KindsVersion::V2 => LineCtx::v2(
                if state.request1_closed {
                    Request1::No
                } else if state.start_measured {
                    Request1::StartMeasured
                } else {
                    Request1::StartNotMeasured
                },
                cwd,
                file_has_rendered,
                author,
            ),
        }
    }

    /// One tool call's result, split into the call's shares (`cells`, from
    /// `codex_cell`). Each share counts under its own kind, part and file;
    /// the tool totals count it under the add-on tool behind it, else the
    /// call's own tool, once per call for each tool.
    pub(super) fn result(
        &mut self,
        state: &mut ParseState,
        day: Day,
        call: &CallClass,
        cells: Vec<CellShare>,
        ts: Option<i64>,
        copied: bool,
    ) {
        // (tool, tokens, the kind of its largest share and that share's tokens)
        let mut tools: Vec<(&str, u64, Kind, u64)> = Vec::new();
        for cell in &cells {
            let tool = cell
                .tool
                .as_ref()
                .map_or(call.tool.as_str(), |tool| tool.as_str());
            let slot = Slot::new(cell.kind, cell.part, tool);
            self.record(
                state,
                day,
                slot,
                cell.tokens,
                0,
                cell.file.as_deref(),
                ts,
                copied,
            );
            match tools.iter_mut().find(|(known, ..)| *known == tool) {
                Some((_, tokens, kind, largest)) => {
                    *tokens += cell.tokens;
                    if cell.tokens > *largest {
                        *kind = cell.kind;
                        *largest = cell.tokens;
                    }
                }
                None => tools.push((tool, cell.tokens, cell.kind, cell.tokens)),
            }
        }
        if copied {
            return;
        }
        for (tool, tokens, kind, _) in tools {
            self.tool(day, tool, kind, &state.session, tokens, true);
        }
    }

    /// A counted request: every open line stays in context for it.
    pub(super) fn request(&mut self, state: &ParseState) {
        for (day, slot, tokens) in &state.open {
            self.sink.residency(*day, slot, *tokens);
        }
    }

    /// One entered item. A copied line only stays resident for this
    /// session's own requests: it adds residency, nothing else.
    #[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
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
        debug_assert!(
            self.kinds == KindsVersion::V1 || Kind::V2.contains(&slot.kind),
            "a kinds_version 2 line counted under {:?}",
            slot.kind
        );
        if !copied {
            let name = file.and_then(|raw| {
                let name = self.names.name(raw);
                self.stats.unnamed_files += u64::from(name.is_none());
                name
            });
            self.sink.entered(&Entered {
                day,
                slot: slot.clone(),
                tokens,
                images,
                file: name.as_deref(),
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
#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
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
pub(super) const HEAD_BYTES: u64 = 8 * 1024 * 1024;
const HEAD_LINE_GUARD: usize = 4 * 1024 * 1024;

/// The first complete lines of a transcript (at most `HEAD_LINES` within
/// `HEAD_BYTES`), each handed to `each` until it returns false, and the bytes
/// read.
fn head_scan(
    path: &Path,
    deadline: Option<Instant>,
    byte_limit: u64,
    mut each: impl FnMut(&str) -> bool,
) -> std::io::Result<u64> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "run wall cap reached",
        ));
    }
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut reader = LineReader::with_buffer(
        file,
        0,
        len.min(HEAD_BYTES).min(byte_limit),
        false,
        HEAD_LINE_GUARD,
        8192,
    )?;
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
pub(super) fn head_lines(source: Source, path: &Path) -> std::io::Result<(Vec<String>, u64)> {
    head_lines_before(source, path, None, HEAD_BYTES)
}

fn head_lines_before(
    source: Source,
    path: &Path,
    deadline: Option<Instant>,
    byte_limit: u64,
) -> std::io::Result<(Vec<String>, u64)> {
    let mut lines = Vec::new();
    let bytes = head_scan(path, deadline, byte_limit, |text| {
        lines.push(text.to_string());
        // Stop once the first-sight identity is complete. Large outputs
        // following a metadata row are never needed for identity.
        let Ok(row) = serde_json::from_str::<serde_json::Value>(text) else {
            return true;
        };
        match source {
            Source::Codex => row["type"] != "session_meta",
            Source::Claude => {
                !(row["sessionId"].is_string()
                    && row["isSidechain"].is_boolean()
                    && (row["isSidechain"] == false || row["agentId"].is_string()))
            }
        }
    })?;
    Ok((lines, bytes))
}

/// The folders a transcript's first lines name (bounded like
/// `head_lines`), in order and without repeats, and the bytes read.
pub(super) fn head_cwds(path: &Path, deadline: Instant) -> std::io::Result<(Vec<String>, u64)> {
    let mut cwds: Vec<String> = Vec::new();
    let bytes = head_scan(path, Some(deadline), HEAD_BYTES, |text| {
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
            if Path::new(cwd).is_dir() {
                return false;
            }
        }
        true
    })?;
    Ok((cwds, bytes))
}

/// A fresh parse state for a transcript first read at `offset` (0 for a
/// full read), and the head bytes read to build it.
pub(super) fn new_parse_state(source: Source, path: &Path, offset: u64) -> (ParseState, u64) {
    let (lines, bytes) = head_lines(source, path).unwrap_or_default();
    (parse_head(source, path, offset, &lines), bytes)
}

/// The same identity probe, with the run's cooperative I/O deadline.
pub(super) fn new_parse_state_before(
    source: Source,
    path: &Path,
    deadline: Instant,
) -> std::io::Result<(ParseState, u64)> {
    let (lines, bytes) = head_lines_before(source, path, Some(deadline), HEAD_BYTES)?;
    Ok((parse_head(source, path, 0, &lines), bytes))
}

fn parse_head(source: Source, path: &Path, offset: u64, lines: &[String]) -> ParseState {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    // The skipped prefix may already contain the first response. Treat new
    // bytes as later work rather than suppressing them under a start verdict.
    let mut state = ParseState {
        request1_closed: offset > 0,
        ..Default::default()
    };
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
    state
}
