//! Re-derivation of the content fields a stored reduction never carries. The
//! head holds, for each such field, the digest of its value; the marks
//! (`DurableMarks`, `SessionStartState::content_end`) say where in the file
//! each was last assigned. A load replays those lines and fences every field
//! before adoption.
#![cfg_attr(not(test), allow(dead_code))]

use std::fs::File;

pub(crate) mod pl_text;

use super::*;
use crate::durable_tail_codec::{Corrupt, Dec, Durable, Enc, Refuse, Shape};

/// Digests (`H`) of the re-derived values. `None`: the field is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Rederive {
    first_prompt: Option<[u8; 32]>,
    workspace: Option<[u8; 32]>,
    agent_label: Option<[u8; 32]>,
    session_start: Option<[u8; 32]>,
    title: Option<[u8; 32]>,
}
crate::durable_tail_codec::durable_struct!(Rederive {
    H first_prompt: Option<[u8; 32]>,
    H workspace: Option<[u8; 32]>,
    H agent_label: Option<[u8; 32]>,
    H session_start: Option<[u8; 32]>,
    H title: Option<[u8; 32]>,
});

fn digest(
    domain: &str,
    put: impl FnOnce(&mut Enc) -> Result<(), Refuse>,
) -> Result<[u8; 32], Refuse> {
    let mut e = Enc::hash(domain);
    put(&mut e)?;
    Ok(e.finish_hash())
}

fn first_prompt_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:first_prompt:v1", |e| {
        acc.first_prompt_material.put(e)?;
        acc.first_prompt_title.put(e)
    })
}

fn workspace_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    workspace_value_digest(&acc.workspace_path)
}

fn workspace_value_digest(path: &Option<PathBuf>) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:workspace:v1", |e| path.put(e))
}

fn agent_label_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:agent_label:v1", |e| {
        acc.codex_agent_label.put(e)
    })
}

fn title_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:title:v1", |e| acc.title.put(e))
}

/// A mark within `bound`, or the field is not re-derivable.
fn head_mark(mark: Option<u64>, bound: u64, field: &'static str) -> Result<u64, Refuse> {
    mark.filter(|end| *end <= bound)
        .ok_or(Refuse::NotRederivable(field))
}

/// The digests of the re-derived fields. Each needs a known mark within
/// `head_bound` (`line_cap` for the title line); Tail state passes no bound.
pub(in crate::snapshots) fn rederive_digests(
    acc: &SnapshotAccumulator,
    head_bound: u64,
    line_cap: u64,
) -> Result<Rederive, Refuse> {
    let marks = acc.durable_marks;
    let mut out = Rederive::default();
    if acc.first_prompt_material.is_some() || acc.first_prompt_title.is_some() {
        head_mark(
            marks.first_prompt,
            head_bound,
            "SnapshotAccumulator.first_prompt_material",
        )?;
        out.first_prompt = Some(first_prompt_digest(acc)?);
    }
    if acc.workspace_path.is_some() {
        head_mark(
            marks.workspace,
            head_bound,
            "SnapshotAccumulator.workspace_path",
        )?;
        out.workspace = Some(workspace_digest(acc)?);
    }
    if acc.codex_agent_label.is_some() {
        head_mark(
            marks.agent_label,
            head_bound,
            "SnapshotAccumulator.codex_agent_label",
        )?;
        out.agent_label = Some(agent_label_digest(acc)?);
    }
    out.session_start = acc
        .session_start
        .durable_content_digest(head_bound)?
        .map(|(digest, _)| digest);
    if acc.title.is_some() {
        marks
            .title_line
            .filter(|(_, len)| *len <= line_cap)
            .ok_or(Refuse::NotRederivable("SnapshotAccumulator.title"))?;
        out.title = Some(title_digest(acc)?);
    }
    Ok(out)
}

/// A decoded record before re-derivation. Its content fields are empty.
pub(crate) struct Decoded {
    reduction: CachedJsonlReduction,
    rederive: Rederive,
}
impl Decoded {
    /// Stored Tail state before re-derivation.
    pub(in crate::snapshots) fn stored(
        reduction: CachedJsonlReduction,
        rederive: Rederive,
    ) -> Self {
        Self {
            reduction,
            rederive,
        }
    }
}

/// Re-derivation I/O, for the per-pass receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RederiveReceipt {
    pub(crate) head_bytes: u64,
    pub(crate) named_lines: u64,
    pub(crate) line_bytes: u64,
}

#[cfg(unix)]
mod bounded_value;
#[cfg(unix)]
mod content;

impl Decoded {
    /// How far the head re-parse must read: the latest mark of a field to
    /// re-derive, each within `bound`. 0 when nothing needs the head.
    pub(crate) fn head_end(&self, bound: u64) -> Result<u64, Refuse> {
        let acc = &self.reduction.accumulator;
        let marks = acc.durable_marks;
        let mut end = 0;
        if self.rederive.first_prompt.is_some() {
            end = end.max(head_mark(
                marks.first_prompt,
                bound,
                "SnapshotAccumulator.first_prompt_material",
            )?);
        }
        if self.rederive.workspace.is_some() {
            end = end.max(head_mark(
                marks.workspace,
                bound,
                "SnapshotAccumulator.workspace_path",
            )?);
        }
        if self.rederive.agent_label.is_some() {
            end = end.max(head_mark(
                marks.agent_label,
                bound,
                "SnapshotAccumulator.codex_agent_label",
            )?);
        }
        if self.rederive.session_start.is_some() {
            end = end.max(head_mark(
                acc.session_start.durable_content_end(),
                bound,
                "SessionStartState.content_end",
            )?);
        }
        Ok(end)
    }

    /// The title line to pread, when the head re-parse does not reach it.
    fn title_line(&self, head_end: u64) -> Result<Option<(u64, u64)>, Refuse> {
        if self.rederive.title.is_none() {
            return Ok(None);
        }
        let (offset, len) = self
            .reduction
            .accumulator
            .durable_marks
            .title_line
            .ok_or(Refuse::NotRederivable("SnapshotAccumulator.title"))?;
        Ok((offset.saturating_add(len) > head_end).then_some((offset, len)))
    }
}
