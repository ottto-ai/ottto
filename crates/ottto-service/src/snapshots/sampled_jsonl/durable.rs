//! M1 durable warm-cache reuse: the record body for one retained
//! `CachedJsonlReduction` (CONTRACT.md M1; SOURCE field ruling and Amendment
//! 1), and the re-derivation of the content fields the body never carries.
//!
//! The body holds the allowlisted fields (`N`/`H`/`U`/`L`, see
//! `durable_tail_codec`) and, for each re-derived content field, the digest of
//! its value. The marks (`DurableMarks`, `SessionStartState::content_end`) say
//! where in the file each was last assigned. Restore re-parses the file head
//! up to the latest mark, at most `HEAD_BOUND` bytes, and preads at most one
//! named line (the title); every value must hash-equal its digest, else the
//! entry reads in Full.
#![cfg_attr(not(test), allow(dead_code))]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::*;
use crate::durable_tail_codec::{Corrupt, Dec, Durable, Enc, Refuse, Shape};

/// Head re-parse bound for re-derived first-write-wins fields (Amendment 1,
/// C-4).
pub(crate) const HEAD_BOUND: u64 = 1024 * 1024;

/// At most this many named lines are pread per entry (Amendment 1). M1 uses
/// one: the title.
pub(crate) const NAMED_LINES: usize = 4;

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
    digest("ottto-dt-rederive:workspace:v1", |e| {
        acc.workspace_path.put(e)
    })
}

fn agent_label_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:agent_label:v1", |e| {
        acc.codex_agent_label.put(e)
    })
}

fn title_digest(acc: &SnapshotAccumulator) -> Result<[u8; 32], Refuse> {
    digest("ottto-dt-rederive:title:v1", |e| acc.title.put(e))
}

/// The allowlist digest for `source`: the compiled field lists and classes
/// of every persisted type, the static label table and the bounds.
pub(crate) fn allowlist_digest(source: SnapshotSource) -> [u8; 32] {
    let mut shape = Shape::default();
    shape.push("ottto-dt-reduction:v1");
    shape.push(source.api_slug());
    shape.push(&format!(
        "head_bound={HEAD_BOUND};named_lines={NAMED_LINES}"
    ));
    CachedJsonlReduction::shape(&mut shape);
    Rederive::shape(&mut shape);
    shape.digest()
}

#[cfg(test)]
pub(crate) fn shape_text() -> String {
    let mut shape = Shape::default();
    CachedJsonlReduction::shape(&mut shape);
    Rederive::shape(&mut shape);
    shape.text().to_string()
}

/// A mark within the head bound, or the field is not re-derivable.
fn head_mark(mark: Option<u64>, field: &'static str) -> Result<u64, Refuse> {
    mark.filter(|end| *end <= HEAD_BOUND)
        .ok_or(Refuse::NotRederivable(field))
}

fn rederive_digests(acc: &SnapshotAccumulator, line_cap: u64) -> Result<Rederive, Refuse> {
    let marks = acc.durable_marks;
    let mut out = Rederive::default();
    if acc.first_prompt_material.is_some() || acc.first_prompt_title.is_some() {
        head_mark(
            marks.first_prompt,
            "SnapshotAccumulator.first_prompt_material",
        )?;
        out.first_prompt = Some(first_prompt_digest(acc)?);
    }
    if acc.workspace_path.is_some() {
        head_mark(marks.workspace, "SnapshotAccumulator.workspace_path")?;
        out.workspace = Some(workspace_digest(acc)?);
    }
    if acc.codex_agent_label.is_some() {
        head_mark(marks.agent_label, "SnapshotAccumulator.codex_agent_label")?;
        out.agent_label = Some(agent_label_digest(acc)?);
    }
    out.session_start = acc
        .session_start
        .durable_content_digest(HEAD_BOUND)?
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

/// The record body for a retained reduction, or why it is not persisted.
/// Only Claude Code and Codex entries are persisted in M1.
pub(crate) fn encode(
    reduction: &CachedJsonlReduction,
    limit: usize,
    line_cap: u64,
) -> Result<Vec<u8>, Refuse> {
    let acc = &reduction.accumulator;
    if !matches!(
        acc.source,
        SnapshotSource::ClaudeCode | SnapshotSource::Codex
    ) {
        return Err(Refuse::NotRederivable("SnapshotAccumulator.source"));
    }
    let rederive = rederive_digests(acc, line_cap)?;
    let mut e = Enc::bytes(limit);
    reduction.put(&mut e)?;
    rederive.put(&mut e)?;
    Ok(e.into_bytes())
}

/// Structural body verification only: no reduction, re-derivation or live
/// inputs. The caller separately checks source/binding and envelope integrity.
/// Precondition: check size, mode and the envelope trailer before this walk.
pub(crate) fn verify(body: &[u8]) -> Result<(), Corrupt> {
    let mut d = Dec::new(body);
    CachedJsonlReduction::verify(&mut d)?;
    Rederive::verify(&mut d)?;
    d.finish()
}

/// A decoded record before re-derivation. Its content fields are empty.
pub(crate) struct Decoded {
    reduction: CachedJsonlReduction,
    rederive: Rederive,
}

pub(crate) fn decode(body: &[u8], source: SnapshotSource) -> Result<Decoded, Corrupt> {
    let mut d = Dec::new(body);
    let reduction = CachedJsonlReduction::take(&mut d)?;
    let rederive = Rederive::take(&mut d)?;
    d.finish()?;
    if reduction.accumulator.source != source {
        return Err(Corrupt);
    }
    Ok(Decoded {
        reduction,
        rederive,
    })
}

/// Re-derivation I/O, for the per-pass receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RederiveReceipt {
    pub(crate) head_bytes: u64,
    pub(crate) named_lines: u64,
    pub(crate) line_bytes: u64,
}

impl Decoded {
    /// How far the head re-parse must read: the latest mark of a field to
    /// re-derive. 0 when nothing needs the head.
    pub(crate) fn head_end(&self) -> Result<u64, Refuse> {
        let acc = &self.reduction.accumulator;
        let marks = acc.durable_marks;
        let mut end = 0;
        if self.rederive.first_prompt.is_some() {
            end = end.max(head_mark(
                marks.first_prompt,
                "SnapshotAccumulator.first_prompt_material",
            )?);
        }
        if self.rederive.workspace.is_some() {
            end = end.max(head_mark(
                marks.workspace,
                "SnapshotAccumulator.workspace_path",
            )?);
        }
        if self.rederive.agent_label.is_some() {
            end = end.max(head_mark(
                marks.agent_label,
                "SnapshotAccumulator.codex_agent_label",
            )?);
        }
        if self.rederive.session_start.is_some() {
            end = end.max(head_mark(
                acc.session_start.durable_content_end(),
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

    /// Re-derives the content fields with `parser`, a fresh parser for the
    /// same source and options on a descriptor of the same file positioned at
    /// 0 (`rederive_parser`), and `file` for the named-line pread. Every value
    /// must hash-equal its digest. The decoded copy is consumed either way: a
    /// refusal leaves nothing behind.
    pub(crate) fn rederive(
        self,
        mut parser: OwnedJsonlParser,
        file: &mut File,
        line_cap: u64,
    ) -> Result<(CachedJsonlReduction, RederiveReceipt), Refuse> {
        let end = self.head_end()?;
        let title_line = self.title_line(end)?;
        let Self {
            mut reduction,
            rederive,
        } = self;
        let mut receipt = RederiveReceipt::default();
        let refused = Refuse::NotRederivable;
        if end > 0 {
            parser.reader.set_extent_limit(end);
            loop {
                match parser.step() {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(_) => return Err(refused("head")),
                }
            }
            receipt.head_bytes = parser.reader.consumed_bytes();
            if receipt.head_bytes != end {
                return Err(refused("head"));
            }
        }
        if let Some((offset, len)) = title_line {
            if len > line_cap || len == 0 {
                return Err(refused("SnapshotAccumulator.title"));
            }
            let line =
                pread_line(file, offset, len).map_err(|_| refused("SnapshotAccumulator.title"))?;
            receipt.named_lines = 1;
            receipt.line_bytes = len;
            let value = std::str::from_utf8(&line)
                .ok()
                .and_then(|text| {
                    serde_json::from_str::<Value>(text.trim_end_matches(['\n', '\r'])).ok()
                })
                .ok_or(refused("SnapshotAccumulator.title"))?;
            parser.tee_line(&value);
        }
        let fresh = &mut parser.accumulator;
        let acc = &mut reduction.accumulator;
        if let Some(expected) = rederive.first_prompt {
            if first_prompt_digest(fresh)? != expected {
                return Err(refused("SnapshotAccumulator.first_prompt_material"));
            }
            acc.first_prompt_material = fresh.first_prompt_material.take();
            acc.first_prompt_title = fresh.first_prompt_title.take();
        }
        if let Some(expected) = rederive.workspace {
            if workspace_digest(fresh)? != expected {
                return Err(refused("SnapshotAccumulator.workspace_path"));
            }
            acc.workspace_path = fresh.workspace_path.take();
        }
        if let Some(expected) = rederive.agent_label {
            if agent_label_digest(fresh)? != expected {
                return Err(refused("SnapshotAccumulator.codex_agent_label"));
            }
            acc.codex_agent_label = fresh.codex_agent_label.take();
        }
        if let Some(expected) = rederive.session_start {
            if fresh.session_start.durable_content_hash()? != expected {
                return Err(refused("SessionStartState.content_end"));
            }
            acc.session_start
                .adopt_durable_content(&mut fresh.session_start);
        }
        if let Some(expected) = rederive.title {
            if title_digest(fresh)? != expected {
                return Err(refused("SnapshotAccumulator.title"));
            }
            acc.title = fresh.title.take();
        }
        Ok((reduction, receipt))
    }
}

/// Exactly one complete line: `len` bytes at `offset`, ending in a newline.
fn pread_line(file: &mut File, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let mut line = vec![0; len];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut line)?;
    if line.last() != Some(&b'\n') {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(line)
}

/// A fresh parser for re-derivation: the same source and options as the
/// record's, no title metadata and no live inputs (no re-derived field reads
/// them), and no reread binding (a bounded head read, not a Full).
pub(crate) fn rederive_parser(
    mut file: File,
    path: &Path,
    decoded: &Decoded,
) -> Result<OwnedJsonlParser> {
    if decoded.reduction.accumulator.source == SnapshotSource::Codex {
        refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)?;
    }
    // A duplicated descriptor shares the held one's offset: start at 0.
    file.seek(SeekFrom::Start(0))?;
    let acc = &decoded.reduction.accumulator;
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        acc.source,
        match acc.source {
            SnapshotSource::Codex => apply_codex_line,
            SnapshotSource::ClaudeCode => apply_claude_code_line,
            SnapshotSource::Pi => apply_pi_line,
        },
        None,
        None,
        None,
        acc.artifacts_enabled,
        acc.context_curve_enabled,
    )?;
    parser.accumulator.claude_request_identity_capture = acc.claude_request_identity_capture;
    Ok(parser)
}

#[cfg(test)]
#[path = "durable_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn store_fixture_body(source: SnapshotSource, count: u64, sum: u64) -> Vec<u8> {
    let reduction = CachedJsonlReduction {
        accumulator: SnapshotAccumulator::new(source),
        report: JsonlReadReport::default(),
        recognized_usage_drop_count: count as usize,
        positive_recognized_usage_count: sum as usize,
        positive_usage_evidence: false,
    };
    encode(
        &reduction,
        crate::durable_tail_store::RECORD_BYTES,
        1024 * 1024,
    )
    .unwrap()
}
