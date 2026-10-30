//! M1 durable warm-cache reuse: the record body for one retained
//! `CachedJsonlReduction` (CONTRACT.md M1; SOURCE field ruling and Amendment
//! 1), and the re-derivation of the content fields the body never carries.
//!
//! The body holds the allowlisted fields (`N`/`H`/`U`/`L`, see
//! `durable_tail_codec`) and, for each re-derived content field, the digest of
//! its value. The marks (`DurableMarks`, `SessionStartState::content_end`) say
//! where in the file each was last assigned. Production restore funds the
//! bounded typed workspace extractor before input. Other content obligations
//! still refuse before input. Empty obligations move the paid decoded graph.
//! The native parser remains a cfg(test) differential oracle only.
#![cfg_attr(not(test), allow(dead_code))]

#[cfg(test)]
use std::fs::File;
#[cfg(test)]
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
    let source =
        crate::durable_tail_store::DurableSource::from_snapshot(reduction.accumulator.source)
            .ok_or(Refuse::NotRederivable("SnapshotAccumulator.source"))?;
    (source.properties().encode)(reduction, limit, line_cap)
}

pub(in crate::snapshots) fn encode_body(
    reduction: &CachedJsonlReduction,
    limit: usize,
    line_cap: u64,
) -> Result<Vec<u8>, Refuse> {
    let CachedJsonlReduction {
        accumulator: acc,
        report,
        recognized_usage_drop_count,
        positive_recognized_usage_count,
        positive_usage_evidence,
    } = reduction;
    encode_parts(
        acc,
        report,
        (
            *recognized_usage_drop_count,
            *positive_recognized_usage_count,
            *positive_usage_evidence,
        ),
        limit,
        line_cap,
    )
}

/// Borrowed PRE-finalization state. Rederivation is computed once for both walks.
pub(in crate::snapshots) struct BodyEncoding<'a> {
    accumulator: &'a SnapshotAccumulator,
    report: &'a JsonlReadReport,
    scalars: (usize, usize, bool),
    rederive: Rederive,
}
impl<'a> BodyEncoding<'a> {
    pub(in crate::snapshots) fn new(
        accumulator: &'a SnapshotAccumulator,
        report: &'a JsonlReadReport,
        scalars: (usize, usize, bool),
        line_cap: u64,
    ) -> Result<Self, Refuse> {
        // Reuse source registration; no additional Claude/Codex dispatch table.
        super::super::sampled_scan::durable_tail::durable_source(accumulator.source)
            .ok_or(Refuse::NotRederivable("SnapshotAccumulator.source"))?;
        Ok(Self {
            accumulator,
            report,
            scalars,
            rederive: rederive_digests(accumulator, line_cap)?,
        })
    }
    fn put(&self, e: &mut Enc<'_>) -> Result<(), Refuse> {
        self.accumulator.put(e)?;
        self.report.put(e)?;
        self.scalars.0.put(e)?;
        self.scalars.1.put(e)?;
        self.scalars.2.put(e)?;
        self.rederive.put(e)
    }
    pub(in crate::snapshots) fn count(&self, limit: usize) -> Result<usize, Refuse> {
        let mut e = Enc::count(limit);
        self.put(&mut e)?;
        Ok(e.counted())
    }
    pub(in crate::snapshots) fn write(
        &self,
        out: &mut dyn std::io::Write,
        exact_len: usize,
    ) -> Result<usize, Refuse> {
        let mut e = Enc::writer(out, exact_len);
        self.put(&mut e)?;
        e.finish_written()
    }
}

// Same field order as CachedJsonlReduction::put, for retained and live callers.
pub(in crate::snapshots) fn encode_parts(
    acc: &SnapshotAccumulator,
    report: &JsonlReadReport,
    scalars: (usize, usize, bool),
    limit: usize,
    line_cap: u64,
) -> Result<Vec<u8>, Refuse> {
    let plan = BodyEncoding::new(acc, report, scalars, line_cap)?;
    let len = plan.count(limit)?;
    let mut out = Vec::with_capacity(len);
    plan.write(&mut out, len)?;
    Ok(out)
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

#[cfg(test)]
pub(crate) fn decode(body: &[u8], source: SnapshotSource) -> Result<Decoded, Corrupt> {
    let source = crate::durable_tail_store::DurableSource::from_snapshot(source).ok_or(Corrupt)?;
    let row = source.properties();
    (row.decode)(body, row.snapshot)
}

#[cfg(test)]
pub(in crate::snapshots) fn decode_body(
    body: &[u8],
    source: SnapshotSource,
) -> Result<Decoded, Corrupt> {
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

/// Funds typed decode only; re-derivation is a separate allocation boundary.
#[cfg(unix)]
pub(crate) fn decode_bounded(
    body: &[u8],
    source: SnapshotSource,
    lease: &mut crate::durable_tail_store::ActiveLease,
) -> Result<Decoded, crate::durable_tail_codec::DecodeFailure> {
    let source = crate::durable_tail_store::DurableSource::from_snapshot(source)
        .ok_or(crate::durable_tail_codec::DecodeFailure::Integrity)?;
    let row = source.properties();
    (row.decode_bounded)(body, row.snapshot, lease)
}

#[cfg(unix)]
pub(in crate::snapshots) fn decode_body_bounded(
    body: &[u8],
    source: SnapshotSource,
    lease: &mut crate::durable_tail_store::ActiveLease,
) -> Result<Decoded, crate::durable_tail_codec::DecodeFailure> {
    use crate::durable_tail_codec::DecodeFailure;
    if !crate::heap_layout_bound::layout_supported() {
        return Err(DecodeFailure::Budget);
    }
    lease
        .charge(std::mem::size_of::<Decoded>() as u64)
        .map_err(|_| DecodeFailure::Budget)?;
    let mut reserve = |bytes| lease.charge(bytes).is_ok();
    let mut d = Dec::bounded(body, &mut reserve);
    let result = (|| {
        let reduction = CachedJsonlReduction::take(&mut d)?;
        let rederive = Rederive::take(&mut d)?;
        if d.remaining() != 0 || reduction.accumulator.source != source {
            return Err(Corrupt);
        }
        Ok(Decoded {
            reduction,
            rederive,
        })
    })();
    d.outcome(result)
}

/// Re-derivation I/O, for the per-pass receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RederiveReceipt {
    pub(crate) head_bytes: u64,
    pub(crate) named_lines: u64,
    pub(crate) line_bytes: u64,
}

impl CachedJsonlReduction {
    pub(in crate::snapshots) fn durable_counting(&self) -> Option<(Option<i64>, u8, u8)> {
        self.accumulator.durable_counting()
    }
}
impl SnapshotAccumulator {
    /// Immutable counting input and mutable ACK evidence remain distinct.
    pub(in crate::snapshots) fn durable_counting(&self) -> Option<(Option<i64>, u8, u8)> {
        self.codex_counting.as_deref().map(|c| c.durable_contract())
    }
}
#[cfg(unix)]
mod content;

/// Content obligations without a supported, pre-funded extractor.
#[derive(Debug)]
pub(crate) struct RederiveUnfunded;

impl Decoded {
    pub(crate) fn cutover(&self) -> Option<Option<i64>> {
        self.reduction
            .accumulator
            .codex_counting
            .as_deref()
            .map(|c| c.durable_cutover())
    }

    /// Move the already-paid graph only when no content needs native input.
    /// Even a zero head mark cannot excuse a nonempty digest obligation.
    pub(crate) fn without_rederive(
        self,
    ) -> Result<(CachedJsonlReduction, RederiveReceipt), RederiveUnfunded> {
        if self.rederive != Rederive::default() {
            return Err(RederiveUnfunded);
        }
        Ok((self.reduction, RederiveReceipt::default()))
    }

    pub(in crate::snapshots) fn immutable_counting(
        &self,
    ) -> Result<crate::snapshots::ImmutableCounting, crate::durable_tail_store::Refusal> {
        crate::snapshots::ImmutableCounting::from_reduction(&self.reduction)
    }
    pub(crate) fn counting(&self) -> Option<(Option<i64>, u8, u8)> {
        self.reduction.durable_counting()
    }

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
    #[cfg(test)]
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
    #[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
        crate::durable_tail_store::DurableSource::from_snapshot(acc.source)
            .ok_or_else(|| anyhow::anyhow!("unadmitted durable source"))?
            .properties()
            .apply_line,
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
