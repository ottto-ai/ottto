//! Wire shape, validation and budget pruning for serialized context curves.
//!
//! The daemon no longer builds full uploaded curves (retired with the
//! `session_context_curve:v1` negotiation). Retained bodies may still carry
//! one, so the wire structs, validation and pruning stay.

use super::timestamp_is_after;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) const MAX_CONTEXT_CURVE_POINTS: usize = 256;
pub(super) const MAX_CONTEXT_CURVE_BOUNDARIES: usize = 64;
pub(super) const MAX_CONTEXT_CURVE_MODEL_WINDOWS: usize = 16;
pub(super) const MAX_CONTEXT_CURVE_WIRE_BYTES: usize = 64 * 1024;
pub(crate) const CONTEXT_CURVE_CONTRACT_VERSION: &str = "session_context_curve:v1";
pub(super) const CONTEXT_CURVE_SAMPLING_REVISION: &str = "deterministic_even_gap:v1";
pub(super) const CONTEXT_CURVE_RETENTION_ANCHOR: u16 = 0x01;
pub(super) const CONTEXT_CURVE_RETENTION_COMPACTION_BEFORE: u16 = 0x02;
pub(super) const CONTEXT_CURVE_RETENTION_COMPACTION_AFTER: u16 = 0x04;
pub(super) const CONTEXT_CURVE_RETENTION_PEAK: u16 = 0x08;
pub(super) const CONTEXT_CURVE_RETENTION_TAIL: u16 = 0x10;
pub(super) const CONTEXT_CURVE_RETENTION_FILL: u16 = 0x20;

// Retired: the two candidate types below are kept only as always-empty
// durable-tail accumulator slots, so the pinned allowlist digest and the
// records already on disk stay readable without a Full re-read.
#[derive(Debug, Clone)]
pub(super) struct ContextCurveCandidatePoint {
    pub(super) observed_at: Option<String>,
    pub(super) effective_input_tokens: u64,
    pub(super) model: Option<String>,
    pub(super) context_window_tokens: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct ContextCurveCandidateBoundary {
    pub(super) observed_at: Option<String>,
    pub(super) point_count_before: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct SnapshotContextCurvePoint {
    pub owned_request_ordinal: u64,
    pub observed_at: String,
    pub effective_input_tokens: u64,
    pub model_window_index: u16,
    pub segment_ordinal: u64,
    pub retention_flags: u16,
    pub compaction_before_request_boundary_index: Option<u64>,
    pub compaction_after_request_boundary_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct SnapshotContextCurveBoundary {
    pub boundary_index: u64,
    pub observed_at: String,
    pub before_owned_request_ordinal: u64,
    pub after_owned_request_ordinal: u64,
    pub segment_before_ordinal: u64,
    pub segment_after_ordinal: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct SnapshotContextCurveModelWindow {
    pub model_window_index: u16,
    pub model: String,
    pub context_window_tokens: Option<u64>,
    pub evidence_kind: String,
    pub evidence_revision: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct SnapshotContextCurve {
    pub contract_version: String,
    pub parser_revision: String,
    pub ownership_revision: String,
    pub sampling_revision: String,
    pub coverage: String,
    pub total_owned_request_count: u64,
    pub retained_point_count: u64,
    pub total_compaction_boundary_count: u64,
    pub retained_boundary_count: u64,
    pub points: Vec<SnapshotContextCurvePoint>,
    pub boundaries: Vec<SnapshotContextCurveBoundary>,
    pub model_windows: Vec<SnapshotContextCurveModelWindow>,
}

pub(super) fn unavailable_context_curve(
    parser_revision: &str,
    ownership_revision: &str,
    coverage: &str,
    _total_owned_request_count: u64,
    _total_compaction_boundary_count: u64,
) -> SnapshotContextCurve {
    SnapshotContextCurve {
        contract_version: CONTEXT_CURVE_CONTRACT_VERSION.to_string(),
        parser_revision: parser_revision.to_string(),
        ownership_revision: ownership_revision.to_string(),
        sampling_revision: CONTEXT_CURVE_SAMPLING_REVISION.to_string(),
        coverage: coverage.to_string(),
        total_owned_request_count: 0,
        retained_point_count: 0,
        total_compaction_boundary_count: 0,
        retained_boundary_count: 0,
        points: Vec::new(),
        boundaries: Vec::new(),
        model_windows: Vec::new(),
    }
}

fn safe_context_curve_model(value: Option<&str>) -> String {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return "unknown".to_string();
    };
    if value.len() > 128
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "-._:".contains(character)))
    {
        return "unknown".to_string();
    }
    value.to_string()
}

fn context_curve_revision_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._:".contains(character))
}

fn compact_context_curve_model_windows(curve: &mut SnapshotContextCurve) {
    let used = curve
        .points
        .iter()
        .map(|point| point.model_window_index)
        .collect::<BTreeSet<_>>();
    let mut old_to_new = BTreeMap::new();
    curve.model_windows.retain(|window| {
        if !used.contains(&window.model_window_index) {
            return false;
        }
        let next = old_to_new.len() as u16;
        old_to_new.insert(window.model_window_index, next);
        true
    });
    for (index, window) in curve.model_windows.iter_mut().enumerate() {
        window.model_window_index = index as u16;
    }
    for point in &mut curve.points {
        point.model_window_index = old_to_new[&point.model_window_index];
    }
}

pub(super) fn prune_one_context_curve_fill_point(curve: &mut SnapshotContextCurve) -> bool {
    let Some(remove_index) = curve
        .points
        .iter()
        .rposition(|point| point.retention_flags == CONTEXT_CURVE_RETENTION_FILL)
    else {
        return false;
    };
    curve.points.remove(remove_index);
    curve.retained_point_count = curve.points.len() as u64;
    curve.coverage = "sampled".to_string();
    compact_context_curve_model_windows(curve);
    true
}

pub(super) fn validate_context_curve(
    index: usize,
    curve: &SnapshotContextCurve,
) -> Result<(), String> {
    let fail = |message: &str| format!("snapshot[{index}] context_curve {message}");
    if curve.contract_version != CONTEXT_CURVE_CONTRACT_VERSION {
        return Err(fail("has unsupported contract_version"));
    }
    if !context_curve_revision_is_safe(&curve.parser_revision)
        || !context_curve_revision_is_safe(&curve.ownership_revision)
        || curve.sampling_revision != CONTEXT_CURVE_SAMPLING_REVISION
    {
        return Err(fail("has invalid revision evidence"));
    }
    if curve.points.len() > MAX_CONTEXT_CURVE_POINTS
        || curve.boundaries.len() > MAX_CONTEXT_CURVE_BOUNDARIES
        || curve.model_windows.len() > MAX_CONTEXT_CURVE_MODEL_WINDOWS
    {
        return Err(fail("exceeds element caps"));
    }
    let encoded_size = serde_json::to_vec(curve)
        .map_err(|error| fail(&format!("cannot serialize: {error}")))?
        .len();
    if encoded_size > MAX_CONTEXT_CURVE_WIRE_BYTES {
        return Err(fail("exceeds 64 KiB wire cap"));
    }
    let available = matches!(curve.coverage.as_str(), "complete" | "sampled");
    if !available {
        if !matches!(
            curve.coverage.as_str(),
            "ownership_unresolved"
                | "scalars_file_birth_only"
                | "parser_unsupported"
                | "pre_capture"
                | "payload_budget_exceeded"
        ) {
            return Err(fail("has invalid coverage"));
        }
        if curve.total_owned_request_count != 0
            || curve.retained_point_count != 0
            || curve.total_compaction_boundary_count != 0
            || curve.retained_boundary_count != 0
            || !curve.points.is_empty()
            || !curve.boundaries.is_empty()
            || !curve.model_windows.is_empty()
        {
            return Err(fail("unavailable coverage must carry zero evidence"));
        }
        return Ok(());
    }
    if curve.total_owned_request_count == 0
        || curve.retained_point_count != curve.points.len() as u64
        || curve.retained_boundary_count != curve.boundaries.len() as u64
        || curve.retained_point_count > curve.total_owned_request_count
        || curve.retained_boundary_count > curve.total_compaction_boundary_count
    {
        return Err(fail("has inconsistent counts"));
    }
    if curve.coverage == "complete"
        && (curve.retained_point_count != curve.total_owned_request_count
            || curve.retained_boundary_count != curve.total_compaction_boundary_count)
    {
        return Err(fail("complete coverage must retain all evidence"));
    }
    if curve.coverage == "sampled"
        && curve.retained_point_count == curve.total_owned_request_count
        && curve.retained_boundary_count == curve.total_compaction_boundary_count
    {
        return Err(fail("sampled coverage must omit evidence"));
    }
    for (position, window) in curve.model_windows.iter().enumerate() {
        if window.model_window_index != position as u16
            || safe_context_curve_model(Some(&window.model)) != window.model
            || window.context_window_tokens == Some(0)
            || !matches!(
                window.evidence_kind.as_str(),
                "provider_reported_window" | "provider_reported_model" | "unavailable"
            )
            || (window.evidence_kind == "provider_reported_window"
                && window.context_window_tokens.is_none())
            || (window.evidence_kind == "provider_reported_model"
                && (window.context_window_tokens.is_some() || window.model == "unknown"))
            || (window.evidence_kind == "unavailable"
                && (window.context_window_tokens.is_some() || window.model != "unknown"))
            || !context_curve_revision_is_safe(&window.evidence_revision)
        {
            return Err(fail("has invalid model-window evidence"));
        }
    }
    let boundary_by_index = curve
        .boundaries
        .iter()
        .map(|boundary| (boundary.boundary_index, boundary))
        .collect::<BTreeMap<_, _>>();
    if boundary_by_index.len() != curve.boundaries.len()
        || curve
            .boundaries
            .windows(2)
            .any(|pair| pair[0].boundary_index >= pair[1].boundary_index)
    {
        return Err(fail("boundary indexes must be unique and increasing"));
    }
    for boundary in &curve.boundaries {
        if boundary.boundary_index == 0
            || boundary.boundary_index > curve.total_compaction_boundary_count
            || boundary.after_owned_request_ordinal
                != boundary.before_owned_request_ordinal.saturating_add(1)
            || boundary.segment_after_ordinal != boundary.segment_before_ordinal.saturating_add(1)
            || OffsetDateTime::parse(&boundary.observed_at, &Rfc3339).is_err()
        {
            return Err(fail("has invalid boundary evidence"));
        }
    }
    if curve.points.windows(2).any(|pair| {
        pair[0].owned_request_ordinal >= pair[1].owned_request_ordinal
            || timestamp_is_after(&pair[0].observed_at, &pair[1].observed_at)
            || pair[0].segment_ordinal > pair[1].segment_ordinal
    }) {
        return Err(fail(
            "point ordinals, timestamps, and segments must be nondecreasing",
        ));
    }
    if curve.boundaries.windows(2).any(|pair| {
        timestamp_is_after(&pair[0].observed_at, &pair[1].observed_at)
            || pair[0].segment_before_ordinal > pair[1].segment_before_ordinal
    }) {
        return Err(fail(
            "boundary timestamps and segments must be nondecreasing",
        ));
    }
    for point in &curve.points {
        if point.owned_request_ordinal == 0
            || point.owned_request_ordinal > curve.total_owned_request_count
            || point.model_window_index as usize >= curve.model_windows.len()
            || point.effective_input_tokens == 0
            || point.retention_flags == 0
            || point.retention_flags > 0x3f
            || OffsetDateTime::parse(&point.observed_at, &Rfc3339).is_err()
        {
            return Err(fail("has invalid point evidence"));
        }
        if let Some(boundary_index) = point.compaction_after_request_boundary_index {
            let boundary = boundary_by_index
                .get(&boundary_index)
                .ok_or_else(|| fail("point references missing after-request boundary"))?;
            if boundary.before_owned_request_ordinal != point.owned_request_ordinal
                || boundary.segment_before_ordinal != point.segment_ordinal
                || point.retention_flags & CONTEXT_CURVE_RETENTION_COMPACTION_BEFORE == 0
            {
                return Err(fail("after-request boundary reference is inconsistent"));
            }
        }
        if let Some(boundary_index) = point.compaction_before_request_boundary_index {
            let boundary = boundary_by_index
                .get(&boundary_index)
                .ok_or_else(|| fail("point references missing before-request boundary"))?;
            if boundary.after_owned_request_ordinal != point.owned_request_ordinal
                || boundary.segment_after_ordinal != point.segment_ordinal
                || point.retention_flags & CONTEXT_CURVE_RETENTION_COMPACTION_AFTER == 0
            {
                return Err(fail("before-request boundary reference is inconsistent"));
            }
        }
        if (point.retention_flags & CONTEXT_CURVE_RETENTION_COMPACTION_BEFORE != 0)
            != point.compaction_after_request_boundary_index.is_some()
            || (point.retention_flags & CONTEXT_CURVE_RETENTION_COMPACTION_AFTER != 0)
                != point.compaction_before_request_boundary_index.is_some()
        {
            return Err(fail("compaction retention flags do not match references"));
        }
    }
    for anchor in [1_u64, 2, 5, 10, 20]
        .into_iter()
        .filter(|ordinal| *ordinal <= curve.total_owned_request_count)
    {
        if !curve.points.iter().any(|point| {
            point.owned_request_ordinal == anchor
                && point.retention_flags & CONTEXT_CURVE_RETENTION_ANCHOR != 0
        }) {
            return Err(fail("does not retain a required anchor"));
        }
    }
    if !curve.points.iter().any(|point| {
        point.owned_request_ordinal == curve.total_owned_request_count
            && point.retention_flags & CONTEXT_CURVE_RETENTION_TAIL != 0
    }) {
        return Err(fail("does not retain the final tail point"));
    }
    let retained_max = curve
        .points
        .iter()
        .map(|point| point.effective_input_tokens)
        .max()
        .unwrap_or_default();
    if !curve.points.iter().any(|point| {
        point.effective_input_tokens == retained_max
            && point.retention_flags & CONTEXT_CURVE_RETENTION_PEAK != 0
    }) {
        return Err(fail("does not retain a flagged peak"));
    }
    for boundary in &curve.boundaries {
        let before = curve
            .points
            .iter()
            .find(|point| point.owned_request_ordinal == boundary.before_owned_request_ordinal)
            .ok_or_else(|| fail("does not retain the request before a boundary"))?;
        let after = curve
            .points
            .iter()
            .find(|point| point.owned_request_ordinal == boundary.after_owned_request_ordinal)
            .ok_or_else(|| fail("does not retain the request after a boundary"))?;
        if before.compaction_after_request_boundary_index != Some(boundary.boundary_index)
            || after.compaction_before_request_boundary_index != Some(boundary.boundary_index)
            || timestamp_is_after(&before.observed_at, &boundary.observed_at)
            || timestamp_is_after(&boundary.observed_at, &after.observed_at)
        {
            return Err(fail("boundary adjacency references are incomplete"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

// Closed owned-field inventory for optional scan overlap admission.
crate::heap_layout_bound::fields!(ContextCurveCandidateBoundary; observed_at, point_count_before);
crate::durable_tail_codec::durable_struct!(ContextCurveCandidateBoundary {
    N observed_at: Option<String>,
    N point_count_before: u64,
});
crate::heap_layout_bound::fields!(ContextCurveCandidatePoint; observed_at, effective_input_tokens, model, context_window_tokens);
crate::durable_tail_codec::durable_struct!(ContextCurveCandidatePoint {
    N observed_at: Option<String>,
    N effective_input_tokens: u64,
    U model: Option<String>,
    N context_window_tokens: Option<u64>,
});
crate::heap_layout_bound::fields!(SnapshotContextCurve; contract_version, parser_revision, ownership_revision, sampling_revision, coverage, total_owned_request_count, retained_point_count, total_compaction_boundary_count, retained_boundary_count, points, boundaries, model_windows);
crate::heap_layout_bound::fields!(SnapshotContextCurveBoundary; boundary_index, observed_at, before_owned_request_ordinal, after_owned_request_ordinal, segment_before_ordinal, segment_after_ordinal);
crate::heap_layout_bound::fields!(SnapshotContextCurveModelWindow; model_window_index, model, context_window_tokens, evidence_kind, evidence_revision);
crate::heap_layout_bound::fields!(SnapshotContextCurvePoint; owned_request_ordinal, observed_at, effective_input_tokens, model_window_index, segment_ordinal, retention_flags, compaction_before_request_boundary_index, compaction_after_request_boundary_index);
