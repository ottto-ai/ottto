//! Pure, deterministic construction and validation for serialized context curves.
//!
//! Provider parsing, ownership decisions, checkpoints, and upload eligibility
//! remain in the parent snapshot collector.

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
pub struct SnapshotContextCurveBoundary {
    pub boundary_index: u64,
    pub observed_at: String,
    pub before_owned_request_ordinal: u64,
    pub after_owned_request_ordinal: u64,
    pub segment_before_ordinal: u64,
    pub segment_after_ordinal: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotContextCurveModelWindow {
    pub model_window_index: u16,
    pub model: String,
    pub context_window_tokens: Option<u64>,
    pub evidence_kind: String,
    pub evidence_revision: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

fn canonical_context_curve_timestamp(value: &str) -> Option<String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn mark_context_curve_retention(
    retention_flags: &mut BTreeMap<u64, u16>,
    total_points: u64,
    ordinal: u64,
    flag: u16,
) {
    if ordinal > 0 && ordinal <= total_points {
        *retention_flags.entry(ordinal).or_default() |= flag;
    }
}

pub(super) fn build_context_curve(
    parser_revision: &str,
    ownership_revision: &str,
    model_evidence_revision: &str,
    candidates: &[ContextCurveCandidatePoint],
    boundary_candidates: &[ContextCurveCandidateBoundary],
    unavailable_coverage: &str,
) -> SnapshotContextCurve {
    let total_points = candidates.len() as u64;
    let total_boundaries = boundary_candidates.len() as u64;
    let unavailable = || {
        unavailable_context_curve(
            parser_revision,
            ownership_revision,
            unavailable_coverage,
            total_points,
            total_boundaries,
        )
    };
    if candidates.is_empty()
        || candidates.iter().any(|point| {
            point.effective_input_tokens == 0
                || point.observed_at.as_deref().map_or(true, |timestamp| {
                    OffsetDateTime::parse(timestamp, &Rfc3339).is_err()
                })
        })
        || boundary_candidates.iter().any(|boundary| {
            boundary.point_count_before == 0
                || boundary.point_count_before >= total_points
                || boundary.observed_at.as_deref().map_or(true, |timestamp| {
                    OffsetDateTime::parse(timestamp, &Rfc3339).is_err()
                })
                || boundary.observed_at.as_deref().is_some_and(|timestamp| {
                    let before = candidates[boundary.point_count_before as usize - 1]
                        .observed_at
                        .as_deref()
                        .expect("candidate timestamps validated together");
                    let after = candidates[boundary.point_count_before as usize]
                        .observed_at
                        .as_deref()
                        .expect("candidate timestamps validated together");
                    timestamp_is_after(before, timestamp) || timestamp_is_after(timestamp, after)
                })
        })
        || boundary_candidates.windows(2).any(|pair| {
            pair[0].point_count_before >= pair[1].point_count_before
                || pair[0]
                    .observed_at
                    .as_deref()
                    .zip(pair[1].observed_at.as_deref())
                    .is_some_and(|(left, right)| timestamp_is_after(left, right))
        })
        || candidates.windows(2).any(|pair| {
            pair[0]
                .observed_at
                .as_deref()
                .zip(pair[1].observed_at.as_deref())
                .is_some_and(|(left, right)| timestamp_is_after(left, right))
        })
    {
        return unavailable();
    }

    let retained_boundary_candidates = if boundary_candidates.len() > MAX_CONTEXT_CURVE_BOUNDARIES {
        let edge_count = MAX_CONTEXT_CURVE_BOUNDARIES / 2;
        boundary_candidates
            .iter()
            .enumerate()
            .take(edge_count)
            .chain(
                boundary_candidates
                    .iter()
                    .enumerate()
                    .skip(boundary_candidates.len() - edge_count),
            )
            .collect::<Vec<_>>()
    } else {
        boundary_candidates.iter().enumerate().collect::<Vec<_>>()
    };

    let mut retention_flags = BTreeMap::<u64, u16>::new();
    for ordinal in [1_u64, 2, 5, 10, 20] {
        mark_context_curve_retention(
            &mut retention_flags,
            total_points,
            ordinal,
            CONTEXT_CURVE_RETENTION_ANCHOR,
        );
    }
    for (_, boundary) in &retained_boundary_candidates {
        mark_context_curve_retention(
            &mut retention_flags,
            total_points,
            boundary.point_count_before,
            CONTEXT_CURVE_RETENTION_COMPACTION_BEFORE,
        );
        mark_context_curve_retention(
            &mut retention_flags,
            total_points,
            boundary.point_count_before + 1,
            CONTEXT_CURVE_RETENTION_COMPACTION_AFTER,
        );
    }
    let peak_ordinal = candidates
        .iter()
        .enumerate()
        .max_by_key(|(_, point)| point.effective_input_tokens)
        .map(|(index, _)| index as u64 + 1)
        .unwrap_or(1);
    mark_context_curve_retention(
        &mut retention_flags,
        total_points,
        peak_ordinal,
        CONTEXT_CURVE_RETENTION_PEAK,
    );
    for ordinal in total_points.saturating_sub(9)..=total_points {
        mark_context_curve_retention(
            &mut retention_flags,
            total_points,
            ordinal.max(1),
            CONTEXT_CURVE_RETENTION_TAIL,
        );
    }

    if retention_flags.len() > MAX_CONTEXT_CURVE_POINTS {
        return unavailable();
    }
    let target = candidates.len().min(MAX_CONTEXT_CURVE_POINTS);
    while retention_flags.len() < target {
        let selected = retention_flags.keys().copied().collect::<Vec<_>>();
        let mut best: Option<(u64, u64)> = None;
        let mut left = 0_u64;
        for right in selected
            .iter()
            .copied()
            .chain(std::iter::once(total_points + 1))
        {
            if right > left + 1 {
                let gap = right - left - 1;
                let midpoint = left + (right - left) / 2;
                match best {
                    Some((best_gap, best_midpoint))
                        if gap < best_gap || (gap == best_gap && midpoint >= best_midpoint) => {}
                    _ => best = Some((gap, midpoint)),
                }
            }
            left = right;
        }
        let Some((_, ordinal)) = best else { break };
        mark_context_curve_retention(
            &mut retention_flags,
            total_points,
            ordinal,
            CONTEXT_CURVE_RETENTION_FILL,
        );
    }

    let mut before_boundary_by_request = BTreeMap::new();
    let mut after_boundary_by_request = BTreeMap::new();
    let boundaries = retained_boundary_candidates
        .iter()
        .map(|(original_index, boundary)| {
            let boundary_index = *original_index as u64 + 1;
            before_boundary_by_request.insert(boundary.point_count_before + 1, boundary_index);
            after_boundary_by_request.insert(boundary.point_count_before, boundary_index);
            SnapshotContextCurveBoundary {
                boundary_index,
                observed_at: boundary
                    .observed_at
                    .as_deref()
                    .and_then(canonical_context_curve_timestamp)
                    .expect("validated boundary timestamp canonicalizes"),
                before_owned_request_ordinal: boundary.point_count_before,
                after_owned_request_ordinal: boundary.point_count_before + 1,
                segment_before_ordinal: *original_index as u64,
                segment_after_ordinal: *original_index as u64 + 1,
            }
        })
        .collect::<Vec<_>>();

    let mut model_window_indexes = BTreeMap::new();
    let mut model_windows = Vec::new();
    let mut model_window_overflow = false;
    let mut points = Vec::with_capacity(retention_flags.len());
    for (ordinal, flags) in retention_flags {
        let candidate = &candidates[ordinal as usize - 1];
        let model = safe_context_curve_model(candidate.model.as_deref());
        let evidence_kind = if candidate.context_window_tokens.is_some() {
            "provider_reported_window"
        } else if model != "unknown" {
            "provider_reported_model"
        } else {
            "unavailable"
        };
        let model_key = (
            model.clone(),
            candidate.context_window_tokens,
            evidence_kind.to_string(),
        );
        let model_window_index = if let Some(index) = model_window_indexes.get(&model_key) {
            *index
        } else if model_windows.len() < MAX_CONTEXT_CURVE_MODEL_WINDOWS {
            let index = model_windows.len() as u16;
            model_window_indexes.insert(model_key, index);
            model_windows.push(SnapshotContextCurveModelWindow {
                model_window_index: index,
                model,
                context_window_tokens: candidate.context_window_tokens,
                evidence_kind: evidence_kind.to_string(),
                evidence_revision: model_evidence_revision.to_string(),
            });
            index
        } else {
            model_window_overflow = true;
            0
        };
        let segment_ordinal = boundary_candidates
            .iter()
            .take_while(|boundary| boundary.point_count_before < ordinal)
            .count() as u64;
        points.push(SnapshotContextCurvePoint {
            owned_request_ordinal: ordinal,
            observed_at: candidate
                .observed_at
                .as_deref()
                .and_then(canonical_context_curve_timestamp)
                .expect("validated point timestamp canonicalizes"),
            effective_input_tokens: candidate.effective_input_tokens,
            model_window_index,
            segment_ordinal,
            retention_flags: flags,
            compaction_before_request_boundary_index: before_boundary_by_request
                .get(&ordinal)
                .copied(),
            compaction_after_request_boundary_index: after_boundary_by_request
                .get(&ordinal)
                .copied(),
        });
    }

    if model_window_overflow {
        return unavailable();
    }
    let mut curve = SnapshotContextCurve {
        contract_version: CONTEXT_CURVE_CONTRACT_VERSION.to_string(),
        parser_revision: parser_revision.to_string(),
        ownership_revision: ownership_revision.to_string(),
        sampling_revision: CONTEXT_CURVE_SAMPLING_REVISION.to_string(),
        coverage: if candidates.len() > MAX_CONTEXT_CURVE_POINTS
            || boundary_candidates.len() > MAX_CONTEXT_CURVE_BOUNDARIES
        {
            "sampled".to_string()
        } else {
            "complete".to_string()
        },
        total_owned_request_count: total_points,
        retained_point_count: points.len() as u64,
        total_compaction_boundary_count: total_boundaries,
        retained_boundary_count: boundaries.len() as u64,
        points,
        boundaries,
        model_windows,
    };
    loop {
        let encoded_size = serde_json::to_vec(&curve)
            .map(|encoded| encoded.len())
            .unwrap_or(usize::MAX);
        if encoded_size <= MAX_CONTEXT_CURVE_WIRE_BYTES {
            return curve;
        }
        if !prune_one_context_curve_fill_point(&mut curve) {
            return unavailable();
        }
    }
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
