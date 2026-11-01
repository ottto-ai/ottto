//! Wire shape for serialized context curves.
//!
//! The daemon no longer builds uploaded curves (retired with the
//! `session_context_curve:v1` negotiation): parsers emit none and restored
//! bodies are nulled, so only the wire structs stay. `v1` pins the retired
//! contract for the committed curve fixtures.

use serde::Serialize;

#[cfg(test)]
pub(super) mod v1 {
    pub(crate) const MAX_CONTEXT_CURVE_POINTS: usize = 256;
    pub(crate) const MAX_CONTEXT_CURVE_BOUNDARIES: usize = 64;
    pub(crate) const MAX_CONTEXT_CURVE_MODEL_WINDOWS: usize = 16;
    pub(crate) const MAX_CONTEXT_CURVE_WIRE_BYTES: usize = 64 * 1024;
    pub(crate) const CONTEXT_CURVE_CONTRACT_VERSION: &str = "session_context_curve:v1";
    pub(crate) const CONTEXT_CURVE_SAMPLING_REVISION: &str = "deterministic_even_gap:v1";
    pub(crate) const CONTEXT_CURVE_RETENTION_ANCHOR: u16 = 0x01;
    pub(crate) const CONTEXT_CURVE_RETENTION_COMPACTION_BEFORE: u16 = 0x02;
    pub(crate) const CONTEXT_CURVE_RETENTION_COMPACTION_AFTER: u16 = 0x04;
    pub(crate) const CONTEXT_CURVE_RETENTION_PEAK: u16 = 0x08;
    pub(crate) const CONTEXT_CURVE_RETENTION_TAIL: u16 = 0x10;
    pub(crate) const CONTEXT_CURVE_RETENTION_FILL: u16 = 0x20;
}

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
