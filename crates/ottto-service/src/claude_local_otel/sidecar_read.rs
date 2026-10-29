//! Sidecar acquisition boundary shared by ordinary and paid loaders.
//! Phase 1 delegates to the existing whole-file readers. Durable state is
//! test-only until its record, receipt and EOF contracts are decided.
use super::*;
use crate::source_rotation::PaidReservation;

pub(super) fn api(
    support_dir: &Path,
    session_id: &str,
) -> Result<(Vec<ClaudeLocalOtelEvidence>, ApiReadWitness)> {
    // DECISION(19b-§8-E1): replace this delegation with admitted restore/Tail
    // only after the shared store supports a receipted sidecar record kind.
    decode_api_sidecar_whole_file(support_dir, session_id)
}

pub(super) fn trace(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> ClaudeTraceOwnershipLoadReport {
    // DECISION(19b-§8-LeadB): retain the current cohort failure semantics;
    // cumulative per-file reports must pass the family barrier before folding.
    load_trace_whole_file(support_dir, session_ids)
}

pub(super) fn paid_api(
    path: &Path,
    session_id: &str,
    paid: &mut PaidReservation,
    occupied: usize,
) -> Option<(Vec<ClaudeLocalOtelEvidence>, ApiReadWitness)> {
    // DECISION(19b-§8-LeadA): charge continuation, EOF and codec overlap within
    // existing admission; a clone of the decoder is not prepaid today.
    bounded_read::api(path, session_id, paid, occupied)
}

pub(super) fn paid_trace(
    path: &Path,
    session_id: &str,
    paid: &mut PaidReservation,
    occupied: usize,
) -> Option<(ClaudeTraceOwnershipLoadReport, ClaudeTraceReadGeneration)> {
    bounded_read::trace(path, session_id, paid, occupied)
}

#[cfg(all(test, unix))]
pub(super) mod durable;
