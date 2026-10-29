//! Sidecar acquisition boundary shared by ordinary and paid loaders.
//! The live path delegates to existing whole-file readers until the durable
//! contract harness is executed and SOURCE/Lead B approve activation.
use super::*;
use crate::source_rotation::PaidReservation;
mod counts;

pub(super) fn take_counts() -> BTreeMap<&'static str, u64> {
    counts::take()
}

pub(super) fn api(
    support_dir: &Path,
    session_id: &str,
) -> Result<(Vec<ClaudeLocalOtelEvidence>, ApiReadWitness)> {
    #[cfg(all(test, unix))]
    if let Some(result) = durable::active_load(support_dir, session_id) {
        let (mut api, _) = result?;
        let generation = if api.health.is_complete() {
            fs::metadata(evidence_path(support_dir, session_id))
                .ok()
                .and_then(|m| api_file_generation(&m))
        } else {
            None
        };
        let rows = api.evidence.remove(session_id).unwrap_or_default();
        return Ok((
            rows,
            ApiReadWitness {
                health: api.health,
                generation,
            },
        ));
    }
    // E1 approved v1 post-save, at-least-once durability. Promote the same
    // harness path here after proof; do not relabel it a write-ahead receipt.
    decode_api_sidecar_whole_file(support_dir, session_id)
}

pub(super) fn trace(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> ClaudeTraceOwnershipLoadReport {
    #[cfg(all(test, unix))]
    if durable::active_for(support_dir) {
        let mut report = ClaudeTraceOwnershipLoadReport::default();
        for session in BTreeSet::from_iter(session_ids) {
            match durable::active_load(support_dir, &session).expect("active reader") {
                Ok((_, mut trace)) => {
                    report.evidence.append(&mut trace.evidence);
                    report.missing_files += trace.missing_files;
                    report.malformed_lines += trace.malformed_lines;
                    report.unreadable_lines += trace.unreadable_lines;
                    report.oversized_files += trace.oversized_files;
                    report.invalid_session_rows += trace.invalid_session_rows;
                    report.missing_request_ids += trace.missing_request_ids;
                    report
                        .conflicting_request_ids
                        .append(&mut trace.conflicting_request_ids);
                }
                Err(_) => report.unreadable_lines += 1,
            }
        }
        return report;
    }
    // DECISION(19b-§8-LeadB): retain the current cohort failure semantics;
    // approve cumulative re-fold and incomplete/estimate behavior for v1.
    load_trace_whole_file(support_dir, session_ids)
}

pub(super) fn paid_api(
    path: &Path,
    session_id: &str,
    paid: &mut PaidReservation,
    occupied: usize,
) -> Option<(Vec<ClaudeLocalOtelEvidence>, ApiReadWitness)> {
    #[cfg(all(test, unix))]
    if let Some(support) = durable::active_path(path, session_id, durable::Kind::Api) {
        durable::pay_active(session_id, paid, occupied)?;
        return api(&support, session_id).ok();
    }
    // The unchanged live paid path retains its existing exact admission.
    bounded_read::api(path, session_id, paid, occupied)
}

pub(super) fn paid_trace(
    path: &Path,
    session_id: &str,
    paid: &mut PaidReservation,
    occupied: usize,
) -> Option<(ClaudeTraceOwnershipLoadReport, ClaudeTraceReadGeneration)> {
    #[cfg(all(test, unix))]
    if let Some(support) = durable::active_path(path, session_id, durable::Kind::Trace) {
        durable::pay_active(session_id, paid, occupied)?;
        let report = trace(&support, [session_id.into()]);
        let generation = claude_trace_read_generation(&support, session_id)?;
        return Some((report, generation));
    }
    bounded_read::trace(path, session_id, paid, occupied)
}

#[cfg(all(test, unix))]
pub(super) mod durable;
