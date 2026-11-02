//! Re-finalization from stored state: which selections continue from the
//! committed Tail, and what happens when the body they finish is not the
//! ACKed one.
//!
//! D138 holds upload-context and body-witness selections on native Full. To
//! enable them, add two arms to `reuse_label` and un-ignore their rows; to
//! drop them, nothing here changes.
//!
//! D142: a stored reuse never claims a rescan. Its identical body takes the
//! exact ACK path with 0 native bytes. A differing body is withheld and the
//! file owes one native Full, the same read and upload as a selection that
//! never tried: nothing is counted as read, and nothing is sent twice.
use super::*;

/// The differ-count label of a selection whose file continues from stored
/// state although its transcript did not change.
pub(super) fn reuse_label(reason: CandidateParseReason) -> Option<&'static str> {
    match reason {
        CandidateParseReason::SourceChanged => Some("source_changed"),
        CandidateParseReason::Rearmed => Some("rearmed"),
        CandidateParseReason::ForcedFamily => Some("forced_family"),
        CandidateParseReason::AuthorityQuarantine => Some("authority_quarantine"),
        CandidateParseReason::ActivityOrQuarantineRetry => Some("activity_or_quarantine_retry"),
        _ => None,
    }
}

/// Whether this selection loads the committed Tail. A due `Audit` certifies
/// against the committed head, as main's against its RAM copy: an unchanged
/// file retires quietly, and only what the file proves changed reads Full.
/// An `UnknownOutcome` re-read of a file with a head continues as well: main
/// continued it from RAM. `NewFile`, the D138 held reasons and every legacy
/// reason stay native.
pub(super) fn reuses_stored(reason: Option<CandidateParseReason>) -> bool {
    match reason {
        None
        | Some(
            CandidateParseReason::TranscriptChanged
            | CandidateParseReason::Audit
            | CandidateParseReason::UnknownOutcome,
        ) => true,
        Some(reason) => reuse_label(reason).is_some(),
    }
}

/// The re-finalized body is not the ACKed one (D142): the entry keeps its
/// upload tuple, stays selected, and its next read in this process is native.
/// A restart loses only the one-use memo, costing one more 0-byte try.
pub(super) fn withhold_for_native(
    index: &mut ScanIndex,
    pending: &PendingIndexFinalization,
    reason: CandidateParseReason,
    hold_expired: bool,
) {
    // The withheld body carried a copy hold's expiry; the owed native read
    // decides it again, or the hold restarts and the body never goes.
    if hold_expired {
        index
            .claude_copy_removals
            .owe_last_hold(claude_money_birth_store::location_key(&pending.index_key));
    }
    if let Some(entry) = index.files.get_mut(&pending.index_key) {
        entry.last_snapshot_fingerprint = pending.previous_snapshot_fingerprint.clone();
        entry.last_upload_body_witness = pending.previous_upload_body_witness.clone();
        evidence_owed::keep_or_clear(entry, false);
    }
    if let Ok(Some(route)) = state_v2::runtime_path(index) {
        let _ =
            state_v2::owe_native_read(&route, &pending.index_key, tail_source::counters::pass());
    }
    if let Some(label) = reuse_label(reason) {
        tail_source::counters::bump("tail_reuse_differs", label);
    }
}

/// Whether this read is the native one a differing body owes. §12 counts its
/// delay: the passes the body waited for this read.
pub(super) fn take_native(route: &Path, key: &str) -> bool {
    let Some(owed) = state_v2::take_native_read(route, key) else {
        return false;
    };
    let waited = tail_source::counters::pass().saturating_sub(owed);
    tail_source::counters::bump("tail_reuse_wait", "reads");
    tail_source::counters::add("tail_reuse_wait", "passes", waited);
    tail_source::counters::max("tail_reuse_wait", "max_passes", waited);
    true
}
