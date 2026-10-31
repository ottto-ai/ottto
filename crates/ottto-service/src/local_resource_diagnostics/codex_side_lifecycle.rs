//! Cumulative process-global Codex parent side-record transitions (U1a-2a),
//! separate from `CodexCursorCounts`, `codex_memo_lifecycle` and the counting
//! census. Counters, gauges and two point lines only: no identifiers, paths,
//! namespaces or retained history.
//!
//! Semantics: every `Counts` field is a lifetime event counter (monotone since
//! process start, saturating, summed over every namespace and overlapping
//! scan). Per-fence totals (`side_refusals`, `side_not_due`) repeat on every
//! fence while their condition holds: they count fences, never parent files,
//! unique objects, additive usage or proof of acceptance. `Gauges` hold the
//! last measured state, overwritten on each measurement and never summed.
//! `side_reads_started - side_reads_ended` is not a crash count: totals reset
//! with the process, so only a `side_read_start` line without a matching
//! `side_read_end` before a new `process_id` supports that reading. Neither is
//! money, a dedup or coverage figure, nor wire data. Independent relaxed loads
//! are not a transactional snapshot.
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

lifetime_counters! {
    // A side read began (G7), after its attempt was charged.
    side_reads_started: ReadStarted,
    // A side read ended, at its exit or abandoned in-process (guard drop).
    side_reads_ended: ReadEnded,
    // A side record was written, by the side exit or by main's certified parse.
    side_records_written: RecordWritten,
    // A request ended in a terminal state (`Unsealed`, `Short`, `Lossy`, `Evicted`).
    side_requests_tombstoned: RequestTombstoned,
    // A request was re-armed or restarted (once per state change).
    side_requests_rearmed: RequestRearmed,
    // A fence refused a side record (per fence).
    side_refusals: Refusal,
    // A fence found its request not due, waiting or ledger-full (per fence).
    side_not_due: NotDue,
    // Ledger housekeeping: a lossless eviction or a replaced gate slot.
    side_ledger_evictions: LedgerEviction,
    // A proof item was dropped or a proof page was skipped: a page whose due
    // proof work never reached the hook, a page with no leftover for one step, a memory-refused step, a refused suspend, a
    // suspended proof retired by main (admission, insert, copy step) or by
    // another index's take, a held lease dropped unfinished (not counting
    // `side_proof_release_drops`).
    side_proof_drops: ProofDrop,
    // M1's release to fit retired a suspended proof before evicting any
    // retained copy (D6(e)); never a retained release cause.
    side_proof_release_drops: ProofReleaseDrop,
}

/// Last measured side state (`set_gauges` only), never a lifetime sum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Gauges {
    pub(crate) side_records: u64,
    pub(crate) side_record_bytes: u64,
    pub(crate) side_requests: u64,
    pub(crate) side_request_bytes: u64,
    pub(crate) side_ledger_entries: u64,
}
static GAUGES: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Record {
    #[serde(flatten)]
    pub(crate) counts: Counts,
    #[serde(flatten)]
    pub(crate) gauges: Gauges,
}
impl Record {
    #[cfg(test)]
    pub(super) fn maximum() -> Self {
        Self {
            counts: Counts::maximum(),
            gauges: Gauges {
                side_records: u64::MAX,
                side_record_bytes: u64::MAX,
                side_requests: u64::MAX,
                side_request_bytes: u64::MAX,
                side_ledger_entries: u64::MAX,
            },
        }
    }
}

pub(crate) fn set_gauges(gauges: Gauges) {
    let Gauges {
        side_records,
        side_record_bytes,
        side_requests,
        side_request_bytes,
        side_ledger_entries,
    } = gauges;
    for (slot, value) in GAUGES.iter().zip([
        side_records,
        side_record_bytes,
        side_requests,
        side_request_bytes,
        side_ledger_entries,
    ]) {
        slot.store(value, Ordering::Relaxed);
    }
}
pub(crate) fn snapshot() -> Record {
    let gauge = |i: usize| GAUGES[i].load(Ordering::Relaxed);
    Record {
        counts: Counts::totals(),
        gauges: Gauges {
            side_records: gauge(0),
            side_record_bytes: gauge(1),
            side_requests: gauge(2),
            side_request_bytes: gauge(3),
            side_ledger_entries: gauge(4),
        },
    }
}

/// Per-process side read sequence for the start/end line pair.
static READ_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One side read's line pair: exactly one `side_read_start` when created and
/// at most one `side_read_end`, either at an exit (`end`) or, if still armed
/// when dropped, as `abandoned`. Each line also counts its lifetime total.
#[must_use]
pub(crate) struct SideReadGuard {
    pseq: u64,
    armed: bool,
}
impl SideReadGuard {
    pub(crate) fn start(attempts: u8) -> Self {
        let pseq = READ_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        record(Event::ReadStarted);
        super::side_read_point(super::SideReadPoint::Start { pseq, attempts });
        Self { pseq, armed: true }
    }
    pub(crate) fn end(mut self) {
        self.finish(false);
    }
    fn finish(&mut self, abandoned: bool) {
        if std::mem::take(&mut self.armed) {
            record(Event::ReadEnded);
            super::side_read_point(super::SideReadPoint::End {
                pseq: self.pseq,
                abandoned,
            });
        }
    }
}
impl Drop for SideReadGuard {
    fn drop(&mut self) {
        self.finish(true);
    }
}
crate::heap_layout_bound::no_heap!(false; SideReadGuard);
