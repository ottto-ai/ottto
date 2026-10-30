//! M1 durable warm-cache reuse: the RAM cache's link to the durable-tail store
//! (CONTRACT.md M1 contracts 1 and 2; SOURCE field ruling with Amendment 1).
//!
//! - Restore runs on a RAM miss for an indexed file that may sample. The
//!   record must bind to the loaded, committed index (generation, entry,
//!   context, scope with format, allowlist, identity contract and counting
//!   view), its certificate must admit on the held FD, its body must decode
//!   and any unfunded content re-derivation holds before input. A record
//!   without content obligations is then charged through
//!   the ordinary cache admission and taken like any retained copy, so the
//!   existing `prepare_acquisition` decides Unchanged, Tail or Full. Any
//!   resource refusal is Pending with no reusable guardless RAM entry; on
//!   a file grown past its committed end, any but a busy lease is a Miss
//!   (ordinary counted Full), so no hold drops growth. Restore advances no
//!   ACK, ledger, census, absence, unchanged-proof, binding or payer state.
//! - Write runs after a successful index save: only entries admitted this
//!   pass, still resident, kept by that save and changed since their last
//!   record, in a bounded batch.
//!
//! The stores live beside the RAM cache for the process lifetime and are not
//! part of its state budget: each holds at most `MAX_RECORDS` digest and
//! verification-stamp entries (`STORES_RESIDENT_BOUND`). Per-key custody maps
//! have fixed prepaid capacities; per-pass key maps follow the committed index.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) mod acquired;
mod m1;
pub(crate) use acquired::{AcquiredChain, AcquisitionProtocol, ImmutableCounting};
mod owed;
pub(in crate::snapshots) use owed::OwedCompletionAdmission;
pub(crate) use owed::{OwedAdmission, OwedQuery, ReceiptOwed};
mod write_ahead;
pub(in crate::snapshots) use write_ahead::{
    CommitFences, FinishAcquisition, LiveFinishView, NativeFinishAttempt,
};
pub(crate) use write_ahead::{
    Degraded, DegradedCause, HeldCause, NotPersisted, PrepareOutcome, PreparedRecord, ReceiptProof,
    ReconcileOutcome, RecordIdentity, Unprepared, UnpreparedDisposition, WriteOutcome,
};

use super::super::*;
use super::SharedCache;
use crate::durable_tail_codec::Refuse;
use crate::durable_tail_store::{
    self as store, Binding, DurableSource, DurableTailStore, Expected, PendingRecord, ReadOutcome,
    SingleWriter,
};
use crate::snapshot_sync::effective_upload_body_witness_revision as effective_revision;
use crate::transcript_acquisition::{
    birth_unix_nanos, CertificateRefusal, Checkpoint, DurableCertificate, FullReason, Scope,
};
use crate::transcript_cache::Taken;
use sampled_jsonl::durable as codec;
use sampled_jsonl::CachedJsonlReduction;

/// Encoded bytes one post-save write may produce, so encoding under the
/// retained lock stays bounded. Entries past it are deferred to a later save.
pub(crate) const WRITE_PASS_BYTES: usize = store::WRITE_PASS_BYTES;

#[cfg(test)]
thread_local! { static TEST_WRITE_BYTES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(in crate::snapshots) fn set_test_write_bytes(bytes: Option<usize>) {
    TEST_WRITE_BYTES.with(|budget| budget.set(bytes));
}

/// Upper bound of both stores' resident maps (two sources), ONE canonical value:
/// - memo 2*256*256 = 131,072 bytes;
/// - compact store pending 2*(32+1)*4096 = 270,336 bytes: a wire pending
///   entry stays <=320 bytes per node. Root's expanded stage/receipt metadata
///   (full `RecordIdentity`, boxed in `ReceiptProof`) is NOT pending: it is
///   charged on the acquisition's active lease inside `stream_reserve_bytes`
///   with the funded 64 KiB stream scratch;
/// - A0-h custody (spent, P2 witness, upgrade marker) and Full-pacing nodes,
///   2*513 nodes of <=1024 bytes = 1,050,624 bytes (`RETAIL_RESERVE_BYTES`);
/// - M3 per-key debt/D3-hold and P1-1 restore-pending maps, 2*257 nodes of
///   <=1024 bytes = 526,336 bytes (`KEY_RESERVE_BYTES`).
///
/// Plus the 225,720-byte fixed-digest diagnostic set (512 entries + root).
/// Total 2,204,088 bytes; the previous canonical pin was 1,978,368 bytes.
/// The 526,336-byte M3 key reserve is debited from STATE_BYTES, within the
/// existing cache budget. Native/container evidence remains required; this
/// explicit prepayment is separate from the retained graph's heap walk.
#[cfg(test)]
pub(crate) const STORES_RESIDENT_BOUND: usize = 2 * store::MAX_RECORDS * 256
    + 2 * (store::MAX_BATCH + 1) * 4096
    + super::RETAIL_RESERVE_BYTES
    + KEY_RESERVE_BYTES
    + STALE_PREDECESSOR_RESERVE_BYTES;

/// M3 per-key maps outside the A0-h custody node, each with its own prepaid
/// capacity of `MAX_RECORDS` nodes (plus the retained root) of <=1024 bytes:
/// the receipt-debt/D3-hold map (`owed::KeyDebt`) and the P1-1 restore-pending
/// map. Neither evicts live custody; debt pressure can reclaim idle diagnostics
/// and expired pacing. Live-capacity overflow keeps the existing safe path.
pub(crate) const KEY_RESERVE_BYTES: usize = 2 * (store::MAX_RECORDS + 1) * 1024;
const _: () = assert!(KEY_RESERVE_BYTES == 526_336);

/// P1-1: process Tail grants whose accepted end lies within the restored
/// certificate (no old bytes owed, the write-ahead steady state). They never
/// take the never-evicted A0-h custody node; a write or receipt at the high
/// water frees them. Overflow refuses toward the existing paced Full.
const RESTORE_PENDING_KEYS: usize = store::MAX_RECORDS;

/// P2: restored class-X head re-reads per source and pass. The sampled-read
/// contract pays `2 * SAMPLE_BYTES` per restore; one cache-full of restores is
/// 2 MiB, which still admits one maximal `HEAD_BOUND` re-read every pass.
/// Past it a restore takes the existing counted, paced resource path.
const REDERIVE_PASS_BYTES: u64 =
    2 * crate::transcript_acquisition::SAMPLE_BYTES as u64 * store::MAX_RECORDS as u64;
const _: () = assert!(REDERIVE_PASS_BYTES >= codec::HEAD_BOUND + codec::TITLE_LINE_BOUND);

#[cfg(test)]
thread_local! {
    static BEFORE_CARRIER_PROBE: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(in crate::snapshots) fn set_before_carrier_probe(hook: Option<Box<dyn FnMut()>>) {
    BEFORE_CARRIER_PROBE.with(|slot| *slot.borrow_mut() = hook);
}

/// Pacing cause of a Codex refused stale record's Full (SOURCE cond. 5).
const STALE_SELECTION_CAUSE: usize = 5;

const RECOVERY_PACE_SECONDS: u64 = 6 * 3600;
const _: () = assert!(RECOVERY_PACE_SECONDS < 24 * 3600);

/// Head re-parse bytes of restores, per source, for the process lifetime.
/// Existing class-X re-derivation is bounded at `HEAD_BOUND`, on a RAM
/// miss only, so the census pass line reports it beside the guard's own
/// counters (SOURCE N1).
static REDERIVE_HEAD_BYTES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static REDERIVE_HEAD_READS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static REDERIVE_LINE_PEAK: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static REDERIVE_FENCE: [[AtomicU64; 5]; 3] = [const { [const { AtomicU64::new(0) }; 5] }; 3];
// Diagnostic-only fixed storage: no keys, allocation, admission or new cause.
// Order matches the summary label, not any persisted/source-admission enum.
static REDERIVE_REFUSED: [[AtomicU64; 5]; 3] = [const { [const { AtomicU64::new(0) }; 5] }; 3];
static NATIVE_PHASE_BYTES: [[AtomicU64; 2]; 3] = [const { [const { AtomicU64::new(0) }; 2] }; 3];
fn diagnostic_source_slot(source: SnapshotSource) -> usize {
    match source {
        SnapshotSource::ClaudeCode => 0,
        SnapshotSource::Codex => 1,
        SnapshotSource::Pi => 2,
    }
}

/// Count every blocking class on an actual content-admission refusal; a row
/// with multiple obligations contributes to each, not just its first field.
pub(in crate::snapshots) fn record_rederive_refused(source: SnapshotSource, classes: [bool; 5]) {
    for (slot, blocked) in REDERIVE_REFUSED[diagnostic_source_slot(source)]
        .iter()
        .zip(classes)
    {
        if blocked {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Only an actual restored Tail may report this disposition. The extent is
/// frozen at native preparation, before index mutations or later appends.
pub(in crate::snapshots) fn restored_tail_below_accepted(
    source: SnapshotSource,
    restored: bool,
    mode: crate::transcript_acquisition::ReadMode,
    frozen: Option<u64>,
    accepted: Option<u64>,
) -> bool {
    restart_restore::enabled()
        && matches!(source, SnapshotSource::Codex | SnapshotSource::Pi)
        && restored
        && mode == crate::transcript_acquisition::ReadMode::Tail
        && frozen.zip(accepted).is_some_and(|(end, floor)| end < floor)
}

pub(in crate::snapshots) fn record_restored_publication(
    source: SnapshotSource,
    behind: bool,
    published: bool,
) {
    if behind && published {
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({"restored_behind_accepted":{"published":1}}),
        );
    }
}

/// Native consumed input, not certificate samples or BufReader readahead.
/// Call after each step, including partial/error steps, using its actual plan.
/// Rederive head input has its own pread observer and is never counted twice.
pub(in crate::snapshots) fn record_native_phase_input(
    source: SnapshotSource,
    mode: crate::transcript_acquisition::ReadMode,
    bytes: u64,
) {
    use crate::transcript_acquisition::ReadMode;
    let phase = match mode {
        ReadMode::Tail => 0,
        ReadMode::Full(_) => 1,
        ReadMode::Unchanged => return,
    };
    NATIVE_PHASE_BYTES[diagnostic_source_slot(source)][phase].fetch_add(bytes, Ordering::Relaxed);
}

pub(crate) fn rederive_head_bytes_total(source: SnapshotSource) -> u64 {
    REDERIVE_HEAD_BYTES[diagnostic_source_slot(source)].load(Ordering::Relaxed)
}

#[cfg(test)]
thread_local! { static REDERIVE_READ_CALLS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(in crate::snapshots) fn record_rederive_read_call() {
    REDERIVE_READ_CALLS.with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
        }
    });
}
#[cfg(test)]
pub(in crate::snapshots) fn capture_rederive_reads<T>(run: impl FnOnce() -> T) -> (T, u64) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REDERIVE_READ_CALLS.set(None);
        }
    }
    assert!(REDERIVE_READ_CALLS.replace(Some(0)).is_none());
    let _reset = Reset;
    let result = run();
    (result, REDERIVE_READ_CALLS.get().unwrap())
}
/// Actual physical class-X bytes, including a later capture/hash refusal.
/// The success receipt is separate; never hide input behind a refusal label.
pub(in crate::snapshots) fn record_rederive_input(source: SnapshotSource, bytes: u64) {
    REDERIVE_HEAD_BYTES[diagnostic_source_slot(source)].fetch_add(bytes, Ordering::Relaxed);
    crate::local_resource_diagnostics::durable_tail_alarm(
        source.api_slug(),
        &serde_json::json!({"rederive_input_bytes": bytes}),
    );
}

pub(in crate::snapshots) fn record_rederive_line_peak(source: SnapshotSource, bytes: u64) {
    REDERIVE_LINE_PEAK[diagnostic_source_slot(source)].fetch_max(bytes, Ordering::Relaxed);
    crate::local_resource_diagnostics::durable_tail_alarm(
        source.api_slug(),
        &serde_json::json!({"rederive_line_peak_bytes":bytes}),
    );
}
pub(in crate::snapshots) fn record_rederive_fence(source: SnapshotSource, classes: [bool; 5]) {
    for (count, mismatch) in REDERIVE_FENCE[diagnostic_source_slot(source)]
        .iter()
        .zip(classes)
    {
        count.fetch_add(u64::from(mismatch), Ordering::Relaxed);
    }
    crate::local_resource_diagnostics::durable_tail_alarm(
        source.api_slug(),
        &serde_json::json!({"rederive_fence_mismatch":classes.map(u64::from)}),
    );
}
#[derive(Clone, Copy)]
enum RetirementEdge {
    Metadata,
    AcceptedObject,
    IndependentEdit,
    ScopedCertificate,
}
impl RetirementEdge {
    fn label(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::AcceptedObject => "accepted_object",
            Self::IndependentEdit => "independent_edit",
            Self::ScopedCertificate => "scoped_certificate",
        }
    }
}

const PACE_SECS: u64 = 6 * 3600;
// Sleep and implausible clock changes must fail toward reading.
const PACE_SANITY_SECS: u64 = 7 * 86_400;
const _: () = assert!(PACE_SECS < 86_400);

fn full_pace_delayed(at: SystemTime, now: SystemTime) -> bool {
    // Backwards and implausibly large forwards jumps both EXPIRE.
    now.duration_since(at).is_ok_and(|age| {
        age.as_secs() <= PACE_SANITY_SECS && age < std::time::Duration::from_secs(PACE_SECS)
    })
}

/// Content-free outcome counts, by class. Field paths are static names; no
/// id, path or value is ever counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) restore_attempts: u64,
    /// Per-process totals, emitted together once at the source pass boundary.
    rederive_failed_first_attempt: [u64; 3],
    /// Missing authority at the closed set of retirement decision edges.
    pub(crate) retire_exact_held: BTreeMap<&'static str, u64>,
    /// Process proxy only: no persisted key identity or restart streak.
    retire_exact_held_first_attempt: [u64; 3],
    retire_exact_first_attempt_tracking_closed: bool,
    rederive_first_attempt_tracking_closed: bool,
    restore_pending_quiet: [u64; 3],
    pub(crate) restored: u64,
    pub(crate) original_v1_mapped: u64,
    pub(crate) durable_restore_after_selection_clear: u64,
    pub(crate) objects: [u64; 3],
    pub(crate) s2_skipped_object_changed: u64,
    pub(crate) retail_attempts: u64,
    pub(crate) retail_keys: u64,
    pub(crate) retail_full: [u64; 3],
    pub(crate) stale_full: [u64; 3],
    pub(crate) near_cap: u64,
    pub(crate) pace_anomaly: u64,
    pub(crate) upgrade_missing_full: u64,
    /// Immediate emission owns these per-source eviction totals exclusively.
    pub(crate) pace_evicted: [u64; 3],
    /// Recovery Full/paced totals per source; eviction has its separate owner.
    recovery_full: [[u64; 2]; 3],
    /// [Full, paced] per Claude/Codex/Pi; process-lifetime, not store-owned.
    pub(crate) active_bound: [[u64; 2]; 3],
    pub(crate) missing: u64,
    pub(crate) upgrade_state_missing: u64,
    pub(crate) migration: [u64; 4], // held, awaiting save, claimed, durably replaced
    pub(crate) refused_record: u64,
    pub(crate) durable_held: [u64; 9],
    pub(crate) held_census: [u64; 2],
    pub(crate) ineligible: BTreeMap<&'static str, u64>,
    pub(crate) certificate_refused: BTreeMap<&'static str, u64>,
    pub(crate) corrupt_body: u64,
    pub(crate) not_rederived: BTreeMap<&'static str, u64>,
    pub(crate) budget_refused: u64,
    /// Non-transient resource refusals whose held file grew: ordinary Full.
    pub(crate) resource_full: BTreeMap<&'static str, u64>,
    pub(crate) rederive_head_bytes: u64,
    pub(crate) rederive_named_lines: u64,
    pub(crate) rederive_line_bytes: u64,
    /// P2 pass budget refusals: [restores, head bytes not read].
    pub(crate) rederive_budget: [u64; 2],
    /// Write phase: entries not persisted, by the refusing field or class.
    pub(crate) not_persisted: BTreeMap<&'static str, u64>,
    pub(crate) write_deferred: u64,
    /// Post-save writes skipped because this process does not hold the
    /// state-directory lock (not the daemon).
    pub(crate) write_unlocked: u64,
    pub(crate) peak_body_bytes: u64,
    /// GC's largest keep map: index keys with a record on disk, at most the
    /// store's `INVENTORY_BOUND`, whatever the index size.
    pub(crate) gc_keep_peak: u64,
    /// M3 D3 Claude holds: [growth bytes, released by write, released by
    /// content change, unfunded hold marker].
    pub(crate) d3: [u64; write_ahead::D3_COUNTS],
    /// Records offered to a post-save batch that returned an error. The
    /// store keeps each one's predecessor until a later write replaces it.
    pub(crate) store_write_after_save_failed: u64,
    /// [files, bytes], an UPPER BOUND: Fulls whose restore refused the
    /// record as behind the committed entry (`entry_changed`), and the native
    /// bytes those Fulls read. It reuses that refusal with no persisted
    /// marker of a failed write, so it also counts a record never offered
    /// (deferred or evicted).
    pub(crate) store_write_failed_restart_full: [u64; 2],
}

impl Counters {
    fn bump(map: &mut BTreeMap<&'static str, u64>, class: &'static str) {
        *map.entry(class).or_default() += 1;
    }

    /// One content-free log line: counts by static class name only, never an
    /// id, path or value. Process-lifetime totals.
    pub(crate) fn summary(&self, source: SnapshotSource, store: &store::StoreCounters) -> String {
        let classes = |map: &BTreeMap<&'static str, u64>| {
            map.iter()
                .map(|(class, count)| format!("{class}:{count}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let diagnostic_slot = diagnostic_source_slot(source);
        let rederive_refused = REDERIVE_REFUSED[diagnostic_slot]
            .each_ref()
            .map(|value| value.load(Ordering::Relaxed));
        let native_phase = NATIVE_PHASE_BYTES[diagnostic_slot]
            .each_ref()
            .map(|value| value.load(Ordering::Relaxed));
        let head_reads = REDERIVE_HEAD_READS[diagnostic_slot].load(Ordering::Relaxed);
        let line_peak = REDERIVE_LINE_PEAK[diagnostic_slot].load(Ordering::Relaxed);
        let fence = REDERIVE_FENCE[diagnostic_slot]
            .each_ref()
            .map(|n| n.load(Ordering::Relaxed));
        let input_head = rederive_head_bytes_total(source);
        let switch = if restart_restore::enabled() {
            "on"
        } else {
            "off"
        };
        let on_refused = restart_restore::on_refused_discovery_dependency();
        format!(
            "ottto-service: durable_tail source={} restart_restore={switch} restart_restore_on_refused{{reason=discovery_dependency}}={on_refused} original_v1_mapped={} durable_restore_after_selection_clear={} objects[same,unknown,changed]={:?} s2_skipped_object_changed={} \
             retail_attempts={} retail_keys={} near_cap={} pace_anomaly={} upgrade_missing_full={} migration[held,await_save,claimed,replaced]={:?} retail_exhausted[full,paced,pace_evicted]={:?} tail_read_bytes={} retail_physical_bytes[process,daily]={:?} budget_refused_retail_old_bytes={} repeated_physical_old_bytes={} upgrade_state_missing={} \
             active_bound[claude,codex,pi]={:?} resource_full={{{}}} rederive_head_bytes={} rederive_named_lines={} rederive_line_bytes={} rederive_budget[refused,refused_bytes]={:?} not_persisted={{{}}} ineligible={{{}}} \
             write_deferred={} write_unlocked={} peak_body_bytes={} store_write_failed[setup,inventory,statvfs]={:?} disk_records={} disk_bytes={} \
             bytes_written={} records_written={} records_clean={} store_budget_refused={} \
             bytes_read={} format_hold[newer,unknown,undecodable,unbindable,known_corrupt,retired_upgrade_missing,receipt_pending,behind_accepted,repin]={:?} durable_held={:?} held_census[kept,invalidated]={:?} \
             guard_header_bytes={} guard_verify_bytes={} delete_verify_bytes={} overwrite_verify_bytes={} \
             uninventoried_records={} store_write_skipped[unknown,inventory_overflow]={:?} \
             gc_records_deleted={} gc_records_read={} gc_bytes_read={} gc_keep_peak={} \
             records_invalidated={} mutation_unproved={} peak_codec_bytes={} t14_rebuild_full_started={} \
             d3_hold[growth_bytes,released_write,released_content,unfunded]={:?} \
             store_write_after_save_failed[files]={} \
             store_write_failed_restart_full[files,bytes]={:?} \
             rederive_refused[first_prompt,title,agent_label,session_start,workspace]={rederive_refused:?} rederive_head_reads={head_reads} rederive_line_peak_bytes={line_peak} rederive_fence_mismatch={fence:?} \
             native_input_bytes[head,tail,full]=[{input_head},{},{}]",
            source.api_slug(),
            self.original_v1_mapped,
            self.durable_restore_after_selection_clear,
            self.objects,
            self.s2_skipped_object_changed,
            self.retail_attempts,
            self.retail_keys,
            self.near_cap,
            self.pace_anomaly,
            self.upgrade_missing_full,
            self.migration,
            self.retail_full,
            retail_bytes(source, 0),
            [retail_bytes(source, 2), retail_bytes(source, 3)],
            retail_bytes(source, 1),
            retail_bytes(source, 1),
            self.upgrade_state_missing,
            self.active_bound,
            classes(&self.resource_full),
            self.rederive_head_bytes,
            self.rederive_named_lines,
            self.rederive_line_bytes,
            self.rederive_budget,
            classes(&self.not_persisted),
            classes(&self.ineligible),
            self.write_deferred,
            self.write_unlocked,
            self.peak_body_bytes,
            store.store_write_failed,
            store.disk_records,
            store.disk_bytes,
            store.bytes_written,
            store.records_written,
            store.records_clean,
            store.budget_refused,
            store.bytes_read,
            store.format_hold,
            self.durable_held,
            self.held_census,
            store.guard_header_bytes,
            store.guard_verify_bytes,
            store.delete_verify_bytes,
            store.overwrite_verify_bytes,
            store.uninventoried_records,
            store.store_write_skipped,
            store.gc_records_deleted,
            store.gc_records_read,
            store.gc_bytes_read,
            self.gc_keep_peak,
            store.records_invalidated,
            store.mutation_unproved,
            store.peak_codec_bytes,
            store.t14_rebuild_full_started,
            self.d3,
            self.store_write_after_save_failed,
            self.store_write_failed_restart_full,
            native_phase[0],
            native_phase[1],
        )
    }
}

/// Diagnostic only: a u64 collision can mis-attribute the UPPER-BOUND
/// counter; it never grants admission, owed, reads or money authority.
fn stale_predecessor_key(key: &str) -> u64 {
    let digest = crate::codex_scan_diagnostics::digest(key);
    u64::from_le_bytes(digest[..8].try_into().expect("fixed digest prefix"))
}
const STALE_PREDECESSOR_KEYS: usize = 2 * store::MAX_RECORDS;
// Same conservative full B-tree node per entry PLUS retained root as
// heap_layout_bound::tree_nodes::<u64, ()>: 256 + 12*8 + 11*8 = 440B.
const STALE_PREDECESSOR_ENTRY_BYTES: usize =
    256 + 12 * std::mem::size_of::<usize>() + 11 * std::mem::size_of::<u64>();
pub(crate) const STALE_PREDECESSOR_RESERVE_BYTES: usize =
    (STALE_PREDECESSOR_KEYS + 1) * STALE_PREDECESSOR_ENTRY_BYTES;

/// Per-pass decisions share the existing index-bounded map. Layout GC is
/// authorized only by the actual selected read's settlement, never its probe.
#[derive(Clone, Debug)]
enum ScopeDecision {
    Scope(Scope),
    Excluded,
    LayoutUnavailable { settled: bool, verified: bool },
}
impl ScopeDecision {
    fn scope(&self) -> Option<&Scope> {
        match self {
            Self::Scope(scope) => Some(scope),
            _ => None,
        }
    }
}
/// The least spacing between two restart-Full alarms in one process.
pub(crate) const RESTART_FULL_ALARM_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

struct Slot {
    dir: PathBuf,
    index_path: PathBuf,
    store: DurableTailStore,
    /// File scopes decided this pass, by key: GC drops a record bound to
    /// another scope. Keys not decided this pass keep their records.
    decided: BTreeMap<String, ScopeDecision>,
    /// The pass's sampled scope and identity-capture mode.
    namespace: Scope,
    identity_capture: bool,
    /// Reset on every pass; supplied only by the owning sync cycle.
    skill_labels_enabled: bool,
    /// A completed OFF purge stays valid until this slot permits labels again.
    skill_label_purge_complete: bool,
    /// Keys held (U) by this source, and the totals the last alarm reported:
    /// [held, t14_rebuild, mode_repaired, disabled, rebuild_full,
    /// upgrade_state_missing, old_binding_no_match, retail_exhausted[3], stale_full[3]].
    held: u64,
    old_binding_no_match: u64,
    reported: [u64; 22],
    /// Last reported D3 Claude hold key count.
    d3_reported: u64,
    /// Key count of the last committed index seen; sizes the per-pass maps.
    indexed: usize,
}

impl Slot {
    fn migration_record(
        &mut self,
        key: &str,
        index: &ScanIndex,
        lease: &mut store::ActiveLease,
    ) -> Result<(Box<store::DurableRecord>, Expected), &'static str> {
        let digest = store::key_digest(DurableSource::ClaudeCode, key);
        let record = match self
            .store
            .read_bounded(&digest, lease)
            .map_err(|_| "o3.input_pending")?
        {
            ReadOutcome::Found(record) => record,
            ReadOutcome::Refused(
                store::Refusal::NewerFormat
                | store::Refusal::Unknown
                | store::Refusal::Undecodable
                | store::Refusal::Unbindable,
            ) => return Err("o3.protected_record"),
            _ => return Err("o3.record"),
        };
        self.migration_expected(key, index, record)
    }

    fn migration_expected(
        &self,
        key: &str,
        index: &ScanIndex,
        record: Box<store::DurableRecord>,
    ) -> Result<(Box<store::DurableRecord>, Expected), &'static str> {
        if index.effective_upload_body_witness_revision_requires_adoption(key)
            || index.files.get(key).is_some_and(|e| {
                e.effective_upload_body_witness_revision
                    > effective_revision(SnapshotSource::ClaudeCode)
            })
            || index.active_effective_upload_body_witness_revision
                > effective_revision(SnapshotSource::ClaudeCode)
        {
            return Err("o3.replay");
        }
        if record.record.binding.context
            != store::context_digest(
                &self.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            )
        {
            return Err("o3.context");
        }
        let scope = self
            .decided
            .get(key)
            .and_then(ScopeDecision::scope)
            .ok_or("o3.scope_missing")?;
        let i = Interpretation::of(
            SnapshotSource::ClaudeCode,
            key,
            index,
            self.identity_capture,
            &self.namespace,
        );
        match claude_expected(key, scope, index, &i, &record) {
            Err("old_binding_no_match") => {}
            Err("context" | "revision_downgrade" | "revision_adoption_required") => {
                return Err("o3.context")
            }
            _ => return Err("o3.binding"),
        }
        let current = expected(
            DurableSource::ClaudeCode,
            SnapshotSource::ClaudeCode,
            key,
            scope,
            index,
            &i,
            None,
        )
        .ok_or("o3.accepted_missing")?;
        Ok((record, current))
    }
}

/// Fixed-size stamp in the existing paid pacing node. Remember structural
/// classification after the first no-record publication changes index binding.
#[derive(Clone, Copy)]
struct FullPace {
    at: std::time::SystemTime,
    structural: bool,
    flags: u8,
    head_extent: u32,
}
const HEAD_USED: u8 = 1;
const FULL_SPENT: u8 = 2;
const DEFERRED: u8 = 4;
const NEAR_EXTRA: u8 = 8;
const _: () = assert!(size_of::<FullPace>() <= 24);
fn full_pace_key(source: SnapshotSource, key: &str) -> store::Digest32 {
    match durable_source(source) {
        Some(ds) => store::key_digest(ds, key),
        None => store::context_digest(source.api_slug(), Some(key)),
    }
}

fn near_source_cap(source: SnapshotSource, length: u64) -> bool {
    let cap = max_jsonl_file_bytes(source);
    length >= cap - cap / 10
}

#[derive(Clone, Copy)]
struct QuietRetirement {
    key: store::Digest32,
    source: SnapshotSource,
    fingerprint: store::Digest32,
    durable: bool,
}

/// Process-lifetime durable state beside the RAM cache.
pub(crate) struct Stores {
    slots: [Option<Slot>; crate::snapshots::durable_sources::SOURCES.len()],
    /// Keys admitted to the RAM cache since their source's last write.
    touched: BTreeSet<String>,
    /// Selection provenance: the source-file fingerprint each admitted
    /// reduction was acquired for. A write binds a reduction only to a
    /// committed entry with this same fingerprint; local-hold settlement that
    /// reverts or clears the entry makes it refuse (F2).
    selected: BTreeMap<String, String>,
    // At most CACHE_ENTRIES; the persisted marker remains owed until receipt.
    retiring: [Option<QuietRetirement>; crate::transcript_cache::CACHE_ENTRIES],
    /// Keys whose restore refused the record as `entry_changed`, until their
    /// next acquisition completes. Process-local, never persisted.
    stale_predecessor: BTreeSet<u64>,
    /// When this process last emitted the restart-Full alarm.
    restart_full_alarmed: Option<std::time::Instant>,
    counters: Counters,
    // Source+key only: never clear on passes, scope changes or cache eviction.
    // A node without authority is freed (`release_idle_custody`).
    retail_spent: BTreeMap<store::Digest32, Box<KeyCustody>>,
    /// P1-1 zero-old-byte process grants, outside `retail_spent`.
    restore_pending: BTreeMap<store::Digest32, RestorePending>,
    /// G3 receipt debt and D3 holds, outside the custody node.
    key_debt: BTreeMap<store::Digest32, Box<owed::KeyDebt>>,
    /// P2 restored head bytes reserved this pass, per durable source.
    rederive_spent: [u64; crate::snapshots::durable_sources::SOURCES.len()],
    retail_full_at: BTreeMap<store::Digest32, FullPace>,
    #[cfg(test)]
    retail_full_now: Option<std::time::SystemTime>,
    upgrade_reads: std::sync::Arc<AtomicU64>,
    /// G3: a source whose owed key could not be enrolled stays conservatively
    /// owed until reconstruction or a disabled store clears it.
    owed_overflow: [bool; crate::snapshots::durable_sources::SOURCES.len()],
    /// D3 resource-pause observations and the first-hold alarm.
    d3: write_ahead::D3State,
}

/// A0-h authority only. Its node uses 1,016 of its 1,024 prepaid bytes by
/// layout arithmetic, so per-key M3 state lives in `key_debt` and
/// `restore_pending`, never here.
#[derive(Default)]
struct KeyCustody {
    spent: Option<(u64, std::time::Instant)>,
    original: Option<store::MutationWitness>,
    upgrade_started: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl KeyCustody {
    /// Spent, witness and upgrade markers are authority; nothing else is.
    fn has_authority(&self) -> bool {
        self.spent.is_some() || self.original.is_some() || self.upgrade_started.is_some()
    }
}

/// The high water and grant time a P1-1 process grant would have spent.
#[derive(Clone, Copy)]
struct RestorePending {
    high: u64,
    at: std::time::Instant,
}
fn restore_pending_node_bytes() -> Option<usize> {
    crate::heap_layout_bound::tree_node_bytes::<store::Digest32, RestorePending>()
}

fn custody_node_bytes() -> Option<usize> {
    crate::heap_layout_bound::tree_node_bytes::<store::Digest32, Box<KeyCustody>>()?
        // Box::new requests Layout::new::<KeyCustody>(); size_of already
        // includes the type's tail padding, so adding alignment double-counts it.
        .checked_add(std::mem::size_of::<KeyCustody>())?
        .checked_add(arc_allocation_bytes::<std::sync::atomic::AtomicBool>()?)
}

// ArcInner on the qualified Rust toolchains: strong + weak counters, then data.
// Round the requested allocation to its alignment; no allocator usable-size claim.
fn arc_allocation_bytes<T>() -> Option<usize> {
    let align = std::mem::align_of::<T>().max(std::mem::align_of::<usize>());
    (2 * std::mem::size_of::<usize>())
        .checked_add(std::mem::size_of::<T>())?
        .checked_add(align - 1)
        .map(|bytes| bytes / align * align)
}
// upgrade_started is charged per key. The ONE shared upgrade_reads Arc is
// charged once against the prepaid extra root node, never once per key.
const _: () = assert!(std::mem::size_of::<AtomicU64>() <= 8);

impl Default for Stores {
    fn default() -> Self {
        Self {
            slots: Default::default(),
            touched: BTreeSet::new(),
            selected: BTreeMap::new(),
            retiring: [None; crate::transcript_cache::CACHE_ENTRIES],
            stale_predecessor: BTreeSet::new(),
            restart_full_alarmed: None,
            counters: Counters::default(),
            retail_spent: BTreeMap::new(),
            restore_pending: BTreeMap::new(),
            key_debt: BTreeMap::new(),
            rederive_spent: Default::default(),
            retail_full_at: BTreeMap::new(),
            #[cfg(test)]
            retail_full_now: None,
            upgrade_reads: Default::default(),
            owed_overflow: Default::default(),
            d3: Default::default(),
        }
    }
}

impl Stores {
    fn retry_offered(&mut self, offered: BTreeMap<store::Digest32, String>, index: &ScanIndex) {
        for key in offered.into_values() {
            if let Some(entry) = index.files.get(&key) {
                self.selected
                    .insert(key.clone(), entry.source_file_fingerprint.clone());
                self.touched.insert(key);
            }
        }
    }

    fn fund_key(&mut self, key: store::Digest32) -> bool {
        if custody_node_bytes().map_or(true, |n| n > 1024)
            || (!self.retail_spent.contains_key(&key)
                && self.retail_spent.len() >= store::MAX_RECORDS * 2)
        {
            Counters::bump(&mut self.counters.ineligible, "custody_unfunded");
            return false;
        }
        self.retail_spent.entry(key).or_default();
        true
    }

    /// Frees `key`'s custody node once it carries no authority, so funding
    /// for a strict check or a consumed witness never pins a slot for life.
    pub(super) fn release_idle_custody(&mut self, key: &store::Digest32) {
        if self
            .retail_spent
            .get(key)
            .is_some_and(|custody| !custody.has_authority())
        {
            self.retail_spent.remove(key);
        }
    }

    /// A write or receipt whose certificate reaches the pending high water
    /// makes the zero-old-byte grant moot: a later restore starts there.
    pub(super) fn release_restore_pending(&mut self, key: &store::Digest32, length: u64) {
        self.clear_rederive_hold(key);
        if self
            .restore_pending
            .get(key)
            .is_some_and(|pending| length >= pending.high)
        {
            self.restore_pending.remove(key);
        }
    }

    /// Records the committed index's key count for `source`.
    fn note_indexed(&mut self, source: DurableSource, index: &ScanIndex) {
        if let Some(slot) = self.slot(source).as_mut() {
            slot.indexed = index.files.len();
        }
    }

    /// P1-1: a restore owing no old bytes spends a bounded pending grant, never
    /// an A0-h custody node. `Ok(None)` hands over to the spent custody: old
    /// bytes owed, or a re-read behind the pending high water, which is
    /// promoted with its original grant time so the Daily gate stays exact.
    fn pending_retail(
        &mut self,
        key: store::Digest32,
        c: &DurableCertificate,
        attempt: RetailAttempt,
        now: std::time::Instant,
    ) -> Result<Option<RetailAttempt>, RetailHold> {
        let zero_old = attempt.old_end <= c.length;
        let prior = self.restore_pending.get(&key).copied();
        if prior.is_some_and(|p| now < p.at) {
            Counters::bump(&mut self.counters.ineligible, "retail_clock_rollback");
            return Err(RetailHold::AccountingLost);
        }
        if let Some(pending) = prior.filter(|p| !zero_old || c.length < p.high) {
            if !self.fund_key(key) {
                // Pending authority is kept; the paced Full reads instead.
                Counters::bump(&mut self.counters.ineligible, "retail_pending_unpromoted");
                return Err(RetailHold::AccountingLost);
            }
            self.restore_pending.remove(&key);
            self.retail_spent.get_mut(&key).expect("funded").spent =
                Some((pending.high, pending.at));
            return Ok(None);
        }
        if !zero_old {
            return Ok(None);
        }
        if c.length > attempt.end || attempt.end < attempt.old_end {
            Counters::bump(&mut self.counters.ineligible, "retail_range_ineligible");
            return Err(RetailHold::Ineligible);
        }
        if prior.is_none() && self.restore_pending.len() >= RESTORE_PENDING_KEYS {
            // A grant a full day old gates nothing the Daily grant would not
            // also allow: reclaim those, never a younger high water.
            let before = self.restore_pending.len();
            self.restore_pending.retain(|_, p| {
                now.checked_duration_since(p.at)
                    .map_or(true, |age| age < RETAIL_DAILY)
            });
            let expired = (before - self.restore_pending.len()) as u64;
            if expired > 0 {
                *self
                    .counters
                    .ineligible
                    .entry("retail_pending_expired")
                    .or_default() += expired;
            }
        }
        if prior.is_none()
            && (restore_pending_node_bytes().map_or(true, |n| n > 1024)
                || self.restore_pending.len() >= RESTORE_PENDING_KEYS)
        {
            Counters::bump(&mut self.counters.ineligible, "retail_pending_overflow");
            return Err(RetailHold::AccountingLost);
        }
        self.counters.retail_keys += u64::from(prior.is_none());
        self.counters.retail_attempts += 1;
        // Spend before any syscall, exactly like the custody grant.
        let high = prior.map_or(attempt.end, |p| p.high.max(attempt.end));
        self.restore_pending
            .insert(key, RestorePending { high, at: now });
        Ok(Some(attempt))
    }

    /// Per-pass key maps (`touched`, `selected`) follow the committed indexes,
    /// with the old fixed capacity as the floor: never a fixed 512-key cliff.
    fn pass_key_cap(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .fold(2 * store::MAX_RECORDS, |cap, slot| {
                cap.saturating_add(slot.indexed)
            })
    }
    fn slot(&mut self, source: DurableSource) -> &mut Option<Slot> {
        &mut self.slots[source.slot()]
    }
}

/// The single-writer proof for the daemon's state directory: #801's
/// `StateDirLock`, held for the life of the daemon process. M1 adds no lock.
/// The store's writes, GC and removal take it; restore only reads and takes
/// nothing. Dropping #801's lock unlocks it (#812); nothing here relies on
/// when it is released.
impl SingleWriter for crate::locked_state_dir::LockedStateDir {
    fn state_dir(&self) -> &Path {
        self.dir()
    }
}

pub(crate) fn durable_source(source: SnapshotSource) -> Option<DurableSource> {
    DurableSource::from_snapshot(source)
}

/// S2: freeze accepted facts before working-index mutation. Unknown object
/// identity keeps this floor; only independently proved replacement may skip it.
#[derive(Clone, Copy)]
pub(crate) struct AcceptedFloor {
    pub(crate) end: u64,
    revision: u64,
    birth: u64,
    generation: u64,
    entry: store::Digest32,
    strict: bool,
    /// A lossy read's raw extent is not a verified accepted-body prefix.
    verified_extent: bool,
}
impl AcceptedFloor {
    pub(crate) fn of(index: &ScanIndex, key: &str) -> Option<Self> {
        let e = index.files.get(key)?;
        Some(Self {
            end: e.size_bytes,
            revision: e.effective_upload_body_witness_revision,
            birth: e.opened_birth_nanos,
            generation: index.generation,
            strict: !e.source_file_fingerprint.is_empty(),
            verified_extent: !e.has_unverified_source(),
            entry: store::replay_entry_digest(
                &store::entry_digest(
                    &e.source_file_fingerprint,
                    e.last_upload_body_witness.as_deref(),
                ),
                e.effective_upload_body_witness_revision,
                index
                    .claude_money_birth_store
                    .money_marks(claude_money_birth_store::location_key(key)),
            ),
        })
    }
    pub(crate) fn behind(self, length: u64) -> bool {
        (self.verified_extent && length < self.end) || !self.permits_real_edit()
    }
    pub(crate) fn permits_real_edit(self) -> bool {
        effective_revision(SnapshotSource::ClaudeCode) >= self.revision
    }
}

/// A different inode alone is ambiguous (copies/hard links/reuse). Births
/// must independently disagree, and the original must bind the frozen entry.
fn accepted_object_changed(
    record: &store::DurableRecord,
    a: AcceptedFloor,
    device: u64,
    inode: u64,
    birth: u64,
) -> bool {
    let c = &record.record.certificate;
    record.format == 1
        && a.strict
        && record.record.binding.entry == a.entry
        && record.index_generation <= a.generation
        && a.birth != 0
        && a.birth == c.birth_nanos
        && birth != 0
        && birth != a.birth
        && (c.device, c.inode) != (device, inode)
}

/// The interpretation inputs a record binds to beyond the file scope.
pub(crate) struct Interpretation<'a> {
    pub(crate) accepted: Option<AcceptedFloor>,
    /// The Claude request-identity contract and identity/attribution parse modes.
    pub(crate) identity_contract: String,
    /// The Codex counting view (`codex_counting_version::singleton_view`).
    pub(crate) counting_view: String,
    pub(crate) namespace: &'a Scope,
}

impl<'a> Interpretation<'a> {
    pub(crate) fn of(
        source: SnapshotSource,
        key: &str,
        index: &ScanIndex,
        identity_capture: bool,
        namespace: &'a Scope,
    ) -> Self {
        let mut identity_contract = format!(
            "{}|changed={}|capture={identity_capture}",
            index
                .claude_request_identity_contract
                .as_deref()
                .unwrap_or("none"),
            index.claude_request_identity_contract_changed,
        );
        if source == SnapshotSource::ClaudeCode {
            identity_contract.push_str(&format!("|attr={}", claude_attribution_capture_enabled()));
        }
        Self {
            accepted: (restart_restore::enabled() && source == SnapshotSource::ClaudeCode)
                .then(|| AcceptedFloor::of(index, key))
                .flatten(),
            identity_contract,
            counting_view: if source == SnapshotSource::Codex {
                codex_counting_version::singleton_view_of_key(key, index)
            } else {
                String::from("none")
            },
            namespace,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn expected(
    source: DurableSource,
    snapshot_source: SnapshotSource,
    key: &str,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    representation: Option<(u16, store::Digest32, u64)>,
) -> Option<Expected> {
    let entry = index.files.get(key)?;
    Some(Expected {
        binding: Binding {
            source,
            key: store::key_digest(source, key),
            context: store::context_digest(
                &interpretation.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            ),
            scope: replay_scope_for(
                snapshot_source,
                scope,
                index,
                interpretation,
                None,
                representation,
            ),
            entry: store::replay_entry_digest(
                &store::entry_digest(
                    &entry.source_file_fingerprint,
                    entry.last_upload_body_witness.as_deref(),
                ),
                entry.effective_upload_body_witness_revision,
                if source == DurableSource::ClaudeCode {
                    index
                        .claude_money_birth_store
                        .money_marks(claude_money_birth_store::location_key(key))
                } else {
                    0
                },
            ),
        },
        committed_generation: index.generation,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObligationKind {
    BodyWitness,
    MoneyRule,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Obligation {
    kind: ObligationKind,
    revision: u64,
}
// SPENT audit rows: body witness r3 (Ron, #805); money v1/v2 (Lead A C2,
// #825), both with mask 0. These diagnostic rows grant no new replay.
const REPLAY_REGISTRY: &[Obligation] = &[
    Obligation {
        kind: ObligationKind::BodyWitness,
        revision: 3,
    },
    Obligation {
        kind: ObligationKind::MoneyRule,
        revision: 1,
    },
    Obligation {
        kind: ObligationKind::MoneyRule,
        revision: 2,
    },
];
fn registered(obligation: Obligation) -> bool {
    REPLAY_REGISTRY.contains(&obligation)
}

/// Reuse the existing binding formula verbatim; overrides are RAM-only probes.
fn replay_scope(
    source: SnapshotSource,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    replay: Option<Obligation>,
) -> store::Digest32 {
    replay_scope_for(source, scope, index, interpretation, replay, None)
}

fn replay_scope_for(
    source: SnapshotSource,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    replay: Option<Obligation>,
    representation: Option<(u16, store::Digest32, u64)>,
) -> store::Digest32 {
    let (format, allowlist, revision) = representation.unwrap_or_else(|| {
        (
            durable_source(source)
                .expect("admitted source")
                .properties()
                .write_format,
            durable_source(source)
                .expect("admitted source")
                .properties()
                .allowlist(),
            effective_revision(source),
        )
    });
    let body_revision = replay.filter(|row| row.kind == ObligationKind::BodyWitness);
    let money_rule = replay.filter(|row| row.kind == ObligationKind::MoneyRule);
    store::replay_scope_digest(
        &if format == store::FORMAT_V3 {
            // Claude is explicitly absent. Codex's body-derived C is checked
            // by v3_replay_scope after decode, before content input or reuse.
            let absent =
                acquired::ImmutableCounting::canonical(source, None).expect("admitted source");
            store::scope_digest_v3(
                &scope.0,
                &allowlist,
                &interpretation.identity_contract,
                absent.bytes(),
            )
        } else {
            store::scope_digest_for(
                format,
                &scope.0,
                &allowlist,
                &interpretation.identity_contract,
                &interpretation.counting_view,
            )
        },
        body_revision.map_or(revision, |row| row.revision),
        body_revision.map_or(index.active_effective_upload_body_witness_revision, |row| {
            row.revision
        }),
        if source == SnapshotSource::ClaudeCode {
            money_rule.map_or(index.claude_money_birth_store.money_rule_version(), |row| {
                row.revision as u16
            })
        } else {
            0
        },
        source == SnapshotSource::ClaudeCode && claude_request_money::e2::enabled(),
    )
}

/// Format-3 scope uses immutable counting from the actual acquisition/body.
/// Mutable ACK evidence remains in the existing CV/CUO checks.
fn v3_replay_scope(
    source: SnapshotSource,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    revision: u64,
    counting: &acquired::ImmutableCounting,
) -> store::Digest32 {
    let allowlist = durable_source(source)
        .expect("admitted source")
        .properties()
        .allowlist();
    store::replay_scope_digest(
        &store::scope_digest_v3(
            &scope.0,
            &allowlist,
            &interpretation.identity_contract,
            counting.bytes(),
        ),
        revision,
        index.active_effective_upload_body_witness_revision,
        if source == SnapshotSource::ClaudeCode {
            index.claude_money_birth_store.money_rule_version()
        } else {
            0
        },
        source == SnapshotSource::ClaudeCode && claude_request_money::e2::enabled(),
    )
}

#[derive(Clone, Copy)]
struct V3RestoreScope<'a> {
    index: &'a ScanIndex,
    interpretation: &'a Interpretation<'a>,
}

fn unregistered_scope(
    source: SnapshotSource,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    recorded: store::Digest32,
) -> Option<Obligation> {
    let current = [
        Obligation {
            kind: ObligationKind::BodyWitness,
            revision: index.active_effective_upload_body_witness_revision,
        },
        Obligation {
            kind: ObligationKind::MoneyRule,
            revision: u64::from(index.claude_money_birth_store.money_rule_version()),
        },
    ];
    current.into_iter().find(|obligation| {
        !registered(*obligation)
            && (obligation.kind != ObligationKind::MoneyRule
                || source == SnapshotSource::ClaudeCode)
            && REPLAY_REGISTRY.iter().any(|row| {
                row.kind == obligation.kind
                    && replay_scope(source, scope, index, interpretation, Some(*row)) == recorded
            })
    })
}

fn claude_expected(
    key: &str,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    record: &store::DurableRecord,
) -> Result<(Expected, u64), &'static str> {
    if record.record.allowlist != codec::allowlist_digest(SnapshotSource::ClaudeCode) {
        return Err("old_binding_representation");
    }
    let current = effective_revision(SnapshotSource::ClaudeCode);
    if record.format == store::FORMAT_V3 {
        return claude_expected_v3(key, scope, index, interpretation, record, current);
    }
    if record.format != 1 {
        return Err("old_binding_representation");
    }
    // NAMED_REVISION_CANDIDATES: record/entry applied, current code, explicitly retained active.
    let applied = index
        .files
        .get(key)
        .ok_or("accepted_floor_missing")?
        .effective_upload_body_witness_revision;
    let revisions = [
        applied,
        current,
        index.active_effective_upload_body_witness_revision,
    ];
    let candidates: BTreeSet<_> = revisions.into_iter().collect();
    let mut matched = None;
    for revision in candidates {
        let expected = expected(
            DurableSource::ClaudeCode,
            SnapshotSource::ClaudeCode,
            key,
            scope,
            index,
            interpretation,
            Some((record.format, record.record.allowlist, revision)),
        )
        .ok_or("accepted_floor_missing")?;
        if expected.binding.context != record.record.binding.context {
            return Err("context");
        }
        if expected.binding.scope != record.record.binding.scope {
            continue;
        }
        if matched.is_some() {
            return Err("old_binding_ambiguous");
        }
        matched = Some((expected, revision));
    }
    let mut proof = matched.ok_or("old_binding_no_match")?;
    if proof.1 != current {
        return Err(if proof.1 > current {
            "revision_downgrade"
        } else {
            "revision_adoption_required"
        });
    }
    // Historical entry/generation are not acquisition gates; mutation binds to this exact R.
    proof.0.binding.entry = record.record.binding.entry;
    proof.0.committed_generation = record.index_generation;
    Ok(proof)
}

/// A v3 record names its finite acquired revision r_a; there is no candidate
/// search. Its entry digest is reserved; the S2 floor and certificate decide.
fn claude_expected_v3(
    key: &str,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    record: &store::DurableRecord,
    current: u64,
) -> Result<(Expected, u64), &'static str> {
    let acquired = record
        .record
        .acquisition
        .ok_or("old_binding_representation")?
        .acquired_revision;
    let mut expected = expected(
        DurableSource::ClaudeCode,
        SnapshotSource::ClaudeCode,
        key,
        scope,
        index,
        interpretation,
        Some((record.format, record.record.allowlist, acquired)),
    )
    .ok_or("accepted_floor_missing")?;
    if expected.binding.context != record.record.binding.context {
        return Err("context");
    }
    if expected.binding.scope != record.record.binding.scope {
        return Err("old_binding_no_match");
    }
    if acquired != current {
        return Err(if acquired > current {
            "revision_downgrade"
        } else {
            "revision_adoption_required"
        });
    }
    expected.binding.entry = record.record.binding.entry;
    expected.committed_generation = record.index_generation;
    Ok((expected, acquired))
}

fn ineligible_class(reason: store::Ineligible) -> &'static str {
    match reason {
        store::Ineligible::Source => "source",
        store::Ineligible::Key => "key",
        store::Ineligible::Context => "context",
        store::Ineligible::Scope => "scope",
        store::Ineligible::GenerationAhead => "generation_ahead",
        store::Ineligible::EntryChanged => "entry_changed",
    }
}

fn full_reason_class(reason: FullReason) -> &'static str {
    match reason {
        FullReason::StateMissing => "state_missing",
        FullReason::AuditDue => "audit_due",
        FullReason::ClockChanged => "clock_changed",
        FullReason::ScopeChanged => "scope_changed",
        FullReason::InvalidCheckpoint => "invalid_checkpoint",
        FullReason::Replaced => "replaced",
        FullReason::Shrunk => "shrunk",
        FullReason::SameSizeEdit => "same_size_edit",
        FullReason::HeadChanged => "head_changed",
        FullReason::BoundaryChanged => "boundary_changed",
        FullReason::UnsupportedIdentity => "unsupported_identity",
    }
}

/// The retained checkpoint's certificate with the birth of the object now
/// at `key`'s path, or `None` when that object is not the checkpoint's (it
/// was replaced since the read: nothing is persisted for it).
fn certificate_at(
    key: &str,
    checkpoint: &Checkpoint,
    index: &ScanIndex,
    now: u64,
) -> Option<DurableCertificate> {
    let mut certificate = checkpoint.durable_certificate(0)?;
    let metadata = std::fs::metadata(key).ok()?;
    if metadata.dev() != certificate.device || metadata.ino() != certificate.inode {
        return None;
    }
    certificate.birth_nanos = birth_unix_nanos(&metadata);
    // Downgrade readers still consume these bytes. A decoded checkpoint has
    // dropped them; only the current committed index supplies write truth.
    certificate.audit_debt_unix_seconds =
        sampled_audit::debt_for_key(index, key, now).map(|debt| debt.due_unix_seconds);
    Some(certificate)
}

fn audit_carrier_matches(
    record: &store::DurableRecord,
    index: &ScanIndex,
    key: &str,
    now: u64,
) -> bool {
    record.envelope_audit_debt.map_or(true, |due| {
        sampled_audit::debt_for_key(index, key, now)
            .is_some_and(|debt| debt.due_unix_seconds <= due)
    })
}

fn refuse_class(refuse: Refuse) -> &'static str {
    match refuse {
        Refuse::NonEmpty(field) | Refuse::NotRederivable(field) | Refuse::NotDigest(field) => field,
        Refuse::UnknownLabel => "static_label",
        Refuse::TooLarge => "record_bytes",
        Refuse::WriteFailed => "encode_io",
    }
}

// Stores is a leaf lock; decoder admission/accounting must stay outside it.
thread_local! { static STORES_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
pub(super) fn stores_held() -> bool {
    STORES_HELD.with(std::cell::Cell::get)
}
pub(super) struct StoresGuard<'a>(std::sync::MutexGuard<'a, Stores>);
impl std::ops::Deref for StoresGuard<'_> {
    type Target = Stores;
    fn deref(&self) -> &Stores {
        &self.0
    }
}
impl std::ops::DerefMut for StoresGuard<'_> {
    fn deref_mut(&mut self) -> &mut Stores {
        &mut self.0
    }
}
impl Drop for StoresGuard<'_> {
    fn drop(&mut self) {
        STORES_HELD.with(|held| held.set(false));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetailHold {
    Exhausted,
    AccountingLost,
    Ineligible,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetailGrant {
    Process,
    Daily,
}
const RETAIL_DAILY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
pub(crate) struct RetailAttempt {
    source: DurableSource,
    grant: RetailGrant,
    object: (u64, u64, u64),
    next: u64,
    end: u64,
    old_end: u64,
}
impl crate::heap_layout_bound::HeapLayoutBound for RetailAttempt {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            source: _,
            grant: _,
            object: _,
            next: _,
            end: _,
            old_end: _,
        } = self;
        c.add(0)
    }
}

// Process totals by source: native physical Tail bytes and old-suffix overlap.
static RETAIL_BYTES: [[AtomicU64; 4]; 2] = [
    [const { AtomicU64::new(0) }; 4],
    [const { AtomicU64::new(0) }; 4],
];
fn retail_bytes(source: SnapshotSource, metric: usize) -> u64 {
    durable_source(source).map_or(0, |s| {
        RETAIL_BYTES[s as usize][metric].load(Ordering::Relaxed)
    })
}

pub(crate) use crate::snapshots::DurableCustody;
impl DurableCustody {
    pub(crate) fn take_retail(&mut self) -> Option<RetailAttempt> {
        self.retail.take()
    }
    pub(crate) fn put_retail(&mut self, attempt: RetailAttempt) {
        assert!(self.retail.is_none(), "retail already attached");
        self.retail = Some(attempt);
    }
    pub(crate) fn retail_mut(&mut self) -> Option<&mut RetailAttempt> {
        self.retail.as_mut()
    }
    pub(crate) fn put_upgrade(&mut self, read: UpgradeRead) {
        assert!(
            self.retail.is_none() && self.upgrade.is_none(),
            "upgrade custody already attached"
        );
        self.upgrade = Some(read);
    }
    pub(crate) fn upgrade_mut(&mut self) -> Option<&mut UpgradeRead> {
        self.upgrade.as_mut()
    }
    pub(crate) fn has_active(&self) -> bool {
        self.active.is_some()
    }
    pub(crate) fn active_mut(&mut self) -> Option<&mut store::ActiveLease> {
        self.active.as_mut()
    }
    /// The acquisition's single lease: acquired once, then charged in place.
    pub(crate) fn ensure_active(
        &mut self,
        cache: &SharedCache,
        source: SnapshotSource,
        need_bytes: u64,
    ) -> Result<&mut store::ActiveLease, LeaseBusy> {
        match self.active.as_mut() {
            Some(lease) => lease.charge(need_bytes).map_err(|_| LeaseBusy)?,
            None => match cache.acquire_active(source, need_bytes) {
                store::LeaseWait::Granted(lease) => self.active = Some(lease),
                store::LeaseWait::Busy | store::LeaseWait::OverBudget => return Err(LeaseBusy),
            },
        }
        self.active.as_mut().ok_or(LeaseBusy)
    }
    #[allow(clippy::result_large_err)] // Refusal returns the caller's lease.
    pub(crate) fn attach_active(
        &mut self,
        lease: store::ActiveLease,
    ) -> Result<(), store::ActiveLease> {
        if self.active.is_some() {
            return Err(lease);
        }
        self.active = Some(lease);
        Ok(())
    }
    pub(crate) fn release_active(&mut self) {
        if let Some(lease) = self.active.take() {
            lease.release();
        }
    }
    pub(crate) fn owed(&self) -> Option<&ReceiptOwed> {
        self.owed.as_ref()
    }
    /// While debt exists the chain lives only inside it, never twice.
    pub(crate) fn chain(&self) -> Option<&AcquiredChain> {
        self.chain.as_ref()
    }
    pub(crate) fn chain_mut(&mut self) -> Option<&mut AcquiredChain> {
        self.chain.as_mut()
    }
    pub(crate) fn take_chain(&mut self) -> Option<AcquiredChain> {
        self.chain.take()
    }
    pub(crate) fn take_owed(&mut self) -> Option<ReceiptOwed> {
        self.owed.take()
    }
    #[allow(clippy::result_large_err)] // Refusal returns the original debt.
    pub(crate) fn put_owed(&mut self, owed: ReceiptOwed) -> Result<(), ReceiptOwed> {
        if self.owed.is_some() || self.chain.is_some() {
            return Err(owed);
        }
        self.owed = Some(owed);
        Ok(())
    }
    #[allow(clippy::result_large_err)] // Refusal returns the original chain.
    pub(crate) fn put_chain(&mut self, chain: AcquiredChain) -> Result<(), AcquiredChain> {
        if self.owed.is_some() || self.chain.is_some() {
            return Err(chain);
        }
        self.chain = Some(chain);
        Ok(())
    }
}

/// The acquisition's active lease could not be granted or extended.
#[derive(Debug)]
pub(crate) struct LeaseBusy;

pub(crate) struct UpgradeRead {
    object: (u64, u64, u64),
    started: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    local_started: bool,
    total: std::sync::Arc<AtomicU64>,
}
impl crate::heap_layout_bound::HeapLayoutBound for UpgradeRead {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            object: _,
            started,
            local_started: _,
            total: _,
        } = self;
        c.add(if started.is_some() { 64 } else { 32 })
    }
}
impl UpgradeRead {
    pub(crate) fn read(&mut self, file: &mut File, bytes: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        if bytes.is_empty() {
            return Ok(0);
        }
        let m = file.metadata()?;
        if (m.dev(), m.ino(), birth_unix_nanos(&m)) != self.object {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upgrade object",
            ));
        }
        let result = file.read(bytes);
        let first = self.started.as_ref().map_or_else(
            || !std::mem::replace(&mut self.local_started, true),
            |started| !started.swap(true, Ordering::Relaxed),
        );
        if first {
            self.total.fetch_add(1, Ordering::Relaxed);
            #[cfg(test)]
            tests::observe_upgrade_read();
        }
        result
    }
}

/// Below BufReader: count successful OS reads including prefetch, even on later failure.
pub(crate) struct AccountedReader<'a, R> {
    attempt: &'a mut RetailAttempt,
    inner: R,
}
impl<R: std::io::Read + std::io::Seek> std::io::Read for AccountedReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let at = self.inner.stream_position()?;
        let limit = self.attempt.limit(at)?.min(bytes.len());
        let n = self.inner.read(&mut bytes[..limit])?;
        self.attempt.count(at, n);
        Ok(n)
    }
}
impl<R: std::io::Read + std::io::Seek> std::io::Seek for AccountedReader<'_, R> {
    fn seek(&mut self, at: std::io::SeekFrom) -> std::io::Result<u64> {
        let pos = self.inner.seek(at)?;
        self.attempt.limit(pos)?;
        Ok(pos)
    }
}
impl RetailAttempt {
    pub(crate) fn grant(&self) -> RetailGrant {
        self.grant
    }

    fn range(&self, file: &File, offset: u64) -> std::io::Result<usize> {
        let m = file.metadata()?;
        if (m.dev(), m.ino(), birth_unix_nanos(&m)) != self.object {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "retail object",
            ));
        }
        self.limit(offset)
    }
    fn limit(&self, offset: u64) -> std::io::Result<usize> {
        if offset < self.next || offset > self.end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "retail fence",
            ));
        }
        Ok((self.end - offset).min(usize::MAX as u64) as usize)
    }
    fn count(&mut self, offset: u64, n: usize) {
        let metric = match self.grant() {
            RetailGrant::Process => 2,
            RetailGrant::Daily => 3,
        };
        RETAIL_BYTES[self.source as usize][metric].fetch_add(n as u64, Ordering::Relaxed);
        #[cfg(test)]
        m3_owed_tests::observe_retail(self.grant, offset, n);
        RETAIL_BYTES[self.source as usize][0].fetch_add(n as u64, Ordering::Relaxed);
        RETAIL_BYTES[self.source as usize][1].fetch_add(
            self.old_end.saturating_sub(offset).min(n as u64),
            Ordering::Relaxed,
        );
        #[cfg(test)]
        tests::observe_retail(offset, n, self.old_end.saturating_sub(offset).min(n as u64));
        self.next = offset + n as u64;
    }
    /// The owner must supply its same held reader; File entry points additionally check O.
    pub(crate) fn accounted<R: std::io::Read + std::io::Seek>(
        &mut self,
        inner: R,
    ) -> AccountedReader<'_, R> {
        AccountedReader {
            attempt: self,
            inner,
        }
    }
    pub(crate) fn read(&mut self, file: &mut File, bytes: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Read, Seek};
        let at = file.stream_position()?;
        self.range(file, at)?;
        self.accounted(file).read(bytes)
    }
    #[cfg(test)]
    pub(crate) fn read_at(
        &mut self,
        file: &File,
        bytes: &mut [u8],
        offset: u64,
    ) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let limit = self.range(file, offset)?.min(bytes.len());
        let n = file.read_at(&mut bytes[..limit], offset)?;
        self.count(offset, n);
        Ok(n)
    }
    pub(crate) fn finish(self) {}
}

fn authorize_strict(
    slot: &mut Slot,
    snapshot_source: SnapshotSource,
    key: &str,
    index: &ScanIndex,
    custody: &mut KeyCustody,
    replacement: &Binding,
    certificate: &DurableCertificate,
) {
    slot.indexed = index.files.len();
    slot.store
        .revoke(&store::key_digest(DurableSource::ClaudeCode, key));
    let Some(scope) = slot.decided.get(key).and_then(ScopeDecision::scope) else {
        return;
    };
    let source = durable_source(snapshot_source).expect("durable source");
    let digest = store::key_digest(source, key);
    let ReadOutcome::Found(record) = slot.store.read(&digest) else {
        return;
    };
    let interpretation = Interpretation::of(
        snapshot_source,
        key,
        index,
        slot.identity_capture,
        &slot.namespace,
    );
    if let Ok((expected, _)) = claude_expected(key, scope, index, &interpretation, &record) {
        if custody.original.is_none() {
            custody.original = slot.store.mutation_witness(&record, &expected);
        }
        // An ambiguous prior receipt still owns its unresolved custody. It is
        // not permission for the freshly verified current record: prove that
        // record independently so later dirty writes can make progress.
        if let Some(proof) = custody
            .original
            .as_ref()
            .filter(|p| slot.store.witness_current(p))
        {
            // A current predecessor witness also survives verification-memo
            // turnover; rebuilding permission must not require a memo slot.
            slot.store.authorize_witness(&record, &expected, proof);
        } else {
            slot.store.authorize(&record, &expected);
        }
    } else if custody
        .upgrade_started
        .as_ref()
        .is_some_and(|s| s.load(Ordering::Relaxed))
    {
        if let (Some(proof), Ok((record, current))) = (
            custody.original.as_ref(),
            slot.migration_expected(key, index, record),
        ) {
            if *replacement == current.binding {
                slot.store
                    .authorize_migration(&record, &current, certificate, proof);
            }
        }
    }
}

impl SharedCache {
    /// Caller already proved strict eligibility/certificate and absence of compatible RAM.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_retail(
        &self,
        source: SnapshotSource,
        key: &str,
        checkpoint: &Checkpoint,
        file: &File,
        accepted_end: u64,
        now: std::time::Instant,
    ) -> Result<RetailAttempt, RetailHold> {
        if custody_node_bytes().map_or(true, |n| n > 1024) {
            return Err(RetailHold::AccountingLost);
        }
        let c = checkpoint
            .durable_certificate(birth_unix_nanos(
                &file.metadata().map_err(|_| RetailHold::Ineligible)?,
            ))
            .ok_or(RetailHold::Ineligible)?;
        let end = file.metadata().map_err(|_| RetailHold::Ineligible)?.len();
        let source = durable_source(source).ok_or(RetailHold::Ineligible)?;
        let key = store::key_digest(source, key);
        let mut stores = self.durable().ok_or(RetailHold::AccountingLost)?;
        if stores
            .retail_spent
            .get(&key)
            .and_then(|c| c.spent)
            .is_none()
        {
            let attempt = RetailAttempt {
                source,
                grant: RetailGrant::Process,
                object: (c.device, c.inode, c.birth_nanos),
                next: c.length,
                end,
                old_end: accepted_end,
            };
            if let Some(granted) = stores.pending_retail(key, &c, attempt, now)? {
                return Ok(granted);
            }
        }
        if let Some((high, spent)) = stores.retail_spent.get(&key).and_then(|c| c.spent.as_ref()) {
            if now < *spent {
                Counters::bump(&mut stores.counters.ineligible, "retail_clock_rollback");
                return Err(RetailHold::AccountingLost);
            }
            if c.length < *high || accepted_end > c.length {
                let Some(deadline) = spent.checked_add(RETAIL_DAILY) else {
                    Counters::bump(&mut stores.counters.ineligible, "retail_clock_overflow");
                    return Err(RetailHold::AccountingLost);
                };
                if now < deadline {
                    Counters::bump(
                        &mut stores.counters.ineligible,
                        "retail_exhausted.budget_refused",
                    );
                    return Err(RetailHold::Exhausted);
                }
            }
        } else if !stores.retail_spent.contains_key(&key)
            && stores.retail_spent.len() >= store::MAX_RECORDS * 2
        {
            Counters::bump(
                &mut stores.counters.ineligible,
                "retail_accounting_overflow",
            );
            return Err(RetailHold::AccountingLost);
        }
        if c.length > end || end < accepted_end {
            Counters::bump(&mut stores.counters.ineligible, "retail_range_ineligible");
            return Err(RetailHold::Ineligible);
        }
        if !stores.fund_key(key) {
            return Err(RetailHold::AccountingLost);
        }
        let prior = stores.retail_spent[&key].spent;
        let first = prior.is_none();
        let grant = if prior.is_some_and(|(high, _)| c.length < high || accepted_end > c.length) {
            RetailGrant::Daily
        } else {
            RetailGrant::Process
        };
        stores.counters.retail_keys += u64::from(first);
        stores.counters.retail_attempts += 1;
        // Spend before any syscall, including interrupted/failed attempts.
        // Keep the largest physical extent: neither a relabel nor a shorter
        // object can refund the process allowance. The node is never evicted.
        let high = prior.map_or(end, |(high, _)| high.max(end));
        stores.retail_spent.get_mut(&key).expect("funded").spent = Some((high, now));
        Ok(RetailAttempt {
            source,
            grant,
            object: (c.device, c.inode, c.birth_nanos),
            next: c.length,
            end,
            old_end: accepted_end,
        })
    }
    /// Ordinary Full admission, not another Tail allowance. Overflow reads safely.
    pub(crate) fn retail_full(
        &self,
        key: &str,
        file: &File,
        accepted_end: u64,
        now: std::time::SystemTime,
    ) -> bool {
        self.paced_full_for(
            SnapshotSource::ClaudeCode,
            key,
            file,
            accepted_end,
            now,
            None,
        )
    }

    pub(crate) fn stale_full(
        &self,
        key: &str,
        file: &File,
        accepted: Option<AcceptedFloor>,
        reason: &str,
    ) -> bool {
        let Some(a) =
            accepted.filter(|a| a.revision <= effective_revision(SnapshotSource::ClaudeCode))
        else {
            return false;
        };
        let cause = match reason {
            "context" => 0,
            "restore_semantics" => 1,
            "revision_adoption_required" => 2,
            _ => return false,
        };
        self.paced_cause_full(key, file, a.end, std::time::SystemTime::now(), Some(cause))
    }

    fn paced_cause_full(
        &self,
        key: &str,
        file: &File,
        accepted_end: u64,
        now: std::time::SystemTime,
        cause: Option<usize>,
    ) -> bool {
        self.paced_full_for(
            SnapshotSource::ClaudeCode,
            key,
            file,
            accepted_end,
            now,
            cause,
        )
    }

    /// The ONE paid map, keyed by source/file across causes. A probe may count
    /// a delay, but only a starting acquisition enrols or spends an allowance.
    fn paced_admission(
        &self,
        source: SnapshotSource,
        key: &str,
        now: std::time::SystemTime,
        active_bound: bool,
        near_cap: bool,
        start: bool,
    ) -> bool {
        self.paced_with_cause(source, key, now, (active_bound, near_cap, start), None)
    }

    fn paced_with_cause(
        &self,
        source: SnapshotSource,
        key: &str,
        now: SystemTime,
        (active_bound, near_cap, start): (bool, bool, bool),
        cause: Option<usize>,
    ) -> bool {
        let Some(mut stores) = self.durable() else {
            return false;
        };
        #[cfg(test)]
        let now = stores.retail_full_now.unwrap_or(now);
        let key = full_pace_key(source, key);
        // A held replay key keeps its Full spend in never-evicted custody.
        // The pace stamp remains the overflow fallback for unfunded keys.
        let full_at = stores
            .key_debt
            .get(&key)
            .and_then(|d| d.full_spend)
            .map(|spend| spend.at)
            .or_else(|| {
                stores
                    .retail_full_at
                    .get(&key)
                    .filter(|stamp| stamp.flags & FULL_SPENT != 0)
                    .map(|stamp| stamp.at)
            });
        // Expiry releases the pace without losing structural classification.
        // A no-record publication may already have changed the index binding.
        if stores.retail_full_at.get(&key).is_some_and(|stamp| {
            now.duration_since(stamp.at)
                .map_or(true, |age| age.as_secs() > PACE_SANITY_SECS)
        }) {
            stores.counters.pace_anomaly += 1;
        }
        let delayed = !near_cap && full_at.is_some_and(|at| full_pace_delayed(at, now));
        if !delayed && !start {
            return true;
        }
        let source_slot = match source {
            SnapshotSource::ClaudeCode => 0,
            SnapshotSource::Codex => 1,
            SnapshotSource::Pi => 2,
        };
        let mut evicted = false;
        if !delayed {
            if stores.retail_full_at.len() >= 2 * store::MAX_RECORDS
                && !stores.retail_full_at.contains_key(&key)
            {
                let oldest = stores
                    .retail_full_at
                    .iter()
                    .min_by_key(|(_, stamp)| stamp.at)
                    .map(|(key, _)| *key);
                if let Some(oldest) = oldest {
                    stores.retail_full_at.remove(&oldest);
                    stores.counters.retail_full[2] += 1;
                    stores.counters.pace_evicted[source_slot] += 1;
                    evicted = true;
                }
            }
            let structural = active_bound
                || stores
                    .retail_full_at
                    .get(&key)
                    .is_some_and(|stamp| stamp.structural);
            if crate::heap_layout_bound::tree_node_bytes::<store::Digest32, FullPace>()
                .is_some_and(|n| n <= 1024)
            {
                let stamp = stores.retail_full_at.entry(key).or_insert(FullPace {
                    at: now,
                    structural,
                    flags: 0,
                    head_extent: 0,
                });
                stamp.at = now;
                stamp.structural = structural;
                stamp.flags = (stamp.flags | FULL_SPENT) & !NEAR_EXTRA;
            }
            if let Some(debt) = stores.key_debt.get_mut(&key) {
                debt.full_spend = Some(owed::FullSpend {
                    at: now,
                    near_extra: false,
                });
            }
        }
        if let Some(stamp) = stores.retail_full_at.get_mut(&key).filter(|_| active_bound) {
            stamp.structural = true;
        }
        let total = if active_bound {
            stores.counters.active_bound[source_slot][usize::from(delayed)] += 1;
            stores.counters.active_bound[source_slot][usize::from(delayed)]
        } else if cause.is_none() {
            stores.counters.retail_full[usize::from(delayed)] += 1;
            stores.counters.recovery_full[source_slot][usize::from(delayed)] += 1;
            stores.counters.recovery_full[source_slot][usize::from(delayed)]
        } else {
            0
        };
        let eviction_total = stores.counters.pace_evicted[source_slot];
        drop(stores);
        if evicted {
            // ONE emission owner: post-save durable_alarm never repeats this.
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"pace_evicted": [1, eviction_total]}),
            );
        }
        if active_bound {
            let class = if delayed {
                "active_bound_delay"
            } else {
                "degraded_no_record"
            };
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({(class): {"active_bound": [1, total]},
                    "near_cap": u64::from(near_cap)}),
            );
        } else if near_cap {
            // An annotation, not a second [delta,total] admission emission.
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"near_cap": {"retail_exhausted": 1}}),
            );
        }
        !delayed
    }

    /// Eligibility only: Codex can still defer before its Full starts.
    pub(in crate::snapshots) fn active_bound_full(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        index: &ScanIndex,
    ) -> bool {
        grown(file, index, key) && self.active_bound_pace(source, key, file, false)
    }

    pub(in crate::snapshots) fn start_active_bound_full(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
    ) -> bool {
        self.active_bound_pace(source, key, file, true)
    }

    fn active_bound_pace(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        start: bool,
    ) -> bool {
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        self.paced_admission(
            source,
            key,
            std::time::SystemTime::now(),
            true,
            near_source_cap(source, metadata.len()),
            start,
        )
    }

    /// Compatibility entry for resource leaves: the single b4/A0-h map owns
    /// stamps and eviction emission for all causes; spend custody is separate.
    fn paced_growth_full(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        accepted_end: u64,
        now: SystemTime,
        _cause: &'static str,
    ) -> bool {
        self.paced_full_for(source, key, file, accepted_end, now, None)
    }

    fn paced_full_for(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        accepted_end: u64,
        now: SystemTime,
        cause: Option<usize>,
    ) -> bool {
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if metadata.len() <= accepted_end {
            return false;
        }
        let allowed = self.paced_with_cause(
            source,
            key,
            now,
            (false, near_source_cap(source, metadata.len()), true),
            cause,
        );
        if let Some(mut stores) = self.durable() {
            if allowed {
                if near_source_cap(source, metadata.len()) {
                    stores.counters.near_cap += 1;
                }
                if cause == Some(4) {
                    stores.counters.upgrade_missing_full += 1;
                } else if cause == Some(3) {
                    if let Some(slot) = stores.slot(DurableSource::ClaudeCode).as_mut() {
                        slot.old_binding_no_match += 1;
                    }
                } else if let Some(cause) = cause {
                    stores.counters.stale_full[cause] += 1;
                }
            } else if let Some(cause) = cause {
                Counters::bump(
                    &mut stores.counters.ineligible,
                    if cause == 4 {
                        "upgrade_state_missing.paced"
                    } else if cause == 3 {
                        "old_binding_no_match.paced"
                    } else {
                        "stale_full.paced"
                    },
                );
            }
        }
        allowed
    }

    pub(super) fn durable(&self) -> Option<StoresGuard<'_>> {
        debug_assert!(!stores_held(), "Stores cannot be nested");
        let guard = self.durable.lock().ok()?;
        STORES_HELD.with(|held| held.set(true));
        Some(StoresGuard(guard))
    }
    /// Option (i) is independent of O3: only committed growth controls this
    /// paced read. It never grants migration/replacement authority.
    pub(in crate::snapshots) fn no_match_full(
        &self,
        key: &str,
        file: &File,
        accepted: Option<AcceptedFloor>,
    ) -> Option<()> {
        if let Some(mut stores) = self.durable() {
            let digest = store::key_digest(DurableSource::ClaudeCode, key);
            if let Some(c) = stores.retail_spent.get_mut(&digest) {
                c.upgrade_started = None;
            }
            stores.release_idle_custody(&digest);
        }
        let a = accepted?;
        if a.revision > effective_revision(SnapshotSource::ClaudeCode) {
            return None;
        }
        self.paced_cause_full(key, file, a.end, std::time::SystemTime::now(), Some(3))
            .then_some(())
    }

    /// Selects `source`'s store for this pass, the sibling of `index_path`,
    /// under the pass's sampled scope (`namespace`) and identity-capture
    /// mode. An index at another path (a destination or account switch) gets
    /// a fresh store; the old directory is left to its own index's GC.
    pub(in crate::snapshots) fn durable_skill_label_permission(
        &self,
        source: SnapshotSource,
        enabled: bool,
    ) {
        if let (Some(ds), Some(mut stores)) = (durable_source(source), self.durable()) {
            if let Some(slot) = stores.slot(ds).as_mut() {
                slot.skill_labels_enabled = enabled;
                if enabled {
                    slot.skill_label_purge_complete = false;
                }
            }
        }
    }
    #[inline(never)]
    pub(in crate::snapshots) fn skill_labels_enabled(&self, source: SnapshotSource) -> bool {
        durable_source(source)
            .and_then(|ds| {
                self.durable().and_then(|mut stores| {
                    stores
                        .slot(ds)
                        .as_ref()
                        .map(|slot| slot.skill_labels_enabled)
                })
            })
            .unwrap_or(false)
    }
    #[inline(never)]
    pub(in crate::snapshots) fn note_skill_label_refusal(&self, reason: Refuse) {
        if let Refuse::NonEmpty(class) = reason {
            if class.starts_with("skill_label_") {
                if let Some(mut stores) = self.durable() {
                    Counters::bump(&mut stores.counters.not_persisted, class);
                }
            }
        }
    }

    pub(crate) fn durable_begin_pass(
        &self,
        source: SnapshotSource,
        index_path: &Path,
        namespace: &Scope,
        identity_capture: bool,
    ) {
        let (Some(source), Some(mut stores)) = (durable_source(source), self.durable()) else {
            return;
        };
        let dir = store::store_dir_for_index(index_path);
        if restart_restore::enabled() {
            // P2 head budget is per pass; authorityless custody nodes are freed.
            stores.rederive_spent[source.slot()] = 0;
            // A native error may discard staging without a publication. Its empty
            // reservation carries no authority and cannot pin next-pass capacity.
            stores.key_debt.retain(|_, debt| !debt.is_empty());
            stores
                .retail_spent
                .retain(|_, custody| custody.has_authority());
        }
        let changed = stores.slot(source).as_ref().map_or(true, |slot| {
            slot.dir != dir
                || slot.namespace != *namespace
                || slot.identity_capture != identity_capture
        });
        if changed {
            for pending in &mut stores.retiring {
                if pending.is_some_and(|pending| durable_source(pending.source) == Some(source)) {
                    *pending = None;
                }
            }
        }
        let slot = stores.slot(source);
        if let Some(current) = slot.as_mut().filter(|current| current.dir == dir) {
            current.decided.clear();
            current.index_path = index_path.to_owned();
            current.namespace = namespace.clone();
            current.identity_capture = identity_capture;
            current.skill_labels_enabled = false;
        } else {
            if let Some(old) = slot
                .as_mut()
                .filter(|s| restart_restore::enabled() && s.store.has_pending())
            {
                old.store.disable("namespace_pending");
                return;
            }
            *slot = Some(Slot {
                store: DurableTailStore::new(dir.clone(), source),
                index_path: index_path.to_owned(),
                dir,
                decided: BTreeMap::new(),
                namespace: namespace.clone(),
                identity_capture,
                skill_labels_enabled: false,
                skill_label_purge_complete: false,
                held: 0,
                old_binding_no_match: 0,
                reported: [0; 22],
                d3_reported: 0,
                indexed: 0,
            });
        }
        if let Some(slot) = slot.as_mut() {
            if !restart_restore::enabled() {
                slot.store.restrict_reads_to_v1();
            }
            slot.store.begin_pass();
            // At most one resource probe per pass; the store owns its back-off.
            // Held keys retry through their own next native write.
            if restart_restore::enabled() && slot.store.resource_paused() {
                if let Some(writer) = crate::locked_state_dir::held_for(&slot.dir) {
                    let index_len = std::fs::metadata(index_path).map_or(0, |m| m.len());
                    slot.store.check_resources(writer, index_len);
                }
            }
        }
    }

    pub(crate) fn durable_hold(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        index: &ScanIndex,
        recovered_audit_due: &mut Option<u64>,
    ) -> Option<store::Refusal> {
        self.durable_guard(snapshot_source, key, false, index, recovered_audit_due)
            .or_else(|| {
                // Downgrade exception: a newer accepted body revision is held, never re-read.
                (restart_restore::enabled()
                    && snapshot_source == SnapshotSource::ClaudeCode
                    && index.files.get(key).is_some_and(|e| {
                        e.effective_upload_body_witness_revision
                            > effective_revision(snapshot_source)
                    }))
                .then_some(store::Refusal::BehindAccepted)
            })
    }

    fn durable_guard(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        restore_recheck: bool,
        index: &ScanIndex,
        recovered_audit_due: &mut Option<u64>,
    ) -> Option<store::Refusal> {
        let ram = !restore_recheck && self.retained().is_ok_and(|ram| ram.peek(key).is_some());
        let source = durable_source(snapshot_source)?;
        let mut stores = self.durable()?;
        let slot = stores.slot(source).as_mut()?;
        let live_context = store::context_digest(
            &slot.namespace.0,
            index.active_upload_context_fingerprint.as_deref(),
        );
        let held = match slot.store.guard_with_carrier(
            &store::key_digest(source, key),
            index.files.contains_key(key),
            &live_context,
        ) {
            Ok(Some(due)) => {
                Counters::bump(&mut stores.counters.ineligible, "audit_carrier");
                *recovered_audit_due = Some(due.min(super::now_seconds()));
                return None; // Native completion alone may discharge this debt.
            }
            Ok(None) => None,
            Err(reason) => Some(reason),
        };
        if held == Some(store::Refusal::Corrupt) && ram {
            Counters::bump(
                &mut stores.counters.not_persisted,
                "known_corrupt_memory_only",
            );
            return None;
        }
        held
    }

    /// `audit_carrier` (recovered miss) or `audit_carrier_staged_unverified`.
    pub(crate) fn durable_note_carrier(&self, class: &'static str) {
        if let Some(mut stores) = self.durable() {
            Counters::bump(&mut stores.counters.ineligible, class);
        }
    }

    /// A grouped member's `durable_full_hold` at job start, also taking its
    /// once-clamped live-context missing-carrier deadline (Addendum 6). The
    /// group settlement counts it once per member that publishes.
    #[cfg(test)]
    pub(crate) fn durable_member_hold(
        &self,
        source: SnapshotSource,
        key: &str,
        index: &ScanIndex,
        recovered_audit_due: &mut Option<u64>,
    ) -> Result<Option<store::Refusal>, store::ActiveOverBudget> {
        self.durable_funded_guard(source, key, |cache| {
            cache.durable_member_hold_active(source, key, true, index, recovered_audit_due)
        })
    }

    pub(in crate::snapshots) fn durable_member_hold_active(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        start: bool,
        index: &ScanIndex,
        recovered_audit_due: &mut Option<u64>,
    ) -> Option<store::Refusal> {
        let source = durable_source(snapshot_source)?;
        let mut stores = self.durable()?;
        let slot = stores.slot(source).as_mut()?;
        let live_context = store::context_digest(
            &slot.namespace.0,
            index.active_upload_context_fingerprint.as_deref(),
        );
        match slot.store.full_guard(
            &store::key_digest(source, key),
            start,
            index.files.contains_key(key),
            &live_context,
        ) {
            Ok(due) => {
                *recovered_audit_due = due.map(|due| due.min(super::now_seconds()));
                None
            }
            Err(reason) => Some(reason),
        }
    }

    /// R1: an entry-less file whose parked paged job captured no deadline
    /// takes the same live-context, once-clamped debt at settlement, read
    /// only (`carrier_debt`): no hold, T14, breaker or RAM side effect.
    pub(crate) fn durable_carrier_reprobe(
        &self,
        source: SnapshotSource,
        key: &str,
        index: &ScanIndex,
    ) -> Result<Option<u64>, store::ActiveOverBudget> {
        if !restart_restore::enabled() {
            return Ok(self.durable_carrier_reprobe_active(source, key, index));
        }
        if !self.durable_classifier_enabled(source)? {
            return Ok(None);
        }
        #[cfg(test)]
        BEFORE_CARRIER_PROBE.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook();
            }
        });
        // Settlement stays read-only: no pending reconciliation, T14 grant,
        // rebuild count or Full-start effect is imported to obtain credit.
        self.durable_funded_probe(source, |cache| {
            cache.durable_carrier_reprobe_active(source, key, index)
        })
    }

    fn durable_carrier_reprobe_active(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        index: &ScanIndex,
    ) -> Option<u64> {
        let source = durable_source(snapshot_source)?;
        let mut stores = self.durable()?;
        let slot = stores.slot(source).as_mut()?;
        let live_context = store::context_digest(
            &slot.namespace.0,
            index.active_upload_context_fingerprint.as_deref(),
        );
        let due = slot
            .store
            .carrier_debt(&store::key_digest(source, key), &live_context)?;
        Some(due.min(super::now_seconds()))
    }

    pub(in crate::snapshots) fn reconcile_pending_key(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
    ) -> Option<store::Refusal> {
        let source = durable_source(snapshot_source)?;
        let digest = store::key_digest(source, key);
        {
            let mut stores = self.durable()?;
            let slot = stores.slot(source).as_mut()?;
            if slot.store.disabled().is_some() || !slot.store.receipt_pending(&digest) {
                return None;
            }
        }
        let store::LeaseWait::Granted(lease) = self.acquire_active(
            snapshot_source,
            (4 * store::RECORD_BYTES + WRITE_PASS_BYTES) as u64,
        ) else {
            // Recheck disabled/debt after the wait; never fall into classifier I/O
            // without funding if another worker reconciled or disabled the slot.
            return self.durable().and_then(|mut stores| {
                let slot = stores.slot(source).as_ref()?;
                (slot.store.disabled().is_none() && slot.store.receipt_pending(&digest))
                    .then_some(store::Refusal::ReceiptPending)
            });
        };
        let result = self.hold_active(snapshot_source, key);
        lease.release();
        result
    }
    fn hold_active(&self, snapshot_source: SnapshotSource, key: &str) -> Option<store::Refusal> {
        let source = durable_source(snapshot_source)?;
        let key = store::key_digest(source, key);
        let mut stores = self.durable()?;
        let slot = stores.slot(source).as_mut()?;
        if let Some(writer) = crate::locked_state_dir::held_for(&slot.dir) {
            if let Ok(store::ReconcileOutcome::Receipted(proof)) =
                slot.store.reconcile_pending(writer, &key)
            {
                if slot.store.retain_receipt(proof).is_err() {
                    return Some(store::Refusal::ReceiptPending);
                }
            }
        }
        // Only a still-pending receipt holds here; the caller's guard classifies
        // a reconciled key, and a store disabled by reconcile publishes (D-DISABLED).
        (slot.store.disabled().is_none() && slot.store.receipt_pending(&key))
            .then_some(store::Refusal::ReceiptPending)
    }

    /// The common guard under the active lease: a pending receipt reconciles
    /// first, and classification also allocates an envelope, so `guard` runs
    /// funded outside Stores.
    pub(in crate::snapshots) fn durable_funded_guard(
        &self,
        source: SnapshotSource,
        key: &str,
        guard: impl FnOnce(&Self) -> Option<store::Refusal>,
    ) -> Result<Option<store::Refusal>, store::ActiveOverBudget> {
        if !restart_restore::enabled() {
            return Ok(guard(self));
        }
        if !self.durable_classifier_enabled(source)? {
            return Ok(None); // D-DISABLED/absent: no input allocation is needed.
        }
        if let Some(reason) = self.reconcile_pending_key(source, key) {
            return Ok(Some(reason));
        }
        self.durable_funded_probe(source, guard)
    }

    fn durable_classifier_enabled(
        &self,
        source: SnapshotSource,
    ) -> Result<bool, store::ActiveOverBudget> {
        let Some(ds) = durable_source(source) else {
            return Ok(false);
        };
        let Some(mut stores) = self.durable() else {
            return Err(store::ActiveOverBudget);
        };
        Ok(stores
            .slot(ds)
            .as_ref()
            .is_some_and(|slot| slot.store.disabled().is_none()))
    }

    pub(in crate::snapshots) fn durable_funded_member_batch(
        &self,
        source: SnapshotSource,
        members: impl FnOnce(&Self) -> bool,
    ) -> Result<bool, store::ActiveOverBudget> {
        if !restart_restore::enabled() {
            return Ok(members(self));
        }
        if !self.durable_classifier_enabled(source)? {
            return Ok(false); // No classifier/no T14 grant; native group proceeds.
        }
        self.durable_funded_probe(source, members)
    }

    fn durable_funded_probe<T>(
        &self,
        source: SnapshotSource,
        probe: impl FnOnce(&Self) -> T,
    ) -> Result<T, store::ActiveOverBudget> {
        if !restart_restore::enabled() {
            return Ok(probe(self));
        }
        // Reserve BEFORE taking Stores; mutex serialization cannot fund a
        // classifier envelope while another worker decodes outside Stores.
        let store::LeaseWait::Granted(lease) =
            self.acquire_active(source, store::RESTORE_INPUT_BYTES)
        else {
            return Err(store::ActiveOverBudget);
        };
        let result = probe(self);
        lease.release();
        Ok(result)
    }

    pub(crate) fn durable_full_hold(
        &self,
        source: SnapshotSource,
        key: &str,
        start: bool,
    ) -> Result<Option<store::Refusal>, store::ActiveOverBudget> {
        self.durable_funded_guard(source, key, |cache| {
            cache.durable_full_hold_active(source, key, start)
        })
    }

    pub(in crate::snapshots) fn durable_full_hold_active(
        &self,
        source: SnapshotSource,
        key: &str,
        start: bool,
    ) -> Option<store::Refusal> {
        let source = durable_source(source)?;
        let mut stores = self.durable()?;
        stores
            .slot(source)
            .as_mut()?
            .store
            .full_hold(&store::key_digest(source, key), start)
    }

    fn missing_reduction_cause(
        &self,
        source: SnapshotSource,
        key: &str,
    ) -> Result<Option<&'static str>, store::ActiveOverBudget> {
        let Some(ds) = durable_source(source) else {
            return Ok(None);
        };
        self.durable_funded_probe(source, |cache| {
            cache.durable().and_then(|mut stores| {
                stores
                    .slot(ds)
                    .as_mut()?
                    .store
                    .missing_cause(&store::key_digest(ds, key))
            })
        })
    }

    /// Preserve discovery of unread retired growth even outside the activity
    /// window. Reuse the missing classifier; quiet files do not probe the store.
    pub(in crate::snapshots) fn missing_reduction_growth(
        &self,
        source: SnapshotSource,
        key: &str,
        files: &BTreeMap<String, ScanIndexEntry>,
        length: u64,
    ) -> bool {
        files
            .get(key)
            .is_some_and(|entry| length > entry.size_bytes)
            && self
                .missing_reduction_cause(source, key)
                .is_ok_and(|cause| cause == Some("repin"))
    }

    pub(in crate::snapshots) fn upgrade_full_allowed(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        index: &ScanIndex,
        page: &mut HistoryPage,
    ) -> bool {
        self.upgrade_full_admission(source, key, file, index, page, true)
    }

    /// A group reads as one unit. Reserve its existing history page and probe
    /// every member's existing pace before spending any member's allowance.
    pub(in crate::snapshots) fn upgrade_group_full_allowed(
        &self,
        source: SnapshotSource,
        members: &[CandidateFile],
        index: &ScanIndex,
        page: &mut HistoryPage,
    ) -> bool {
        let files: Option<Vec<_>> = members
            .iter()
            .filter(|member| {
                index
                    .files
                    .get(&local_index_key(&member.path))
                    .is_some_and(|entry| member.size_bytes > entry.size_bytes)
            })
            .map(|member| {
                Some((
                    local_index_key(&member.path),
                    File::open(&member.path).ok()?,
                ))
            })
            .collect();
        let Some(files) = files else {
            return false;
        };
        let mut reserved = page.clone();
        if !files.iter().all(|(key, file)| {
            self.upgrade_full_admission(source, key, file, index, &mut reserved, false)
        }) {
            return false;
        }
        if !files.iter().all(|(key, file)| {
            self.upgrade_full_admission(source, key, file, index, &mut reserved, true)
        }) {
            return false;
        }
        *page = reserved;
        true
    }

    /// Missing reductions share one per-key pace. Retired-pin rebuilds also
    /// reserve the existing history page before the first native input.
    fn upgrade_full_admission(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        index: &ScanIndex,
        page: &mut HistoryPage,
        start: bool,
    ) -> bool {
        let Some(entry) = index.files.get(key).filter(|e| {
            !e.source_file_fingerprint.is_empty() || e.last_upload_body_witness.is_some()
        }) else {
            return true;
        };
        let Some(_) = durable_source(source) else {
            return true;
        };
        match self.durable_classifier_enabled(source) {
            Ok(false) => return true, // Disabled/absent stores preserve native Full behavior.
            Err(_) => return false,
            Ok(true) => {}
        }
        let cause = match self.missing_reduction_cause(source, key) {
            Ok(cause) => cause,
            Err(_) => return false,
        };
        let Some(cause) = cause else {
            return true;
        };
        if cause != "repin" && (source != SnapshotSource::ClaudeCode || !restart_restore::enabled())
        {
            return true;
        }
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if metadata.len() <= entry.size_bytes {
            return cause != "repin"; // Quiet retired records consume no source input.
        }
        if cause == "repin" {
            if metadata.len() > max_jsonl_file_bytes(SnapshotSource::ClaudeCode)
                || !page.reserve(key, metadata.len())
            {
                return false;
            }
            if !self
                .durable()
                .is_some_and(|mut stores| stores.fund_debt(full_pace_key(source, key)).is_some())
            {
                return false;
            }
            if !self.paced_with_cause(
                source,
                key,
                SystemTime::now(),
                (false, false, start),
                Some(4),
            ) {
                return false;
            }
            if !start {
                return true;
            }
            if let Some(mut stores) = self.durable() {
                stores.counters.upgrade_missing_full += 1;
                Counters::bump(&mut stores.counters.resource_full, "repin");
            }
            return true;
        }
        if !start {
            return self.paced_with_cause(
                source,
                key,
                SystemTime::now(),
                (false, near_source_cap(source, metadata.len()), false),
                Some(4),
            );
        }
        self.paced_cause_full(key, file, entry.size_bytes, SystemTime::now(), Some(4))
    }

    pub(in crate::snapshots) fn migration_start(
        &self,
        key: &str,
        file: &File,
        index: &mut ScanIndex,
        accepted: Option<AcceptedFloor>,
    ) -> Result<MigrationStart, &'static str> {
        let result = (|| {
            let a = accepted.ok_or("o3.accepted_missing")?;
            let m = file.metadata().map_err(|_| "o3.metadata")?;
            if a.revision > effective_revision(SnapshotSource::ClaudeCode)
                || index.active_effective_upload_body_witness_revision
                    > effective_revision(SnapshotSource::ClaudeCode)
                || index.effective_upload_body_witness_revision_requires_adoption(key)
            {
                return Err("o3.revision");
            }
            if m.len() <= a.end {
                return Err("o3.idle");
            }
            if self
                .retained()
                .map_err(|_| "o3.custody")?
                .peek(key)
                .is_some()
            {
                return Err("o3.ram");
            }
            let digest = store::key_digest(DurableSource::ClaudeCode, key);
            let mut lease = match self.acquire_active(SnapshotSource::ClaudeCode, 0) {
                store::LeaseWait::Granted(lease) => lease,
                _ => return Err("o3.input_pending"),
            };
            let mut stores = self.durable().ok_or("o3.custody")?;
            let (record, current) = stores.slots[DurableSource::ClaudeCode.slot()]
                .as_mut()
                .ok_or("o3.store")?
                .migration_record(key, index, &mut lease)?;
            let r = &record.record.certificate;
            if record.index_generation > a.generation {
                return Err("o3.generation");
            }
            if !migration_object(r, &m) {
                return Err("o3.object");
            }
            if m.len() <= r.length {
                return Err("o3.certificate_extent");
            }
            if !stores.fund_key(digest) {
                return Err("o3.custody");
            }
            let stores = &mut *stores;
            let slot = stores.slots[DurableSource::ClaudeCode.slot()]
                .as_mut()
                .ok_or("o3.store")?;
            let custody = stores.retail_spent.get_mut(&digest).ok_or("o3.custody")?;
            if custody.original.is_none() {
                custody.original = slot.store.migration_witness(&record, &current, m.len());
            }
            if !custody
                .original
                .as_ref()
                .is_some_and(|p| slot.store.migration_matches(p, &record, &current))
            {
                return Err("o3.survivor");
            }
            let floor = custody
                .original
                .as_ref()
                .and_then(|p| p.migration_floor())
                .ok_or("o3.survivor")?;
            if m.len() < floor {
                return Err("o3.floor");
            }
            let claimed = index.o3_replay.upgrade_missing(key, true);
            if !claimed {
                if index.o3_replay.needs_save() {
                    stores.counters.migration[1] += 1;
                    return Ok(MigrationStart::AwaitSave);
                }
                // A consumed/crashed grant cannot be refunded. Rule 6 still
                // requires progress: use the existing paced resource read.
                return Err("o3.spent");
            }
            stores
                .retail_spent
                .get_mut(&digest)
                .expect("funded")
                .upgrade_started = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )));

            stores.counters.migration[2] += 1;
            Ok(MigrationStart::Full(floor))
        })();
        // Only genuine idle/correctness barriers can suppress option (i).
        if let Err(reason) = result {
            if !matches!(
                reason,
                "o3.idle"
                    | "o3.revision"
                    | "o3.replay"
                    | "o3.context"
                    | "o3.protected_record"
                    | "o3.input_pending"
            ) && self.no_match_full(key, file, accepted).is_some()
            {
                return Ok(MigrationStart::Fallback);
            }
        }
        if let Err(reason) = result {
            if let Some(mut stores) = self.durable() {
                stores.counters.migration[0] += 1;
                Counters::bump(&mut stores.counters.ineligible, reason);
            }
        }
        result
    }

    pub(in crate::snapshots) fn upgrade_read(
        &self,
        key: &str,
        file: &File,
    ) -> Result<Option<UpgradeRead>, RetailHold> {
        self.upgrade_reader(key, file, None)
    }
    pub(in crate::snapshots) fn migration_read(
        &self,
        key: &str,
        file: &File,
        index: &ScanIndex,
    ) -> Result<Option<UpgradeRead>, RetailHold> {
        if self.durable().is_some_and(|mut s| {
            s.slots[DurableSource::ClaudeCode.slot()]
                .as_mut()
                .is_some_and(|c| {
                    c.store
                        .absent(&store::key_digest(DurableSource::ClaudeCode, key))
                })
        }) {
            self.upgrade_read(key, file)
        } else {
            self.upgrade_reader(key, file, Some(index))
        }
    }
    fn upgrade_reader(
        &self,
        name: &str,
        file: &File,
        index: Option<&ScanIndex>,
    ) -> Result<Option<UpgradeRead>, RetailHold> {
        let key = name;
        let key = store::key_digest(DurableSource::ClaudeCode, key);
        let needs_input = index.is_some()
            && self.durable().is_some_and(|s| {
                s.retail_spent.get(&key).is_some_and(|c| {
                    c.upgrade_started.is_some()
                        && c.original.as_ref().is_some_and(|p| p.is_migration())
                })
            });
        let mut input_lease = if needs_input {
            match self.acquire_active(SnapshotSource::ClaudeCode, 0) {
                store::LeaseWait::Granted(lease) => Some(lease),
                _ => return Err(RetailHold::AccountingLost),
            }
        } else {
            None
        };
        let mut stores = self.durable().ok_or(RetailHold::AccountingLost)?;
        if !stores.slots[DurableSource::ClaudeCode.slot()]
            .as_mut()
            .is_some_and(|s| s.store.absent(&key))
        {
            if !stores
                .retail_spent
                .get(&key)
                .and_then(|c| c.original.as_ref())
                .is_some_and(|p| p.is_migration())
            {
                return Ok(None);
            }
            let Some(index) = index else {
                return Ok(None);
            };
            if !stores
                .retail_spent
                .get(&key)
                .is_some_and(|c| c.upgrade_started.is_some())
            {
                return Ok(None);
            }
            let stores = &mut *stores;
            let slot = stores.slots[DurableSource::ClaudeCode.slot()]
                .as_mut()
                .ok_or(RetailHold::Ineligible)?;
            let (record, current) = slot
                .migration_record(
                    name,
                    index,
                    input_lease.as_mut().ok_or(RetailHold::AccountingLost)?,
                )
                .map_err(|_| RetailHold::Ineligible)?;
            if !migration_object(
                &record.record.certificate,
                &file.metadata().map_err(|_| RetailHold::Ineligible)?,
            ) || !stores
                .retail_spent
                .get(&key)
                .and_then(|c| c.original.as_ref())
                .is_some_and(|p| slot.store.migration_matches(p, &record, &current))
            {
                return Err(RetailHold::Ineligible);
            }
        }
        let funded = stores.fund_key(key);
        let metadata = file.metadata();
        #[cfg(test)]
        let metadata = if tests::b1_metadata_fails() {
            Err(std::io::Error::other("injected observer fstat failure"))
        } else {
            metadata
        };
        let m = metadata.map_err(|_| {
            Counters::bump(&mut stores.counters.ineligible, "metadata");
            RetailHold::Ineligible
        })?;
        let started = if funded {
            Some(
                stores
                    .retail_spent
                    .get_mut(&key)
                    .expect("funded")
                    .upgrade_started
                    .get_or_insert_with(|| {
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
                    })
                    .clone(),
            )
        } else {
            None
        };
        Ok(Some(UpgradeRead {
            object: (m.dev(), m.ino(), birth_unix_nanos(&m)),
            started,
            local_started: false,
            total: stores.upgrade_reads.clone(),
        }))
    }

    /// Q11 capacity/exhaustion is disclosed stale custody, never an integrity failure.
    pub(in crate::snapshots) fn durable_retail_hold(
        &self,
        source: SnapshotSource,
        reason: RetailHold,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
    ) {
        let class = match reason {
            RetailHold::Exhausted => "retail_hold.exhausted",
            RetailHold::AccountingLost => "retail_hold.accounting_lost",
            RetailHold::Ineligible => "retail_hold.ineligible",
        };
        self.durable_custody_hold(source, class, index, candidate);
    }
    pub(in crate::snapshots) fn durable_custody_hold(
        &self,
        source: SnapshotSource,
        class: &'static str,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
    ) {
        let kept = source == SnapshotSource::ClaudeCode
            && claude_request_census::retain_held(index, candidate);
        if let Some(mut stores) = self.durable() {
            Counters::bump(&mut stores.counters.ineligible, class);
            stores.counters.held_census[usize::from(!kept)] += 1;
            if let Some(ds) = durable_source(source) {
                if let Some(slot) = stores.slot(ds).as_mut() {
                    slot.held += 1;
                }
            }
        }
    }

    pub(in crate::snapshots) fn durable_stale_hold(
        &self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
    ) {
        self.durable_custody_hold(source, "stale_hold", index, candidate);
    }

    pub(in crate::snapshots) fn migration_failure(
        &self,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
    ) -> bool {
        if !restart_restore::enabled() {
            return false;
        }
        let key = local_index_key(&candidate.path);
        let hold = self.durable().is_some_and(|mut s| {
            s.retail_spent
                .get_mut(&store::key_digest(DurableSource::ClaudeCode, &key))
                .is_some_and(|c| {
                    if c.original.as_ref().is_some_and(|p| p.is_migration()) {
                        c.upgrade_started = None;
                        true
                    } else {
                        false
                    }
                })
        });
        if hold {
            self.stale("o3.native_failure");
            self.durable_stale_hold(SnapshotSource::ClaudeCode, index, candidate);
        }
        hold
    }

    pub(in crate::snapshots) fn durable_hold_exit(
        &self,
        source: SnapshotSource,
        reason: store::Refusal,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
        census: &mut ScanCensus,
    ) {
        if reason == store::Refusal::BehindAccepted {
            if let Some(mut stores) = self.durable() {
                stores.counters.durable_held[reason as usize] += 1;
            }
            self.durable_stale_hold(source, index, candidate);
            return;
        }
        let kept = source == SnapshotSource::ClaudeCode
            && claude_request_census::retain_held(index, candidate);
        if reason == store::Refusal::Corrupt {
            if let Some(mut stores) = self.durable() {
                Counters::bump(&mut stores.counters.not_persisted, "known_corrupt_held");
            }
            return;
        }
        if let Some(mut stores) = self.durable() {
            stores.counters.durable_held[reason as usize] += 1;
            if source == SnapshotSource::ClaudeCode {
                stores.counters.held_census[usize::from(!kept)] += 1;
            }
            if let Some(durable) = durable_source(source) {
                if let Some(slot) = stores.slot(durable).as_mut() {
                    slot.held += 1;
                }
            }
        }
        if reason != store::Refusal::ReceiptPending {
            census.record_unreadable(UnreadableCause::Reduction, 1);
        }
    }

    fn stale(&self, reason: &'static str) -> RestoreOutcome {
        if let Some(mut stores) = self.durable() {
            Counters::bump(&mut stores.counters.ineligible, reason);
        }
        if reason == "behind_accepted.legacy" {
            RestoreOutcome::Held(store::Refusal::BehindAccepted)
        } else {
            RestoreOutcome::Stale(reason)
        }
    }

    /// Restores `key` from the durable store into the RAM cache and takes it,
    /// or a typed pending/integrity/missing outcome. `held` is
    /// the parser's opened FD for `path`, not yet read; bounded positional
    /// content reads preserve its offset, and the read plan repositions it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn durable_restore(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        index: &ScanIndex,
        interpretation: &Interpretation<'_>,
    ) -> RestoreOutcome {
        if !restart_restore::enabled() {
            return self.m1_restore(
                snapshot_source,
                key,
                path,
                scope,
                held,
                index,
                interpretation,
            );
        }
        let floor_behind = interpretation
            .accepted
            .is_some_and(|a| held.metadata().map_or(true, |m| a.behind(m.len())));
        if snapshot_source == SnapshotSource::Codex
            && refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)
                .is_err()
        {
            return RestoreOutcome::Miss(MissClass::Failure(Failure::NotRederived(
                Refuse::NotRederivable("compressed"),
            )));
        }
        // Class discovered by an earlier native finish is already durable
        // in the existing protected-history carrier. begin_pass clears the
        // per-pass decisions, so that carrier must also refuse old singleton
        // bytes before any store read, including when GC was deferred.
        let committed_excluded = snapshot_source == SnapshotSource::Codex
            && index
                .files
                .get(key)
                .is_some_and(ScanIndexEntry::codex_history_is_protected);
        if committed_excluded {
            self.durable_exclude_native_class(key);
        }
        if snapshot_source == SnapshotSource::Codex
            && self.durable().is_some_and(|mut stores| {
                let excluded = committed_excluded
                    || stores
                        .slot(DurableSource::Codex)
                        .as_ref()
                        .is_some_and(|slot| {
                            matches!(slot.decided.get(key), Some(ScopeDecision::Excluded))
                        });
                if excluded {
                    Counters::bump(
                        &mut stores.counters.ineligible,
                        "wa.class_changed.restore_refused",
                    );
                }
                excluded
            })
        {
            return RestoreOutcome::Miss(MissClass::ExcludedClass);
        }
        if let Some(reason) = self.reconcile_pending_key(snapshot_source, key) {
            return RestoreOutcome::Held(reason);
        }
        #[cfg(test)]
        tests::before_cold_transfer();
        let mut lease = match self.acquire_prepared_transfer(snapshot_source) {
            store::LeaseWait::Granted(lease) => lease,
            store::LeaseWait::Busy => {
                return self.restore_resource_pending(
                    snapshot_source,
                    "active_wait",
                    key,
                    held,
                    index,
                )
            }
            store::LeaseWait::OverBudget => {
                return if floor_behind {
                    RestoreOutcome::FloorHeld
                } else {
                    self.restore_active_bound(snapshot_source, key, held, index)
                };
            }
        };
        // Incoming key, admission scratch/stored key and dirty-candidate key.
        // The initial transfer reserve separately covers one <=8MiB victim key.
        if key
            .len()
            .checked_mul(4)
            .and_then(|n| u64::try_from(n).ok())
            .map_or(true, |bytes| lease.charge(bytes).is_err())
        {
            lease.release();
            if floor_behind {
                return RestoreOutcome::FloorHeld;
            }
            return self.restore_resource_pending(snapshot_source, "cache_key", key, held, index);
        }
        let structural = self.durable().is_some_and(|stores| {
            stores
                .retail_full_at
                .get(&full_pace_key(snapshot_source, key))
                .is_some_and(|stamp| stamp.structural)
        });
        if structural
            && grown(held, index, key)
            && !index.effective_upload_body_witness_revision_requires_adoption(key)
        {
            // Only unread growth consumes a structural memo. Real same-size
            // corrections/shrink and approved replay keep ordinary admission.
            // Classify the current survivor under funding before applying a
            // RAM memo. Unknown/newer/receipt holds still outrank the grant.
            if lease.charge(store::RESTORE_INPUT_BYTES).is_err() {
                lease.release();
                return RestoreOutcome::Pending;
            }
            let hold = self.durable_full_hold_active(snapshot_source, key, false);
            lease.release();
            return hold.map_or_else(
                || self.restore_active_bound(snapshot_source, key, held, index),
                RestoreOutcome::Held,
            );
        }
        let result = self.restore_known(
            snapshot_source,
            key,
            path,
            scope,
            held,
            index,
            interpretation,
            &mut lease,
        );
        // The common guard held U/T14 before acquisition; this sees class changes since.
        let outcome = match result {
            Ok(Ok(completed)) => {
                // Admission and take share one retained lock and this paid owner.
                match self.insert_with_custody(key.to_string(), completed, 0, false, true, true) {
                    Ok(Some(taken)) => {
                        if let Some(mut stores) = self.durable() {
                            stores.counters.restored += 1;
                            #[cfg(test)]
                            super::transition_fixture::reach(
                                super::transition_fixture::CrashPoint::Restore,
                            );
                            stores.counters.durable_restore_after_selection_clear += u64::from(
                                snapshot_source == SnapshotSource::ClaudeCode
                                    && index
                                        .files
                                        .get(key)
                                        .is_some_and(|e| e.source_file_fingerprint.is_empty()),
                            );
                        }
                        RestoreOutcome::Restored(Box::new(taken), lease)
                    }
                    refused => {
                        drop(refused); // Original graph/temporary custody before its credit.
                        lease.release();
                        self.restore_resource_pending(
                            snapshot_source,
                            "cache_transit",
                            key,
                            held,
                            index,
                        )
                    }
                }
            }
            Ok(Err(phase)) => {
                lease.release();
                if floor_behind {
                    return RestoreOutcome::FloorHeld;
                }
                if matches!(phase, "input" | "certificate_scope") {
                    self.restore_active_bound(snapshot_source, key, held, index)
                } else {
                    self.restore_resource_pending(snapshot_source, phase, key, held, index)
                }
            }
            Err(RestoreOutcome::Miss(MissClass::AcceptedFloor)) => {
                lease.release();
                RestoreOutcome::FloorHeld
            }
            Err(RestoreOutcome::Miss(class @ MissClass::RealEdit(_))) => {
                lease.release();
                RestoreOutcome::Miss(class)
            }
            Err(RestoreOutcome::Miss(class @ MissClass::LayoutUnavailable(_))) => {
                // Absence for this already-selected acquisition, not a new
                // Full permission. Native preparation keeps its usual S2 checks.
                lease.release();
                RestoreOutcome::Miss(class)
            }
            Err(_) if floor_behind => {
                lease.release();
                RestoreOutcome::FloorHeld
            }
            Err(RestoreOutcome::Miss(class @ MissClass::AuditCarrier)) => {
                lease.release();
                RestoreOutcome::Miss(class)
            }
            Err(RestoreOutcome::Miss(class)) => {
                let result = self
                    .durable_guard(snapshot_source, key, true, index, &mut None)
                    .map_or(RestoreOutcome::Miss(class), RestoreOutcome::Held);
                lease.release();
                result
            }
            Err(outcome) => {
                lease.release();
                outcome
            }
        };
        if matches!(
            outcome,
            RestoreOutcome::Miss(MissClass::Failure(Failure::Ineligible(
                store::Ineligible::EntryChanged
            )))
        ) {
            if let Some(mut stores) = self.durable() {
                if stores.stale_predecessor.len() < STALE_PREDECESSOR_KEYS {
                    stores.stale_predecessor.insert(stale_predecessor_key(key));
                }
            }
        }
        outcome
    }

    /// Count only a completed Full after an entry_changed refusal; any
    /// completion clears this process-local diagnostic mark, never authority.
    pub(crate) fn durable_acquisition_completed(
        &self,
        key: &str,
        mode: crate::transcript_acquisition::ReadMode,
        native_bytes: u64,
    ) {
        let Some(mut stores) = self.durable() else {
            return;
        };
        if stores.stale_predecessor.remove(&stale_predecessor_key(key))
            && matches!(mode, crate::transcript_acquisition::ReadMode::Full(_))
        {
            let counts = &mut stores.counters.store_write_failed_restart_full;
            counts[0] += 1;
            counts[1] = counts[1].saturating_add(native_bytes);
        }
    }

    fn restore_active_bound(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        index: &ScanIndex,
    ) -> RestoreOutcome {
        if self.active_bound_full(source, key, file, index) {
            RestoreOutcome::Degraded
        } else {
            RestoreOutcome::Pending
        }
    }

    /// A busy lease is a bounded FIFO delay. Every other phase repeats for
    /// this record and cache state (including unsupported content obligations), so a
    /// file grown past its committed end takes the ordinary counted Full
    /// (a fresh native parse, its own funding) instead of an idle-drop hold.
    fn restore_resource_pending(
        &self,
        source: SnapshotSource,
        phase: &'static str,
        key: &str,
        held: &File,
        index: &ScanIndex,
    ) -> RestoreOutcome {
        let rederive = phase.starts_with("rederive_") || phase == "decode";
        let full = !matches!(phase, "active_wait" | "rederive_quiet" | "rederive_budget")
            && if rederive {
                self.rederive_full(
                    source,
                    key,
                    held,
                    index.files.get(key).map_or(0, |e| e.size_bytes),
                    source != SnapshotSource::Codex,
                )
            } else if source == SnapshotSource::Codex {
                grown(held, index, key)
                    && held.metadata().is_ok_and(|m| {
                        self.paced_admission(
                            source,
                            key,
                            SystemTime::now(),
                            false,
                            near_source_cap(source, m.len()),
                            false,
                        )
                    })
            } else {
                self.paced_growth_full(
                    source,
                    key,
                    held,
                    index.files.get(key).map_or(0, |entry| entry.size_bytes),
                    SystemTime::now(),
                    "resource_full_granted",
                )
            };
        if let Some(mut stores) = self.durable() {
            if full && source != SnapshotSource::Codex {
                Counters::bump(&mut stores.counters.resource_full, phase);
            } else if !full {
                stores.counters.budget_refused += 1;
                Counters::bump(&mut stores.counters.ineligible, phase);
            }
        }
        let event = if full && source == SnapshotSource::Codex {
            "restore_resource_eligible"
        } else if full {
            "restore_resource_full"
        } else {
            "restore_resource_pending"
        };
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({(event):{(phase):1}}),
        );
        if full {
            RestoreOutcome::Miss(MissClass::Resource(phase))
        } else {
            RestoreOutcome::Pending
        }
    }

    pub(in crate::snapshots) fn start_resource_full(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        accepted_end: u64,
        phase: &'static str,
    ) -> bool {
        let granted = if phase.starts_with("rederive_") || phase == "decode" {
            self.rederive_full(source, key, file, accepted_end, true)
        } else {
            self.paced_growth_full(source, key, file, accepted_end, SystemTime::now(), phase)
        };
        if !granted {
            return false;
        }
        if let Some(mut stores) = self.durable() {
            Counters::bump(&mut stores.counters.resource_full, phase);
        }
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({"restore_resource_full":{(phase):1}}),
        );
        true
    }

    /// The refused stale record's Full is counted under its own cause and paced
    /// once per file in the ONE pacing map; a delayed Full stays Pending.
    /// This is eligibility only: a cursor/page can still defer before input.
    fn stale_selection_full(
        &self,
        source: SnapshotSource,
        key: &str,
        held: &File,
    ) -> RestoreOutcome {
        let near_cap = held
            .metadata()
            .is_ok_and(|m| near_source_cap(source, m.len()));
        let granted = self.paced_with_cause(
            source,
            key,
            SystemTime::now(),
            (false, near_cap, false),
            Some(STALE_SELECTION_CAUSE),
        );
        if !granted {
            if let Some(mut stores) = self.durable() {
                Counters::bump(
                    &mut stores.counters.ineligible,
                    "selection_cleared.stale_record_full.paced",
                );
            }
        }
        if granted {
            MissClass::StaleSelection.into()
        } else {
            RestoreOutcome::Pending
        }
    }

    /// Enroll the source-fault cause only after native/page admission, at
    /// the same input boundary as the real Full selection counter.
    pub(in crate::snapshots) fn start_stale_selection_full(
        &self,
        source: SnapshotSource,
        key: &str,
        held: &File,
    ) -> bool {
        let near_cap = held
            .metadata()
            .is_ok_and(|m| near_source_cap(source, m.len()));
        let granted = self.paced_with_cause(
            source,
            key,
            SystemTime::now(),
            (false, near_cap, true),
            Some(STALE_SELECTION_CAUSE),
        );
        if let Some(mut stores) = self.durable() {
            Counters::bump(
                &mut stores.counters.ineligible,
                if granted {
                    "selection_cleared.stale_record_full"
                } else {
                    "selection_cleared.stale_record_full.paced"
                },
            );
        }
        granted
    }

    /// Missing authority preserves the predecessor and discoverability. The
    /// named existing exits are revalidation followed by writer retire_exact,
    /// or a later native replacement's exact receipt; no absence is inferred.
    fn hold_rederive_retirement(
        &self,
        source: DurableSource,
        key: store::Digest32,
        edge: RetirementEdge,
        exit: &'static str,
    ) {
        if let Some(mut stores) = self.durable() {
            Counters::bump(&mut stores.counters.retire_exact_held, edge.label());
            if let Some(debt) = stores.fund_debt(key) {
                debt.rederive_hold = Some(source);
            } else {
                stores.owed_overflow[source.slot()] = true;
            }
        }
        self.record_first_retire_result(source, key, true);
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.properties().snapshot.api_slug(),
            &serde_json::json!({"retire_exact_held":{(edge.label()):1}, "retire_exact_held_exit":exit}),
        );
    }

    fn record_first_retire_result(&self, source: DurableSource, key: store::Digest32, held: bool) {
        let Some(mut stores) = self.durable() else {
            return;
        };
        if stores.counters.retire_exact_first_attempt_tracking_closed {
            return;
        }
        if stores.fund_debt(key).is_none() {
            stores.counters.retire_exact_first_attempt_tracking_closed = true;
            return;
        }
        if stores.counters.retire_exact_first_attempt_tracking_closed {
            return;
        }
        let debt = stores.key_debt.get_mut(&key).expect("funded");
        if debt.first_retire_held.is_none() {
            debt.first_retire_held = Some(held);
            stores.counters.retire_exact_held_first_attempt
                [diagnostic_source_slot(source.properties().snapshot)] += u64::from(held);
        }
    }

    fn retire_or_hold(
        &self,
        original_matches: bool,
        source: DurableSource,
        record: &store::DurableRecord,
        expected: &Expected,
        edge: RetirementEdge,
    ) {
        if original_matches {
            self.queue_rederive_retirement(source, record, expected, edge);
        } else if let Some(mut stores) = self.durable() {
            Counters::bump(&mut stores.counters.ineligible, "rederive_retire_unproven");
            drop(stores);
            self.hold_rederive_retirement(
                source,
                record.record.binding.key,
                edge,
                "native_replacement_receipt",
            );
        }
    }

    /// Per-edge original binding must already be eligible. Failure to retain
    /// authority holds safely; it never manufactures a deletion witness.
    fn queue_rederive_retirement(
        &self,
        source: DurableSource,
        record: &store::DurableRecord,
        expected: &Expected,
        edge: RetirementEdge,
    ) {
        #[cfg(test)]
        super::test_hooks::fire(super::test_hooks::Point::BeforeRetireWitness);
        // Early metadata/object edit edges can fence-drop before scoped
        // content replay. They share the same first-attempt observation.
        self.record_first_rederive_result(
            source.properties().snapshot,
            record.record.binding.key,
            true,
        );
        let Some(mut stores) = self.durable() else {
            return;
        };
        let key = record.record.binding.key;
        let proof = stores.slot(source).as_mut().and_then(|slot| {
            slot.store.authorize(record, expected);
            slot.store.mutation_witness(record, expected)
        });
        let Some(proof) = proof else {
            Counters::bump(&mut stores.counters.ineligible, "rederive_retire_unproven");
            drop(stores);
            self.hold_rederive_retirement(source, key, edge, "revalidated_retire_exact");
            return;
        };
        if !stores.fund_key(key) || stores.fund_debt(key).is_none() {
            Counters::bump(&mut stores.counters.ineligible, "rederive_retire_unfunded");
            drop(stores);
            self.hold_rederive_retirement(source, key, edge, "native_replacement_receipt");
            return;
        }
        let custody = stores.retail_spent.get_mut(&key).expect("funded");
        // Never overwrite an outstanding migration/original predecessor.
        if custody.original.is_none() {
            custody.original = Some(proof);
        } else if !custody
            .original
            .as_ref()
            .is_some_and(|p| p.same_predecessor(&proof))
        {
            drop(stores);
            self.retire_or_hold(false, source, record, expected, edge);
            return;
        }
        let debt = stores.fund_debt(key).expect("funded");
        debt.retire_source = Some(source);
        debt.rederive_hold = Some(source);
        drop(stores);
        self.record_first_retire_result(source, key, false);
    }

    /// Head-once is an extent discriminator, never predecessor authority.
    /// Existing debt custody owns discovery and the one overflow retry.
    fn rederive_gate(
        &self,
        source: SnapshotSource,
        digest: store::Digest32,
        extent: u64,
        input: bool,
        deferred: bool,
    ) -> Result<(), Failure> {
        let Some(ds) = durable_source(source) else {
            return Ok(());
        };
        let mut stores = self
            .durable()
            .ok_or(Failure::Resource("stores_unavailable"))?;
        if stores
            .key_debt
            .get(&digest)
            .is_some_and(|debt| debt.retire_source == Some(ds))
        {
            return Err(Failure::Certificate(CertificateRefusal::Changed(
                FullReason::HeadChanged,
            )));
        }
        let now = SystemTime::now();
        #[cfg(test)]
        let now = stores.retail_full_now.unwrap_or(now);
        let extent =
            u32::try_from(extent).map_err(|_| Failure::Resource("rederive_unsupported"))?;
        let absent = !stores.retail_full_at.contains_key(&digest);
        if absent && stores.retail_full_at.len() >= 2 * store::MAX_RECORDS {
            if let Some(oldest) = stores
                .retail_full_at
                .iter()
                .min_by_key(|(_, p)| p.at)
                .map(|(k, _)| *k)
            {
                stores.retail_full_at.remove(&oldest);
                stores.counters.pace_evicted[diagnostic_source_slot(source)] += 1;
                crate::local_resource_diagnostics::durable_tail_alarm(
                    source.api_slug(),
                    &serde_json::json!({"pace_evicted":1}),
                );
            }
        }
        let stamp = stores.retail_full_at.entry(digest).or_insert(FullPace {
            at: now,
            structural: false,
            flags: 0,
            head_extent: extent,
        });
        if stamp.head_extent != extent {
            stamp.head_extent = extent;
            stamp.flags &= !(HEAD_USED | DEFERRED);
        }
        if stamp.flags & HEAD_USED != 0 {
            return Err(Failure::Resource("rederive_paced"));
        }
        if stamp.flags & DEFERRED != 0
            && now
                .duration_since(stamp.at)
                .map_or(true, |age| age.as_secs() >= PACE_SECS)
        {
            return Err(Failure::Resource("rederive_budget_aged"));
        }
        if deferred {
            if stamp.flags & (DEFERRED | FULL_SPENT) == 0 {
                stamp.at = now;
            }
            stamp.flags |= DEFERRED;
        }
        // Custody is funded independently of pace-node eviction. No synthetic
        // receipt debt: this bit cannot block settlement/upload of other keys.
        let prior_full = (stamp.flags & FULL_SPENT != 0).then_some(owed::FullSpend {
            at: stamp.at,
            near_extra: stamp.flags & NEAR_EXTRA != 0,
        });
        let Some(debt) = stores.fund_debt(digest) else {
            stores.owed_overflow[ds.slot()] = true;
            return Err(Failure::Resource("rederive_custody"));
        };
        if debt.full_spend.is_none() {
            debt.full_spend = prior_full;
        }
        debt.rederive_hold = Some(ds);
        if input {
            if debt.head_extent == Some(extent) {
                if debt.extra_head {
                    return Err(Failure::Resource("rederive_paced"));
                }
                debt.extra_head = true;
            } else {
                debt.head_extent = Some(extent);
                debt.extra_head = false;
            }
            let stamp = stores.retail_full_at.get_mut(&digest).expect("enrolled");
            stamp.flags |= HEAD_USED;
            stamp.flags &= !DEFERRED;
            REDERIVE_HEAD_READS[diagnostic_source_slot(source)].fetch_add(1, Ordering::Relaxed);
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"rederive_head_reads":1}),
            );
        }
        Ok(())
    }

    /// Re-derive failures share the cross-cause Full stamp, with at most one
    /// extra near-cap read per six-hour window (rotation can remove discovery).
    fn rederive_full(
        &self,
        source: SnapshotSource,
        key: &str,
        file: &File,
        accepted_end: u64,
        start: bool,
    ) -> bool {
        let Ok(meta) = file.metadata() else {
            return false;
        };
        if meta.len() <= accepted_end {
            return false;
        }
        let now = SystemTime::now();
        if self.paced_admission(source, key, now, false, false, start) {
            return true;
        }
        if !near_source_cap(source, meta.len()) {
            return false;
        }
        let Some(mut stores) = self.durable() else {
            return false;
        };
        let digest = full_pace_key(source, key);
        let spent_extra = stores
            .key_debt
            .get(&digest)
            .and_then(|d| d.full_spend)
            .map(|spend| spend.near_extra)
            .or_else(|| {
                stores
                    .retail_full_at
                    .get(&digest)
                    .map(|stamp| stamp.flags & NEAR_EXTRA != 0)
            });
        // Missing spend evidence grants no additional near-cap exception.
        if spent_extra != Some(false) {
            return false;
        }
        if start {
            if let Some(spend) = stores
                .key_debt
                .get_mut(&digest)
                .and_then(|d| d.full_spend.as_mut())
            {
                spend.near_extra = true;
            }
            if let Some(stamp) = stores.retail_full_at.get_mut(&digest) {
                stamp.flags |= NEAR_EXTRA;
            }
            Counters::bump(
                &mut stores.counters.resource_full,
                "rederive_failure_full.near_cap",
            );
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"rederive_failure_full":{"near_cap":1}}),
            );
        }
        true
    }

    /// P2: reserves `bytes` of this pass's restored head budget before input.
    fn reserve_rederive(&self, source: SnapshotSource, bytes: u64) -> Result<(), Failure> {
        let Some(ds) = durable_source(source) else {
            return Ok(());
        };
        let mut stores = self
            .durable()
            .ok_or(Failure::Resource("stores_unavailable"))?;
        let spent = stores.rederive_spent[ds.slot()];
        match spent.checked_add(bytes) {
            Some(total) if total <= REDERIVE_PASS_BYTES => {
                stores.rederive_spent[ds.slot()] = total;
                Ok(())
            }
            _ => {
                stores.counters.rederive_budget[0] += 1;
                stores.counters.rederive_budget[1] += bytes;
                Err(Failure::Resource("rederive_budget"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_known(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        index: &ScanIndex,
        interpretation: &Interpretation<'_>,
        lease: &mut store::ActiveLease,
    ) -> Result<Result<sampled_jsonl::CompletedNativeAcquisition, &'static str>, RestoreOutcome>
    {
        let source = durable_source(snapshot_source).ok_or(MissClass::Unavailable)?;
        let store_key = store::key_digest(source, key);
        let record = {
            let Some(mut stores) = self.durable() else {
                return Ok(Err("stores_unavailable"));
            };
            if !index.files.contains_key(key) && stores.slot(source).is_none() {
                return Err(MissClass::NoEntry.into());
            }
            stores.counters.restore_attempts += 1;
            stores.note_indexed(source, index);
            // Codex keeps its predecessor selection gate; Claude first proves the original binding.
            if source == DurableSource::Codex
                && index
                    .files
                    .get(key)
                    .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            {
                Counters::bump(&mut stores.counters.ineligible, "selection_cleared");
                // SOURCE cond. 5: a record surviving behind a cleared selection
                // (the D3 strict rebind's carrier, no new persisted field) is a
                // refused stale record. A disabled store cannot prove absence.
                let Some(slot) = stores.slot(source).as_mut() else {
                    return Err(MissClass::SelectionCleared.into());
                };
                if slot.store.absent(&store_key) {
                    return Err(MissClass::SelectionCleared.into());
                }
                slot.store.note_stale_refusal();
                drop(stores);
                return Err(self.stale_selection_full(snapshot_source, key, held));
            }
            // Revision adoption and money-rule replay both use this debt.
            // Check before disk I/O: an owed raw replay may never be served
            // by an otherwise valid pre-replay reduction plus Tail.
            if index.effective_upload_body_witness_revision_requires_adoption(key) {
                Counters::bump(&mut stores.counters.ineligible, "history_owed");
                return Err(MissClass::HistoryOwed.into());
            }
            let (outcome, disabled) = match stores.slot(source).as_mut() {
                Some(slot) => match slot.store.read_bounded(&store_key, lease) {
                    Ok(outcome) => (outcome, slot.store.disabled().is_some()),
                    Err(store::ActiveOverBudget) => return Ok(Err("input")),
                },
                None => {
                    return Err((if index.files.contains_key(key) {
                        MissClass::Unavailable
                    } else {
                        MissClass::NoEntry
                    })
                    .into())
                }
            };
            match outcome {
                ReadOutcome::Found(record) => record,
                ReadOutcome::Missing => {
                    stores.counters.missing += 1;
                    return Err((if disabled {
                        MissClass::Unavailable
                    } else if !index.files.contains_key(key) {
                        MissClass::NoEntry
                    } else {
                        MissClass::Missing
                    })
                    .into());
                }
                ReadOutcome::Refused(reason) => {
                    stores.counters.refused_record += 1;
                    return Err(MissClass::Record(reason).into());
                }
            }
        };
        if record.format == store::FORMAT_V3 && !crate::heap_layout_bound::layout_supported() {
            let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
            let slot = stores.slot(source).as_mut().ok_or(MissClass::Unavailable)?;
            if slot.decided.len() >= slot.indexed.saturating_add(2 * store::MAX_RECORDS)
                && !slot.decided.contains_key(key)
            {
                return Err(RestoreOutcome::Pending); // Budget deferral: no input, no GC.
            }
            slot.decided.insert(
                key.to_owned(),
                ScopeDecision::LayoutUnavailable {
                    settled: false,
                    verified: false,
                },
            );
            Counters::bump(
                &mut stores.counters.ineligible,
                "restore_unavailable.layout",
            );
            let audit_debt = (record.record.binding.context
                == store::context_digest(
                    &interpretation.namespace.0,
                    index.active_upload_context_fingerprint.as_deref(),
                ))
            .then_some(record.envelope_audit_debt)
            .flatten();
            return Err(MissClass::LayoutUnavailable(audit_debt).into());
        }
        // Missing membership is itself missing audit custody. Check the verified
        // same-context carrier before the entry-dependent binding; indexed keys
        // retain their existing real-edit and accepted-floor precedence below.
        if !index.files.contains_key(key)
            && record.record.binding.context
                == store::context_digest(
                    &interpretation.namespace.0,
                    index.active_upload_context_fingerprint.as_deref(),
                )
            && !audit_carrier_matches(
                &record,
                index,
                key,
                unix_seconds(SystemTime::now()).unwrap_or(0),
            )
        {
            Counters::bump(
                &mut self
                    .durable()
                    .ok_or(MissClass::Unavailable)?
                    .counters
                    .ineligible,
                "audit_carrier",
            );
            return Err(MissClass::AuditCarrier.into());
        }
        let original_expected = expected(
            source,
            snapshot_source,
            key,
            scope,
            index,
            interpretation,
            Some((
                record.format,
                record.record.allowlist,
                effective_revision(snapshot_source),
            )),
        )
        .ok_or(MissClass::NoEntry)?;
        // A future body revision is a downgrade hold even on changed input.
        if interpretation
            .accepted
            .is_some_and(|a| a.revision > effective_revision(snapshot_source))
        {
            return Err(MissClass::AcceptedFloor.into());
        }
        let original_matches = record.eligible(&original_expected).is_ok()
            && interpretation.accepted.map_or(true, |a| {
                a.strict
                    && a.entry == record.record.binding.entry
                    && record.record.certificate.length == a.end
                    && record.index_generation <= a.generation
            });
        if original_matches {
            if let Err(CertificateRefusal::Changed(
                reason @ (FullReason::Shrunk | FullReason::SameSizeEdit),
            )) = record.record.certificate.check_metadata(held)
            {
                if let Some(mut stores) = self.durable() {
                    Counters::bump(
                        &mut stores.counters.certificate_refused,
                        full_reason_class(reason),
                    );
                }
                self.queue_rederive_retirement(
                    source,
                    &record,
                    &original_expected,
                    RetirementEdge::Metadata,
                );
                return Err(MissClass::RealEdit(reason).into());
            }
        }
        if let Some(a) = interpretation.accepted {
            let metadata = held.metadata().map_err(|_| MissClass::AcceptedFloor)?;
            if a.revision <= effective_revision(SnapshotSource::ClaudeCode)
                && record.record.binding.source == source
                && record.record.binding.key == store_key
                && record.record.binding.context
                    == store::context_digest(
                        &interpretation.namespace.0,
                        index.active_upload_context_fingerprint.as_deref(),
                    )
                && accepted_object_changed(
                    &record,
                    a,
                    metadata.dev(),
                    metadata.ino(),
                    birth_unix_nanos(&metadata),
                )
            {
                if let Some(mut stores) = self.durable() {
                    Counters::bump(
                        &mut stores.counters.ineligible,
                        "s2_skipped_real_edit.replaced",
                    );
                }
                self.retire_or_hold(
                    original_matches,
                    source,
                    &record,
                    &original_expected,
                    RetirementEdge::AcceptedObject,
                );
                return Err(MissClass::RealEdit(FullReason::Replaced).into());
            }
            if a.behind(metadata.len()) {
                if let Some(mut stores) = self.durable() {
                    Counters::bump(&mut stores.counters.ineligible, "accepted_body_floor");
                    crate::local_resource_diagnostics::durable_tail_alarm(
                        snapshot_source.api_slug(),
                        &serde_json::json!({"restored_behind_accepted":{"held":1}}),
                    );
                }
                return Err(MissClass::AcceptedFloor.into());
            }
        }
        if record.record.binding.context
            == store::context_digest(
                &interpretation.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            )
            && !audit_carrier_matches(
                &record,
                index,
                key,
                unix_seconds(SystemTime::now()).unwrap_or(0),
            )
        {
            Counters::bump(
                &mut self
                    .durable()
                    .ok_or(MissClass::Unavailable)?
                    .counters
                    .ineligible,
                "audit_carrier",
            );
            return Err(MissClass::AuditCarrier.into());
        }
        index.files.get(key).ok_or(MissClass::NoEntry)?;
        if source == DurableSource::ClaudeCode && interpretation.accepted.is_none() {
            return Err(self.stale("accepted_floor_missing"));
        }
        let mut expected = expected(
            source,
            snapshot_source,
            key,
            scope,
            index,
            interpretation,
            Some((
                record.format,
                record.record.allowlist,
                effective_revision(snapshot_source),
            )),
        )
        .ok_or(MissClass::NoEntry)?;
        let mut adapter_revision = None;
        if source == DurableSource::ClaudeCode {
            let (original, revision) =
                match claude_expected(key, scope, index, interpretation, &record) {
                    Ok(proof) => proof,
                    Err(reason) => {
                        // Probe before the early stale return, outside Stores.
                        let owed = unregistered_scope(
                            snapshot_source,
                            scope,
                            index,
                            interpretation,
                            record.record.binding.scope,
                        );
                        if matches!(
                            reason,
                            "context"
                                | "old_binding_no_match"
                                | "restore_semantics"
                                | "revision_adoption_required"
                        ) {
                            if let Some(a) = interpretation
                                .accepted
                                .filter(|a| a.revision <= effective_revision(snapshot_source))
                            {
                                if let Ok(metadata) = held.metadata() {
                                    let object = accepted_object(
                                        &record,
                                        &a,
                                        metadata.dev(),
                                        metadata.ino(),
                                        birth_unix_nanos(&metadata),
                                    );
                                    // Same/Unknown accepted objects must retain the
                                    // accepted prefix. A proved replacement is A2.
                                    if metadata.len() >= a.end || object == ObjectVerdict::Changed {
                                        if let Ok(Some(edit)) =
                                            record.record.certificate.independent_edit(held)
                                        {
                                            if let Some(mut stores) = self.durable() {
                                                Counters::bump(
                                                    &mut stores.counters.certificate_refused,
                                                    full_reason_class(edit),
                                                );
                                            }
                                            self.retire_or_hold(
                                                original_matches,
                                                source,
                                                &record,
                                                &original_expected,
                                                RetirementEdge::IndependentEdit,
                                            );
                                            return Err(MissClass::Failure(Failure::Certificate(
                                                CertificateRefusal::Changed(edit),
                                            ))
                                            .into());
                                        }
                                    }
                                }
                            }
                        }
                        return Err(match (self.stale(reason), owed) {
                            (RestoreOutcome::Stale(reason), Some(owed)) => {
                                RestoreOutcome::StaleUnregistered(reason, owed)
                            }
                            (outcome, _) => outcome,
                        });
                    }
                };
            let Some(a) = interpretation.accepted else {
                return Err(self.stale("accepted_floor_missing"));
            };
            let Ok(current) = held.metadata() else {
                return Err(self.stale("accepted_floor_metadata"));
            };
            let verdict = accepted_object(
                &record,
                &a,
                current.dev(),
                current.ino(),
                birth_unix_nanos(&current),
            );
            let behind = revision < a.revision || current.len() < a.end;
            if let Some(mut stores) = self.durable() {
                stores.counters.original_v1_mapped += 1;
                stores.counters.objects[verdict as usize] += 1;
                stores.counters.s2_skipped_object_changed +=
                    u64::from(behind && verdict == ObjectVerdict::Changed);
            }
            if behind && verdict != ObjectVerdict::Changed {
                return Err(self.stale("behind_accepted.legacy"));
            }
            expected = original;
            adapter_revision = Some(revision);
        }
        if record.format == store::FORMAT_V3 {
            let acquisition = record.record.acquisition.ok_or(MissClass::NoEntry)?;
            let current = effective_revision(snapshot_source);
            if acquisition.acquired_revision != current {
                return Err(self.stale(if acquisition.acquired_revision > current {
                    "revision_downgrade"
                } else {
                    "revision_adoption_required"
                }));
            }
            expected.binding.scope = record.record.binding.scope;
        }
        let restored = self.durable_restore_record_scoped(
            snapshot_source,
            &record,
            &expected,
            path,
            scope,
            held,
            lease,
            Some(V3RestoreScope {
                index,
                interpretation,
            }),
        );
        if matches!(
            restored,
            Err(Failure::Certificate(CertificateRefusal::Changed(
                FullReason::HeadChanged
                    | FullReason::BoundaryChanged
                    | FullReason::Shrunk
                    | FullReason::SameSizeEdit
                    | FullReason::Replaced
            )))
        ) {
            self.queue_rederive_retirement(
                source,
                &record,
                &expected,
                RetirementEdge::ScopedCertificate,
            );
        }
        // Registry probes include allowlist hashing; keep them outside Stores.
        let owed = if matches!(restored, Err(Failure::Ineligible(store::Ineligible::Scope))) {
            unregistered_scope(
                snapshot_source,
                scope,
                index,
                interpretation,
                record.record.binding.scope,
            )
        } else {
            None
        };
        let Some(mut stores) = self.durable() else {
            return Ok(Err("stores_unavailable"));
        };
        let (checkpoint, reduction, receipt) = match restored {
            Ok(restored) => restored,
            Err(class) => {
                let transient = matches!(
                    &class,
                    Failure::NotRederived(Refuse::NotRederivable("descriptor"))
                );
                let counters = &mut stores.counters;
                match class {
                    Failure::Ineligible(reason) => {
                        Counters::bump(&mut counters.ineligible, ineligible_class(reason))
                    }
                    Failure::Certificate(reason) => Counters::bump(
                        &mut counters.certificate_refused,
                        match reason {
                            CertificateRefusal::Changed(reason) => full_reason_class(reason),
                            CertificateRefusal::ReadError => "read_error",
                        },
                    ),
                    Failure::Resource(phase) => return Ok(Err(phase)),
                    Failure::Corrupt => counters.corrupt_body += 1,
                    Failure::NotRederived(refuse) => {
                        Counters::bump(&mut counters.not_rederived, refuse_class(refuse));
                        // Typed cap/hash/read refusal cannot authorize an idle
                        // Full. Keep the same no-read/growth safety net.
                        return Ok(Err("rederive_unfunded"));
                    }
                }
                if source == DurableSource::ClaudeCode && !matches!(class, Failure::Certificate(_))
                {
                    return Err(RestoreOutcome::Stale(if transient {
                        "descriptor"
                    } else {
                        "restore_semantics"
                    }));
                }
                if let Some(owed) = owed {
                    return Err(MissClass::Unregistered(owed).into());
                }
                if original_matches {
                    if let Failure::Certificate(CertificateRefusal::Changed(
                        reason @ (FullReason::HeadChanged | FullReason::BoundaryChanged),
                    )) = class
                    {
                        return Err(MissClass::RealEdit(reason).into());
                    }
                }
                return Err(MissClass::Failure(class).into());
            }
        };
        #[cfg(test)]
        super::test_hooks::fire(super::test_hooks::Point::AfterRestoredContent);
        if interpretation
            .accepted
            .is_some_and(|a| held.metadata().map_or(true, |m| a.behind(m.len())))
        {
            Counters::bump(&mut stores.counters.ineligible, "accepted_body_floor");
            crate::local_resource_diagnostics::durable_tail_alarm(
                snapshot_source.api_slug(),
                &serde_json::json!({"restored_behind_accepted":{"held":1}}),
            );
            return Err(MissClass::AcceptedFloor.into());
        }
        if let Some(slot) = stores.slot(source).as_mut() {
            slot.store.authorize(&record, &expected);
        }
        let needs_original = record.format == store::FORMAT_V1
            || interpretation
                .accepted
                .is_some_and(|floor| floor.end > record.record.certificate.sealed_offset);
        if source == DurableSource::ClaudeCode && needs_original && stores.fund_key(store_key) {
            let proof = stores
                .slot(source)
                .as_ref()
                .ok_or(MissClass::Unavailable)?
                .store
                .mutation_witness(&record, &expected);
            let custody = stores
                .retail_spent
                .get_mut(&store_key)
                .ok_or(MissClass::Unavailable)?;
            if custody.original.is_none() {
                custody.original = proof;
            }
            stores.release_idle_custody(&store_key);
        }
        stores.counters.rederive_head_bytes += receipt.head_bytes;
        stores.counters.rederive_named_lines += receipt.named_lines;
        stores.counters.rederive_line_bytes += receipt.line_bytes;
        drop(stores);
        if source == DurableSource::ClaudeCode
            && interpretation
                .accepted
                .is_some_and(|a| !held.metadata().is_ok_and(|m| m.len() >= a.end))
        {
            return Err(self.stale("behind_accepted.legacy"));
        }
        let mut durable = DurableCustody::default();
        if let Some(chain) = self.restored_chain(
            snapshot_source,
            key,
            &record,
            adapter_revision,
            &checkpoint,
            held,
            index,
            lease,
            acquired::ImmutableCounting::from_reduction(&reduction)
                .ok()
                .as_ref(),
        ) {
            durable
                .put_chain(chain)
                .unwrap_or_else(|_| unreachable!("fresh custody"));
        }
        Ok(Ok(sampled_jsonl::CompletedNativeAcquisition {
            durable,
            checkpoint,
            reduction: Some(reduction),
            released: None,
            unsealed: false,
        }))
    }

    /// The restored chain inherits the original proof: a Claude v1 record's
    /// unique adapter revision (Legacy), or a v3 record's verified r_a and
    /// protocol. Codex v1 has no unique mapping and gets no chain; nothing is
    /// restamped. O is computed on the held FD, whose position is restored.
    #[allow(clippy::too_many_arguments)]
    fn restored_chain(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        record: &store::DurableRecord,
        adapter_revision: Option<u64>,
        checkpoint: &Checkpoint,
        held: &mut File,
        index: &ScanIndex,
        lease: &mut store::ActiveLease,
        counting: Option<&acquired::ImmutableCounting>,
    ) -> Option<AcquiredChain> {
        use std::io::{Seek, SeekFrom};
        let ds = durable_source(snapshot_source)?;
        let (revision, protocol) = match (record.format, record.record.acquisition) {
            (store::FORMAT_V3, Some(acquisition)) => {
                (acquisition.acquired_revision, acquisition.protocol)
            }
            (store::FORMAT_V1, None) => {
                let revision = match adapter_revision {
                    Some(revision) => revision,
                    None if snapshot_source == SnapshotSource::Codex => {
                        let mut stores = self.durable()?;
                        let slot = stores.slot(ds).as_ref()?;
                        let interpretation = Interpretation::of(
                            snapshot_source,
                            key,
                            index,
                            slot.identity_capture,
                            &slot.namespace,
                        );
                        let entry = index.files.get(key)?;
                        let candidates = std::collections::BTreeSet::from([
                            entry.effective_upload_body_witness_revision,
                            effective_revision(snapshot_source),
                            index.active_effective_upload_body_witness_revision,
                        ]);
                        let mut matched = None;
                        for revision in candidates {
                            let expected = expected(
                                ds,
                                snapshot_source,
                                key,
                                checkpoint.scope(),
                                index,
                                &interpretation,
                                Some((store::FORMAT_V1, record.record.allowlist, revision)),
                            )?;
                            if record.eligible(&expected).is_ok() {
                                if matched.is_some() {
                                    return None;
                                }
                                matched = Some(revision);
                            }
                        }
                        matched
                            .filter(|revision| *revision == effective_revision(snapshot_source))?
                    }
                    None => return None,
                };
                (revision, AcquisitionProtocol::Legacy)
            }
            _ => return None,
        };
        let binding = self.live_binding(
            ds,
            snapshot_source,
            key,
            checkpoint.scope(),
            index,
            revision,
            counting?,
            lease,
        )?;
        // Two bounded content samples plus the digest text, funded before input.
        lease
            .charge((2 * FILE_CONTENT_SAMPLE_BYTES + 128) as u64)
            .ok()?;
        let position = held.stream_position().ok()?;
        #[cfg(test)]
        super::test_hooks::fire(super::test_hooks::Point::BeforeRestoredIdentity);
        let identity = opened_object_identity(snapshot_source, held);
        held.seek(SeekFrom::Start(position)).ok()?;
        let identity = identity.ok()?;
        let m = held.metadata().ok()?;
        acquired::restore_chain(
            acquired::ChainInputs {
                source: snapshot_source,
                key,
                opened_object_identity: &identity,
                object: (m.dev(), m.ino(), birth_unix_nanos(&m)),
                checkpoint,
                binding,
                acquired_revision: revision,
                committed_generation: index.generation,
            },
            protocol,
            lease,
        )
        .ok()
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn durable_restore_record(
        &self,
        source: SnapshotSource,
        record: &store::DurableRecord,
        expected: &Expected,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        lease: &mut store::ActiveLease,
    ) -> Result<(Checkpoint, CachedJsonlReduction, codec::RederiveReceipt), Failure> {
        self.durable_restore_record_scoped(source, record, expected, path, scope, held, lease, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn durable_restore_record_scoped(
        &self,
        source: SnapshotSource,
        record: &store::DurableRecord,
        expected: &Expected,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        lease: &mut store::ActiveLease,
        v3: Option<V3RestoreScope<'_>>,
    ) -> Result<(Checkpoint, CachedJsonlReduction, codec::RederiveReceipt), Failure> {
        let scoped = v3.is_some();
        let result =
            self.restore_record_content(source, record, expected, path, scope, held, lease, v3);
        // Eligible scoped failures include certificate/fence drops. Quiet is
        // an observation, not a content attempt. OFF uses the native M1 path.
        if scoped
            && !matches!(
                result,
                Err(Failure::Resource("rederive_quiet") | Failure::Ineligible(_))
            )
        {
            self.record_first_rederive_result(source, record.record.binding.key, result.is_err());
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_record_content(
        &self,
        source: SnapshotSource,
        record: &store::DurableRecord,
        expected: &Expected,
        path: &Path,
        scope: &Scope,
        held: &mut File,
        lease: &mut store::ActiveLease,
        v3: Option<V3RestoreScope<'_>>,
    ) -> Result<(Checkpoint, CachedJsonlReduction, codec::RederiveReceipt), Failure> {
        if source == SnapshotSource::Codex {
            refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)
                .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("compressed")))?;
        }
        record.eligible(expected).map_err(Failure::Ineligible)?;
        record
            .record
            .certificate
            .check_metadata(held)
            .map_err(Failure::Certificate)?;
        let committed = v3
            .and_then(|v| {
                v.index
                    .files
                    .get(path.to_string_lossy().as_ref())
                    .map(|e| e.size_bytes)
            })
            .unwrap_or(record.record.certificate.length);
        if held
            .metadata()
            .map_err(|_| Failure::Certificate(CertificateRefusal::ReadError))?
            .len()
            <= committed
            && v3.is_some()
        {
            if let Some(mut stores) = self.durable() {
                stores.counters.restore_pending_quiet[diagnostic_source_slot(source)] += 1;
            }
            return Err(Failure::Resource("rederive_quiet"));
        }
        let before =
            crate::transcript_acquisition::FileStamp::capture(held.metadata().map_err(|_| {
                Failure::Certificate(CertificateRefusal::Changed(FullReason::Replaced))
            })?)
            .map_err(|_| Failure::Certificate(CertificateRefusal::Changed(FullReason::Replaced)))?;
        lease
            .charge(scope.0.len() as u64)
            .map_err(|_| Failure::Resource("certificate_scope"))?;
        let (checkpoint, _) = record
            .record
            .certificate
            .restore_grown(held, scope.clone())
            .map_err(Failure::Certificate)?;
        let decoded = codec::decode_bounded(&record.record.body, source, lease).map_err(
            |reason| match reason {
                crate::durable_tail_codec::DecodeFailure::Budget => Failure::Resource("decode"),
                crate::durable_tail_codec::DecodeFailure::Integrity => Failure::Corrupt,
            },
        )?;
        if !decoded.permits_skill_labels(self.skill_labels_enabled(source)) {
            return Err(Failure::NotRederived(Refuse::NonEmpty(
                "skill_label_consent_off",
            )));
        }
        if record.format == store::FORMAT_V3 {
            let inputs = v3.ok_or(Failure::Ineligible(store::Ineligible::Scope))?;
            let counting = decoded.immutable_counting().map_err(|_| Failure::Corrupt)?;
            let acquired = record
                .record
                .acquisition
                .ok_or(Failure::Corrupt)?
                .acquired_revision;
            if record.record.binding.scope
                != v3_replay_scope(
                    source,
                    scope,
                    inputs.index,
                    inputs.interpretation,
                    acquired,
                    &counting,
                )
            {
                return Err(Failure::Ineligible(store::Ineligible::Scope));
            }
        }
        if decoded
            .cutover()
            .is_some_and(|stored| stored != codex_counting_version::cutover_unix_ms())
        {
            return Err(Failure::Ineligible(store::Ineligible::Scope));
        }
        let digest = record.record.binding.key;
        let extent = record.record.certificate.length;
        let content = decoded.has_content();
        if content {
            self.rederive_gate(source, digest, extent, false, false)?;
        }
        let plan = decoded.rederive_plan().map_err(|reason| {
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"rederive_unsupported":{(reason):1}}),
            );
            Failure::Resource("rederive_unsupported")
        })?;
        lease
            .charge(plan.charge)
            .map_err(|_| Failure::Resource("rederive_unfunded"))?;
        if content {
            if let Err(failure) = self.reserve_rederive(source, plan.input_bytes()) {
                self.rederive_gate(source, digest, extent, false, true)?;
                return Err(failure);
            }
            self.rederive_gate(source, digest, extent, true, false)?;
        }
        let classes = decoded.content_classes();
        let (reduction, receipt, retained) = decoded
            .rederive_content_planned(held, &plan)
            .map_err(|error| {
                if matches!(error, Refuse::NotRederivable("content_fence")) {
                    Failure::Certificate(CertificateRefusal::Changed(FullReason::HeadChanged))
                } else {
                    record_rederive_refused(source, classes);
                    Failure::Resource("rederive_refused")
                }
            })?;
        if content {
            lease
                .refund(
                    plan.charge
                        .checked_sub(retained)
                        .ok_or(Failure::Resource("rederive_unfunded"))?,
                )
                .map_err(|_| Failure::Resource("rederive_unfunded"))?;
        }
        if source == SnapshotSource::Codex
            && v3.is_some_and(|inputs| {
                !codex_counting_version::reusable_under_view(
                    reduction.finish_view().0,
                    &inputs.interpretation.counting_view,
                )
            })
        {
            return Err(Failure::Ineligible(store::Ineligible::Scope));
        }
        let after =
            crate::transcript_acquisition::FileStamp::capture(held.metadata().map_err(|_| {
                Failure::Certificate(CertificateRefusal::Changed(FullReason::Replaced))
            })?)
            .map_err(|_| Failure::Certificate(CertificateRefusal::Changed(FullReason::Replaced)))?;
        if !crate::transcript_acquisition::append_compatible(&before, &after) {
            return Err(Failure::Certificate(CertificateRefusal::Changed(
                FullReason::Replaced,
            )));
        }

        Ok((checkpoint, reduction, receipt))
    }

    fn record_first_rederive_result(
        &self,
        source: SnapshotSource,
        digest: store::Digest32,
        failed: bool,
    ) {
        let Some(mut stores) = self.durable() else {
            return;
        };
        if stores.counters.rederive_first_attempt_tracking_closed {
            return;
        }
        if stores.fund_debt(digest).is_none() {
            stores.close_first_rederive_tracking();
            return;
        }
        // Funding may have reclaimed an idle diagnostic marker.
        if stores.counters.rederive_first_attempt_tracking_closed {
            return;
        }
        let debt = stores.key_debt.get_mut(&digest).expect("funded");
        if debt.first_rederive_failed.is_none() {
            debt.first_rederive_failed = Some(failed);
            stores.counters.rederive_failed_first_attempt[diagnostic_source_slot(source)] +=
                u64::from(failed);
        }
    }

    /// Aggregate process proxies on the existing carrier, once per source pass.
    pub(crate) fn durable_rederive_proxies(&self, source: SnapshotSource) {
        if !restart_restore::enabled() {
            return;
        }
        let Some(stores) = self.durable() else {
            return;
        };
        let slot = diagnostic_source_slot(source);
        let failed = stores.counters.rederive_failed_first_attempt[slot];
        let quiet = stores.counters.restore_pending_quiet[slot];
        let retire_held = stores.counters.retire_exact_held_first_attempt[slot];
        let retire_tracking_closed = stores.counters.retire_exact_first_attempt_tracking_closed;
        let stores_tracking_closed = stores.counters.rederive_first_attempt_tracking_closed;
        drop(stores);
        crate::local_resource_diagnostics::durable_tail_alarm(
            source.api_slug(),
            &serde_json::json!({
                "rederive_failed_first_attempt": failed,
                "restore_pending_quiet": quiet,
                "rederive_first_attempt_tracking_closed": stores_tracking_closed,
                "retire_exact_held_first_attempt": retire_held,
                "retire_exact_first_attempt_tracking_closed": retire_tracking_closed,
            }),
        );
    }

    /// A proved non-singleton class keeps its native owner. No mark or pending
    /// receipt is cleared by a class flag; outstanding debt stays counted/parked.
    pub(in crate::snapshots) fn durable_exclude_native_class(&self, key: &str) {
        if !restart_restore::enabled() {
            return;
        }
        let Some(mut stores) = self.durable() else {
            return;
        };
        let digest = store::key_digest(DurableSource::Codex, key);
        let parked = stores.owed_mark(&digest) != owed::OwedMark::None
            || stores
                .slot(DurableSource::Codex)
                .as_ref()
                .is_some_and(|slot| slot.store.receipt_pending(&digest));
        let Some(slot) = stores.slot(DurableSource::Codex).as_mut() else {
            return;
        };
        if slot.decided.len() < slot.indexed.saturating_add(2 * store::MAX_RECORDS)
            || slot.decided.contains_key(key)
        {
            slot.decided
                .insert(key.to_string(), ScopeDecision::Excluded);
            Counters::bump(
                &mut stores.counters.ineligible,
                if parked {
                    "wa.class_changed.owed_parked"
                } else {
                    "wa.class_changed.excluded"
                },
            );
        } else {
            Counters::bump(&mut stores.counters.ineligible, "pass_overflow.decided");
        }
    }

    pub(in crate::snapshots) fn durable_note_native_layout_skipped(&self, source: SnapshotSource) {
        if let Some(mut stores) = self.durable() {
            Counters::bump(
                &mut stores.counters.ineligible,
                match source {
                    SnapshotSource::ClaudeCode => "native_stage_skipped.layout_unsupported.claude",
                    _ => "native_stage_skipped.layout_unsupported.codex",
                },
            );
        }
    }

    /// Read completion/failure, never selection, budget deferral or cancellation.
    pub(in crate::snapshots) fn durable_layout_read_settled(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        index: &mut ScanIndex,
        verified: bool,
    ) {
        if !restart_restore::enabled() {
            return;
        }
        if crate::heap_layout_bound::layout_supported() {
            return;
        }
        let Some(source) = durable_source(snapshot_source) else {
            return;
        };
        let Some(mut stores) = self.durable() else {
            return;
        };
        let Some(slot) = stores.slot(source).as_mut() else {
            return;
        };
        // Some selectors (history adoption) intentionally skip restore. They
        // may still retire a known unrestorable A after their actual read.
        let digest = store::key_digest(source, key);
        let Some((format, _)) = slot.store.representation(&digest) else {
            return;
        };
        if format != store::FORMAT_V3 {
            return;
        }
        if slot.decided.len() >= slot.indexed.saturating_add(2 * store::MAX_RECORDS)
            && !slot.decided.contains_key(key)
        {
            return;
        }
        let was_counted = matches!(
            slot.decided.get(key),
            Some(ScopeDecision::LayoutUnavailable { .. })
        );
        // A failed/lossy read cannot clear envelope debt. Re-arm only the
        // existing same-context index carrier before post-save GC can retire A.
        if !verified {
            let context = store::context_digest(
                &slot.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            );
            if let Some(due) = slot.store.carrier_debt(&digest, &context) {
                let now = super::now_seconds();
                let _ =
                    MissClass::LayoutUnavailable(Some(due.min(now))).rearm_audit(index, key, now);
            }
        }
        slot.decided.insert(
            key.to_owned(),
            ScopeDecision::LayoutUnavailable {
                settled: true,
                verified,
            },
        );
        if !was_counted {
            Counters::bump(
                &mut stores.counters.ineligible,
                "restore_unavailable.layout",
            );
        }
        if !verified {
            Counters::bump(
                &mut stores.counters.ineligible,
                "restore_unavailable.layout.read_failed",
            );
        }
    }

    /// Notes the file scope `key` is decided under this pass, for GC and the
    /// strict predecessor check. Sized by the committed index; an overflow is
    /// counted and only keeps that key's record (GC) or reads it (no write).
    pub(crate) fn durable_note_scope(&self, source: SnapshotSource, key: &str, scope: &Scope) {
        let (Some(source), Some(mut stores)) = (durable_source(source), self.durable()) else {
            return;
        };
        let Some(slot) = stores.slot(source).as_mut() else {
            return;
        };
        if slot.decided.len() < slot.indexed.saturating_add(2 * store::MAX_RECORDS)
            || slot.decided.contains_key(key)
        {
            if !matches!(
                slot.decided.get(key),
                Some(ScopeDecision::Excluded | ScopeDecision::LayoutUnavailable { .. })
            ) {
                slot.decided
                    .insert(key.to_string(), ScopeDecision::Scope(scope.clone()));
            }
        } else {
            Counters::bump(&mut stores.counters.ineligible, "pass_overflow.decided");
        }
    }

    /// Records the selection `key`'s admitted reduction was acquired for:
    /// the scanned source-file fingerprint the scan wrote into its entry.
    /// An overflow is counted; that reduction is not written (it reads later).
    pub(crate) fn durable_note_selection(&self, key: &str, source_file_fingerprint: &str) {
        if let Some(mut stores) = self.durable() {
            if stores.selected.len() < stores.pass_key_cap() || stores.selected.contains_key(key) {
                stores
                    .selected
                    .insert(key.to_string(), source_file_fingerprint.to_string());
            } else {
                Counters::bump(&mut stores.counters.ineligible, "pass_overflow.selected");
            }
        }
    }

    /// Marks `key` admitted this pass: a write candidate after the next save.
    /// An overflow is counted; that entry is not written (it reads later).
    pub(super) fn durable_touch(&self, key: &str) {
        if let Some(mut stores) = self.durable() {
            if stores.touched.len() < stores.pass_key_cap() || stores.touched.contains(key) {
                stores.touched.insert(key.to_string());
            } else {
                Counters::bump(&mut stores.counters.ineligible, "pass_overflow.touched");
            }
        }
    }

    pub(in crate::snapshots) fn take_prepared(
        &self,
        source: SnapshotSource,
        key: &str,
    ) -> Result<Option<(Taken<CachedJsonlReduction>, store::ActiveLease)>, ()> {
        if self.retained().is_ok_and(|cache| cache.peek(key).is_none()) {
            return Ok(None);
        }
        #[cfg(test)]
        tests::before_warm_transfer();
        let store::LeaseWait::Granted(lease) = self.acquire_prepared_transfer(source) else {
            return Err(());
        };
        match self.take(key) {
            Some(taken) => Ok(Some((taken, lease))),
            None => {
                lease.release();
                Ok(None)
            }
        }
    }

    fn acquire_prepared_transfer(&self, source: SnapshotSource) -> store::LeaseWait {
        // Every admitted graph+key <= ENTRY_BYTES; cover moved Box/carrier and
        // fixed acquisition scratch too. This is transfer funding, not decode.
        self.acquire_active(
            source,
            (store::RECORD_BYTES + super::AUDIT_AND_SCRATCH_BYTES) as u64,
        )
    }

    pub(crate) fn acquire_active(
        &self,
        source: SnapshotSource,
        need_bytes: u64,
    ) -> store::LeaseWait {
        if need_bytes > store::ACTIVE_BYTES {
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({"active_budget_refused":1}),
            );
            return store::LeaseWait::OverBudget;
        }
        match store::ActiveLease::acquire(source.api_slug()) {
            store::LeaseWait::Granted(mut lease) => {
                if lease.charge(need_bytes).is_ok() {
                    store::LeaseWait::Granted(lease)
                } else {
                    lease.release();
                    store::LeaseWait::OverBudget
                }
            }
            other => other,
        }
    }

    /// No durable slot means no old certificate exists in this acquisition
    /// context. Otherwise keep the persisted marker until this exact body's
    /// debt-free replacement and a second index CAS both succeed.
    pub(crate) fn durable_stage_quiet_retirement(
        &self,
        source: SnapshotSource,
        key: &str,
        fingerprint: &str,
    ) -> bool {
        if !restart_restore::enabled() {
            return false;
        }
        let Some(mut stores) = self.durable() else {
            return true;
        };
        let Some(durable_source) = durable_source(source) else {
            return false;
        };
        if stores.slot(durable_source).is_none() {
            return false;
        }
        let key = store::key_digest(durable_source, key);
        let slot = stores
            .retiring
            .iter()
            .position(|pending| pending.is_some_and(|p| p.key == key))
            .or_else(|| stores.retiring.iter().position(Option::is_none))
            .unwrap_or(0);
        // Replacing a RAM proof candidate never removes its persisted marker;
        // that key must revalidate on its next visit before it can retire.
        stores.retiring[slot] = Some(QuietRetirement {
            key,
            source,
            fingerprint: Sha256::digest(fingerprint.as_bytes()).into(),
            durable: false,
        });
        true
    }

    pub(crate) fn durable_reconcile_retirements<W: SingleWriter>(
        &self,
        writer: &W,
        source: SnapshotSource,
        index: &mut ScanIndex,
        index_path: &Path,
    ) -> usize {
        if !restart_restore::enabled() {
            return 0;
        }
        if !index_path.starts_with(writer.state_dir()) {
            return 0;
        }
        let Some(durable_source) = durable_source(source) else {
            return 0;
        };
        let ready: Vec<_> = self
            .durable()
            .map(|stores| {
                index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        stores
                            .retiring
                            .iter()
                            .flatten()
                            .find(|pending| pending.key == store::key_digest(durable_source, key))
                            .is_some_and(|pending| {
                                pending.source == source
                                    && pending.durable
                                    && pending.fingerprint
                                        == <[u8; 32]>::from(Sha256::digest(
                                            entry.source_file_fingerprint.as_bytes(),
                                        ))
                            })
                    })
                    .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut undo = BTreeMap::new();
        for (key, fingerprint) in &ready {
            let previous = index
                .files
                .get(key)
                .and_then(|entry| entry.scan_identity_version.clone());
            if !index.claude_account_deferred_holds.contains_key(key)
                && index.retire_quiet_audit(key, fingerprint)
            {
                undo.insert(key.clone(), previous);
            }
        }
        if undo.is_empty() {
            return 0;
        }
        if index.save(index_path).is_err() {
            for (key, previous) in undo {
                if let Some(entry) = index.files.get_mut(&key) {
                    entry.scan_identity_version = previous;
                }
            }
            return 0;
        }
        let retired = undo.len();
        if let Some(mut stores) = self.durable() {
            for pending in &mut stores.retiring {
                if pending.is_some_and(|p| {
                    undo.keys()
                        .any(|key| store::key_digest(durable_source, key) == p.key)
                }) {
                    *pending = None;
                }
            }
        }
        crate::local_resource_diagnostics::traversal_point(
            "sampled_audit_retirement",
            source.api_slug(),
            &serde_json::json!({"audit_quiet_retired": retired,
                "pending_audits": index.files.values().filter(|entry| entry.has_unverified_source()).count()}),
        );
        retired
    }

    /// After a successful save of `index` (the committed generation), writes
    /// the records of this source's entries admitted since its last write
    /// that are still resident and kept by the save, then collects records
    /// the save no longer keeps. `writer` proves the single state-directory
    /// writer (#801).
    pub(crate) fn durable_write_after_save<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
        index: &ScanIndex,
    ) -> Option<store::BatchReceipt> {
        durable_source(snapshot_source)?;
        // The index save has already committed. Consent erasure neither
        // advances an ACK nor clears custody/owed metadata. A missing record
        // subsequently follows the native recovery path on natural growth.
        let purge_needed = self
            .durable()
            .and_then(|mut stores| {
                stores
                    .slot(durable_source(snapshot_source)?)
                    .as_ref()
                    .map(|slot| !slot.skill_labels_enabled && !slot.skill_label_purge_complete)
            })
            .unwrap_or(false);
        if !restart_restore::enabled() && !purge_needed {
            return None;
        }
        let store::LeaseWait::Granted(lease) = self.acquire_active(
            snapshot_source,
            (4 * store::RECORD_BYTES + WRITE_PASS_BYTES) as u64,
        ) else {
            return None;
        };
        if purge_needed {
            let mut stores = self.durable()?;
            let slot = stores.slot(durable_source(snapshot_source)?).as_mut()?;
            match slot.store.purge_private_labels(writer, |body| {
                codec::body_has_skill_labels(body).unwrap_or(false)
            }) {
                Ok(report) => {
                    slot.skill_label_purge_complete = report.refused == 0;
                    *stores
                        .counters
                        .not_persisted
                        .entry("skill_label_purged")
                        .or_default() += report.erased;
                    *stores
                        .counters
                        .not_persisted
                        .entry("skill_label_purge_failed")
                        .or_default() += report.refused;
                }
                Err(_) => {
                    Counters::bump(
                        &mut stores.counters.not_persisted,
                        "skill_label_purge_failed",
                    );
                }
            }
        }
        if !restart_restore::enabled() {
            lease.release();
            return None;
        }
        let service = std::time::Instant::now();
        let result = self.write_after_save_active(writer, snapshot_source, index);
        let micros = service.elapsed().as_micros().min(u64::MAX as u128) as u64;
        crate::local_resource_diagnostics::durable_tail_alarm(
            snapshot_source.api_slug(),
            &serde_json::json!({
                "durable_writer_service_us":micros, "durable_writer_slow_pass":u64::from(micros > 64_000_000)
            }),
        );
        lease.release();
        result
    }

    fn write_after_save_active<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
        index: &ScanIndex,
    ) -> Option<store::BatchReceipt> {
        let source = durable_source(snapshot_source)?;
        let allowlist = source.properties().allowlist();
        let (touched, mut selected, namespace, identity_capture, retiring) = {
            let mut stores = self.durable()?;
            stores.note_indexed(source, index);
            let slot = stores.slot(source).as_ref()?;
            let pass = (slot.namespace.clone(), slot.identity_capture);
            (
                std::mem::take(&mut stores.touched),
                std::mem::take(&mut stores.selected),
                pass.0,
                pass.1,
                stores
                    .retiring
                    .iter()
                    .flatten()
                    .filter(|pending| pending.source == snapshot_source)
                    .map(|pending| (pending.key, pending.fingerprint))
                    .collect::<BTreeMap<_, _>>(),
            )
        };
        let namespace = &namespace;
        let mut pending = Vec::new();
        let mut offered = BTreeMap::new();
        // The M1 active allowance covers these small provenance copies beside
        // its bounded body batch. A quiet retry has no new selector scope.
        let mut offered_scopes = Vec::new();
        let mut retirement_offers = BTreeSet::new();
        let mut later = BTreeSet::new();
        let mut budget = WRITE_PASS_BYTES;
        #[cfg(test)]
        if let Some(bytes) = TEST_WRITE_BYTES.with(std::cell::Cell::get) {
            budget = budget.min(bytes);
        }
        let mut not_persisted = Vec::new();
        let mut invalidate = BTreeSet::new();
        let mut peak = 0_u64;
        let skill_labels_enabled = self.skill_labels_enabled(snapshot_source);
        {
            let cache = self.retained().ok()?;
            for key in touched {
                let Some(retained) = cache.peek(&key) else {
                    selected.remove(&key);
                    continue;
                };
                if retained.state.source() != snapshot_source {
                    later.insert(key);
                    continue;
                }
                // Selection provenance: only a reduction acquired for the
                // committed entry's own fingerprint binds to it. A held or
                // reverted entry (local-hold settlement restored the prior
                // entry or cleared its fingerprint), or a RAM reduction ahead
                // of the saved selection, refuses. Claude preserves the
                // predecessor; Codex keeps its existing invalidation.
                let acquired_for = selected.remove(&key);
                match index.files.get(&key) {
                    None => continue,
                    Some(entry)
                        if !entry.source_file_fingerprint.is_empty()
                            && acquired_for.as_deref()
                                == Some(entry.source_file_fingerprint.as_str()) => {}
                    Some(_) => {
                        if source == DurableSource::Codex {
                            invalidate.insert(store::key_digest(source, &key));
                        }
                        not_persisted.push("selection");
                        continue;
                    }
                }
                if index.effective_upload_body_witness_revision_requires_adoption(&key) {
                    invalidate.insert(store::key_digest(source, &key));
                    not_persisted.push("history_owed");
                    continue;
                }
                let interpretation =
                    Interpretation::of(snapshot_source, &key, index, identity_capture, namespace);
                // Only entries the save kept bind; a dropped key has no entry.
                let Some(expected) = expected(
                    source,
                    snapshot_source,
                    &key,
                    retained.checkpoint.scope(),
                    index,
                    &interpretation,
                    None,
                ) else {
                    continue;
                };
                let Some(mut certificate) = certificate_at(
                    &key,
                    &retained.checkpoint,
                    index,
                    unix_seconds(SystemTime::now()).unwrap_or(0),
                ) else {
                    not_persisted.push("certificate");
                    continue;
                };
                let retiring = retiring
                    .get(&expected.binding.key)
                    .is_some_and(|fingerprint| {
                        index.files.get(&key).is_some_and(|entry| {
                            <[u8; 32]>::from(Sha256::digest(
                                entry.source_file_fingerprint.as_bytes(),
                            )) == *fingerprint
                                && entry.has_unverified_source()
                                && !entry.has_prefix_provenance()
                        }) && !index.claude_account_deferred_holds.contains_key(&key)
                            && retained.checkpoint.audit_debt().is_none()
                    });
                if retiring {
                    certificate.audit_debt_unix_seconds = None;
                }
                // Byte-budget deferral keeps the acquired provenance (the
                // requeue below carries it to the next save).
                if budget == 0 {
                    selected.extend(acquired_for.map(|fingerprint| (key.clone(), fingerprint)));
                    later.insert(key);
                    continue;
                }
                match codec::encode_permitted(
                    &retained.state,
                    budget.min(store::BODY_BYTES),
                    jsonl_line_cap() as u64,
                    skill_labels_enabled,
                ) {
                    Ok(body) => {
                        budget = budget.saturating_sub(body.len());
                        peak = peak.max(body.len() as u64);
                        offered_scopes.push((key.clone(), retained.checkpoint.scope().clone()));
                        if retiring {
                            retirement_offers.insert(expected.binding.key);
                        }
                        offered.insert(expected.binding.key, key);
                        pending.push(PendingRecord {
                            acquisition: None,
                            binding: expected.binding,
                            certificate,
                            body,
                            allowlist,
                        });
                    }
                    Err(Refuse::TooLarge) if budget < store::RECORD_BYTES => {
                        selected.extend(acquired_for.map(|fingerprint| (key.clone(), fingerprint)));
                        later.insert(key);
                    }
                    Err(refuse) => not_persisted.push(refuse_class(refuse)),
                }
            }
        }
        // Reconstruct from the actual retained acquisition, not the new index
        // or an old namespace. begin_pass cleared the per-pass classifier map.
        for (key, scope) in offered_scopes {
            self.durable_note_scope(snapshot_source, &key, &scope);
        }
        let mut stores = self.durable()?;
        let deferred = later.len() as u64;
        // Deferred keys keep their provenance for the next save.
        for key in &later {
            if let Some(fingerprint) = selected.remove(key) {
                stores.selected.insert(key.clone(), fingerprint);
            }
        }
        stores.touched.extend(later);
        let counters = &mut stores.counters;
        counters.write_deferred += deferred;
        counters.peak_body_bytes = counters.peak_body_bytes.max(peak);
        for class in not_persisted {
            Counters::bump(&mut counters.not_persisted, class);
        }
        if source == DurableSource::ClaudeCode {
            for key in offered.values() {
                let digest = store::key_digest(source, key);
                if !stores.fund_key(digest) {
                    stores
                        .slot(DurableSource::ClaudeCode)
                        .as_mut()?
                        .store
                        .revoke(&digest);
                    continue;
                }
                let stores = &mut *stores;
                let replacement = pending.iter().find(|r| r.binding.key == digest)?;
                authorize_strict(
                    stores.slots[source.slot()].as_mut()?,
                    snapshot_source,
                    key,
                    index,
                    stores.retail_spent.get_mut(&digest)?,
                    &replacement.binding,
                    &replacement.certificate,
                );
                stores.release_idle_custody(&digest);
            }
        }
        {
            let stores = &mut *stores;
            let mut attempts = 0;
            for (digest, debt) in stores.key_debt.iter_mut() {
                if attempts >= store::MAX_BATCH {
                    break;
                }
                if debt.retire_source != Some(source) || offered.contains_key(digest) {
                    continue;
                }
                let Some(custody) = stores.retail_spent.get_mut(digest) else {
                    continue;
                };
                let Some(proof) = custody.original.as_ref() else {
                    continue;
                };
                attempts += 1;
                let Some(slot) = stores.slots[source.slot()].as_mut() else {
                    break;
                };
                let outcome = slot
                    .store
                    .retire_exact(writer, proof, &mut debt.retire_sync);
                let class = match outcome {
                    store::RetireOutcome::Retry => "rederive_retire.retry",
                    store::RetireOutcome::Retired => "rederive_retire.retired",
                    store::RetireOutcome::Superseded => "rederive_retire.superseded",
                };
                Counters::bump(&mut stores.counters.ineligible, class);
                if !matches!(outcome, store::RetireOutcome::Retry) {
                    debt.retire_source = None;
                    custody.original = None;
                }
            }
            stores.retail_spent.retain(|_, c| c.has_authority());
        }
        let slot = stores.slot(source).as_mut()?;
        if !invalidate.is_empty() {
            let _ = slot.store.remove_keys(writer, &invalidate);
        }
        let index_length = match std::fs::metadata(&slot.index_path) {
            Ok(metadata) => metadata.len(),
            Err(_) => {
                Counters::bump(&mut stores.counters.not_persisted, "index_metadata");
                stores.retry_offered(offered, index);
                return None;
            }
        };
        let offered_files = pending.len() as u64;
        let before = slot.store.counters().store_write_failed;
        let result = slot
            .store
            .write_after_save(writer, index.generation, index_length, pending);
        let after = slot.store.counters().store_write_failed;
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(_) => {
                stores.counters.store_write_after_save_failed += offered_files;
                let stage = ["setup", "inventory", "statvfs"]
                    .into_iter()
                    .enumerate()
                    .find(|(i, _)| after[*i] > before[*i])
                    .map_or("store_io", |(_, stage)| stage);
                Counters::bump(&mut stores.counters.not_persisted, stage);
                stores.retry_offered(offered, index);
                drop(stores);
                crate::local_resource_diagnostics::durable_tail_alarm(
                    snapshot_source.api_slug(),
                    &serde_json::json!({"store_write_failed":{(stage):1}, "not_persisted":{(stage):1}}),
                );
                return None;
            }
        };
        {
            let stores = &mut *stores;
            for digest in offered.keys() {
                if let Some(c) = stores.retail_spent.get_mut(digest) {
                    if c.original.as_ref().is_some_and(|p| {
                        stores.slots[source.slot()]
                            .as_ref()
                            .expect("slot")
                            .store
                            .replacement_committed(p, &receipt)
                    }) {
                        stores.counters.migration[3] +=
                            u64::from(c.original.as_ref().is_some_and(|p| p.is_migration()));
                        c.original = None;
                        if let Some(debt) = stores.key_debt.get_mut(digest) {
                            debt.retire_source = None;
                            debt.retire_sync = false;
                        }
                    }
                }
                stores.release_idle_custody(digest);
            }
        }
        // Count totals must account for EVERY offer. A held/unknown/skipped
        // record, budget refusal or any writer error keeps all affected debt.
        if receipt.budget_refused == 0
            && receipt.written + receipt.clean + receipt.deferred_keys.len() == offered.len()
        {
            for digest in retirement_offers {
                if !receipt.deferred_keys.contains(&digest) {
                    if let Some(pending) = offered.get(&digest).and_then(|_| {
                        stores
                            .retiring
                            .iter_mut()
                            .flatten()
                            .find(|pending| pending.key == digest)
                    }) {
                        pending.durable = true;
                    }
                }
            }
        }
        // Records past the batch limit are offered again after the next save.
        for key in &receipt.deferred_keys {
            if let Some(key) = offered.remove(key) {
                if let Some(entry) = index.files.get(&key) {
                    stores
                        .selected
                        .insert(key.clone(), entry.source_file_fingerprint.clone());
                }
                stores.touched.insert(key);
            }
        }
        drop(stores);
        Some(receipt)
    }

    /// Collects records the committed `index` no longer keeps, from another
    /// context, scope or allowlist, and torn temps. Runs after a save.
    pub(crate) fn durable_gc<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
        index: &ScanIndex,
    ) -> std::io::Result<()> {
        if !restart_restore::enabled() {
            return Ok(());
        }
        let Some(source) = durable_source(snapshot_source) else {
            return Ok(());
        };
        let Some(mut stores) = self.durable() else {
            return Ok(());
        };
        stores.note_indexed(source, index);
        let Some(slot) = stores.slot(source).as_mut() else {
            return Ok(());
        };
        let (namespace, identity_capture) = (&slot.namespace, slot.identity_capture);
        let context = store::context_digest(
            &namespace.0,
            index.active_upload_context_fingerprint.as_deref(),
        );
        // Only keys with a record on disk (at most `INVENTORY_BOUND`) are
        // looked up; the index is streamed, never copied.
        let inventory = slot.store.inventory()?;
        if source == DurableSource::ClaudeCode {
            slot.store.revoke_all();
        }
        let mut keep = BTreeMap::new();
        let mut mapping_holds = BTreeMap::new();
        if !inventory.is_empty() {
            for key in index.files.keys() {
                let digest = store::key_digest(source, key);
                if !inventory.contains(&digest) {
                    continue;
                }
                if let Some(ScopeDecision::LayoutUnavailable { settled, verified }) =
                    slot.decided.get(key)
                {
                    keep.insert(
                        digest,
                        if *settled {
                            store::GcKeep::LayoutUnavailable {
                                audit_debt: index.files[key].unverified_deadline(),
                                verified: *verified,
                            }
                        } else {
                            store::GcKeep::Unknown
                        },
                    );
                    continue;
                }
                if matches!(slot.decided.get(key), Some(ScopeDecision::Excluded))
                    || source == DurableSource::Codex
                        && index.files[key].codex_history_is_protected()
                {
                    keep.insert(
                        digest,
                        store::GcKeep::Excluded {
                            audit_debt: index.files[key].unverified_deadline(),
                        },
                    );
                    continue;
                }
                let scope = slot
                    .decided
                    .get(key)
                    .and_then(ScopeDecision::scope)
                    .and_then(|scope| {
                        if index.files[key].has_unverified_source() {
                            return None; // Keep the predecessor until a verified Full replaces it.
                        }
                        let interpretation = Interpretation::of(
                            snapshot_source,
                            key,
                            index,
                            identity_capture,
                            namespace,
                        );
                        if source == DurableSource::ClaudeCode {
                            let ReadOutcome::Found(record) = slot.store.read(&digest) else {
                                return None;
                            };
                            let (original, _) = match claude_expected(
                                key,
                                scope,
                                index,
                                &interpretation,
                                &record,
                            ) {
                                Ok(proof) => proof,
                                Err(reason) => {
                                    Counters::bump(&mut mapping_holds, reason);
                                    slot.held += 1;
                                    return None;
                                }
                            };
                            slot.store.authorize(&record, &original);
                            return Some(original.binding.scope);
                        }
                        let (format, allowlist) = slot.store.representation(&digest)?;
                        if format == store::FORMAT_V3 {
                            return None;
                        }
                        expected(
                            source,
                            snapshot_source,
                            key,
                            scope,
                            index,
                            &interpretation,
                            Some((format, allowlist, effective_revision(snapshot_source))),
                        )
                        .map(|expected| {
                            if source == DurableSource::ClaudeCode {
                                if let ReadOutcome::Found(record) = slot.store.read(&digest) {
                                    slot.store.authorize(&record, &expected);
                                }
                            }
                            expected.binding.scope
                        })
                    });
                keep.insert(
                    digest,
                    scope.map_or(store::GcKeep::Unknown, store::GcKeep::Scope),
                );
            }
        }
        for (reason, n) in mapping_holds {
            *stores.counters.ineligible.entry(reason).or_default() += n;
        }
        stores.counters.gc_keep_peak = stores.counters.gc_keep_peak.max(keep.len() as u64);
        let Some(slot) = stores.slot(source).as_mut() else {
            return Ok(());
        };
        slot.store.gc_classified(writer, &context, &keep)
    }

    /// Fresh-index cleanup uses the same verified, bounded GC; U/T14 survive.
    pub(crate) fn durable_remove<W: SingleWriter>(
        &self,
        writer: &W,
        snapshot_source: SnapshotSource,
    ) -> std::io::Result<()> {
        let Some(source) = durable_source(snapshot_source) else {
            return Ok(());
        };
        let Some(mut stores) = self.durable() else {
            return Ok(());
        };
        for pending in &mut stores.retiring {
            if pending.is_some_and(|pending| pending.source == snapshot_source) {
                *pending = None;
            }
        }
        match stores.slot(source).as_mut() {
            Some(slot) => {
                if source == DurableSource::ClaudeCode {
                    slot.store.revoke_all();
                }
                slot.store.gc(writer, &[0; 32], &BTreeMap::new())
            }
            None => Ok(()),
        }
    }

    /// A post-save pass in a process that does not hold the state-directory
    /// lock: nothing is written or collected, and the admitted keys are
    /// dropped (they would never be written).
    pub(crate) fn durable_note_unlocked(&self, snapshot_source: SnapshotSource) {
        if durable_source(snapshot_source).is_none() {
            return;
        }
        if let Some(mut stores) = self.durable() {
            stores.touched.clear();
            stores.selected.clear();
            stores.retiring.fill(None);
            stores.counters.write_unlocked += 1;
        }
    }

    /// Local alarm on the `local_resources` carrier (#799), counts only: this
    /// source's held keys, T14 rebuilds and mode repairs since the last
    /// report (with totals), and once, the cause that disabled the store.
    /// A U hold keeps the source census retryable; T14 holds keep it healthy.
    pub(crate) fn durable_alarm(&self, snapshot_source: SnapshotSource) {
        self.durable_alarm_at(snapshot_source, std::time::Instant::now());
    }

    pub(crate) fn durable_alarm_at(&self, snapshot_source: SnapshotSource, at: std::time::Instant) {
        self.durable_restart_full_alarm(snapshot_source, at);
        #[derive(serde::Serialize)]
        struct HoldAlarm {
            keys: u64,
            oldest_age: u64,
        }
        #[derive(serde::Serialize)]
        struct StageSkipped {
            layout_unsupported: u64,
        }
        #[derive(serde::Serialize)]
        struct RestoreUnavailable {
            layout: u64,
            gc: u64,
        }
        #[derive(serde::Serialize)]
        struct StoreAlarm {
            #[serde(flatten)]
            store: store::StoreCounters,
            #[serde(skip_serializing_if = "Option::is_none")]
            store_bytes_alarm: Option<bool>,
            owed_overflow_discovery_only: bool,
            platform: &'static str,
            native_stage_skipped: StageSkipped,
            restore_unavailable: RestoreUnavailable,
            #[serde(skip_serializing_if = "Option::is_none")]
            d3_claude_hold: Option<HoldAlarm>,
        }
        #[derive(serde::Serialize)]
        struct Alarm {
            held_keys: [u64; 2],
            old_binding_no_match: [u64; 2],
            context: [u64; 2],
            restore_semantics: [u64; 2],
            revision_adoption_required: [u64; 2],
            retail_exhausted: [u64; 2],
            retail_exhausted_paced: [u64; 2],
            upgrade_state_missing: [u64; 2],
            upgrade_missing_full: [u64; 2],
            near_cap: [u64; 2],
            pace_anomaly: [u64; 2],
            upgrade_count_basis: &'static str,
            migration: [[u64; 2]; 4],
            t14_rebuild: [u64; 2],
            t14_rebuild_full_started: u64,
            mode_repaired: [u64; 2],
            #[serde(skip_serializing_if = "Option::is_none")]
            store_disabled: Option<&'static str>,
        }
        let Some(source) = durable_source(snapshot_source) else {
            return;
        };
        let Some(mut stores) = self.durable() else {
            return;
        };
        // Claude observes O3 native reads; the claim ledger retired with #856.
        let claude = source == DurableSource::ClaudeCode;
        let upgrade = if claude {
            stores.upgrade_reads.load(Ordering::Relaxed)
        } else {
            0
        };
        let retail = if claude {
            stores.counters.retail_full
        } else {
            [0; 3]
        };
        let stale = if claude {
            stores.counters.stale_full
        } else {
            [0; 3]
        };
        let near_cap = if claude { stores.counters.near_cap } else { 0 };
        let anomaly = if claude {
            stores.counters.pace_anomaly
        } else {
            0
        };
        let upgrade_full = if claude {
            stores.counters.upgrade_missing_full
        } else {
            0
        };
        let migration = if source == DurableSource::ClaudeCode {
            stores.counters.migration
        } else {
            [0; 4]
        };
        let recovery = stores.counters.recovery_full[source as usize];
        let [hold_keys, oldest_age] = if claude {
            stores.claude_holds()
        } else {
            [0, 0]
        };
        let hold_alarm = claude && stores.take_hold_alarm();
        let owed_overflow_discovery_only = stores.owed_overflow[source.slot()];
        let skipped = stores
            .counters
            .ineligible
            .get(if claude {
                "native_stage_skipped.layout_unsupported.claude"
            } else {
                "native_stage_skipped.layout_unsupported.codex"
            })
            .copied()
            .unwrap_or(0);
        let unavailable = stores
            .counters
            .ineligible
            .get("restore_unavailable.layout")
            .copied()
            .unwrap_or(0);
        let Some(slot) = stores.slot(source).as_mut() else {
            return;
        };
        let hold_changed = std::mem::replace(&mut slot.d3_reported, hold_keys) != hold_keys;
        let (store, disabled) = (slot.store.counters(), slot.store.disabled());
        let now = [
            slot.held,
            store.t14_rebuild,
            store.mode_repaired,
            u64::from(disabled.is_some()),
            store.t14_rebuild_full_started,
            upgrade,
            slot.old_binding_no_match,
            retail[0],
            retail[1],
            retail[2],
            stale[0],
            stale[1],
            stale[2],
            near_cap,
            upgrade_full,
            migration[0],
            migration[1],
            migration[2],
            migration[3],
            anomaly,
            recovery[0],
            recovery[1],
        ];
        let last = std::mem::replace(&mut slot.reported, now);
        drop(stores);
        // Idle and disabled stores still publish their snapshots. Only a source
        // with cause-only totals omits an empty snapshot, including on repeat
        // calls after its delta has been reported.
        let cause_only = now[..5] == [0; 5] && now[5..].iter().any(|&n| n != 0);
        if store != store::StoreCounters::default() || !cause_only || hold_alarm || hold_changed {
            // One existing store snapshot carries the fault reason, degraded
            // publishes, refusals, pause duration and per-key hold age together.
            crate::local_resource_diagnostics::durable_tail_alarm(
                snapshot_source.api_slug(),
                &StoreAlarm {
                    store_bytes_alarm: restart_restore::enabled()
                        .then_some(store.disk_bytes > 512 * 1024 * 1024),
                    store,
                    owed_overflow_discovery_only,
                    platform: std::env::consts::OS,
                    native_stage_skipped: StageSkipped {
                        layout_unsupported: skipped,
                    },
                    restore_unavailable: RestoreUnavailable {
                        layout: unavailable,
                        gc: store.restore_unavailable_layout_gc,
                    },
                    d3_claude_hold: (claude && (hold_keys > 0 || hold_alarm || hold_changed))
                        .then_some(HoldAlarm {
                            keys: hold_keys,
                            oldest_age,
                        }),
                },
            );
        }
        if now != last {
            let pair = |n: usize| [now[n].saturating_sub(last[n]), now[n]];
            crate::local_resource_diagnostics::durable_tail_alarm(
                snapshot_source.api_slug(),
                &Alarm {
                    held_keys: pair(0),
                    old_binding_no_match: pair(6),
                    context: pair(10),
                    restore_semantics: pair(11),
                    revision_adoption_required: pair(12),
                    retail_exhausted: pair(20),
                    retail_exhausted_paced: pair(21),
                    upgrade_state_missing: pair(5),
                    near_cap: pair(13),
                    upgrade_missing_full: pair(14),
                    migration: [pair(15), pair(16), pair(17), pair(18)],
                    pace_anomaly: pair(19),
                    upgrade_count_basis: "native_read",
                    t14_rebuild: pair(1),
                    t14_rebuild_full_started: store.t14_rebuild_full_started,
                    mode_repaired: pair(2),
                    store_disabled: disabled.filter(|_| last[3] == 0),
                },
            );
        }
    }

    /// One alarm at this process's first `store_write_failed_restart_full`
    /// file, then at most one per `RESTART_FULL_ALARM_WINDOW`: the once-per-
    /// 24 h throttle of the accepted rebuild alarm (`load_containment.rs`),
    /// kept process-local so no persisted field is added. The counter on the
    /// `durable_tail` line stays the persistent signal. Counts only.
    fn durable_restart_full_alarm(&self, snapshot_source: SnapshotSource, at: std::time::Instant) {
        #[derive(serde::Serialize)]
        struct Alarm {
            store_write_failed_restart_full: [u64; 2],
            store_write_after_save_failed: u64,
        }
        let Some(mut stores) = self.durable() else {
            return;
        };
        if stores.counters.store_write_failed_restart_full[0] == 0 {
            return;
        }
        if stores
            .restart_full_alarmed
            .is_some_and(|last| at.saturating_duration_since(last) < RESTART_FULL_ALARM_WINDOW)
        {
            return;
        }
        stores.restart_full_alarmed = Some(at);
        let alarm = Alarm {
            store_write_failed_restart_full: stores.counters.store_write_failed_restart_full,
            store_write_after_save_failed: stores.counters.store_write_after_save_failed,
        };
        drop(stores);
        crate::local_resource_diagnostics::durable_tail_restart_full_alarm(
            snapshot_source.api_slug(),
            &alarm,
        );
    }

    /// This process's durable counts and the source's store counters.
    pub(crate) fn durable_counters(
        &self,
        snapshot_source: SnapshotSource,
    ) -> Option<(Counters, store::StoreCounters)> {
        let source = durable_source(snapshot_source)?;
        let mut stores = self.durable()?;
        let mut counters = stores.counters.clone();
        if source == DurableSource::ClaudeCode {
            counters.upgrade_state_missing = stores.upgrade_reads.load(Ordering::Relaxed);
        } else {
            counters.migration = [0; 4];
        }
        if source != DurableSource::ClaudeCode {
            counters.retail_full = [0; 3];
            counters.stale_full = [0; 3];
            counters.near_cap = 0;
            counters.pace_anomaly = 0;
            counters.upgrade_missing_full = 0;
        }
        counters.retail_full[..2].copy_from_slice(&counters.recovery_full[source as usize]);
        counters.retail_full[2] = counters.pace_evicted[source as usize];
        let store = stores.slot(source).as_ref()?.store.counters();
        Some((counters, store))
    }

    /// Dev-only inspection of an existing slot. Never initializes a store or
    /// opens records; the caller inventories its own scratch after releasing
    /// this lock. The path must never enter aggregate output.
    #[cfg(feature = "replay-harness")]
    pub(crate) fn durable_replay_store(
        &self,
        snapshot_source: SnapshotSource,
    ) -> Option<(PathBuf, Option<&'static str>)> {
        let source = durable_source(snapshot_source)?;
        let mut stores = self.durable()?;
        let slot = stores.slot(source).as_ref()?;
        Some((slot.dir.clone(), slot.store.disabled()))
    }
}

/// The class returned by the attempted restore, never reconstructed from totals.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MissClass {
    AcceptedFloor,
    ExcludedClass,
    /// Known v3, but this binary's bounded restore layout is unavailable.
    LayoutUnavailable(Option<u64>),
    RealEdit(FullReason),
    Unavailable,
    NoEntry,
    AuditCarrier,
    SelectionCleared,
    /// A Codex record survived a cleared selection: refused, paced Full.
    StaleSelection,
    HistoryOwed,
    Missing,
    Record(store::Refusal),
    Failure(Failure),
    /// A non-transient resource refusal whose held file grew: ordinary Full.
    Resource(&'static str),
    BudgetRefused,
    TakeLost,
    Unregistered(Obligation),
}

impl MissClass {
    /// A cleared carrier may be an index-new/record-old completed-audit crash.
    /// Re-arm an immediate INDEX obligation; never restore envelope debt into
    /// a checkpoint or invent membership for an absent entry.
    pub(crate) fn rearm_audit(
        self,
        index: &mut ScanIndex,
        key: &str,
        now: u64,
    ) -> Option<crate::transcript_acquisition::AuditDebt> {
        let envelope_due = match self {
            Self::AuditCarrier => None,
            Self::LayoutUnavailable(Some(due)) => Some(due),
            _ => return None,
        };
        let entry = index.files.get_mut(key)?;
        let due = entry
            .unverified_deadline()
            .filter(|due| *due > 0)
            .map_or(envelope_due.unwrap_or(now), |due| {
                due.min(envelope_due.unwrap_or(now))
            });
        // Layout unavailability cannot turn the existing selection into a
        // due-audit read. Preserve a valid future deadline until settlement.
        let due = if matches!(self, Self::AuditCarrier) {
            due.min(now)
        } else {
            due
        };
        entry.set_unverified_deadline(due);
        Some(crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: due,
        })
    }

    pub(crate) fn label(self) -> &'static str {
        // Restore's producers use this closed set of content-free suffixes.
        // Refuse::UnknownLabel uses the existing static_label class.
        macro_rules! prefixed {
            ($prefix:literal, $suffix:expr, $($label:literal),+ $(,)?) => {
                match $suffix {
                    $($label => concat!($prefix, $label),)+
                    _ => concat!($prefix, "static_label"),
                }
            };
        }
        match self {
            Self::ExcludedClass => "class_excluded",
            Self::LayoutUnavailable(_) => "restore_unavailable.layout",
            Self::AcceptedFloor => "accepted_body_floor",
            Self::RealEdit(reason) => match reason {
                FullReason::Replaced => "s2_skipped_real_edit.replaced",
                FullReason::Shrunk => "s2_skipped_real_edit.shrunk",
                FullReason::SameSizeEdit => "s2_skipped_real_edit.same_size_edit",
                FullReason::HeadChanged => "s2_skipped_real_edit.head_changed",
                FullReason::BoundaryChanged => "s2_skipped_real_edit.boundary_changed",
                _ => "s2_skipped_real_edit.invalid_checkpoint",
            },
            Self::Unavailable => "unavailable",
            Self::NoEntry => "no_entry",
            Self::AuditCarrier => "ineligible.audit_carrier",
            Self::SelectionCleared => "ineligible.selection_cleared",
            Self::StaleSelection => "ineligible.selection_cleared.stale_record",
            Self::HistoryOwed => "ineligible.history_owed",
            Self::Missing => "missing",
            Self::BudgetRefused => "budget_refused",
            Self::TakeLost => "restore_take_lost",
            Self::Resource(phase) | Self::Failure(Failure::Resource(phase)) => prefixed!(
                "resource_full.",
                phase,
                "decode",
                "cache_transit",
                "stores_unavailable",
                "input",
                "cache_key",
                "certificate_scope",
                "rederive_unfunded",
                "rederive_budget"
            ),
            Self::Unregistered(owed) => match owed.kind {
                ObligationKind::BodyWitness => "unregistered_replay.body_witness",
                ObligationKind::MoneyRule => "unregistered_replay.money_rule",
            },
            Self::Record(reason) => match reason {
                store::Refusal::NewerFormat => "refused_record.newer",
                store::Refusal::Unknown => "refused_record.unknown",
                store::Refusal::Undecodable => "refused_record.undecodable",
                store::Refusal::Unbindable => "refused_record.unbindable",
                store::Refusal::Corrupt => "refused_record.corrupt",
                store::Refusal::BehindAccepted => "refused_record.behind_accepted",
                store::Refusal::ReceiptPending => "refused_record.receipt_pending",
                store::Refusal::Repin => "repin",
            },
            Self::Failure(Failure::Corrupt) => "corrupt_body",
            Self::Failure(Failure::Ineligible(reason)) => prefixed!(
                "ineligible.",
                ineligible_class(reason),
                "source",
                "key",
                "context",
                "scope",
                "generation_ahead",
                "entry_changed"
            ),
            Self::Failure(Failure::Certificate(reason)) => prefixed!(
                "certificate_refused.",
                match reason {
                    CertificateRefusal::Changed(reason) => full_reason_class(reason),
                    CertificateRefusal::ReadError => "read_error",
                },
                "state_missing",
                "audit_due",
                "clock_changed",
                "scope_changed",
                "invalid_checkpoint",
                "replaced",
                "shrunk",
                "same_size_edit",
                "head_changed",
                "boundary_changed",
                "unsupported_identity",
                "read_error"
            ),
            Self::Failure(Failure::NotRederived(refuse)) => prefixed!(
                "not_rederived.",
                refuse_class(refuse),
                "descriptor",
                "parser",
                "head",
                "compressed",
                "record_bytes",
                "SnapshotAccumulator.first_prompt_material",
                "SnapshotAccumulator.workspace_path",
                "SnapshotAccumulator.codex_agent_label",
                "SessionStartState.content_end",
                "SnapshotAccumulator.title",
                "CodexPrelude.skills_body"
            ),
        }
    }
}

pub(crate) enum RestoreOutcome {
    Restored(Box<Taken<CachedJsonlReduction>>, store::ActiveLease),
    M1Restored(Box<Taken<CachedJsonlReduction>>),
    Pending,
    Miss(MissClass),
    /// Known correctness hold, census-neutral; never a Full fallback.
    FloorHeld,
    /// Structural eligibility; pace is spent after page/cursor deferral.
    Degraded,
    Held(store::Refusal),
    Stale(&'static str),
    StaleUnregistered(&'static str, Obligation),
}
impl From<MissClass> for RestoreOutcome {
    fn from(class: MissClass) -> Self {
        Self::Miss(class)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum MigrationStart {
    AwaitSave,
    Full(u64),
    Fallback,
}
fn migration_object(r: &DurableCertificate, m: &std::fs::Metadata) -> bool {
    (r.device, r.inode) == (m.dev(), m.ino())
        && (r.birth_nanos == 0 || birth_unix_nanos(m) == 0 || r.birth_nanos == birth_unix_nanos(m))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectVerdict {
    Same,
    Unknown,
    Changed,
}
fn accepted_object(
    record: &store::DurableRecord,
    a: &AcceptedFloor,
    device: u64,
    inode: u64,
    birth: u64,
) -> ObjectVerdict {
    let r = &record.record.certificate;
    let bridge = record.format == 1
        && a.strict
        && record.record.binding.entry == a.entry
        && record.index_generation <= a.generation
        && a.birth != 0
        && a.birth == r.birth_nanos;
    if !bridge || birth == 0 {
        return ObjectVerdict::Unknown;
    }
    if (r.device, r.inode) != (device, inode) {
        if birth != a.birth {
            ObjectVerdict::Changed
        } else {
            ObjectVerdict::Unknown
        }
    } else if birth == a.birth {
        ObjectVerdict::Same
    } else {
        ObjectVerdict::Unknown
    } // Equal inode/different birth is reuse ambiguity.
}

#[cfg(test)]
mod restore_test {
    use super::*;
    // Direct-test callers keep the same credit until their graph is dropped or
    // explicitly transferred. Production continues to use Restored(Taken, lease).
    pub(in crate::snapshots) struct RestoredForTest {
        taken: Option<Box<Taken<CachedJsonlReduction>>>,
        lease: Option<store::ActiveLease>,
    }
    impl std::ops::Deref for RestoredForTest {
        type Target = Taken<CachedJsonlReduction>;
        fn deref(&self) -> &Self::Target {
            self.taken.as_deref().unwrap()
        }
    }
    impl RestoredForTest {
        pub(in crate::snapshots) fn into_parts(
            mut self,
        ) -> (Taken<CachedJsonlReduction>, store::ActiveLease) {
            (*self.taken.take().unwrap(), self.lease.take().unwrap())
        }
    }
    impl Drop for RestoredForTest {
        fn drop(&mut self) {
            drop(self.taken.take());
            if let Some(lease) = self.lease.take() {
                lease.release();
            }
        }
    }
    impl RestoreOutcome {
        pub(in crate::snapshots) fn into_test_option(self) -> Option<RestoredForTest> {
            match self {
                Self::M1Restored(taken) => Some(RestoredForTest {
                    taken: Some(taken),
                    lease: None,
                }),
                Self::Restored(taken, lease) => Some(RestoredForTest {
                    taken: Some(taken),
                    lease: Some(lease),
                }),
                Self::Miss(_)
                | Self::Stale(_)
                | Self::StaleUnregistered(_, _)
                | Self::Degraded
                | Self::Held(store::Refusal::BehindAccepted) => None,
                Self::FloorHeld => None,
                Self::Pending if !crate::heap_layout_bound::layout_supported() => None,
                Self::Pending => panic!("ordinary restore unexpectedly Pending"),
                Self::Held(reason) => panic!("ordinary restore unexpectedly Held: {reason:?}"),
            }
        }
    }
}

/// Held-FD length past the committed end; metadata only, no read.
fn grown(held: &File, index: &ScanIndex, key: &str) -> bool {
    let committed = index.files.get(key).map_or(0, |e| e.size_bytes);
    held.metadata().is_ok_and(|m| m.len() > committed)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Failure {
    Resource(&'static str),
    Ineligible(store::Ineligible),
    Certificate(CertificateRefusal),
    Corrupt,
    NotRederived(Refuse),
}

#[cfg(test)]
pub(crate) fn record_consumed(bytes: u64) {
    tests::record_consumed(bytes);
}

#[cfg(test)]
#[path = "durable_tail_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "transition_seed.rs"]
pub(crate) mod transition_seed;

#[cfg(test)]
#[path = "durable_tail_store_write_tests.rs"]
mod store_write_tests;

#[cfg(test)]
pub(crate) use tests::seed_pinned_v1;

#[cfg(all(test, unix))]
#[path = "m3_owed_tests.rs"]
mod m3_owed_tests;

#[cfg(test)]
mod resources_tests;

#[cfg(test)]
#[path = "restart_restore_tests.rs"]
mod restart_restore_tests;
