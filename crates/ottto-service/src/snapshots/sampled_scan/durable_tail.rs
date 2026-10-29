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
//! verification-stamp entries (`STORES_RESIDENT_BOUND`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
pub(crate) const WRITE_PASS_BYTES: usize = 8 * 1024 * 1024;

/// Upper bound of both stores' resident digest maps (two sources).
/// Pin history: Lead A approved 65,536 -> 401,408 bytes on 2026-10-29:
/// memo 2*256*256 = 131,072; pending 2*(32+1)*4096 = 270,336 bytes.
/// A0-h pays both spent and Full-pacing nodes (1,050,624 bytes): total
/// 1,452,032 bytes. FullPace's structural bit stays within its 1024-byte node.
/// Any further growth requires a new owner decision. Native/container evidence
/// remains required; this pin is not enforcement by the cache's heap walk.
#[cfg(test)]
pub(crate) const STORES_RESIDENT_BOUND: usize =
    2 * store::MAX_RECORDS * 256 + 2 * (store::MAX_BATCH + 1) * 4096 + super::RETAIL_RESERVE_BYTES;

#[cfg(test)]
thread_local! {
    static BEFORE_CARRIER_PROBE: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(in crate::snapshots) fn set_before_carrier_probe(hook: Option<Box<dyn FnMut()>>) {
    BEFORE_CARRIER_PROBE.with(|slot| *slot.borrow_mut() = hook);
}

const RECOVERY_PACE_SECONDS: u64 = 6 * 3600;
const _: () = assert!(RECOVERY_PACE_SECONDS < 24 * 3600);

/// Head re-parse bytes of restores, per source, for the process lifetime.
/// Existing class-X re-derivation is bounded at `HEAD_BOUND`, on a RAM
/// miss only, so the census pass line reports it beside the guard's own
/// counters (SOURCE N1).
static REDERIVE_HEAD_BYTES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

pub(crate) fn rederive_head_bytes_total(source: SnapshotSource) -> u64 {
    durable_source(source).map_or(0, |source| {
        REDERIVE_HEAD_BYTES[source as usize].load(Ordering::Relaxed)
    })
}

/// Actual physical class-X bytes, including a later capture/hash refusal.
/// The success receipt is separate; never hide input behind a refusal label.
pub(in crate::snapshots) fn record_rederive_input(source: SnapshotSource, bytes: u64) {
    if let Some(ds) = durable_source(source) {
        REDERIVE_HEAD_BYTES[ds as usize].fetch_add(bytes, Ordering::Relaxed);
    }
    crate::local_resource_diagnostics::durable_tail_alarm(
        source.api_slug(),
        &serde_json::json!({"rederive_input_bytes": bytes}),
    );
}

const PACE_SECS: u64 = 6 * 3600;
// Civil-time anomalies expire authority toward reading, never toward holding.
const PACE_SANITY_SECS: u64 = 86_400;
const _: () = assert!(PACE_SECS < 86_400);

/// Content-free outcome counts, by class. Field paths are static names; no
/// id, path or value is ever counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) restore_attempts: u64,
    pub(crate) restored: u64,
    pub(crate) retail_attempts: u64,
    pub(crate) retail_keys: u64,
    pub(crate) retail_full: [u64; 3],
    /// Immediate emission owns these per-source eviction totals exclusively.
    pub(crate) pace_evicted: [u64; 3],
    /// Recovery Full/paced totals per source; eviction has its separate owner.
    recovery_full: [[u64; 2]; 3],
    /// [Full, paced] per Claude/Codex/Pi; process-lifetime, not store-owned.
    pub(crate) active_bound: [[u64; 2]; 3],
    pub(crate) missing: u64,
    pub(crate) refused_record: u64,
    pub(crate) durable_held: [u64; 7],
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
        format!(
            "ottto-service: durable_tail source={} retail_attempts={} retail_keys={} tail_read_bytes={} \
             budget_refused_retail_old_bytes={} repeated_physical_old_bytes={} retail_full[full,paced,pace_evicted]={:?} resource_full={{{}}} active_bound[claude,codex,pi]={:?} rederive_head_bytes={} \
             rederive_named_lines={} rederive_line_bytes={} not_persisted={{{}}} ineligible={{{}}} \
             write_deferred={} write_unlocked={} peak_body_bytes={} store_write_failed[setup,inventory,statvfs]={:?} disk_records={} disk_bytes={} \
             bytes_written={} records_written={} records_clean={} store_budget_refused={} \
             bytes_read={} format_hold[newer,unknown,undecodable,unbindable,known_corrupt,retired_upgrade_missing,receipt_pending]={:?} durable_held={:?} held_census[kept,invalidated]={:?} \
             guard_header_bytes={} guard_verify_bytes={} delete_verify_bytes={} overwrite_verify_bytes={} \
             uninventoried_records={} store_write_skipped[unknown,inventory_overflow]={:?} \
             gc_records_deleted={} gc_records_read={} gc_bytes_read={} gc_keep_peak={} \
             records_invalidated={} mutation_unproved={} peak_codec_bytes={} t14_rebuild_full_started={}",
            source.api_slug(),
            self.retail_attempts,
            self.retail_keys,
            retail_bytes(source, 0),
            retail_bytes(source, 1),
            retail_bytes(source, 1),
            self.retail_full,
            classes(&self.resource_full),
            self.active_bound,
            self.rederive_head_bytes,
            self.rederive_named_lines,
            self.rederive_line_bytes,
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
        )
    }
}

struct Slot {
    dir: PathBuf,
    index_path: PathBuf,
    store: DurableTailStore,
    /// File scopes decided this pass, by key: GC drops a record bound to
    /// another scope. Keys not decided this pass keep their records.
    decided: BTreeMap<String, Scope>,
    /// The pass's sampled scope and identity-capture mode.
    namespace: Scope,
    identity_capture: bool,
    /// Keys held (U) by this source, and the totals the last alarm reported:
    /// [held, t14_rebuild, mode_repaired, disabled, rebuild_full].
    held: u64,
    reported: [u64; 7],
}

/// Fixed-size stamp in the existing paid pacing node. Remember structural
/// classification after the first no-record publication changes index binding.
#[derive(Clone, Copy)]
struct FullPace {
    at: std::time::SystemTime,
    structural: bool,
}
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

/// Process-lifetime durable state beside the RAM cache.
#[derive(Default)]
pub(crate) struct Stores {
    claude: Option<Slot>,
    codex: Option<Slot>,
    /// Keys admitted to the RAM cache since their source's last write.
    touched: BTreeSet<String>,
    /// Selection provenance: the source-file fingerprint each admitted
    /// reduction was acquired for. A write binds a reduction only to a
    /// committed entry with this same fingerprint; local-hold settlement that
    /// reverts or clears the entry makes it refuse (F2).
    selected: BTreeMap<String, String>,
    counters: Counters,
    // Source+key only: never clear on passes, scope changes or cache eviction.
    retail_spent: BTreeMap<store::Digest32, (u64, std::time::Instant)>,
    // Independently paid pacing, never used to renew Q11 spent authority.
    retail_full_at: BTreeMap<store::Digest32, FullPace>,
    #[cfg(test)]
    retail_full_now: Option<std::time::SystemTime>,
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

    fn slot(&mut self, source: DurableSource) -> &mut Option<Slot> {
        match source {
            DurableSource::ClaudeCode => &mut self.claude,
            DurableSource::Codex => &mut self.codex,
        }
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
    match source {
        SnapshotSource::ClaudeCode => Some(DurableSource::ClaudeCode),
        SnapshotSource::Codex => Some(DurableSource::Codex),
        SnapshotSource::Pi => None,
    }
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
            accepted: (source == SnapshotSource::ClaudeCode)
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
    representation: Option<(u16, store::Digest32)>,
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
    representation: Option<(u16, store::Digest32)>,
) -> store::Digest32 {
    let (format, allowlist) =
        representation.unwrap_or_else(|| (store::FORMAT_VERSION, codec::allowlist_digest(source)));
    let body_revision = replay.filter(|row| row.kind == ObligationKind::BodyWitness);
    let money_rule = replay.filter(|row| row.kind == ObligationKind::MoneyRule);
    store::replay_scope_digest(
        &store::scope_digest_for(
            format,
            &scope.0,
            &allowlist,
            &interpretation.identity_contract,
            &interpretation.counting_view,
        ),
        body_revision.map_or_else(
            || crate::snapshot_sync::effective_upload_body_witness_revision(source),
            |row| row.revision,
        ),
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
pub(crate) struct RetailAttempt {
    source: DurableSource,
    object: (u64, u64, u64),
    next: u64,
    end: u64,
    old_end: u64,
}
impl crate::heap_layout_bound::HeapLayoutBound for RetailAttempt {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            source: _,
            object: _,
            next: _,
            end: _,
            old_end: _,
        } = self;
        c.add(0)
    }
}

// Process totals by source: native physical Tail bytes and old-suffix overlap.
static RETAIL_BYTES: [[AtomicU64; 2]; 2] = [
    [AtomicU64::new(0), AtomicU64::new(0)],
    [AtomicU64::new(0), AtomicU64::new(0)],
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
) {
    let Some(scope) = slot.decided.get(key) else {
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
    if let Some(expected) = expected(
        source,
        snapshot_source,
        key,
        scope,
        index,
        &interpretation,
        Some((record.format, record.record.allowlist)),
    ) {
        slot.store.authorize(&record, &expected);
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
        if crate::heap_layout_bound::tree_node_bytes::<store::Digest32, (u64, std::time::Instant)>()
            .map_or(true, |n| n > 1024)
        {
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
        if let Some((high, spent)) = stores.retail_spent.get(&key) {
            if now < *spent {
                Counters::bump(&mut stores.counters.ineligible, "retail_clock_rollback");
                return Err(RetailHold::AccountingLost);
            }
            if c.length < *high || accepted_end > c.length {
                Counters::bump(
                    &mut stores.counters.ineligible,
                    "retail_exhausted.budget_refused",
                );
                return Err(RetailHold::Exhausted);
            }
        } else if stores.retail_spent.len() >= store::MAX_RECORDS * 2 {
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
        let first = !stores.retail_spent.contains_key(&key);
        stores.counters.retail_keys += u64::from(first);
        stores.counters.retail_attempts += 1;
        stores.retail_spent.insert(key, (end, now));
        Ok(RetailAttempt {
            source,
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
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if metadata.len() <= accepted_end {
            return false;
        }
        self.paced_full(
            SnapshotSource::ClaudeCode,
            key,
            now,
            false,
            near_source_cap(SnapshotSource::ClaudeCode, metadata.len()),
            true,
        )
    }

    /// The ONE paid map, keyed by source/file across causes. A probe may count
    /// a delay, but only a starting acquisition enrols or spends an allowance.
    fn paced_full(
        &self,
        source: SnapshotSource,
        key: &str,
        now: std::time::SystemTime,
        active_bound: bool,
        near_cap: bool,
        start: bool,
    ) -> bool {
        let Some(mut stores) = self.durable() else {
            return false;
        };
        #[cfg(test)]
        let now = stores.retail_full_now.unwrap_or(now);
        let key = full_pace_key(source, key);
        let delayed = !near_cap
            && stores.retail_full_at.get(&key).is_some_and(|stamp| {
                // Backwards and implausibly large forwards jumps both EXPIRE.
                now.duration_since(stamp.at).is_ok_and(|age| {
                    age.as_secs() <= PACE_SANITY_SECS
                        && age < std::time::Duration::from_secs(PACE_SECS)
                })
            });
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
            stores.retail_full_at.insert(
                key,
                FullPace {
                    at: now,
                    structural,
                },
            );
        }
        if let Some(stamp) = stores.retail_full_at.get_mut(&key).filter(|_| active_bound) {
            stamp.structural = true;
        }
        let total = if active_bound {
            stores.counters.active_bound[source_slot][usize::from(delayed)] += 1;
            stores.counters.active_bound[source_slot][usize::from(delayed)]
        } else {
            stores.counters.retail_full[usize::from(delayed)] += 1;
            stores.counters.recovery_full[source_slot][usize::from(delayed)] += 1;
            stores.counters.recovery_full[source_slot][usize::from(delayed)]
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
        self.paced_full(
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
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        metadata.len() > accepted_end
            && self.paced_full(
                source,
                key,
                now,
                false,
                near_source_cap(source, metadata.len()),
                true,
            )
    }

    pub(super) fn durable(&self) -> Option<StoresGuard<'_>> {
        debug_assert!(!stores_held(), "Stores cannot be nested");
        let guard = self.durable.lock().ok()?;
        STORES_HELD.with(|held| held.set(true));
        Some(StoresGuard(guard))
    }

    /// Selects `source`'s store for this pass, the sibling of `index_path`,
    /// under the pass's sampled scope (`namespace`) and identity-capture
    /// mode. An index at another path (a destination or account switch) gets
    /// a fresh store; the old directory is left to its own index's GC.
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
        let slot = stores.slot(source);
        if let Some(current) = slot.as_mut().filter(|current| current.dir == dir) {
            current.decided.clear();
            current.index_path = index_path.to_owned();
            current.namespace = namespace.clone();
            current.identity_capture = identity_capture;
        } else {
            if let Some(old) = slot.as_mut().filter(|s| s.store.has_pending()) {
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
                held: 0,
                reported: [0; 7],
            });
        }
        if let Some(slot) = slot.as_mut() {
            slot.store.begin_pass();
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
            cache.durable_member_hold_active(source, key, index, recovered_audit_due)
        })
    }

    pub(in crate::snapshots) fn durable_member_hold_active(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
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
            true,
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
            let _ = slot.store.reconcile_pending(writer, &key);
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
        self.durable()?
            .slot(source)
            .as_mut()?
            .store
            .full_hold(&store::key_digest(source, key), start)
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

    pub(in crate::snapshots) fn durable_hold_exit(
        &self,
        source: SnapshotSource,
        reason: store::Refusal,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
        census: &mut ScanCensus,
    ) {
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
        match result {
            Ok(Ok(completed)) => {
                // Admission and take share one retained lock and this paid owner.
                match self.insert_with_custody(key.to_string(), completed, 0, false, true, true) {
                    Ok(Some(taken)) => {
                        if let Some(mut stores) = self.durable() {
                            stores.counters.restored += 1;
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
                if matches!(phase, "decode" | "input" | "certificate_scope") {
                    self.restore_active_bound(snapshot_source, key, held, index)
                } else {
                    self.restore_resource_pending(snapshot_source, phase, key, held, index)
                }
            }
            Err(MissClass::AcceptedFloor) => {
                lease.release();
                RestoreOutcome::FloorHeld
            }
            Err(class @ MissClass::RealEdit(_)) => {
                lease.release();
                RestoreOutcome::Miss(class)
            }
            Err(_) if floor_behind => {
                lease.release();
                RestoreOutcome::FloorHeld
            }
            Err(class @ MissClass::AuditCarrier) => {
                lease.release();
                RestoreOutcome::Miss(class)
            }
            Err(class) => {
                let result = self
                    .durable_guard(snapshot_source, key, true, index, &mut None)
                    .map_or(RestoreOutcome::Miss(class), RestoreOutcome::Held);
                lease.release();
                result
            }
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
        let full = phase != "active_wait"
            && self.paced_growth_full(
                source,
                key,
                held,
                index.files.get(key).map_or(0, |entry| entry.size_bytes),
                SystemTime::now(),
                "resource_full_granted",
            );
        if let Some(mut stores) = self.durable() {
            if full {
                Counters::bump(&mut stores.counters.resource_full, phase);
            } else {
                stores.counters.budget_refused += 1;
                Counters::bump(&mut stores.counters.ineligible, phase);
            }
        }
        let event = if full {
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
    ) -> Result<Result<sampled_jsonl::CompletedNativeAcquisition, &'static str>, MissClass> {
        let source = durable_source(snapshot_source).ok_or(MissClass::Unavailable)?;
        let store_key = store::key_digest(source, key);
        let record = {
            let Some(mut stores) = self.durable() else {
                return Ok(Err("stores_unavailable"));
            };
            if !index.files.contains_key(key) && stores.slot(source).is_none() {
                return Err(MissClass::NoEntry);
            }
            stores.counters.restore_attempts += 1;
            // A cleared fingerprint is reparse debt (a held or reverted
            // selection): it always reads Full.
            if index
                .files
                .get(key)
                .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            {
                Counters::bump(&mut stores.counters.ineligible, "selection_cleared");
                return Err(MissClass::SelectionCleared);
            }
            // Revision adoption and money-rule replay both use this debt.
            // Check before disk I/O: an owed raw replay may never be served
            // by an otherwise valid pre-replay reduction plus Tail.
            if index.effective_upload_body_witness_revision_requires_adoption(key) {
                Counters::bump(&mut stores.counters.ineligible, "history_owed");
                return Err(MissClass::HistoryOwed);
            }
            let (outcome, disabled) = match stores.slot(source).as_mut() {
                Some(slot) => match slot.store.read_bounded(&store_key, lease) {
                    Ok(outcome) => (outcome, slot.store.disabled().is_some()),
                    Err(store::ActiveOverBudget) => return Ok(Err("input")),
                },
                None => {
                    return Err(if index.files.contains_key(key) {
                        MissClass::Unavailable
                    } else {
                        MissClass::NoEntry
                    })
                }
            };
            match outcome {
                ReadOutcome::Found(record) => record,
                ReadOutcome::Missing => {
                    stores.counters.missing += 1;
                    return Err(if disabled {
                        MissClass::Unavailable
                    } else if !index.files.contains_key(key) {
                        MissClass::NoEntry
                    } else {
                        MissClass::Missing
                    });
                }
                ReadOutcome::Refused(reason) => {
                    stores.counters.refused_record += 1;
                    return Err(MissClass::Record(reason));
                }
            }
        };
        // Missing membership is itself missing audit custody. Check the verified
        // same-context carrier before the entry-dependent binding; indexed keys
        // retain their existing real-edit and accepted-floor precedence below.
        if !index.files.contains_key(key) {
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
                return Err(MissClass::AuditCarrier);
            }
        }
        let expected = expected(
            source,
            snapshot_source,
            key,
            scope,
            index,
            interpretation,
            Some((record.format, record.record.allowlist)),
        )
        .ok_or(MissClass::NoEntry)?;
        // A future body revision is a downgrade hold even on changed input.
        if interpretation
            .accepted
            .is_some_and(|a| a.revision > effective_revision(snapshot_source))
        {
            return Err(MissClass::AcceptedFloor);
        }
        let original_matches = record.eligible(&expected).is_ok()
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
                return Err(MissClass::RealEdit(reason));
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
                return Err(MissClass::RealEdit(FullReason::Replaced));
            }
            if a.behind(metadata.len()) {
                if let Some(mut stores) = self.durable() {
                    Counters::bump(&mut stores.counters.ineligible, "accepted_body_floor");
                }
                return Err(MissClass::AcceptedFloor);
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
            return Err(MissClass::AuditCarrier);
        }
        index.files.get(key).ok_or(MissClass::NoEntry)?;

        let restored = self.durable_restore_record(
            snapshot_source,
            &record,
            &expected,
            path,
            scope,
            held,
            lease,
        );
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
                if let Some(owed) = owed {
                    return Err(MissClass::Unregistered(owed));
                }
                if original_matches {
                    if let Failure::Certificate(CertificateRefusal::Changed(
                        reason @ (FullReason::HeadChanged | FullReason::BoundaryChanged),
                    )) = class
                    {
                        return Err(MissClass::RealEdit(reason));
                    }
                }
                return Err(MissClass::Failure(class));
            }
        };
        if interpretation
            .accepted
            .is_some_and(|a| held.metadata().map_or(true, |m| a.behind(m.len())))
        {
            Counters::bump(&mut stores.counters.ineligible, "accepted_body_floor");
            return Err(MissClass::AcceptedFloor);
        }
        if let Some(slot) = stores.slot(source).as_mut() {
            slot.store.authorize(&record, &expected);
        }
        stores.counters.rederive_head_bytes += receipt.head_bytes;
        stores.counters.rederive_named_lines += receipt.named_lines;
        stores.counters.rederive_line_bytes += receipt.line_bytes;
        drop(stores);
        Ok(Ok(sampled_jsonl::CompletedNativeAcquisition {
            durable: Default::default(),
            checkpoint,
            reduction: Some(reduction),
            released: None,
            unsealed: false,
        }))
    }

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
            .restore(held, scope.clone())
            .map_err(Failure::Certificate)?;
        let decoded = codec::decode_bounded(&record.record.body, source, lease).map_err(
            |reason| match reason {
                crate::durable_tail_codec::DecodeFailure::Budget => Failure::Resource("decode"),
                crate::durable_tail_codec::DecodeFailure::Integrity => Failure::Corrupt,
            },
        )?;
        if decoded
            .cutover()
            .is_some_and(|stored| stored != codex_counting_version::cutover_unix_ms())
        {
            return Err(Failure::Ineligible(store::Ineligible::Scope));
        }
        // Metadata and bounded certificate samples precede every repeatable
        // resource refusal. Fund b4's content-only extractor before its input.
        let charge = decoded
            .content_charge()
            .map_err(|_| Failure::Resource("rederive_unfunded"))?;
        lease
            .charge(charge)
            .map_err(|_| Failure::Resource("rederive_unfunded"))?;
        let (reduction, receipt) = decoded
            .rederive_content(held)
            .map_err(Failure::NotRederived)?;
        let after =
            crate::transcript_acquisition::FileStamp::capture(held.metadata().map_err(|_| {
                Failure::Certificate(CertificateRefusal::Changed(FullReason::Replaced))
            })?)
            .map_err(|_| Failure::Certificate(CertificateRefusal::Changed(FullReason::Replaced)))?;
        if !before.same_content(&after) {
            return Err(Failure::Certificate(CertificateRefusal::Changed(
                FullReason::Replaced,
            )));
        }

        Ok((checkpoint, reduction, receipt))
    }

    /// Notes the file scope `key` is decided under this pass, for GC.
    pub(crate) fn durable_note_scope(&self, source: SnapshotSource, key: &str, scope: &Scope) {
        let (Some(source), Some(mut stores)) = (durable_source(source), self.durable()) else {
            return;
        };
        if let Some(slot) = stores.slot(source).as_mut() {
            if slot.decided.len() < store::MAX_RECORDS * 2 || slot.decided.contains_key(key) {
                slot.decided.insert(key.to_string(), scope.clone());
            }
        }
    }

    /// Records the selection `key`'s admitted reduction was acquired for:
    /// the scanned source-file fingerprint the scan wrote into its entry.
    pub(crate) fn durable_note_selection(&self, key: &str, source_file_fingerprint: &str) {
        if let Some(mut stores) = self.durable() {
            if stores.selected.len() < store::MAX_RECORDS * 2 || stores.selected.contains_key(key) {
                stores
                    .selected
                    .insert(key.to_string(), source_file_fingerprint.to_string());
            }
        }
    }

    /// Marks `key` admitted this pass: a write candidate after the next save.
    pub(super) fn durable_touch(&self, key: &str) {
        if let Some(mut stores) = self.durable() {
            if stores.touched.len() < store::MAX_RECORDS * 2 {
                stores.touched.insert(key.to_string());
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
        let store::LeaseWait::Granted(lease) = self.acquire_active(
            snapshot_source,
            (4 * store::RECORD_BYTES + WRITE_PASS_BYTES) as u64,
        ) else {
            return None;
        };
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
        let allowlist = codec::allowlist_digest(snapshot_source);
        let (touched, mut selected, namespace, identity_capture) = {
            let mut stores = self.durable()?;
            let slot = stores.slot(source).as_ref()?;
            let pass = (slot.namespace.clone(), slot.identity_capture);
            (
                std::mem::take(&mut stores.touched),
                std::mem::take(&mut stores.selected),
                pass.0,
                pass.1,
            )
        };
        let namespace = &namespace;
        let mut pending = Vec::new();
        let mut offered = BTreeMap::new();
        let mut later = BTreeSet::new();
        let mut budget = WRITE_PASS_BYTES;
        let mut not_persisted = Vec::new();
        let mut invalidate = BTreeSet::new();
        let mut peak = 0_u64;
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
                // of the saved selection, refuses, and any older record for
                // the key is invalidated: it must never restore.
                let acquired_for = selected.remove(&key);
                match index.files.get(&key) {
                    None => continue,
                    Some(entry)
                        if !entry.source_file_fingerprint.is_empty()
                            && acquired_for.as_deref()
                                == Some(entry.source_file_fingerprint.as_str()) => {}
                    Some(_) => {
                        invalidate.insert(store::key_digest(source, &key));
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
                let Some(certificate) = certificate_at(
                    &key,
                    &retained.checkpoint,
                    index,
                    unix_seconds(SystemTime::now()).unwrap_or(0),
                ) else {
                    not_persisted.push("certificate");
                    continue;
                };
                // Byte-budget deferral keeps the acquired provenance (the
                // requeue below carries it to the next save).
                if budget == 0 {
                    selected.extend(acquired_for.map(|fingerprint| (key.clone(), fingerprint)));
                    later.insert(key);
                    continue;
                }
                match codec::encode(
                    &retained.state,
                    budget.min(store::BODY_BYTES),
                    jsonl_line_cap() as u64,
                ) {
                    Ok(body) => {
                        budget = budget.saturating_sub(body.len());
                        peak = peak.max(body.len() as u64);
                        offered.insert(expected.binding.key, key);
                        pending.push(PendingRecord {
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
        let slot = stores.slot(source).as_mut()?;
        if source == DurableSource::ClaudeCode {
            for key in offered.values() {
                authorize_strict(slot, snapshot_source, key, index);
            }
        }
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
        let before = slot.store.counters().store_write_failed;
        let result = slot
            .store
            .write_after_save(writer, index.generation, index_length, pending);
        let after = slot.store.counters().store_write_failed;
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(_) => {
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
        let Some(source) = durable_source(snapshot_source) else {
            return Ok(());
        };
        let Some(mut stores) = self.durable() else {
            return Ok(());
        };
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
        let mut keep = BTreeMap::new();
        if !inventory.is_empty() {
            for key in index.files.keys() {
                let digest = store::key_digest(source, key);
                if !inventory.contains(&digest) {
                    continue;
                }
                let scope = slot.decided.get(key).and_then(|scope| {
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
                    let representation = slot.store.representation(&digest)?;
                    expected(
                        source,
                        snapshot_source,
                        key,
                        scope,
                        index,
                        &interpretation,
                        Some(representation),
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
                keep.insert(digest, scope);
            }
        }
        stores.counters.gc_keep_peak = stores.counters.gc_keep_peak.max(keep.len() as u64);
        let Some(slot) = stores.slot(source).as_mut() else {
            return Ok(());
        };
        slot.store.gc(writer, &context, &keep)
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
        match stores.slot(source).as_mut() {
            Some(slot) => slot.store.gc(writer, &[0; 32], &BTreeMap::new()),
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
            stores.counters.write_unlocked += 1;
        }
    }

    /// Local alarm on the `local_resources` carrier (#799), counts only: this
    /// source's held keys, T14 rebuilds and mode repairs since the last
    /// report (with totals), and once, the cause that disabled the store.
    /// A U hold keeps the source census retryable; T14 holds keep it healthy.
    pub(crate) fn durable_alarm(&self, snapshot_source: SnapshotSource) {
        #[derive(serde::Serialize)]
        struct Alarm {
            held_keys: [u64; 2],
            t14_rebuild: [u64; 2],
            t14_rebuild_full_started: u64,
            mode_repaired: [u64; 2],
            retail_exhausted: [u64; 2],
            retail_exhausted_paced: [u64; 2],
            #[serde(skip_serializing_if = "Option::is_none")]
            store_disabled: Option<&'static str>,
        }
        let Some(source) = durable_source(snapshot_source) else {
            return;
        };
        let Some(mut stores) = self.durable() else {
            return;
        };
        let recovery = stores.counters.recovery_full[source as usize];
        let Some(slot) = stores.slot(source).as_mut() else {
            return;
        };
        let (store, disabled) = (slot.store.counters(), slot.store.disabled());
        let now = [
            slot.held,
            store.t14_rebuild,
            store.mode_repaired,
            u64::from(disabled.is_some()),
            store.t14_rebuild_full_started,
            recovery[0],
            recovery[1],
        ];
        let last = std::mem::replace(&mut slot.reported, now);
        drop(stores);
        crate::local_resource_diagnostics::durable_tail_alarm(snapshot_source.api_slug(), &store);
        if now != last {
            let pair = |n: usize| [now[n].saturating_sub(last[n]), now[n]];
            crate::local_resource_diagnostics::durable_tail_alarm(
                snapshot_source.api_slug(),
                &Alarm {
                    held_keys: pair(0),
                    t14_rebuild: pair(1),
                    t14_rebuild_full_started: store.t14_rebuild_full_started,
                    mode_repaired: pair(2),
                    retail_exhausted: pair(5),
                    retail_exhausted_paced: pair(6),
                    store_disabled: disabled.filter(|_| last[3] == 0),
                },
            );
        }
    }

    /// This process's durable counts and the source's store counters.
    pub(crate) fn durable_counters(
        &self,
        snapshot_source: SnapshotSource,
    ) -> Option<(Counters, store::StoreCounters)> {
        let source = durable_source(snapshot_source)?;
        let mut stores = self.durable()?;
        let mut counters = stores.counters.clone();
        counters.retail_full[..2].copy_from_slice(&counters.recovery_full[source as usize]);
        counters.retail_full[2] = counters.pace_evicted[source as usize];
        let store = stores.slot(source).as_ref()?.store.counters();
        Some((counters, store))
    }
}

/// The class returned by the attempted restore, never reconstructed from totals.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MissClass {
    AcceptedFloor,
    RealEdit(FullReason),
    Unavailable,
    NoEntry,
    AuditCarrier,
    SelectionCleared,
    HistoryOwed,
    Missing,
    Record(store::Refusal),
    Failure(Failure),
    /// A non-transient resource refusal whose held file grew: ordinary Full.
    Resource(&'static str),
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
        if !matches!(self, Self::AuditCarrier) {
            return None;
        }
        let entry = index.files.get_mut(key)?;
        let due = entry
            .unverified_deadline()
            .filter(|due| *due > 0)
            .map_or(now, |due| due.min(now));
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
            Self::HistoryOwed => "ineligible.history_owed",
            Self::Missing => "missing",
            Self::Resource(phase) | Self::Failure(Failure::Resource(phase)) => prefixed!(
                "resource_full.",
                phase,
                "decode",
                "cache_transit",
                "stores_unavailable",
                "input",
                "cache_key",
                "certificate_scope",
                "rederive_unfunded"
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
                store::Refusal::ReceiptPending => "refused_record.receipt_pending",
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
    Pending,
    Miss(MissClass),
    /// Known correctness hold, census-neutral; never a Full fallback.
    FloorHeld,
    /// Structural eligibility; pace is spent after page/cursor deferral.
    Degraded,
    Held(store::Refusal),
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
                Self::Restored(taken, lease) => Some(RestoredForTest {
                    taken: Some(taken),
                    lease: Some(lease),
                }),
                Self::Miss(_) | Self::Degraded => None,
                Self::FloorHeld => panic!("ordinary restore unexpectedly behind accepted body"),
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
#[path = "durable_tail_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
pub(crate) use tests::seed_pinned_v1;
