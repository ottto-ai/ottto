//! M1 durable warm-cache reuse: the RAM cache's link to the durable-tail store
//! (CONTRACT.md M1 contracts 1 and 2; SOURCE field ruling with Amendment 1).
//!
//! - Restore runs on a RAM miss for an indexed file that may sample. The
//!   record must bind to the loaded, committed index (generation, entry,
//!   context, scope with format, allowlist, identity contract and counting
//!   view), its certificate must admit on the held FD, its body must decode
//!   and its content fields must re-derive. The copy is then charged through
//!   the ordinary cache admission and taken like any retained copy, so the
//!   existing `prepare_acquisition` decides Unchanged, Tail or Full. Any
//!   refusal leaves nothing behind: the read is Full. Restore advances no
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
#[cfg(test)]
pub(crate) const STORES_RESIDENT_BOUND: usize =
    2 * store::MAX_RECORDS * 128 + super::RETAIL_RESERVE_BYTES;

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

const PACE_SECS: u64 = 6 * 3600;
const _: () = assert!(PACE_SECS < 86_400);

/// Content-free outcome counts, by class. Field paths are static names; no
/// id, path or value is ever counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) restore_attempts: u64,
    pub(crate) restored: u64,
    pub(crate) original_v1_mapped: u64,
    pub(crate) durable_restore_after_selection_clear: u64,
    pub(crate) objects: [u64; 3],
    pub(crate) s2_skipped_object_changed: u64,
    pub(crate) retail_attempts: u64,
    pub(crate) retail_keys: u64,
    pub(crate) retail_full: [u64; 3],
    pub(crate) stale_full: [u64; 3],
    pub(crate) missing: u64,
    pub(crate) upgrade_state_missing: u64,
    pub(crate) refused_record: u64,
    pub(crate) durable_held: [u64; 6],
    pub(crate) held_census: [u64; 2],
    pub(crate) ineligible: BTreeMap<&'static str, u64>,
    pub(crate) certificate_refused: BTreeMap<&'static str, u64>,
    pub(crate) corrupt_body: u64,
    pub(crate) not_rederived: BTreeMap<&'static str, u64>,
    pub(crate) budget_refused: u64,
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
            "ottto-service: durable_tail source={} original_v1_mapped={} durable_restore_after_selection_clear={} objects[same,unknown,changed]={:?} s2_skipped_object_changed={} \
             retail_attempts={} retail_keys={} retail_exhausted[full,paced,pace_evicted]={:?} tail_read_bytes={} budget_refused_retail_old_bytes={} repeated_physical_old_bytes={} upgrade_state_missing={} \
             rederive_head_bytes={} rederive_named_lines={} rederive_line_bytes={} not_persisted={{{}}} ineligible={{{}}} \
             write_deferred={} write_unlocked={} peak_body_bytes={} disk_records={} disk_bytes={} \
             bytes_written={} records_written={} records_clean={} store_budget_refused={} \
             bytes_read={} format_hold[newer,unknown,undecodable,unbindable,known_corrupt,behind_accepted]={:?} durable_held={:?} held_census[kept,invalidated]={:?} \
             guard_header_bytes={} guard_verify_bytes={} delete_verify_bytes={} overwrite_verify_bytes={} \
             uninventoried_records={} store_write_skipped[unknown,inventory_overflow]={:?} \
             gc_records_deleted={} gc_records_read={} gc_bytes_read={} gc_keep_peak={} \
             records_invalidated={} mutation_unproved={} peak_codec_bytes={} t14_rebuild_full_started={}",
            source.api_slug(),
            self.original_v1_mapped,
            self.durable_restore_after_selection_clear,
            self.objects,
            self.s2_skipped_object_changed,
            self.retail_attempts,
            self.retail_keys,
            self.retail_full,
            retail_bytes(source, 0),
            retail_bytes(source, 1),
            retail_bytes(source, 1),
            self.upgrade_state_missing,
            self.rederive_head_bytes,
            self.rederive_named_lines,
            self.rederive_line_bytes,
            classes(&self.not_persisted),
            classes(&self.ineligible),
            self.write_deferred,
            self.write_unlocked,
            self.peak_body_bytes,
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
    store: DurableTailStore,
    /// File scopes decided this pass, by key: GC drops a record bound to
    /// another scope. Keys not decided this pass keep their records.
    decided: BTreeMap<String, Scope>,
    /// The pass's sampled scope and identity-capture mode.
    namespace: Scope,
    identity_capture: bool,
    /// Keys held (U) by this source, and the totals the last alarm reported:
    /// [held, t14_rebuild, mode_repaired, disabled, rebuild_full,
    /// upgrade_state_missing, old_binding_no_match, retail_exhausted[3], stale_full[3]].
    held: u64,
    old_binding_no_match: u64,
    reported: [u64; 13],
}

/// Process-lifetime durable state beside the RAM cache.
#[derive(Default)]
pub(crate) struct Stores {
    slots: [Option<Slot>; crate::snapshots::durable_sources::SOURCES.len()],
    /// Keys admitted to the RAM cache since their source's last write.
    touched: BTreeSet<String>,
    /// Selection provenance: the source-file fingerprint each admitted
    /// reduction was acquired for. A write binds a reduction only to a
    /// committed entry with this same fingerprint; local-hold settlement that
    /// reverts or clears the entry makes it refuse (F2).
    selected: BTreeMap<String, String>,
    counters: Counters,
    // Source+key only: never clear on passes, scope changes or cache eviction.
    retail_spent: BTreeMap<store::Digest32, Box<KeyCustody>>,
    retail_full_at: BTreeMap<store::Digest32, std::time::Instant>,
    #[cfg(test)]
    retail_full_now: Option<std::time::Instant>,
    upgrade_reads: std::sync::Arc<AtomicU64>,
}

#[derive(Default)]
struct KeyCustody {
    spent: Option<(u64, std::time::Instant)>,
    original: Option<store::MutationWitness>,
    upgrade_started: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
fn custody_node_bytes() -> Option<usize> {
    crate::heap_layout_bound::tree_node_bytes::<store::Digest32, Box<KeyCustody>>()?
        .checked_add(std::mem::size_of::<KeyCustody>() + std::mem::align_of::<KeyCustody>())?
        .checked_add(64) // Both Arc payloads/headers/alignment, conservatively per node.
}

impl Stores {
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

#[derive(Clone, Copy)]
pub(crate) struct AcceptedFloor {
    pub(crate) end: u64,
    revision: u64,
    birth: u64,
    generation: u64,
    entry: store::Digest32,
    strict: bool,
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
                .format,
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
        &store::scope_digest_for(
            format,
            &scope.0,
            &allowlist,
            &interpretation.identity_contract,
            &interpretation.counting_view,
        ),
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
    if record.format != 1
        || record.record.allowlist != codec::allowlist_digest(SnapshotSource::ClaudeCode)
    {
        return Err("old_binding_representation");
    }
    let current = effective_revision(SnapshotSource::ClaudeCode);
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

/// Inline ownership; later active custody extends this same owner.
#[derive(Default)]
pub(crate) struct DurableCustody {
    retail: Option<RetailAttempt>,
    upgrade: Option<UpgradeRead>,
}
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
}

pub(crate) struct UpgradeRead {
    object: (u64, u64, u64),
    started: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    local_started: bool,
    total: std::sync::Arc<AtomicU64>,
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
    prior: &mut Option<store::MutationWitness>,
) {
    slot.store
        .revoke(&store::key_digest(DurableSource::ClaudeCode, key));
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
    if let Ok((expected, _)) = claude_expected(key, scope, index, &interpretation, &record) {
        if prior.is_none() {
            *prior = slot.store.mutation_witness(&record, &expected);
        }
        if let Some(proof) = prior.as_ref() {
            slot.store.authorize_witness(&record, &expected, proof);
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
        if custody_node_bytes().is_none_or(|n| n > 1024) {
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
        if let Some((high, spent)) = stores.retail_spent.get(&key).and_then(|c| c.spent.as_ref()) {
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
        let first = stores.retail_spent[&key].spent.is_none();
        stores.counters.retail_keys += u64::from(first);
        stores.counters.retail_attempts += 1;
        stores.retail_spent.get_mut(&key).expect("funded").spent = Some((end, now));
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
        now: std::time::Instant,
    ) -> bool {
        self.paced_full(key, file, accepted_end, now, None)
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
        self.paced_full(key, file, a.end, std::time::Instant::now(), Some(cause))
    }

    fn paced_full(
        &self,
        key: &str,
        file: &File,
        accepted_end: u64,
        now: std::time::Instant,
        cause: Option<usize>,
    ) -> bool {
        if !file.metadata().is_ok_and(|m| m.len() > accepted_end) {
            return false;
        }
        let Some(mut stores) = self.durable() else {
            return true;
        };
        #[cfg(test)]
        let now = stores.retail_full_now.unwrap_or(now);
        let interval = std::time::Duration::from_secs(PACE_SECS);
        stores.retail_full_at.retain(|_, at| {
            now.checked_duration_since(*at)
                .is_none_or(|age| age < interval)
        });
        let key = store::key_digest(DurableSource::ClaudeCode, key);
        if stores.retail_full_at.contains_key(&key) {
            if cause.is_none() {
                stores.counters.retail_full[1] += 1;
            } else {
                Counters::bump(
                    &mut stores.counters.ineligible,
                    if cause == Some(3) {
                        "old_binding_no_match.paced"
                    } else {
                        "stale_full.paced"
                    },
                );
            }
            return false;
        }
        if stores.retail_full_at.len() >= 2 * store::MAX_RECORDS {
            let oldest = stores
                .retail_full_at
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                stores.retail_full_at.remove(&oldest);
                stores.counters.retail_full[2] += 1;
            }
        }
        stores.retail_full_at.insert(key, now);
        if cause == Some(3) {
            if let Some(slot) = stores.slot(DurableSource::ClaudeCode).as_mut() {
                slot.old_binding_no_match += 1;
            }
        } else if let Some(cause) = cause {
            stores.counters.stale_full[cause] += 1;
        } else {
            stores.counters.retail_full[0] += 1;
        }
        true
    }

    pub(super) fn durable(&self) -> Option<StoresGuard<'_>> {
        debug_assert!(!stores_held(), "Stores cannot be nested");
        let guard = self.durable.lock().ok()?;
        STORES_HELD.with(|held| held.set(true));
        Some(StoresGuard(guard))
    }
    // R2 transitional old_binding_no_match; A1b2d removes or converts this arm.
    pub(crate) fn no_match_full(
        &self,
        key: &str,
        file: &File,
        a: Option<AcceptedFloor>,
    ) -> Option<()> {
        let a = a?;
        if a.revision > effective_revision(SnapshotSource::ClaudeCode) {
            return None;
        }
        self.paced_full(key, file, a.end, std::time::Instant::now(), Some(3))
            .then_some(())
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
            current.store.begin_pass();
            current.namespace = namespace.clone();
            current.identity_capture = identity_capture;
        } else {
            *slot = Some(Slot {
                store: DurableTailStore::new(dir.clone(), source),
                dir,
                decided: BTreeMap::new(),
                namespace: namespace.clone(),
                identity_capture,
                held: 0,
                old_binding_no_match: 0,
                reported: [0; 13],
            });
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
                (snapshot_source == SnapshotSource::ClaudeCode
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
    pub(crate) fn durable_member_hold(
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

    pub(crate) fn durable_full_hold(
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

    pub(in crate::snapshots) fn upgrade_read(
        &self,
        key: &str,
        file: &File,
    ) -> Result<Option<UpgradeRead>, RetailHold> {
        let key = store::key_digest(DurableSource::ClaudeCode, key);
        let mut stores = self.durable().ok_or(RetailHold::AccountingLost)?;
        if !stores
            .slot(DurableSource::ClaudeCode)
            .as_ref()
            .is_some_and(|s| s.store.absent(&key))
        {
            return Ok(None);
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
        if let Some(mut stores) = self.durable() {
            Counters::bump(
                &mut stores.counters.ineligible,
                match reason {
                    RetailHold::Exhausted => "retail_hold.exhausted",
                    RetailHold::AccountingLost => "retail_hold.accounting_lost",
                    RetailHold::Ineligible => "retail_hold.ineligible",
                },
            );
        }
        self.durable_stale_hold(source, index, candidate);
    }
    pub(in crate::snapshots) fn durable_stale_hold(
        &self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        candidate: &CandidateFile,
    ) {
        let kept = source == SnapshotSource::ClaudeCode
            && claude_request_census::retain_held(index, candidate);
        if let Some(mut stores) = self.durable() {
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
        census.record_unreadable(UnreadableCause::Reduction, 1);
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
    /// or a typed stale/integrity hold. A missing record keeps its existing Full path. `held` is
    /// the parser's opened FD for `path`, not yet read; a duplicate of it
    /// serves the bounded re-derivation, and the read plan repositions it.
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
        if snapshot_source == SnapshotSource::Codex
            && refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)
                .is_err()
        {
            return RestoreOutcome::Miss(MissClass::Failure(Failure::NotRederived(
                Refuse::NotRederivable("compressed"),
            )));
        }
        // The common guard held U/T14 before acquisition; this sees class changes since.
        match self.restore_known(
            snapshot_source,
            key,
            path,
            scope,
            held,
            index,
            interpretation,
        ) {
            Ok(taken) => RestoreOutcome::Restored(Box::new(taken)),
            Err(RestoreOutcome::Miss(class @ MissClass::AuditCarrier)) => {
                RestoreOutcome::Miss(class)
            }
            Err(RestoreOutcome::Miss(class)) => self
                .durable_guard(snapshot_source, key, true, index, &mut None)
                .map_or(RestoreOutcome::Miss(class), RestoreOutcome::Held),
            // Typed stale/held outcomes (P11-S2, original-binding proof) are final.
            Err(outcome) => outcome,
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
    ) -> Result<Taken<CachedJsonlReduction>, RestoreOutcome> {
        let source = durable_source(snapshot_source).ok_or(MissClass::Unavailable)?;
        let store_key = store::key_digest(source, key);
        let record = {
            let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
            if !index.files.contains_key(key) && stores.slot(source).is_none() {
                return Err(MissClass::NoEntry.into());
            }
            stores.counters.restore_attempts += 1;
            // Codex keeps its predecessor selection gate; Claude first proves the original binding.
            if source == DurableSource::Codex
                && index
                    .files
                    .get(key)
                    .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
            {
                Counters::bump(&mut stores.counters.ineligible, "selection_cleared");
                return Err(MissClass::SelectionCleared.into());
            }
            // Revision adoption and money-rule replay both use this debt.
            // Check before disk I/O: an owed raw replay may never be served
            // by an otherwise valid pre-replay reduction plus Tail.
            if index.effective_upload_body_witness_revision_requires_adoption(key) {
                Counters::bump(&mut stores.counters.ineligible, "history_owed");
                return Err(MissClass::HistoryOwed.into());
            }
            let (outcome, disabled) = match stores.slot(source).as_mut() {
                Some(slot) => (slot.store.read(&store_key), slot.store.disabled().is_some()),
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
        if source == DurableSource::ClaudeCode {
            let (original, revision) =
                match claude_expected(key, scope, index, interpretation, &record) {
                    Ok(proof) => proof,
                    Err(reason) => return Err(self.stale(reason)),
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
        }
        let restored =
            self.durable_restore_record(snapshot_source, &record, &expected, path, scope, held);
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
        let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
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
                    Failure::Corrupt => counters.corrupt_body += 1,
                    Failure::NotRederived(refuse) => {
                        Counters::bump(&mut counters.not_rederived, refuse_class(refuse))
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
                    return Err(MissClass::Unregistered(owed).into().into());
                }
                return Err(MissClass::Failure(class).into().into());
            }
        };
        if let Some(slot) = stores.slot(source).as_mut() {
            slot.store.authorize(&record, &expected);
        }
        if source == DurableSource::ClaudeCode && stores.fund_key(store_key) {
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
        }
        stores.counters.rederive_head_bytes += receipt.head_bytes;
        REDERIVE_HEAD_BYTES[source as usize].fetch_add(receipt.head_bytes, Ordering::Relaxed);
        stores.counters.rederive_named_lines += receipt.named_lines;
        stores.counters.rederive_line_bytes += receipt.line_bytes;
        drop(stores);
        // The restored copy is charged to the RAM cache exactly as a retained
        // copy is admitted; a refused charge leaves the read Full.
        if source == DurableSource::ClaudeCode
            && interpretation
                .accepted
                .is_some_and(|a| !held.metadata().is_ok_and(|m| m.len() >= a.end))
        {
            return Err(self.stale("behind_accepted.legacy"));
        }
        let admitted = self.insert_admitted(
            key.to_string(),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint,
                reduction: Some(reduction),
                released: None,
                unsealed: false,
            },
            0,
        );
        let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
        if !admitted {
            stores.counters.budget_refused += 1;
            return Err(MissClass::BudgetRefused.into());
        }
        stores.counters.restored += 1;
        stores.counters.durable_restore_after_selection_clear += u64::from(
            source == DurableSource::ClaudeCode
                && index
                    .files
                    .get(key)
                    .is_some_and(|e| e.source_file_fingerprint.is_empty()),
        );
        drop(stores);
        self.take(key)
            .ok_or(RestoreOutcome::Miss(MissClass::TakeLost))
    }

    fn durable_restore_record(
        &self,
        source: SnapshotSource,
        record: &store::DurableRecord,
        expected: &Expected,
        path: &Path,
        scope: &Scope,
        held: &mut File,
    ) -> Result<(Checkpoint, CachedJsonlReduction, codec::RederiveReceipt), Failure> {
        if source == SnapshotSource::Codex {
            refuse_compressed_codex(Some(path), None, CodexZstCause::DurableTailUnsupported)
                .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("compressed")))?;
        }
        record.eligible(expected).map_err(Failure::Ineligible)?;
        let decoded = codec::decode(&record.record.body, source).map_err(|_| Failure::Corrupt)?;
        if source == SnapshotSource::ClaudeCode && decoded.counting().is_some() {
            return Err(Failure::Corrupt);
        }
        if decoded
            .cutover()
            .is_some_and(|stored| stored != codex_counting_version::cutover_unix_ms())
        {
            return Err(Failure::Ineligible(store::Ineligible::Scope));
        }
        let (checkpoint, _) = record
            .record
            .certificate
            .restore(held, scope.clone())
            .map_err(Failure::Certificate)?;
        let mut rederive = held
            .try_clone()
            .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("descriptor")))?;
        let parser = codec::rederive_parser(
            rederive
                .try_clone()
                .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("descriptor")))?,
            path,
            &decoded,
        )
        .map_err(|_| Failure::NotRederived(Refuse::NotRederivable("parser")))?;
        let (reduction, receipt) = decoded
            .rederive(parser, &mut rederive, jsonl_line_cap() as u64)
            .map_err(Failure::NotRederived)?;
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
        let source = durable_source(snapshot_source)?;
        let allowlist = source.properties().allowlist();
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
                    budget.min(store::RECORD_BYTES),
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
                authorize_strict(
                    stores.slots[source.slot()].as_mut()?,
                    snapshot_source,
                    key,
                    index,
                    &mut stores.retail_spent.get_mut(&digest)?.original,
                );
            }
        }
        let slot = stores.slot(source).as_mut()?;
        if !invalidate.is_empty() {
            let _ = slot.store.remove_keys(writer, &invalidate);
        }
        let receipt = match slot
            .store
            .write_after_save(writer, index.generation, pending)
        {
            Ok(receipt) => receipt,
            Err(_) => {
                for key in offered
                    .values()
                    .filter(|_| source == DurableSource::ClaudeCode)
                {
                    if let Some(entry) = index.files.get(key) {
                        stores
                            .selected
                            .insert(key.clone(), entry.source_file_fingerprint.clone());
                        stores.touched.insert(key.clone());
                    }
                }
                return None;
            }
        };
        if source == DurableSource::ClaudeCode {
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
                        c.original = None;
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
                    if source == DurableSource::ClaudeCode {
                        let ReadOutcome::Found(record) = slot.store.read(&digest) else {
                            return None;
                        };
                        let (original, _) =
                            match claude_expected(key, scope, index, &interpretation, &record) {
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
                    expected(
                        source,
                        snapshot_source,
                        key,
                        scope,
                        index,
                        &interpretation,
                        Some((format, allowlist, effective_revision(snapshot_source))),
                    )
                    .map(|expected| expected.binding.scope)
                });
                keep.insert(digest, scope);
            }
        }
        for (reason, n) in mapping_holds {
            *stores.counters.ineligible.entry(reason).or_default() += n;
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
            old_binding_no_match: [u64; 2],
            context: [u64; 2],
            restore_semantics: [u64; 2],
            revision_adoption_required: [u64; 2],
            retail_exhausted: [u64; 2],
            retail_exhausted_paced: [u64; 2],
            pace_evicted: [u64; 2],
            upgrade_state_missing: [u64; 2],
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
            upgrade,
            slot.old_binding_no_match,
            retail[0],
            retail[1],
            retail[2],
            stale[0],
            stale[1],
            stale[2],
        ];
        let last = std::mem::replace(&mut slot.reported, now);
        drop(stores);
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
                    retail_exhausted: pair(7),
                    retail_exhausted_paced: pair(8),
                    pace_evicted: pair(9),
                    upgrade_state_missing: pair(5),
                    t14_rebuild: pair(1),
                    t14_rebuild_full_started: store.t14_rebuild_full_started,
                    mode_repaired: pair(2),
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
        if source == DurableSource::ClaudeCode {
            counters.upgrade_state_missing = stores.upgrade_reads.load(Ordering::Relaxed);
        }
        if source != DurableSource::ClaudeCode {
            counters.retail_full = [0; 3];
            counters.stale_full = [0; 3];
        }
        let store = stores.slot(source).as_ref()?.store.counters();
        Some((counters, store))
    }
}

/// The class returned by the attempted restore, never reconstructed from totals.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MissClass {
    Unavailable,
    NoEntry,
    AuditCarrier,
    SelectionCleared,
    HistoryOwed,
    Missing,
    Record(store::Refusal),
    Failure(Failure),
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
            Self::Unavailable => "unavailable",
            Self::NoEntry => "no_entry",
            Self::AuditCarrier => "ineligible.audit_carrier",
            Self::SelectionCleared => "ineligible.selection_cleared",
            Self::HistoryOwed => "ineligible.history_owed",
            Self::Missing => "missing",
            Self::BudgetRefused => "budget_refused",
            Self::TakeLost => "restore_take_lost",
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
    Restored(Box<Taken<CachedJsonlReduction>>),
    Miss(MissClass),
    Held(store::Refusal),
    Stale(&'static str),
}
impl From<MissClass> for RestoreOutcome {
    fn from(class: MissClass) -> Self {
        Self::Miss(class)
    }
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

#[derive(Clone, Copy, Debug)]
pub(crate) enum Failure {
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
pub(in crate::snapshots) mod tests;

#[cfg(test)]
pub(crate) use tests::seed_pinned_v1;
