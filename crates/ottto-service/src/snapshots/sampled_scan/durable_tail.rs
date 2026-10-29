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
pub(crate) const STORES_RESIDENT_BOUND: usize = 2 * store::MAX_RECORDS * 128;

/// Head re-parse bytes of restores, per source, for the process lifetime.
/// The re-parse bypasses the reread guard (bounded at `HEAD_BOUND`, on a RAM
/// miss only), so the census pass line reports it beside the guard's own
/// counters (SOURCE N1).
static REDERIVE_HEAD_BYTES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

pub(crate) fn rederive_head_bytes_total(source: SnapshotSource) -> u64 {
    durable_source(source).map_or(0, |source| {
        REDERIVE_HEAD_BYTES[source as usize].load(Ordering::Relaxed)
    })
}

/// Content-free outcome counts, by class. Field paths are static names; no
/// id, path or value is ever counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) restore_attempts: u64,
    pub(crate) restored: u64,
    pub(crate) missing: u64,
    pub(crate) refused_record: u64,
    pub(crate) durable_held: [u64; 5],
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
            "ottto-service: durable_tail source={} rederive_head_bytes={} \
             rederive_named_lines={} rederive_line_bytes={} not_persisted={{{}}} \
             write_deferred={} write_unlocked={} peak_body_bytes={} disk_records={} disk_bytes={} \
             bytes_written={} records_written={} records_clean={} store_budget_refused={} \
             bytes_read={} format_hold[newer,unknown,undecodable,unbindable,known_corrupt]={:?} durable_held={:?} held_census[kept,invalidated]={:?} \
             guard_header_bytes={} guard_verify_bytes={} delete_verify_bytes={} overwrite_verify_bytes={} \
             uninventoried_records={} store_write_skipped[unknown,inventory_overflow]={:?} \
             gc_records_deleted={} gc_records_read={} gc_bytes_read={} gc_keep_peak={} \
             records_invalidated={} peak_codec_bytes={} t14_rebuild_full_started={}",
            source.api_slug(),
            self.rederive_head_bytes,
            self.rederive_named_lines,
            self.rederive_line_bytes,
            classes(&self.not_persisted),
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
    /// [held, t14_rebuild, mode_repaired, disabled, rebuild_full].
    held: u64,
    reported: [u64; 5],
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
}

impl Stores {
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

/// The interpretation inputs a record binds to beyond the file scope.
pub(crate) struct Interpretation<'a> {
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

fn expected(
    source: DurableSource,
    snapshot_source: SnapshotSource,
    key: &str,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
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
            scope: replay_scope(snapshot_source, scope, index, interpretation, None),
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
    let body_revision = replay.filter(|row| row.kind == ObligationKind::BodyWitness);
    let money_rule = replay.filter(|row| row.kind == ObligationKind::MoneyRule);
    store::replay_scope_digest(
        &store::scope_digest(
            &scope.0,
            &codec::allowlist_digest(source),
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
fn certificate_at(key: &str, checkpoint: &Checkpoint) -> Option<DurableCertificate> {
    let mut certificate = checkpoint.durable_certificate(0)?;
    let metadata = std::fs::metadata(key).ok()?;
    if metadata.dev() != certificate.device || metadata.ino() != certificate.inode {
        return None;
    }
    certificate.birth_nanos = birth_unix_nanos(&metadata);
    Some(certificate)
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

impl SharedCache {
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
                reported: [0; 5],
            });
        }
    }

    pub(crate) fn durable_hold(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
    ) -> Option<store::Refusal> {
        self.durable_guard(snapshot_source, key, false)
    }

    fn durable_guard(
        &self,
        snapshot_source: SnapshotSource,
        key: &str,
        restore_recheck: bool,
    ) -> Option<store::Refusal> {
        let ram = !restore_recheck && self.retained().is_ok_and(|ram| ram.peek(key).is_some());
        let source = durable_source(snapshot_source)?;
        let held = self
            .durable()?
            .slot(source)
            .as_mut()?
            .store
            .hold(&store::key_digest(source, key));
        if held == Some(store::Refusal::Corrupt) && ram {
            Counters::bump(
                &mut self.durable()?.counters.not_persisted,
                "known_corrupt_memory_only",
            );
            return None;
        }
        held
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
        census.record_unreadable(UnreadableCause::Reduction, 1);
    }

    /// Restores `key` from the durable store into the RAM cache and takes it,
    /// or `None` (the read is then Full, with nothing left behind). `held` is
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
            Err(class) => self
                .durable_guard(snapshot_source, key, true)
                .map_or(RestoreOutcome::Miss(class), RestoreOutcome::Held),
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
    ) -> Result<Taken<CachedJsonlReduction>, MissClass> {
        let source = durable_source(snapshot_source).ok_or(MissClass::Unavailable)?;
        let expected = expected(source, snapshot_source, key, scope, index, interpretation)
            .ok_or(MissClass::NoEntry)?;
        let allowlist = codec::allowlist_digest(snapshot_source);
        let record = {
            let mut stores = self.durable().ok_or(MissClass::Unavailable)?;
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
                Some(slot) => (
                    slot.store.read(&expected.binding.key, &allowlist),
                    slot.store.disabled().is_some(),
                ),
                None => return Err(MissClass::Unavailable),
            };
            match outcome {
                ReadOutcome::Found(record) => record,
                ReadOutcome::Missing => {
                    stores.counters.missing += 1;
                    return Err(if disabled {
                        MissClass::Unavailable
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
                if let Some(owed) = owed {
                    return Err(MissClass::Unregistered(owed));
                }
                return Err(MissClass::Failure(class));
            }
        };
        stores.counters.rederive_head_bytes += receipt.head_bytes;
        REDERIVE_HEAD_BYTES[source as usize].fetch_add(receipt.head_bytes, Ordering::Relaxed);
        stores.counters.rederive_named_lines += receipt.named_lines;
        stores.counters.rederive_line_bytes += receipt.line_bytes;
        drop(stores);
        // The restored copy is charged to the RAM cache exactly as a retained
        // copy is admitted; a refused charge leaves the read Full.
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
            return Err(MissClass::BudgetRefused);
        }
        stores.counters.restored += 1;
        #[cfg(test)]
        super::transition_fixture::reach(super::transition_fixture::CrashPoint::Restore);
        drop(stores);
        self.take(key).ok_or(MissClass::TakeLost)
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
        let (checkpoint, _) = record
            .record
            .certificate
            .restore(held, scope.clone())
            .map_err(Failure::Certificate)?;
        let decoded = codec::decode(&record.record.body, source).map_err(|_| Failure::Corrupt)?;
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
                ) else {
                    continue;
                };
                let Some(certificate) = certificate_at(&key, &retained.checkpoint) else {
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
        let slot = stores.slot(source).as_mut()?;
        if !invalidate.is_empty() {
            let _ = slot.store.remove_keys(writer, &invalidate);
        }
        let receipt = slot
            .store
            .write_after_save(writer, index.generation, pending)
            .ok()?;
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
        let allowlist = codec::allowlist_digest(snapshot_source);
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
                    let interpretation = Interpretation::of(
                        snapshot_source,
                        key,
                        index,
                        identity_capture,
                        namespace,
                    );
                    expected(source, snapshot_source, key, scope, index, &interpretation)
                        .map(|expected| expected.binding.scope)
                });
                keep.insert(digest, scope);
            }
        }
        stores.counters.gc_keep_peak = stores.counters.gc_keep_peak.max(keep.len() as u64);
        let Some(slot) = stores.slot(source).as_mut() else {
            return Ok(());
        };
        slot.store.gc(writer, &context, &allowlist, &keep)
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
            Some(slot) => slot.store.gc(
                writer,
                &[0; 32],
                &codec::allowlist_digest(snapshot_source),
                &BTreeMap::new(),
            ),
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
            #[serde(skip_serializing_if = "Option::is_none")]
            store_disabled: Option<&'static str>,
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
        let (store, disabled) = (slot.store.counters(), slot.store.disabled());
        let now = [
            slot.held,
            store.t14_rebuild,
            store.mode_repaired,
            u64::from(disabled.is_some()),
            store.t14_rebuild_full_started,
        ];
        let last = std::mem::replace(&mut slot.reported, now);
        drop(stores);
        if now != last {
            let pair = |n: usize| [now[n].saturating_sub(last[n]), now[n]];
            crate::local_resource_diagnostics::durable_tail_alarm(
                snapshot_source.api_slug(),
                &Alarm {
                    held_keys: pair(0),
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
        let counters = stores.counters.clone();
        let store = stores.slot(source).as_ref()?.store.counters();
        Some((counters, store))
    }
}

/// The class returned by the attempted restore, never reconstructed from totals.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MissClass {
    Unavailable,
    NoEntry,
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
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Failure {
    Ineligible(store::Ineligible),
    Certificate(CertificateRefusal),
    Corrupt,
    NotRederived(Refuse),
}

#[cfg(test)]
#[path = "durable_tail_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "transition_seed.rs"]
pub(crate) mod transition_seed;
