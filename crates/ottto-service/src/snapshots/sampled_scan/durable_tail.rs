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
//! part of its state budget: each holds at most `MAX_RECORDS` 64-byte digest
//! pairs (`STORES_RESIDENT_BOUND`).
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::super::*;
use super::SharedCache;
use crate::durable_tail_codec::Refuse;
use crate::durable_tail_store::{
    self as store, Binding, DurableSource, DurableTailStore, Expected, PendingRecord, ReadOutcome,
    SingleWriter,
};
use crate::transcript_acquisition::{
    birth_unix_nanos, Checkpoint, DurableCertificate, FullReason, Scope,
};
use crate::transcript_cache::Taken;
use sampled_jsonl::durable as codec;
use sampled_jsonl::CachedJsonlReduction;

/// Encoded bytes one post-save write may produce, so encoding under the
/// retained lock stays bounded. Entries past it are deferred to a later save.
pub(crate) const WRITE_PASS_BYTES: usize = 8 * 1024 * 1024;

/// Upper bound of both stores' resident digest maps (two sources).
pub(crate) const STORES_RESIDENT_BOUND: usize = 2 * store::MAX_RECORDS * 128;

/// Content-free outcome counts, by class. Field paths are static names; no
/// id, path or value is ever counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) restore_attempts: u64,
    pub(crate) restored: u64,
    pub(crate) missing: u64,
    pub(crate) refused_record: u64,
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
    pub(crate) peak_body_bytes: u64,
}

impl Counters {
    fn bump(map: &mut BTreeMap<&'static str, u64>, class: &'static str) {
        *map.entry(class).or_default() += 1;
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
}

/// Process-lifetime durable state beside the RAM cache.
#[derive(Default)]
pub(crate) struct Stores {
    claude: Option<Slot>,
    codex: Option<Slot>,
    /// Keys admitted to the RAM cache since their source's last write.
    touched: BTreeSet<String>,
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

/// The single-writer proof for the daemon's state directory. #801 owns the
/// lock (`StateDirLock`, flock before any state write); until it lands this
/// names the support directory only. M1 lands after #801 or together with
/// it, and then passes the held lock here instead (no new lock).
pub(crate) struct StateDirWriter<'a>(pub(crate) &'a Path);

impl SingleWriter for StateDirWriter<'_> {
    fn state_dir(&self) -> &Path {
        self.0
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
    /// The Claude request-identity contract in force and the parse mode.
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
        Self {
            identity_contract: format!(
                "{}|changed={}|capture={identity_capture}",
                index
                    .claude_request_identity_contract
                    .as_deref()
                    .unwrap_or("none"),
                index.claude_request_identity_contract_changed,
            ),
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
    let allowlist = codec::allowlist_digest(snapshot_source);
    Some(Expected {
        binding: Binding {
            source,
            key: store::key_digest(source, key),
            context: store::context_digest(
                &interpretation.namespace.0,
                index.active_upload_context_fingerprint.as_deref(),
            ),
            scope: store::scope_digest(
                &scope.0,
                &allowlist,
                &interpretation.identity_contract,
                &interpretation.counting_view,
            ),
            entry: store::entry_digest(
                &entry.source_file_fingerprint,
                entry.last_upload_body_witness.as_deref(),
            ),
        },
        committed_generation: index.generation,
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
        Refuse::NonEmpty(field) | Refuse::NotRederivable(field) => field,
        Refuse::UnknownLabel => "static_label",
        Refuse::TooLarge => "record_bytes",
    }
}

impl SharedCache {
    fn durable(&self) -> Option<std::sync::MutexGuard<'_, Stores>> {
        self.durable.lock().ok()
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
            current.namespace = namespace.clone();
            current.identity_capture = identity_capture;
        } else {
            *slot = Some(Slot {
                store: DurableTailStore::new(dir.clone()),
                dir,
                decided: BTreeMap::new(),
                namespace: namespace.clone(),
                identity_capture,
            });
        }
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
    ) -> Option<Taken<CachedJsonlReduction>> {
        let source = durable_source(snapshot_source)?;
        let expected = expected(source, snapshot_source, key, scope, index, interpretation)?;
        let allowlist = codec::allowlist_digest(snapshot_source);
        let record = {
            let mut stores = self.durable()?;
            stores.counters.restore_attempts += 1;
            let outcome = match stores.slot(source).as_mut() {
                Some(slot) => slot.store.read(&expected.binding.key, &allowlist),
                None => return None,
            };
            match outcome {
                ReadOutcome::Found(record) => record,
                ReadOutcome::Missing => {
                    stores.counters.missing += 1;
                    return None;
                }
                ReadOutcome::Refused(_) => {
                    stores.counters.refused_record += 1;
                    return None;
                }
            }
        };
        let restored =
            self.durable_restore_record(snapshot_source, &record, &expected, path, scope, held);
        let mut stores = self.durable()?;
        let (checkpoint, reduction, receipt) = match restored {
            Ok(restored) => restored,
            Err(class) => {
                let counters = &mut stores.counters;
                match class {
                    Failure::Ineligible(reason) => {
                        Counters::bump(&mut counters.ineligible, ineligible_class(reason))
                    }
                    Failure::Certificate(reason) => {
                        Counters::bump(&mut counters.certificate_refused, full_reason_class(reason))
                    }
                    Failure::Corrupt => counters.corrupt_body += 1,
                    Failure::NotRederived(refuse) => {
                        Counters::bump(&mut counters.not_rederived, refuse_class(refuse))
                    }
                }
                return None;
            }
        };
        stores.counters.rederive_head_bytes += receipt.head_bytes;
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
        let mut stores = self.durable()?;
        if !admitted {
            stores.counters.budget_refused += 1;
            return None;
        }
        stores.counters.restored += 1;
        drop(stores);
        self.take(key)
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
        let (touched, namespace, identity_capture) = {
            let mut stores = self.durable()?;
            let slot = stores.slot(source).as_ref()?;
            let pass = (slot.namespace.clone(), slot.identity_capture);
            (std::mem::take(&mut stores.touched), pass.0, pass.1)
        };
        let namespace = &namespace;
        let mut pending = Vec::new();
        let mut later = BTreeSet::new();
        let mut budget = WRITE_PASS_BYTES;
        let mut not_persisted = Vec::new();
        let mut peak = 0_u64;
        {
            let cache = self.retained().ok()?;
            for key in touched {
                let Some(retained) = cache.peek(&key) else {
                    continue;
                };
                if retained.state.accumulator.source != snapshot_source {
                    later.insert(key);
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
                if budget == 0 {
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
                        pending.push(PendingRecord {
                            binding: expected.binding,
                            certificate,
                            body,
                            allowlist,
                        });
                    }
                    Err(Refuse::TooLarge) if budget < store::RECORD_BYTES => {
                        later.insert(key);
                    }
                    Err(refuse) => not_persisted.push(refuse_class(refuse)),
                }
            }
        }
        let mut stores = self.durable()?;
        let deferred = later.len() as u64;
        stores.touched.extend(later);
        let counters = &mut stores.counters;
        counters.write_deferred += deferred;
        counters.peak_body_bytes = counters.peak_body_bytes.max(peak);
        for class in not_persisted {
            Counters::bump(&mut counters.not_persisted, class);
        }
        let slot = stores.slot(source).as_mut()?;
        slot.store
            .write_after_save(writer, index.generation, pending)
            .ok()
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
        let mut keep = BTreeMap::new();
        for key in index.files.keys() {
            let scope = slot.decided.get(key).and_then(|scope| {
                let interpretation =
                    Interpretation::of(snapshot_source, key, index, identity_capture, namespace);
                expected(source, snapshot_source, key, scope, index, &interpretation)
                    .map(|expected| expected.binding.scope)
            });
            keep.insert(store::key_digest(source, key), scope);
        }
        slot.store.gc(writer, &context, &allowlist, &keep)
    }

    /// Index reset or uninstall: the store goes with the index.
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
            Some(slot) => slot.store.remove_all(writer),
            None => Ok(()),
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

enum Failure {
    Ineligible(store::Ineligible),
    Certificate(FullReason),
    Corrupt,
    NotRederived(Refuse),
}
