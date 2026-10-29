//! M3 G1/G2: the native write-ahead facade over the store's stream API.
//!
//! Order (root contract): prepare under Stores, body stream outside Stores,
//! register the compact pending commit under Stores, rename outside Stores,
//! then the exact receipt under Stores. No body Vec, graph clone or forged
//! receipt exists on this path; every non-receipt outcome is explicit.
//!
//! D3 source split: a Codex fault that leaves any survivor degrades with a
//! strict retained-entry rebind the native owner saves before ACK; a Claude key
//! whose stale predecessor survives is held per key until its next successful
//! write or a content change, while other keys keep publishing.
use super::*;
use crate::locked_state_dir::held_for;

pub(crate) use crate::durable_tail_store::{
    PrepareStoreFailure, PreparedRecord, ReceiptProof, RecordIdentity,
};

/// The one funded64KiB stream buffer the store's writer owns while streaming.
const STREAM_SCRATCH_BYTES: u64 = 64 * 1024;

/// Borrowed PRE-finalization native state; never a copy of the graph.
pub(in crate::snapshots) struct LiveFinishView<'a> {
    pub(in crate::snapshots) accumulator: &'a SnapshotAccumulator,
    pub(in crate::snapshots) report: &'a JsonlReadReport,
    pub(in crate::snapshots) recognized_usage_drop_count: usize,
    pub(in crate::snapshots) positive_recognized_usage_count: usize,
    pub(in crate::snapshots) positive_usage_evidence: bool,
    pub(in crate::snapshots) checkpoint: &'a Checkpoint,
    pub(in crate::snapshots) chain: &'a AcquiredChain,
    pub(in crate::snapshots) line_cap: u64,
}
impl<'a> LiveFinishView<'a> {
    #[allow(clippy::too_many_arguments)] // Exact G1 view constructor (skeleton).
    pub(in crate::snapshots) fn new(
        accumulator: &'a SnapshotAccumulator,
        report: &'a JsonlReadReport,
        recognized_usage_drop_count: usize,
        positive_recognized_usage_count: usize,
        positive_usage_evidence: bool,
        checkpoint: &'a Checkpoint,
        chain: &'a AcquiredChain,
        line_cap: u64,
    ) -> Result<Self, NotPersisted> {
        if accumulator.source != chain.source() || line_cap == 0 {
            return Err(NotPersisted::Layout);
        }
        if checkpoint.scope() != chain.file_scope() {
            return Err(NotPersisted::Certificate);
        }
        if checkpoint.durable_certificate(chain.object().2).is_none() {
            return Err(NotPersisted::Unsealed);
        }
        Ok(Self {
            accumulator,
            report,
            recognized_usage_drop_count,
            positive_recognized_usage_count,
            positive_usage_evidence,
            checkpoint,
            chain,
            line_cap,
        })
    }
}

pub(in crate::snapshots) enum FinishAcquisition {
    Certified(sampled_jsonl::CompletedNativeAcquisition),
    Uncertified(DurableCustody),
}
impl FinishAcquisition {
    pub(in crate::snapshots) fn custody(&self) -> &DurableCustody {
        match self {
            Self::Certified(completed) => &completed.durable,
            Self::Uncertified(custody) => custody,
        }
    }
    pub(in crate::snapshots) fn custody_mut(&mut self) -> &mut DurableCustody {
        match self {
            Self::Certified(completed) => &mut completed.durable,
            Self::Uncertified(custody) => custody,
        }
    }
    pub(in crate::snapshots) fn checkpoint(&self) -> Option<&Checkpoint> {
        match self {
            Self::Certified(completed) => Some(&completed.checkpoint),
            Self::Uncertified(_) => None,
        }
    }
}

/// Owns staging and acquisition even when the native finish failed.
pub(in crate::snapshots) struct NativeFinishAttempt {
    pub(in crate::snapshots) native: anyhow::Result<ParsedJsonlFile>,
    pub(in crate::snapshots) acquisition: FinishAcquisition,
    pub(in crate::snapshots) preparation: Option<PrepareOutcome>,
}

pub(crate) enum PrepareOutcome {
    Prepared(PreparedRecord),
    NotPersisted(NotPersisted),
    Degraded(Degraded),
    StoreFailed(PrepareStoreFailure),
}
pub(crate) enum WriteOutcome {
    Receipted {
        generation: u64,
        receipt: ReceiptProof,
    },
    ReceiptPending,
    FailedPublishedWithoutRecord(DegradedCause),
    FailedHeld(HeldCause),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotPersisted {
    Codec,
    EntryCap,
    Certificate,
    Unsealed,
    ActiveBound,
    Layout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Degraded {
    Disabled,
    NoLock,
    /// Store-level resource pause after ENOSPC; the store retries it itself.
    Paused,
    /// The store refused before any write; the predecessor is untouched.
    Refused,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unprepared {
    NotPersisted(NotPersisted),
    Degraded(Degraded),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeldCause {
    Fence,
    Protected(store::Refusal),
    ReceiptPending,
    CustodyBound,
    Incompatible,
    /// D3 Claude: this key's stale predecessor survived; hold this key only.
    StaleSurvivor,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DegradedCause {
    /// No record survives (cleanup proved the predecessor absent).
    WriteFailedRetired,
    /// Disabled or unlocked store: no disk claim was made either way.
    StoreUntouched,
    /// A proved content change: the surviving predecessor cannot bind.
    PriorUnbindable,
    /// D3 Codex: the native owner must durably save the retained entry with
    /// its source fingerprint cleared BEFORE ACK, keeping key, #865 debt and
    /// membership, so no surviving record can bind after restart.
    StrictRebind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PriorRecord {
    Absent,
    Retained { format: u16 },
    Protected(store::Refusal),
    Unobserved(Degraded),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnpreparedDisposition {
    PublishRetainingPrior { format: u16, cause: Unprepared },
    PublishWithoutRecord { cause: Unprepared },
    PublishStoreUntouched { cause: Degraded },
    Hold(HeldCause),
}
/// The store's public receipt exists only at synchronous stream finish; a
/// later reconciliation reports the class, and debt discharges on that receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconcileOutcome {
    /// A pending completion was verified and retained in the store.
    Receipted,
    /// No pending; a record survives under its existing authority.
    Retained,
    Absent,
    Held(HeldCause),
}

/// Fences checked against the frozen PRE-mutation committed state.
pub(in crate::snapshots) struct CommitFences<'a> {
    held: &'a mut File,
    path: &'a Path,
    expected_opened_object_identity: &'a str,
    checkpoint: Option<&'a Checkpoint>,
    chain: &'a AcquiredChain,
    committed_index: &'a ScanIndex,
}
impl<'a> CommitFences<'a> {
    pub(in crate::snapshots) fn new(
        held: &'a mut File,
        path: &'a Path,
        expected_opened_object_identity: &'a str,
        checkpoint: Option<&'a Checkpoint>,
        chain: &'a AcquiredChain,
        committed_index: &'a ScanIndex,
    ) -> Result<Self, HeldCause> {
        if Path::new(chain.key()) != path {
            return Err(HeldCause::Incompatible);
        }
        // O: the object this pass opened is the one the chain acquired.
        if chain.opened_object_identity() != expected_opened_object_identity {
            return Err(HeldCause::Fence);
        }
        let metadata = held.metadata().map_err(|_| HeldCause::Fence)?;
        if (metadata.dev(), metadata.ino(), birth_unix_nanos(&metadata)) != chain.object() {
            return Err(HeldCause::Fence);
        }
        // PRE S2: no committed save happened since the chain was captured, so
        // the accepted facts the native finish started from are still frozen.
        if committed_index.generation != chain.committed_generation() {
            return Err(HeldCause::Fence);
        }
        if chain.source() == SnapshotSource::ClaudeCode
            && AcceptedFloor::of(committed_index, chain.key())
                .is_some_and(|a| !a.permits_real_edit())
        {
            return Err(HeldCause::Incompatible);
        }
        if let Some(checkpoint) = checkpoint {
            if checkpoint.scope() != chain.file_scope() {
                return Err(HeldCause::Incompatible);
            }
            checkpoint
                .durable_certificate(chain.object().2)
                .ok_or(HeldCause::Incompatible)?
                .check_metadata(held)
                .map_err(|_| HeldCause::Fence)?;
        }
        Ok(Self {
            held,
            path,
            expected_opened_object_identity,
            checkpoint,
            chain,
            committed_index,
        })
    }

    /// The prepared candidate is exactly this chain's next record.
    fn admit(&mut self, identity: &RecordIdentity) -> Result<(), HeldCause> {
        let checkpoint = self.checkpoint.ok_or(HeldCause::Fence)?;
        if Path::new(self.chain.key()) != self.path {
            return Err(HeldCause::Incompatible);
        }
        if identity.binding() != self.chain.binding()
            || identity.generation() != self.chain.committed_generation()
            || identity.acquired_revision() != self.chain.acquired_revision()
            || identity.protocol() != self.chain.write_protocol()
            || identity.sealed_offset() != checkpoint.sealed_offset()
        {
            return Err(HeldCause::Incompatible);
        }
        // Recheck immediately before mutation: O, held object and committed state.
        let metadata = self.held.metadata().map_err(|_| HeldCause::Fence)?;
        if (metadata.dev(), metadata.ino(), birth_unix_nanos(&metadata)) != self.chain.object()
            || self.committed_index.generation != self.chain.committed_generation()
            || self.chain.opened_object_identity() != self.expected_opened_object_identity
        {
            return Err(HeldCause::Fence);
        }
        checkpoint
            .durable_certificate(self.chain.object().2)
            .ok_or(HeldCause::Incompatible)?
            .check_metadata(self.held)
            .map_err(|_| HeldCause::Fence)
    }

    fn source(&self) -> Option<DurableSource> {
        durable_source(self.chain.source())
    }
    fn key(&self) -> &str {
        self.chain.key()
    }
    /// Current held object: (device, inode, birth) and length.
    fn observed(&self) -> Option<((u64, u64, u64), u64)> {
        let m = self.held.metadata().ok()?;
        Some(((m.dev(), m.ino(), birth_unix_nanos(&m)), m.len()))
    }
}

impl SharedCache {
    /// Native capture of a fresh acquisition chain. The caller proved the real
    /// held O and, for `write_ahead_eligible`, a byte-zero native origin.
    #[allow(clippy::too_many_arguments)] // Every input is one proved native fact.
    pub(in crate::snapshots) fn durable_capture_chain(
        &self,
        lease: &mut store::ActiveLease,
        source: SnapshotSource,
        key: &str,
        opened_object_identity: &str,
        held: &File,
        checkpoint: &Checkpoint,
        index: &ScanIndex,
        write_ahead_eligible: bool,
    ) -> Result<AcquiredChain, HeldCause> {
        let ds = durable_source(source).ok_or(HeldCause::Incompatible)?;
        let m = held.metadata().map_err(|_| HeldCause::Fence)?;
        let revision = effective_revision(source);
        let binding = self
            .live_binding(ds, source, key, checkpoint.scope(), index, revision)
            .ok_or(HeldCause::Incompatible)?;
        self.authorize_predecessor(lease, source, key, index, &binding, checkpoint, &m)?;
        acquired::capture_chain(
            acquired::ChainInputs {
                source,
                key,
                opened_object_identity,
                object: (m.dev(), m.ino(), birth_unix_nanos(&m)),
                checkpoint,
                binding,
                acquired_revision: revision,
                committed_generation: index.generation,
            },
            AcquisitionProtocol::Legacy,
            write_ahead_eligible,
            lease,
        )
        .map_err(|_| HeldCause::CustodyBound)
    }

    /// A later pass reuses a retained or restored chain: r_a, protocol and
    /// eligibility are inherited, never restamped; O/binding/generation move.
    pub(in crate::snapshots) fn durable_rebind_chain(
        &self,
        lease: &mut store::ActiveLease,
        chain: &mut AcquiredChain,
        opened_object_identity: &str,
        held: &File,
        checkpoint: &Checkpoint,
        index: &ScanIndex,
    ) -> Result<(), HeldCause> {
        let ds = durable_source(chain.source()).ok_or(HeldCause::Incompatible)?;
        if chain.acquired_revision() != effective_revision(chain.source()) {
            return Err(HeldCause::Incompatible); // Adoption owns a new acquisition.
        }
        let m = held.metadata().map_err(|_| HeldCause::Fence)?;
        let binding = self
            .live_binding(
                ds,
                chain.source(),
                chain.key(),
                checkpoint.scope(),
                index,
                chain.acquired_revision(),
            )
            .ok_or(HeldCause::Incompatible)?;
        self.authorize_predecessor(
            lease,
            chain.source(),
            chain.key(),
            index,
            &binding,
            checkpoint,
            &m,
        )?;
        chain.rebind(
            opened_object_identity,
            (m.dev(), m.ino(), birth_unix_nanos(&m)),
            checkpoint.scope(),
            binding,
            index.generation,
        )
    }

    /// Root's prepare_stream mutates only an exactly authorized Claude
    /// predecessor. Reuse the strict M1 witness path (it also captures the P2
    /// original witness the exact replacement ACK consumes), funded first.
    #[allow(clippy::too_many_arguments)] // One proved native fact per input.
    fn authorize_predecessor(
        &self,
        lease: &mut store::ActiveLease,
        source: SnapshotSource,
        key: &str,
        index: &ScanIndex,
        binding: &Binding,
        checkpoint: &Checkpoint,
        held: &std::fs::Metadata,
    ) -> Result<(), HeldCause> {
        if source != SnapshotSource::ClaudeCode {
            return Ok(()); // Codex v1 needs no memo; Codex native v3 is P5.
        }
        let certificate = checkpoint
            .durable_certificate(birth_unix_nanos(held))
            .ok_or(HeldCause::Incompatible)?;
        lease
            .charge(store::RESTORE_INPUT_BYTES)
            .map_err(|_| HeldCause::CustodyBound)?;
        let digest = binding.key;
        let mut guard = self.durable().ok_or(HeldCause::Fence)?;
        let stores = &mut *guard;
        if !stores.fund_key(digest) {
            return Err(HeldCause::CustodyBound);
        }
        let (Some(slot), Some(custody)) = (
            stores.slots[DurableSource::ClaudeCode.slot()].as_mut(),
            stores.retail_spent.get_mut(&digest),
        ) else {
            return Err(HeldCause::Fence);
        };
        authorize_strict(slot, source, key, index, custody, binding, &certificate);
        Ok(())
    }

    /// The v3 binding the existing reader expects: the current pass's context
    /// and scope formula with format 3 and r_a; the entry digest is reserved.
    pub(super) fn live_binding(
        &self,
        ds: DurableSource,
        source: SnapshotSource,
        key: &str,
        scope: &Scope,
        index: &ScanIndex,
        revision: u64,
    ) -> Option<Binding> {
        let (namespace, identity_capture) = {
            let mut stores = self.durable()?;
            let slot = stores.slot(ds).as_ref()?;
            (slot.namespace.clone(), slot.identity_capture)
        };
        let interpretation = Interpretation::of(source, key, index, identity_capture, &namespace);
        let mut expected = expected(
            ds,
            source,
            key,
            scope,
            index,
            &interpretation,
            Some((store::FORMAT_V3, ds.properties().allowlist(), revision)),
        )?;
        expected.binding.entry = [0; 32];
        Some(expected.binding)
    }

    pub(in crate::snapshots) fn prepare_live(
        &self,
        lease: &mut store::ActiveLease,
        view: LiveFinishView<'_>,
    ) -> PrepareOutcome {
        let outcome = self.prepare_live_inner(lease, &view);
        if let PrepareOutcome::NotPersisted(reason) = &outcome {
            self.note_not_persisted(*reason);
        }
        outcome
    }

    fn prepare_live_inner(
        &self,
        lease: &mut store::ActiveLease,
        view: &LiveFinishView<'_>,
    ) -> PrepareOutcome {
        let chain = view.chain;
        let Some(source) = durable_source(chain.source()) else {
            return PrepareOutcome::NotPersisted(NotPersisted::Layout);
        };
        let Some(certificate) = view.checkpoint.durable_certificate(chain.object().2) else {
            return PrepareOutcome::NotPersisted(NotPersisted::Certificate);
        };
        // Count first, without allocating the stream buffer; the complete
        // header+trailer record bound is applied before any staging.
        let plan = match codec::BodyEncoding::new(
            view.accumulator,
            view.report,
            (
                view.recognized_usage_drop_count,
                view.positive_recognized_usage_count,
                view.positive_usage_evidence,
            ),
            view.line_cap,
        ) {
            Ok(plan) => plan,
            Err(_) => return PrepareOutcome::NotPersisted(NotPersisted::Codec),
        };
        let limit = store::BODY_BYTES - (store::HEADER_V3_BYTES - store::HEADER_BYTES);
        let body_len = match plan.count(limit) {
            Ok(len) => len,
            Err(Refuse::TooLarge) => return PrepareOutcome::NotPersisted(NotPersisted::EntryCap),
            Err(_) => return PrepareOutcome::NotPersisted(NotPersisted::Codec),
        };
        if lease.charge(STREAM_SCRATCH_BYTES).is_err() {
            return PrepareOutcome::NotPersisted(NotPersisted::ActiveBound);
        }
        let header = store::PreparedHeader {
            binding: chain.binding().clone(),
            certificate,
            format: store::FORMAT_V3,
            allowlist: source.properties().allowlist(),
            acquisition: store::AcquisitionFields {
                acquired_revision: chain.acquired_revision(),
                protocol: chain.write_protocol(),
            },
            generation: chain.committed_generation(),
            body_len,
        };
        let preparation = {
            let Some(mut stores) = self.durable() else {
                return PrepareOutcome::Degraded(Degraded::Disabled);
            };
            let Some(slot) = stores.slot(source).as_mut() else {
                return PrepareOutcome::Degraded(Degraded::Disabled);
            };
            if slot.store.disabled().is_some() {
                return PrepareOutcome::Degraded(Degraded::Disabled);
            }
            if slot.store.resource_paused() {
                return PrepareOutcome::Degraded(Degraded::Paused);
            }
            let Some(writer) = held_for(&slot.dir) else {
                return PrepareOutcome::Degraded(Degraded::NoLock);
            };
            match slot.store.prepare_stream(writer, header) {
                Ok(preparation) => preparation,
                Err(failure) => return PrepareOutcome::StoreFailed(failure),
            }
        };
        // Outside Stores: the same encoder streams exactly the counted body.
        match preparation.write(|out| plan.write(out, body_len)) {
            Ok(prepared) => PrepareOutcome::Prepared(prepared),
            Err(failure) => PrepareOutcome::StoreFailed(failure),
        }
    }

    pub(in crate::snapshots) fn commit_prepared(
        &self,
        prepared: PreparedRecord,
        mut fences: CommitFences<'_>,
    ) -> WriteOutcome {
        if let Err(cause) = fences.admit(prepared.identity()) {
            self.discard_prepared(prepared);
            return WriteOutcome::FailedHeld(cause);
        }
        let Some(source) = fences.source() else {
            self.discard_prepared(prepared);
            return WriteOutcome::FailedHeld(HeldCause::Incompatible);
        };
        // Predecessor authorization happened at chain capture/rebind, before
        // prepare_stream checked it; registration rechecks the prior stamp.
        let pending = {
            let Some(mut guard) = self.durable() else {
                self.discard_prepared(prepared);
                return WriteOutcome::FailedHeld(HeldCause::Fence);
            };
            let stores = &mut *guard;
            let unavailable = stores.slots[source.slot()].as_ref().map_or(true, |slot| {
                slot.store.disabled().is_some() || held_for(&slot.dir).is_none()
            });
            if unavailable {
                drop(guard);
                self.discard_prepared(prepared);
                return self.settle_unavailable(source, fences.key());
            }
            let slot = stores.slots[source.slot()].as_mut().expect("slot");
            let writer = held_for(&slot.dir).expect("checked writer");
            let registered = slot.store.commit_stream(writer, prepared);
            drop(guard);
            match registered {
                Ok(pending) => pending,
                Err(failure) => return self.resolve_failed_preparation(failure, fences),
            }
        };
        // Outside Stores: conditional rename and survivor stamp, no fsync per record.
        let committed = match pending.commit() {
            Ok(committed) => committed,
            Err(failure) => return self.resolve_failed_preparation(failure, fences),
        };
        let Some(mut guard) = self.durable() else {
            // The compact pending stays registered; reconciliation owns it.
            return WriteOutcome::ReceiptPending;
        };
        let finished = match guard.slot(source).as_mut() {
            Some(slot) => slot.store.finish_stream(committed),
            None => return WriteOutcome::ReceiptPending,
        };
        match finished {
            Ok(receipt) => {
                receipted_locked(&mut guard, source, fences.key(), &receipt);
                WriteOutcome::Receipted {
                    generation: receipt.generation(),
                    receipt,
                }
            }
            Err(failure) => {
                drop(guard);
                self.resolve_failed_preparation(failure, fences)
            }
        }
    }

    /// Explicit cleanup outside Stores. The store's shared cleanup backing
    /// counts verified/failed/fallback outcomes on the #799 carrier.
    pub(in crate::snapshots) fn discard_prepared(&self, prepared: PreparedRecord) {
        debug_assert!(!stores_held(), "temp cleanup runs outside Stores");
        let _counted = prepared.discard();
    }

    pub(crate) fn discard_failed_preparation(&self, mut failure: PrepareStoreFailure) {
        debug_assert!(!stores_held(), "temp cleanup runs outside Stores");
        let _counted = failure.discard();
    }

    pub(in crate::snapshots) fn resolve_failed_preparation(
        &self,
        mut failure: PrepareStoreFailure,
        fences: CommitFences<'_>,
    ) -> WriteOutcome {
        debug_assert!(!stores_held(), "resolution I/O runs outside Stores");
        let Some(source) = fences.source() else {
            self.discard_failed_preparation(failure);
            return WriteOutcome::FailedHeld(HeldCause::Incompatible);
        };
        // Before registration nothing of ours is pending and the predecessor
        // was never touched: adjudicate against the observed prior record.
        if matches!(failure.stage(), "stream_prepare" | "stream_register") {
            let protected = failure.protected();
            let enospc = failure.is_enospc();
            let _counted = failure.discard();
            return match protected {
                Some(store::Refusal::ReceiptPending) if failure.stage() == "stream_prepare" => {
                    WriteOutcome::FailedHeld(HeldCause::ReceiptPending)
                }
                Some(refusal) if failure.stage() == "stream_prepare" => {
                    WriteOutcome::FailedHeld(HeldCause::Protected(refusal))
                }
                _ => {
                    let reason = if enospc {
                        Degraded::Paused
                    } else {
                        Degraded::Refused
                    };
                    let disposition = self.resolve_unprepared(Unprepared::Degraded(reason), fences);
                    unprepared_write(disposition)
                }
            };
        }
        let resolve = {
            let Some(mut guard) = self.durable() else {
                // No adjudication possible: the failure keeps its owned temp
                // until its identity-checked fallback; nothing publishes.
                return WriteOutcome::FailedHeld(HeldCause::ReceiptPending);
            };
            let unavailable = guard.slot(source).as_ref().map_or(true, |slot| {
                slot.store.disabled().is_some() || held_for(&slot.dir).is_none()
            });
            if unavailable {
                drop(guard);
                self.discard_failed_preparation(failure);
                return self.settle_unavailable(source, fences.key());
            }
            let slot = guard.slot(source).as_mut().expect("slot");
            let writer = held_for(&slot.dir).expect("checked writer");
            slot.store.resolve_failed_stream(writer, failure)
        };
        let resolution = resolve.resolve();
        let disposition = {
            let Some(mut stores) = self.durable() else {
                return WriteOutcome::FailedHeld(HeldCause::ReceiptPending);
            };
            let Some(slot) = stores.slot(source).as_mut() else {
                return WriteOutcome::FailedHeld(HeldCause::ReceiptPending);
            };
            slot.store.finish_resolution(resolution)
        };
        self.settle(disposition, &fences)
    }

    /// Disabled or unlocked: the store was not touched and no claim is made.
    fn settle_unavailable(&self, source: DurableSource, key: &str) -> WriteOutcome {
        if let Some(mut stores) = self.durable() {
            stores.clear_owed(store::key_digest(source, key));
            if let Some(slot) = stores.slot(source).as_mut() {
                slot.store.note_degraded_publish();
            }
        }
        WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::StoreUntouched)
    }

    /// One mapping from the store's adjudication to native publication.
    fn settle(
        &self,
        disposition: store::FailureDisposition,
        fences: &CommitFences<'_>,
    ) -> WriteOutcome {
        let Some(source) = fences.source() else {
            return WriteOutcome::FailedHeld(HeldCause::Incompatible);
        };
        let key = fences.key();
        let digest = store::key_digest(source, key);
        let observed = fences.observed();
        let Some(mut guard) = self.durable() else {
            return WriteOutcome::FailedHeld(HeldCause::ReceiptPending);
        };
        let stores = &mut *guard;
        let note_degraded = |stores: &mut Stores| {
            if let Some(slot) = stores.slots[source.slot()].as_mut() {
                slot.store.note_degraded_publish();
            }
        };
        match disposition {
            store::FailureDisposition::Receipted(receipt) => {
                receipted_locked(stores, source, key, &receipt);
                WriteOutcome::Receipted {
                    generation: receipt.generation(),
                    receipt,
                }
            }
            store::FailureDisposition::Protected(store::Refusal::ReceiptPending) => {
                WriteOutcome::FailedHeld(HeldCause::ReceiptPending)
            }
            store::FailureDisposition::Protected(refusal) => {
                WriteOutcome::FailedHeld(HeldCause::Protected(refusal))
            }
            store::FailureDisposition::PublishDegraded {
                strict_rebind: true,
                ..
            } => {
                // Codex double failure: the store disabled itself and dropped
                // its in-RAM pending set; no debt marker may outlive it.
                stores.clear_source_owed(source);
                note_degraded(stores);
                WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::StrictRebind)
            }
            store::FailureDisposition::PublishDegraded { .. } => {
                // Cleanup proved the predecessor absent: degraded publish.
                // Publication without a record leaves no receipt to owe.
                stores.release_hold(digest, HoldRelease::Absent);
                stores.clear_owed(digest);
                note_degraded(stores);
                WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::WriteFailedRetired)
            }
            store::FailureDisposition::Hold { .. } if source == DurableSource::ClaudeCode => {
                let held = stores
                    .retail_spent
                    .get(&digest)
                    .is_some_and(|custody| custody.hold.is_some());
                if stores.hold_content_changed(digest)
                    || (held && !stores.observe_hold(digest, observed))
                {
                    // The surviving predecessor no longer binds this object.
                    stores.release_hold(digest, HoldRelease::Content);
                    stores.clear_owed(digest);
                    note_degraded(stores);
                    WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::PriorUnbindable)
                } else {
                    stores.hold_key(digest, observed);
                    WriteOutcome::FailedHeld(HeldCause::StaleSurvivor)
                }
            }
            // Codex receipt mismatch: transient, the next pass re-acquires.
            store::FailureDisposition::Hold { .. } => {
                WriteOutcome::FailedHeld(HeldCause::ReceiptPending)
            }
        }
    }

    pub(in crate::snapshots) fn resolve_unprepared(
        &self,
        reason: Unprepared,
        fences: CommitFences<'_>,
    ) -> UnpreparedDisposition {
        let Some(source) = fences.source() else {
            return UnpreparedDisposition::Hold(HeldCause::Incompatible);
        };
        let digest = store::key_digest(source, fences.key());
        let observed = fences.observed();
        let Some(mut guard) = self.durable() else {
            return UnpreparedDisposition::PublishStoreUntouched {
                cause: Degraded::Disabled,
            };
        };
        let stores = &mut *guard;
        let prior = match stores.slots[source.slot()].as_mut() {
            None => PriorRecord::Unobserved(Degraded::Disabled),
            Some(slot) if slot.store.disabled().is_some() => {
                PriorRecord::Unobserved(Degraded::Disabled)
            }
            Some(slot) if slot.store.absent(&digest) => PriorRecord::Absent,
            // Header-only classification of the survivor, never its body.
            Some(slot) => match slot.store.hold(&digest) {
                Some(refusal) => PriorRecord::Protected(refusal),
                None => slot
                    .store
                    .representation(&digest)
                    .map_or(PriorRecord::Unobserved(Degraded::Refused), |(format, _)| {
                        PriorRecord::Retained { format }
                    }),
            },
        };
        let fault = matches!(
            reason,
            Unprepared::Degraded(Degraded::Paused | Degraded::Refused)
        );
        let note_degraded = |stores: &mut Stores| {
            if let Some(slot) = stores.slots[source.slot()].as_mut() {
                slot.store.note_degraded_publish();
            }
        };
        let disposition = match prior {
            PriorRecord::Protected(store::Refusal::ReceiptPending) => {
                UnpreparedDisposition::Hold(HeldCause::ReceiptPending)
            }
            PriorRecord::Protected(refusal) => {
                UnpreparedDisposition::Hold(HeldCause::Protected(refusal))
            }
            PriorRecord::Unobserved(cause) => {
                note_degraded(stores);
                UnpreparedDisposition::PublishStoreUntouched {
                    cause: match reason {
                        Unprepared::Degraded(degraded) => degraded,
                        Unprepared::NotPersisted(_) => cause,
                    },
                }
            }
            PriorRecord::Absent => {
                if fault {
                    note_degraded(stores);
                }
                stores.release_hold(digest, HoldRelease::Absent);
                UnpreparedDisposition::PublishWithoutRecord { cause: reason }
            }
            // A store fault or resource pause never retires a valid
            // predecessor: hold only this Claude key; keys without a stale
            // survivor (and every Codex key, whose v1 entry refuses) publish.
            PriorRecord::Retained { .. } if fault && source == DurableSource::ClaudeCode => {
                let held = stores
                    .retail_spent
                    .get(&digest)
                    .is_some_and(|custody| custody.hold.is_some());
                if stores.hold_content_changed(digest)
                    || (held && !stores.observe_hold(digest, observed))
                {
                    stores.release_hold(digest, HoldRelease::Content);
                    note_degraded(stores);
                    UnpreparedDisposition::PublishStoreUntouched {
                        cause: Degraded::Refused,
                    }
                } else {
                    stores.hold_key(digest, observed);
                    UnpreparedDisposition::Hold(HeldCause::StaleSurvivor)
                }
            }
            PriorRecord::Retained { format } => UnpreparedDisposition::PublishRetainingPrior {
                format,
                cause: reason,
            },
        };
        // A publication owes no receipt for this acquisition any more.
        if !matches!(disposition, UnpreparedDisposition::Hold(_)) {
            stores.clear_owed(digest);
        }
        disposition
    }

    /// Selection-time reconciliation of an outstanding pending receipt. Root
    /// settles native streams synchronously; the funded M1 reconciler retains
    /// a verified completion in the store for its exact ACK delivery.
    pub(crate) fn reconcile_receipt(&self, source: SnapshotSource, key: &str) -> ReconcileOutcome {
        let Some(ds) = durable_source(source) else {
            return ReconcileOutcome::Absent;
        };
        let digest = store::key_digest(ds, key);
        let had_pending = self.durable().is_some_and(|mut stores| {
            stores.slot(ds).as_ref().is_some_and(|slot| {
                slot.store.disabled().is_none() && slot.store.receipt_pending(&digest)
            })
        });
        match self.reconcile_pending_key(source, key) {
            Some(store::Refusal::ReceiptPending) => {
                return ReconcileOutcome::Held(HeldCause::ReceiptPending)
            }
            Some(refusal) => return ReconcileOutcome::Held(HeldCause::Protected(refusal)),
            None => {}
        }
        let Some(mut guard) = self.durable() else {
            return ReconcileOutcome::Held(HeldCause::ReceiptPending);
        };
        let stores = &mut *guard;
        let (disabled, absent) = match stores.slots[ds.slot()].as_ref() {
            None => return ReconcileOutcome::Absent,
            Some(slot) => (slot.store.disabled().is_some(), slot.store.absent(&digest)),
        };
        if disabled {
            // A disabled store dropped its pending set and serves nothing.
            stores.clear_source_owed(ds);
            ReconcileOutcome::Absent
        } else if absent {
            ReconcileOutcome::Absent
        } else if had_pending {
            ReconcileOutcome::Receipted
        } else {
            ReconcileOutcome::Retained
        }
    }

    /// Native discovery/publication query for a held Claude key; counts growth
    /// and releases on a content change of the held object. Age-independent.
    pub(in crate::snapshots) fn durable_claude_hold(
        &self,
        source: SnapshotSource,
        key: &str,
        held: &File,
    ) -> bool {
        if source != SnapshotSource::ClaudeCode {
            return false;
        }
        let digest = store::key_digest(DurableSource::ClaudeCode, key);
        let observed = held
            .metadata()
            .ok()
            .map(|m| ((m.dev(), m.ino(), birth_unix_nanos(&m)), m.len()));
        let Some(mut stores) = self.durable() else {
            return false;
        };
        stores.observe_hold(digest, observed)
    }

    /// The native classifier proved a genuine content change (real edit or
    /// replacement): the surviving predecessor can no longer bind.
    pub(in crate::snapshots) fn durable_release_hold(&self, source: SnapshotSource, key: &str) {
        let Some(ds) = durable_source(source) else {
            return;
        };
        if let Some(mut stores) = self.durable() {
            stores.mark_hold_content_changed(store::key_digest(ds, key));
        }
    }

    fn note_not_persisted(&self, reason: NotPersisted) {
        if let Some(mut stores) = self.durable() {
            Counters::bump(
                &mut stores.counters.not_persisted,
                match reason {
                    NotPersisted::Codec => "wa.codec",
                    NotPersisted::EntryCap => "wa.entry_cap",
                    NotPersisted::Certificate => "wa.certificate",
                    NotPersisted::Unsealed => "wa.unsealed",
                    NotPersisted::ActiveBound => "wa.active_bound",
                    NotPersisted::Layout => "wa.layout",
                },
            );
        }
    }
}

/// A failure before registration never touched the predecessor: the same
/// prior-record adjudication as an unprepared write, as a write outcome.
fn unprepared_write(disposition: UnpreparedDisposition) -> WriteOutcome {
    match disposition {
        UnpreparedDisposition::Hold(cause) => WriteOutcome::FailedHeld(cause),
        UnpreparedDisposition::PublishWithoutRecord { .. } => {
            WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::WriteFailedRetired)
        }
        UnpreparedDisposition::PublishRetainingPrior { .. }
        | UnpreparedDisposition::PublishStoreUntouched { .. } => {
            WriteOutcome::FailedPublishedWithoutRecord(DegradedCause::StoreUntouched)
        }
    }
}

/// The exact receipt is the next successful write for this key: it releases a
/// D3 hold and consumes the P2 original witness through the exact ACK adapter.
fn receipted_locked(stores: &mut Stores, source: DurableSource, key: &str, receipt: &ReceiptProof) {
    let digest = store::key_digest(source, key);
    stores.release_hold(digest, HoldRelease::Write);
    if source != DurableSource::ClaudeCode {
        return;
    }
    let Some(slot) = stores.slots[source.slot()].as_mut() else {
        return;
    };
    if let Some(custody) = stores.retail_spent.get_mut(&digest) {
        if custody
            .original
            .as_ref()
            .is_some_and(|original| slot.store.replacement_receipted(original, receipt))
        {
            stores.counters.migration[3] += u64::from(
                custody
                    .original
                    .as_ref()
                    .is_some_and(|original| original.is_migration()),
            );
            custody.original = None;
        }
    }
}

// Process-lifetime D3 hold counts on the existing #799 diagnostics line. Store
// faults, degraded publishes, stale refusals and pause seconds are store counters.
pub(super) const D3_HOLD_GROWTH_BYTES: usize = 0;
pub(super) const D3_RELEASED_WRITE: usize = 1;
pub(super) const D3_RELEASED_CONTENT: usize = 2;
pub(super) const D3_HOLD_UNFUNDED: usize = 3;
pub(super) const D3_COUNTS: usize = 4;

/// Fixed metadata in the key's existing funded custody node; never a body,
/// witness or debt copy. RAM only: a restart re-derives it from the survivor.
#[derive(Clone, Copy)]
pub(super) struct ClaudeHold {
    since: std::time::Instant,
    object: (u64, u64, u64),
    length: u64,
    content_changed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HoldRelease {
    Write,
    Content,
    Absent,
}

/// The first D3 hold in this process alarms once, on the next report.
#[derive(Default)]
pub(super) struct D3State {
    hold_alarmed: bool,
    hold_alarm_due: bool,
}

impl Stores {
    /// Hold only this key; the source and every other key keep publishing.
    pub(super) fn hold_key(
        &mut self,
        digest: store::Digest32,
        observed: Option<((u64, u64, u64), u64)>,
    ) {
        if !self.fund_key(digest) {
            // The attempt still holds; only the cross-pass marker is unfunded.
            self.counters.d3[D3_HOLD_UNFUNDED] += 1;
            return;
        }
        let Some(custody) = self.retail_spent.get_mut(&digest) else {
            return;
        };
        if custody.hold.is_none() {
            let (object, length) = observed.unwrap_or(((0, 0, 0), 0));
            custody.hold = Some(ClaudeHold {
                since: std::time::Instant::now(),
                object,
                length,
                content_changed: false,
            });
            if !self.d3.hold_alarmed {
                self.d3.hold_alarmed = true;
                self.d3.hold_alarm_due = true;
            }
        }
    }

    pub(super) fn release_hold(&mut self, digest: store::Digest32, why: HoldRelease) {
        if let Some(custody) = self.retail_spent.get_mut(&digest) {
            if custody.hold.take().is_some() {
                self.counters.d3[if why == HoldRelease::Write {
                    D3_RELEASED_WRITE
                } else {
                    D3_RELEASED_CONTENT
                }] += 1;
            }
        }
    }

    pub(super) fn hold_content_changed(&self, digest: store::Digest32) -> bool {
        self.retail_spent
            .get(&digest)
            .and_then(|custody| custody.hold)
            .is_some_and(|hold| hold.content_changed)
    }

    pub(super) fn mark_hold_content_changed(&mut self, digest: store::Digest32) {
        if let Some(hold) = self
            .retail_spent
            .get_mut(&digest)
            .and_then(|custody| custody.hold.as_mut())
        {
            hold.content_changed = true;
        }
    }

    /// Whether `digest` is still held. Growth is counted and never releases;
    /// a replaced object releases. Same-object edits are proved by the native
    /// classifier through `durable_release_hold`.
    pub(super) fn observe_hold(
        &mut self,
        digest: store::Digest32,
        observed: Option<((u64, u64, u64), u64)>,
    ) -> bool {
        let Some(hold) = self
            .retail_spent
            .get_mut(&digest)
            .and_then(|custody| custody.hold.as_mut())
        else {
            return false;
        };
        let Some((object, length)) = observed else {
            return true;
        };
        if hold.object != (0, 0, 0) && object != hold.object {
            self.release_hold(digest, HoldRelease::Content);
            return false;
        }
        if length > hold.length {
            self.counters.d3[D3_HOLD_GROWTH_BYTES] += length - hold.length;
            hold.length = length;
        }
        true
    }

    /// `d3_claude_hold{keys, oldest_age}`: bounded walk of the funded nodes.
    pub(super) fn claude_holds(&self) -> [u64; 2] {
        let mut keys = 0;
        let mut oldest = 0;
        for hold in self
            .retail_spent
            .values()
            .filter_map(|custody| custody.hold)
        {
            keys += 1;
            oldest = oldest.max(hold.since.elapsed().as_secs());
        }
        [keys, oldest]
    }

    /// The first hold in this process alarms once, on the next report.
    pub(super) fn take_hold_alarm(&mut self) -> bool {
        std::mem::take(&mut self.d3.hold_alarm_due)
    }
}

#[cfg(test)]
#[path = "write_ahead_tests.rs"]
mod tests;
