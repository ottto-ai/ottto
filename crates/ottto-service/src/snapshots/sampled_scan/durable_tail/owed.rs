//! Receipt debt owns acquisition facts, never parsed output or an ACK.
//!
//! One non-Clone debt per acquisition lives in the existing DurableCustody;
//! the content-free per-key marker lives in the existing funded key custody
//! node. A candidate-less debt deliberately cannot match any receipt.
use super::write_ahead::FinishAcquisition;
use super::{
    durable_source, sampled_jsonl, store, AcquiredChain, CachedJsonlReduction, DurableSource,
    HeldCause, PreparedRecord, ReceiptProof, RecordIdentity, SharedCache, Stores, Taken,
};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshots::SnapshotSource;
use crate::transcript_acquisition::Checkpoint;

/// Content-free per-key debt class in the existing key custody node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum OwedMark {
    #[default]
    None,
    /// A bound candidate may discharge it with its exact receipt.
    Owed(DurableSource),
    /// Candidate-less: only a later native acquisition's receipt clears it.
    Hold(DurableSource),
}

pub(crate) struct ReceiptOwed {
    chain: AcquiredChain,
    checkpoint: Checkpoint,
    candidate: Option<RecordIdentity>,
}

impl ReceiptOwed {
    pub(crate) fn source(&self) -> SnapshotSource {
        self.chain.source()
    }

    pub(crate) fn key(&self) -> &str {
        self.chain.key()
    }

    pub(crate) fn chain(&self) -> &AcquiredChain {
        &self.chain
    }

    pub(crate) fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub(crate) fn candidate(&self) -> Option<&RecordIdentity> {
        self.candidate.as_ref()
    }

    /// ReceiptProof is constructed only by the store after canonical-path sync
    /// and exact final-stamp verification. NoPending, retained A and retirement
    /// are not receipts. The parent must revalidate a delayed proof at delivery.
    pub(crate) fn matches(&self, receipt: &ReceiptProof) -> bool {
        self.candidate.as_ref() == Some(receipt.identity())
            && receipt.identity().binding() == self.chain.binding()
    }

    pub(crate) fn bind_prepared(&mut self, prepared: &PreparedRecord) -> Result<(), HeldCause> {
        let identity = prepared.identity();
        let certificate = identity.certificate();
        let checkpoint = self
            .checkpoint
            .durable_certificate(certificate.birth_nanos)
            .ok_or(HeldCause::Incompatible)?;
        if identity.binding() != self.chain.binding()
            || identity.acquired_revision() != self.chain.acquired_revision()
            || identity.generation() != self.chain.committed_generation()
            || identity.sealed_offset() != self.checkpoint.sealed_offset()
            || certificate != &checkpoint
            || identity.protocol() != self.chain.write_protocol()
        {
            return Err(HeldCause::Incompatible);
        }
        // RecordIdentity has only fixed binding/certificate/wire facts. This
        // copy neither clones the acquired strings nor changes candidate bytes.
        self.candidate = Some(identity.clone());
        Ok(())
    }
}

pub(crate) enum OwedQuery {
    None,
    Owed,
    Hold(HeldCause),
}
pub(crate) enum OwedAdmission {
    Admitted,
    Refused(Box<Taken<CachedJsonlReduction>>),
}
pub(in crate::snapshots) enum OwedCompletionAdmission {
    Admitted,
    Refused(sampled_jsonl::CompletedNativeAcquisition),
}

impl Stores {
    /// Enroll before any eviction. An unfunded node sets the source-wide
    /// conservative class bit, so no owed key can read as debt-free.
    pub(super) fn set_owed(&mut self, digest: store::Digest32, mark: OwedMark) {
        let source = match mark {
            OwedMark::None => return self.clear_owed(digest),
            OwedMark::Owed(source) | OwedMark::Hold(source) => source,
        };
        if !self.fund_key(digest) {
            self.owed_overflow[source.slot()] = true;
            return;
        }
        if let Some(custody) = self.retail_spent.get_mut(&digest) {
            // A candidate-less hold is never downgraded by a weaker offer.
            if !(matches!(custody.owed, OwedMark::Hold(_)) && matches!(mark, OwedMark::Owed(_))) {
                custody.owed = mark;
            }
        }
    }
    pub(super) fn clear_owed(&mut self, digest: store::Digest32) {
        if let Some(custody) = self.retail_spent.get_mut(&digest) {
            custody.owed = OwedMark::None;
        }
    }
    /// SOURCE condition 3: a disabled store leaves no orphan OwedMark.
    pub(super) fn clear_source_owed(&mut self, source: DurableSource) {
        for custody in self.retail_spent.values_mut() {
            if matches!(custody.owed, OwedMark::Owed(s) | OwedMark::Hold(s) if s == source) {
                custody.owed = OwedMark::None;
            }
        }
        self.owed_overflow[source.slot()] = false;
    }
    pub(super) fn owed_mark(&self, digest: &store::Digest32) -> OwedMark {
        self.retail_spent
            .get(digest)
            .map_or(OwedMark::None, |custody| custody.owed)
    }
}

fn checkpoint_bytes(checkpoint: &Checkpoint) -> Option<u64> {
    let mut c = Counter::new(usize::MAX);
    checkpoint.heap_bound(&mut c)?;
    u64::try_from(c.bytes.checked_add(std::mem::size_of::<Checkpoint>())?).ok()
}

impl SharedCache {
    /// Queried before selector Skip/comparison/family/scoped retry logic.
    pub(crate) fn owed_before_skip(&self, source: SnapshotSource, key: &str) -> OwedQuery {
        let Some(ds) = durable_source(source) else {
            return OwedQuery::None;
        };
        let digest = store::key_digest(ds, key);
        let Some(mut stores) = self.durable() else {
            // Unknown custody fails toward holding, never toward Full.
            return OwedQuery::Hold(HeldCause::ReceiptPending);
        };
        if stores
            .retail_spent
            .get(&digest)
            .is_some_and(|custody| custody.hold.is_some())
        {
            return OwedQuery::Hold(HeldCause::StaleSurvivor);
        }
        let pending = stores.slot(ds).as_ref().is_some_and(|slot| {
            slot.store.disabled().is_none() && slot.store.receipt_pending(&digest)
        });
        match stores.owed_mark(&digest) {
            OwedMark::Hold(_) => OwedQuery::Hold(HeldCause::ReceiptPending),
            OwedMark::Owed(_) => OwedQuery::Owed,
            OwedMark::None if pending || stores.owed_overflow[ds.slot()] => OwedQuery::Owed,
            OwedMark::None => OwedQuery::None,
        }
    }

    /// Moves the acquisition chain into one funded debt; graph and output stay
    /// with their existing owner. No candidate means a non-dischargeable hold.
    pub(in crate::snapshots) fn mark_receipt_owed(
        &self,
        acquisition: &mut FinishAcquisition,
        candidate: Option<&RecordIdentity>,
    ) -> Result<(), HeldCause> {
        if acquisition.checkpoint().is_none() {
            return Err(HeldCause::Incompatible); // Uncertified finish: no debt.
        }
        let (source, key) = {
            let custody = acquisition.custody();
            let chain = custody
                .owed()
                .map(ReceiptOwed::chain)
                .or_else(|| custody.chain())
                .ok_or(HeldCause::Incompatible)?;
            (
                chain.source(),
                store::key_digest(
                    durable_source(chain.source()).ok_or(HeldCause::Incompatible)?,
                    chain.key(),
                ),
            )
        };
        let custody = acquisition.custody_mut();
        if let Some(mut owed) = custody.take_owed() {
            let bound = match candidate {
                Some(candidate) if owed.candidate.as_ref() != Some(candidate) => {
                    Err(HeldCause::Incompatible)
                }
                _ => Ok(()),
            };
            let has_candidate = owed.candidate.is_some();
            custody
                .put_owed(owed)
                .map_err(|_| HeldCause::CustodyBound)?;
            bound?;
            self.mark_key(source, key, has_candidate);
            return Ok(());
        }
        // Fund the checkpoint copy on this acquisition's own active lease.
        let bytes = checkpoint_bytes(acquisition.checkpoint().ok_or(HeldCause::Incompatible)?)
            .ok_or(HeldCause::CustodyBound)?;
        acquisition
            .custody_mut()
            .active_mut()
            .ok_or(HeldCause::CustodyBound)?
            .charge(bytes)
            .map_err(|_| HeldCause::CustodyBound)?;
        let checkpoint = checkpoint_owned(acquisition)?;
        let custody = acquisition.custody_mut();
        let chain = custody.take_chain().ok_or(HeldCause::Incompatible)?;
        let owed = ReceiptOwed {
            chain,
            checkpoint,
            candidate: candidate.cloned(),
        };
        let has_candidate = owed.candidate.is_some();
        if let Err(owed) = custody.put_owed(owed) {
            // Never lose the chain: return it to its single owner slot.
            let _ = custody.put_chain(owed.chain);
            return Err(HeldCause::CustodyBound);
        }
        self.mark_key(source, key, has_candidate);
        Ok(())
    }

    fn mark_key(&self, source: SnapshotSource, digest: store::Digest32, candidate: bool) {
        let Some(ds) = durable_source(source) else {
            return;
        };
        if let Some(mut stores) = self.durable() {
            stores.set_owed(
                digest,
                if candidate {
                    OwedMark::Owed(ds)
                } else {
                    OwedMark::Hold(ds)
                },
            );
        }
    }

    /// Binds a later native preparation to the outstanding debt before commit,
    /// so only that exact candidate's receipt can discharge it.
    pub(in crate::snapshots) fn bind_owed_prepared(
        &self,
        acquisition: &mut FinishAcquisition,
        prepared: &PreparedRecord,
    ) -> Result<(), HeldCause> {
        let custody = acquisition.custody_mut();
        let mut owed = custody.take_owed().ok_or(HeldCause::Incompatible)?;
        let bound = owed.bind_prepared(prepared);
        let source = owed.source();
        let digest = durable_source(source).map(|ds| store::key_digest(ds, owed.key()));
        custody
            .put_owed(owed)
            .map_err(|_| HeldCause::CustodyBound)?;
        bound?;
        self.mark_key(source, digest.ok_or(HeldCause::Incompatible)?, true);
        Ok(())
    }

    /// Exact receipt for this acquisition: discharges a matching debt or
    /// upgrades the live chain. Store evidence is never money/ACK equivalence.
    pub(in crate::snapshots) fn receipt_acquisition(
        &self,
        acquisition: &mut FinishAcquisition,
        receipt: &ReceiptProof,
    ) -> Result<(), HeldCause> {
        let custody = acquisition.custody_mut();
        if let Some(owed) = custody.take_owed() {
            return match self.discharge_owed(owed, receipt) {
                Ok(chain) => custody
                    .put_chain(chain)
                    .map_err(|_| HeldCause::CustodyBound),
                Err(owed) => {
                    custody
                        .put_owed(owed)
                        .map_err(|_| HeldCause::CustodyBound)?;
                    Err(HeldCause::Incompatible)
                }
            };
        }
        let chain = custody.chain_mut().ok_or(HeldCause::Incompatible)?;
        chain.receipted(receipt.identity())?;
        // An index-held marker for this key is fulfilled by its exact receipt.
        if let (Some(ds), Some(mut stores)) = (durable_source(chain.source()), self.durable()) {
            stores.clear_owed(store::key_digest(ds, chain.key()));
        }
        Ok(())
    }

    /// Same O lineage, full scope and certificate object before replacing the
    /// checkpoint; any advance invalidates the stale candidate.
    pub(crate) fn advance_owed(
        &self,
        owed: &mut ReceiptOwed,
        checkpoint: &Checkpoint,
    ) -> Result<(), HeldCause> {
        let birth = owed.chain.object().2;
        let old = owed
            .checkpoint
            .durable_certificate(birth)
            .ok_or(HeldCause::Incompatible)?;
        let new = checkpoint
            .durable_certificate(birth)
            .ok_or(HeldCause::Incompatible)?;
        if checkpoint.scope() != owed.chain.file_scope()
            || (new.device, new.inode) != (old.device, old.inode)
            || new.sealed_offset < old.sealed_offset
        {
            return Err(HeldCause::Incompatible);
        }
        // Funded in place: the replacement may not exceed the paid copy.
        if checkpoint_bytes(checkpoint).ok_or(HeldCause::CustodyBound)?
            > checkpoint_bytes(&owed.checkpoint).ok_or(HeldCause::CustodyBound)?
        {
            return Err(HeldCause::CustodyBound);
        }
        owed.checkpoint.clone_from(checkpoint);
        owed.candidate = None;
        let ds = durable_source(owed.source()).ok_or(HeldCause::Incompatible)?;
        if let Some(mut stores) = self.durable() {
            stores.set_owed(store::key_digest(ds, owed.key()), OwedMark::Hold(ds));
        }
        Ok(())
    }

    /// Refusal returns the original non-Clone debt unchanged.
    #[allow(clippy::result_large_err)] // The debt itself is the refusal value.
    pub(crate) fn discharge_owed(
        &self,
        owed: ReceiptOwed,
        receipt: &ReceiptProof,
    ) -> Result<AcquiredChain, ReceiptOwed> {
        let Some(ds) = durable_source(owed.source()) else {
            return Err(owed);
        };
        if !owed.matches(receipt) {
            return Err(owed);
        }
        let digest = store::key_digest(ds, owed.key());
        // Full current-stamp delivery revalidation of a possibly delayed proof.
        let current = self.durable().is_some_and(|mut stores| {
            stores
                .slot(ds)
                .as_ref()
                .is_some_and(|slot| slot.store.receipt_current(receipt))
        });
        if !current {
            return Err(owed);
        }
        let ReceiptOwed {
            mut chain,
            checkpoint,
            candidate,
        } = owed;
        if chain.receipted(receipt.identity()).is_err() {
            return Err(ReceiptOwed {
                chain,
                checkpoint,
                candidate,
            });
        }
        if let Some(mut stores) = self.durable() {
            stores.clear_owed(digest);
        }
        Ok(chain)
    }

    /// The generic funded P3 return; the debt marker stays index-held either way.
    pub(crate) fn return_owed_taken(
        &self,
        key: String,
        mut taken: Box<Taken<CachedJsonlReduction>>,
        live_bytes: usize,
    ) -> OwedAdmission {
        taken.finalization_charge = live_bytes;
        match self.return_prepared_taken(key, taken) {
            Ok(()) => OwedAdmission::Admitted,
            Err(taken) => OwedAdmission::Refused(taken),
        }
    }

    /// Owed completion admission; never a write candidate (no post-save offer).
    pub(in crate::snapshots) fn retain_owed_completion(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
    ) -> OwedCompletionAdmission {
        match self.insert_with_custody(key, completed, live_bytes, false, false, false) {
            Ok(_) => OwedCompletionAdmission::Admitted,
            Err(completed) => OwedCompletionAdmission::Refused(completed),
        }
    }

    /// The committed index owns the key; this content-free marker keeps it in
    /// the discovery walk before recent-file/size/prune exclusions.
    pub(in crate::snapshots) fn retain_owed_discovery(&self, source: SnapshotSource, key: &str) {
        let Some(ds) = durable_source(source) else {
            return;
        };
        if let Some(mut stores) = self.durable() {
            let digest = store::key_digest(ds, key);
            if stores.owed_mark(&digest) == OwedMark::None {
                stores.set_owed(digest, OwedMark::Owed(ds));
            }
        }
    }

    /// Age-independent: debt, a pending receipt, a D3 hold or the source-wide
    /// conservative bit keeps the key discoverable.
    pub(in crate::snapshots) fn owes_discovery(&self, source: SnapshotSource, key: &str) -> bool {
        !matches!(self.owed_before_skip(source, key), OwedQuery::None)
    }
}

fn checkpoint_owned(acquisition: &FinishAcquisition) -> Result<Checkpoint, HeldCause> {
    // Charged by the caller on this acquisition's active lease before the copy.
    acquisition
        .checkpoint()
        .cloned()
        .ok_or(HeldCause::Incompatible)
}

impl HeapLayoutBound for ReceiptOwed {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            chain,
            checkpoint,
            candidate: _, // canonical RecordIdentity has no owned allocations
        } = self;
        chain.heap_bound(c)?;
        checkpoint.heap_bound(c)
    }
}
