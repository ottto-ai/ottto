//! Receipt debt owns acquisition facts, never parsed output or an ACK.
//!
//! The parent integrates this module with the acquired-chain and prepared-write
//! owners. A candidate-less debt deliberately cannot match any receipt.
use super::{AcquiredChain, HeldCause, PreparedRecord, ReceiptProof, RecordIdentity};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::snapshots::SnapshotSource;
use crate::transcript_acquisition::Checkpoint;

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
            || (identity.protocol() != self.chain.protocol()
                && !(self.chain.write_ahead_eligible()
                    && identity.protocol() == super::AcquisitionProtocol::WriteAhead))
        {
            return Err(HeldCause::Incompatible);
        }
        // RecordIdentity has only fixed binding/certificate/wire facts. This
        // copy neither clones the acquired strings nor changes candidate bytes.
        self.candidate = Some(identity.clone());
        Ok(())
    }
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
