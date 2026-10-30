//! Acquisition provenance travels with the existing checkpoint custody owner.
//! These fields never become index membership, replay permission or money ACKs.
use super::SnapshotAccumulator;
use super::{store, CachedJsonlReduction, HeldCause, SnapshotSource};
use crate::transcript_acquisition as ta;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcquisitionProtocol {
    Legacy,
    WriteAhead,
}

/// Canonical C: schema, state presence, cutover presence/value, counting version.
/// ACK evidence deliberately stays outside this immutable scope input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ImmutableCounting {
    bytes: [u8; 13],
}
impl ImmutableCounting {
    pub(crate) fn from_reduction(reduction: &CachedJsonlReduction) -> Result<Self, store::Refusal> {
        Self::canonical(reduction.source(), reduction.durable_counting())
    }
    pub(in crate::snapshots) fn from_accumulator(
        accumulator: &SnapshotAccumulator,
    ) -> Result<Self, store::Refusal> {
        Self::canonical(accumulator.source, accumulator.durable_counting())
    }
    pub(super) fn canonical(
        source: SnapshotSource,
        contract: Option<(Option<i64>, u8, u8)>,
    ) -> Result<Self, store::Refusal> {
        if store::DurableSource::from_snapshot(source).is_none()
            || source == SnapshotSource::ClaudeCode && contract.is_some()
        {
            return Err(store::Refusal::Corrupt);
        }
        let mut bytes = [0; 13];
        bytes[..2].copy_from_slice(&1u16.to_le_bytes());
        if let Some((cutover, version, evidence)) = contract {
            if version > 2 || evidence > 2 {
                return Err(store::Refusal::Corrupt);
            }
            bytes[2] = 1;
            bytes[3] = u8::from(cutover.is_some());
            bytes[4..12].copy_from_slice(&cutover.unwrap_or(0).to_le_bytes());
            bytes[12] = version;
        }
        Ok(Self { bytes })
    }
    pub(crate) fn bytes(&self) -> &[u8; 13] {
        &self.bytes
    }
}

/// Non-Clone: changing graph ownership moves this exact acquisition provenance.
/// The opened object triple is fixed metadata; O itself is the native identity.
pub(crate) struct AcquiredChain {
    source: SnapshotSource,
    key: String,
    opened_object_identity: String,
    file_scope: ta::Scope,
    object: (u64, u64, u64),
    binding: store::Binding,
    acquired_revision: u64,
    protocol: AcquisitionProtocol,
    write_ahead_eligible: bool,
    committed_generation: u64,
}
impl AcquiredChain {
    pub(crate) fn source(&self) -> SnapshotSource {
        self.source
    }
    pub(crate) fn key(&self) -> &str {
        &self.key
    }
    pub(crate) fn opened_object_identity(&self) -> &str {
        &self.opened_object_identity
    }
    pub(crate) fn file_scope(&self) -> &ta::Scope {
        &self.file_scope
    }
    /// Device, inode and birth nanos of the object O was computed on.
    pub(crate) fn object(&self) -> (u64, u64, u64) {
        self.object
    }
    pub(crate) fn binding(&self) -> &store::Binding {
        &self.binding
    }
    pub(crate) fn acquired_revision(&self) -> u64 {
        self.acquired_revision
    }
    pub(crate) fn protocol(&self) -> AcquisitionProtocol {
        self.protocol
    }
    pub(crate) fn write_ahead_eligible(&self) -> bool {
        self.write_ahead_eligible
    }
    pub(crate) fn committed_generation(&self) -> u64 {
        self.committed_generation
    }
    /// Protocol the next record carries: only an eligible native acquisition
    /// writes WriteAhead; a Legacy origin stays Legacy across rewrites.
    pub(crate) fn write_protocol(&self) -> AcquisitionProtocol {
        if self.write_ahead_eligible {
            AcquisitionProtocol::WriteAhead
        } else {
            self.protocol
        }
    }

    /// A later acquisition of the same object keeps r_a, protocol and
    /// eligibility; only this pass's O, binding and committed generation move.
    /// O is a fixed-width digest, so its buffer is reused, never regrown.
    pub(super) fn rebind(
        &mut self,
        opened_object_identity: &str,
        object: (u64, u64, u64),
        scope: &ta::Scope,
        binding: store::Binding,
        committed_generation: u64,
    ) -> Result<(), HeldCause> {
        if object != self.object
            || scope != &self.file_scope
            || binding.source != self.binding.source
            || binding.key != self.binding.key
            || committed_generation < self.committed_generation
        {
            return Err(HeldCause::Incompatible);
        }
        if opened_object_identity.len() > self.opened_object_identity.capacity() {
            return Err(HeldCause::CustodyBound);
        }
        self.opened_object_identity.clear();
        self.opened_object_identity.push_str(opened_object_identity);
        self.binding = binding;
        self.committed_generation = committed_generation;
        Ok(())
    }

    /// Only the store's receipt for this chain's candidate upgrades provenance.
    pub(super) fn receipted(&mut self, identity: &store::RecordIdentity) -> Result<(), HeldCause> {
        if identity.binding() != &self.binding
            || identity.acquired_revision() != self.acquired_revision
            || identity.protocol() != self.write_protocol()
        {
            return Err(HeldCause::Incompatible);
        }
        self.protocol = identity.protocol();
        Ok(())
    }
}

// These constructors are visible only to the existing native/restore adapter.
// Caller proves original O, scope, certificate, unique revision and eligibility.
pub(super) struct ChainInputs<'a> {
    pub(super) source: SnapshotSource,
    pub(super) key: &'a str,
    pub(super) opened_object_identity: &'a str,
    pub(super) object: (u64, u64, u64),
    pub(super) checkpoint: &'a ta::Checkpoint,
    pub(super) binding: store::Binding,
    pub(super) acquired_revision: u64,
    pub(super) committed_generation: u64,
}
pub(super) fn capture_chain(
    inputs: ChainInputs<'_>,
    protocol: AcquisitionProtocol,
    write_ahead_eligible: bool,
    lease: &mut store::ActiveLease,
) -> Result<AcquiredChain, store::ActiveOverBudget> {
    let scope = inputs.checkpoint.scope();
    if store::DurableSource::from_snapshot(inputs.source) != Some(inputs.binding.source) {
        return Err(store::ActiveOverBudget);
    }
    // Fund fixed metadata and all three owned strings before the first allocation.
    let bytes = std::mem::size_of::<AcquiredChain>()
        .checked_add(inputs.key.len())
        .and_then(|n| n.checked_add(inputs.opened_object_identity.len()))
        .and_then(|n| n.checked_add(scope.0.len()))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(store::ActiveOverBudget)?;
    lease.charge(bytes)?;
    Ok(AcquiredChain {
        source: inputs.source,
        key: inputs.key.to_owned(),
        opened_object_identity: inputs.opened_object_identity.to_owned(),
        file_scope: scope.clone(),
        object: inputs.object,
        binding: inputs.binding,
        acquired_revision: inputs.acquired_revision,
        protocol,
        write_ahead_eligible,
        committed_generation: inputs.committed_generation,
    })
}
/// Restored provenance: the caller proved the original v1 adapter revision or
/// the verified v3 acquisition fields. A format rewrite never grants eligibility.
pub(super) fn restore_chain(
    inputs: ChainInputs<'_>,
    protocol: AcquisitionProtocol,
    lease: &mut store::ActiveLease,
) -> Result<AcquiredChain, store::ActiveOverBudget> {
    capture_chain(inputs, protocol, false, lease)
}

impl crate::heap_layout_bound::HeapLayoutBound for AcquiredChain {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // Inline fields are charged by the enclosing owner; every owned capacity is new.
        let Self {
            source: _,
            key,
            opened_object_identity,
            file_scope,
            object: _,
            binding: _,
            acquired_revision: _,
            protocol: _,
            write_ahead_eligible: _,
            committed_generation: _,
        } = self;
        c.add(key.capacity())?;
        c.add(opened_object_identity.capacity())?;
        c.add(file_scope.0.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [behaviour] immutable counting distinguishes absent none legacy v2 and zero date.
    #[test]
    fn immutable_counting_distinguishes_absent_none_legacy_v2_and_zero_date() {
        let absent = ImmutableCounting::canonical(SnapshotSource::ClaudeCode, None).unwrap();
        assert_eq!(absent.bytes(), &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut seen = std::collections::BTreeSet::new();
        seen.insert(*absent.bytes());
        for date in [None, Some(0), Some(-1), Some(1234)] {
            for version in 0..=2 {
                let c =
                    ImmutableCounting::canonical(SnapshotSource::Codex, Some((date, version, 0)))
                        .unwrap();
                assert!(seen.insert(*c.bytes()));
                assert_eq!(c.bytes()[2], 1);
                assert_eq!(c.bytes()[3], u8::from(date.is_some()));
                assert_eq!(&c.bytes()[4..12], &date.unwrap_or(0).to_le_bytes());
                for ack in 1..=2 {
                    assert_eq!(
                        c,
                        ImmutableCounting::canonical(
                            SnapshotSource::Codex,
                            Some((date, version, ack))
                        )
                        .unwrap()
                    );
                }
            }
        }
        assert!(
            ImmutableCounting::canonical(SnapshotSource::ClaudeCode, Some((None, 0, 0))).is_err()
        );
        assert!(ImmutableCounting::canonical(SnapshotSource::Codex, Some((None, 3, 0))).is_err());
        assert!(ImmutableCounting::canonical(SnapshotSource::Codex, Some((None, 0, 3))).is_err());
    }
}
