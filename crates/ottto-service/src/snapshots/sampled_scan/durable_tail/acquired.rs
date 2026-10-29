//! Wire protocol and immutable counting inputs for the admitted envelopes.
//! Native acquisition custody is added with its production consumers.
#[cfg(test)]
use super::SnapshotAccumulator;
use super::{store, CachedJsonlReduction, SnapshotSource};

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
    #[cfg(test)]
    pub(in crate::snapshots) fn from_accumulator(
        accumulator: &SnapshotAccumulator,
    ) -> Result<Self, store::Refusal> {
        Self::canonical(accumulator.source, accumulator.durable_counting())
    }
    fn canonical(
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
    // Inspection helper for the scope-contract controls until native v3 activation.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; 13] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
