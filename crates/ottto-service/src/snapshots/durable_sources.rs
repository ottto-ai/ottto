//! One dispatch table for admitted durable sources. Rows retain the v1 wire contract.
use super::sampled_jsonl::{durable, CachedJsonlReduction};
use super::*;
use crate::durable_tail_codec::{Corrupt, Refuse};
use crate::durable_tail_store::{Digest32, DurableSource};

pub(crate) struct Properties {
    pub(crate) source: DurableSource,
    pub(crate) snapshot: SnapshotSource,
    pub(crate) tag: u8,
    pub(crate) format: u16,
    pub(crate) allowlist_pin: &'static str,
    pub(super) encode: fn(&CachedJsonlReduction, usize, u64) -> Result<Vec<u8>, Refuse>,
    #[cfg(test)]
    pub(super) decode: fn(&[u8], SnapshotSource) -> Result<durable::Decoded, Corrupt>,
    #[cfg(unix)]
    pub(super) decode_bounded:
        fn(
            &[u8],
            SnapshotSource,
            &mut crate::durable_tail_store::ActiveLease,
        ) -> Result<durable::Decoded, crate::durable_tail_codec::DecodeFailure>,
    pub(super) verify: fn(&[u8]) -> Result<(), Corrupt>,
    #[cfg(test)]
    pub(super) apply_line: fn(&Value, &mut SnapshotAccumulator),
}

// Pins from both historical v1 writers (72205c6c and ffc6c846).
// Enum ordinals index this table and Stores' slots; tags remain independent wire IDs.
pub(crate) const SOURCES: &[Properties] = &[
    Properties {
        source: DurableSource::ClaudeCode,
        snapshot: SnapshotSource::ClaudeCode,
        tag: 1,
        format: 1,
        allowlist_pin: "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c",
        encode: durable::encode_body,
        #[cfg(test)]
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify,
        #[cfg(test)]
        apply_line: apply_claude_code_line,
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        tag: 2,
        format: 1,
        allowlist_pin: "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
        encode: durable::encode_body,
        #[cfg(test)]
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify,
        #[cfg(test)]
        apply_line: apply_codex_line,
    },
];

impl DurableSource {
    pub(crate) fn slot(self) -> usize {
        self as usize
    }

    pub(crate) fn properties(self) -> &'static Properties {
        &SOURCES[self.slot()]
    }

    pub(crate) fn from_snapshot(source: SnapshotSource) -> Option<Self> {
        SOURCES
            .iter()
            .find(|row| row.snapshot == source)
            .map(|row| row.source)
    }
}

impl Properties {
    pub(crate) fn allowlist(&self) -> Digest32 {
        sampled_jsonl::durable::allowlist_digest(self.snapshot)
    }
}
