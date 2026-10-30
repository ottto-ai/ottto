//! One dispatch table for admitted durable sources. Each source admits exact v1/v3 representations.
use super::sampled_jsonl::durable;
#[cfg(test)]
use super::sampled_jsonl::CachedJsonlReduction;
use super::*;
use crate::durable_tail_codec::Corrupt;
#[cfg(test)]
use crate::durable_tail_codec::Refuse;
use crate::durable_tail_store::{Digest32, DurableSource};

pub(crate) struct Representation {
    pub(crate) format: u16,
    pub(crate) allowlist_pin: &'static str,
    pub(crate) header_bytes: usize,
}

const fn representations(pin: &'static str) -> [Representation; 2] {
    [
        Representation {
            format: 1,
            allowlist_pin: pin,
            header_bytes: crate::durable_tail_store::HEADER_BYTES,
        },
        Representation {
            format: 3,
            allowlist_pin: pin,
            header_bytes: crate::durable_tail_store::HEADER_V3_BYTES,
        },
    ]
}

pub(crate) struct Properties {
    pub(crate) source: DurableSource,
    pub(crate) snapshot: SnapshotSource,
    pub(crate) tag: u8,
    pub(crate) write_format: u16,
    pub(crate) representations: &'static [Representation],
    #[cfg(test)]
    pub(super) encode: fn(&CachedJsonlReduction, usize, u64) -> Result<Vec<u8>, Refuse>,
    pub(super) decode: fn(&[u8], SnapshotSource) -> Result<durable::Decoded, Corrupt>,
    #[cfg(unix)]
    pub(super) decode_bounded:
        fn(
            &[u8],
            SnapshotSource,
            &mut crate::durable_tail_store::ActiveLease,
        ) -> Result<durable::Decoded, crate::durable_tail_codec::DecodeFailure>,
    pub(super) verify: fn(&[u8]) -> Result<(), Corrupt>,
    pub(super) apply_line: fn(&Value, &mut SnapshotAccumulator),
}

// Current PL-retained schema only. Historical pins refuse at dispatch; there is
// no reader-first dual-pin path. Both admitted envelope versions use this body.
// Enum ordinals index this table and Stores' slots; tags remain independent wire IDs.
pub(crate) const SOURCES: &[Properties] = &[
    Properties {
        source: DurableSource::ClaudeCode,
        snapshot: SnapshotSource::ClaudeCode,
        tag: 1,
        // Advance only with the atomic native write-ahead activation.
        write_format: 1,
        representations: &representations(
            "95c373175449b72f29d65ad493f5506f6980a338b57e59560a345b0ca0a02cd2",
        ),
        #[cfg(test)]
        encode: durable::encode_body,
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify,
        apply_line: apply_claude_code_line,
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        tag: 2,
        // Advance only with the atomic native write-ahead activation.
        write_format: 1,
        representations: &representations(
            "458f4632159f42471342573ed64a7071c7e3376a7ebcdbdec5eb603e8bb0b3d0",
        ),
        #[cfg(test)]
        encode: durable::encode_body,
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify,
        apply_line: apply_codex_line,
    },
    Properties {
        source: DurableSource::Pi,
        snapshot: SnapshotSource::Pi,
        tag: 3,
        write_format: 3,
        representations: &[Representation {
            format: 3,
            // PROVISIONAL: covers the shared E→PL shape. Do not merge this value.
            // The single shipped A_P repin follows Lead B's M-2 Pi fields merging
            // into this branch and must be reviewed by SOURCE.
            allowlist_pin: "2b5c22e9aaa50964dba5ea7e4f148a826a246fffa9efc4925895dd0a6d654260",
            header_bytes: crate::durable_tail_store::HEADER_V3_BYTES,
        }],
        #[cfg(test)]
        encode: durable::encode_body,
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::pi::verify,
        apply_line: apply_pi_line,
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
    pub(crate) fn representation(
        &self,
        format: u16,
        allowlist: &Digest32,
    ) -> Option<&'static Representation> {
        self.representations.iter().find(|r| {
            r.format == format
                && crate::durable_tail_store::parse_hex_digest(r.allowlist_pin).as_ref()
                    == Some(allowlist)
        })
    }

    pub(crate) fn allowlist(&self) -> Digest32 {
        sampled_jsonl::durable::allowlist_digest(self.snapshot)
    }
}
