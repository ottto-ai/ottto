//! One dispatch table for admitted durable sources. ON admits v3 reductions only.
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

const fn representations(pin: &'static str) -> [Representation; 1] {
    [Representation {
        format: 3,
        allowlist_pin: pin,
        header_bytes: crate::durable_tail_store::HEADER_V3_BYTES,
    }]
}

/// How a durable-restored read that ends strictly below the frozen accepted
/// extent is treated (`restored_behind_accepted`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BelowAccepted {
    /// The accepted floor holds the read.
    Held,
    /// A restored Tail publishes below it.
    Tail,
}

pub(crate) struct Properties {
    pub(crate) source: DurableSource,
    pub(crate) snapshot: SnapshotSource,
    pub(crate) tag: u8,
    pub(crate) below_accepted: BelowAccepted,
    pub(crate) write_format: u16,
    pub(crate) representations: &'static [Representation],
    #[cfg(test)]
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
    /// The complete structural walk, including the end check, on the
    /// caller's decoder (which may observe it, e.g. for private labels).
    pub(super) verify: fn(&mut crate::durable_tail_codec::Dec<'_>) -> Result<(), Corrupt>,
    /// The body walks and what the source's body adds to the allowlist shape.
    pub(super) put: durable::PutBody,
    pub(super) take:
        fn(&mut crate::durable_tail_codec::Dec<'_>) -> Result<durable::Decoded, Corrupt>,
    pub(super) shape_extension: fn(&mut crate::durable_tail_codec::Shape),
}

// Current PL-retained schema only. Historical pins refuse at dispatch; there is
// no reader-first dual-pin path. Only v3 uses this body.
// Enum ordinals index this table and Stores' slots; tags remain independent wire IDs.
pub(crate) const SOURCES: &[Properties] = &[
    Properties {
        source: DurableSource::ClaudeCode,
        snapshot: SnapshotSource::ClaudeCode,
        tag: 1,
        below_accepted: BelowAccepted::Held,
        write_format: 3,
        representations: &representations(
            "95c373175449b72f29d65ad493f5506f6980a338b57e59560a345b0ca0a02cd2",
        ),
        #[cfg(test)]
        encode: durable::encode_body,
        #[cfg(test)]
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify_body,
        put: durable::put_body,
        take: durable::take_body,
        shape_extension: durable::no_shape_extension,
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        tag: 2,
        below_accepted: BelowAccepted::Tail,
        write_format: 3,
        representations: &representations(
            "458f4632159f42471342573ed64a7071c7e3376a7ebcdbdec5eb603e8bb0b3d0",
        ),
        #[cfg(test)]
        encode: durable::encode_body,
        #[cfg(test)]
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify_body,
        put: durable::put_body,
        take: durable::take_body,
        shape_extension: durable::no_shape_extension,
    },
    Properties {
        source: DurableSource::Pi,
        snapshot: SnapshotSource::Pi,
        tag: 3,
        below_accepted: BelowAccepted::Tail,
        write_format: 3,
        representations: &representations(
            "c4f301b3ec5afe28933bfb8af315fe3061fd6d93184589f559206b38d7f81ce8",
        ),
        #[cfg(test)]
        encode: durable::encode_body,
        #[cfg(test)]
        decode: durable::decode_body,
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::pi::verify_body,
        put: durable::pi::put_body,
        take: durable::pi::take_body,
        shape_extension: durable::pi::shape_extension,
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

/// A source without a durable row has no restored read to report.
pub(crate) fn below_accepted(source: SnapshotSource) -> BelowAccepted {
    DurableSource::from_snapshot(source).map_or(BelowAccepted::Held, |source| {
        source.properties().below_accepted
    })
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
