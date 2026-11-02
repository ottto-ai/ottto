//! One dispatch table for admitted durable sources. ON admits v3 reductions only.
use super::sampled_jsonl::durable;
use super::*;
use crate::durable_tail_codec::Corrupt;
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
    /// Its index routes through the state v2 store. Only ever set: a published
    /// route's custody wins, and clearing it would let v1 load the frozen
    /// JSON. Leaving needs an explicit export back to v1.
    pub(crate) state_v2: bool,
    pub(crate) write_format: u16,
    pub(crate) representations: &'static [Representation],
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
        state_v2: true,
        write_format: 3,
        representations: &representations(
            "cf70e0f79a51e32fcf63c592302c5fa66289c66eafb1bf426597d3b873378bc3",
        ),
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
        state_v2: true,
        write_format: 3,
        representations: &representations(
            "3b7390ea33f805055983bd87d94cbcd59dbf528f1ad066c1f52316a7133bb189",
        ),
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
        // Pi joins the v2 store in its own later step.
        state_v2: false,
        write_format: 3,
        representations: &representations(
            "10a14138dc3d8c6c41f499fb728e96b9755ab21b87b7e850386a2c39a513f527",
        ),
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::pi::verify_body,
        put: durable::pi::put_body,
        take: durable::pi::take_body,
        shape_extension: durable::pi::shape_extension,
    },
];

impl scan_index_persistence::Source {
    // Lives here, not beside the enum: the integration tests compile that file alone.
    pub(crate) fn snapshot(self) -> SnapshotSource {
        match self {
            Self::Claude => SnapshotSource::ClaudeCode,
            Self::Codex => SnapshotSource::Codex,
            Self::Pi => SnapshotSource::Pi,
        }
    }
}

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
