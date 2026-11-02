//! Record-format details are separate from source identity and routing.
use super::super::sampled_jsonl::durable;
use super::*;
use crate::durable_tail_codec::Corrupt;
use crate::durable_tail_store::Digest32;

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

pub(crate) struct RecordProperties {
    pub(crate) write_format: u16,
    pub(crate) representations: &'static [Representation],
    #[cfg(unix)]
    pub(in crate::snapshots) decode_bounded:
        fn(
            &[u8],
            SnapshotSource,
            &mut crate::durable_tail_store::ActiveLease,
        ) -> Result<durable::Decoded, crate::durable_tail_codec::DecodeFailure>,
    /// The complete structural walk, including the end check, on the
    /// caller's decoder (which may observe it, e.g. for private labels).
    pub(in crate::snapshots) verify:
        fn(&mut crate::durable_tail_codec::Dec<'_>) -> Result<(), Corrupt>,
    /// The body walks and what the source's body adds to the allowlist shape.
    pub(in crate::snapshots) put: durable::PutBody,
    pub(in crate::snapshots) take:
        fn(&mut crate::durable_tail_codec::Dec<'_>) -> Result<durable::Decoded, Corrupt>,
    pub(in crate::snapshots) shape_extension: fn(&mut crate::durable_tail_codec::Shape),
}

const RECORDS: &[RecordProperties] = &[
    RecordProperties {
        write_format: 3,
        representations: &representations(
            "95c373175449b72f29d65ad493f5506f6980a338b57e59560a345b0ca0a02cd2",
        ),
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify_body,
        put: durable::put_body,
        take: durable::take_body,
        shape_extension: durable::no_shape_extension,
    },
    RecordProperties {
        write_format: 3,
        representations: &representations(
            "458f4632159f42471342573ed64a7071c7e3376a7ebcdbdec5eb603e8bb0b3d0",
        ),
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::verify_body,
        put: durable::put_body,
        take: durable::take_body,
        shape_extension: durable::no_shape_extension,
    },
    RecordProperties {
        write_format: 3,
        representations: &representations(
            "c4f301b3ec5afe28933bfb8af315fe3061fd6d93184589f559206b38d7f81ce8",
        ),
        #[cfg(unix)]
        decode_bounded: durable::decode_body_bounded,
        verify: durable::pi::verify_body,
        put: durable::pi::put_body,
        take: durable::pi::take_body,
        shape_extension: durable::pi::shape_extension,
    },
];

// Preserve existing record callers while source identity/routing has no format fields.
impl std::ops::Deref for Properties {
    type Target = RecordProperties;
    fn deref(&self) -> &Self::Target {
        &RECORDS[self.source.slot()]
    }
}

impl RecordProperties {
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
}

impl Properties {
    pub(crate) fn allowlist(&self) -> Digest32 {
        sampled_jsonl::durable::allowlist_digest(self.snapshot)
    }
}
