//! Tail state codecs: how one source's PRE-finalization reduction splits into
//! the head and pages of the state database's Tail store (`state_v2::tail`),
//! and back.
//!
//! A head binds the file's route and parse-time meaning, never a delivery
//! input, so an upload-policy, account or sidecar change never voids it.
//! Encoding refuses no record for policy: labels are data, filtered only at
//! upload. Stored state that is missing or inconsistent is a reconstruction
//! cause the caller counts, never a default-empty success.
use super::state_v2::{Change, Collection, CollectionMeta, Shape as PageShape, StagedFile};
use super::*;
use crate::durable_tail_codec::{Corrupt, Dec, Durable, Enc, HDigest, Refuse};
use crate::transcript_acquisition::DurableCertificate;

pub(in crate::snapshots) mod claude;
pub(in crate::snapshots) mod load;
pub(in crate::snapshots) mod seam;

/// One collection a source stores in pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct CollectionSpec {
    pub(in crate::snapshots) collection: Collection,
    pub(in crate::snapshots) shape: PageShape,
    /// Elements per page for `Slot` and `Log` (element `i` on page `i / g`);
    /// 0 for `Hour`, one page per hour.
    pub(in crate::snapshots) g: u32,
    /// Staged with its table entry even when empty, so a load can tell an
    /// empty collection from a missing one.
    pub(in crate::snapshots) required: bool,
}

/// Why stored state cannot be reused. Each is a counted reconstruction,
/// never a hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum ReconstructCause {
    /// Bytes that do not decode, or decoded facts that contradict each other.
    Corrupt,
    /// A capture mode or page geometry this build does not read this way.
    Incompatible,
    /// A required collection, or some of its elements, is missing.
    Incomplete,
    /// A lower revision this build has no decoder for.
    Revision,
    /// The head was written for another route, scan root or path.
    Identity,
    /// A re-derived content field no longer matches its stored digest.
    NotRederivable,
}
impl ReconstructCause {
    pub(in crate::snapshots) fn label(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::Incompatible => "incompatible",
            Self::Incomplete => "incomplete",
            Self::Revision => "revision",
            Self::Identity => "identity",
            Self::NotRederivable => "not_rederivable",
        }
    }
}
impl From<Corrupt> for ReconstructCause {
    fn from(_: Corrupt) -> Self {
        Self::Corrupt
    }
}

/// What a head binds: the route and file it was reduced for, and the
/// parse-time capture mode. The route is the destination-scoped index path,
/// so it names the upload destination namespace. The reduction revision is
/// the head's stored revision. Upload context, replay generation, the
/// artifacts flag, the sidecar digest, the account witness and version
/// strings are not inputs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) struct HeadIdentity {
    binding: [u8; 32],
    capture: bool,
}
impl HeadIdentity {
    pub(in crate::snapshots) fn new(
        index_path: &Path,
        source: SnapshotSource,
        scan_root: &Path,
        path: &Path,
        request_identity_capture: bool,
    ) -> Self {
        let (index_path, scan_root, path) = (
            local_index_key(index_path),
            local_index_key(scan_root),
            local_index_key(path),
        );
        let mut hash = Sha256::new();
        for part in [
            "ottto-tail-head-identity:v1",
            &index_path,
            source.api_slug(),
            &scan_root,
            &path,
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        Self {
            binding: hash.finalize().into(),
            capture: request_identity_capture,
        }
    }
    fn put(&self, e: &mut Enc<'_>) -> Result<(), Refuse> {
        self.binding.put_h(e, "HeadIdentity.binding")?;
        self.capture.put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Ok(Self {
            binding: <[u8; 32]>::take_h(d)?,
            capture: bool::take(d)?,
        })
    }
    /// Decodes only the head's leading identity, before any page or private
    /// field: another route is `Identity`, another capture mode `Incompatible`.
    pub(in crate::snapshots) fn check(&self, head: &[u8]) -> Result<(), ReconstructCause> {
        let stored = Self::take(&mut Dec::new(head))?;
        if stored.binding != self.binding {
            return Err(ReconstructCause::Identity);
        }
        if stored.capture != self.capture {
            return Err(ReconstructCause::Incompatible);
        }
        Ok(())
    }
}

/// A decoded head's parts outside the accumulator.
pub(in crate::snapshots) struct DecodedHead {
    pub(in crate::snapshots) certificate: DurableCertificate,
    pub(in crate::snapshots) report: JsonlReadReport,
    pub(in crate::snapshots) scalars: (usize, usize, bool),
    /// Digests of the re-derived (`X`) fields, checked after re-derivation.
    pub(in crate::snapshots) rederive: sampled_jsonl::durable::Rederive,
}

// The checkpoint as the head stores it: samples as offset and SHA-256 only.
crate::durable_tail_codec::durable_struct!(DurableCertificate {
    N device: u64,
    N inode: u64,
    N length: u64,
    N modified: (i64, i64),
    N birth_nanos: u64,
    N sealed_offset: u64,
    N sample_len: u32,
    H head_sha256: [u8; 32],
    H boundary_sha256: [u8; 32],
    N verified_unix_seconds: u64,
    N audit_debt_unix_seconds: Option<u64>,
});

/// One source's Tail codec. Generic code iterates `collections()`, never a
/// fixed list.
pub(in crate::snapshots) trait TailSource {
    const SOURCE: SnapshotSource;
    /// Bumped only when the meaning of the parse-time reduction changes.
    const REDUCTION_REVISION: u32;
    fn collections() -> &'static [CollectionSpec];
    /// How many elements of `collection` the accumulator holds.
    fn elements(acc: &SnapshotAccumulator, collection: Collection) -> u64;
    /// A finish-only or live field that must still be empty at the seam.
    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str>;
    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse>;
    /// A `Log` collection's elements, in its full encode's (sorted) order.
    fn log_keys(acc: &SnapshotAccumulator, collection: Collection) -> Vec<&String>;
    /// One `Log` page holding `keys`, in this order.
    fn log_page(collection: Collection, keys: &[&String]) -> Result<Vec<u8>, Refuse>;
    /// A stored `Log` page's elements, in stored order.
    fn log_page_keys(collection: Collection, bytes: &[u8])
        -> Result<Vec<String>, ReconstructCause>;
    /// Every page of `collection`, by position.
    fn encode_pages(
        acc: &SnapshotAccumulator,
        collection: Collection,
    ) -> Result<Vec<(u64, Vec<u8>)>, Refuse>;
    /// Replaces `into` with the head's fields; decode pages after it.
    fn decode_head(
        revision: u32,
        head: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<DecodedHead, ReconstructCause>;
    /// One page, in ascending page order per collection.
    fn decode_page(
        collection: Collection,
        page: u64,
        bytes: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<(), ReconstructCause>;
    /// Facts the decoded state must satisfy beyond its counts.
    fn facts(acc: &SnapshotAccumulator) -> Result<(), ReconstructCause>;

    /// After every page: each declared collection's stored geometry and
    /// element count against the decoded state, then the source's facts.
    fn validate_loaded(
        acc: &SnapshotAccumulator,
        stored: &BTreeMap<Collection, CollectionMeta>,
    ) -> Result<(), ReconstructCause> {
        if stored.keys().any(|collection| {
            !Self::collections()
                .iter()
                .any(|spec| spec.collection == *collection)
        }) {
            return Err(ReconstructCause::Corrupt);
        }
        for spec in Self::collections() {
            let Some(meta) = stored.get(&spec.collection) else {
                if spec.required {
                    return Err(ReconstructCause::Incomplete);
                }
                continue;
            };
            if meta.shape != spec.shape || meta.elements_per_page != spec.g {
                return Err(ReconstructCause::Incompatible);
            }
            if meta.elements != Self::elements(acc, spec.collection) {
                return Err(ReconstructCause::Incomplete);
            }
        }
        Self::facts(acc)
    }
}

/// A complete stage of one file: its head and every page, replacing all
/// stored rows.
pub(in crate::snapshots) fn stage_full<S: TailSource>(
    view: &PreFinalization<'_>,
    certificate: &DurableCertificate,
    id: &HeadIdentity,
) -> Result<StagedFile, Refuse> {
    let mut staged = StagedFile {
        revision: S::REDUCTION_REVISION,
        head: S::encode_head(view, certificate, id)?,
        change: Change::Reset,
        ..StagedFile::default()
    };
    for spec in S::collections() {
        let elements = S::elements(view.accumulator, spec.collection);
        if elements == 0 && !spec.required {
            continue;
        }
        staged.collections.insert(
            spec.collection,
            CollectionMeta {
                shape: spec.shape,
                elements_per_page: spec.g,
                elements,
            },
        );
        for (page, bytes) in S::encode_pages(view.accumulator, spec.collection)? {
            staged.pages.insert((spec.collection, page), bytes);
        }
    }
    Ok(staged)
}

/// One exactly sized value: the field walk counts, then writes.
fn encode(put: impl Fn(&mut Enc<'_>) -> Result<(), Refuse>) -> Result<Vec<u8>, Refuse> {
    let mut count = Enc::count(usize::MAX);
    put(&mut count)?;
    let len = count.counted();
    let mut out = Vec::with_capacity(len);
    let mut writer = Enc::writer(&mut out, len);
    put(&mut writer)?;
    writer.finish_written()?;
    Ok(out)
}

/// `Slot` and `Log` pages: element `i` on page `i / g`, each page a count and
/// its elements.
fn fixed_pages<T>(
    items: &[T],
    g: u32,
    put: impl Fn(&T, &mut Enc<'_>) -> Result<(), Refuse>,
) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
    items
        .chunks(g as usize)
        .enumerate()
        .map(|(page, chunk)| Ok((page as u64, page_bytes(chunk.iter(), &put)?)))
        .collect()
}

/// One page: a count, then each element.
fn page_bytes<'a, T: 'a>(
    items: impl ExactSizeIterator<Item = &'a T> + Clone,
    put: impl Fn(&T, &mut Enc<'_>) -> Result<(), Refuse>,
) -> Result<Vec<u8>, Refuse> {
    encode(|e| {
        e.varint(items.len() as u64)?;
        items.clone().try_for_each(|item| put(item, e))
    })
}

/// One page's elements, each through `take`. An empty page, a count above
/// `g` (when set) or trailing bytes are corrupt.
fn read_page(
    bytes: &[u8],
    g: u32,
    mut take: impl FnMut(&mut Dec<'_>) -> Result<(), ReconstructCause>,
) -> Result<(), ReconstructCause> {
    let mut d = Dec::new(bytes);
    let count = d.varint()?;
    if count == 0 || (g > 0 && count > u64::from(g)) {
        return Err(ReconstructCause::Corrupt);
    }
    for _ in 0..count {
        take(&mut d)?;
    }
    Ok(d.finish()?)
}

/// A `Slot` page must start where the previous pages ended.
fn slot_start(page: u64, g: u32, held: usize) -> Result<(), ReconstructCause> {
    if page.checked_mul(u64::from(g)) == Some(held as u64) {
        Ok(())
    } else {
        Err(ReconstructCause::Corrupt)
    }
}
