//! Tail state codecs: how one source's PRE-finalization reduction splits into
//! the head and pages of the state database's Tail store (`state_v2::tail`),
//! and back.
//!
//! A head binds the file's route and parse-time meaning, never a delivery
//! input, so an upload-policy, account or sidecar change never voids it.
//! Encoding refuses no record for policy: labels are data, filtered only at
//! upload. Stored state that is missing or inconsistent is a reconstruction
//! cause the caller counts, never a default-empty success.
use super::state_v2::{Collection, CollectionMeta, Shape as PageShape};
use super::*;
use crate::durable_tail_codec::{durable_field, Corrupt, Dec, Durable, Enc, HDigest, Refuse};
use crate::transcript_acquisition::DurableCertificate;

pub(in crate::snapshots) mod claude;
pub(in crate::snapshots) mod codex;
pub(in crate::snapshots) mod counters;
pub(in crate::snapshots) mod load;
pub(in crate::snapshots) mod pi;
pub(in crate::snapshots) mod seam;

/// The one list of sources with a Tail codec: `$s` names the source's codec
/// type inside `$arm`; every other source takes `$none`. A source joins by
/// adding its arm here, never through its `state_v2` registry flag.
macro_rules! with_codec {
    ($source:expr, $s:ident => $arm:expr, _ => $none:expr) => {
        match $source {
            SnapshotSource::ClaudeCode => {
                type $s = claude::Claude;
                $arm
            }
            SnapshotSource::Codex => {
                type $s = codex::Codex;
                $arm
            }
            SnapshotSource::Pi => {
                type $s = pi::Pi;
                $arm
            }
        }
    };
}

/// Whether `source` has a Tail codec: its Tail counters exist, and on a Tail
/// route its reduction is never kept in RAM.
pub(in crate::snapshots) fn has_codec(source: SnapshotSource) -> bool {
    with_codec!(source, S => S::SOURCE == source, _ => false)
}

/// The reduction revision `source`'s codec writes, when it has one.
pub(in crate::snapshots) fn reduction_revision(source: SnapshotSource) -> Option<u32> {
    with_codec!(source, S => Some(S::REDUCTION_REVISION), _ => None)
}

/// The state database route `source`'s Tail lives on, when it has a codec.
/// `Err`: the route exists but cannot be read now (a database hold); the
/// caller holds the file, and RAM is never its fallback.
pub(in crate::snapshots) fn tail_route(
    source: SnapshotSource,
    index: &ScanIndex,
) -> anyhow::Result<Option<PathBuf>> {
    if !has_codec(source) {
        return Ok(None);
    }
    state_v2::runtime_path(index)
}

/// Whether `source`'s reduction is kept in RAM between reads: exactly when it
/// has no Tail codec. Retention and the take both key on this one rule, so a
/// copy is kept only where the next read takes it back. A codec source keeps
/// none, whatever its route's state.
pub(in crate::snapshots) fn keeps_ram(source: SnapshotSource) -> bool {
    !has_codec(source)
}

/// `source`'s load of `candidate` on `route`, through its codec. `live` is the
/// read's fresh accumulator, configured with this cycle's inputs.
#[allow(
    clippy::too_many_arguments,
    reason = "one codec dispatch carries the cycle's load inputs"
)]
pub(in crate::snapshots) fn load_candidate(
    source: SnapshotSource,
    index: &ScanIndex,
    route: &Path,
    candidate: &CandidateFile,
    live: &SnapshotAccumulator,
    capture: bool,
    held: &mut File,
    scope: &crate::transcript_acquisition::Scope,
) -> load::Load {
    with_codec!(
        source,
        S => load::entry::<S>(index, route, candidate, live, capture, held, scope),
        _ => load::Load::Cold(None)
    )
}

/// `key`'s accepted usage on its committed head, as (requests, tokens), for
/// a codec that stores usage before finish. `None`: no readable head, or a
/// codec whose usage folds only at finish (its totals are unknown, not zero).
pub(in crate::snapshots) fn stored_usage(
    source: SnapshotSource,
    index: &ScanIndex,
    key: &str,
) -> Option<(u64, u64)> {
    with_codec!(source, S => stored_usage_of::<S>(index, key), _ => None)
}

fn stored_usage_of<S: TailSource>(index: &ScanIndex, key: &str) -> Option<(u64, u64)> {
    if !S::USAGE_BEFORE_FINISH {
        return None;
    }
    let head = state_v2::load_head(index, key, S::REDUCTION_REVISION).ok()??;
    let mut acc = SnapshotAccumulator::new(S::SOURCE);
    S::decode_head(head.revision, &head.body, &mut acc).ok()?;
    let totals = &acc.accepted_usage_totals;
    Some((totals.request_count, totals.total_tokens()))
}

/// `source`'s pending Tail write for one completion, through its codec.
#[allow(
    clippy::too_many_arguments,
    reason = "one codec dispatch carries the completion's write inputs"
)]
pub(in crate::snapshots) fn pending(
    source: SnapshotSource,
    index: &ScanIndex,
    completed: &sampled_jsonl::CompletedNativeAcquisition,
    active: &sampled_scan::Active,
    candidate: &CandidateFile,
    held: &File,
    capture: bool,
    base: Option<seam::TailBase>,
    quiet: bool,
) -> Option<seam::PendingTail> {
    with_codec!(
        source,
        S => seam::PendingTail::new::<S>(index, completed, active, candidate, held, capture, base, quiet),
        _ => None
    )
}

/// A certified cursor job's Tail write, handed to the same staging path as an
/// ordinary completion (`pending`, then the PRE encode and native verdict).
/// A cursor certificate reports its completion unsealed (fail-closed,
/// `CompletedNativeAcquisition::unsealed`); the job's own bit is whether the
/// native EOF applied an unterminated final record past its sealed offset,
/// so only that bit drops the publish. A withheld fragment is not applied:
/// the reduction is the reduction through the sealed offset, and the next
/// read tails from there.
pub(in crate::snapshots) fn certified_job(
    tail: seam::PendingTail,
    eof_applied: bool,
) -> seam::PendingTail {
    tail.sealed_by_job(eof_applied)
}

/// `key`'s committed sealed offset on `source`'s Tail route: where its next
/// read continues, read from the head's certificate without decoding the
/// reduction. `None`: no codec, no route, no readable head, or a route that
/// cannot be read now; the caller then plans the whole file.
pub(in crate::snapshots) fn committed_sealed_offset(
    source: SnapshotSource,
    index: &ScanIndex,
    key: &str,
) -> Option<u64> {
    let revision = reduction_revision(source)?;
    tail_route(source, index).ok()??;
    let head = state_v2::load_head(index, key, revision).ok()??;
    if head.metadata_only {
        return None;
    }
    let mut d = Dec::new(&head.body);
    HeadIdentity::take(&mut d).ok()?;
    Some(DurableCertificate::take(&mut d).ok()?.sealed_offset)
}

/// Why a source's live inputs could not be installed into a loaded head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum LiveLoadError {
    /// The live input is not available now: the file holds with its debt.
    Unavailable,
    /// The stored state contradicts the live input: a counted reconstruction.
    Reconstruct(ReconstructCause),
}

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
    /// Its pages hold private strings: a rewrite or removal of a committed
    /// page stages `Change::DropsPrivate`, so the old value is purged (F3).
    pub(in crate::snapshots) private: bool,
}

/// Why stored state cannot be reused. Each is a counted reconstruction,
/// never a hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum ReconstructCause {
    /// Bytes that do not decode, or decoded facts that contradict each other.
    Corrupt,
    /// A capture mode, page geometry or revision this build does not read
    /// this way.
    Incompatible,
    /// A required collection, or some of its elements, is missing.
    Incomplete,
    /// The head was written for another route, scan root or path.
    Identity,
    /// The head's keyed fields were made under another attribution key: an
    /// explicit action (a key rotation), not a failure. Attribution toggled
    /// on or off is no rotation (`HeadIdentity::check`).
    KeyEpoch,
    /// A Codex group read from its first member (D168): a counted replay,
    /// never a load outcome or a failure after a head.
    GroupReplay,
    /// A file with a protected Codex receipt read from its start, so the
    /// receipt's prefix is reproduced (D168): a counted replay, never a load
    /// outcome or a failure after a head.
    TierPrefixReplay,
}
impl ReconstructCause {
    pub(in crate::snapshots) fn label(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::Incompatible => "incompatible",
            Self::Incomplete => "incomplete",
            Self::Identity => "identity",
            Self::KeyEpoch => "key_epoch",
            Self::GroupReplay => "group_replay",
            Self::TierPrefixReplay => "tier_prefix_replay",
        }
    }
}
impl From<Corrupt> for ReconstructCause {
    fn from(_: Corrupt) -> Self {
        Self::Corrupt
    }
}

/// What a head binds: the route and file it was reduced for, the
/// parse-time capture mode, and the epoch of the key its keyed fields were
/// made under. The route is the destination-scoped index path, so it names
/// the upload destination namespace. The reduction revision is the head's
/// stored revision. Upload context, replay generation, the artifacts flag,
/// the sidecar digest, the account witness and version strings are not
/// inputs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) struct HeadIdentity {
    binding: [u8; 32],
    capture: bool,
    /// The source's `TailSource::key_epoch` when the head was made.
    key_epoch: Option<[u8; 32]>,
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
            key_epoch: with_codec!(source, S => S::key_epoch(), _ => None),
        }
    }
    fn put(&self, e: &mut Enc<'_>) -> Result<(), Refuse> {
        self.binding.put_h(e, "HeadIdentity.binding")?;
        self.capture.put(e)?;
        // No key is all zeros: an HMAC output never is.
        self.key_epoch
            .unwrap_or_default()
            .put_h(e, "HeadIdentity.key_epoch")
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let binding = <[u8; 32]>::take_h(d)?;
        let capture = bool::take(d)?;
        let key_epoch = <[u8; 32]>::take_h(d)?;
        Ok(Self {
            binding,
            capture,
            key_epoch: (key_epoch != [0; 32]).then_some(key_epoch),
        })
    }
    /// Decodes only the head's leading identity, before any page or private
    /// field: another route is `Identity`, another capture mode
    /// `Incompatible`, another key `KeyEpoch`. `Ok(true)`: a key on one side
    /// only, so session attribution was toggled since. That is a settings
    /// change, applied forward only (D168-2): the head is reused with its
    /// keyed fields scrubbed, as a retained parse's are, never re-read.
    pub(in crate::snapshots) fn check(&self, head: &[u8]) -> Result<bool, ReconstructCause> {
        let stored = Self::take(&mut Dec::new(head))?;
        if stored.binding != self.binding {
            return Err(ReconstructCause::Identity);
        }
        if stored.capture != self.capture {
            return Err(ReconstructCause::Incompatible);
        }
        match (stored.key_epoch, self.key_epoch) {
            (Some(stored), Some(current)) if stored != current => Err(ReconstructCause::KeyEpoch),
            (stored, current) => Ok(stored != current),
        }
    }
}

/// A decoded head's parts outside the accumulator.
pub(in crate::snapshots) struct DecodedHead {
    pub(in crate::snapshots) certificate: DurableCertificate,
    pub(in crate::snapshots) report: JsonlReadReport,
    pub(in crate::snapshots) scalars: (usize, usize, bool),
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
    /// The head stores the accepted usage totals: usage is accepted while the
    /// file is read, not folded at finish.
    const USAGE_BEFORE_FINISH: bool = false;
    fn collections() -> &'static [CollectionSpec];
    /// How many elements of `collection` the accumulator holds.
    fn elements(acc: &SnapshotAccumulator, collection: Collection) -> u64;
    /// A finish-only or live field that must still be empty at the seam: the
    /// stage refuses it as an `E` field, setting that file aside alone.
    fn finish_field_nonempty(acc: &SnapshotAccumulator) -> Option<&'static str>;
    fn encode_head(
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Vec<u8>, Refuse>;
    /// A `Log` collection's elements, in its full encode's (sorted) order.
    /// A codec without a `Log` collection keeps the defaults.
    fn log_keys(_acc: &SnapshotAccumulator, _collection: Collection) -> Vec<&String> {
        Vec::new()
    }
    /// One `Log` page holding `keys`, in this order.
    fn log_page(_collection: Collection, keys: &[&String]) -> Result<Vec<u8>, Refuse> {
        page_bytes(keys.iter(), |key, e| key.put(e))
    }
    /// A stored `Log` page's elements, in stored order.
    fn log_page_keys(
        _collection: Collection,
        _bytes: &[u8],
    ) -> Result<Vec<String>, ReconstructCause> {
        Err(ReconstructCause::Corrupt)
    }
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
    /// The epoch of the key every keyed field this codec stores is made
    /// under; `None` without a key. A head from another key is never reused.
    fn key_epoch() -> Option<[u8; 32]> {
        None
    }
    /// Installs the live inputs of this read into a validated stored state,
    /// before the load publishes it as reused. `live` is the read's fresh
    /// accumulator, configured before any line (traces, parent ledgers and
    /// proof, sidecar projection, counting rule); a load never parses with it.
    /// By default a source's live inputs join at finish, never into the
    /// stored state.
    fn install_live(
        _stored: &mut SnapshotAccumulator,
        _fresh: &CandidateFile,
        _live: &SnapshotAccumulator,
    ) -> Result<(), LiveLoadError> {
        Ok(())
    }

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

/// The head envelope every codec writes: the identity, the checkpoint
/// certificate, the read report and the three reduction scalars, then the
/// codec's `lead`, the shared head-field walk and the codec's `trailer`.
/// Opening-call file paths are content: the opening-settings fact stores them
/// by call id, so no head holds them.
fn encode_envelope(
    view: &PreFinalization<'_>,
    certificate: &DurableCertificate,
    id: &HeadIdentity,
    lead: impl Fn(&mut Enc<'_>) -> Result<(), Refuse>,
    trailer: impl Fn(&mut Enc<'_>) -> Result<(), Refuse>,
) -> Result<Vec<u8>, Refuse> {
    let scalars = (
        view.recognized_usage_drop_count,
        view.positive_recognized_usage_count,
        view.positive_usage_evidence,
    );
    Enc::count_write(usize::MAX, |e| {
        e.with_moved_field("OpeningCall.files", |e| {
            id.put(e)?;
            certificate.put(e)?;
            view.report.put(e)?;
            scalars.put(e)?;
            lead(e)?;
            put_fields(view.accumulator, e)?;
            trailer(e)
        })
    })
}

/// `S`'s envelope back, at its own revision only: the accumulator, the
/// codec's `lead` and `trailer`, and the parts outside the accumulator.
fn decode_envelope<S: TailSource, L, T>(
    revision: u32,
    head: &[u8],
    lead: impl FnOnce(&mut Dec<'_>) -> Result<L, Corrupt>,
    trailer: impl FnOnce(&mut Dec<'_>) -> Result<T, Corrupt>,
) -> Result<(SnapshotAccumulator, L, T, DecodedHead), ReconstructCause> {
    if revision != S::REDUCTION_REVISION {
        return Err(ReconstructCause::Incompatible);
    }
    let mut d = Dec::new(head);
    HeadIdentity::take(&mut d)?;
    let certificate = DurableCertificate::take(&mut d)?;
    let report = JsonlReadReport::take(&mut d)?;
    let scalars = <(usize, usize, bool)>::take(&mut d)?;
    let lead = lead(&mut d)?;
    let acc = take_fields(&mut d)?;
    let trailer = trailer(&mut d)?;
    d.finish()?;
    let head = DecodedHead {
        certificate,
        report,
        scalars,
    };
    Ok((acc, lead, trailer, head))
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
    Enc::count_write(usize::MAX, |e| {
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

/// An hourly bucket's page: its hour since the epoch. A start that does not
/// parse (the parser never writes one) shares the last page.
fn hour_page(bucket_start: &str) -> u64 {
    OffsetDateTime::parse(bucket_start, &Rfc3339).map_or(u64::MAX, |start| {
        start.unix_timestamp().div_euclid(3600) as u64
    })
}

/// `Hour` pages of `map`, the one hourly page codec (capability buckets, and
/// `UsageHours` for the sources that store usage buckets): each entry on its
/// bucket start's hour page in map order, a page a count then each key and
/// value.
fn hour_pages<K: Durable, V: Durable>(
    map: &BTreeMap<K, V>,
    start: impl Fn(&K) -> &str,
) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
    let mut hours: BTreeMap<u64, Vec<(&K, &V)>> = BTreeMap::new();
    for (key, value) in map {
        hours
            .entry(hour_page(start(key)))
            .or_default()
            .push((key, value));
    }
    hours
        .into_iter()
        .map(|(hour, entries)| {
            let bytes = page_bytes(entries.iter(), |(key, value), e| {
                key.put(e)?;
                value.put(e)
            })?;
            Ok((hour, bytes))
        })
        .collect()
}

/// The hashed changed-file log shared by every source's codec. `G` is page
/// geometry: additional keys create additional pages, never a total-data cap.
mod changed_files {
    use super::*;
    pub(super) const G: u32 = 256;
    pub(super) fn keys(acc: &SnapshotAccumulator) -> Vec<&String> {
        acc.activity_changed_file_hashes.iter().collect()
    }
    pub(super) fn page(keys: &[&String]) -> Result<Vec<u8>, Refuse> {
        page_bytes(keys.iter(), |hash, e| {
            hash.put_h(e, "SnapshotAccumulator.activity_changed_file_hashes")
        })
    }
    pub(super) fn page_keys(bytes: &[u8]) -> Result<Vec<String>, ReconstructCause> {
        let mut keys = Vec::new();
        read_page(bytes, G, |d| {
            keys.push(String::take_h(d)?);
            Ok(())
        })?;
        Ok(keys)
    }
    pub(super) fn encode(acc: &SnapshotAccumulator) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
        keys(acc)
            .chunks(G as usize)
            .enumerate()
            .map(|(n, keys)| Ok((n as u64, page(keys)?)))
            .collect()
    }
    pub(super) fn decode(
        bytes: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<(), ReconstructCause> {
        read_page(bytes, G, |d| {
            if into.activity_changed_file_hashes.insert(String::take_h(d)?) {
                Ok(())
            } else {
                Err(ReconstructCause::Corrupt)
            }
        })
    }
}

/// A capability bucket's start: the first part of its key.
fn capability_hour(key: &(String, String, String)) -> &str {
    &key.0
}

/// One stored `Hour` page into `map`. An entry off its own hour's page, or a
/// key stored twice, is corrupt.
fn read_hour_page<K: Durable + Ord, V: Durable>(
    page: u64,
    bytes: &[u8],
    map: &mut BTreeMap<K, V>,
    start: impl Fn(&K) -> &str,
) -> Result<(), ReconstructCause> {
    read_page(bytes, 0, |d| {
        let key = K::take(d)?;
        let value = V::take(d)?;
        if hour_page(start(&key)) != page || map.insert(key, value).is_some() {
            return Err(ReconstructCause::Corrupt);
        }
        Ok(())
    })
}

/// The session facts collection every codec stores: content the head never
/// carries, one fact per page at its kind's position.
const SESSION_FACTS: CollectionSpec = CollectionSpec {
    collection: Collection::SessionFacts,
    shape: PageShape::Slot,
    g: 1,
    required: true,
    private: true,
};

/// The session facts (D168-1): content the head never carries, one element
/// per page at the kind's position, `[kind][version][value]`. A slot is
/// rewritten when its fact changes. A kind or version this build does not
/// know is incompatible: new ones come with a reduction revision. Kinds are
/// shared by every codec; a kind its source never sets is never stored (the
/// Codex agent label and prelude on Claude).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fact {
    Title = 0,
    FirstPrompt = 1,
    Workspace = 2,
    OpeningSettings = 3,
    /// Codex: the agent label (nickname or role) a subagent rollout carries.
    AgentLabel = 4,
    /// Codex: the session-start prelude parser, with its loaded texts.
    CodexPrelude = 5,
}
const FACTS: [Fact; 6] = [
    Fact::Title,
    Fact::FirstPrompt,
    Fact::Workspace,
    Fact::OpeningSettings,
    Fact::AgentLabel,
    Fact::CodexPrelude,
];
const FACT_VERSION: u64 = 1;

impl Fact {
    fn present(self, acc: &SnapshotAccumulator) -> bool {
        match self {
            Self::Title => acc.title.is_some(),
            Self::FirstPrompt => {
                acc.first_prompt_material.is_some() || acc.first_prompt_title.is_some()
            }
            Self::Workspace => acc.workspace_path.is_some(),
            Self::OpeningSettings => acc.session_start.has_opening_fact(),
            Self::AgentLabel => acc.codex_agent_label.is_some(),
            Self::CodexPrelude => acc.session_start.has_codex_prelude(),
        }
    }

    fn put(self, acc: &SnapshotAccumulator, e: &mut Enc<'_>) -> Result<(), Refuse> {
        e.varint(self as u64)?;
        e.varint(FACT_VERSION)?;
        match self {
            Self::Title => acc.title.put(e),
            Self::FirstPrompt => {
                acc.first_prompt_material.put(e)?;
                acc.first_prompt_title.put(e)
            }
            // A path never enters a record body (`PathBuf` refuses outside
            // hashing); the workspace path is a parsed JSON string, stored so.
            Self::Workspace => acc
                .workspace_path
                .as_ref()
                .map(|path| {
                    path.to_str()
                        .map(str::to_owned)
                        .ok_or(Refuse::NonEmpty("SnapshotAccumulator.workspace_path"))
                })
                .transpose()?
                .put(e),
            Self::OpeningSettings => acc.session_start.put_opening_fact(e),
            Self::AgentLabel => acc.codex_agent_label.put(e),
            Self::CodexPrelude => acc.session_start.put_codex_prelude_fact(e),
        }
    }

    /// One fact page into a decoded head's state.
    fn take(
        page: u64,
        bytes: &[u8],
        into: &mut SnapshotAccumulator,
    ) -> Result<(), ReconstructCause> {
        let fact = usize::try_from(page)
            .ok()
            .and_then(|at| FACTS.get(at).copied())
            .ok_or(ReconstructCause::Incompatible)?;
        let mut d = Dec::new(bytes);
        if d.varint()? != page {
            return Err(ReconstructCause::Corrupt);
        }
        if d.varint()? != FACT_VERSION {
            return Err(ReconstructCause::Incompatible);
        }
        match fact {
            Self::Title => into.title = <Option<String> as Durable>::take(&mut d)?,
            Self::FirstPrompt => {
                into.first_prompt_material = <Option<String> as Durable>::take(&mut d)?;
                into.first_prompt_title = <Option<String> as Durable>::take(&mut d)?;
            }
            Self::Workspace => {
                into.workspace_path = <Option<String> as Durable>::take(&mut d)?.map(PathBuf::from)
            }
            Self::OpeningSettings => into.session_start.take_opening_fact(&mut d)?,
            Self::AgentLabel => into.codex_agent_label = <Option<String> as Durable>::take(&mut d)?,
            Self::CodexPrelude => into.session_start.take_codex_prelude_fact(&mut d)?,
        }
        d.finish()?;
        // A stored slot holds its fact: an empty one is corrupt.
        if fact.present(into) {
            Ok(())
        } else {
            Err(ReconstructCause::Corrupt)
        }
    }
}

/// How many session facts `acc` holds.
fn fact_count(acc: &SnapshotAccumulator) -> usize {
    FACTS.iter().filter(|fact| fact.present(acc)).count()
}

/// The session-fact pages of `acc`, each at its kind's position.
fn fact_pages(acc: &SnapshotAccumulator) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
    FACTS
        .into_iter()
        .filter(|fact| fact.present(acc))
        .map(|fact| {
            Ok((
                fact as u64,
                Enc::count_write(usize::MAX, |e| fact.put(acc, e))?,
            ))
        })
        .collect()
}

/// One stored session-fact page into a decoded head's state.
fn read_fact_page(
    page: u64,
    bytes: &[u8],
    into: &mut SnapshotAccumulator,
) -> Result<(), ReconstructCause> {
    Fact::take(page, bytes, into)
}

// Artifacts are head data: collected whatever the upload toggle says, and
// filtered only when an item is built.
crate::durable_tail_codec::durable_struct!(SessionArtifact {
    U kind: String,
    U value: String,
});

macro_rules! head_fields {
    ($({ $($c:ident $f:ident : $ty:ty,)* }
        retired { $($rc:ident $rf:ident : $rty:ty = $empty:expr => $old:ident : $shape:ty,)* })*
        last { $($last_c:ident $last_f:ident : $last_ty:ty,)* }) => {
        fn put_fields(acc: &SnapshotAccumulator, e: &mut Enc<'_>) -> Result<(), Refuse> {
            let SnapshotAccumulator { $($($f,)*)* $($last_f,)* } = acc;
            $(
                $(durable_field!(put $c, e, $f, $ty, concat!("SnapshotAccumulator.", stringify!($f)));)*
                $(let value: &$rty = &$empty;
                durable_field!(put $rc, e, value, $rty, concat!("SnapshotAccumulator.", stringify!($old)));)*
            )*
            $(durable_field!(put $last_c, e, $last_f, $last_ty, concat!("SnapshotAccumulator.", stringify!($last_f)));)*
            Ok(())
        }
        fn take_fields(d: &mut Dec<'_>) -> Result<SnapshotAccumulator, Corrupt> {
            $(
                $(let $f = durable_field!(take $c, d, $ty);)*
                $(let _ = durable_field!(take $rc, d, $rty);)*
            )*
            $(let $last_f = durable_field!(take $last_c, d, $last_ty);)*
            Ok(SnapshotAccumulator { $($($f,)*)* $($last_f,)* })
        }
        #[cfg(test)]
        fn shape_fields(s: &mut crate::durable_tail_codec::Shape) {
            $(
                $(durable_field!(shape $c, s, $f, $ty);)*
                $(durable_field!(shape $rc, s, $old, $shape);)*
            )*
            $(durable_field!(shape $last_c, s, $last_f, $last_ty);)*
        }
    };
}
// The head-field core every codec writes: each accumulator field by its Tail
// home. Stored fields keep their record class, except that skill labels are
// plain data and the fork parent and artifacts are stored. `X` fields are
// content every codec keeps as session facts (`tail.page.session_facts`); the
// Codex agent label is Codex's fact, and a Claude head refuses it. `I` marks a
// field this walk does not store: a codec keeps its own `I` fields in its
// pages or in a trailer after this walk, or never stores them (finish-only
// and live fields, listed in its `finish_field_nonempty`). Claude's: pages
// (responses, tool uses, changed files, capability buckets, compactions),
// finish-only fields (usage ids and occurrences, money, cache observations
// and requests, usage buckets and totals), live fields (Desktop identity and
// spawn lineage, account hash). The Pi ledger and Codex's `I` fields are
// written only by those sources' parsers (Codex's by
// `apply_codex_owned_line`), so a Claude parse leaves them empty (D62).
// D203: retired entries retain only the original byte walk and shape descriptors.
head_fields! {
    {
        N source: SnapshotSource,
        H cache_configuration_witness: Option<String>,
        N cache_task_complete_at: Option<String>,
        N cache_pending_idle: Option<u64>,
        I cache_active_turns: BTreeSet<String>,
        N context_curve_enabled: bool,
        U source_session_id: Option<String>,
        I account_identifier_hash: Option<String>,
        X title: Option<String>,
        N title_source: Option<String>,
        X first_prompt_title: Option<String>,
        X first_prompt_material: Option<String>,
        N provider_skills: BTreeSet<String>,
        N started_at: Option<String>,
        N ended_at: Option<String>,
        N last_activity_at: Option<String>,
        U workspace_hash: Option<String>,
        X workspace_path: Option<PathBuf>,
        U latest_model: Option<String>,
        U latest_reasoning_effort: Option<String>,
        L latest_turn_id: Option<String>,
        I codex_turn_traces: Option<Arc<CodexTurnTraceMap>>,
        I codex_observed_priority_turns: Option<BTreeMap<String, bool>>,
        N codex_priority_witnesses_uncapped: bool,
        I codex_tier_replay: Option<codex_file_join::TierReplay>,
        D codex_counting: Option<Box<codex_usage_occurrence::CodexCounting>>,
        D current_selector: SelectorCapture,
        I session_cumulative_usage: Option<UsageTotals>,
        N codex_session_meta_seen: bool,
        N codex_record_seen: bool,
        U codex_creator_header_id: Option<String>,
        D codex_creator_evidence: Option<SessionAccountEvidence>,
        N codex_creator_evidence_conflicted: bool,
        I claude_desktop_identity: Option<SessionAccountEvidence>,
        I claude_desktop_spawn_lineage: Option<ClaudeDesktopSpawnLineage>,
        N claude_owned_session_id_observed: bool,
        N claude_owned_session_id_conflicted: bool,
        D codex_ownership_boundary: CodexOwnershipBoundary,
        N codex_legacy_trigger_seen: bool,
        N codex_legacy_bootstrap_valid: bool,
    }
    retired {
        I retired_codex_parent_ownership_ledgers: serde::de::IgnoredAny = serde::de::IgnoredAny => codex_parent_ownership_ledgers: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    }
    {
        N codex_sidecar_created_thread: bool,
        D codex_path_sidecar_candidates: Vec<CodexPathSidecarCandidate>,
        U codex_resolved_path_identity: Option<String>,
        N codex_sidecar_identity_ambiguous: bool,
        U codex_sidecar_parent: Option<(String, String)>,
        N codex_sidecar_child_created_at_nanos: Option<i128>,
        N codex_bind_seed_len: Option<u64>,
        I codex_sidecar_projected_next_ordinal: Option<u64>,
        U codex_parent_session_ref: Option<String>,
    }
    retired {
        I retired_codex_parent_signatures: serde::de::IgnoredAny = serde::de::IgnoredAny => codex_parent_signatures: Option<CodexParentPrefix>,
        H retired_codex_parent_prefix_digest: PrefixDigest = [0; 32] => codex_parent_prefix_digest: PrefixDigest,
        D retired_codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)> = None => codex_parent_prefix_decided: Option<(u64, PrefixDigest, bool)>,
        I retired_codex_parent_prefix_proof: serde::de::IgnoredAny = serde::de::IgnoredAny => codex_parent_prefix_proof: Option<(CodexParentPrefixProof, PrefixDigest)>,
        I retired_codex_parent_proof_used: serde::de::IgnoredAny = serde::de::IgnoredAny => codex_parent_proof_used: Option<(CodexParentPrefixProof, Option<CodexParentUnresolvable>)>,
        N retired_codex_parent_proof_mismatch: bool = false => codex_parent_proof_mismatch: bool,
        I retired_codex_parent_proof_refusal: serde::de::IgnoredAny = serde::de::IgnoredAny => codex_parent_proof_refusal: Option<ProofRefusal>,
        N retired_codex_proof_decision_only: bool = false => codex_proof_decision_only: bool,
        N retired_codex_boundary_buffer_count: u8 = 0 => codex_boundary_buffer_count: u8,
        H retired_codex_proof_ledger_row: Option<String> = None => codex_proof_ledger_row: Option<String>,
        H retired_codex_parent_ledger_identity_used: Option<String> = None => codex_parent_ledger_identity_used: Option<String>,
        D retired_codex_parent_unresolvable: Option<CodexParentUnresolvable> = None => codex_parent_unresolvable: Option<CodexParentUnresolvable>,
        N retired_codex_parent_ledger_consulted: bool = false => codex_parent_ledger_consulted: bool,
        N retired_codex_parent_signature_index: usize = 0 => codex_parent_signature_index: usize,
    }
    {
        N codex_native_created_thread_valid: bool,
        N codex_created_thread_native_only: bool,
        N codex_native_created_thread_header_nanos: Option<i128>,
        N codex_native_created_thread_last_nanos: Option<i128>,
        L codex_native_created_thread_task_turn_id: Option<String>,
        N codex_native_created_thread_first_turn_bound: bool,
    }
    retired {
        I retired_codex_physical_signatures: serde::de::IgnoredAny = serde::de::IgnoredAny => codex_physical_signatures: crate::owned_heap::OwnedVec<String>,
        N retired_codex_physical_signatures_complete: bool = true => codex_physical_signatures_complete: bool,
    }
    last {
        N codex_ordinal_expected: Option<u64>,
        N codex_ordinal_sequence_valid: bool,
        N codex_owned_record_seen: bool,
        N codex_is_fork: bool,
        N codex_inherited_usage_records_skipped: u64,
        N codex_duplicate_usage_records_skipped: u64,
        N codex_cumulative_reset_count: u64,
        D codex_context_curve_candidates: crate::owned_heap::OwnedVec<ContextCurveCandidatePoint>,
        D codex_context_curve_boundaries: crate::owned_heap::OwnedVec<ContextCurveCandidateBoundary>,
        N codex_context_curve_exact_supported: bool,
        H codex_last_usage_event_identity: Option<String>,
        E codex_legacy_bootstrap_buffer: Vec<Value>,
        I accepted_usage_totals: UsageTotals,
        I usage_buckets: BTreeMap<String, UsageBucketState>,
        D origin: SnapshotOrigin,
        U codex_root_session_ref: Option<String>,
        N codex_spawn_depth: Option<u64>,
        X codex_agent_label: Option<String>,
        I activity_tool_counts: BTreeMap<String, u64>,
        I activity_call_tools: BTreeMap<ActivityCallId, ActivityCallTool>,
        I activity_mcp_tool_counts: BTreeMap<String, u64>,
        I activity_mcp_tool_usage_counts: BTreeMap<String, u64>,
        I activity_mcp_call_ids: BTreeMap<String, bool>,
        I activity_capability_buckets: BTreeMap<(String, String, String), u64>,
        I seen_claude_capability_tool_uses: crate::owned_heap::OwnedMap<String, ()>,
        N activity_skills: BTreeSet<String>,
        N skill_detector_incomplete: bool,
        I activity_changed_file_hashes: BTreeSet<String>,
        N activity_patch_operations: u64,
        N activity_lines_added: u64,
        N activity_lines_deleted: u64,
        N activity_web_searches: u64,
        N activity_mcp_calls: u64,
        N activity_subagent_spawns: u64,
        U artifacts: Vec<SessionArtifact>,
        N artifacts_enabled: bool,
        N latency_duration_ms_sum: u64,
        N latency_duration_ms_count: u64,
        N latency_ttft_ms_sum: u64,
        N latency_ttft_ms_count: u64,
        N latency_duration_ms_max: u64,
        N latency_ttft_ms_max: u64,
        I claude_responses: ClaudeResponseBook,
        N claude_response_sequence: u64,
        N claude_response_record_count: usize,
        I claude_usage_request_ids: BTreeSet<String>,
        I claude_usage_occurrences: BTreeMap<String, ClaudeTranscriptUsageOccurrence>,
        N claude_request_identity_capture: bool,
        D claude_org_markers: Option<Box<claude_request_identity::OrgMarkers>>,
        I cache_observations: Option<CacheObservations>,
        I cache_requests: crate::owned_heap::OwnedVec<OwnedRequest>,
        N cache_requests_complete: bool,
        N claude_context_curve_identity_complete: bool,
        N claude_context_curve_request_index_complete: bool,
        N claude_context_curve_owned_start_proven: bool,
        D claude_file_birth: ClaudeFileBirth,
        L claude_fork_parent: Option<String>,
        I claude_money: Option<Box<claude_request_money::e2::FileFold>>,
        U tool_usage_counts: BTreeMap<String, u64>,
        N tool_usage_truncated: bool,
        I seen_pi_usage_keys: PiLedger,
        N dropped_usage_record_count: u64,
        N claude_last_user_ts: Option<String>,
        N claude_line_clocks: Option<(i128, i128)>,
        N peak_context_fill_tokens: u64,
        N first_turn_context_tokens: Option<u64>,
        N last_turn_context_tokens: Option<u64>,
        N first_turn_context_window_tokens: Option<u64>,
        N peak_context_fill_window_tokens: Option<u64>,
        N last_turn_context_window_tokens: Option<u64>,
        N compaction_count: u64,
        I compaction_timestamps: crate::owned_heap::OwnedVec<String>,
        D codex_compaction_sizes: CodexCompactionSizes,
        D local_context_points: LocalContextPoints,
        I claude_compaction_observations: crate::owned_heap::OwnedVec<ClaudeCompactionObservation>,
        L claude_compaction_link_tip: Option<(u64, String)>,
        D session_start: Box<session_start::SessionStartState>,
        I codex_dictionary_slots: crate::snapshots::codex_dictionary_slots::CodexDictionarySlots,
        I codex_sidecar_binding: Option<String>,
    }
}

#[cfg(test)]
mod retired_slot_tests {
    use super::*;

    /// [format] Retired head slots always write the previous empty bytes;
    /// decoded state cannot restore a legacy decision or retained allocation.
    #[test]
    fn retired_head_slots_are_inert_and_keep_empty_bytes() {
        for source in [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
            SnapshotSource::Codex,
        ] {
            let acc = SnapshotAccumulator::new(source);
            let empty = Enc::count_write(usize::MAX, |e| put_fields(&acc, e)).unwrap();
            assert_eq!(
                Enc::count_write(usize::MAX, |e| put_fields(&acc, e)).unwrap(),
                empty
            );
            let mut d = Dec::new(&empty);
            let restored = take_fields(&mut d).unwrap();
            assert_eq!(restored.source, source);
            d.finish().unwrap();
            assert_eq!(
                Enc::count_write(usize::MAX, |e| put_fields(&restored, e)).unwrap(),
                empty
            );
        }
    }

    /// [format] Shipped ordinal 3 remains readable, and no writer emits it.
    #[test]
    fn ownership_ordinal_three_is_a_decode_only_tombstone() {
        let mut d = Dec::new(&[3]);
        let retired = CodexOwnershipBoundary::take(&mut d).unwrap();
        d.finish().unwrap();
        assert!(matches!(
            retired,
            CodexOwnershipBoundary::AwaitingParentPrefix
        ));
        assert!(Enc::count_write(usize::MAX, |e| retired.put(e)).is_err());
        assert_eq!(
            Enc::count_write(usize::MAX, |e| CodexOwnershipBoundary::AllLocal.put(e)).unwrap(),
            [1]
        );
    }
}
