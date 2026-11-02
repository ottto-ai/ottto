//! The PRE seam's Tail write. PRE encodes one file's head and changed pages
//! into a local buffer; only the native finish's verdict hands it to the
//! store. The store has no per-file unstage, so a completion rejected after
//! PRE (lossy, zero-positive, incomplete, a late conflict, unsealed) never
//! reaches `stage_tail`: its predecessor stays, and native settlement
//! discloses the loss. Upload never waits on any of this.
//!
//! Changed pages are relative to the committed head the read continued (its
//! `TailBase`): a page whose encoding equals the committed page's is not
//! restated. A `Log` collection never reorders committed pages: elements new
//! since the base follow them, sorted among themselves (the accumulator's
//! sets keep no arrival order), filling the last committed page while it has
//! room. A full encode writes each `Log` sorted. Without a base every page is
//! restated; a Full read replaces every stored row.
use super::{stage_full, CollectionSpec, HeadIdentity, ReconstructCause, TailSource};
use crate::durable_tail_codec::Refuse;
use crate::snapshots::sampled_jsonl::CompletedNativeAcquisition;
use crate::snapshots::state_v2::{
    self, Change, Collection, CollectionMeta, SetAsideCause, Shape as PageShape, StagedFile,
};
use crate::snapshots::*;
use crate::transcript_acquisition::{DurableCertificate, ReadMode};

/// One completion's Tail write, from its acquisition to the native verdict.
pub(in crate::snapshots) struct PendingTail {
    /// The route's index path: where the stage waits for the next full save.
    route: PathBuf,
    key: String,
    id: HeadIdentity,
    certificate: DurableCertificate,
    /// Native EOF applied bytes past the sealed offset: never stored.
    unsealed: bool,
    full: bool,
    base: Option<TailBase>,
    encode: fn(&PreFinalization<'_>, &PendingTail) -> Encoded,
    encoded: Option<Encoded>,
}

/// What PRE encoded, held until the verdict. A refusal is held too.
pub(in crate::snapshots) struct Encoded {
    staged: Result<StagedFile, Refuse>,
    /// A finish-only or live field already set at PRE.
    finish_field: Option<&'static str>,
}

impl PendingTail {
    /// A certified Claude completion on a state database route. `None`: no
    /// route or no valid certificate, so nothing is written for this read.
    pub(in crate::snapshots) fn claude(
        index: &ScanIndex,
        completed: &CompletedNativeAcquisition,
        active: &sampled_scan::Active,
        candidate: &CandidateFile,
        held: &File,
        namespace: &str,
        capture: bool,
    ) -> Option<Self> {
        let route = state_v2::runtime_path(index).ok()??;
        let birth = crate::transcript_acquisition::birth_unix_nanos(&held.metadata().ok()?);
        Some(Self {
            id: HeadIdentity::new(
                namespace,
                &route,
                SnapshotSource::ClaudeCode,
                &candidate.scan_root,
                &candidate.path,
                capture,
            ),
            route,
            key: active.key.clone(),
            certificate: completed.checkpoint.durable_certificate(birth)?,
            unsealed: completed.unsealed,
            full: matches!(active.mode, ReadMode::Full(_)),
            // The committed base comes with the Tail load.
            base: None,
            encode: tail_encode::<super::claude::Claude>,
            encoded: None,
        })
    }

    /// The PRE seam: encode into the local buffer only.
    pub(in crate::snapshots) fn encode(&mut self, view: &PreFinalization<'_>) {
        let encoded = (self.encode)(view, self);
        self.encoded = Some(encoded);
    }

    /// The native verdict, then this completion's one call into the store.
    pub(in crate::snapshots) fn publish(self, native: &Result<ParsedJsonlFile>) {
        let Some(encoded) = self.encoded else {
            return; // PRE never ran: the read failed before it.
        };
        if self.unsealed || !finish_loss_free(native) {
            return;
        }
        // Staging only fails on a poisoned route lock; the predecessor stays.
        let _ = match (encoded.staged, encoded.finish_field) {
            (Err(_), _) => state_v2::set_aside_tail(&self.route, &self.key, SetAsideCause::Encode),
            (Ok(_), Some(_)) => state_v2::set_aside_tail(
                &self.route,
                &self.key,
                SetAsideCause::UnexpectedFinishField,
            ),
            (Ok(staged), None) => state_v2::stage_tail(&self.route, &self.key, staged),
        };
    }
}

fn tail_encode<S: TailSource>(view: &PreFinalization<'_>, tail: &PendingTail) -> Encoded {
    let staged = match tail.base.as_ref().filter(|_| !tail.full) {
        Some(base) => base.stage::<S>(view, &tail.certificate, &tail.id),
        None => stage_full::<S>(view, &tail.certificate, &tail.id).map(|mut staged| {
            if !tail.full {
                staged.change = Change::Ordinary;
            }
            staged
        }),
    };
    Encoded {
        staged,
        finish_field: S::finish_field_nonempty(view.accumulator),
    }
}

/// The committed head's pages a read continued: each page's digest, and each
/// `Log`'s committed elements and last page.
#[derive(Default)]
pub(in crate::snapshots) struct TailBase {
    pages: BTreeMap<(Collection, u64), [u8; 32]>,
    logs: BTreeMap<Collection, LogBase>,
}
#[derive(Default)]
struct LogBase {
    keys: BTreeSet<u64>,
    last: (u64, Vec<String>),
}

/// A `Log` element's identity in the base: the first 8 bytes of its SHA-256.
/// A collision leaves an element unstored, which the load's element count
/// rejects as an incomplete reconstruction.
fn key_digest(key: &str) -> u64 {
    let mut first = [0; 8];
    first.copy_from_slice(&Sha256::digest(key.as_bytes())[..8]);
    u64::from_be_bytes(first)
}
fn page_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl TailBase {
    /// One committed page, in the load's order: by collection, then page.
    pub(in crate::snapshots) fn observe<S: TailSource>(
        &mut self,
        collection: Collection,
        page: u64,
        bytes: &[u8],
    ) -> Result<(), ReconstructCause> {
        self.pages.insert((collection, page), page_digest(bytes));
        if S::collections()
            .iter()
            .any(|spec| spec.collection == collection && spec.shape == PageShape::Log)
        {
            let keys = S::log_page_keys(collection, bytes)?;
            let log = self.logs.entry(collection).or_default();
            log.keys.extend(keys.iter().map(|key| key_digest(key)));
            log.last = (page, keys);
        }
        Ok(())
    }

    /// The new head, every collection's metadata, and only the pages whose
    /// bytes differ from the committed ones.
    fn stage<S: TailSource>(
        &self,
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<StagedFile, Refuse> {
        let acc = view.accumulator;
        let mut staged = StagedFile {
            revision: S::REDUCTION_REVISION,
            head: S::encode_head(view, certificate, id)?,
            change: Change::Ordinary,
            ..StagedFile::default()
        };
        for spec in S::collections() {
            let elements = S::elements(acc, spec.collection);
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
            let pages = match self.logs.get(&spec.collection) {
                Some(log) => log_pages::<S>(acc, spec, log)?,
                None => S::encode_pages(acc, spec.collection)?,
            };
            for (page, bytes) in pages {
                if self.pages.get(&(spec.collection, page)) != Some(&page_digest(&bytes)) {
                    staged.pages.insert((spec.collection, page), bytes);
                }
            }
        }
        Ok(staged)
    }
}

/// A `Log`'s pages from its last committed one on: that page's elements in
/// stored order while it has room, then the new elements sorted.
fn log_pages<S: TailSource>(
    acc: &SnapshotAccumulator,
    spec: &CollectionSpec,
    log: &LogBase,
) -> Result<Vec<(u64, Vec<u8>)>, Refuse> {
    let mut fresh: Vec<&String> = S::log_keys(acc, spec.collection)
        .into_iter()
        .filter(|key| !log.keys.contains(&key_digest(key)))
        .collect();
    if fresh.is_empty() {
        return Ok(Vec::new());
    }
    fresh.sort_unstable();
    let g = spec.g as usize;
    let (last, committed) = &log.last;
    let (first, mut keys) = if committed.len() < g {
        (*last, committed.iter().collect::<Vec<_>>())
    } else {
        (last + 1, Vec::new())
    };
    keys.extend(fresh);
    keys.chunks(g)
        .enumerate()
        .map(|(n, chunk)| Ok((first + n as u64, S::log_page(spec.collection, chunk)?)))
        .collect()
}

#[cfg(test)]
#[path = "seam_tests.rs"]
mod tests;
