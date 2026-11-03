//! The PRE seam's Tail write. PRE encodes one file's head and changed pages
//! into a local buffer; only the native finish's verdict hands it to the
//! store. The store has no per-file unstage, so a completion rejected after
//! PRE (lossy, zero-positive, incomplete, a late conflict, unsealed) never
//! reaches `stage_tail`: its predecessor stays, and native settlement
//! discloses the loss. Upload never waits on any of this.
//!
//! Changed pages are relative to the committed head the read continued (its
//! `TailBase`, built by the load): a page whose encoding equals the committed
//! page's is not restated, and a read that changes no page and no head byte
//! writes nothing. A `Log` collection never reorders committed pages:
//! elements new since the base follow them, sorted among themselves (the
//! accumulator's sets keep no arrival order), filling the last committed page
//! while it has room. A full encode writes each `Log` sorted. A committed page
//! of another shape that the new encode no longer holds is obsolete. A
//! rewritten or obsolete page of a private collection (the session facts)
//! stages `DropsPrivate`, so its old value is purged. Without a base (a Full
//! read, or a retry of a set-aside file) the stage is a `Reset` that replaces
//! every stored row.
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
    source: SnapshotSource,
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
    /// `None`: nothing differs from the committed head.
    staged: Result<Option<StagedFile>, Refuse>,
    /// A finish-only or live field already set at PRE.
    finish_field: Option<&'static str>,
}

impl PendingTail {
    /// A certified `S` completion on a state database route. `None`: no
    /// route or no valid certificate, so nothing is written for this read.
    /// `base` is the committed head the load continued; `quiet` a quiet audit
    /// this completion retires, so the head no longer carries its debt.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::snapshots) fn new<S: TailSource>(
        index: &ScanIndex,
        completed: &CompletedNativeAcquisition,
        active: &sampled_scan::Active,
        candidate: &CandidateFile,
        held: &File,
        capture: bool,
        base: Option<TailBase>,
        quiet: bool,
    ) -> Option<Self> {
        let route = state_v2::runtime_path(index).ok()??;
        let birth = crate::transcript_acquisition::birth_unix_nanos(&held.metadata().ok()?);
        let mut certificate = completed.checkpoint.durable_certificate(birth)?;
        if quiet {
            certificate.audit_debt_unix_seconds = None;
        }
        Some(Self {
            source: S::SOURCE,
            id: HeadIdentity::new(
                &route,
                S::SOURCE,
                &candidate.scan_root,
                &candidate.path,
                capture,
            ),
            route,
            key: active.key.clone(),
            certificate,
            unsealed: completed.unsealed,
            full: matches!(active.mode, ReadMode::Full(_)),
            base,
            encode: tail_encode::<S>,
            encoded: None,
        })
    }

    /// The PRE seam: encode into the local buffer only.
    pub(in crate::snapshots) fn encode(&mut self, view: &PreFinalization<'_>) {
        let encoded = (self.encode)(view, self);
        self.encoded = Some(encoded);
    }

    /// The native verdict, then this completion's one call into the store.
    /// True when the committed head stays valid for this completion: staged,
    /// or nothing to restate.
    pub(in crate::snapshots) fn publish(self, native: &Result<ParsedJsonlFile>) -> bool {
        let Some(encoded) = self.encoded else {
            return false; // PRE never ran: the read failed before it.
        };
        if self.unsealed || !finish_loss_free(native) {
            super::counters::bump(self.source, "tail_publish", "dropped");
            return false;
        }
        // Staging only fails on a poisoned route lock; the predecessor stays.
        match (encoded.staged, encoded.finish_field) {
            (Err(_), _) => {
                super::counters::bump(self.source, "tail_full_encode", "failed");
                let _ = state_v2::set_aside_tail(&self.route, &self.key, SetAsideCause::Encode);
                false
            }
            (Ok(_), Some(_)) => {
                let _ = state_v2::set_aside_tail(
                    &self.route,
                    &self.key,
                    SetAsideCause::UnexpectedFinishField,
                );
                false
            }
            (Ok(Some(staged)), None) => {
                state_v2::stage_tail(&self.route, &self.key, staged).is_ok()
            }
            (Ok(None), None) => true,
        }
    }
}

fn tail_encode<S: TailSource>(view: &PreFinalization<'_>, tail: &PendingTail) -> Encoded {
    let staged = match tail.base.as_ref().filter(|_| !tail.full) {
        Some(base) => base.stage::<S>(view, &tail.certificate, &tail.id),
        None => stage_full::<S>(view, &tail.certificate, &tail.id).map(Some),
    };
    Encoded {
        staged,
        finish_field: S::finish_field_nonempty(view.accumulator),
    }
}

/// The committed head a read continued: its digest, each page's digest, and
/// each `Log`'s committed elements and last page. Flat sorted vectors, so its
/// heap is one bounded charge.
pub(in crate::snapshots) struct TailBase {
    head: [u8; 32],
    /// The head is from a lower revision: an unchanged read still restates it.
    migrate: bool,
    /// In load order: by collection, then page.
    pages: Vec<((Collection, u64), [u8; 32])>,
    logs: Vec<(Collection, LogBase)>,
}
struct LogBase {
    /// Sorted element digests.
    keys: Vec<u64>,
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
    /// The base of a committed head whose source body is `head`; `migrate`
    /// when that head was written at a lower revision.
    pub(in crate::snapshots) fn new(head: &[u8], migrate: bool) -> Self {
        Self {
            head: page_digest(head),
            migrate,
            pages: Vec::new(),
            logs: Vec::new(),
        }
    }

    /// One committed page, in the load's order: by collection, then page.
    pub(in crate::snapshots) fn observe<S: TailSource>(
        &mut self,
        collection: Collection,
        page: u64,
        bytes: &[u8],
    ) -> Result<(), ReconstructCause> {
        self.pages.push(((collection, page), page_digest(bytes)));
        if S::collections()
            .iter()
            .any(|spec| spec.collection == collection && spec.shape == PageShape::Log)
        {
            let keys = S::log_page_keys(collection, bytes)?;
            if self.logs.last().map(|(last, _)| *last) != Some(collection) {
                self.logs.push((
                    collection,
                    LogBase {
                        keys: Vec::new(),
                        last: (page, Vec::new()),
                    },
                ));
            }
            let (_, log) = self.logs.last_mut().expect("pushed above");
            log.keys.extend(keys.iter().map(|key| key_digest(key)));
            log.keys.sort_unstable();
            log.last = (page, keys);
        }
        Ok(())
    }

    fn committed(&self, page: (Collection, u64)) -> Option<&[u8; 32]> {
        self.pages
            .binary_search_by(|(at, _)| at.cmp(&page))
            .ok()
            .map(|at| &self.pages[at].1)
    }

    /// The new head, every collection's metadata, and only the pages whose
    /// bytes differ from the committed ones; `None` when neither the head
    /// nor any page differs. A lower-revision head with nothing else to write
    /// is restated alone: same stamp, verification and debt, so it earns no
    /// acquisition or Full credit and touches no ACK or receipt.
    fn stage<S: TailSource>(
        &self,
        view: &PreFinalization<'_>,
        certificate: &DurableCertificate,
        id: &HeadIdentity,
    ) -> Result<Option<StagedFile>, Refuse> {
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
            let log = self
                .logs
                .iter()
                .find(|(collection, _)| *collection == spec.collection);
            let pages = match log {
                Some((_, log)) => log_pages::<S>(acc, spec, log)?,
                None => S::encode_pages(acc, spec.collection)?,
            };
            let mut rewritten = false;
            if log.is_none() {
                let held: BTreeSet<u64> = pages.iter().map(|(page, _)| *page).collect();
                for &((collection, page), _) in &self.pages {
                    if collection == spec.collection && !held.contains(&page) {
                        staged.obsolete.insert((collection, page));
                        rewritten = true;
                    }
                }
            }
            for (page, bytes) in pages {
                match self.committed((spec.collection, page)) {
                    Some(digest) if *digest == page_digest(&bytes) => continue,
                    Some(_) => rewritten = true,
                    None => {}
                }
                staged.pages.insert((spec.collection, page), bytes);
            }
            if rewritten && spec.private {
                staged.change = Change::DropsPrivate;
            }
        }
        let changed = !staged.pages.is_empty()
            || !staged.obsolete.is_empty()
            || page_digest(&staged.head) != self.head;
        if self.migrate && !changed {
            super::counters::bump(S::SOURCE, "tail_head_migrated", "heads");
        }
        Ok((changed || self.migrate).then_some(staged))
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for TailBase {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let logs = self.logs.iter().try_fold(0usize, |sum, (_, log)| {
            let names = log
                .last
                .1
                .iter()
                .try_fold(0usize, |sum, key| sum.checked_add(key.capacity()))?;
            sum.checked_add(log.keys.capacity().checked_mul(size_of::<u64>())?)?
                .checked_add(log.last.1.capacity().checked_mul(size_of::<String>())?)?
                .checked_add(names)
        })?;
        c.add(
            self.pages
                .capacity()
                .checked_mul(size_of::<((Collection, u64), [u8; 32])>())?
                .checked_add(
                    self.logs
                        .capacity()
                        .checked_mul(size_of::<(Collection, LogBase)>())?,
                )?
                .checked_add(logs)?,
        )
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
        .filter(|key| log.keys.binary_search(&key_digest(key)).is_err())
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
pub(in crate::snapshots::tail_source) mod tests;
#[cfg(test)]
#[path = "transition_tests.rs"]
mod transition_tests;
