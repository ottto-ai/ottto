//! A source's continuation from the state database. RAM keeps no reduction
//! of a source with a Tail codec on a database route: a read that continues
//! a file loads its committed Tail head, checks the head's identity, then the
//! file against the head's certificate, then streams the pages (the session
//! facts among them), validates the decoded state, and installs the read's
//! live inputs. Content is never read back from the file: a quiet restart
//! reads 0 transcript bytes.
//!
//! Each load counts once in `tail_db_loads{outcome}` on its source's line; a
//! hit adds the bytes it read to `tail_db_load_bytes{head,page}`. Counters
//! only: no point repeats them (§13). Stored state that cannot be
//! reused is a counted reconstruction (`tail_reconstruct`) and the read starts
//! at once as a Full; a file shorter than its head reads Full (`Shrunk`) and
//! is counted in `tail_shorter_file_full`. Only a head from a newer build, a
//! session fact of a kind or version this build does not know, or a live
//! input that is not available now, holds the file, untouched. A session
//! fact that does not match its head (a count mismatch) is corrupt: that
//! file alone reconstructs. A
//! metadata-only head (revisions or inventory, no reduction) is no
//! checkpoint: the file's first read, with no credit. A head bound to another
//! route, scan root or path is retired before anything else in it is read
//! (C′), whatever the Full that follows achieves. A head made under another
//! key (a rotation) is an explicit-action reconstruction: counted, but
//! neither a release-gate failure nor an alarm. Attribution toggled on or off
//! since the head is no rotation: the head is reused with its context digest
//! scrubbed, as main scrubs a retained parse's (D168-2).
use super::counters;
use super::seam::TailBase;
use super::{HeadIdentity, LiveLoadError, ReconstructCause, TailSource};
use crate::snapshots::sampled_jsonl::CachedJsonlReduction;
use crate::snapshots::state_v2::{self, Hold};
use crate::snapshots::*;
use crate::transcript_acquisition::{CertificateRefusal, FullReason, Scope};
use crate::transcript_cache::{Retained, Taken};

/// What a load hands the read.
pub(in crate::snapshots) enum Load {
    /// Continue from the stored reduction. `base` is `None` for a file set
    /// aside, so its next stage replaces every stored row.
    Reused(Box<Taken<CachedJsonlReduction>>, Option<TailBase>),
    /// A newer build's head, or a live input not available now: the file
    /// waits, untouched, with its debt.
    Held,
    /// Start a Full read now, with the reason the file proved, if any.
    Cold(Option<FullReason>),
}

/// A selection of an unchanged transcript for evidence read at finish (late
/// telemetry or side calls, a family or account proof, a quarantine retry).
/// Its re-fold from stored state reads 0 transcript bytes; a body that is not
/// the ACKed one goes as an ordinary update, counted `tail_refold{reason}`.
pub(in crate::snapshots) fn late_evidence(reason: CandidateParseReason) -> bool {
    matches!(
        reason,
        CandidateParseReason::SourceChanged
            | CandidateParseReason::Rearmed
            | CandidateParseReason::ForcedFamily
            | CandidateParseReason::AuthorityQuarantine
            | CandidateParseReason::ActivityOrQuarantineRetry
    )
}

/// Whether this selection loads the committed Tail. A due `Audit` certifies
/// against the committed head: an unchanged file retires quietly, and only
/// what the file proves changed reads Full. An `UnknownOutcome` re-read
/// continues as well. Growth beats an upload-context selection: a file that
/// `grew` past its committed entry continues as for `TranscriptChanged`; a
/// context-only one stays native, as do `BodyWitnessAdoption` and every
/// legacy selection. A `NewFile` is a first read, except one `e2` withheld
/// (`held_new`): its committed head is custody, never acceptance, and it
/// continues as a changed file does.
///
/// A late-evidence re-fold needs complete stored state and never answers a
/// server challenge: a set-aside file, or one whose body waits on a retry (a
/// head-CAS conflict among them), reads natively instead.
pub(in crate::snapshots) fn reuses_stored(
    index: &ScanIndex,
    key: &str,
    reason: Option<CandidateParseReason>,
    grew: bool,
    held_new: bool,
) -> bool {
    match reason {
        None
        | Some(
            CandidateParseReason::TranscriptChanged
            | CandidateParseReason::Audit
            | CandidateParseReason::UnknownOutcome,
        ) => true,
        Some(CandidateParseReason::UploadContext) => grew,
        Some(CandidateParseReason::NewFile) => held_new,
        Some(reason) => late_evidence(reason) && !set_aside(index, key) && !retry_held(index, key),
    }
}

/// A NEW key `e2` withheld, by its durable custody: the withheld read left
/// its census record and no index entry. Its committed head (if any) is then
/// custody, never acceptance; the load still validates it against the file.
pub(in crate::snapshots) fn held_new(index: &ScanIndex, key: &str) -> bool {
    !index.files.contains_key(key) && index.claude_request_census.get(key).is_some()
}

/// A body of this file waits in the upload ledger for a retry: the server
/// refused it (a head-CAS conflict, a held decrease) and the ledger keeps it.
fn retry_held(index: &ScanIndex, key: &str) -> bool {
    index
        .file_snapshot_fingerprints
        .get(key)
        .is_some_and(|set| {
            set.iter().any(|fingerprint| {
                index
                    .quarantined_snapshot_fingerprints
                    .get(fingerprint)
                    .is_some_and(|record| {
                        record.disposition == SnapshotQuarantineDisposition::RetryPending
                    })
            })
        })
}

/// The per-candidate marker check, before an ordinary Skip: a file whose
/// Tail failed alone re-reads from its committed head even when its graph
/// stamps already match.
pub(in crate::snapshots) fn set_aside(index: &ScanIndex, key: &str) -> bool {
    matches!(state_v2::tail_set_aside(index, key), Ok(Some(_)))
}

/// A4d: after a complete census with no decode hold, a head whose file the
/// census did not observe, that is no residue and has no index entry, is
/// absent. Each absent head is classified by its custody, never deleted by
/// set difference: a reduction retires at the next save (the store keeps its
/// unresolved revisions under a metadata-only head); a metadata-only head
/// with revisions keeps its debt, which absence never clears; one with no
/// revisions retires. A head that fails to load is set aside, not retired
/// (F4). A read error of the key set, or a database hold, retires nothing.
/// A set-aside marker with no head is not listed.
pub(in crate::snapshots) fn retire_absent(
    source: SnapshotSource,
    index: &ScanIndex,
    observed: &BTreeSet<String>,
    residue: &BTreeSet<String>,
) {
    let (Ok(Some(route)), Some(revision)) = (
        super::tail_route(source, index),
        super::reduction_revision(source),
    ) else {
        return;
    };
    let Ok(mut absent) = state_v2::tail_head_keys(index) else {
        return;
    };
    absent.retain(|key| {
        !observed.contains(key) && !residue.contains(key) && !index.files.contains_key(key)
    });
    let mut retire = BTreeSet::new();
    let (mut kept_debt, mut set_aside) = (0_u64, 0_u64);
    for key in absent {
        match state_v2::load_head(index, &key, revision) {
            Ok(Some(head))
                if head.metadata_only
                    && head.table.contains_key(&state_v2::Collection::Revisions) =>
            {
                kept_debt += 1;
            }
            Ok(Some(_)) => {
                retire.insert(key);
            }
            Ok(None) => {}
            Err(error)
                if matches!(
                    error.downcast_ref::<Hold>(),
                    Some(Hold::DbUnavailable | Hold::ReloadRequired)
                ) =>
            {
                return;
            }
            Err(_) => {
                let _ = state_v2::set_aside_tail(&route, &key, state_v2::SetAsideCause::Row);
                set_aside += 1;
            }
        }
    }
    if kept_debt + set_aside > 0 {
        crate::local_resource_diagnostics::traversal_point(
            "tail_absent",
            source.api_slug(),
            &serde_json::json!({
                "retired": retire.len(), "kept_debt": kept_debt, "set_aside": set_aside
            }),
        );
    }
    let _ = state_v2::retire_tail(&route, retire);
}

/// `S`'s load of `candidate` on `route`; `held` is the read's opened file and
/// `live` its fresh accumulator.
pub(in crate::snapshots) fn entry<S: TailSource>(
    index: &ScanIndex,
    route: &Path,
    candidate: &CandidateFile,
    live: &SnapshotAccumulator,
    capture: bool,
    held: &mut File,
    scope: &Scope,
) -> Load {
    let id = HeadIdentity::new(
        route,
        S::SOURCE,
        &candidate.scan_root,
        &candidate.path,
        capture,
    );
    load::<S>(
        index,
        route,
        &local_index_key(&candidate.path),
        &id,
        held,
        scope,
        candidate,
        live,
    )
}

enum Miss {
    NoHead,
    /// A head with no reduction: no checkpoint to continue.
    MetadataOnly,
    Future,
    /// A session fact of a kind or version this build does not know: a
    /// newer build's, held as a future revision is, never read Full.
    FutureFact,
    /// The file is no longer the certified one: an ordinary Full.
    Changed(FullReason),
    /// The database or the file could not be read.
    Unreadable,
    Reconstruct(ReconstructCause),
    /// A live input is not available now: the file holds with its debt.
    LiveUnavailable,
}

/// What a hit loaded: the reduction, its base, and the bytes it read.
struct Hit {
    taken: Box<Taken<CachedJsonlReduction>>,
    base: TailBase,
    head_bytes: u64,
    page_bytes: u64,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the shared load takes every codec's cycle inputs"
)]
pub(super) fn load<S: TailSource>(
    index: &ScanIndex,
    route: &Path,
    key: &str,
    id: &HeadIdentity,
    held: &mut File,
    scope: &Scope,
    fresh: &CandidateFile,
    live: &SnapshotAccumulator,
) -> Load {
    let source = S::SOURCE;
    // (outcome, counted reconstruction, load)
    let loaded = stored::<S>(index, key, id, held, scope, fresh, live);
    let (outcome, reconstruct, load) = match loaded {
        Ok(hit) => {
            let base = (!set_aside(index, key)).then_some(hit.base);
            counters::bump(source, "tail_db_loads", "hit");
            counters::add(source, "tail_db_load_bytes", "head", hit.head_bytes);
            counters::add(source, "tail_db_load_bytes", "page", hit.page_bytes);
            return Load::Reused(hit.taken, base);
        }
        Err(Miss::Future | Miss::FutureFact | Miss::LiveUnavailable) => ("held", None, Load::Held),
        // Valid stored state for a file that changed: an ordinary Full. A
        // shorter file is main's counted Full; no floor holds it (D158).
        Err(Miss::Changed(reason)) => {
            if reason == FullReason::Shrunk {
                counters::bump(source, "tail_shorter_file_full", "files");
            }
            ("miss", None, Load::Cold(Some(reason)))
        }
        Err(Miss::NoHead) => {
            counters::bump(source, "tail_bootstrap_full", "no_head");
            ("miss", Some("no_head"), Load::Cold(None))
        }
        // Debt or inventory only: the file's first read, no reconstruction.
        Err(Miss::MetadataOnly) => {
            counters::bump(source, "tail_bootstrap_full", "metadata_only");
            ("miss", None, Load::Cold(None))
        }
        Err(Miss::Unreadable) => ("error", Some("unreadable"), Load::Cold(None)),
        Err(Miss::Reconstruct(cause)) => {
            if cause == ReconstructCause::Identity {
                // C′: void before any reuse; a fresh `Reset` stage of this
                // key in the same pass cancels the retirement.
                let _ = state_v2::retire_tail(route, [key.to_owned()]);
            }
            let outcome = if cause == ReconstructCause::KeyEpoch {
                "miss"
            } else {
                "error"
            };
            (outcome, Some(cause.label()), Load::Cold(None))
        }
    };
    if let Some(cause) = reconstruct {
        // A head was read and could not be reused; the release gate reads
        // these apart from a file's first read. A key change is an explicit
        // action, counted apart from both.
        let explicit_action = cause == ReconstructCause::KeyEpoch.label();
        let after_head = !matches!(cause, "no_head" | "unreadable") && !explicit_action;
        let bytes = held.metadata().map_or(0, |metadata| metadata.len());
        counters::bump(source, "tail_reconstruct", cause);
        counters::add(source, "tail_reconstruct_bytes", cause, bytes);
        if after_head {
            counters::bump(source, "tail_reconstruct_after_head", cause);
            if counters::restart_full_alarm_due(source) {
                crate::local_resource_diagnostics::tail_restart_full_alarm(
                    source.api_slug(),
                    &serde_json::json!({ "cause": cause }),
                );
            }
        }
    }
    counters::bump(source, "tail_db_loads", outcome);
    load
}

/// The stored reduction, its base and the bytes read, or why not. The
/// session facts load here, with the pages, only for a read that continues
/// the file.
fn stored<S: TailSource>(
    index: &ScanIndex,
    key: &str,
    id: &HeadIdentity,
    held: &mut File,
    scope: &Scope,
    fresh: &CandidateFile,
    live: &SnapshotAccumulator,
) -> Result<Hit, Miss> {
    let head = match state_v2::load_head(index, key, S::REDUCTION_REVISION) {
        Ok(Some(head)) => head,
        Ok(None) => return Err(Miss::NoHead),
        Err(error) if error.downcast_ref::<Hold>() == Some(&Hold::Future) => {
            return Err(Miss::Future)
        }
        Err(_) => return Err(Miss::Unreadable),
    };
    // Before any decode: a metadata-only head has nothing to restore.
    if head.metadata_only {
        return Err(Miss::MetadataOnly);
    }
    let toggled = id.check(&head.body).map_err(Miss::Reconstruct)?;
    let mut acc = SnapshotAccumulator::new(S::SOURCE);
    let decoded = S::decode_head(head.revision, &head.body, &mut acc).map_err(Miss::Reconstruct)?;
    // The file against the certificate, before any page.
    let checkpoint = match decoded.certificate.restore_grown(held, scope.clone()) {
        Ok((checkpoint, _)) => checkpoint,
        Err(CertificateRefusal::Changed(reason)) => return Err(Miss::Changed(reason)),
        Err(CertificateRefusal::ReadError) => return Err(Miss::Unreadable),
    };
    let mut base = TailBase::new(&head.body);
    let mut failed = None;
    let mut page_bytes = 0u64;
    let pages = state_v2::load_tail(index, key, &head, |collection, page, bytes| {
        page_bytes = page_bytes.saturating_add(bytes.len() as u64);
        S::decode_page(collection, page, &bytes, &mut acc)
            .and_then(|()| base.observe::<S>(collection, page, &bytes))
            .map_err(|cause| {
                failed = Some((collection, cause));
                anyhow::anyhow!("tail_page")
            })
    });
    if pages.is_err() {
        return Err(match failed {
            Some((state_v2::Collection::SessionFacts, ReconstructCause::Incompatible)) => {
                Miss::FutureFact
            }
            Some((_, cause)) => Miss::Reconstruct(cause),
            None => Miss::Reconstruct(ReconstructCause::Corrupt),
        });
    }
    // The reduction's collections only: `Revisions` is the file's freshness
    // debt (G7), never a reduction page (`load_tail` skips it too).
    let table = head
        .table
        .iter()
        .filter(|(c, _)| **c != state_v2::Collection::Revisions)
        .map(|(c, m)| (*c, m.meta))
        .collect();
    S::validate_loaded(&acc, &table).map_err(Miss::Reconstruct)?;
    S::install_live(&mut acc, fresh, live).map_err(|error| match error {
        LiveLoadError::Unavailable => Miss::LiveUnavailable,
        LiveLoadError::Reconstruct(cause) => Miss::Reconstruct(cause),
    })?;
    let mut reduction = CachedJsonlReduction::stored(acc, decoded.report, decoded.scalars);
    if toggled {
        reduction.scrub_identity(true, false);
    }
    let taken = Taken {
        modified_hint: checkpoint.modified_hint(),
        retained: Retained {
            checkpoint,
            state: reduction,
        },
        finalization_charge: 0,
        e2_held_new_file: false,
    };
    Ok(Hit {
        taken: Box::new(taken),
        base,
        head_bytes: head.body.len() as u64,
        page_bytes,
    })
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod facts_tests;
#[cfg(test)]
#[path = "format_tests.rs"]
mod format_tests;
#[cfg(test)]
#[path = "held_original_tests.rs"]
mod held_original_tests;
#[cfg(test)]
#[path = "refold_tests.rs"]
mod refold_tests;
#[cfg(test)]
#[path = "settlement_tests.rs"]
mod settlement_tests;
#[cfg(test)]
#[path = "load_tests.rs"]
mod tests;
