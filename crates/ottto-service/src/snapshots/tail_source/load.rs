//! A source's continuation from the state database. RAM keeps no reduction
//! of a source with a Tail codec on a database route: a read that continues
//! a file loads its committed Tail head, checks the head's identity, then the
//! file against the head's certificate, then streams the pages, validates the
//! decoded state, re-derives the content fields from the file at their marks
//! (checking each against its stored digest), and installs the read's live
//! inputs.
//!
//! Each load counts once in `tail_db_loads{outcome}` on its source's line,
//! with the head and page bytes it read on a hit. Stored state that cannot be
//! reused is a counted reconstruction (`tail_reconstruct`) and the read starts
//! at once as a Full; a file shorter than its head reads Full (`Shrunk`) and
//! is counted in `tail_shorter_file_full`. Only a head from a newer build, or
//! a live input that is not available now, holds the file, untouched. A head
//! bound to another route, scan root or path is retired before anything else
//! in it is read (C′), whatever the Full that follows achieves. A head made
//! under another key (a rotation) is an explicit-action reconstruction:
//! counted, but neither a release-gate failure nor an alarm. Attribution
//! toggled on or off since the head is no rotation: the head is reused with
//! its context digest scrubbed, as main scrubs a retained parse's (D168-2).
use super::counters;
use super::seam::TailBase;
use super::{HeadIdentity, LiveLoadError, ReconstructCause, TailSource};
use crate::snapshots::sampled_jsonl::durable::Decoded;
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

/// The per-candidate marker check, before an ordinary Skip: a file whose
/// Tail failed alone re-reads from its committed head even when its graph
/// stamps already match.
pub(in crate::snapshots) fn set_aside(index: &ScanIndex, key: &str) -> bool {
    matches!(state_v2::tail_set_aside(index, key), Ok(Some(_)))
}

/// A4d: after a complete census with no decode hold, a head whose file the
/// census did not observe, that is no residue and has no index entry, is
/// absent; its rows retire at the next save. A read error retires nothing.
/// A set-aside marker with no head is not listed.
pub(in crate::snapshots) fn retire_absent(
    source: SnapshotSource,
    index: &ScanIndex,
    observed: &BTreeSet<String>,
    residue: &BTreeSet<String>,
) {
    let Some(route) = super::tail_route(source, index) else {
        return;
    };
    let Ok(mut absent) = state_v2::tail_head_keys(index) else {
        return;
    };
    absent.retain(|key| {
        !observed.contains(key) && !residue.contains(key) && !index.files.contains_key(key)
    });
    let _ = state_v2::retire_tail(&route, absent);
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
    Future,
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
    rederive_bytes: u64,
    head_bytes: u64,
    page_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
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
    let slug = source.api_slug();
    let point = |stage, counts: serde_json::Value| {
        crate::local_resource_diagnostics::traversal_point(stage, slug, &counts)
    };
    // (outcome, cause, counted reconstruction, load)
    let loaded = stored::<S>(index, key, id, held, scope, fresh, live);
    let (outcome, cause, reconstruct, load) = match loaded {
        Ok(hit) => {
            let base = (!set_aside(index, key)).then_some(hit.base);
            point(
                "tail_db_loads",
                serde_json::json!({
                    "outcome": "hit",
                    "rederive_bytes": hit.rederive_bytes,
                    "head_bytes": hit.head_bytes,
                    "page_bytes": hit.page_bytes,
                }),
            );
            counters::bump(source, "tail_db_loads", "hit");
            return Load::Reused(hit.taken, base);
        }
        Err(Miss::Future) => ("held", "future_revision".into(), None, Load::Held),
        Err(Miss::LiveUnavailable) => ("held", "live_unavailable".into(), None, Load::Held),
        // Valid stored state for a file that changed: an ordinary Full. A
        // shorter file is main's counted Full; no floor holds it (D158).
        Err(Miss::Changed(reason)) => {
            if reason == FullReason::Shrunk {
                counters::bump(source, "tail_shorter_file_full", "files");
            }
            (
                "miss",
                serde_json::json!(reason),
                None,
                Load::Cold(Some(reason)),
            )
        }
        Err(Miss::NoHead) => {
            counters::bump(source, "tail_bootstrap_full", "no_head");
            ("miss", "no_head".into(), Some("no_head"), Load::Cold(None))
        }
        Err(Miss::Unreadable) => (
            "error",
            "unreadable".into(),
            Some("unreadable"),
            Load::Cold(None),
        ),
        Err(Miss::Reconstruct(cause)) => {
            if cause == ReconstructCause::Identity {
                // C′: void before any reuse; a fresh `Reset` stage of this
                // key in the same pass cancels the retirement.
                let _ = state_v2::retire_tail(route, [key.to_owned()]);
                point("tail_identity_failure", serde_json::json!({"files": 1}));
            }
            let outcome = if cause == ReconstructCause::KeyEpoch {
                "miss"
            } else {
                "error"
            };
            (
                outcome,
                cause.label().into(),
                Some(cause.label()),
                Load::Cold(None),
            )
        }
    };
    if let Some(cause) = reconstruct {
        // A head was read and could not be reused; the release gate reads
        // these apart from a file's first read. A key change is an explicit
        // action, counted apart from both.
        let explicit_action = cause == ReconstructCause::KeyEpoch.label();
        let after_head = !matches!(cause, "no_head" | "unreadable") && !explicit_action;
        let bytes = held.metadata().map_or(0, |metadata| metadata.len());
        point(
            "tail_reconstruct",
            serde_json::json!({
                "cause": cause,
                "after_head": after_head,
                "explicit_action": explicit_action,
                "bytes": bytes,
            }),
        );
        counters::bump(source, "tail_reconstruct", cause);
        counters::add(source, "tail_reconstruct_bytes", cause, bytes);
        if after_head {
            counters::bump(source, "tail_reconstruct_after_head", cause);
            if counters::restart_full_alarm_due(source) {
                crate::local_resource_diagnostics::tail_restart_full_alarm(
                    slug,
                    &serde_json::json!({ "cause": cause }),
                );
            }
        }
    }
    point(
        "tail_db_loads",
        serde_json::json!({"outcome": outcome, "cause": cause}),
    );
    counters::bump(source, "tail_db_loads", outcome);
    load
}

fn not_rederivable<E>(_: E) -> Miss {
    Miss::Reconstruct(ReconstructCause::NotRederivable)
}

/// The stored reduction, its base and the bytes read, or why not.
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
    let toggled = id.check(&head.body).map_err(Miss::Reconstruct)?;
    let mut acc = SnapshotAccumulator::new(S::SOURCE);
    let decoded = S::decode_head(head.revision, &head.body, &mut acc).map_err(Miss::Reconstruct)?;
    // The file against the certificate, before any page.
    let checkpoint = match decoded.certificate.restore_grown(held, scope.clone()) {
        Ok((checkpoint, _)) => checkpoint,
        Err(CertificateRefusal::Changed(reason)) => return Err(Miss::Changed(reason)),
        Err(CertificateRefusal::ReadError) => return Err(Miss::Unreadable),
    };
    let mut base = TailBase::new(&head.body, head.revision < S::REDUCTION_REVISION);
    let mut failed = None;
    let mut page_bytes = 0u64;
    let pages = state_v2::load_tail(index, key, &head, |collection, page, bytes| {
        page_bytes = page_bytes.saturating_add(bytes.len() as u64);
        S::decode_page(collection, page, &bytes, &mut acc)
            .and_then(|()| base.observe::<S>(collection, page, &bytes))
            .map_err(|cause| {
                failed = Some(cause);
                anyhow::anyhow!("tail_page")
            })
    });
    if pages.is_err() {
        return Err(Miss::Reconstruct(
            failed.unwrap_or(ReconstructCause::Corrupt),
        ));
    }
    let table = head.table.iter().map(|(c, m)| (*c, m.meta)).collect();
    S::validate_loaded(&acc, &table).map_err(Miss::Reconstruct)?;
    S::install_live(&mut acc, fresh, live).map_err(|error| match error {
        LiveLoadError::Unavailable => Miss::LiveUnavailable,
        LiveLoadError::Reconstruct(cause) => Miss::Reconstruct(cause),
    })?;
    let mut reduction = CachedJsonlReduction::stored(acc, decoded.report, decoded.scalars);
    if toggled {
        reduction.scrub_context_digest();
    }
    let content = Decoded::stored(reduction, decoded.rederive);
    let plan = content
        .rederive_plan_within(u64::MAX, u64::MAX)
        .map_err(not_rederivable)?;
    let (reduction, receipt, _) = content
        .rederive_content_planned(held, &plan)
        .map_err(not_rederivable)?;
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
        rederive_bytes: receipt.head_bytes + receipt.line_bytes,
        head_bytes: head.body.len() as u64,
        page_bytes,
    })
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod format_tests;
#[cfg(test)]
#[path = "settlement_tests.rs"]
mod settlement_tests;
#[cfg(test)]
#[path = "load_tests.rs"]
mod tests;
