//! Claude's continuation from the state database. RAM keeps no Claude
//! reduction on a database route: a read that continues a file loads its
//! committed Tail head, checks the head's identity, then the file against the
//! head's certificate, then streams the pages (the session facts among
//! them), and validates the decoded state. Content is never read back from
//! the file: a quiet restart reads 0 transcript bytes.
//!
//! Each load counts once in `tail_db_loads{source, outcome}`. Stored state
//! that cannot be reused is a counted reconstruction (`tail_reconstruct`) and
//! the read starts at once as a Full; only a head from a newer build holds
//! the file, untouched. A head bound to another route, scan root or path is
//! retired before anything else in it is read (C′), whatever the Full that
//! follows achieves.
use super::claude::Claude;
use super::counters;
use super::seam::TailBase;
use super::{HeadIdentity, ReconstructCause, TailSource};
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
    /// A newer build's head: the file waits for that build.
    Held,
    /// Start a Full read now, with the reason the file proved, if any.
    Cold(Option<FullReason>),
}

/// The route Claude's Tail lives on: the state database.
pub(in crate::snapshots) fn route(source: SnapshotSource, index: &ScanIndex) -> Option<PathBuf> {
    (source == SnapshotSource::ClaudeCode)
        .then(|| state_v2::runtime_path(index).ok().flatten())
        .flatten()
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
    let Some(route) = route(source, index) else {
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

/// Claude's load of `candidate` on `route`; `held` is the read's opened file.
pub(in crate::snapshots) fn claude(
    index: &ScanIndex,
    route: &Path,
    candidate: &CandidateFile,
    capture: bool,
    held: &mut File,
    scope: &Scope,
) -> Load {
    let id = HeadIdentity::new(
        route,
        Claude::SOURCE,
        &candidate.scan_root,
        &candidate.path,
        capture,
    );
    load::<Claude>(
        index,
        route,
        &local_index_key(&candidate.path),
        &id,
        held,
        scope,
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
}

pub(super) fn load<S: TailSource>(
    index: &ScanIndex,
    route: &Path,
    key: &str,
    id: &HeadIdentity,
    held: &mut File,
    scope: &Scope,
) -> Load {
    let slug = S::SOURCE.api_slug();
    let point = |stage, counts: serde_json::Value| {
        crate::local_resource_diagnostics::traversal_point(stage, slug, &counts)
    };
    // (outcome, cause, counted reconstruction, load)
    let (outcome, cause, reconstruct, load) = match stored::<S>(index, key, id, held, scope) {
        Ok((taken, base)) => {
            let base = (!set_aside(index, key)).then_some(base);
            point("tail_db_loads", serde_json::json!({"outcome": "hit"}));
            counters::bump("tail_db_loads", "hit");
            return Load::Reused(taken, base);
        }
        Err(Miss::Future) => ("held", "future_revision".into(), None, Load::Held),
        // Valid stored state for a file that changed: an ordinary Full.
        Err(Miss::Changed(reason)) => (
            "miss",
            serde_json::json!(reason),
            None,
            Load::Cold(Some(reason)),
        ),
        Err(Miss::NoHead) => {
            counters::bump("tail_bootstrap_full", "no_head");
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
            (
                "error",
                cause.label().into(),
                Some(cause.label()),
                Load::Cold(None),
            )
        }
    };
    if let Some(cause) = reconstruct {
        // A head was read and could not be reused; the release gate reads
        // these apart from a file's first read.
        let after_head = !matches!(cause, "no_head" | "unreadable");
        let bytes = held.metadata().map_or(0, |metadata| metadata.len());
        point(
            "tail_reconstruct",
            serde_json::json!({ "cause": cause, "after_head": after_head, "bytes": bytes }),
        );
        counters::bump("tail_reconstruct", cause);
        counters::add("tail_reconstruct_bytes", cause, bytes);
        if after_head {
            counters::bump("tail_reconstruct_after_head", cause);
            if counters::restart_full_alarm_due() {
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
    counters::bump("tail_db_loads", outcome);
    load
}

/// The stored reduction and its base, or why not. The session facts load
/// here, with the pages, only for a read that continues the file.
fn stored<S: TailSource>(
    index: &ScanIndex,
    key: &str,
    id: &HeadIdentity,
    held: &mut File,
    scope: &Scope,
) -> Result<(Box<Taken<CachedJsonlReduction>>, TailBase), Miss> {
    let head = match state_v2::load_head(index, key, S::REDUCTION_REVISION) {
        Ok(Some(head)) => head,
        Ok(None) => return Err(Miss::NoHead),
        Err(error) if error.downcast_ref::<Hold>() == Some(&Hold::Future) => {
            return Err(Miss::Future)
        }
        Err(_) => return Err(Miss::Unreadable),
    };
    id.check(&head.body).map_err(Miss::Reconstruct)?;
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
    let pages = state_v2::load_tail(index, key, &head, |collection, page, bytes| {
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
    let reduction = CachedJsonlReduction::stored(acc, decoded.report, decoded.scalars);
    let taken = Taken {
        modified_hint: checkpoint.modified_hint(),
        retained: Retained {
            checkpoint,
            state: reduction,
        },
        finalization_charge: 0,
        e2_held_new_file: false,
    };
    Ok((Box::new(taken), base))
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod facts_tests;
#[cfg(test)]
#[path = "floor_tests.rs"]
mod floor_tests;
#[cfg(test)]
#[path = "settlement_tests.rs"]
mod settlement_tests;
#[cfg(test)]
#[path = "load_tests.rs"]
mod tests;
