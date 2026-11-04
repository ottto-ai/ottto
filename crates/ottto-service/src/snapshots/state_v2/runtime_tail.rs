//! Route seams of the Tail store (`tail.rs`): staging in the route's state,
//! on-demand reads on the graph's session, and the cycle-exit commit.
use super::super::tail::{
    Collection, Observation, PathCarry, SetAside, SetAsideCause, StagedFile, TailHead, TailStage,
};
use super::*;

/// Prepare-time carry: the original RAM graph stays old until COMMIT. The
/// ordinary save owns CAS merge, graph encoding, Tail movement and rollback.
pub(in crate::snapshots) fn carry_tail(
    index: &mut ScanIndex,
    to: &str,
    carry: PathCarry,
) -> Result<()> {
    let path = runtime_path(index)?.ok_or(Hold::ReloadRequired)?;
    let _owner = super::super::super::CheckpointLock::acquire(&path)?;
    let mut next = index.clone();
    with_save_session(
        &path,
        index.v2().persistence_v2.clone(),
        index.generation,
        |state, session, id| {
            let previous = match state.save_digests.take() {
                Some(previous) => previous,
                None => {
                    let (committed, mut cx) = import::hydrate_context(&mut session.db)?;
                    let previous = kinds::baseline(&committed, &mut cx)?;
                    session.cx = cx;
                    previous
                }
            };
            let moved = state.tail.carry_observation(to, &carry)?;
            recovered_write(&path, None, &id, session, |session| {
                session.cx.carry = Some((to.to_owned(), carry));
                session.cx.tail = Some(moved);
                let digests =
                    import::save(&mut session.db, &id, previous, &mut next, &mut session.cx)?;
                session.stamp = session.db.stamp()?;
                state.save_digests = Some(digests);
                Ok(())
            })
        },
    )?
    .ok_or(Hold::ReloadRequired)?;
    *index = next;
    super::super::super::sampled_audit::renew_growth_claims(index, &path);
    Ok(())
}
/// Staged state never declines; a later completion of the file merges into it.
pub(in crate::snapshots) fn stage_tail(path: &Path, key: &str, file: StagedFile) -> Result<()> {
    with_state(path, |state| {
        state.tail.stage(key, file);
        Ok(())
    })
}
/// This file's completion could not encode: its predecessor stays.
pub(in crate::snapshots) fn set_aside_tail(
    path: &Path,
    key: &str,
    cause: SetAsideCause,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.set_aside(key, cause);
        Ok(())
    })
}
/// `keys`: files a complete census proved absent, or whose stored state is void.
/// The next save deletes their rows; anything staged for them is dropped, and a
/// later `Reset` stage of a key cancels its retirement. No sweep or age ever
/// supplies this list.
pub(in crate::snapshots) fn retire_tail(
    path: &Path,
    keys: impl IntoIterator<Item = String>,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.retire(keys);
        Ok(())
    })
}
/// The head this pass staged on `path` for `key`, not yet committed.
#[cfg(test)]
pub(in crate::snapshots) fn staged_head_for_test(path: &Path, key: &str) -> Option<(u32, Vec<u8>)> {
    with_state(path, |state| Ok(state.tail.staged_head(key))).unwrap()
}
/// A debt-only change of one file, committed with the next save or at exit; a
/// later one of the same file before then replaces it. It never publishes the
/// file's graph progress and never clears its marker.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the Tail debt owner (G7) calls this")
)]
pub(in crate::snapshots) fn observe_tail(
    path: &Path,
    key: &str,
    observation: Observation,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.observe(key, observation);
        Ok(())
    })
}
/// `observe_tail` for many files at once: one stage report, not one per file.
pub(in crate::snapshots) fn observe_tails(
    path: &Path,
    observations: Vec<(String, Observation)>,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.observe_all(observations);
        Ok(())
    })
}
/// Source withdrawal or a foreign scope: every Tail row of `keys`, debt included,
/// is erased with the next save. A file that still held unaccepted revisions
/// adds one to `tail_discovery.deleted_unaccepted_files` and contributes its
/// oldest known change to `deleted_unaccepted_oldest_at`; `index` saves both.
pub(in crate::snapshots) fn erase_tail(
    path: &Path,
    index: &mut ScanIndex,
    keys: impl IntoIterator<Item = String>,
) -> Result<()> {
    for key in keys {
        let committed = read_txn(index, |tx| {
            super::super::tail::erasure_debt(tx, key.as_bytes())
        })?
        .0;
        let (counted, oldest) = with_state(path, |state| Ok(state.tail.erase(&key, committed)))?;
        if counted {
            let discovery = &mut index.tail_discovery;
            discovery.deleted_unaccepted_files =
                discovery.deleted_unaccepted_files.saturating_add(1);
            discovery.deleted_unaccepted_oldest_at = discovery
                .deleted_unaccepted_oldest_at
                .into_iter()
                .chain(oldest)
                .min();
        }
    }
    Ok(())
}
/// One file's committed head, on the graph's authenticated session; no page is
/// visited. A future revision holds; a lower one is the caller's to decide.
pub(in crate::snapshots) fn load_head(
    index: &ScanIndex,
    key: &str,
    revision: u32,
) -> Result<Option<TailHead>> {
    read_txn_at(index, |tx, stamp| {
        super::super::tail::load_head(tx, key.as_bytes(), revision, stamp.0)
    })
}
/// Historical first-seen evidence only; no disposition or attempt is applied.
pub(in crate::snapshots) fn legacy_archive_was_seen(index: &ScanIndex, key: &str) -> Result<bool> {
    Ok(read_txn(index, |tx| {
        Ok(tx
            .get(&super::super::mapper::key("v1_field.archives", key, 1)?)?
            .is_some())
    })?
    .0)
}

/// `head`'s pages, one short read transaction, streamed to `visit`. See
/// `tail::load_pages` for its outcomes.
pub(in crate::snapshots) fn load_tail(
    index: &ScanIndex,
    key: &str,
    head: &TailHead,
    mut visit: impl FnMut(Collection, u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    let started = Instant::now();
    read_txn_at(index, |tx, stamp| {
        super::super::tail::load_pages(tx, key.as_bytes(), head, stamp.0, &mut visit)
    })?;
    telemetry::event("tail_load_tx_ms", &started.elapsed().as_millis());
    Ok(())
}
/// `head`'s revisions by id, one short read transaction; same outcomes as
/// `load_tail`, and a metadata-only head has them too.
pub(in crate::snapshots) fn load_revisions(
    index: &ScanIndex,
    key: &str,
    head: &TailHead,
    mut visit: impl FnMut(u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    read_txn_at(index, |tx, stamp| {
        super::super::tail::load_revisions(tx, key.as_bytes(), head, stamp.0, &mut visit)
    })
}
/// The route of `index`'s live session, for a caller holding only the graph:
/// `None` for a v1 graph, which has no Tail store.
pub(in crate::snapshots) fn tail_route_path(
    index: &ScanIndex,
) -> Result<Option<std::path::PathBuf>> {
    runtime_path(index)
}
/// Every key with a committed head, this route's graph generation, keys only.
pub(in crate::snapshots) fn tail_head_keys(
    index: &ScanIndex,
) -> Result<std::collections::BTreeSet<String>> {
    Ok(read_txn(index, super::super::tail::head_keys)?.0)
}
pub(in crate::snapshots) fn tail_set_aside(
    index: &ScanIndex,
    key: &str,
) -> Result<Option<SetAside>> {
    Ok(read_txn(index, |tx| {
        super::super::tail::read_set_aside(tx, key.as_bytes())
    })?
    .0)
}

/// Normal cycle exit: a stage no later save will carry gets one Tail-only commit.
/// On `Err` the stage stays for the pass owner's drop. No external effect follows.
pub(super) fn commit_at_exit(path: &Path, runtime: &std::sync::Weak<Runtime>) -> Result<()> {
    if with_state(path, |state| Ok(state.tail.is_empty()))? {
        return Ok(());
    }
    exit_commit(path, runtime)
}
/// The pass owner's drop never writes, unwinding or not: whatever is left is
/// dropped and counted, its next read replaying from the previous head.
pub(super) fn discard_at_exit(path: &Path) {
    let _ = with_state(path, |state| {
        let dropped = std::mem::take(&mut state.tail);
        if !dropped.is_empty() {
            telemetry::event(
                "tail_stage_dropped",
                &serde_json::json!({"files": dropped.files(), "bytes": dropped.bytes()}),
            );
        }
        Ok(())
    });
}
/// The claim owner's boundaries: owner lock, session checks, ACK recovery, then
/// G authenticated before BEGIN IMMEDIATE. The session's stamp is the lineage:
/// only a confirmed G+1 promotes it, so stale siblings at G then refuse.
fn exit_commit(path: &Path, runtime: &std::sync::Weak<Runtime>) -> Result<()> {
    let runtime = runtime.upgrade().ok_or(Hold::ReloadRequired)?;
    let _owner = super::super::super::CheckpointLock::acquire(path)?;
    let expected = runtime
        .session
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .as_ref()
        .ok_or(Hold::ReloadRequired)?
        .stamp
        .0;
    let _save_window = telemetry::Window::begin("save");
    with_save_session(path, Some(runtime), expected, |state, session, id| {
        recovered_write(path, None, &id, session, |session| {
            super::super::tail::commit_exit(&mut session.db, &id, expected, &state.tail)?;
            session.stamp = session.db.stamp()?;
            state.save_digests = None;
            state.tail = TailStage::default();
            Ok(())
        })
    })?
    .ok_or_else(|| Hold::ReloadRequired.into())
}
