//! Committed, content-free membership for R1's restart-record erasure sweep.
use super::*;
use crate::durable_tail_store::DurableSource;
use crate::snapshots::scan_index_persistence::Source;
use std::collections::BTreeSet;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "R1 consumes these staged sweep result fields")
)]
#[derive(Debug)]
pub(crate) struct LiveKeys {
    pub complete: bool,
    pub incomplete_reason: Option<IncompleteReason>,
    pub generation: u64,
    pub digests: BTreeSet<[u8; 32]>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IncompleteReason {
    Hold,
    Reload,
    Import,
    Ambiguous,
    Off,
}
impl LiveKeys {
    pub(in crate::snapshots::state_v2) fn incomplete(reason: IncompleteReason) -> Self {
        Self {
            complete: false,
            incomplete_reason: Some(reason),
            generation: 0,
            digests: BTreeSet::new(),
        }
    }
}

/// Caller retains the source owner/CheckpointLock, as on save/erasure, and
/// rechecks generation before each unlink batch. Do not acquire it recursively.
/// WAL readers see one committed snapshot; never consult the cached graph.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "R1 integrates this committed-membership seam in its sweep"
    )
)]
pub(crate) fn live_key_digests(index_path: &Path) -> Result<LiveKeys> {
    // Like every public v2 entry point: no path-bearing error context escapes.
    held(live_keys(index_path))
}
fn live_keys(index_path: &Path) -> Result<LiveKeys> {
    let Some(binding) =
        super::super::super::scan_index_integration::scan_index_storage_binding(index_path)
    else {
        return Ok(LiveKeys::incomplete(IncompleteReason::Off));
    };
    let source = match binding.source {
        Source::Claude => DurableSource::ClaudeCode,
        Source::Codex => DurableSource::Codex,
        // No Pi key mapping yet: never vouch for an empty set (a sweep would
        // erase every Pi record once Pi gains restart records). Map with Pi-ON.
        Source::Pi => return Ok(LiveKeys::incomplete(IncompleteReason::Off)),
    };
    let route = {
        let states = states().lock().map_err(|_| Hold::DbUnavailable)?;
        let mut matches = states.iter().filter(|(path, _)| {
            super::super::super::scan_index_integration::scan_index_storage_binding(path).as_ref()
                == Some(&binding)
        });
        let route = matches
            .next()
            .map(|(path, state)| (path.clone(), state.clone()));
        if route.is_some() && matches.next().is_some() {
            return Ok(LiveKeys::incomplete(IncompleteReason::Hold));
        }
        route
    };
    let Some((path, state)) = route else {
        // Not loaded yet (daemon start, a sweep before the first load):
        // published custody makes v1 JSON stale, so no answer is possible until its
        // load imports the route. Unpublished opens no store or sentinel.
        let reason = if published(index_path)? {
            IncompleteReason::Import
        } else {
            IncompleteReason::Off
        };
        return Ok(LiveKeys::incomplete(reason));
    };
    let state = state.lock().map_err(|_| Hold::DbUnavailable)?;
    if !state.latched {
        return Ok(LiveKeys::incomplete(IncompleteReason::Import));
    }
    let Some(runtime) = &state.current else {
        // Explicit erasure invalidates the route before unlinking. Partial
        // erasure stays held until every owned artifact has disappeared.
        for (suffix, _, _) in fence::ARTIFACTS {
            if fence::exists(&fence::sibling(&path, suffix))? {
                return Ok(LiveKeys::incomplete(IncompleteReason::Hold));
            }
        }
        if fence::exists(&crate::durable_tail_store::store_dir_for_index(&path))?
            || super::super::ack::failed_import_inventory(&path)?.0 != 0
        {
            return Ok(LiveKeys::incomplete(IncompleteReason::Hold));
        }
        // Absence alone is insufficient after a failed erasure fsync. Reuse
        // its durability boundary before certifying the empty erased scope.
        super::super::super::sync_checkpoint_parent(&path)?;
        return Ok(LiveKeys {
            complete: true,
            incomplete_reason: None,
            generation: 0,
            digests: BTreeSet::new(),
        });
    };
    if state.save_hold.is_some() || state.custody_held() {
        return Ok(LiveKeys::incomplete(IncompleteReason::Hold));
    }
    let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
    let Some(session) = guard.as_mut() else {
        return Ok(LiveKeys::incomplete(IncompleteReason::Reload));
    };
    if session.cx.ambiguous {
        return Ok(LiveKeys::incomplete(IncompleteReason::Ambiguous));
    }
    if session.reload || session.db.reload_required() {
        return Ok(LiveKeys::incomplete(IncompleteReason::Reload));
    }
    ensure!(
        session.identity.binding == binding && session.path == path,
        Hold::ForeignBinding
    );
    let pair = fence::reconcile(&path, &binding, state.latched)?;
    ensure!(
        pair.is_some_and(|(identity, _)| identity == session.identity),
        Hold::FenceLost
    );
    session.db.live_key_digests(source, session.stamp)
}
