//! Yield all Ottto acquisition work to due privacy maintenance.
use super::*;

pub(in super::super::super) fn before_collection(index: &ScanIndex) -> Result<()> {
    let Some(runtime) = &index.v2().persistence_v2 else {
        return Ok(());
    };
    // Release the session lock before acquiring the checkpoint lock, preserving
    // the established checkpoint -> route -> session ordering.
    let (path, due) = {
        let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
        let session = guard.as_mut().ok_or(Hold::DbUnavailable)?;
        (session.path.clone(), session.db.collection_pause_due()?)
    };
    if telemetry::sample_cached_graph() {
        with_state(&path, |state| {
            if let Some(cached) = &state.cached {
                telemetry::retained(cached, "cached_graph");
            }
            Ok(())
        })?;
    }
    if !due {
        return Ok(());
    }
    let _lock = super::super::super::CheckpointLock::acquire_for_maintenance(&path).inspect_err(
        |error| {
            if let Ok(mut guard) = runtime.session.lock() {
                if let Some(session) = guard.as_mut() {
                    session.db.collection_lock_refused(
                        if error.to_string().starts_with("state_v2_own_") {
                            "own_lock"
                        } else if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
                        {
                            "external_lock"
                        } else {
                            "lock_io"
                        },
                    );
                }
            }
        },
    )?;
    held(with_state(&path, |state| {
        let mut guard = runtime.session.lock().map_err(|_| Hold::DbUnavailable)?;
        let session = guard.as_mut().ok_or(Hold::DbUnavailable)?;
        ensure!(!session.reload && session.path == path, Hold::DbUnavailable);
        let pair = fence::reconcile(&path, &session.identity.binding, state.latched)?;
        ensure!(
            pair.is_some_and(|(id, _)| id == session.identity),
            Hold::FenceLost
        );
        ensure!(session.db.stamp()? == session.stamp, Hold::ReloadRequired);
        session.db.before_collection().map_err(Hold::storage)?;
        session.stamp = session.db.stamp()?;
        Ok(())
    }))
}

/// Retain source debt and requeue the failed path through the existing bounded
/// traversal. Backoff suppresses parsing, never discovery or age retention.
/// A failure is a hold: the session is dropped, so the collection guard
/// (before_collection) and every save/side-effect guard refuse this scan.
pub(in super::super::super) fn retain_resume_exclusions(index: &mut ScanIndex, roots: &[PathBuf]) {
    let keys = held(runtime_path(index).and_then(|path| {
        let Some(path) = path else {
            return Ok(Vec::new());
        };
        with_state(&path, |state| {
            let now = Instant::now();
            for excluded in state.resume_excluded.values_mut() {
                excluded.passes = excluded.passes.saturating_add(1);
                if excluded.passes >= 3
                    || now.saturating_duration_since(excluded.first_seen)
                        > Duration::from_secs(6 * 3600)
                {
                    telemetry::event("v2_resume_stage_excluded_alarm", &1);
                }
            }
            if !state.resume_excluded.is_empty() {
                telemetry::event(
                    "v2_resume_stage_excluded",
                    &(state.resume_excluded.len() as u64),
                );
            }
            Ok(state.resume_excluded.keys().cloned().collect::<Vec<_>>())
        })
    }));
    let Ok(keys) = keys else {
        if let Some(runtime) = &index.v2().persistence_v2 {
            if let Ok(mut session) = runtime.session.lock() {
                session.take();
            }
        }
        return;
    };
    for key in keys {
        super::super::super::sampled_audit::retain_resume_excluded(index, &key, roots);
    }
}

pub(in super::super::super) fn resume_key_retained(index: &ScanIndex, key: &str) -> bool {
    let Ok(Some(path)) = runtime_path(index) else {
        return index.v2().persistence_v2.is_some();
    };
    with_state(&path, |state| Ok(state.resume_excluded.contains_key(key))).unwrap_or(true)
}

/// Metadata can count growth while the bounded staging backoff blocks parsing.
pub(in super::super::super) fn resume_selection_held(
    index: &ScanIndex,
    key: &str,
    len: Option<u64>,
) -> bool {
    let result = (|| {
        let Some(path) = runtime_path(index)? else {
            return Ok(false);
        };
        with_state(&path, |state| {
            let Some(excluded) = state.resume_excluded.get_mut(key) else {
                return Ok(false);
            };
            if let Some(len) = len.filter(|len| *len > excluded.observed_len) {
                telemetry::event(
                    "v2_resume_excluded_growth_bytes",
                    &(len - excluded.observed_len),
                );
                excluded.observed_len = len;
            }
            Ok(Instant::now() < excluded.retry_at)
        })
    })();
    result.unwrap_or(true)
}
