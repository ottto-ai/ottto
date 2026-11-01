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
    held(with_state(&path, |state| {
        ensure!(!state.custody_held(), Hold::AckCustody);
        Ok(())
    }))?;
    if !due {
        return Ok(());
    }
    let lock =
        super::super::super::CheckpointLock::acquire_for_maintenance(&path).inspect_err(|error| {
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
        });
    let _lock = match lock {
        Ok(lock) => lock,
        Err(error)
            if matches!(
                error.to_string().as_str(),
                "state_v2_own_lock_busy" | "state_v2_own_maintenance_busy"
            ) || error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
        {
            // This lock is only for advisory maintenance. Leave its obligation
            // pending and let collection continue under its normal ownership.
            telemetry::event("maintenance_lock_deferred_alarm", &true);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
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
