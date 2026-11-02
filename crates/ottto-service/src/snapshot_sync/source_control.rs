//! Web disable and install, delivered on the local-health heartbeat response.
//!
//! The server sends the latest explicit choice per source, ordered by a
//! revision it assigns per device and source. A newer revision applies once.
//! A disable also holds at its own revision, so a late local reconnect cannot
//! outlive it. Older revisions and another device's control do nothing.
use super::{
    disable_snapshot_source, reconnect_snapshot_source, source_granted, source_marker,
    SNAPSHOT_SOURCES,
};
use crate::backfill::{load_backfill_state, update_backfill_state};
use crate::snapshots::SnapshotSource;
use ottto_core::LocalDeviceBinding;
use serde::Deserialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::path::Path;

pub(crate) const CAPABILITY: &str = "source_control:v1";

type MarkerWrite = fn(&Path, SnapshotSource) -> anyhow::Result<()>;

#[derive(Deserialize)]
struct Control {
    contract: String,
    device_id: String,
    sources: Vec<SourceState>,
}

#[derive(Deserialize)]
struct SourceState {
    source: String,
    revision: u64,
    desired_state: String,
}

/// Health authenticates through any granted source, so a Mac with every
/// source disabled still polls and can hear an explicit install.
pub(crate) fn transport_source(device: &LocalDeviceBinding) -> Option<SnapshotSource> {
    SNAPSHOT_SOURCES
        .into_iter()
        .find(|source| source_granted(device, *source))
}

/// Applies `source_control` from a heartbeat response; true when a marker
/// changed. The marker is written before the revision is recorded, so a crash
/// between them repeats an idempotent write. A source whose write fails stays
/// owed and never holds the others.
pub(crate) fn apply(support_dir: &Path, device_id: &str, response: &Value) -> bool {
    let Some(control) = response.get("source_control").filter(|c| !c.is_null()) else {
        return false;
    };
    let control = match Control::deserialize(control) {
        Ok(control) if control.contract == CAPABILITY && control.device_id == device_id => control,
        _ => {
            eprintln!("source control skipped: unreadable or for another device");
            return false;
        }
    };
    let applied = load_backfill_state(support_dir).source_control_revisions;
    let (mut changed, mut advanced, mut failed) = (false, Vec::new(), 0usize);
    for state in control.sources {
        let Some(source) = SNAPSHOT_SOURCES
            .into_iter()
            .find(|source| source.api_slug() == state.source)
        else {
            continue;
        };
        let seen = applied
            .get(&state.source)
            .filter(|(device, _)| device == device_id)
            .map_or(0, |(_, revision)| *revision);
        let marker = source_marker(support_dir, source);
        let write: Option<MarkerWrite> =
            match (state.desired_state.as_str(), state.revision.cmp(&seen)) {
                (_, Ordering::Less) => continue,
                ("disabled", _) if matches!(marker.as_deref(), None | Some("reconnect")) => {
                    Some(disable_snapshot_source as MarkerWrite)
                }
                ("enabled", Ordering::Greater) if marker.is_some() => {
                    Some(reconnect_snapshot_source)
                }
                ("disabled" | "enabled", _) => None,
                _ => continue,
            };
        if let Some(write) = write {
            if write(support_dir, source).is_err() {
                failed += 1;
                continue;
            }
            changed = true;
        }
        if state.revision > seen {
            advanced.push((state.source, state.revision));
        }
    }
    if !advanced.is_empty() {
        let saved = update_backfill_state(support_dir, |backfill| {
            for (source, revision) in advanced {
                let entry = (device_id.to_string(), revision);
                backfill.source_control_revisions.insert(source, entry);
            }
        });
        failed += usize::from(saved.is_err());
    }
    if failed > 0 {
        eprintln!("source control owed: {failed} write(s) failed");
    }
    changed
}

/// A heartbeat response carrying one source's control for `device_id`.
#[cfg(test)]
pub(crate) fn response_for_test(
    device_id: &str,
    source: &str,
    revision: u64,
    state: &str,
) -> Value {
    serde_json::json!({"accepted": true, "source_control": {
        "contract": CAPABILITY, "device_id": device_id,
        "sources": [{"source": source, "revision": revision, "desired_state": state,
            "changed_at": "2026-11-02T12:00:00Z",
            "action_id": "00000000-0000-4000-8000-000000000001"}]}})
}
