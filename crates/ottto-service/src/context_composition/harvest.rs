//! Composition scheduler entry point and shared opt-out and destination helpers.

use super::LOCAL_DISABLE_ENV;
use crate::snapshots::SnapshotSource;
use anyhow::Result;
use ottto_core::LocalDeviceBinding;
use std::fs;
use std::path::{Path, PathBuf};

pub fn spawn_context_composition_sync() -> Result<()> {
    crate::snapshot_sync::home_dir()?;
    super::v2::spawn_v2_sync()
}

pub(super) fn agent_source_label(source: SnapshotSource) -> &'static str {
    match source {
        SnapshotSource::ClaudeCode => "claude-code",
        SnapshotSource::Codex => "codex",
        _ => "unknown",
    }
}

pub(super) fn local_harvest_disabled(support_dir: &Path) -> bool {
    if std::env::var(LOCAL_DISABLE_ENV)
        .map(|value| is_truthy(&value))
        .unwrap_or(false)
    {
        return true;
    }
    support_dir
        .join("context_composition")
        .join("disabled")
        .exists()
}

pub(super) fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(super) fn destination_identity(
    device: &LocalDeviceBinding,
    machine_id: &str,
    api_base_url: &str,
) -> String {
    format!("{}|{}|{}", device.device_id, machine_id, api_base_url)
}

pub(super) fn org_disabled_marker_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("context_composition")
        .join(format!("org_disabled-{}", agent_source_label(source)))
}

pub(super) fn read_marker(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub(super) fn write_marker(path: &Path, identity: &str) {
    if let Some(dir) = path.parent() {
        if fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let _ = fs::write(path, identity.as_bytes());
}
