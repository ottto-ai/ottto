//! Publication evidence is independent of the candidate database. Caller holds
//! CheckpointLock throughout sniff, reconciliation, publication and adoption.
use super::*;
use anyhow::{bail, ensure};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fence {
    schema_version: u32,
    files: BTreeMap<String, serde_json::Value>,
    storage_format: u32,
    generation: u64,
    db_id: String,
    binding: super::super::scan_index_persistence::Binding,
}
impl Fence {
    pub(super) fn new(identity: &Identity) -> Self {
        Self {
            schema_version: 4,
            files: BTreeMap::new(),
            storage_format: 2,
            generation: identity.fence_generation,
            db_id: identity.db_id.clone(),
            binding: identity.binding.clone(),
        }
    }
    fn identity(&self) -> Identity {
        Identity {
            format: FORMAT,
            db_id: self.db_id.clone(),
            binding: self.binding.clone(),
            fence_generation: self.generation,
        }
    }
}

pub(super) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}
pub(super) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn read(path: &Path) -> Result<Option<Fence>> {
    if !exists(path)? {
        return Ok(None);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // A bounded sniff never feeds a large v1 index to serde. Invalid small v1
    // JSON remains v1 containment's decision unless final DB evidence exists.
    if file.metadata()?.len() > 4096 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(None);
    };
    if value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        < 4
        && value
            .get("storage_format")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            < 2
    {
        return Ok(None);
    }
    let fence: Fence = serde_json::from_slice(&bytes).map_err(|_| Hold::Future)?;
    ensure!(
        fence.schema_version == 4
            && fence.storage_format == 2
            && fence.files.is_empty()
            && !fence.db_id.is_empty()
            && fence.db_id.len() <= 256,
        Hold::Future
    );
    Ok(Some(fence))
}

/// None permits v1 only when there is no evidence of publication. `latched`
/// survives all returned publication failures in this process.
pub(super) fn reconcile(
    path: &Path,
    binding: &super::super::scan_index_persistence::Binding,
    latched: bool,
) -> Result<Option<(Identity, PathBuf)>> {
    let final_db = sibling(path, ".v2.sqlite");
    let final_present = exists(&final_db)?;
    let parsed = read(path);
    let fence = match parsed {
        Ok(Some(f)) => f,
        Ok(None) if final_present => return Err(Hold::FenceLost.into()),
        Ok(None) if latched => return Err(Hold::DbUnavailable.into()),
        Ok(None) => return Ok(None),
        Err(_) if final_present => return Err(Hold::FenceLost.into()),
        Err(e) => return Err(e),
    };
    ensure!(fence.binding == *binding, Hold::ForeignBinding);
    let identity = fence.identity();
    if !final_present {
        let import = sibling(path, ".v2.sqlite.import");
        // Probe independently authenticated identity BEFORE rename or RW open.
        sqlite::Sqlite::probe(&import, &identity).map_err(Hold::storage)?;
        fs::rename(&import, &final_db).map_err(|_| Hold::DbUnavailable)?;
        boundary(Boundary::DbRenamed)?;
    }
    // Retry the durability barrier even when a previous attempt's rename
    // succeeded but its directory sync returned an error.
    super::super::sync_checkpoint_parent(path).map_err(|_| Hold::DbUnavailable)?;
    boundary(Boundary::FinalSynced)?;
    Ok(Some((identity, final_db)))
}

/// Safe creation is deliberately shared by fence and preserved-baseline files.
pub(super) fn create_private(path: &Path) -> Result<File> {
    sqlite::private_parent(path)?;
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

pub(super) fn preserve_file(from: &Path, to: &Path) -> Result<u64> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(from)?;
    let before = input.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1 && before.uid() == unsafe { libc::geteuid() },
        "state_v2_unsafe_baseline"
    );
    let mut output = create_private(to)?;
    let bytes = std::io::copy(&mut input, &mut output)?;
    let after = input.metadata()?;
    let named = fs::symlink_metadata(from)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && named.dev() == before.dev()
            && named.ino() == before.ino()
            && bytes == before.len(),
        "state_v2_baseline_changed"
    );
    output.set_permissions(fs::Permissions::from_mode(0o400))?;
    output.sync_all()?;
    super::super::sync_checkpoint_parent(to)?;
    Ok(bytes)
}

/// The importer must finish and fsync baseline + .import BEFORE calling this.
/// Set latch BEFORE the first rename attempt; every subsequent error is a hold.
pub(super) fn publish(path: &Path, identity: &Identity, latch: &mut bool) -> Result<()> {
    let temp = sibling(path, ".v2-fence.tmp");
    let mut file = create_private(&temp)?;
    serde_json::to_writer(&mut file, &Fence::new(identity))?;
    file.flush()?;
    file.sync_all()?;
    *latch = true;
    boundary(Boundary::FenceAttempt)?;
    fs::rename(&temp, path).map_err(|_| Hold::DbUnavailable)?;
    boundary(Boundary::FenceRenamed)?;
    super::super::sync_checkpoint_parent(path).map_err(|_| Hold::DbUnavailable)?;
    boundary(Boundary::FenceSynced)?;
    let pair = reconcile(path, &identity.binding, true)?;
    if pair.is_none() {
        bail!(Hold::DbUnavailable);
    }
    Ok(())
}

/// Only callable after reconcile excludes publication. Never removes a final DB.
pub(super) fn cleanup_unpublished(path: &Path, latched: bool) -> Result<u64> {
    ensure!(
        !latched && !exists(&sibling(path, ".v2.sqlite"))? && read(path)?.is_none(),
        Hold::DbUnavailable
    );
    let mut removed = 0;
    for suffix in [
        ".v2.sqlite.import",
        ".v2.sqlite.import-wal",
        ".v2.sqlite.import-shm",
        ".v2-fence.tmp",
        ".v1-readonly",
        ".v1-readonly.shards",
    ] {
        let artifact = sibling(path, suffix);
        match fs::symlink_metadata(&artifact) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                fs::remove_dir_all(&artifact)?;
                removed += 1;
            }
            Ok(_) => {
                fs::remove_file(&artifact)?;
                removed += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if removed != 0 {
        super::super::sync_checkpoint_parent(path)?;
    }
    Ok(removed)
}

pub(super) fn evidence(path: &Path) -> Result<bool> {
    Ok(exists(&sibling(path, ".v2.sqlite"))? || !matches!(read(path), Ok(None)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Boundary {
    FenceAttempt,
    FenceRenamed,
    FenceSynced,
    DbRenamed,
    FinalSynced,
}
#[cfg(test)]
thread_local! { static FAILURE: std::cell::Cell<Option<Boundary>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(super) fn fail_at(boundary: Boundary) {
    FAILURE.with(|f| f.set(Some(boundary)));
}
fn boundary(point: Boundary) -> Result<()> {
    #[cfg(test)]
    if FAILURE.with(|f| {
        if f.get() == Some(point) {
            f.set(None);
            true
        } else {
            false
        }
    }) {
        bail!(Hold::DbUnavailable);
    }
    let _ = point;
    Ok(())
}
