//! Publication evidence is independent of the candidate database. Caller holds
//! CheckpointLock throughout sniff, reconciliation, publication and adoption.
use super::*;
use anyhow::{bail, ensure, Context};
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Cleanup {
    SourceOnly,
    Unpublished,
    ObsoleteBackup,
}
/// One inventory drives orphan cleanup, explicit erasure and erasure gauges.
/// Publication must be excluded before deleting any unpublished artifact.
pub(super) const ARTIFACTS: &[(&str, Cleanup, Option<&str>)] = &[
    ("", Cleanup::SourceOnly, None),
    (".shards", Cleanup::SourceOnly, None),
    (".v2.sqlite", Cleanup::SourceOnly, None),
    (".v2.sqlite-wal", Cleanup::SourceOnly, None),
    (".v2.sqlite-shm", Cleanup::SourceOnly, None),
    (
        ".v2.sqlite.owner",
        Cleanup::SourceOnly,
        Some("owner_lock_inventory"),
    ),
    // Cleanup-only names: no writer or recovery/adoption path remains.
    (".v2.sqlite.migration-backup", Cleanup::ObsoleteBackup, None),
    (".v2-recovery", Cleanup::ObsoleteBackup, None),
    (
        ".v2.sqlite.import",
        Cleanup::Unpublished,
        Some("import_remnant_inventory"),
    ),
    (".v2.sqlite.import-wal", Cleanup::Unpublished, None),
    (".v2.sqlite.import-shm", Cleanup::Unpublished, None),
    (
        ".v1-readonly",
        Cleanup::Unpublished,
        Some("baseline_inventory"),
    ),
    (".v1-readonly.shards", Cleanup::Unpublished, None),
    (".v2-fence.tmp", Cleanup::Unpublished, None),
    (
        ".v2-ack-receipt",
        Cleanup::SourceOnly,
        Some("ack_receipt_inventory"),
    ),
];

/// Old backup copies still carry private-text debt after their writers are
/// removed. Delete and fsync them before maintenance clears that obligation.
pub(super) fn purge_obsolete_backups(path: &Path) -> Result<()> {
    for (suffix, cleanup, _) in ARTIFACTS {
        if *cleanup == Cleanup::ObsoleteBackup {
            remove_artifact(&sibling(path, suffix))?;
        }
    }
    // Also sync on retry when a prior attempt unlinked a name but its parent
    // fsync failed; absence alone cannot certify that deletion is durable.
    super::super::sync_checkpoint_parent(path)
}

pub(super) fn remove_artifact(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    Ok(true)
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
    let oversized = file.metadata()?.len() > 4096;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if oversized {
        ensure!(!declares_v2(&bytes), Hold::Future);
        return Ok(None);
    }
    let value = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => value,
        Err(_) if declares_v2(&bytes) => return Err(Hold::Future.into()),
        Err(_) => return Ok(None),
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

// A damaged/oversized fence must not become v1 containment just because the
// complete strict parse fails. Published fences put schema_version first.
fn declares_v2(bytes: &[u8]) -> bool {
    struct Hint<'a>(&'a std::cell::Cell<bool>);
    impl<'de> serde::de::Visitor<'de> for Hint<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("index header")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<(), M::Error> {
            while let Some(key) = map.next_key::<String>()? {
                if key == "storage_format" || key == "schema_version" {
                    let first_v2 = if key == "storage_format" { 2 } else { 4 };
                    if map.next_value::<u64>()? >= first_v2 {
                        self.0.set(true);
                        return Ok(());
                    }
                } else {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }
    let claim = std::cell::Cell::new(false);
    let _ = serde::de::Deserializer::deserialize_map(
        &mut serde_json::Deserializer::from_slice(bytes),
        Hint(&claim),
    );
    // end_map may reject an unconsumed suffix. The custody claim survives it.
    claim.get()
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
    }
    // Retry the durability barrier even when a previous attempt's rename
    // succeeded but its directory sync returned an error.
    super::super::sync_checkpoint_parent(path)
        .context("state_v2_fence_sync")
        .map_err(Hold::storage)?;
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
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
    fs::rename(&temp, path).map_err(|_| Hold::DbUnavailable)?;
    super::super::sync_checkpoint_parent(path).map_err(|_| Hold::DbUnavailable)?;
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
    for (suffix, cleanup, _) in ARTIFACTS {
        if *cleanup != Cleanup::SourceOnly && remove_artifact(&sibling(path, suffix))? {
            removed += 1;
        }
    }
    if removed != 0 {
        super::super::sync_checkpoint_parent(path)?;
    }
    Ok(removed)
}

pub(super) fn evidence(path: &Path) -> Result<bool> {
    Ok(exists(&sibling(path, ".v2.sqlite"))? || read(path)?.is_some())
}
