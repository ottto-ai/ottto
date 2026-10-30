//! Verified rolling recovery custody. Publish a new descriptor before reclaiming
//! any older bundle; explicit erasure removes every generation immediately.
use super::*;
use anyhow::{ensure, Context};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const DESCRIPTOR_LIMIT: u64 = 8 * 1024 * 1024;
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
enum Role {
    Database,
    Wal,
    Fence,
    Receipt,
    Baseline,
    Shard(String),
    Resume(String),
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Artifact {
    role: Role,
    bytes: u64,
    digest: [u8; 32],
    trailer: Option<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    version: u32,
    set: ack::RecoverySet,
    artifacts: Vec<Artifact>,
}
fn root(path: &Path) -> PathBuf {
    fence::sibling(path, ".v2-recovery")
}
fn open(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "state_v2_backup_private"
    );
    Ok(file)
}
fn safe_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 256
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            && name != "."
            && name != "..",
        "state_v2_backup_name"
    );
    Ok(())
}
fn commitment(path: &Path, trailer: Option<[u8; 32]>) -> Result<(u64, [u8; 32])> {
    use std::io::{Seek, SeekFrom};
    let mut file = open(path)?;
    let before = file.metadata()?;
    let length = before.len();
    let mut hash = Sha256::new();
    let mut prefix = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut at = 0_u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        if trailer.is_some() {
            let n_prefix = (length.saturating_sub(32).saturating_sub(at) as usize).min(n);
            prefix.update(&buffer[..n_prefix]);
        }
        at += n as u64;
    }
    if let Some(expected) = trailer {
        ensure!(
            length >= 32 && <[u8; 32]>::from(prefix.finalize()) == expected,
            "state_v2_backup_rec_trailer"
        );
        file.seek(SeekFrom::End(-32))?;
        let mut actual = [0; 32];
        file.read_exact(&mut actual)?;
        ensure!(actual == expected, "state_v2_backup_rec_trailer");
    }
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        at == length
            && before.dev() == named.dev()
            && before.ino() == named.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "state_v2_backup_changed"
    );
    Ok((length, hash.finalize().into()))
}
fn member(dir: &Path, n: usize) -> PathBuf {
    dir.join(format!("{n}.member"))
}
fn check(descriptor: &Descriptor, dir: &Path) -> Result<()> {
    ensure!(
        matches!(descriptor.version, 1 | 2) && descriptor.artifacts.len() <= 65_536,
        "state_v2_backup_version"
    );
    for role in [Role::Database, Role::Fence, Role::Receipt] {
        ensure!(
            descriptor
                .artifacts
                .iter()
                .filter(|a| a.role == role)
                .count()
                == 1,
            "state_v2_backup_members"
        );
    }
    ensure!(
        descriptor
            .artifacts
            .iter()
            .filter(|a| a.role == Role::Wal)
            .count()
            <= 1,
        "state_v2_backup_members"
    );
    let checkpoints = descriptor.set.checkpoints()?;
    let mut names = std::collections::BTreeSet::new();
    for artifact in &descriptor.artifacts {
        let name = match &artifact.role {
            Role::Resume(name) | Role::Shard(name) => Some(name),
            _ => None,
        };
        if let Some(name) = name {
            safe_name(name)?;
            ensure!(
                names.insert((matches!(artifact.role, Role::Resume(_)), name)),
                "state_v2_backup_members"
            );
        }
        if let Role::Resume(name) = &artifact.role {
            ensure!(
                checkpoints
                    .iter()
                    .any(|c| c.record_name == *name && artifact.trailer == Some(c.trailer_digest)),
                "state_v2_backup_members"
            );
        }
    }
    ensure!(
        descriptor
            .artifacts
            .iter()
            .filter(|a| matches!(a.role, Role::Resume(_)))
            .count()
            == checkpoints.len(),
        "state_v2_backup_members"
    );
    for (n, artifact) in descriptor.artifacts.iter().enumerate() {
        ensure!(
            commitment(&member(dir, n), artifact.trailer)? == (artifact.bytes, artifact.digest),
            "state_v2_backup_digest"
        );
    }
    Ok(())
}
/// A failure before pointer publication has no recovery authority. Reclaim
/// only this attempt; once pointer replacement starts its outcome may be durable.
struct PendingBundle {
    dir: PathBuf,
    pointer_started: bool,
}
impl Drop for PendingBundle {
    fn drop(&mut self) {
        if !self.pointer_started && fs::remove_dir_all(&self.dir).is_ok() {
            let _ = super::super::sync_checkpoint_parent(&self.dir);
            telemetry::event("recovery_backup_unpublished_reclaimed", &1);
        }
    }
}
fn reclaim_unpublished(path: &Path) -> Result<()> {
    let parent = root(path);
    let current = active_dir(path)?;
    let current_verified = read(path).is_ok();
    for entry in fs::read_dir(&parent)? {
        let entry = entry?;
        if entry.path() == current {
            continue;
        }
        let name = entry.file_name();
        if name.to_str().is_some_and(|s| s.starts_with("generation-")) {
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "state_v2_backup_private"
            );
            // A damaged pointer/current seal cannot authorize deleting another
            // sealed candidate. Incomplete copies have no descriptor/authority.
            if current_verified || !fence::exists(&entry.path().join("descriptor.json"))? {
                fs::remove_dir_all(entry.path())?;
                telemetry::event("recovery_backup_unpublished_reclaimed", &1);
            }
        }
    }
    super::super::sync_checkpoint_parent(&parent.join("current.json"))
}
/// Called after import close/fsync while checkpoint and progress owners remain
/// held. Descriptor publication is the final fsync; no fence replacement may
/// start until the independently read-back bundle passes verification.
pub(super) fn persist_import(path: &Path, set: ack::RecoverySet) -> Result<()> {
    persist(path, set, &fence::sibling(path, ".v2.sqlite.import"))
}
fn persist(path: &Path, set: ack::RecoverySet, database: &Path) -> Result<()> {
    let parent = root(path);
    if !fence::exists(&parent)? {
        fs::DirBuilder::new().mode(0o700).create(&parent)?;
    }
    check_dir(&parent)?;
    reclaim_unpublished(path)?;
    let name = format!(
        "generation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let dir = parent.join(&name);
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let mut pending = PendingBundle {
        dir: dir.clone(),
        pointer_started: false,
    };
    let mut descriptor = Descriptor {
        version: if database == fence::sibling(path, ".v2.sqlite") {
            2
        } else {
            1
        },
        set,
        artifacts: Vec::new(),
    };
    let mut copy = |role, source: PathBuf, trailer| -> Result<()> {
        let n = descriptor.artifacts.len();
        ensure!(n < 65_536, "state_v2_backup_admission");
        let expected = commitment(&source, trailer)?;
        fence::preserve_file(&source, &member(&dir, n))?;
        ensure!(
            commitment(&member(&dir, n), trailer)? == expected
                && commitment(&source, trailer)? == expected,
            "state_v2_backup_changed"
        );
        descriptor.artifacts.push(Artifact {
            role,
            bytes: expected.0,
            digest: expected.1,
            trailer,
        });
        Ok(())
    };
    copy(Role::Database, database.to_owned(), None)?;
    // The source owner excludes writes through both copies. Retain the exact
    // WAL rather than forcing a TRUNCATE on every ordinary save/recovery.
    if database == fence::sibling(path, ".v2.sqlite") {
        let wal = fence::sibling(path, ".v2.sqlite-wal");
        if fence::exists(&wal)? {
            copy(Role::Wal, wal, None)?;
        }
    }
    copy(Role::Receipt, fence::sibling(path, ".v2-ack-receipt"), None)?;
    let baseline = fence::sibling(path, ".v1-readonly");
    if fence::exists(&baseline)? {
        copy(Role::Baseline, baseline, None)?;
    }
    let shards = fence::sibling(path, ".v1-readonly.shards");
    if fence::exists(&shards)? {
        let m = fs::symlink_metadata(&shards)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.mode() & 0o077 == 0,
            "state_v2_backup_private"
        );
        for entry in fs::read_dir(shards)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("state_v2_backup_name"))?;
            safe_name(&name)?;
            copy(Role::Shard(name), entry.path(), None)?;
        }
    }
    let records = crate::durable_tail_store::store_dir_for_index(path);
    for checkpoint in descriptor.set.checkpoints()? {
        safe_name(&checkpoint.record_name)?;
        copy(
            Role::Resume(checkpoint.record_name.clone()),
            records.join(&checkpoint.record_name),
            Some(checkpoint.trailer_digest),
        )?;
    }
    if database == fence::sibling(path, ".v2.sqlite") {
        // Rolling backup retains the independent witness's exact bytes.
        copy(Role::Fence, path.to_owned(), None)?;
    } else {
        let n = descriptor.artifacts.len();
        let bytes = serde_json::to_vec(&fence::Fence::new(descriptor.set.identity()))?;
        let fence_path = member(&dir, n);
        ottto_core::write_owner_only_file_atomic(&fence_path, &bytes)?;
        let (bytes, digest) = commitment(&fence_path, None)?;
        descriptor.artifacts.push(Artifact {
            role: Role::Fence,
            bytes,
            digest,
            trailer: None,
        });
    }
    let mut encoded = units_spool::Builder::new(DESCRIPTOR_LIMIT)?;
    serde_json::to_writer(&mut encoded, &descriptor)?;
    let encoded = encoded.finish()?;
    let mut bytes = Vec::new();
    encoded.reader().read_to_end(&mut bytes)?;
    let descriptor_path = dir.join("descriptor.json");
    ottto_core::write_owner_only_file_atomic(&descriptor_path, &bytes)?;
    super::super::sync_checkpoint_parent(&descriptor_path)?;
    super::super::sync_checkpoint_parent(&dir)?;
    let readback = read_dir(&dir)?;
    ensure!(readback.set == descriptor.set, "state_v2_backup_descriptor");
    check(&readback, &dir)?;
    // The old CURRENT and all exact .rec/receipt/baseline copies stay valid
    // until the replacement's independent read-back has completed.
    let pointer = parent.join("current.json");
    pending.pointer_started = true;
    ottto_core::write_owner_only_file_atomic(&pointer, &serde_json::to_vec(&name)?)?;
    super::super::sync_checkpoint_parent(&pointer)?;
    ensure!(
        read(path)?.set == descriptor.set,
        "state_v2_backup_descriptor"
    );
    telemetry::event("recovery_backup_verified", &1);
    // Reclaim only after the newer verified bundle is durable. Partial GC is
    // harmless and retried on the next roll; it cannot invalidate CURRENT.
    for entry in fs::read_dir(&parent)? {
        let entry = entry?;
        if entry.file_name() == name.as_str() || entry.file_name() == "current.json" {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "state_v2_backup_private"
        );
        if metadata.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    super::super::sync_checkpoint_parent(&pointer)?;
    telemetry::event("recovery_backup_superseded", &1);
    Ok(())
}
fn check_dir(dir: &Path) -> Result<()> {
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "state_v2_backup_private"
    );
    Ok(())
}
fn active_dir(path: &Path) -> Result<PathBuf> {
    let parent = root(path);
    check_dir(&parent)?;
    let pointer = parent.join("current.json");
    if !fence::exists(&pointer)? {
        return Ok(parent);
    } // sealed-import v1 layout
    let file = open(&pointer)?;
    ensure!(file.metadata()?.len() <= 512, "state_v2_backup_name");
    let name: String = serde_json::from_reader(file.take(513))?;
    safe_name(&name)?;
    Ok(parent.join(name))
}
fn read(path: &Path) -> Result<Descriptor> {
    read_dir(&active_dir(path)?)
}
fn read_dir(dir: &Path) -> Result<Descriptor> {
    check_dir(dir)?;
    let file = open(&dir.join("descriptor.json"))?;
    ensure!(
        file.metadata()?.len() <= DESCRIPTOR_LIMIT,
        "state_v2_backup_admission"
    );
    let descriptor: Descriptor = serde_json::from_reader(file.take(DESCRIPTOR_LIMIT + 1))?;
    check(&descriptor, dir)?;
    Ok(descriptor)
}
/// Caller holds source/checkpoint ownership; progress stays locked from capture
/// through descriptor publication. The exact DB/WAL pair is copied while the
/// same Sqlite owner excludes writes. Failure retains the previous bundle.
pub(super) fn roll(path: &Path, db: &mut sqlite::Sqlite, identity: &Identity) -> Result<()> {
    if !fence::exists(&fence::sibling(path, ".v2-ack-receipt"))? {
        return Ok(());
    }
    crate::snapshot_sync::with_state_v2_progress_lock(path, |progress| {
        let generation = db.stamp()?.0;
        let recovery = ack::ProgressRecovery::for_backup(identity.clone(), generation, path);
        let set = {
            let mut tx = db.begin(TxnMode::Read)?;
            ack::RecoverySet::capture(&mut tx, &recovery, progress)?
        };
        let database = fence::sibling(path, ".v2.sqlite");
        if let Ok(previous) = read(path) {
            if previous.set == set {
                if let Some(artifact) = previous
                    .artifacts
                    .iter()
                    .find(|a| matches!(a.role, Role::Database))
                {
                    if commitment(&database, None)? == (artifact.bytes, artifact.digest)
                        && wal_matches(path, &previous)?
                    {
                        return Ok(());
                    }
                }
            }
        }
        persist(path, set, &database)
    })
}

/// Explicit recovery only: the caller retains source + checkpoint ownership.
/// Refuse an older DB when a newer external receipt cannot be reconciled with
/// this snapshot. Recovery never rewinds progress or synthesizes a missing ACK.
#[allow(dead_code)]
pub(super) fn restore(path: &Path) -> Result<()> {
    let descriptor = read(path)?;
    let binding = super::super::scan_index_integration::scan_index_storage_binding(path)
        .context("state_v2_backup_binding")?;
    ensure!(
        binding == descriptor.set.identity().binding,
        "state_v2_backup_binding"
    );
    crate::snapshot_sync::with_state_v2_progress_lock(path, |progress_path| {
        let receipt = descriptor
            .artifacts
            .iter()
            .position(|a| matches!(a.role, Role::Receipt))
            .context("state_v2_backup_receipt")?;
        descriptor.set.reconcile_receipt_before_restore(
            path,
            progress_path,
            &member(&active_dir(path)?, receipt),
        )?;
        check(&descriptor, &active_dir(path)?)?;
        // Every existing destination must already match. Destructive repair of
        // a differing published pair needs a separately reviewed recovery plan.
        for (n, artifact) in descriptor.artifacts.iter().enumerate() {
            if matches!(artifact.role, Role::Fence) {
                continue;
            }
            let target = destination(path, &artifact.role)?;
            if fence::exists(&target)? {
                ensure!(
                    commitment(&target, artifact.trailer)? == (artifact.bytes, artifact.digest),
                    "state_v2_backup_restore_conflict"
                );
            } else {
                if let Some(parent) = target.parent() {
                    if !parent.exists() {
                        fs::DirBuilder::new().mode(0o700).create(parent)?;
                    }
                }
                fence::preserve_file(&member(&active_dir(path)?, n), &target)?;
            }
            if matches!(artifact.role, Role::Database | Role::Wal) {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
                open(&target)?.sync_all()?;
            }
        }
        // The exact base may expose an older generation until its verified
        // WAL has been restored. Check generation only after completing the
        // pair; newer external receipts were already reconciled/refused above.
        descriptor.set.reconcile_before_restore(
            path,
            progress_path,
            &member(&active_dir(path)?, receipt),
        )?;
        // Independent stored fence bytes are restored last, after every exact
        // member is durable. Never derive a witness from the candidate DB.
        let (n, artifact) = descriptor
            .artifacts
            .iter()
            .enumerate()
            .find(|(_, a)| matches!(a.role, Role::Fence))
            .context("state_v2_backup_fence")?;
        if fence::exists(path)? {
            ensure!(
                commitment(path, None)? == (artifact.bytes, artifact.digest),
                "state_v2_backup_restore_conflict"
            );
        } else {
            fence::preserve_file(&member(&active_dir(path)?, n), path)?;
        }
        super::super::sync_checkpoint_parent(path)?;
        telemetry::event("recovery_backup_restored", &1);
        Ok(())
    })
}
fn destination(path: &Path, role: &Role) -> Result<PathBuf> {
    Ok(match role {
        Role::Database => fence::sibling(path, ".v2.sqlite"),
        Role::Wal => fence::sibling(path, ".v2.sqlite-wal"),
        Role::Fence => path.to_owned(),
        Role::Receipt => fence::sibling(path, ".v2-ack-receipt"),
        Role::Baseline => fence::sibling(path, ".v1-readonly"),
        Role::Shard(name) => {
            safe_name(name)?;
            fence::sibling(path, ".v1-readonly.shards").join(name)
        }
        Role::Resume(name) => {
            safe_name(name)?;
            crate::durable_tail_store::store_dir_for_index(path).join(name)
        }
    })
}
fn wal_matches(path: &Path, descriptor: &Descriptor) -> Result<bool> {
    let wal = fence::sibling(path, ".v2.sqlite-wal");
    match descriptor.artifacts.iter().find(|a| a.role == Role::Wal) {
        Some(a) => Ok(fence::exists(&wal)? && commitment(&wal, None)? == (a.bytes, a.digest)),
        None => Ok(!fence::exists(&wal)? || commitment(&wal, None)?.0 == 0),
    }
}
/// A database-only migration copy is insufficient. Destructive migrations
/// require the independently sealed bundle for this exact current database.
/// A stale bundle cannot authorize a destructive migration.
pub(super) fn require_destructive_backup(database: &Path) -> Result<()> {
    let name = database
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_suffix(".v2.sqlite"))
        .context("state_v2_backup_database_name")?;
    let index = database.with_file_name(name);
    let descriptor = read(&index)?;
    crate::snapshot_sync::with_state_v2_progress_lock(&index, |progress| {
        let receipt = descriptor
            .artifacts
            .iter()
            .position(|a| matches!(a.role, Role::Receipt))
            .context("state_v2_backup_receipt")?;
        descriptor.set.reconcile_before_restore(
            &index,
            progress,
            &member(&active_dir(&index)?, receipt),
        )?;
        let artifact = descriptor
            .artifacts
            .iter()
            .find(|a| matches!(a.role, Role::Database))
            .context("state_v2_backup_database")?;
        ensure!(
            commitment(database, None)? == (artifact.bytes, artifact.digest)
                && wal_matches(&index, &descriptor)?,
            "state_v2_backup_database_changed"
        );
        Ok(())
    })
}

/// Explicit forget/uninstall/source erasure overrides backup protection and
/// removes ALL generations, including interrupted, unpublished replacements.
pub(super) fn erase(path: &Path) -> Result<()> {
    let dir = root(path);
    match fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => fs::remove_dir_all(&dir)?,
        Ok(_) => anyhow::bail!("state_v2_backup_private"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    super::super::sync_checkpoint_parent(&dir)
}

#[cfg(test)]
#[path = "recovery_backup_tests.rs"]
mod tests;
