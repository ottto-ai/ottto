//! The per-index checkpoint lock: one flock per scan index, plus the
//! in-process owner registry that gives v2 maintenance the next lock turn.

use crate::snapshots::*;

pub(in crate::snapshots) struct CheckpointLock {
    file: File,
    priority_path: Option<PathBuf>,
    maintenance: bool,
    pub(in crate::snapshots) custody: bool,
}

impl CheckpointLock {
    pub(in crate::snapshots) fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_mode(path, false)
    }
    fn acquire_mode(path: &Path, maintenance: bool) -> Result<Self> {
        Self::acquire_with_custody(path, maintenance, None)
    }
    pub(in crate::snapshots) fn acquire_with_custody(
        path: &Path,
        maintenance: bool,
        custody: Option<bool>,
    ) -> Result<Self> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create checkpoint directory {}", parent.display()))?;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .context("open local snapshot checkpoint lock")?;
        // Custody is the single authority for v2 maintenance priority. Routes
        // the store does not serve keep main's nonblocking flock behavior,
        // including when the v2 checkpoint-owner registry is poisoned.
        // Maintenance already owns a reservation even if its runtime was
        // invalidated while it waited for the previous checkpoint owner.
        let custody = match custody {
            Some(value) => value,
            None => state_v2::published(path)?,
        };
        let priority = maintenance || custody;
        let mut owners = if priority {
            Some(
                checkpoint_owners()
                    .0
                    .lock()
                    .map_err(|_| anyhow::anyhow!("checkpoint_owner_registry"))?,
            )
        } else {
            None
        };
        if !maintenance
            && owners
                .as_ref()
                .is_some_and(|o| o.maintenance.contains(path))
        {
            anyhow::bail!("state_v2_maintenance_pause");
        }
        #[cfg(unix)]
        {
            let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if status != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("local snapshot checkpoint is owned by another daemon");
            }
        }
        if let Some(owners) = owners.as_mut() {
            owners.owned.insert(path.to_owned());
        }
        Ok(Self {
            file,
            priority_path: priority.then(|| path.to_owned()),
            maintenance,
            custody,
        })
    }
}

impl Drop for CheckpointLock {
    fn drop(&mut self) {
        let mut owners = self
            .priority_path
            .as_ref()
            .and_then(|_| checkpoint_owners().0.lock().ok());
        #[cfg(unix)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
        if let (Some(owners), Some(path)) = (owners.as_mut(), self.priority_path.as_ref()) {
            owners.owned.remove(path);
            if self.maintenance {
                owners.maintenance.remove(path);
            }
            checkpoint_owners().1.notify_all();
        }
    }
}

#[derive(Default)]
pub(in crate::snapshots) struct CheckpointOwners {
    owned: BTreeSet<PathBuf>,
    pub(in crate::snapshots) maintenance: BTreeSet<PathBuf>,
}
pub(in crate::snapshots) fn checkpoint_owners(
) -> &'static (Mutex<CheckpointOwners>, std::sync::Condvar) {
    static OWNERS: std::sync::OnceLock<(Mutex<CheckpointOwners>, std::sync::Condvar)> =
        std::sync::OnceLock::new();
    OWNERS.get_or_init(|| {
        (
            Mutex::new(CheckpointOwners::default()),
            std::sync::Condvar::new(),
        )
    })
}
impl CheckpointLock {
    /// Reserve the next lock turn before waiting for this process's owner.
    /// New normal work yields; another process's flock is a counted failure.
    pub(in crate::snapshots) fn acquire_for_maintenance(path: &Path) -> Result<Self> {
        anyhow::ensure!(state_v2::published(path)?, "state_v2_runtime_inactive");
        let registry = checkpoint_owners();
        let mut owners = registry
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("checkpoint_owner_registry"))?;
        anyhow::ensure!(
            owners.maintenance.insert(path.to_owned()),
            "state_v2_own_maintenance_busy"
        );
        registry.1.notify_all();
        struct Reservation<'a>(&'a Path);
        impl Drop for Reservation<'_> {
            fn drop(&mut self) {
                if let Ok(mut owners) = checkpoint_owners().0.lock() {
                    owners.maintenance.remove(self.0);
                    checkpoint_owners().1.notify_all();
                }
            }
        }
        let reservation = Reservation(path);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while owners.owned.contains(path) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                drop(owners);
                anyhow::bail!("state_v2_own_lock_busy");
            }
            owners = registry
                .1
                .wait_timeout(owners, remaining)
                .map_err(|_| anyhow::anyhow!("checkpoint_owner_registry"))?
                .0;
        }
        drop(owners);
        let lock = Self::acquire_mode(path, true)?;
        // The lock's Drop now owns the reservation.
        std::mem::forget(reservation);
        Ok(lock)
    }
}
