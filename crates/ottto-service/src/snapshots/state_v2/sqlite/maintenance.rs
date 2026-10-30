//! Purge scheduling and engine maintenance, under the caller's store lock.
//! A checkpoint alone cannot erase fragments in live SQLite pages.
use super::*;
use std::os::fd::AsRawFd;

#[derive(Clone, Copy)]
pub(in super::super) struct PurgePolicy {
    pub(in super::super) deadline: Duration,
    pub(in super::super) work: Duration,
}
impl Default for PurgePolicy {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(24 * 60 * 60),
            work: Duration::from_millis(250),
        }
    }
}

/// Private counts/bytes/times only. None means unavailable, never zero.
#[derive(Clone, Default, Debug, Serialize)]
pub(in super::super) struct MaintenanceStats {
    wal_peak_bytes: u64,
    wal_alarm: bool,
    wal_measurement_unavailable: u64,
    vacuum_latency_ms: Option<u64>,
    vacuum_wal_peak_bytes: Option<u64>,
    free_space_available_bytes: Option<u64>,
    free_space_required_bytes: Option<u64>,
    free_space_admitted: Option<bool>,
    erasure_pending_age_s: Option<u64>,
    erasure_overdue: bool,
    pub(super) erasure_pending_marks: u64,
    pub(super) row_write_attempts: u64,
    pub(super) row_delete_attempts: u64,
    erasure_vacuum: ErasureVacuum,
    erasure_vacuum_failed: std::collections::BTreeMap<&'static str, u64>,
    oldest_pending_age_s: Option<u64>,
    vacuum_attempts: u64,
    vacuum_failures: u64,
    vacuum_deferred: u64,
    checkpoint_complete: [u64; 3],
    checkpoint_incomplete: [u64; 3],
    commit_outcomes: [u64; 4],
    commit_latency_us: CommitLatency,
    cache_used_bytes: Option<u64>,
    db_bytes: Option<u64>,
}
#[derive(Clone, Default, Debug, Serialize)]
struct ErasureVacuum {
    runs: u64,
    bytes: u64,
    seconds: f64,
}
#[derive(Clone, Default, Debug, Serialize)]
struct CommitLatency {
    p50: Option<u64>,
    p95: Option<u64>,
    recent_samples: usize,
    #[serde(skip)]
    samples: Vec<u64>,
    #[serde(skip)]
    cursor: usize,
}
impl MaintenanceStats {
    pub(super) fn commit(&mut self, outcome: &DurableCommitOutcome, latency: Option<Duration>) {
        let slot = match outcome {
            DurableCommitOutcome::Committed(_) => 0,
            DurableCommitOutcome::NotPublished => 1,
            DurableCommitOutcome::Published(_) => 2,
            DurableCommitOutcome::Ambiguous => 3,
        };
        self.commit_outcomes[slot] = self.commit_outcomes[slot].saturating_add(1);
        if let Some(us) = latency.and_then(|d| u64::try_from(d.as_micros()).ok()) {
            let h = &mut self.commit_latency_us;
            if h.samples.len() < 128 {
                h.samples.push(us);
            } else {
                h.samples[h.cursor] = us;
            }
            h.cursor = (h.cursor + 1) % 128;
            let mut sorted = h.samples.clone();
            sorted.sort_unstable();
            h.recent_samples = sorted.len();
            h.p50 = Some(sorted[(sorted.len() * 50).div_ceil(100) - 1]);
            h.p95 = Some(sorted[(sorted.len() * 95).div_ceil(100) - 1]);
        }
    }
    pub(super) fn observe_wal(&mut self, bytes: Option<u64>) {
        if let Some(bytes) = bytes {
            self.wal_peak_bytes = self.wal_peak_bytes.max(bytes);
            self.wal_alarm |= bytes >= WAL_ALARM_BYTES;
        } else {
            self.wal_measurement_unavailable = self.wal_measurement_unavailable.saturating_add(1);
        }
    }
    pub(super) fn checkpoint(&mut self, mode: CheckpointMode, state: CheckpointState) {
        let slot = match mode {
            CheckpointMode::Passive => 0,
            CheckpointMode::Purge => 1,
            CheckpointMode::IdleReclaim => 2,
        };
        let counts = if state == CheckpointState::Complete {
            &mut self.checkpoint_complete
        } else {
            &mut self.checkpoint_incomplete
        };
        counts[slot] = counts[slot].saturating_add(1);
    }
}

/// Interrupt work at VM progress points. Busy waits have their separate 100 ms
/// bound. This is a finite work budget, not a hard wall-clock latency promise.
fn limited<T>(conn: &Connection, work: Duration, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut deadline = Instant::now()
        .checked_add(work)
        .context("state_v2_work_budget")?;
    struct Reset<'a>(&'a Connection);
    impl Drop for Reset<'_> {
        fn drop(&mut self) {
            unsafe {
                rusqlite::ffi::sqlite3_progress_handler(
                    self.0.handle(),
                    0,
                    None,
                    std::ptr::null_mut(),
                );
            }
        }
    }
    unsafe {
        rusqlite::ffi::sqlite3_progress_handler(
            conn.handle(),
            1000,
            Some(progress),
            (&mut deadline as *mut Instant).cast(),
        );
    }
    let _reset = Reset(conn);
    f()
}

fn free_space(path: &Path) -> Option<u64> {
    let file = File::open(path.parent()?).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // fstatvfs initializes the struct only on success; no paths enter gauges.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    u64::try_from(u128::from(stat.f_bavail) * u128::from(stat.f_frsize)).ok()
}

impl Sqlite {
    pub(in super::super) fn set_purge_policy(
        &mut self,
        deadline: Duration,
        work: Duration,
    ) -> Result<()> {
        ensure!(
            !deadline.is_zero() && deadline <= Duration::from_secs(72 * 3600) && !work.is_zero(),
            "state_v2_purge_policy"
        );
        self.purge_policy = PurgePolicy { deadline, work };
        Ok(())
    }

    pub(in super::super) fn maintenance_stats(&self) -> MaintenanceStats {
        self.stats.clone()
    }

    pub(super) fn vacuum(&mut self) -> Result<()> {
        migrations::check_current(self.conn()?)?;
        let started = Instant::now();
        let bytes = fs::metadata(&self.path).ok().map(|m| m.len()).unwrap_or(0);
        let result = self.vacuum_inner();
        self.stats.erasure_vacuum.seconds += started.elapsed().as_secs_f64();
        self.stats.vacuum_latency_ms = u64::try_from(started.elapsed().as_millis()).ok();
        if result.is_ok() {
            self.stats.erasure_vacuum.bytes = self.stats.erasure_vacuum.bytes.saturating_add(bytes);
        }
        if let Err(error) = &result {
            let reason = error
                .downcast_ref::<rusqlite::Error>()
                .and_then(|e| e.sqlite_error_code())
                .map(|code| match code {
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                        "busy"
                    }
                    rusqlite::ErrorCode::OperationInterrupted => "timeout",
                    rusqlite::ErrorCode::DiskFull => "disk_full",
                    _ => "engine",
                })
                .unwrap_or("space_or_io");
            self.erasure_failed(reason);
        }
        result
    }
    pub(super) fn erasure_failed(&mut self, reason: &'static str) {
        let count = self.stats.erasure_vacuum_failed.entry(reason).or_default();
        *count = count.saturating_add(1);
    }
    fn vacuum_inner(&mut self) -> Result<()> {
        ensure!(!self.import, "state_v2_import_purge_refused");
        // Main-file length alone undercounts live pages still in the WAL.
        let logical = (|| -> Result<u64> {
            let conn = self.conn()?;
            let pages: u64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            let size: u64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            pages.checked_mul(size).context("state_v2_vacuum_space")
        })()
        .ok();
        let required = logical
            .zip(fs::metadata(&self.path).ok().map(|m| m.len()))
            .and_then(|(logical, file)| logical.max(file).checked_mul(2));
        let available = free_space(&self.path);
        self.stats.free_space_required_bytes = required;
        self.stats.free_space_available_bytes = available;
        let admitted = required.zip(available).map(|(r, a)| a >= r);
        self.stats.free_space_admitted = admitted;
        ensure!(admitted == Some(true), "state_v2_vacuum_space");
        // VACUUM may generate a DB-sized WAL. Count it separately from ordinary
        // saves; neither the 64 MiB alarm nor the work budget is a WAL cap.
        let started = Instant::now();
        self.stats.vacuum_attempts = self.stats.vacuum_attempts.saturating_add(1);
        self.stats.erasure_vacuum.runs = self.stats.erasure_vacuum.runs.saturating_add(1);
        let result = limited(self.conn()?, self.purge_policy.work, || {
            Ok(self.conn()?.execute_batch("VACUUM")?)
        });
        self.stats.vacuum_latency_ms = u64::try_from(started.elapsed().as_millis()).ok();
        let bytes = self.wal_bytes();
        self.stats.observe_wal(bytes);
        if let Some(bytes) = bytes {
            self.stats.vacuum_wal_peak_bytes =
                Some(self.stats.vacuum_wal_peak_bytes.unwrap_or(0).max(bytes));
        }
        if result.is_err() {
            self.stats.vacuum_failures = self.stats.vacuum_failures.saturating_add(1);
        }
        result
    }

    pub(in super::super) fn maintenance(&mut self, idle: bool) -> Result<()> {
        let result = self.maintenance_inner(idle);
        self.stats.db_bytes = fs::metadata(&self.path).ok().map(|m| m.len());
        self.stats.cache_used_bytes = self.conn().ok().and_then(|conn| {
            let (mut current, mut high) = (0, 0);
            let rc = unsafe {
                rusqlite::ffi::sqlite3_db_status(
                    conn.handle(),
                    rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED,
                    &mut current,
                    &mut high,
                    0,
                )
            };
            if rc == rusqlite::ffi::SQLITE_OK {
                u64::try_from(current).ok()
            } else {
                None
            }
        });
        crate::local_resource_diagnostics::claude_state_v2(&self.stats);
        result
    }
    fn maintenance_inner(&mut self, idle: bool) -> Result<()> {
        migrations::check_current(self.conn()?)?;
        if self.import {
            return Ok(());
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let pending = self.read_control::<u64>("erasure_pending")?.unwrap_or(0) != 0;
        let since = self.read_control::<u64>("erasure_since")?;
        let age = if pending {
            since.and_then(|s| now.checked_sub(s))
        } else {
            None
        };
        self.stats.erasure_pending_age_s = age;
        self.stats.oldest_pending_age_s = age;
        // A missing/future clock cannot establish that the privacy deadline is
        // still open. Keep custody and use the conservative overdue posture.
        let overdue = pending
            && age.map_or(true, |age| {
                Duration::from_secs(age) >= self.purge_policy.deadline
            });
        self.stats.erasure_overdue = overdue;
        let last = self.read_control::<u64>("erasure_attempt")?;
        let wall_due = last.map_or(true, |last| {
            // A clock rollback cannot establish elapsed cooldown across a
            // restart. Keep the obligation/overdue alarm instead of retrying.
            now.checked_sub(last)
                .is_some_and(|age| Duration::from_secs(age) >= self.purge_policy.deadline)
        });
        let monotonic_due = self
            .last_purge_attempt
            .map_or(true, |last| last.elapsed() >= self.purge_policy.deadline);
        let mut erased = !pending;
        if pending && (idle || overdue) && wall_due && monotonic_due {
            // Persist pacing BEFORE starting work. Crash, timeout, low space or
            // busy TRUNCATE retains the original generation and first deadline.
            if self.control("erasure_attempt", &now).is_err() {
                self.reload = true;
                bail!("current_index_requires_reload");
            }
            self.last_purge_attempt = Some(Instant::now());
            let result = self.checkpoint(CheckpointMode::Purge);
            if result.state == CheckpointState::Complete {
                // Only verified VACUUM + zero-length TRUNCATE authorizes this
                // durable N-only clear. A crash before it simply retains debt.
                if self.control("erasure_pending", &0_u64).is_err() {
                    self.reload = true;
                    bail!("current_index_requires_reload");
                }
                erased = true;
                self.stats.erasure_overdue = false;
                self.stats.erasure_pending_age_s = None;
                self.stats.oldest_pending_age_s = None;
            }
        } else if pending && (idle || overdue) {
            self.stats.vacuum_deferred = self.stats.vacuum_deferred.saturating_add(1);
        }

        let bytes = self.wal_bytes();
        self.stats.observe_wal(bytes);
        let required = self.debt || bytes.map_or(true, |bytes| bytes >= WAL_PASSIVE_BYTES);
        if required {
            let result = self.checkpoint(CheckpointMode::Passive);
            self.debt = required && result.state != CheckpointState::Complete;
        }
        if idle {
            let result = self.checkpoint(CheckpointMode::IdleReclaim);
            if result.state == CheckpointState::Complete {
                self.debt = false;
            }
        }
        ensure!(!self.debt, "state_v2_wal_debt");
        ensure!(!overdue || erased, "state_v2_erasure_overdue");
        Ok(())
    }
}
