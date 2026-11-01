//! Purge scheduling and engine maintenance, under the caller's store lock.
//! A checkpoint alone cannot erase fragments in live SQLite pages.
use super::*;
use std::os::fd::AsRawFd;

#[derive(Clone, Copy)]
pub(in super::super) struct PurgePolicy {
    pub(in super::super) deadline: Duration,
    pub(in super::super) work: Duration,
    pub(super) space: fn(&Path) -> Option<u64>,
    /// Hard charged-work ceiling for one save.
    pub(super) save_ceiling: u64,
}
impl Default for PurgePolicy {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(24 * 60 * 60),
            work: Duration::from_secs(2),
            space: free_space,
            save_ceiling: SAVE_CEILING_BYTES,
        }
    }
}

/// Budgets scale with allocated bytes, rounded up to a MiB. VM interruption
/// bounds CPU work; SQLite's busy handler separately bounds lock waits.
pub(super) fn size_budget(bytes: u64, ms_per_mib: u64) -> Duration {
    Duration::from_millis(
        2_000_u64.saturating_add(bytes.div_ceil(1024 * 1024).saturating_mul(ms_per_mib)),
    )
}
fn retry_seconds(failures: u64) -> u64 {
    3600 * (1_u64 << failures.saturating_sub(1).min(2))
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
    pub(super) encoded_bytes_per_save: u64,
    pub(super) dirty_rows_per_save: u64,
    pub(super) max_value_bytes: u64,
    pub(super) record_rows: u64,
    pub(super) file_rows: u64,
    pub(super) records_alarm: bool,
    pub(super) files_alarm: bool,
    pub(super) value_size_alarm: bool,
    db_size_alarm: bool,
    erasure_breaches: u64,
    maintenance_pauses: u64,
    erasure_late_completions: u64,
    erasure_resume_refusals: u64,
    reference_drift: u64,
    reference_check_failed: u64,
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
            if bytes > WAL_ALARM_BYTES && !self.wal_alarm {
                super::super::telemetry::event("wal_size_alarm", &bytes);
            }
            self.wal_alarm |= bytes > WAL_ALARM_BYTES;
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
        self.purge_policy = PurgePolicy {
            deadline,
            work,
            ..self.purge_policy
        };
        Ok(())
    }

    #[cfg(test)]
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
            .and_then(|(logical, file)| logical.max(file).checked_mul(2))
            .and_then(|n| n.checked_add(1024 * 1024 * 1024));
        let available = (self.purge_policy.space)(&self.path);
        self.stats.free_space_required_bytes = required;
        self.stats.free_space_available_bytes = available;
        let admitted = required.zip(available).map(|(r, a)| a >= r);
        self.stats.free_space_admitted = admitted;
        ensure!(admitted == Some(true), "state_v2_vacuum_space");
        // VACUUM may generate a DB-sized WAL. Count it separately from ordinary
        // saves; neither the 64 MiB alarm nor the work budget is a WAL cap.
        let started = Instant::now();
        self.stats.vacuum_attempts = self.stats.vacuum_attempts.saturating_add(1);

        // Interrupted VACUUM restarts from scratch. Increase its work allowance
        // after failures, with a hard pause bound; never loop until it succeeds.
        let failures = self.read_control::<u64>("erasure_failures")?.unwrap_or(0);
        let budget = size_budget(logical.unwrap_or(0), 20)
            .max(self.purge_policy.work)
            .saturating_mul(1_u32 << failures.saturating_sub(1).min(5))
            .min(Duration::from_secs(60));
        let result = limited(self.conn()?, budget, || {
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

    fn logical_bytes(&self) -> Result<u64> {
        let pages: u64 = self
            .conn()?
            .query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let size: u64 = self
            .conn()?
            .query_row("PRAGMA page_size", [], |r| r.get(0))?;
        pages.checked_mul(size).context("state_v2_db_size")
    }
    fn erasure_complete(&mut self, now: u64, covered_epoch: u64) -> Result<()> {
        let mut tx = self.begin(TxnMode::Write)?;
        // Source ownership serializes deletions with VACUUM. Still compare the
        // captured epoch: a future concurrent scheduler may not clear new debt.
        let pending = tx
            .store
            .read_control::<u64>("erasure_pending")?
            .unwrap_or(0);
        for (name, value) in [
            ("erasure_success", now),
            ("erasure_failures", 0),
            ("erasure_purged_epoch", covered_epoch),
            (
                "erasure_pending",
                if pending == covered_epoch { 0 } else { pending },
            ),
        ] {
            tx.put(RowInput {
                value_version: 1,
                key: &RowKey::Meta(name.into()),
                fixed: &Fixed::None,
                value: &control_json(&value)?,
            })?;
        }
        if tx.store.conn()?.execute_batch("COMMIT").is_err() {
            tx.store.reload = true;
            bail!("current_index_requires_reload");
        }
        tx.finished = true;
        Ok(())
    }
    pub(in super::super) fn maintenance(&mut self, idle: bool) -> Result<()> {
        self.maintain(idle.then_some(true), false)
    }
    /// Acquisition yields our connection and transactions at this boundary.
    /// Own work never takes priority over a due privacy maintenance pause.
    pub(in super::super) fn between_cycles(&mut self, quiet: bool) -> Result<()> {
        self.maintain(Some(quiet), false)
    }
    /// A failed idle attempt is debt, not a recovery boundary. Only overdue
    /// startup, a wall/monotonic sleep gap, or recovered space arms recovery.
    pub(in super::super) fn collection_pause_due(&mut self) -> Result<bool> {
        let wall = SystemTime::now();
        let mono = Instant::now();
        let previous = self.last_collection_check.replace((wall, mono));
        if self.read_control::<u64>("erasure_pending")?.unwrap_or(0) == 0 {
            self.recovery_attempts_left = 0;
            return Ok(false);
        }
        let now = wall.duration_since(UNIX_EPOCH)?.as_secs();
        let age = self
            .read_control::<u64>("erasure_since")?
            .and_then(|s| now.checked_sub(s));
        let overdue = age.map_or(true, |a| a >= self.purge_policy.deadline.as_secs());
        let woke = previous.map_or(true, |(old_wall, old_mono)| {
            wall.duration_since(old_wall).map_or(true, |elapsed| {
                elapsed
                    > mono
                        .duration_since(old_mono)
                        .saturating_add(Duration::from_secs(5))
            })
        });
        let recovered_space = self.stats.free_space_admitted == Some(false)
            && self
                .stats
                .free_space_required_bytes
                .zip((self.purge_policy.space)(&self.path))
                .is_some_and(|(required, available)| available >= required);
        if overdue && (woke || recovered_space) {
            // Bound consecutive recovery pauses even if the engine repeatedly
            // times out. Debt/alarm remain until a verified purge completes.
            self.recovery_attempts_left = 2;
            if recovered_space {
                self.stats.free_space_admitted = Some(true);
            }
        }
        let pause_due = age.map_or(true, |a| {
            a >= (self.purge_policy.deadline.as_secs() * 5 / 6).min(20 * 3600)
        });
        Ok(self.recovery_attempts_left > 0 || pause_due && self.purge_retry_due(now, age)?)
    }
    fn purge_retry_due(&self, now: u64, age: Option<u64>) -> Result<bool> {
        let failures = self.read_control::<u64>("erasure_failures")?.unwrap_or(0);
        let remaining = age.and_then(|a| self.purge_policy.deadline.as_secs().checked_sub(a));
        let retry = Duration::from_secs(match remaining {
            Some(remaining) if remaining > 0 => retry_seconds(failures).min((remaining / 2).max(1)),
            _ => retry_seconds(failures).min(300),
        });
        let last = self.read_control::<u64>("erasure_attempt")?;
        let wall_due = last.map_or(true, |s| {
            now.checked_sub(s).is_some_and(|a| a >= retry.as_secs())
        });
        let monotonic_due = self
            .last_purge_attempt
            .map_or(true, |s| s.elapsed() >= retry);
        Ok(wall_due && monotonic_due)
    }
    pub(in super::super) fn before_collection(&mut self) -> Result<()> {
        if !self.collection_pause_due()? {
            return Ok(());
        }
        let recovering = self.recovery_attempts_left > 0;
        self.recovery_attempts_left = self.recovery_attempts_left.saturating_sub(1);
        self.maintain(Some(false), recovering)?;
        if recovering && self.read_control::<u64>("erasure_pending")?.unwrap_or(0) != 0 {
            self.stats.erasure_resume_refusals =
                self.stats.erasure_resume_refusals.saturating_add(1);
            crate::local_resource_diagnostics::claude_state_v2(&self.stats);
            bail!("state_v2_erasure_before_collection");
        }
        Ok(())
    }
    pub(in super::super) fn collection_lock_refused(&mut self, reason: &'static str) {
        let pending = self
            .read_control::<u64>("erasure_pending")
            .ok()
            .flatten()
            .unwrap_or(0)
            != 0;
        let age = self
            .read_control::<u64>("erasure_since")
            .ok()
            .flatten()
            .and_then(|since| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()?
                    .as_secs()
                    .checked_sub(since)
            });
        if pending && age.map_or(true, |age| age >= self.purge_policy.deadline.as_secs()) {
            if !self.stats.erasure_overdue {
                self.stats.erasure_breaches = self.stats.erasure_breaches.saturating_add(1);
                super::super::telemetry::event("erasure_deadline_breach", &1);
            }
            self.stats.erasure_overdue = true;
            self.stats.erasure_resume_refusals =
                self.stats.erasure_resume_refusals.saturating_add(1);
            self.erasure_failed(reason);
            crate::local_resource_diagnostics::claude_state_v2(&self.stats);
        }
    }
    fn maintain(&mut self, window: Option<bool>, resume: bool) -> Result<()> {
        let result = self.maintenance_inner(window, resume);
        self.stats.db_bytes = self
            .logical_bytes()
            .ok()
            .zip(fs::metadata(&self.path).ok())
            .map(|(logical, m)| logical.max(m.len()));
        self.stats.db_size_alarm = self.stats.db_bytes.is_some_and(|n| n > 1_000_000_000);
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
    fn maintenance_inner(&mut self, window: Option<bool>, resume: bool) -> Result<()> {
        migrations::check_current(self.conn()?)?;
        if self.import {
            return Ok(());
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let epoch = self.read_control::<u64>("erasure_pending")?.unwrap_or(0);
        let pending = epoch != 0;
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
        if overdue && !self.stats.erasure_overdue {
            self.stats.erasure_breaches = self.stats.erasure_breaches.saturating_add(1);
            super::super::telemetry::event("erasure_deadline_breach", &1);
        }
        self.stats.erasure_overdue = overdue;
        let failures = self.read_control::<u64>("erasure_failures")?.unwrap_or(0);
        let recovering = resume && overdue;
        let success = self.read_control::<u64>("erasure_success")?;
        let success_due =
            success.map_or(true, |s| now.checked_sub(s).is_some_and(|age| age >= 86400));
        // Ordinary failed idle and overdue attempts retain deadline-aware
        // pacing. Only an actual recovery boundary bypasses that backoff.
        let retry_due = self.purge_retry_due(now, age)?;
        let deadline = self.purge_policy.deadline.as_secs();
        let early = age.map_or(true, |a| a >= (deadline / 2).min(12 * 3600));
        let pause_due = age.map_or(true, |a| a >= (deadline * 5 / 6).min(20 * 3600));
        let idle = window.is_some();
        let opportunity = window
            .is_some_and(|quiet| overdue || recovering || if quiet { early } else { pause_due });
        // Forced pauses override successful-run cadence, never failed-attempt
        // pacing. Genuine recovery gets a bounded immediate attempt budget.
        if pending && opportunity && (recovering || (success_due || pause_due) && retry_due) {
            if window == Some(false) {
                self.stats.maintenance_pauses = self.stats.maintenance_pauses.saturating_add(1);
            }
            self.control("erasure_attempt", &now)?;
            // Crash during work is a failed attempt, with persisted pacing.
            self.control("erasure_failures", &failures.saturating_add(1))?;
            self.last_purge_attempt = Some(Instant::now());
            if let Some(name) = self
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_suffix(".v2.sqlite"))
            {
                if super::super::fence::purge_obsolete_backups(&self.path.with_file_name(name))
                    .is_err()
                {
                    self.erasure_failed("backup_io");
                    return Ok(());
                }
            }
            let result = self.checkpoint(CheckpointMode::Purge);
            if result.state == CheckpointState::Complete {
                // Success and epoch clear are atomic. A crash never grants a
                // false completion; recovery may override normal cadence.
                let completed_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let late = overdue
                    || since
                        .and_then(|s| completed_at.checked_sub(s))
                        .map_or(true, |age| age >= self.purge_policy.deadline.as_secs());
                if late && !self.stats.erasure_overdue {
                    self.stats.erasure_overdue = true;
                    self.stats.erasure_breaches = self.stats.erasure_breaches.saturating_add(1);
                    super::super::telemetry::event("erasure_deadline_breach", &1);
                }
                self.erasure_complete(completed_at, epoch)?;
                self.stats.erasure_vacuum.runs = self.stats.erasure_vacuum.runs.saturating_add(1);
                if late {
                    self.stats.erasure_late_completions =
                        self.stats.erasure_late_completions.saturating_add(1);
                    super::super::telemetry::event("erasure_late_completion_alarm", &1);
                }
                if self.read_control::<u64>("erasure_pending")? == Some(0) {
                    self.stats.erasure_overdue = false;
                    self.stats.erasure_pending_age_s = None;
                    self.stats.oldest_pending_age_s = None;
                }
            }
        } else if pending && idle {
            self.stats.vacuum_deferred = self.stats.vacuum_deferred.saturating_add(1);
        }

        if window == Some(true) {
            let extract = self.references;
            let last = self.read_control::<u64>("reference_check_success")?;
            let attempt = self.read_control::<u64>("reference_check_attempt")?;
            if last.map_or(true, |s| now.checked_sub(s).is_some_and(|age| age >= 86400))
                && attempt.map_or(true, |s| now.checked_sub(s).is_some_and(|age| age >= 3600))
            {
                self.control("reference_check_attempt", &now)?;
                self.conn()?.execute_batch("BEGIN")?;
                let result = limited(self.conn()?, size_budget(self.logical_bytes()?, 10), || {
                    references::verify_counts(self.conn()?, extract)
                });
                self.conn()?.execute_batch("ROLLBACK")?;
                match result {
                    Ok(()) => self.control("reference_check_success", &now)?,
                    Err(error)
                        if error.downcast_ref::<super::super::Hold>()
                            == Some(&super::super::Hold::ReferenceDrift) =>
                    {
                        self.stats.reference_drift = self.stats.reference_drift.saturating_add(1);
                        super::super::telemetry::event("reference_drift", &1);
                        self.control("reference_drift", &1_u64)?;
                        return Err(error);
                    }
                    Err(_) => {
                        self.stats.reference_check_failed =
                            self.stats.reference_check_failed.saturating_add(1);
                    }
                }
            }
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
        let max_wal = self.logical_bytes()?.max(256 * 1024 * 1024);
        ensure!(
            !self.debt
                || pending && self.read_control::<u64>("erasure_attempt")?.is_some()
                || self.wal_bytes().is_some_and(|b| b < max_wal),
            "state_v2_wal_debt"
        );
        Ok(())
    }
}
