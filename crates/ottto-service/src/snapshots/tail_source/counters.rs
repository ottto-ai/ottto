//! The Tail counters: `[since last emit, process total]` per name and label,
//! counts only, carried on the page's `durable_tail_alarm`. They reset at
//! process start and never decide anything.
use std::collections::BTreeMap;

type Counts = BTreeMap<(&'static str, &'static str), [u64; 2]>;

#[cfg(not(test))]
static COUNTS: std::sync::Mutex<Counts> = std::sync::Mutex::new(BTreeMap::new());
#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::RefCell<Counts> = const { std::cell::RefCell::new(BTreeMap::new()) };
}
fn with<R>(visit: impl FnOnce(&mut Counts) -> R) -> R {
    #[cfg(not(test))]
    {
        visit(
            &mut COUNTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
    #[cfg(test)]
    COUNTS.with(|counts| visit(&mut counts.borrow_mut()))
}

pub(in crate::snapshots) fn bump(name: &'static str, label: &'static str) {
    add(name, label, 1);
}

pub(in crate::snapshots) fn add(name: &'static str, label: &'static str, n: u64) {
    with(|counts| {
        for count in counts.entry((name, label)).or_default() {
            *count = count.saturating_add(n);
        }
    });
}

/// A maximum: since the last line, and over the process.
pub(in crate::snapshots) fn max(name: &'static str, label: &'static str, n: u64) {
    with(|counts| {
        for count in counts.entry((name, label)).or_default() {
            *count = (*count).max(n);
        }
    });
}

/// One executed D168 replay on the existing read-cause record: dropped when the
/// replay ends however it ends, so interrupted work counts too. `add` the bytes
/// actually read as they are read; a file's metadata length is not its replay.
/// Ordinary suffix bytes stay ordinary acquisition bytes. It raises no alarm.
#[cfg_attr(not(test), allow(dead_code))] // Held by the group and prefix replays through the shared dispatch.
pub(in crate::snapshots) struct ReplayCharge {
    slug: &'static str,
    cause: super::ReconstructCause,
    bytes: u64,
}
#[cfg_attr(not(test), allow(dead_code))] // Held by the group and prefix replays through the shared dispatch.
impl ReplayCharge {
    pub(in crate::snapshots) fn begin(slug: &'static str, cause: super::ReconstructCause) -> Self {
        Self {
            slug,
            cause,
            bytes: 0,
        }
    }
    pub(in crate::snapshots) fn add(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}
impl Drop for ReplayCharge {
    fn drop(&mut self) {
        let cause = self.cause.label();
        bump("tail_reconstruct", cause);
        add("tail_reconstruct_bytes", cause, self.bytes);
        crate::local_resource_diagnostics::traversal_point(
            "tail_reconstruct",
            self.slug,
            &serde_json::json!({ "cause": cause, "after_head": true, "bytes": self.bytes }),
        );
    }
}

/// At most once per 24 h while reconstructions after a head persist. RAM only:
/// a restart alarms again.
pub(in crate::snapshots) fn restart_full_alarm_due() -> bool {
    const EVERY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
    static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = std::time::Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < EVERY) {
        return false;
    }
    *last = Some(now);
    true
}

#[cfg(not(test))]
static PASSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
thread_local! {
    static PASSES: std::sync::atomic::AtomicU64 = const { std::sync::atomic::AtomicU64::new(0) };
}

/// Claude's passes this process has begun: the unit a wait is counted in.
pub(in crate::snapshots) fn begin_pass() {
    #[cfg(not(test))]
    PASSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    PASSES.with(|passes| passes.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
}

pub(in crate::snapshots) fn pass() -> u64 {
    #[cfg(not(test))]
    {
        PASSES.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    PASSES.with(|passes| passes.load(std::sync::atomic::Ordering::Relaxed))
}

/// This page's line, when anything counted since the last one.
pub(in crate::snapshots) fn emit(source: &str) {
    let line = with(|counts| {
        if counts.values().all(|[since, _]| *since == 0) {
            return None;
        }
        let mut line: BTreeMap<&str, BTreeMap<&str, [u64; 2]>> = BTreeMap::new();
        for ((name, label), count) in counts.iter_mut() {
            line.entry(name).or_default().insert(label, *count);
            count[0] = 0;
        }
        Some(line)
    });
    if let Some(line) = line {
        crate::local_resource_diagnostics::durable_tail_alarm(source, &line);
    }
}

#[cfg(test)]
pub(in crate::snapshots) fn total(name: &'static str, label: &'static str) -> u64 {
    with(|counts| counts.get(&(name, label)).map_or(0, |count| count[1]))
}
