//! The Tail counters: `[since last emit, process total]` per source, name and
//! label, counts only, carried on that source's `durable_tail_alarm`. They
//! reset at process start and never decide anything.
use crate::snapshots::SnapshotSource;
use std::collections::BTreeMap;

/// Keyed by the source's slug, then name and label.
type Counts = BTreeMap<(&'static str, &'static str, &'static str), [u64; 2]>;

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

pub(in crate::snapshots) fn bump(source: SnapshotSource, name: &'static str, label: &'static str) {
    add(source, name, label, 1);
}

pub(in crate::snapshots) fn add(
    source: SnapshotSource,
    name: &'static str,
    label: &'static str,
    n: u64,
) {
    with(|counts| {
        for count in counts.entry((source.api_slug(), name, label)).or_default() {
            *count = count.saturating_add(n);
        }
    });
}

/// One executed D168 replay on the reconstruction counters, with the bytes
/// the replay read. A replay is no failure after a head: it raises no alarm
/// and opens no window. Its bytes are also in the page's
/// `completed_full_native_bytes`, as every Full's.
pub(in crate::snapshots) fn replay(
    source: SnapshotSource,
    cause: super::ReconstructCause,
    bytes: u64,
) {
    let label = cause.label();
    bump(source, "tail_reconstruct", label);
    add(source, "tail_reconstruct_bytes", label, bytes);
}

/// Per source, at most once per 24 h while reconstructions after a head
/// persist. RAM only: a restart alarms again.
pub(in crate::snapshots) fn restart_full_alarm_due(source: SnapshotSource) -> bool {
    const EVERY: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
    static LAST: std::sync::Mutex<BTreeMap<&'static str, std::time::Instant>> =
        std::sync::Mutex::new(BTreeMap::new());
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = std::time::Instant::now();
    if last
        .get(source.api_slug())
        .is_some_and(|at| now.duration_since(*at) < EVERY)
    {
        return false;
    }
    last.insert(source.api_slug(), now);
    true
}

/// `source`'s line on this page, when anything of it counted since the last.
pub(in crate::snapshots) fn emit(source: SnapshotSource) {
    let line = with(|counts| {
        let mut line: BTreeMap<&str, BTreeMap<&str, [u64; 2]>> = BTreeMap::new();
        let mut changed = false;
        for ((owner, name, label), count) in counts.iter_mut() {
            if *owner != source.api_slug() {
                continue;
            }
            changed |= count[0] != 0;
            line.entry(name).or_default().insert(label, *count);
            count[0] = 0;
        }
        changed.then_some(line)
    });
    if let Some(line) = line {
        crate::local_resource_diagnostics::durable_tail_alarm(source.api_slug(), &line);
    }
}

/// Every process total by name and label, summed over sources.
#[cfg(test)]
pub(in crate::snapshots) fn totals() -> BTreeMap<(&'static str, &'static str), u64> {
    with(|counts| {
        let mut totals = BTreeMap::new();
        for ((_, name, label), count) in counts.iter() {
            *totals.entry((*name, *label)).or_default() += count[1];
        }
        totals
    })
}

/// A process total, summed over sources.
#[cfg(test)]
pub(in crate::snapshots) fn total(name: &'static str, label: &'static str) -> u64 {
    with(|counts| {
        counts
            .iter()
            .filter(|((_, n, l), _)| *n == name && *l == label)
            .map(|(_, count)| count[1])
            .sum()
    })
}
