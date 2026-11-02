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
    with(|counts| {
        for count in counts.entry((name, label)).or_default() {
            *count += 1;
        }
    });
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
