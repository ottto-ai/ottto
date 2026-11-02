//! Test-only recorder for the ignored ON-proof harness
//! (`restart_restore_real_copy`): per deferral/hold class, how many files
//! were held, served, or left unresolved, and the longest wait in passes; plus
//! count-only completed-read buckets. Inert unless the harness enables it, so
//! other tests never accumulate state here. Output is counts only: keys stay
//! in memory and are never printed.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static ENABLED: AtomicBool = AtomicBool::new(false);
static REC: Mutex<Option<Rec>> = Mutex::new(None);

#[derive(Default)]
struct Class {
    holds: u64,
    hold_events: u64,
    served: u64,
    max_wait_passes: u64,
}

#[derive(Default)]
struct Rec {
    pass: u64,
    /// (key, class) -> pass the hold opened.
    open: BTreeMap<(String, String), u64>,
    classes: BTreeMap<String, Class>,
    /// Native reads completed per key in this arm.
    reads: BTreeMap<String, u64>,
    /// Per lane pass, reset by `row`.
    row_new_holds: BTreeMap<String, u64>,
    row_served: BTreeMap<String, u64>,
    row_reads: BTreeMap<&'static str, BTreeMap<String, [u64; 2]>>,
}

/// Write-side deferrals: a later record write or native read serves them.
fn write_class(class: &str) -> bool {
    class.starts_with("wa.") || class.starts_with("pass_overflow.")
}

fn with(f: impl FnOnce(&mut Rec)) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let mut guard = REC.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(Rec::default));
}

pub(crate) fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// One harness round (every source's pass) is one pass number.
pub(crate) fn next_pass() {
    with(|r| r.pass += 1);
}

/// `key` is deferred or held under `class` this pass; repeats keep the
/// first opening.
pub(crate) fn hold(class: &str, key: &str) {
    with(|r| {
        let pass = r.pass;
        let entry = r.classes.entry(class.to_owned()).or_default();
        entry.hold_events += 1;
        let slot = (key.to_owned(), class.to_owned());
        if !r.open.contains_key(&slot) {
            r.open.insert(slot, pass);
            entry.holds += 1;
            *r.row_new_holds.entry(class.to_owned()).or_default() += 1;
        }
    });
}

fn serve(r: &mut Rec, key: &str, only_write: bool) -> Vec<String> {
    let pass = r.pass;
    let classes: Vec<String> = r
        .open
        .range((key.to_owned(), String::new())..)
        .take_while(|((k, _), _)| k == key)
        .map(|((_, c), _)| c.clone())
        .filter(|c| !only_write || write_class(c))
        .collect();
    for class in &classes {
        let first = r
            .open
            .remove(&(key.to_owned(), class.clone()))
            .unwrap_or(pass);
        let entry = r.classes.entry(class.clone()).or_default();
        entry.served += 1;
        entry.max_wait_passes = entry.max_wait_passes.max(pass - first);
        *r.row_served.entry(class.clone()).or_default() += 1;
    }
    classes
}

/// A durable record was restored for `key`: serves every open hold.
pub(crate) fn restored(key: &str) {
    with(|r| {
        serve(r, key, false);
    });
}

/// A record for `key` was prepared for commit: serves write-side deferrals.
pub(crate) fn written(key: &str) {
    with(|r| {
        serve(r, key, true);
    });
}

/// A native acquisition of `key` completed: serves every open hold, and
/// counts its bytes by read mode, parse reason, nth read of the key in this
/// arm, and the hold class it served.
pub(crate) fn completed(key: &str, mode: &str, reason: &str, native_bytes: u64) {
    with(|r| {
        let nth = r.reads.entry(key.to_owned()).or_default();
        *nth += 1;
        let nth = match *nth {
            1 => "1",
            2 => "2",
            _ => "3+",
        };
        let served = serve(r, key, false);
        let full = mode.starts_with("Full");
        let mut add = |table: &'static str, bucket: String| {
            let cell = r
                .row_reads
                .entry(table)
                .or_default()
                .entry(bucket)
                .or_default();
            cell[0] += 1;
            cell[1] += native_bytes;
        };
        add("by_mode", mode.to_owned());
        if full {
            add("full_by_parse_reason", reason.to_owned());
            add("full_by_nth_read", nth.to_owned());
        }
        add(
            "by_mode_nth_read",
            format!("{}|{nth}", if full { "Full" } else { mode }),
        );
        if served.is_empty() {
            add("by_served_class", "none".to_owned());
        }
        for class in served {
            add("by_served_class", class);
        }
    });
}

/// Per lane pass (reset each call): new holds and serves per class, open
/// holds, and completed-read buckets as `[count, native_bytes]`.
pub(crate) fn row() -> Value {
    let mut out = Value::Null;
    with(|r| {
        out = json!({
            "new_holds": std::mem::take(&mut r.row_new_holds),
            "served": std::mem::take(&mut r.row_served),
            "open_holds": r.open.len(),
            "reads": std::mem::take(&mut r.row_reads),
        });
    });
    out
}

/// End of arm: per class holds (files), hold events, served, unresolved,
/// max_wait_passes (served) and unresolved_max_open_passes.
pub(crate) fn end() -> Value {
    let mut out = Value::Null;
    with(|r| {
        let mut unresolved: BTreeMap<&str, [u64; 2]> = BTreeMap::new();
        for ((_, class), first) in &r.open {
            let cell = unresolved.entry(class.as_str()).or_default();
            cell[0] += 1;
            cell[1] = cell[1].max(r.pass - first);
        }
        let classes: BTreeMap<&str, Value> = r
            .classes
            .iter()
            .map(|(class, c)| {
                let [open, open_max] = unresolved.get(class.as_str()).copied().unwrap_or_default();
                (
                    class.as_str(),
                    json!({"holds": c.holds, "hold_events": c.hold_events, "served": c.served,
                        "unresolved": open, "max_wait_passes": c.max_wait_passes,
                        "unresolved_max_open_passes": open_max}),
                )
            })
            .collect();
        let reread_files = r.reads.values().filter(|n| **n > 1).count();
        out = json!({"passes": r.pass, "classes": classes, "files_read": r.reads.len(),
            "files_read_more_than_once": reread_files});
    });
    out
}
