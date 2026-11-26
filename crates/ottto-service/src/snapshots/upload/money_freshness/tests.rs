use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::upload::freshness_debt::tests::Fixture;
use crate::snapshots::walk_idle::{PASS_GAP, WALK_GAP};
use crate::snapshots::*;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// The first pass after the backstop expires arrives within one pass gap.
const LISTING_ALLOWANCE: u64 = PASS_GAP;
/// A slow full walk: its last page still ends inside the alarm window.
const WALK_LAG: u64 = 97 * 60;

#[test]
fn relisting_interval_leaves_margin_in_the_alarm_window() {
    assert_eq!(LISTING_INTERVAL_SECONDS, 3 * 60 * 60);
    const { assert!(2 * LISTING_INTERVAL_SECONDS <= super::ALARM_AFTER) };
    // A change with no hint just after a walk began waits for the backstop,
    // the next listing and one slow walk.
    const { assert!(WALK_GAP + LISTING_ALLOWANCE + WALK_LAG < super::ALARM_AFTER) };
}

fn stamp(path: &Path, at: u64) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(at))
        .unwrap();
}

fn clock(now: u64) {
    crate::snapshots::sampled_scan::set_test_now(Some(now));
}

/// One complete single-page walk that begins at `start` and ends at `end`: its
/// `freshness_alarm` row.
fn walk(f: &mut Fixture, start: u64, end: u64) -> serde_json::Value {
    clock(start);
    f.index.traversal = None;
    ensure_bounded_traversal(
        f.source,
        std::slice::from_ref(&f.root),
        &mut f.index,
        "2026-10-30T00:00:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    alarm_row("walk", || {
        advance_bounded_directory_traversal_with_budget(
            f.source,
            &mut f.index,
            BACKFILL_WINDOW_DAYS,
            64,
            None,
            // The page's carries run before the walk's end is aggregated.
            |_| clock(end),
        );
    })
}

fn failed_pass(f: &Fixture, now: u64) -> serde_json::Value {
    clock(now);
    alarm_row("last_walk", || super::report_failed_pass(f.source))
}

fn alarm_row(basis: &str, run: impl FnOnce()) -> serde_json::Value {
    let ((), rows) = crate::local_resource_diagnostics::capture(run);
    let row = rows.iter().find(|row| row["stage"] == "freshness_alarm");
    let row = row.expect("one row")["counts"].clone();
    assert_eq!(row["basis"], basis);
    row
}

/// Well in the past, so every pinned time stays behind the real clock.
fn base() -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now - 4 * super::ALARM_AFTER
}

/// A change with no hint just after one walk began is listed by the backstop
/// walk, which begins one listing after `WALK_GAP` and runs 97 min: every
/// `walk` row stays under the alarm.
#[test]
fn backstop_walk_rows_stay_under_the_alarm() {
    let mut f = Fixture::new(Source::Claude, "walk-gap-backstop");
    let first = base();
    let row = walk(&mut f, first, first + WALK_LAG);
    assert_eq!(row["alarm"], false, "{row}");
    let changed = f.file("changed.jsonl", 40);
    stamp(&changed, first + 1);
    let backstop = first + WALK_GAP + LISTING_ALLOWANCE;
    let row = walk(&mut f, backstop, backstop + WALK_LAG);
    let debt = &row["debt"];
    assert_eq!(debt["outstanding_files"], 1, "{row}");
    assert_eq!(debt["over_6h_files"], 0);
    assert_eq!(
        debt["oldest_age_s"],
        WALK_GAP + LISTING_ALLOWANCE + WALK_LAG - 1
    );
    assert!(debt["oldest_age_s"].as_u64().unwrap() < super::ALARM_AFTER);
    assert_eq!(debt["last_complete_discovery_at"], backstop);
    assert_eq!(row["alarm"], false);
    crate::snapshots::sampled_scan::set_test_now(None);
    f.close();
}

/// The same change found by a long walk (a busy Codex walk took 148 min)
/// ages past 6 h before that walk's last page, so the walk alarms: a wait the
/// walk gate allows past the window is reported, never shown fresh.
#[test]
fn long_backstop_walk_alarms_past_six_hours() {
    const LONG_WALK: u64 = 148 * 60;
    const { assert!(WALK_GAP + LISTING_ALLOWANCE + LONG_WALK > super::ALARM_AFTER) };
    let mut f = Fixture::new(Source::Claude, "walk-gap-long");
    let first = base();
    let row = walk(&mut f, first, first + LONG_WALK);
    assert_eq!(row["alarm"], false, "{row}");
    let changed = f.file("changed.jsonl", 40);
    stamp(&changed, first + 1);
    let backstop = first + WALK_GAP + LISTING_ALLOWANCE;
    let row = walk(&mut f, backstop, backstop + LONG_WALK);
    let debt = &row["debt"];
    assert_eq!(debt["outstanding_files"], 1, "{row}");
    // Past 6 h only by the walk's end: the alarm reads the end-of-walk age.
    assert_eq!(
        debt["oldest_age_s"],
        WALK_GAP + LISTING_ALLOWANCE + LONG_WALK - 1
    );
    assert_eq!(row["alarm"], true, "{row}");
    crate::snapshots::sampled_scan::set_test_now(None);
    f.close();
}

/// Just before, at and after 6 h, through the real walk end and failed-pass
/// report: a slow listing, a failed listing (the last walk re-aged) and debt
/// that was already old. Only past 6 h alarms; with no walk yet, unknown alarms.
#[test]
fn rows_alarm_only_past_six_hours() {
    for past in [-1_i64, 0, 1] {
        let edge = super::ALARM_AFTER.checked_add_signed(past).unwrap();
        let alarm = past > 0;

        // A slow listing: the walk's own start is its last complete discovery.
        let mut f = Fixture::new(Source::Claude, "walk-gap-slow");
        let start = base();
        let row = walk(&mut f, start, start + edge);
        assert_eq!(row["debt"]["outstanding_files"], 0, "{row}");
        assert_eq!(row["alarm"], alarm, "slow listing {past}: {row}");

        // A failed listing re-ages the last walk.
        let row = walk(&mut f, start, start);
        assert_eq!(row["alarm"], false, "{row}");
        let row = failed_pass(&f, start + edge);
        assert_eq!(row["debt"]["outstanding_files"], 0, "{row}");
        assert_eq!(row["alarm"], alarm, "failed listing {past}: {row}");

        // A restart forgets the last walk: unknown, never fresh.
        super::restart_for_test();
        let row = failed_pass(&f, start);
        assert!(row["debt"].is_null(), "{row}");
        assert_eq!(row["alarm"], true);
        f.close();

        // Debt older than the walk that finds it.
        let mut f = Fixture::new(Source::Claude, "walk-gap-old");
        let start = base();
        let old = f.file("old.jsonl", 40);
        stamp(&old, start - edge);
        let row = walk(&mut f, start, start);
        assert_eq!(row["debt"]["outstanding_files"], 1, "{row}");
        assert_eq!(row["debt"]["over_6h_files"], u64::from(alarm));
        assert_eq!(row["debt"]["oldest_age_s"], edge);
        assert_eq!(row["alarm"], alarm, "old debt {past}: {row}");
        crate::snapshots::sampled_scan::set_test_now(None);
        f.close();
    }
}
