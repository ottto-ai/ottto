//! Test-only seams over a route's progress rows: COMMIT faults, direct row
//! edits, import hooks and per-page outcome counts.
use super::*;

/// Make the next progress COMMIT on the live session behind `index` fail with
/// SQLite's own deferred-constraint refusal. With `reopen`, another connection
/// commits `progress_generation` = that value before the finalizer reopens to
/// classify the failed COMMIT.
pub(crate) fn fail_next_progress_commit_for_test(index: &ScanIndex, reopen: Option<u64>) {
    let runtime = index.v2().persistence_v2.as_ref().expect("a routed index");
    let guard = runtime.session.lock().unwrap();
    let session = guard.as_ref().expect("a live session");
    sqlite::fence_commit_writing(&session.db, progress::GENERATION);
    if let Some(value) = reopen {
        sqlite::on_reopen_write_control(progress::GENERATION, value);
    }
}

/// Rewrite the committed progress rows of `index`'s route through `edit`
/// (cache states, cache heads, ledger), as one more progress page.
pub(crate) fn edit_progress_rows_for_test(
    path: &Path,
    index: &ScanIndex,
    edit: impl FnOnce(
        &mut BTreeMap<String, serde_json::Value>,
        &mut BTreeMap<String, serde_json::Value>,
        &mut serde_json::Value,
    ),
) {
    type Json = serde_json::Value;
    let runtime = index.v2().persistence_v2.as_ref().expect("a routed index");
    let (page, baseline) = {
        let mut guard = runtime.session.lock().unwrap();
        let db = &mut guard.as_mut().expect("a live session").db;
        let mut tx = db.begin(TxnMode::Read).unwrap();
        progress::read::<Json, Json, Json>(&mut tx).unwrap()
    };
    let mut page = page.expect("the route holds progress rows");
    edit(
        &mut page.cache_state,
        &mut page.cache_head,
        &mut page.ledger,
    );
    let outcome = crate::snapshot_sync::with_state_v2_progress_owner(path, None, |owner, _| {
        commit_progress_locked(path, index, owner, baseline, &page)
    })
    .unwrap();
    assert!(matches!(outcome, progress::Outcome::Committed(_)));
}

type ProgressImportHook = Box<dyn FnOnce(&ScanIndex)>;
thread_local! {
    static BEFORE_PROGRESS_IMPORT: std::cell::RefCell<Option<ProgressImportHook>> =
        const { std::cell::RefCell::new(None) };
}
/// Run `hook` once on the routed index, just before the next progress import
/// opens its write transaction.
pub(crate) fn before_progress_import_for_test(hook: impl FnOnce(&ScanIndex) + 'static) {
    BEFORE_PROGRESS_IMPORT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}
#[expect(dead_code, reason = "the progress import runs the armed hook")]
pub(in super::super) fn run_before_progress_import(index: &ScanIndex) {
    if let Some(hook) = BEFORE_PROGRESS_IMPORT.with(|slot| slot.borrow_mut().take()) {
        hook(index);
    }
}

/// The next progress COMMIT on the live session behind `index` becomes durable
/// and then reports an error, as a lost COMMIT reply would.
pub(crate) fn lose_next_progress_commit_reply_for_test(index: &ScanIndex) {
    let runtime = index.v2().persistence_v2.as_ref().expect("a routed index");
    let guard = runtime.session.lock().unwrap();
    let session = guard.as_ref().expect("a live session");
    sqlite::lose_next_progress_commit_reply(&session.db);
}

/// How this thread's progress pages ended since the last take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProgressPagesForTest {
    pub(crate) committed: u64,
    pub(crate) unchanged: u64,
    pub(crate) not_published: u64,
    pub(crate) reload: u64,
}
thread_local! {
    static PROGRESS_PAGES: std::cell::Cell<ProgressPagesForTest> =
        const { std::cell::Cell::new(ProgressPagesForTest { committed: 0, unchanged: 0, not_published: 0, reload: 0 }) };
}
pub(crate) fn take_progress_pages_for_test() -> ProgressPagesForTest {
    PROGRESS_PAGES.with(std::cell::Cell::take)
}

/// Keyed progress rows the last load set aside, as `progress_row_set_aside`
/// reported them on this thread.
pub(crate) fn take_progress_set_aside_for_test() -> Option<u64> {
    telemetry::take_thread_event_for_test("progress_row_set_aside").and_then(|v| v.as_u64())
}

/// A claim-only growth save on `index`'s route, as a pass makes before a
/// growth read: graph G advances, progress rows do not.
pub(crate) fn claim_growth_for_test(path: &Path, index: &ScanIndex) {
    let key = index.files.keys().next().expect("an indexed file").clone();
    let debt: crate::snapshots::sampled_audit::GrowthRetention = serde_json::from_value(
        serde_json::json!({"predecessor_size": 1, "last_growth_full_unix": 1}),
    )
    .unwrap();
    let (claimed, _) = claim_growth_locked(path, index, index.generation, &key, |rows, _, _| {
        rows.insert(key.clone(), debt);
        true
    })
    .unwrap();
    assert!(claimed, "the growth claim committed");
}

/// Another writer completes the progress import of `json` on `index`'s route,
/// with its own marker, without this process's progress owner.
pub(crate) fn import_progress_rows_for_test(index: &ScanIndex, json: &[u8]) {
    let _ = (index, json);
    unimplemented!("the progress import is not wired yet")
}
