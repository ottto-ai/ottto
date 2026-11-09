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

/// Rewrite the committed progress rows of the route at `path` through `edit`
/// (cache states, cache heads, ledger), as one more progress page.
pub(crate) fn edit_progress_rows_for_test(
    path: &Path,
    _index: &ScanIndex,
    edit: impl FnOnce(
        &mut BTreeMap<String, serde_json::Value>,
        &mut BTreeMap<String, serde_json::Value>,
        &mut serde_json::Value,
    ),
) {
    crate::snapshot_sync::with_state_v2_progress_owner(path, None, |owner, _| {
        let mut read = progress::read_progress_rows(path, owner)?;
        let mut ledger = read.ledger.expect("the route holds progress rows");
        edit(&mut read.cache_state, &mut read.cache_head, &mut ledger);
        let page = read.rows.commit(
            owner,
            (&read.cache_state, &read.cache_head, &ledger),
            &[] as &[(&str, ())],
        )?;
        assert!(matches!(page, progress::ProgressPage::Committed(_)));
        Ok(())
    })
    .unwrap();
}

/// Overwrite the identity row `name` of the route at `path` with a value no
/// hint decodes from, as one more progress page.
pub(crate) fn damage_identity_row_for_test(path: &Path, name: &str) {
    crate::snapshot_sync::with_state_v2_progress_owner(path, None, |owner, _| {
        let mut read = progress::read_progress_rows(path, owner)?;
        let ledger = read.ledger.expect("the route holds progress rows");
        let damaged = [(name, serde_json::json!({ "damaged": true }))];
        let page = (read.rows).commit(
            owner,
            (&read.cache_state, &read.cache_head, &ledger),
            &damaged,
        )?;
        assert!(matches!(page, progress::ProgressPage::Committed(_)));
        Ok(())
    })
    .unwrap();
}

/// Delete the last chunk row of the committed ledger stream of the route at
/// `path`, its manifest left as it is, as one more progress commit.
pub(crate) fn drop_progress_ledger_chunk_for_test(path: &Path) {
    crate::snapshot_sync::with_state_v2_progress_owner(path, None, |owner, _| {
        with_progress_session(path, owner, |db, identity, graph| {
            let generation = db.read_control::<u64>(progress::GENERATION)?.unwrap_or(0);
            db.validate_save(identity, graph)?;
            let mut tx = db.begin(TxnMode::Write)?;
            let kind = RecordKind::parse("progress.ledger")?;
            let mut last: Option<RowKey> = None;
            while let Some(h) = tx.scan_kind(&kind, last.as_ref(), 1)?.pop() {
                last = Some(h.key);
            }
            mapper::remove(&mut tx, &last.expect("a ledger chunk"))?;
            let next = generation + 1;
            let outcome = tx.commit_inner(sqlite::Cas::Progress {
                expected: generation,
                next,
            });
            assert_eq!(outcome, DurableCommitOutcome::Committed(next));
            Ok(())
        })
    })
    .unwrap();
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
/// Count one page outcome; `None` is a page that must reload.
pub(in super::super) fn count_progress_page_for_test(outcome: Option<&progress::ProgressPage>) {
    PROGRESS_PAGES.with(|pages| {
        let mut counts = pages.get();
        match outcome {
            Some(progress::ProgressPage::Committed(_)) => counts.committed += 1,
            Some(progress::ProgressPage::Unchanged) => counts.unchanged += 1,
            Some(progress::ProgressPage::NotPublished) => counts.not_published += 1,
            None => counts.reload += 1,
        }
        pages.set(counts);
    });
}

/// Keyed progress rows the last load set aside, as `progress_row_set_aside`
/// reported them on this thread.
pub(crate) fn take_progress_set_aside_for_test() -> Option<u64> {
    telemetry::take_thread_event_for_test("progress_row_set_aside").and_then(|v| v.as_u64())
}

/// A claim-only growth save by the pass holding `index`, as it makes before
/// a growth read: under CheckpointLock graph G advances and the pass's claim
/// receipt follows it; no growth row and no progress row changes.
pub(crate) fn claim_growth_for_test(path: &Path, index: &ScanIndex) {
    let key = (index.files.keys().next().cloned())
        .unwrap_or_else(|| "progress-rows-growth-claim".to_owned());
    let _lock = crate::snapshots::CheckpointLock::acquire(path).unwrap();
    let (claimed, _) =
        claim_growth_locked(path, index, index.generation, &key, |_, _, _| true).unwrap();
    assert!(claimed, "the growth claim committed");
    if index.v2().growth_claim_context.is_some() {
        crate::snapshots::sampled_audit::publish_growth_claim_receipt(
            index,
            path,
            index.generation + 1,
        )
        .unwrap();
    }
}

/// Another writer completes the progress import of `json` on `index`'s route,
/// with its own marker, without this process's progress owner.
pub(crate) fn import_progress_rows_for_test(index: &ScanIndex, json: &[u8]) {
    use sha2::Digest;
    type Json = serde_json::Value;
    let runtime = index.v2().persistence_v2.as_ref().expect("a routed index");
    let path = runtime
        .session
        .lock()
        .unwrap()
        .as_ref()
        .expect("a live session")
        .path
        .clone();
    let mut ledger: Json = serde_json::from_slice(json).unwrap();
    let object = ledger.as_object_mut().unwrap();
    let mut map = |name: &str| -> BTreeMap<String, Json> {
        serde_json::from_value(object.remove(name).unwrap_or_default()).unwrap_or_default()
    };
    let (states, heads) = (map("accepted_cache_states"), map("accepted_cache_heads"));
    // Identity hints split into identity rows under their epoch's scope.
    let hints = map("accepted_identity_buckets");
    if let Some(hint) = hints.values().next() {
        object.insert(
            "accepted_identity_scope".into(),
            serde_json::json!({"key_epoch": hint["key_epoch"],
                "discard_before": 0, "retained_before": 0}),
        );
    }
    let mut points = |tx: &mut dyn Transaction, progress_generation: u64| -> Result<bool> {
        for (name, accepted) in &hints {
            let point = serde_json::json!({"progress_generation": progress_generation,
                "accepted": accepted});
            progress::put_point(tx, name, &point)?;
        }
        Ok(!hints.is_empty())
    };
    let generation = object
        .remove("generation")
        .and_then(|g| g.as_u64())
        .unwrap_or(0);
    let marker = progress::Marker {
        sha256: format!("{:x}", sha2::Sha256::digest(json)),
        generation,
    };
    let page = progress::Page {
        cache_state: &states,
        cache_head: &heads,
        ledger: &ledger,
    };
    let imported = progress_session_locked(&path, |db, identity, graph| {
        progress::import(db, identity, graph, &page, &marker, Some(&mut points))
    })
    .unwrap();
    assert!(matches!(imported, progress::Imported::Committed(_)));
}
