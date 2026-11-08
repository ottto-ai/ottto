//! Upload-progress rows in the custody store. Synthetic fixtures, run in CI.
use super::tests::{load_with, save_with, with_session_db, Fixture, G};
use super::*;
use serde_json::{json, Value as Json};

type Page = progress::Page<Json, Json, Json>;

fn page(sessions: &[&str], offset: u64) -> Page {
    progress::Page {
        cache_state: sessions
            .iter()
            .map(|s| (s.to_string(), json!({ "offset": offset })))
            .collect(),
        cache_head: sessions
            .iter()
            .map(|s| (s.to_string(), json!({ "head": s })))
            .collect(),
        ledger: json!({ "schema_version": 1, "offset": offset }),
    }
}
fn commit(
    f: &Fixture,
    index: &ScanIndex,
    expected: u64,
    baseline: Option<progress::Baseline>,
    page: &Page,
) -> Result<progress::Outcome> {
    crate::snapshot_sync::with_state_v2_progress_owner(&f.path, None, |owner, _| {
        commit_progress_locked(&f.path, index, owner, expected, baseline, page)
    })
}
fn control(index: &ScanIndex, name: &str) -> Option<u64> {
    let mut value = None;
    with_session_db(index, |db| value = db.read_control(name).unwrap());
    value
}
fn session_stamp(index: &ScanIndex) -> (u64, u64) {
    let runtime = index.v2().persistence_v2.as_ref().unwrap();
    let guard = runtime.session.lock().unwrap();
    guard.as_ref().unwrap().stamp
}
fn progress_headers(db: &mut sqlite::Sqlite) -> Vec<Header> {
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let mut headers = Vec::new();
    for kind in catalogue::PROGRESS_KINDS {
        headers.extend(
            tx.scan_kind(&RecordKind::parse(kind).unwrap(), None, 128)
                .unwrap(),
        );
    }
    headers
}
fn has_member(db: &mut sqlite::Sqlite, session: &str) -> bool {
    let key = mapper::key("progress.cache_state", session, 1).unwrap();
    db.begin(TxnMode::Read)
        .unwrap()
        .get(&key)
        .unwrap()
        .is_some()
}

/// [behaviour] A progress page advances `progress_generation` alone: G, the
/// session stamp and the capability stamp stay, a stale expected value
/// refuses without a write, removed members owe no erasure, and the graph
/// session saves on afterwards without disturbing the progress rows.
#[test]
fn progress_commit_moves_only_its_own_generation() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let stamp = session_stamp(&index);
    let capability = control(&index, "minimum_writer_capability");
    assert_eq!(capability, Some(sqlite::writer_capability_for_test()));
    let first = commit(&f, &index, 0, None, &page(&["a", "b"], 1)).unwrap();
    let progress::Outcome::Committed(baseline) = first else {
        panic!("the first page commits");
    };
    assert_eq!(baseline.generation, 1);
    assert_eq!(control(&index, "progress_generation"), Some(1));
    assert_eq!(control(&index, "generation"), Some(G));
    assert_eq!(control(&index, "minimum_writer_capability"), capability);
    assert_eq!(session_stamp(&index), stamp);
    with_session_db(&index, |db| assert_eq!(db.stamp().unwrap(), stamp));

    // A stale expected value refuses: no row, no generation, no reload.
    let mut before = Vec::new();
    with_session_db(&index, |db| before = progress_headers(db));
    assert_eq!(
        commit(&f, &index, 0, None, &page(&["c"], 9)).unwrap(),
        progress::Outcome::NotPublished
    );
    assert_eq!(control(&index, "progress_generation"), Some(1));
    with_session_db(&index, |db| {
        assert_eq!(progress_headers(db), before);
        assert!(!db.reload_required());
        // Every graph row would now owe erasure on removal; progress never does.
        db.path_extractor(|_, _, emit| emit("/synthetic/private/path"));
    });
    let erasure = control(&index, "erasure_pending");

    // The next page against the committed baseline removes "a".
    let second = commit(&f, &index, 1, Some(baseline), &page(&["b", "c"], 2)).unwrap();
    let progress::Outcome::Committed(baseline) = second else {
        panic!("the second page commits");
    };
    assert_eq!(baseline.generation, 2);
    assert_eq!(control(&index, "erasure_pending"), erasure);
    with_session_db(&index, |db| {
        assert_eq!(sqlite::erasure_marks_for_test(db), 0);
        assert!(!has_member(db, "a") && has_member(db, "c"));
        before = progress_headers(db);
    });
    assert_eq!(session_stamp(&index), stamp);

    // The graph session is still current: its save commits G+1 and leaves
    // every progress row and the progress generation as they were.
    index.historical_replay_generation = Some("after-progress".into());
    assert!(save_with(&f.path, &mut index).unwrap());
    assert_eq!(index.generation, G + 1);
    assert_eq!(control(&index, "progress_generation"), Some(2));
    with_session_db(&index, |db| assert_eq!(progress_headers(db), before));
}

/// [regress] A COMMIT error reopens and classifies from the progress CAS row,
/// never from the graph's generation.
#[test]
fn progress_commit_error_classifies_from_the_progress_row() {
    let cases: [(Option<(&str, u64)>, DurableCommitOutcome); 4] = [
        (None, DurableCommitOutcome::NotPublished),
        (
            Some(("progress_generation", 1)),
            DurableCommitOutcome::Published(1),
        ),
        (
            Some(("progress_generation", 9)),
            DurableCommitOutcome::Ambiguous,
        ),
        // The graph's row moving says nothing about this commit.
        (
            Some(("generation", G + 1)),
            DurableCommitOutcome::NotPublished,
        ),
    ];
    for (racer, outcome) in cases {
        let f = Fixture::new();
        f.published();
        let index = load_with(&f.path, false).unwrap().unwrap();
        with_session_db(&index, |db| {
            sqlite::fence_commit_writing(db, "progress_generation");
            if let Some((name, value)) = racer {
                sqlite::on_reopen_write_control(name, value);
            }
            let mut tx = db.begin(TxnMode::Write).unwrap();
            mapper::put(
                &mut tx,
                &mapper::key("progress.ledger", "", 1).unwrap(),
                &json!({ "offset": 1 }),
            )
            .unwrap();
            let published = outcome != DurableCommitOutcome::NotPublished;
            assert_eq!(
                tx.commit_inner(sqlite::Cas::Progress {
                    expected: 0,
                    next: 1
                }),
                outcome
            );
            assert_eq!(db.reload_required(), published);
        });
    }
}

/// [behaviour] Progress rows are counted apart from graph records and never
/// trip the records alarm; the graph's catalogue walk seeks past them without
/// reading a header but still walks the kinds on both sides; a progress
/// commit refuses any graph row; and the ledger sizes against VALUE_BYTES.
#[test]
fn progress_rows_stay_out_of_graph_counts_and_walk() {
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&index, |db| {
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
        db.audit_headers().unwrap();
        let (graph, progress, alarm) = sqlite::row_counts_for_test(db);
        assert_eq!((progress, alarm), (0, false));
        // At the alarm threshold, progress rows never trip it.
        sqlite::set_record_rows_for_test(db, 200_000);
        let sessions: Vec<String> = (0..300).map(|n| format!("session-{n:03}")).collect();
        let sessions: Vec<&str> = sessions.iter().map(String::as_str).collect();
        let outcome = progress::commit(db, &identity, G, None, 0, &page(&sessions, 1)).unwrap();
        assert!(matches!(outcome, progress::Outcome::Committed(_)));
        // Members of both maps, their two manifests and the ledger.
        let rows = 2 * 300 + 2 + 1;
        assert_eq!(sqlite::row_counts_for_test(db), (200_000, rows, false));
        db.audit_headers().unwrap();
        assert_eq!(sqlite::row_counts_for_test(db), (graph, rows, false));

        // A progress commit refuses a graph row in its transaction.
        let before = mapper::key("account.current", "before-progress", 1).unwrap();
        let after = mapper::key("proof.owned_start", "after-progress", 1).unwrap();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        mapper::put(&mut tx, &before, &json!({})).unwrap();
        assert_eq!(
            tx.commit_inner(sqlite::Cas::Progress {
                expected: 1,
                next: 2
            }),
            DurableCommitOutcome::NotPublished
        );
        assert_eq!(
            db.read_control::<u64>("progress_generation").unwrap(),
            Some(1)
        );

        // Graph rows on both sides of the range are records; they count.
        sqlite::set_record_rows_for_test(db, 199_999);
        let mut tx = db.begin(TxnMode::Write).unwrap();
        mapper::put(&mut tx, &before, &json!({})).unwrap();
        mapper::put(&mut tx, &after, &json!({})).unwrap();
        assert_eq!(tx.commit(G, G + 1), DurableCommitOutcome::Committed(G + 1));
        assert_eq!(sqlite::row_counts_for_test(db), (200_001, rows, true));
        assert_eq!(
            db.read_control::<u64>("progress_generation").unwrap(),
            Some(1)
        );

        // No progress header is read by the graph walk: damaged ones pass,
        // and the retired rows on both sides are still found.
        assert_eq!(sqlite::corrupt_progress_headers_for_test(db), rows as usize);
        let (_, cx) = kinds::hydrate(db, identity.binding.clone()).unwrap();
        assert!(cx.retired.contains(&before) && cx.retired.contains(&after));
    });
    let ledger = mapper::key("progress.ledger", "", 1).unwrap();
    assert_eq!(value_target(&ledger), VALUE_BYTES);
    let member = mapper::key("progress.cache_state", "session", 1).unwrap();
    assert_eq!(value_target(&member), MUTABLE_VALUE_BYTES);
}
