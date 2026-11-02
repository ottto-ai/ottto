//! The Tail store over the real route: published fixtures, real saves and the
//! real exit guard. Claude and Codex share every path here; none is per source.
use super::super::tail::{
    Change, Collection, CollectionMeta, SetAsideCause, Shape, StagedFile, TailHead,
};
use super::tail_route::{load_tail, retire_tail, set_aside_tail, stage_tail, tail_set_aside};
use super::tests::{load_with, save_with, save_with_mode, with_session_db, Fixture, G};
use super::*;

const FILE: &str = "/synthetic/tail/file.jsonl";
const SIBLING: &str = "/synthetic/tail/z-sibling.jsonl";
/// Larger than one stored fragment, and not zstd-compressible by accident.
const LONG: usize = 17 * 1024 * 1024;
const REVISION: u32 = 1;

fn long_value() -> Vec<u8> {
    (0..LONG).map(|n| (n % 251) as u8).collect()
}
fn meta() -> CollectionMeta {
    CollectionMeta {
        shape: Shape::Slot,
        elements_per_page: 8,
        elements: 24,
    }
}
fn staged(head: &[u8], pages: &[(Collection, u64, &[u8])]) -> StagedFile {
    StagedFile {
        revision: REVISION,
        head: head.to_vec(),
        collections: pages.iter().map(|(c, _, _)| (*c, meta())).collect(),
        pages: pages
            .iter()
            .map(|(c, n, value)| ((*c, *n), value.to_vec()))
            .collect(),
        ..Default::default()
    }
}
type Pages = BTreeMap<(Collection, u64), Vec<u8>>;
fn read(index: &ScanIndex, key: &str) -> Result<(Option<TailHead>, Pages)> {
    let mut pages = Pages::new();
    let head = load_tail(index, key, REVISION, |collection, page, value| {
        pages.insert((collection, page), value);
        Ok(())
    })?;
    Ok((head, pages))
}
fn rows(index: &ScanIndex, kind: &str, key: &str) -> Vec<Header> {
    let mut found = Vec::new();
    with_session_db(index, |db| {
        let kind = RecordKind::parse(kind).unwrap();
        let mut tx = db.begin(TxnMode::Read).unwrap();
        found = tx
            .scan_record_key(&kind, key.as_bytes(), None, 128)
            .unwrap();
    });
    found
}
fn all_tail_rows(index: &ScanIndex, key: &str) -> usize {
    catalogue::TAIL_KINDS
        .iter()
        .map(|kind| rows(index, kind, key).len())
        .sum()
}
fn erasure_marks(index: &ScanIndex) -> u64 {
    let mut marks = 0;
    with_session_db(index, |db| marks = sqlite::erasure_marks_for_test(db));
    marks
}
fn stage_empty(path: &Path) -> bool {
    with_state(path, |state| Ok(state.tail.is_empty())).unwrap()
}
fn progress_row() -> crate::snapshots::ScanIndexEntry {
    serde_json::from_value(serde_json::json!({
        "size_bytes": 4, "modified_unix_seconds": 1,
        "source_file_fingerprint": "a".repeat(64),
        "scan_identity_version": crate::snapshots::LOCAL_SCAN_INDEX_IDENTITY_VERSION
    }))
    .unwrap()
}

/// [behaviour] Heads, pages and fragments roundtrip; only changed rows move, and
/// missing rows refuse instead of reading as a partial state.
#[test]
fn head_pages_and_fragments_roundtrip_and_replace_only_changed_rows() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let long = long_value();
    // A leading zstd magic stays opaque; it must never be expanded as a frame.
    let framed: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3];
    stage_tail(
        &f.path,
        FILE,
        staged(
            &long,
            &[
                (Collection::Responses, 0, b"first"),
                (Collection::Responses, 1, &long),
                (Collection::ToolUses, 0, framed),
            ],
        ),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(stage_empty(&f.path), "a committed save publishes the stage");
    let (head, pages) = read(&index, FILE).unwrap();
    let head = head.unwrap();
    assert_eq!(head.body, long);
    assert_eq!(head.table[&Collection::Responses].pages, 2);
    assert_eq!(head.table[&Collection::Responses].meta, meta());
    assert_eq!(pages[&(Collection::Responses, 0)], b"first");
    assert_eq!(pages[&(Collection::Responses, 1)], long);
    assert_eq!(pages[&(Collection::ToolUses, 0)], framed);
    assert_eq!(rows(&index, "tail.frag", FILE).len(), 4);

    let untouched = rows(&index, "tail.page.responses", FILE)[0].clone();
    let mut change = staged(b"short", &[(Collection::Responses, 1, b"shrunk")]);
    change.obsolete.insert((Collection::ToolUses, 0));
    stage_tail(&f.path, FILE, change).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let (head, pages) = read(&index, FILE).unwrap();
    let head = head.unwrap();
    assert_eq!(head.body, b"short");
    assert_eq!(head.table[&Collection::Responses].pages, 2);
    assert_eq!(head.table[&Collection::ToolUses].pages, 0);
    assert_eq!(pages[&(Collection::Responses, 0)], b"first", "not restated");
    assert_eq!(pages[&(Collection::Responses, 1)], b"shrunk");
    assert_eq!(pages.len(), 2);
    assert_eq!(rows(&index, "tail.frag", FILE).len(), 0);
    assert_eq!(rows(&index, "tail.page.responses", FILE)[0], untouched);

    with_session_db(&index, |db| sqlite::delete_row_for_test(db, &untouched.key));
    let refused = read(&index, FILE).unwrap_err();
    assert_eq!(refused.to_string(), "state_v2_tail_membership");
    assert!(refused.downcast_ref::<Hold>().is_none());
}

/// [behaviour] Graph saves never touch Tail rows or list them; only a removed
/// progress row, an authorised list or a reset deletes them, and those purge.
#[test]
fn graph_saves_keep_tail_rows_until_retire_or_reset_erases_them() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    index.files.insert(FILE.into(), progress_row());
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();
    set_aside_tail(&f.path, SIBLING, SetAsideCause::Encode).unwrap();

    // Claim-only saves share this path and publish nothing.
    save_with_mode(&f.path, &mut index, true, None).unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 0);
    assert!(!stage_empty(&f.path));

    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 2);
    assert_eq!(erasure_marks(&index), 0, "a first write removes nothing");
    let marker = tail_set_aside(&index, SIBLING).unwrap().unwrap();
    assert_eq!(marker.cause, SetAsideCause::Encode);

    // Ordinary, and a partial save's reverted progress: Tail stays. No Tail row
    // is in a baseline, kept or hydrated.
    let mut reverted = progress_row();
    reverted.size_bytes = 2;
    index.files.insert(FILE.into(), reverted);
    save_with(&f.path, &mut index).unwrap();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    save_with(&f.path, &mut index).unwrap();
    with_state(&f.path, |state| {
        let baseline = state.save_digests.as_ref().unwrap();
        assert!(!baseline.rows.keys().any(tail::owned));
        Ok(())
    })
    .unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 2);
    assert_eq!(tail_set_aside(&index, SIBLING).unwrap(), Some(marker));

    // An overwrite of accumulating state owes no purge; a dropped private
    // string and a reset do, even with the same page count.
    let page = |change| StagedFile {
        change,
        ..staged(b"head2", &[(Collection::Responses, 0, b"page2")])
    };
    for (change, marks) in [
        (Change::Ordinary, 0),
        (Change::DropsPrivate, 1),
        (Change::Reset, 1),
    ] {
        stage_tail(&f.path, FILE, page(change)).unwrap();
        save_with(&f.path, &mut index).unwrap();
        assert_eq!(erasure_marks(&index), marks, "{change:?}");
        assert_eq!(all_tail_rows(&index, FILE), 2);
    }

    // A removed progress row retires in its own commit.
    index.files.remove(FILE);
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 0);
    assert_eq!(erasure_marks(&index), 1);

    // Only an authorised list retires a file with no progress row.
    stage_tail(
        &f.path,
        SIBLING,
        staged(b"head", &[(Collection::UsageHours, 7, b"page")]),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, SIBLING), 2);
    assert!(tail_set_aside(&index, SIBLING).unwrap().is_none());
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, SIBLING), 2, "no sweep, no age");
    retire_tail(&f.path, [SIBLING.to_owned()]).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, SIBLING), 0);
    assert_eq!(erasure_marks(&index), 1);
}

/// [behaviour] One bad file rolls back alone: its predecessor stays, the marker
/// and sibling commit and bookkeeping is restored. Retry clears the marker.
#[test]
fn one_bad_file_rolls_back_while_sibling_and_marker_commit() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    stage_tail(
        &f.path,
        FILE,
        staged(b"old", &[(Collection::Responses, 0, b"old")]),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();

    let oversized = vec![1_u8; 4 * 1024 * 1024];
    let bad = || StagedFile {
        change: Change::Reset,
        ..staged(
            b"new",
            &[
                (Collection::Responses, 0, b"new"),
                (Collection::Responses, 1, &oversized),
            ],
        )
    };
    for attempts in 1..=2 {
        with_session_db(&index, |db| sqlite::set_save_ceiling(db, 1024 * 1024));
        stage_tail(&f.path, FILE, bad()).unwrap();
        stage_tail(
            &f.path,
            SIBLING,
            staged(b"sibling", &[(Collection::Requests, 0, b"sibling")]),
        )
        .unwrap();
        save_with(&f.path, &mut index).unwrap();
        let (head, pages) = read(&index, FILE).unwrap();
        assert_eq!(head.unwrap().body, b"old", "the predecessor stays");
        assert_eq!(pages[&(Collection::Responses, 0)], b"old");
        assert_eq!(pages.len(), 1);
        assert_eq!(erasure_marks(&index), 0, "the reset's marks rolled back");
        with_session_db(&index, |db| assert_eq!(db.save_failure(), None));
        let (head, _) = read(&index, SIBLING).unwrap();
        assert_eq!(head.unwrap().body, b"sibling");
        let marker = tail_set_aside(&index, FILE).unwrap().unwrap();
        assert_eq!(
            (marker.cause, marker.attempts),
            (SetAsideCause::Row, attempts)
        );
        assert!(tail_set_aside(&index, SIBLING).unwrap().is_none());
    }

    with_session_db(&index, |db| sqlite::set_save_ceiling(db, u64::MAX));
    stage_tail(&f.path, FILE, bad()).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let (head, pages) = read(&index, FILE).unwrap();
    assert_eq!(head.unwrap().body, b"new");
    assert_eq!(pages[&(Collection::Responses, 1)], oversized);
    assert!(
        tail_set_aside(&index, FILE).unwrap().is_none(),
        "retry clears"
    );
}

/// [behaviour] A full database is no one file's fault: nothing commits.
#[test]
fn systemic_failure_commits_neither_file_nor_marker() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&index, |db| sqlite::cap_pages(db));
    let long = vec![1_u8; 1024 * 1024];
    stage_tail(
        &f.path,
        FILE,
        staged(b"small", &[(Collection::Responses, 0, b"small")]),
    )
    .unwrap();
    stage_tail(
        &f.path,
        SIBLING,
        staged(b"long", &[(Collection::Responses, 0, &long)]),
    )
    .unwrap();
    let error = save_with(&f.path, &mut index).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveFull));
    assert!(!stage_empty(&f.path), "kept for the next save or exit");
    with_state(&f.path, |state| {
        state.tail = Default::default();
        state.save_hold = None;
        Ok(())
    })
    .unwrap();
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(index.generation, G);
    assert_eq!(all_tail_rows(&index, FILE), 0);
    assert_eq!(all_tail_rows(&index, SIBLING), 0);
    assert!(tail_set_aside(&index, SIBLING).unwrap().is_none());
}

/// [format] The exit commit is G to G+1 behind ACK recovery; only that confirmed
/// generation moves the session, so stale siblings refuse and a fresh load reads.
#[test]
fn exit_commit_recovers_receipts_first_and_fences_stale_siblings() {
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false).unwrap().unwrap();
    let mut sibling = load_with(&f.path, false).unwrap().unwrap();
    let recovery =
        super::super::ack::ProgressRecovery::seal_import(f.identity(), G, &f.path, None).unwrap();
    let next = br#"{"generation":1,"accepted":"exact-body"}"#;
    recovery.before_progress_save(None, next).unwrap();
    let progress = f.path.with_file_name(format!(
        "{}-upload-progress.json",
        f.path.file_stem().unwrap().to_str().unwrap()
    ));
    assert!(!progress.exists());
    // The last commit before Tail state: exactly this layout is raised.
    with_session_db(&index, |db| db.control("catalogue_layout", &3_u32).unwrap());
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();

    drop(BaselineRelease::new(&f.path, &index));

    assert_eq!(fs::read(&progress).unwrap(), next, "receipt replayed first");
    assert!(stage_empty(&f.path));
    with_session_db(&index, |db| {
        assert_eq!(db.stamp().unwrap().0, G + 1);
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(4));
        assert_eq!(
            db.read_control::<u64>("minimum_writer_capability").unwrap(),
            Some(3)
        );
    });
    let stale = save_with(&f.path, &mut sibling).unwrap_err();
    assert_eq!(stale.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
    assert!(crate::snapshots::state_v2_side_effect_guard(&f.path, &index)().is_err());
    let reloaded = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(reloaded.generation, G + 1);
    let (head, pages) = read(&reloaded, FILE).unwrap();
    assert_eq!(head.unwrap().body, b"head");
    assert_eq!(pages[&(Collection::Responses, 0)], b"page");

    // A missing receipt holds the write: no Tail row, no generation.
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false).unwrap().unwrap();
    let recovery =
        super::super::ack::ProgressRecovery::seal_import(f.identity(), G, &f.path, None).unwrap();
    recovery.before_progress_save(None, next).unwrap();
    fs::remove_file(fence::sibling(&f.path, ".v2-ack-receipt")).unwrap();
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();
    drop(BaselineRelease::new(&f.path, &index));
    assert!(stage_empty(&f.path), "dropped and counted");
    assert!(telemetry::take_thread_event_for_test("tail_stage_dropped").is_some());
    with_session_db(&index, |db| assert_eq!(db.stamp().unwrap().0, G));
}

/// [format] An unconfirmed exit never adopts a stamp: refused stays G, and a
/// commit that published without confirmation reloads what committed. A store
/// behind the previous layout keeps its layout until a full save fills it in.
#[test]
fn exit_commit_outcomes_reload_and_older_layouts_are_not_raised() {
    for published in [false, true] {
        let f = Fixture::new();
        f.published();
        let index = load_with(&f.path, false).unwrap().unwrap();
        if published {
            kinds::FAIL_DIGEST_PROMOTION.with(|fail| fail.set(true));
        } else {
            with_session_db(&index, |db| sqlite::fence_commit_writing(db, "generation"));
        }
        stage_tail(
            &f.path,
            FILE,
            staged(b"head", &[(Collection::Responses, 0, b"page")]),
        )
        .unwrap();
        drop(BaselineRelease::new(&f.path, &index));
        assert!(stage_empty(&f.path));
        assert!(crate::snapshots::state_v2_side_effect_guard(&f.path, &index)().is_err());
        let reloaded = load_with(&f.path, false).unwrap().unwrap();
        assert_eq!(reloaded.generation, G + u64::from(published));
        assert_eq!(read(&reloaded, FILE).unwrap().0.is_some(), published);
    }

    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&index, |db| db.control("catalogue_layout", &2_u32).unwrap());
    stage_tail(&f.path, FILE, staged(b"head", &[])).unwrap();
    drop(BaselineRelease::new(&f.path, &index));
    let mut reloaded = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&reloaded, |db| {
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(2));
    });
    assert!(read(&reloaded, FILE).unwrap().0.is_some());
    save_with(&f.path, &mut reloaded).unwrap();
    with_session_db(&reloaded, |db| {
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(4));
    });
}

/// [format] A future revision and a newer writer hold, and are never a Full;
/// the reader decides what an older revision means.
#[test]
fn future_revision_and_newer_writer_hold() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let mut file = staged(b"head", &[(Collection::Responses, 0, b"page")]);
    file.revision = REVISION + 1;
    stage_tail(&f.path, FILE, file).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let error = read(&index, FILE).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future));
    let head = load_tail(&index, FILE, REVISION + 2, |_, _, _| Ok(()));
    assert_eq!(head.unwrap().unwrap().revision, REVISION + 1);

    with_session_db(&index, sqlite::future_writer_for_test);
    stage_tail(&f.path, FILE, staged(b"newer", &[])).unwrap();
    drop(BaselineRelease::new(&f.path, &index));
    assert!(telemetry::take_thread_event_for_test("tail_stage_dropped").is_some());
    let error = load_with(&f.path, false).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::NewerSchema));
}

/// A published store whose head, page and live WAL hold these literals in the
/// clear. The returned session keeps them there and erases them when dropped.
pub(crate) fn seed_tail_literals_for_test(
    support: &Path,
    literal: &str,
) -> super::super::money_test_support::ColdSession {
    let (session, mut index) = super::super::money_test_support::ColdSession::publish(
        super::super::super::scan_index_persistence::Source::Claude,
        &ScanIndex::default(),
        &support.canonicalize().unwrap(),
    );
    let path = session.path().to_owned();
    let (label, private) = (format!("{literal}-L"), format!("{literal}-PL"));
    stage_tail(
        &path,
        FILE,
        staged(
            label.as_bytes(),
            &[(Collection::ToolUses, 0, private.as_bytes())],
        ),
    )
    .unwrap();
    save_locked(&path, &mut index, false, None, true).unwrap();
    let wal = fs::read(sqlite::sidecar(
        &fence::sibling(&path, ".v2.sqlite"),
        "-wal",
    ))
    .unwrap();
    for needle in [&label, &private] {
        assert!(
            wal.windows(needle.len()).any(|b| b == needle.as_bytes()),
            "positive control: the literal is stored in the clear"
        );
    }
    let (head, _) = read(&index, FILE).unwrap();
    assert!(head.is_some());
    session
}
/// Stage one synthetic file for this route's next full save.
pub(crate) fn stage_tail_for_test(path: &Path) {
    stage_tail(
        path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();
}
pub(crate) fn tail_published_for_test(index: &ScanIndex) -> bool {
    read(index, FILE).is_ok_and(|(head, _)| head.is_some())
}
