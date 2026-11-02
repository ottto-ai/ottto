//! The Tail store over the real route: published fixtures, real saves and the
//! real exit guard. Claude and Codex share every path here; none is per source.
use super::super::tail::{
    Change, Collection, CollectionMeta, Common, DebtSummary, Disposition, InventoryFacts,
    Observation, Representation, SetAsideCause, Shape, StagedFile, TailHead,
};
use super::tail_route::{
    dispose_tail, erase_tail, load_head, load_revisions, load_tail, observe_tail, retire_tail,
    set_aside_tail, stage_tail, tail_head_keys, tail_set_aside,
};
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
    let Some(head) = load_head(index, key, REVISION)? else {
        return Ok((None, pages));
    };
    load_tail(index, key, &head, |collection, page, value| {
        pages.insert((collection, page), value);
        Ok(())
    })?;
    Ok((Some(head), pages))
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
/// Fragments are addressed by file digest: every one in the store.
fn frag_rows(index: &ScanIndex) -> usize {
    let mut found = 0;
    with_session_db(index, |db| {
        let kind = RecordKind::parse("tail.frag").unwrap();
        let mut tx = db.begin(TxnMode::Read).unwrap();
        found = tx.scan_kind(&kind, None, 128).unwrap().len();
    });
    found
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
    assert_eq!(frag_rows(&index), 4);

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
    assert_eq!(frag_rows(&index), 0);
    assert_eq!(rows(&index, "tail.page.responses", FILE)[0], untouched);

    with_session_db(&index, |db| sqlite::delete_row_for_test(db, &untouched.key));
    let refused = read(&index, FILE).err().unwrap();
    assert_eq!(refused.to_string(), "state_v2_tail_membership");
    assert!(refused.downcast_ref::<Hold>().is_none());

    // Any page number addresses its fragments; a retired file takes only its own.
    let far = 1_u64 << 40;
    let reset = StagedFile {
        change: Change::Reset,
        ..staged(b"head", &[(Collection::Responses, 0, &long)])
    };
    stage_tail(&f.path, FILE, reset).unwrap();
    stage_tail(
        &f.path,
        SIBLING,
        staged(&long, &[(Collection::Requests, far, &long)]),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(frag_rows(&index), 6);
    retire_tail(&f.path, [FILE.to_owned()]).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(frag_rows(&index), 4);
    assert!(read(&index, FILE).unwrap().0.is_none());
    let (head, pages) = read(&index, SIBLING).unwrap();
    assert_eq!(head.unwrap().body, long);
    assert_eq!(pages[&(Collection::Requests, far)], long);
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

fn usage_family() -> crate::snapshots::ClaudeUsageFamilyPending {
    crate::snapshots::ClaudeUsageFamilyPending {
        census_window_end: "2026-11-02T00:00:00Z".into(),
        member_request_id_hashes: BTreeMap::from([(
            "family".into(),
            std::collections::BTreeSet::from(["c".repeat(64)]),
        )]),
        member_occurrences: BTreeMap::new(),
        invalid: false,
        idless_revision: None,
        identity_contract: None,
        contract_unproven: false,
    }
}

/// [behaviour] One bad file rolls back alone with its own graph rows: its
/// predecessor stays, while its marker, a sibling and shared rows commit and the
/// route reloads. Hydrate accepts the shared rows ahead of the file's; the retry
/// merges them idempotently and clears the marker.
#[test]
fn one_file_closure_rolls_back_alone_and_the_route_reloads() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    index.files.insert(FILE.into(), progress_row());
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
    // The file's rows change and gain a member; a sibling's and shared rows too.
    let advance = |index: &mut ScanIndex| {
        let mut grown = progress_row();
        grown.size_bytes = 8;
        index.files.insert(FILE.into(), grown);
        index.confirmed_empty_files.insert(FILE.into());
        index.files.insert(SIBLING.into(), progress_row());
        index.accepted_snapshot_fingerprints.insert("b".repeat(64));
        index
            .claude_usage_family_pending
            .add("family".into(), usage_family());
    };
    let shared_committed = |index: &ScanIndex| {
        assert!(index.files.get(SIBLING).is_some());
        assert!(index
            .accepted_snapshot_fingerprints
            .contains(&"b".repeat(64)));
        let family = index.claude_usage_family_pending.view("family");
        assert_eq!(family.map(|family| family.hash_member_count()), Some(1));
    };
    for attempts in 1..=2 {
        with_session_db(&index, |db| sqlite::set_save_ceiling(db, 1024 * 1024));
        advance(&mut index);
        stage_tail(&f.path, FILE, bad()).unwrap();
        stage_tail(
            &f.path,
            SIBLING,
            staged(b"sibling", &[(Collection::Requests, 0, b"sibling")]),
        )
        .unwrap();
        let reload = save_with(&f.path, &mut index).unwrap_err();
        assert_eq!(reload.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
        assert!(stage_empty(&f.path), "the commit published the stage");

        index = load_with(&f.path, false).unwrap().unwrap();
        assert_eq!(index.files.get(FILE).unwrap().size_bytes, 4);
        assert!(!index.confirmed_empty_files.contains(FILE), "counted out");
        shared_committed(&index);
        let (head, pages) = read(&index, FILE).unwrap();
        assert_eq!(head.unwrap().body, b"old", "the predecessor stays");
        assert_eq!(pages[&(Collection::Responses, 0)], b"old");
        assert_eq!(pages.len(), 1);
        assert_eq!(erasure_marks(&index), 0, "the reset's marks rolled back");
        let (head, _) = read(&index, SIBLING).unwrap();
        assert_eq!(head.unwrap().body, b"sibling");
        let marker = tail_set_aside(&index, FILE).unwrap().unwrap();
        assert_eq!(
            (marker.cause, marker.attempts),
            (SetAsideCause::Row, attempts)
        );
        assert!(tail_set_aside(&index, SIBLING).unwrap().is_none());
    }

    advance(&mut index);
    stage_tail(&f.path, FILE, bad()).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(index.files.get(FILE).unwrap().size_bytes, 8);
    assert!(index.confirmed_empty_files.contains(FILE));
    shared_committed(&index);
    let (head, pages) = read(&index, FILE).unwrap();
    assert_eq!(head.unwrap().body, b"new");
    assert_eq!(pages[&(Collection::Responses, 1)], oversized);
    assert!(
        tail_set_aside(&index, FILE).unwrap().is_none(),
        "retry clears"
    );
}

/// [behaviour] A retire drops the key's pending stage, and a later reset
/// cancels the retire, so the same save keeps the fresh head.
#[test]
fn retire_drops_pending_stage_and_reset_cancels_retire() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();

    retire_tail(&f.path, [FILE.to_owned()]).unwrap();
    let reset = StagedFile {
        change: Change::Reset,
        ..staged(b"fresh", &[(Collection::Requests, 0, b"fresh")])
    };
    stage_tail(&f.path, FILE, reset).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let (head, pages) = read(&index, FILE).unwrap();
    assert_eq!(head.unwrap().body, b"fresh");
    assert_eq!(
        pages,
        Pages::from([((Collection::Requests, 0), b"fresh".to_vec())])
    );

    stage_tail(
        &f.path,
        FILE,
        staged(b"stale", &[(Collection::Responses, 1, b"stale")]),
    )
    .unwrap();
    retire_tail(&f.path, [FILE.to_owned()]).unwrap();
    let files = with_state(&f.path, |state| Ok(state.tail.files())).unwrap();
    assert_eq!(files, 0, "the stale stage went");
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 0);
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

    // The owner's drop alone never writes: discarded, counted, G unchanged.
    drop(BaselineRelease::new(&f.path, &index));
    assert!(stage_empty(&f.path));
    assert!(telemetry::take_thread_event_for_test("tail_stage_dropped").is_some());
    assert!(!progress.exists());
    with_session_db(&index, |db| assert_eq!(db.stamp().unwrap().0, G));
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();

    BaselineRelease::new(&f.path, &index).commit_tail().unwrap();

    assert_eq!(fs::read(&progress).unwrap(), next, "receipt replayed first");
    assert!(stage_empty(&f.path));
    with_session_db(&index, |db| {
        assert_eq!(db.stamp().unwrap().0, G + 1);
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(4));
        assert_eq!(
            db.read_control::<u64>("minimum_writer_capability").unwrap(),
            Some(4)
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
    let release = BaselineRelease::new(&f.path, &index);
    assert!(release.commit_tail().is_err());
    assert!(!stage_empty(&f.path), "the owner's drop decides");
    drop(release);
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
        let release = BaselineRelease::new(&f.path, &index);
        assert!(release.commit_tail().is_err());
        drop(release);
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
    BaselineRelease::new(&f.path, &index).commit_tail().unwrap();
    let mut reloaded = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&reloaded, |db| {
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(2));
    });
    assert!(read(&reloaded, FILE).unwrap().0.is_some());
    save_with(&f.path, &mut reloaded).unwrap();
    with_session_db(&reloaded, |db| {
        assert_eq!(
            db.read_control::<u32>("catalogue_layout").unwrap(),
            Some(catalogue::LAYOUT)
        );
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
    let error = read(&index, FILE).err().unwrap();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future));
    let head = load_head(&index, FILE, REVISION + 2);
    assert_eq!(head.unwrap().unwrap().revision, REVISION + 1);

    with_session_db(&index, sqlite::future_writer_for_test);
    stage_tail(&f.path, FILE, staged(b"newer", &[])).unwrap();
    let release = BaselineRelease::new(&f.path, &index);
    assert!(release.commit_tail().is_err());
    drop(release);
    assert!(telemetry::take_thread_event_for_test("tail_stage_dropped").is_some());
    let error = load_with(&f.path, false).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::NewerSchema));
}

/// [behaviour] The source-facing reads: a head without its pages, pages streamed
/// and bound to that head's generation, and exactly the committed head keys. A
/// bootstrap reset owes no purge, and each late kind roundtrips.
#[test]
fn split_reads_head_keys_late_kinds_and_bootstrap_reset() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    assert!(tail_head_keys(&index).unwrap().is_empty());
    let kinds = [
        Collection::PiUsageKeys,
        Collection::CodexActiveTurns,
        Collection::CodexOpenCalls,
        Collection::CodexNameCounts,
        Collection::SessionFacts,
    ];
    let pages = kinds.map(|collection| (collection, 0, b"page".as_slice()));
    let reset = StagedFile {
        change: Change::Reset,
        ..staged(b"head", &pages)
    };
    stage_tail(&f.path, FILE, reset).unwrap();
    stage_tail(&f.path, SIBLING, staged(b"sibling", &[])).unwrap();
    set_aside_tail(
        &f.path,
        "/synthetic/tail/headless.jsonl",
        SetAsideCause::Encode,
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(erasure_marks(&index), 0, "nothing prior to purge");
    assert_eq!(
        tail_head_keys(&index).unwrap(),
        std::collections::BTreeSet::from([FILE.to_owned(), SIBLING.to_owned()])
    );

    let head = load_head(&index, FILE, REVISION).unwrap().unwrap();
    let mut seen = Vec::new();
    load_tail(&index, FILE, &head, |collection, page, value| {
        seen.push((collection, page, value));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        seen,
        kinds.map(|collection| (collection, 0, b"page".to_vec()))
    );
    let mut visits = 0;
    let stopped = load_tail(&index, FILE, &head, |_, _, _| {
        visits += 1;
        Err(anyhow::anyhow!("stop"))
    });
    assert_eq!(stopped.unwrap_err().to_string(), "stop");
    assert_eq!(visits, 1, "pages arrive one at a time");

    // A missing page fails only the page phase: the head never visited it.
    let page = rows(&index, "tail.page.pi_usage_keys", FILE)[0].clone();
    with_session_db(&index, |db| sqlite::delete_row_for_test(db, &page.key));
    let again = load_head(&index, FILE, REVISION).unwrap().unwrap();
    assert_eq!(again.table[&Collection::PiUsageKeys].pages, 1);
    let refused = load_tail(&index, FILE, &again, |_, _, _| Ok(()));
    assert_eq!(refused.unwrap_err().to_string(), "state_v2_tail_membership");

    // Pages never pair with a head from another generation.
    stage_tail(&f.path, SIBLING, staged(b"sibling2", &[])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let mut visits = 0;
    let stale = load_tail(&index, FILE, &head, |_, _, _| {
        visits += 1;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(stale.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
    assert_eq!(visits, 0);

    // A long fact fragments, and its owner sorts after the revisions': a retire
    // that keeps the debt still takes the fact's fragments and only those.
    let long = long_value();
    let reset = StagedFile {
        change: Change::Reset,
        ..staged(b"head", &[(Collection::SessionFacts, 0, &long)])
    };
    stage_tail(&f.path, FILE, reset).unwrap();
    observe_tail(&f.path, FILE, observation(&[long.as_slice()])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(frag_rows(&index), 4);
    let (_, pages) = read(&index, FILE).unwrap();
    assert_eq!(pages[&(Collection::SessionFacts, 0)], long);
    retire_tail(&f.path, [FILE.to_owned()]).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(rows(&index, "tail.page.session_facts", FILE).is_empty());
    assert_eq!(frag_rows(&index), 2, "only the kept revision's fragments");
    assert_eq!(revisions(&index, FILE)[&0], long);
}

fn revisions(index: &ScanIndex, key: &str) -> BTreeMap<u64, Vec<u8>> {
    let head = load_head(index, key, REVISION).unwrap().unwrap();
    let mut found = BTreeMap::new();
    load_revisions(index, key, &head, |id, value| {
        found.insert(id, value);
        Ok(())
    })
    .unwrap();
    found
}
fn observation(added: &[&[u8]]) -> Observation {
    Observation {
        summary: DebtSummary {
            earliest_unacked_change_at: Some(7_000),
            lower_bound: true,
            reason_bits: 0b101,
            disposition: None,
        },
        added: added.iter().map(|value| value.to_vec()).collect(),
        ..Default::default()
    }
}

/// [format] A layout-4 store: a Tail-only exit commit, debt included, never
/// stamps layout 5; the next full save upgrades it with the new roots. The first
/// commit fences capability-3 writers out.
#[test]
fn layout_four_store_exit_keeps_four_and_full_save_upgrades_to_five() {
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false).unwrap().unwrap();
    let new_roots: Vec<RowKey> = catalogue::LAYOUTS
        .iter()
        .filter(|(_, _, layout)| *layout == 5)
        .map(|(kind, _, _)| mapper::key(kind, "", 0).unwrap())
        .collect();
    assert_eq!(new_roots.len(), 2);
    with_session_db(&index, |db| {
        for key in &new_roots {
            sqlite::delete_row_for_test(db, key);
        }
        db.control("catalogue_layout", &4_u32).unwrap();
    });
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert!(index.claude_folder_login_ledger.is_empty());
    assert_eq!(index.tail_discovery, Default::default());
    stage_tail(&f.path, FILE, staged(b"head", &[])).unwrap();
    observe_tail(&f.path, FILE, observation(&[b"debt"])).unwrap();
    BaselineRelease::new(&f.path, &index).commit_tail().unwrap();
    let mut reloaded = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&reloaded, |db| {
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(4));
        // Capability 3 refuses any store whose minimum is above it.
        assert_eq!(
            db.read_control::<u64>("minimum_writer_capability").unwrap(),
            Some(4)
        );
    });
    assert_eq!(revisions(&reloaded, FILE).len(), 1);
    save_with(&f.path, &mut reloaded).unwrap();
    with_session_db(&reloaded, |db| {
        assert_eq!(db.read_control::<u32>("catalogue_layout").unwrap(), Some(5));
        let mut tx = db.begin(TxnMode::Read).unwrap();
        for key in &new_roots {
            assert!(tx.get(key).unwrap().is_some(), "{key:?}");
        }
    });
}

/// [behaviour] Debt outlives its reduction: observations never clear the marker;
/// reset merges committed debt; retire keeps it under a metadata-only head that
/// never loads pages; disposal leaves nothing. A future envelope holds.
#[test]
fn debt_survives_reset_and_retire_until_disposed() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    set_aside_tail(&f.path, FILE, SetAsideCause::Encode).unwrap();
    save_with(&f.path, &mut index).unwrap();

    observe_tail(&f.path, FILE, observation(&[b"r0", b"r1"])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(
        tail_set_aside(&index, FILE).unwrap().is_some(),
        "debt keeps it"
    );
    let head = load_head(&index, FILE, REVISION).unwrap().unwrap();
    assert!(!head.metadata_only);
    assert_eq!(head.common.debt, observation(&[]).summary);
    assert_eq!(head.common.next_revision_id, 2);
    assert_eq!(
        revisions(&index, FILE),
        BTreeMap::from([(0, b"r0".to_vec()), (1, b"r1".to_vec())])
    );

    let reset = StagedFile {
        change: Change::Reset,
        ..staged(b"fresh", &[(Collection::Requests, 0, b"fresh")])
    };
    stage_tail(&f.path, FILE, reset).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(tail_set_aside(&index, FILE).unwrap().is_none(), "replaced");
    let (head, pages) = read(&index, FILE).unwrap();
    assert_eq!(head.unwrap().common.debt, observation(&[]).summary);
    assert_eq!(pages.len(), 1);
    assert_eq!(revisions(&index, FILE).len(), 2, "reset kept the debt");

    set_aside_tail(&f.path, FILE, SetAsideCause::Encode).unwrap();
    save_with(&f.path, &mut index).unwrap();
    retire_tail(&f.path, [FILE.to_owned()]).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(
        tail_set_aside(&index, FILE).unwrap().is_some(),
        "retiring with debt neither replaces nor disposes"
    );
    let head = load_head(&index, FILE, REVISION).unwrap().unwrap();
    assert!(head.metadata_only && head.body.is_empty());
    assert_eq!(head.common.next_revision_id, 2);
    let mut visits = 0;
    let refused = load_tail(&index, FILE, &head, |_, _, _| {
        visits += 1;
        Ok(())
    });
    assert_eq!(
        refused.unwrap_err().to_string(),
        "state_v2_tail_metadata_only"
    );
    assert_eq!(visits, 0);
    assert!(rows(&index, "tail.page.requests", FILE).is_empty());
    assert!(tail_head_keys(&index).unwrap().contains(FILE));

    let mut settle = observation(&[b"r2"]);
    settle.resolved.insert(0);
    settle.replaced.insert(1, b"r1x".to_vec());
    observe_tail(&f.path, FILE, settle).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(
        revisions(&index, FILE),
        BTreeMap::from([(1, b"r1x".to_vec()), (2, b"r2".to_vec())])
    );
    assert_eq!(
        erasure_marks(&index),
        1,
        "settled and overwritten debt purge"
    );

    dispose_tail(&f.path, FILE, Disposition::Settled).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 0, "no reduction, no debt");
    assert!(tail_set_aside(&index, FILE).unwrap().is_none(), "disposed");

    // An unknown revision id fails this file alone: set aside, nothing written.
    let mut unknown = observation(&[]);
    unknown.resolved.insert(99);
    observe_tail(&f.path, FILE, unknown).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert!(
        tail_set_aside(&index, FILE).unwrap().is_some(),
        "unknown id"
    );
    assert!(revisions(&index, FILE).is_empty());
    with_session_db(&index, |db| {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let error = tail::retire_future_head_for_test(&mut tx, FILE.as_bytes()).unwrap_err();
        assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future));
    });

    // A newer envelope, code or flag holds; never a default.
    let common = Common {
        representation: Representation::Archive,
        ..Default::default()
    };
    let encoded = tail::encode_head(REVISION, &Default::default(), &common, None).unwrap();
    assert!(tail::decode_head(&encoded).is_ok());
    for (at, value) in [(5, 2), (6, 4), (24, 3), (30, 4)] {
        let mut newer = encoded.clone();
        newer[at] = value;
        let error = tail::decode_head(&newer).err().unwrap();
        assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future), "{at}");
    }
}

/// [behaviour] Only a Tail head holds a reduction: neither side of the codec
/// accepts another, and an observation leaving Tail drops reduction and pages.
#[test]
fn reduction_requires_tail_representation() {
    let archive = Common {
        representation: Representation::Archive,
        ..Default::default()
    };
    let refused = tail::encode_head(REVISION, &Default::default(), &archive, Some(b"body"));
    assert_eq!(
        refused.unwrap_err().to_string(),
        "state_v2_tail_value_shape"
    );
    let mut bytes = tail::encode_head(
        REVISION,
        &Default::default(),
        &Common::default(),
        Some(b"body"),
    )
    .unwrap();
    assert!(tail::decode_head(&bytes).is_ok());
    bytes[6] = Representation::Archive as u8;
    let error = tail::decode_head(&bytes).err().unwrap();
    assert_eq!(error.to_string(), "state_v2_tail_value_shape");

    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let page = long_value();
    for key in [FILE, SIBLING] {
        stage_tail(
            &f.path,
            key,
            staged(b"head", &[(Collection::Requests, 0, page.as_slice())]),
        )
        .unwrap();
    }
    save_with(&f.path, &mut index).unwrap();

    let leaves_tail = |added: &[&[u8]]| Observation {
        representation: Representation::Archive,
        ..observation(added)
    };
    observe_tail(&f.path, FILE, leaves_tail(&[b"r0"])).unwrap();
    observe_tail(&f.path, SIBLING, leaves_tail(&[])).unwrap();
    save_with(&f.path, &mut index).unwrap();

    let head = load_head(&index, FILE, REVISION).unwrap().unwrap();
    assert!(head.metadata_only && head.body.is_empty());
    assert_eq!(head.common.representation, Representation::Archive);
    assert!(rows(&index, "tail.page.requests", FILE).is_empty());
    assert_eq!(frag_rows(&index), 0);
    assert_eq!(
        revisions(&index, FILE),
        BTreeMap::from([(0, b"r0".to_vec())])
    );
    assert_eq!(all_tail_rows(&index, SIBLING), 0, "no reduction, no debt");
}

/// [format] A file with no reduction keeps its header facts in the head, and the
/// stored stamp still proves the same object and content. Envelope 1 written
/// before the member existed is the same bytes, and decodes to none.
#[test]
fn inventory_facts_need_no_reduction_and_old_envelope_has_none() {
    let mut old = vec![0, 0, 0, REVISION as u8, 0, 1, Representation::Tail as u8];
    old.extend_from_slice(&[0; 24]);
    assert_eq!(
        tail::encode_head(REVISION, &Default::default(), &Common::default(), None).unwrap(),
        old
    );
    assert_eq!(tail::decode_head(&old).unwrap().common.inventory, None);

    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let file = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
    let facts = InventoryFacts {
        owner: "owner-id".into(),
        created_unix_ms: Some(-5),
        stamp: crate::snapshots::sampled_scan::codex_cursor::OpenStamp::of(&file).content_stamp(),
        read_bytes: 412,
    };
    let with_facts = |added: &[&[u8]]| Observation {
        inventory: Some(facts.clone()),
        ..observation(added)
    };
    observe_tail(&f.path, FILE, with_facts(&[])).unwrap();
    observe_tail(&f.path, SIBLING, with_facts(&[b"r0"])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let head = load_head(&index, FILE, REVISION).unwrap().unwrap();
    assert!(head.metadata_only && head.body.is_empty());
    let stored = head.common.inventory.unwrap();
    assert_eq!(stored, facts);
    let now = crate::transcript_acquisition::FileStamp::capture(file).unwrap();
    assert!(stored.stamp.matches_acquisition(&now));

    // A reduction stage keeps them; only the source's bytes change.
    stage_tail(&f.path, FILE, staged(b"head", &[])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let head = load_head(&index, FILE, REVISION).unwrap().unwrap();
    assert_eq!(head.body, b"head");
    assert_eq!(head.common.inventory.as_ref(), Some(&facts));

    // Retiring keeps them under kept debt; absence and plain retirement end them.
    retire_tail(&f.path, [FILE.to_string(), SIBLING.to_string()]).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, FILE), 0, "no debt");
    let head = load_head(&index, SIBLING, REVISION).unwrap().unwrap();
    assert!(head.metadata_only);
    assert_eq!(head.common.inventory.as_ref(), Some(&facts));
    dispose_tail(&f.path, SIBLING, Disposition::Absence).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(all_tail_rows(&index, SIBLING), 0, "absent");
}

/// [behaviour] Scope erasure is not a reset: every row and the marker go, and
/// files that held unaccepted debt add to a count that survives the erasure.
#[test]
fn erasure_deletes_debt_and_counts_unaccepted_files() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(index.tail_discovery.deleted_unaccepted_oldest_at, None);
    stage_tail(
        &f.path,
        FILE,
        staged(b"head", &[(Collection::Responses, 0, b"page")]),
    )
    .unwrap();
    observe_tail(&f.path, FILE, observation(&[b"debt"])).unwrap();
    stage_tail(&f.path, SIBLING, staged(b"sibling", &[])).unwrap();
    set_aside_tail(
        &f.path,
        "/synthetic/tail/staged.jsonl",
        SetAsideCause::Encode,
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    let mut pending = observation(&[b"new"]);
    pending.summary.earliest_unacked_change_at = Some(3_000);
    observe_tail(&f.path, "/synthetic/tail/staged.jsonl", pending).unwrap();

    erase_tail(&f.path, &mut index, [FILE.to_owned()]).unwrap();
    assert_eq!(index.tail_discovery.deleted_unaccepted_files, 1);
    assert_eq!(
        index.tail_discovery.deleted_unaccepted_oldest_at,
        Some(7_000)
    );

    let keys = [FILE, SIBLING, "/synthetic/tail/staged.jsonl"].map(str::to_owned);
    erase_tail(&f.path, &mut index, keys.clone()).unwrap();
    erase_tail(&f.path, &mut index, keys.clone()).unwrap();
    assert_eq!(
        index.tail_discovery.deleted_unaccepted_files, 2,
        "once each"
    );
    assert_eq!(
        index.tail_discovery.deleted_unaccepted_oldest_at,
        Some(3_000)
    );
    save_with(&f.path, &mut index).unwrap();
    for key in &keys {
        assert_eq!(all_tail_rows(&index, key), 0, "{key}");
        assert!(tail_set_aside(&index, key).unwrap().is_none());
    }
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(index.tail_discovery.deleted_unaccepted_files, 2);
    assert_eq!(
        index.tail_discovery.deleted_unaccepted_oldest_at,
        Some(3_000)
    );
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
