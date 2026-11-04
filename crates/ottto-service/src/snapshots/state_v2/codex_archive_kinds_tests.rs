use super::*;
use crate::snapshots::scan_index_persistence::{Binding, Source};

/// [format] Claude stores keep the pre-archive row set and hydrate without archive roots.
/// The kinds are owned, but a store holding no archive custody writes no row for them.
#[test]
fn claude_store_omits_archive_rows_and_hydrates_legacy_absence() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let (index, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let expected = baseline(&index, &mut cx).unwrap().rows;
    let mut presence: BTreeMap<String, bool> = db.read_control("field_presence").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for field in ["archives", "archive_deferred_alarm_count"] {
        assert!(!presence.contains_key(field));
        presence.remove(field);
        let kind = format!("v1_field.{field}");
        assert!(catalogue::OWNED.iter().any(|(name, _)| *name == kind));
        assert!(!expected.keys().any(|key| {
            matches!(key, RowKey::Record { kind: stored, .. } if stored.name() == kind)
        }));
        // A pre-archive store has neither root. Deleting the draft roots must
        // be a no-op for a plain store written by the current mapper.
        assert!(!tx
            .delete(&RowKey::Record {
                kind: RecordKind(kind),
                key_bytes: Vec::new(),
                position: 0,
            })
            .unwrap());
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.control("field_presence", &presence).unwrap();
    let (mut restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(serde_json::to_value(&restored)
        .unwrap()
        .get("archives")
        .is_none());
    let actual = baseline(&restored, &mut cx).unwrap().rows;
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    let identity = db.read_control("identity").unwrap().unwrap();
    let previous = restored.clone();
    save_graph(&mut db, &identity, &previous, &mut restored, &mut cx).unwrap();
    let (restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        baseline(&restored, &mut cx)
            .unwrap()
            .rows
            .keys()
            .collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
}

fn codex_binding() -> Binding {
    Binding {
        source: Source::Codex,
        namespace_hash: "c".repeat(64),
    }
}
fn codex_store() -> (Scratch, sqlite::Sqlite) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ottto-codex-archive-kinds-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let mut db = sqlite::Sqlite::create_import(&dir.join("index.v2.sqlite.import")).unwrap();
    db.control(
        "identity",
        &Identity {
            format: FORMAT,
            db_id: "synthetic-codex-archive".into(),
            binding: codex_binding(),
            fence_generation: 0,
        },
    )
    .unwrap();
    db.control("generation", &0_u64).unwrap();
    (Scratch(dir), db)
}
const RETIRED_ARCHIVE_KINDS: [&str; 2] =
    ["v1_field.archives", "v1_field.archive_deferred_alarm_count"];
fn assert_kinds(db: &mut sqlite::Sqlite, present: bool) {
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for kind in RETIRED_ARCHIVE_KINDS {
        let rows = tx
            .scan_kind(&RecordKind::parse(kind).unwrap(), None, 1)
            .unwrap();
        assert_eq!(!rows.is_empty(), present, "{kind}");
    }
}
/// Save `next` over the committed store, then reopen it.
fn save_and_reopen(
    db: &mut sqlite::Sqlite,
    previous: &ScanIndex,
    next: &mut ScanIndex,
    cx: &mut KindCx,
) -> (ScanIndex, KindCx) {
    let identity = db.read_control("identity").unwrap().unwrap();
    // Before the fix this refused with state_v2_archive_state_unsupported,
    // failing every checkpoint save, so no Codex pass could upload.
    save_graph(db, &identity, previous, next, cx).unwrap();
    hydrate(db, codex_binding()).unwrap()
}

/// [format] Retired layout-2 archive rows are accepted but never hydrated,
/// digested, rewritten or swept. Preserve their bytes through save and reopen.
#[test]
fn codex_store_persists_archive_custody_through_populate_delta_and_upgrade() {
    let (scratch, mut db) = codex_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut cx = KindCx {
        binding: Some(codex_binding()),
        ..Default::default()
    };
    populate(&ScanIndex::default(), &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    assert_kinds(&mut db, false);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut expected = Vec::new();
    for kind in RETIRED_ARCHIVE_KINDS {
        assert!(catalogue::OWNED.iter().any(|(name, _)| *name == kind));
        assert_eq!(catalogue::introduced(kind).unwrap(), 2);
        // Deliberately incompatible payload: attempting active decode must fail.
        let key = mapper::key(kind, "", 0).unwrap();
        let header =
            mapper::put(&mut tx, &key, &serde_json::json!({"future": [false, 7]})).unwrap();
        expected.push((key, header));
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    db.finish_import().unwrap();
    let reopen = || {
        let mut db =
            sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db
    };
    let mut db = reopen();
    let (mut index, mut cx) = hydrate(&mut db, codex_binding()).unwrap();
    let rows = baseline(&index, &mut cx).unwrap().rows;
    for (key, _) in &expected {
        assert!(
            !rows.contains_key(key),
            "inert rows are not baseline digests"
        );
    }
    assert!(serde_json::to_value(&index)
        .unwrap()
        .get("archives")
        .is_none());
    let previous = index.clone();
    let (restored, _) = save_and_reopen(&mut db, &previous, &mut index, &mut cx);
    assert_eq!(
        serde_json::to_value(&restored).unwrap(),
        serde_json::to_value(&index).unwrap()
    );
    drop(db);
    let mut db = reopen();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for (key, header) in expected {
        let actual = tx
            .get(&key)
            .unwrap()
            .expect("inert row survives ordinary save");
        assert_eq!(
            actual, header,
            "byte commitment, key and position preserved"
        );
    }
}

/// [regress] A population above the old write target contributes no dirty
/// archive rows on repeated ordinary saves and cannot halve the scan page.
#[test]
fn a_repeat_refused_archive_pass_dirties_no_row_and_keeps_the_page_limit() {
    let (scratch, mut db) = codex_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut cx = KindCx {
        binding: Some(codex_binding()),
        ..Default::default()
    };
    populate(&ScanIndex::default(), &mut tx, &mut cx).unwrap();
    for n in 0..5_001 {
        mapper::put(&mut tx, &mapper::key("v1_field.archives", &format!("/synthetic/{n}.zst"), 0).unwrap(),
            &serde_json::json!({"disposition": {"Held": {"cause": "CompressedAdmissionRefused", "quiet": false}}})).unwrap();
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    db.finish_import().unwrap();
    let mut db =
        sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
    db.path_extractor(private_paths);
    let save = |db: &mut sqlite::Sqlite| {
        let (mut next, mut cx) = hydrate(db, codex_binding()).unwrap();
        let previous = next.clone();
        let before = db.save_row_attempts();
        save_graph(db, &identity, &previous, &mut next, &mut cx).unwrap();
        let after = db.save_row_attempts();
        assert!(
            !db.save_over_target(),
            "inert population cannot reduce the page limit"
        );
        (after.0 - before.0, after.1 - before.1)
    };
    let unchanged = save(&mut db);
    assert_eq!(save(&mut db), unchanged);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert_eq!(
        tx.scan_kind(
            &RecordKind::parse("v1_field.archives").unwrap(),
            None,
            5_002
        )
        .unwrap()
        .len(),
        5_001
    );
}
