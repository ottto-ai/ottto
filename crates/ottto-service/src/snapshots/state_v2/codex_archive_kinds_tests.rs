use super::*;
use crate::snapshots::codex_compressed_input::ArchiveEvidence;
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
    assert!(restored.archives.is_empty());
    assert_eq!(restored.archive_deferred_alarm_count, 0);
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
fn custody(index: &ScanIndex) -> (serde_json::Value, u64) {
    (
        serde_json::to_value(&index.archives).unwrap(),
        index.archive_deferred_alarm_count,
    )
}
fn assert_kinds(db: &mut sqlite::Sqlite, present: bool) {
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for kind in kinds_misc::ARCHIVE_KINDS {
        let root = tx.get(&mapper::key(kind, "", 0).unwrap()).unwrap();
        let rows = tx
            .scan_kind(&RecordKind::parse(kind).unwrap(), None, 1)
            .unwrap();
        assert_eq!(
            (root.is_some(), !rows.is_empty()),
            (present, present),
            "{kind}"
        );
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

/// [regress] A Codex-bound store keeps archive custody (held, owed evidence and a
/// deferred alarm) through populate, a changed delta, a delta to empty and a
/// store written before the kinds existed. No save refuses, so passes upload.
#[test]
fn codex_store_persists_archive_custody_through_populate_delta_and_upgrade() {
    let (first, second) = (
        "/synthetic/archived/a.jsonl.zst",
        "/synthetic/archived/b.jsonl.zst",
    );
    let held = ArchiveEvidence::unknown();
    assert!(held.owed_cause().is_some(), "held evidence is owed");
    let mut index = ScanIndex::default();
    index.archives.insert(first.into(), held.clone());
    index.archive_deferred_alarm_count = 2;
    // The v1 inventory admits both fields, so the v1 import reaches populate.
    let v1 = serde_json::json!({
        "schema_version": 2, "generation": 0, "files": {},
        "archives": index.archives, "archive_deferred_alarm_count": 2,
    });
    assert_eq!(
        codec::inventory(std::io::Cursor::new(serde_json::to_vec(&v1).unwrap())),
        Ok(())
    );

    // Populate (the import's writer) stores both kinds and their presence.
    let (_scratch, mut db) = codex_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut cx = KindCx {
        binding: Some(codex_binding()),
        ..Default::default()
    };
    populate(&index, &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    assert_kinds(&mut db, true);
    let (mut restored, mut cx) = hydrate(&mut db, codex_binding()).unwrap();
    assert_eq!(custody(&restored), custody(&index));
    assert_eq!(cx.presence.get("archives"), Some(&true));
    assert_eq!(cx.presence.get("archive_deferred_alarm_count"), Some(&true));

    // Delta to a changed archive set.
    let previous = restored.clone();
    restored.archives.get_mut(first).unwrap().owner = Some("synthetic-owner".into());
    restored.archives.insert(second.into(), held);
    restored.archive_deferred_alarm_count = 3;
    let (mut reopened, mut cx) = save_and_reopen(&mut db, &previous, &mut restored, &mut cx);
    assert_eq!(custody(&reopened), custody(&restored));
    assert_eq!(reopened.archives.len(), 2);

    // Delta to empty drops the rows; the store hydrates empty.
    let previous = reopened.clone();
    reopened.archives.clear();
    reopened.archive_deferred_alarm_count = 0;
    let (emptied, _) = save_and_reopen(&mut db, &previous, &mut reopened, &mut cx);
    assert_kinds(&mut db, false);
    assert!(emptied.archives.is_empty());
    assert_eq!(emptied.archive_deferred_alarm_count, 0);

    // Upgrade: a store written before these kinds existed (rows and presence
    // keys deleted) opens empty, then gains both rows on its next save.
    let (_scratch, mut db) = codex_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut cx = KindCx {
        binding: Some(codex_binding()),
        ..Default::default()
    };
    populate(&index, &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut presence: BTreeMap<String, bool> = db.read_control("field_presence").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for kind in kinds_misc::ARCHIVE_KINDS {
        mapper::rows(&mut tx, kind, |tx, h| mapper::remove(tx, &h.key)).unwrap();
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    for field in ["archives", "archive_deferred_alarm_count"] {
        assert_eq!(presence.remove(field), Some(true));
    }
    db.control("field_presence", &presence).unwrap();
    assert_kinds(&mut db, false);
    let (mut opened, mut cx) = hydrate(&mut db, codex_binding()).unwrap();
    assert!(opened.archives.is_empty());
    assert_eq!(opened.archive_deferred_alarm_count, 0);
    let previous = opened.clone();
    opened.archives = index.archives.clone();
    opened.archive_deferred_alarm_count = index.archive_deferred_alarm_count;
    let (upgraded, cx) = save_and_reopen(&mut db, &previous, &mut opened, &mut cx);
    assert_kinds(&mut db, true);
    assert_eq!(custody(&upgraded), custody(&index));
    assert_eq!(cx.presence.get("archives"), Some(&true));
    assert_eq!(
        serde_json::to_vec(&upgraded).unwrap(),
        serde_json::to_vec(&opened).unwrap()
    );
}
