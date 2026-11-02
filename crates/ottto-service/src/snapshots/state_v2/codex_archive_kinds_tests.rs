use super::*;

/// [format] Claude stores keep the pre-archive row set and hydrate without archive roots.
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
        assert!(!catalogue::OWNED.iter().any(|(name, _)| *name == kind));
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

/// [format] Claude typed saves refuse archive custody instead of silently discarding it.
#[test]
fn claude_store_refuses_archive_state_on_import_and_delta() {
    for deferred in [false, true] {
        let (_scratch, mut db) = Scratch::store();
        commit_populate(&mut db, &fixture());
        let (mut index, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let previous = baseline(&index, &mut cx).unwrap();
        if deferred {
            index.archive_deferred_alarm_count = 1;
        } else {
            index.archives.insert(
                "synthetic".into(),
                crate::snapshots::codex_compressed_input::ArchiveEvidence::unknown(),
            );
        }
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let error = delta(previous, &index, &mut tx, &mut cx).err().unwrap();
        assert!(error
            .to_string()
            .contains("state_v2_archive_state_unsupported"));
        drop(tx);
        let (_scratch, mut empty) = Scratch::store();
        let mut tx = empty.begin(TxnMode::Write).unwrap();
        let error = populate(&index, &mut tx, &mut KindCx::default()).unwrap_err();
        assert!(error
            .to_string()
            .contains("state_v2_archive_state_unsupported"));
    }
}
