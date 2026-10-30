use super::*;

fn progress(generation: u64, body: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"generation":generation,"body":body})).unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    ottto_core::write_owner_only_file_atomic(path, bytes).unwrap();
}
#[test]
fn receipt_first_replaces_only_exact_predecessor_and_replays_idempotently() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-receipt-first");
    let index = scratch.join("index");
    let path = scratch.join("progress");
    let binding = ProgressRecovery::synthetic(&index, &"a".repeat(64), 10);
    let old = progress(4, "old");
    let new = progress(5, "new");
    write(&path, &old);
    binding.adopt(Some(&old)).unwrap();
    binding.before_progress_save(Some(&old), &new).unwrap();
    // Crash: exact receipt durable, neither progress replacement nor DB save.
    binding.recover(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), new);
    binding.recover(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), new);
}
#[test]
fn mismatched_identity_generation_and_same_generation_forks_hold_without_changes() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-refuse");
    let path = scratch.join("progress");
    let binding = ProgressRecovery::synthetic(&scratch.join("index"), &"a".repeat(64), 10);
    let old = progress(4, "old");
    write(&path, &old);
    binding.adopt(Some(&old)).unwrap();
    for case in ["db", "namespace", "source", "generation"] {
        let mut other = binding.clone();
        match case {
            "db" => other.scope.identity.db_id.push('x'),
            "namespace" => other.scope.identity.binding.namespace_hash = "b".repeat(64),
            "source" => {
                other.scope.identity.binding.source =
                    super::super::super::scan_index_persistence::Source::Codex
            }
            "generation" => other.scope.generation = 9,
            _ => unreachable!(),
        }
        assert!(other.recover(&path).is_err(), "{case}");
        assert_eq!(std::fs::read(&path).unwrap(), old);
    }
    let fork = progress(4, "different-body");
    write(&path, &fork);
    assert!(binding.recover(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), fork);
    std::fs::remove_file(&path).unwrap();
    assert!(
        binding.recover(&path).is_err(),
        "missing historical progress is not empty"
    );
}
#[test]
fn absent_initial_progress_is_only_a_binding_marker_and_next_receipt_can_recover_it() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-missing");
    let path = scratch.join("progress");
    let binding = ProgressRecovery::synthetic(&scratch.join("index"), &"a".repeat(64), 10);
    binding.adopt(None).unwrap();
    binding.recover(&path).unwrap();
    assert!(!path.exists());
    let next = progress(1, "accepted");
    binding.before_progress_save(None, &next).unwrap();
    binding.recover(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), next);
}
#[test]
fn missing_or_damaged_receipt_never_falls_back_to_unbound_progress() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-corrupt");
    let path = scratch.join("progress");
    let binding = ProgressRecovery::synthetic(&scratch.join("index"), &"a".repeat(64), 10);
    let old = progress(4, "old");
    write(&path, &old);
    assert!(binding.recover(&path).is_err());
    binding.adopt(Some(&old)).unwrap();
    let mut receipt = binding.receipt().unwrap();
    receipt.progress = String::from_utf8(progress(4, "tampered")).unwrap();
    write(&binding.path, &serde_json::to_vec(&receipt).unwrap());
    assert!(binding.recover(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), old);
}

#[test]
fn recovery_set_pins_db_identity_generation_progress_and_every_exact_resume_reference() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-recovery-set");
    let index = scratch.join("index");
    let path = scratch.join("progress");
    let db_path = scratch.join("db.import");
    let binding = ProgressRecovery::synthetic(&index, &"a".repeat(64), 0);
    let old = progress(4, "old");
    write(&path, &old);
    binding.adopt(Some(&old)).unwrap();
    let mut db = sqlite::Sqlite::create_import(&db_path).unwrap();
    db.control("identity", &binding.scope.identity).unwrap();
    db.control("generation", &0_u64).unwrap();
    db.finish_import().unwrap();
    let open = || {
        let mut db = sqlite::Sqlite::open(&db_path, &binding.scope.identity).unwrap();
        db.path_extractor(|_, _, _| Ok(()));
        db
    };
    let mut db = open();
    struct Bytes(&'static [u8]);
    impl Value for Bytes {
        fn write(&self, out: &mut dyn Write) -> Result<()> {
            out.write_all(self.0)?;
            Ok(())
        }
    }
    let key = RowKey::record("resume.checkpoint", b"synthetic-file".to_vec(), 0).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &key,
        fixed: &Fixed::None,
        value_version: 1,
        value: &Bytes(b"exact-immutable-generation-name-trailer-tuple"),
    })
    .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let manifest = {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        RecoverySet::capture(&mut tx, &binding, &path).unwrap()
    };
    drop(db);
    let mut db = open();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    manifest.verify(&mut tx, &binding, &path).unwrap();
    for case in ["db", "generation", "resume"] {
        let mut fork: RecoverySet =
            serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        match case {
            "db" => fork.scope.identity.db_id.push('x'),
            "generation" => fork.scope.generation += 1,
            "resume" => fork.resume[0].digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(fork.verify(&mut tx, &binding, &path).is_err(), "{case}");
    }
    drop(tx);
    // A missing exact restart member cannot borrow a nearby name/generation.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    assert!(manifest.verify(&mut tx, &binding, &path).is_err());
    drop(tx); // rollback
              // A newer external receipt is replayed first; the old backup descriptor
              // then holds until an explicit consistent recovery set has been proved.
    let next = progress(5, "newer-accepted-body");
    binding.before_progress_save(Some(&old), &next).unwrap();
    binding.recover(&path).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(manifest.verify(&mut tx, &binding, &path).is_err());
}

#[test]
fn import_sealing_is_idempotent_but_never_rebinds_a_different_db_or_progress() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-import-seal");
    let index = scratch.join("index");
    let binding = ProgressRecovery::synthetic(&index, &"a".repeat(64), 10);
    let old = progress(4, "old");
    let identity = binding.scope.identity.clone();
    ProgressRecovery::seal_import(identity.clone(), 10, &index, Some(&old)).unwrap();
    ProgressRecovery::seal_import(identity.clone(), 10, &index, Some(&old)).unwrap();
    assert!(ProgressRecovery::seal_import(
        identity.clone(),
        10,
        &index,
        Some(&progress(4, "fork"))
    )
    .is_err());
    let mut foreign = identity;
    foreign.db_id.push('x');
    assert!(ProgressRecovery::seal_import(foreign, 10, &index, Some(&old)).is_err());
}

#[test]
fn post_commit_cleanup_receipt_binds_latest_db_generation_and_refuses_rollback() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-postcommit-generation");
    let path = scratch.join("progress");
    let db_path = scratch.join("db.import");
    let mut binding = ProgressRecovery::synthetic(&scratch.join("index"), &"a".repeat(64), 0);
    let before = progress(1, "accepted-body");
    write(&path, &before);
    binding.adopt(Some(&before)).unwrap();
    let mut db = sqlite::Sqlite::create_import(&db_path).unwrap();
    db.control("identity", &binding.scope.identity).unwrap();
    db.control("generation", &0_u64).unwrap();
    db.finish_import().unwrap();
    let mut db = sqlite::Sqlite::open(&db_path, &binding.scope.identity).unwrap();
    binding.db_path = Some(db_path);
    // The source commit that adopts the ACK happens after preparation.
    let tx = db.begin(TxnMode::Write).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let cleaned = progress(2, "ACK-retired-by-source-generation-1");
    binding
        .before_progress_save(Some(&before), &cleaned)
        .unwrap();
    write(&path, &cleaned);
    assert_eq!(binding.receipt().unwrap().scope.generation, 1);
    // Simulate restoring the same DB identity from its older generation.
    db.control("generation", &0_u64).unwrap();
    assert!(binding.recover(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), cleaned);
}
