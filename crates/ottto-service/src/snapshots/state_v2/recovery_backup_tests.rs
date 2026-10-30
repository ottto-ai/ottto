//! Synthetic bundle qualification; executed only in CI.
use super::*;
use std::os::unix::fs::PermissionsExt;
struct Fixture {
    _scratch: crate::test_scratch::ScratchDir,
    path: PathBuf,
    progress: PathBuf,
    recovery: ack::ProgressRecovery,
}
impl Fixture {
    fn new() -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("v2-independent-recovery");
        let parent = scratch.join("snapshots/destinations").join("a".repeat(64));
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("claude_code-test-scan-index.json");
        let identity = Identity {
            format: FORMAT,
            db_id: "synthetic-recovery-bundle".into(),
            binding: super::super::super::scan_index_integration::scan_index_storage_binding(&path)
                .unwrap(),
            fence_generation: 0,
        };
        let progress =
            crate::snapshot_sync::with_state_v2_progress_lock(&path, |p| Ok(p.to_owned())).unwrap();
        let old = br#"{"generation":4,"body":"synthetic-original"}"#;
        ottto_core::write_owner_only_file_atomic(&progress, old).unwrap();
        let recovery =
            ack::ProgressRecovery::seal_import(identity.clone(), 0, &path, Some(old)).unwrap();
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&path, ".v2.sqlite.import")).unwrap();
        db.control("identity", &identity).unwrap();
        db.control("generation", &0_u64).unwrap();
        let set = {
            let mut tx = db.begin(TxnMode::Read).unwrap();
            ack::RecoverySet::capture(&mut tx, &recovery, &progress).unwrap()
        };
        db.finish_import().unwrap();
        let baseline = fence::sibling(&path, ".v1-readonly");
        ottto_core::write_owner_only_file_atomic(&baseline, b"synthetic-v1-baseline").unwrap();
        persist_import(&path, set).unwrap();
        // Seal_import's live DB path is available after fence publication.
        fence::publish(&path, &identity, &mut false).unwrap();
        Self {
            _scratch: scratch,
            path,
            progress,
            recovery,
        }
    }
}
#[test]
fn descriptor_survives_reopen_and_restores_pair_companion_and_baseline_independently() {
    let f = Fixture::new();
    let before = read(&f.path).unwrap();
    let db = fence::sibling(&f.path, ".v2.sqlite");
    let db_bytes = fs::read(&db).unwrap();
    let fence_bytes = fs::read(&f.path).unwrap();
    let receipt = fence::sibling(&f.path, ".v2-ack-receipt");
    let receipt_bytes = fs::read(&receipt).unwrap();
    let baseline = fence::sibling(&f.path, ".v1-readonly");
    for path in [&db, &f.path, &receipt, &baseline] {
        fs::remove_file(path).unwrap();
    }
    restore(&f.path).unwrap();
    assert_eq!(fs::read(&db).unwrap(), db_bytes);
    assert_eq!(fs::read(&f.path).unwrap(), fence_bytes);
    assert_eq!(fs::read(&receipt).unwrap(), receipt_bytes);
    assert_eq!(fs::read(&baseline).unwrap(), b"synthetic-v1-baseline");
    assert_eq!(read(&f.path).unwrap().set, before.set);
    erase(&f.path).unwrap();
    assert!(!root(&f.path).exists());
    assert!(db.exists());
    assert_eq!(fs::metadata(&db).unwrap().mode() & 0o777, 0o600);
    let reopened = sqlite::Sqlite::open(&db, before.set.identity()).unwrap();
    drop(reopened);
}
#[test]
fn newer_receipt_replays_before_old_bundle_restore_refuses() {
    let f = Fixture::new();
    let before_db = fs::read(fence::sibling(&f.path, ".v2.sqlite")).unwrap();
    let old = fs::read(&f.progress).unwrap();
    let next = br#"{"generation":5,"body":"synthetic-newly-accepted"}"#;
    f.recovery.before_progress_save(Some(&old), next).unwrap();
    assert!(restore(&f.path).is_err());
    assert_eq!(fs::read(&f.progress).unwrap(), next);
    assert_eq!(
        fs::read(fence::sibling(&f.path, ".v2.sqlite")).unwrap(),
        before_db
    );
    assert!(root(&f.path).exists());
}
#[test]
fn missing_or_corrupt_backup_member_prevents_any_restore() {
    let f = Fixture::new();
    let db = fence::sibling(&f.path, ".v2.sqlite");
    let before = fs::read(&db).unwrap();
    let payload = member(&active_dir(&f.path).unwrap(), 0);
    fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&payload, b"synthetic-corruption").unwrap();
    assert!(restore(&f.path).is_err());
    assert_eq!(fs::read(&db).unwrap(), before);
    fs::remove_file(payload).unwrap();
    assert!(restore(&f.path).is_err());
    assert_eq!(fs::read(&db).unwrap(), before);
}
#[test]
fn exact_record_trailer_is_verified_without_a_restart_store_codec() {
    let scratch = crate::test_scratch::ScratchDir::new("v2-backup-record-trailer");
    let path = scratch.join("exact.7.attempt.rec");
    let prefix = b"synthetic-record-envelope-and-body";
    let trailer: [u8; 32] = Sha256::digest(prefix).into();
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(&trailer);
    ottto_core::write_owner_only_file_atomic(&path, &bytes).unwrap();
    assert!(commitment(&path, Some(trailer)).is_ok());
    assert!(commitment(&path, Some([0; 32])).is_err());
    bytes[0] ^= 1;
    ottto_core::write_owner_only_file_atomic(&path, &bytes).unwrap();
    assert!(commitment(&path, Some(trailer)).is_err());
}

#[test]
fn rolling_backup_supersedes_only_verified_generations_and_erases_interrupted_ones() {
    let f = Fixture::new();
    let old_dir = active_dir(&f.path).unwrap();
    let old_set = read(&f.path).unwrap().set;
    let identity = old_set.identity().clone();
    let db_path = fence::sibling(&f.path, ".v2.sqlite");
    let mut db = sqlite::Sqlite::open(&db_path, &identity).unwrap();
    let tx = db.begin(TxnMode::Write).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    // A missing mandatory member fails replacement without deleting the seal.
    let receipt = fence::sibling(&f.path, ".v2-ack-receipt");
    let bytes = fs::read(&receipt).unwrap();
    ottto_core::write_owner_only_file_atomic(&receipt, b"invalid-receipt").unwrap();
    assert!(roll(&f.path, &mut db, &identity).is_err());
    assert_eq!(active_dir(&f.path).unwrap(), old_dir);
    assert_eq!(read(&f.path).unwrap().set, old_set);
    ottto_core::write_owner_only_file_atomic(&receipt, &bytes).unwrap();
    roll(&f.path, &mut db, &identity).unwrap();
    assert_ne!(active_dir(&f.path).unwrap(), old_dir);
    assert!(!old_dir.exists());
    let newer = read(&f.path).unwrap();
    assert_ne!(newer.set, old_set);
    let interrupted = root(&f.path).join("generation-interrupted");
    fs::create_dir(&interrupted).unwrap();
    fs::write(interrupted.join("private.member"), b"synthetic-private").unwrap();
    erase(&f.path).unwrap();
    assert!(!root(&f.path).exists());
    assert!(db_path.exists());
}

#[test]
fn exact_rec_predecessor_is_protected_until_replacement_bundle_verifies() {
    let f = Fixture::new();
    let identity = read(&f.path).unwrap().set.identity().clone();
    let db_path = fence::sibling(&f.path, ".v2.sqlite");
    let mut db = sqlite::Sqlite::open(&db_path, &identity).unwrap();
    // Checkpoint replacements require the same private-text inventory as runtime writes.
    db.path_extractor(kinds::private_paths);
    let records = crate::durable_tail_store::store_dir_for_index(&f.path);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&records)
        .unwrap();
    let key = RowKey::record("resume.checkpoint", b"synthetic-file".to_vec(), 0).unwrap();
    let mut old_dir: Option<PathBuf> = None;
    for generation in 1..=2 {
        let prefix = format!("synthetic-record-{generation}");
        let digest: [u8; 32] = Sha256::digest(prefix.as_bytes()).into();
        let name = format!("synthetic.{generation}.attempt.rec");
        let mut record = prefix.into_bytes();
        record.extend_from_slice(&digest);
        let source = records.join(&name);
        ottto_core::write_owner_only_file_atomic(&source, &record).unwrap();
        let checkpoint = kinds_files::ResumeCheckpoint {
            record_generation: generation,
            record_name: name.clone(),
            trailer_digest: digest,
            file_generation: generation,
            committed_bytes: 0,
            reduction_version: 1,
            reduction_allowlist: [1; 32],
            reduction_pin: vec![1],
            binding: identity.binding.clone(),
            key_digest: [2; 32],
            context: [3; 32],
            scope: [4; 32],
            entry: [5; 32],
            publication: [6; 16],
            certificate: kinds_files::Certificate {
                device: 1,
                inode: 2,
                length: 0,
                modified: (0, 0),
                birth_nanos: 0,
                sealed_offset: 0,
                sample_len: 0,
                head_sha256: [7; 32],
                boundary_sha256: [8; 32],
                verified_unix_seconds: 1,
                audit_debt_unix_seconds: None,
            },
        };
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            key: &key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &codec::Json(&checkpoint),
        })
        .unwrap();
        assert_eq!(
            tx.commit(generation - 1, generation),
            DurableCommitOutcome::Committed(generation)
        );
        if generation == 2 {
            // Live GC cannot invalidate the exact predecessor's independent copy.
            fs::remove_file(records.join("synthetic.1.attempt.rec")).unwrap();
            ottto_core::write_owner_only_file_atomic(&source, b"bad-record").unwrap();
            for _ in 0..3 {
                assert!(roll(&f.path, &mut db, &identity).is_err());
                assert_eq!(
                    fs::read_dir(root(&f.path))
                        .unwrap()
                        .filter(|e| e.as_ref().unwrap().file_type().unwrap().is_dir())
                        .count(),
                    1,
                    "failed replacement retained database/baseline copies"
                );
            }
            let old = read(&f.path).unwrap();
            assert_eq!(
                active_dir(&f.path).unwrap(),
                old_dir.as_ref().unwrap().to_owned()
            );
            assert_eq!(
                old.set.checkpoints().unwrap()[0].record_name,
                "synthetic.1.attempt.rec"
            );
            assert!(old
                .artifacts
                .iter()
                .any(|a| matches!(&a.role, Role::Baseline)));
            ottto_core::write_owner_only_file_atomic(&source, &record).unwrap();
        }
        roll(&f.path, &mut db, &identity).unwrap();
        let descriptor = read(&f.path).unwrap();
        assert_eq!(descriptor.set.checkpoints().unwrap()[0], checkpoint);
        let current = active_dir(&f.path).unwrap();
        if let Some(old) = old_dir.replace(current) {
            assert!(!old.exists());
        }
    }
}

#[test]
fn rolling_db_wal_pair_restores_without_forcing_a_source_checkpoint() {
    let f = Fixture::new();
    let identity = read(&f.path).unwrap().set.identity().clone();
    let db_path = fence::sibling(&f.path, ".v2.sqlite");
    let mut db = sqlite::Sqlite::open(&db_path, &identity).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &RowKey::Meta("baseline_bytes".into()),
        fixed: &Fixed::None,
        value_version: 1,
        value: &ControlJson(&123_u64),
    })
    .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let wal = fence::sibling(&f.path, ".v2.sqlite-wal");
    let before = fs::read(&wal).unwrap();
    assert!(!before.is_empty());
    roll(&f.path, &mut db, &identity).unwrap();
    assert_eq!(fs::read(&wal).unwrap(), before);
    assert!(read(&f.path)
        .unwrap()
        .artifacts
        .iter()
        .any(|a| matches!(a.role, Role::Wal)));
    drop(db);
    fs::remove_file(&db_path).unwrap();
    if wal.exists() {
        fs::remove_file(&wal).unwrap();
    }
    fs::remove_file(&f.path).unwrap();
    // A previous restore copied only the exact older base before crashing.
    // Receipt reconciliation must not mistake that incomplete pair for a newer
    // or conflicting DB and refuse before completing its verified WAL.
    let descriptor = read(&f.path).unwrap();
    let database_member = descriptor
        .artifacts
        .iter()
        .position(|a| matches!(a.role, Role::Database))
        .unwrap();
    fence::preserve_file(
        &member(&active_dir(&f.path).unwrap(), database_member),
        &db_path,
    )
    .unwrap();
    restore(&f.path).unwrap();
    let restored = sqlite::Sqlite::open(&db_path, &identity).unwrap();
    assert_eq!(restored.stamp().unwrap().0, 1);
    assert_eq!(
        restored.read_control::<u64>("baseline_bytes").unwrap(),
        Some(123)
    );
}
