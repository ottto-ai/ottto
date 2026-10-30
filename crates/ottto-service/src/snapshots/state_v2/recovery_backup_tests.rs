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
    let payload = member(&root(&f.path), 0);
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
