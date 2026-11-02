use super::super::super::scan_index_persistence::Source;
use super::super::money_test_support::synthetic_file;
use super::*;

fn progress(generation: u64, body: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"generation":generation,"body":body})).unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    ottto_core::write_owner_only_file_atomic(path, bytes).unwrap();
}
/// [money] receipt first replaces only exact predecessor and replays idempotently.
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
/// [money] mismatched identity generation and same generation forks hold without changes.
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
/// [money] absent initial progress is only a binding marker and next receipt can recover it.
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
/// [money] missing or damaged receipt never falls back to unbound progress.
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

/// [money] import sealing is idempotent but never rebinds a different db or progress.
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

/// [money] post commit cleanup receipt binds latest db generation and refuses rollback.
#[test]
fn post_commit_cleanup_receipt_binds_latest_db_generation_and_refuses_rollback() {
    let scratch = crate::test_scratch::ScratchDir::canonical("v2-ack-postcommit-generation");
    let path = scratch.join("progress");
    let db_path = scratch.join("db.v2.sqlite.import");
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

/// [regress] v1 progress created with umask 022 seals unchanged; companions stay private.
#[test]
fn v1_readable_progress_seals_without_rewriting_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = crate::test_scratch::ScratchDir::new("v2-ack-v1-permissions");
    let parent = scratch.join("a".repeat(64));
    std::fs::create_dir(&parent).unwrap();
    let index = parent.join(synthetic_file(Source::Claude, ".json"));
    let path = parent.join(synthetic_file(Source::Claude, "-upload-progress.json"));
    let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":3,
        "destination_namespace_hash":"a".repeat(64),"generation":1}))
    .unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let original = OriginalProgress::capture(&index).unwrap();
    let binding = ProgressRecovery::synthetic(&index, &"a".repeat(64), 1);
    assert!(original
        .retry_identity(binding.scope.identity.clone())
        .is_ok());
    ProgressRecovery::seal_import(binding.scope.identity.clone(), 1, &index, Some(&bytes)).unwrap();
    binding.recover(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let companion = fence::sibling(&index, ".v2-ack-receipt");
    assert_eq!(
        std::fs::metadata(&companion).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(OriginalProgress::capture(&index).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

/// [money] obsolete unpublished seal preserves custody then retries after v1 advances.
#[test]
fn obsolete_unpublished_seal_preserves_custody_then_retries_after_v1_advances() {
    let scratch = crate::test_scratch::ScratchDir::canonical("v2-ack-obsolete-import");
    let parent = scratch.join("a".repeat(64));
    std::fs::create_dir(&parent).unwrap();
    let index = parent.join(synthetic_file(Source::Claude, ".json"));
    let path = parent.join(synthetic_file(Source::Claude, "-upload-progress.json"));
    let progress = |generation| {
        serde_json::to_vec(&serde_json::json!({"schema_version":3,
        "destination_namespace_hash":"a".repeat(64),"generation":generation}))
        .unwrap()
    };
    let old = progress(1);
    write(&path, &old);
    let previous = ProgressRecovery::synthetic(&index, &"a".repeat(64), 1);
    let mut identity = previous.scope.identity.clone();
    identity.fence_generation = 1;
    ProgressRecovery::seal_import(identity.clone(), 1, &index, Some(&old)).unwrap();
    let companion = fence::sibling(&index, ".v2-ack-receipt");
    let old_seal = std::fs::read(&companion).unwrap();
    // V1 collection continues after a pre-fence failure and advances progress.
    write(&path, &progress(2));
    let original = OriginalProgress::capture(&index).unwrap();
    identity.fence_generation = 2;
    identity.db_id = "new-attempt".into();
    assert_eq!(original.retry_identity(identity.clone()).unwrap(), identity);
    assert!(!companion.exists());
    let archived = failed_imports(&index).unwrap();
    assert_eq!(archived.len(), 1);
    assert_eq!(std::fs::read(&archived[0]).unwrap(), old_seal);
    // Restart with the predecessor archive but no new seal remains retryable.
    let resumed = OriginalProgress::capture(&index).unwrap();
    assert_eq!(resumed.retry_identity(identity.clone()).unwrap(), identity);
    let mut db = sqlite::Sqlite::create_import(&scratch.join("retry.v2.sqlite.import")).unwrap();
    db.control("identity", &identity).unwrap();
    db.control("generation", &2_u64).unwrap();
    resumed.seal(&index, &identity, &mut db).unwrap();
    assert!(failed_imports(&index).unwrap().is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), progress(2));
    let sealed = std::fs::read(&companion).unwrap();
    write(&path, &progress(3));
    let newest = OriginalProgress::capture(&index).unwrap();
    identity.fence_generation = 3;
    // Any final-DB evidence forbids treating the existing seal as unpublished.
    write(&fence::sibling(&index, ".v2.sqlite"), b"published-evidence");
    assert!(newest.retry_identity(identity).is_err());
    assert_eq!(std::fs::read(&companion).unwrap(), sealed);
}
/// [money] interrupted predecessor copy retries without losing exact companion.
#[test]
fn interrupted_predecessor_copy_retries_without_losing_exact_companion() {
    let scratch = crate::test_scratch::ScratchDir::canonical("v2-ack-import-copy-retry");
    let index = scratch.join("index");
    let companion = fence::sibling(&index, ".v2-ack-receipt");
    let original = b"exact-owned-companion";
    write(&companion, original);
    let suffix: String = digest(original)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let partial = fence::sibling(&index, &format!(".v2-ack-receipt.failed-import-{suffix}"));
    write(&partial, &original[..5]);
    preserve_failed_import(&index, &companion, original).unwrap();
    assert_eq!(std::fs::read(&partial).unwrap(), original);
    assert!(!companion.exists());
}
