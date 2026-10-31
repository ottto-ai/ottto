//! Synthetic store fixtures only. These are written for CI, never run by the
//! build helper on the developer's Mac. Application F1–F9 remain to be implemented with routing.
use super::*;
use std::fs;
use std::path::PathBuf;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(crate::test_scratch::canonical_private_dir("ottto-state-v2"))
    }
    fn path(&self) -> PathBuf {
        self.0.join("index.v2.sqlite.import")
    }
    fn identity(&self) -> Identity {
        Identity {
            format: FORMAT,
            db_id: "synthetic-test-db".into(),
            fence_generation: 0,
            binding: super::super::scan_index_persistence::Binding {
                source: super::super::scan_index_persistence::Source::Claude,
                namespace_hash: "a".repeat(64),
            },
        }
    }
    fn live_store(&self) -> sqlite::Sqlite {
        self.store().finish_import().unwrap();
        {
            let mut db = sqlite::Sqlite::open(&self.path(), &self.identity()).unwrap();
            db.path_extractor(test_paths);
            db
        }
    }
    fn store(&self) -> sqlite::Sqlite {
        let mut db = sqlite::Sqlite::create_import(&self.path()).unwrap();
        db.path_extractor(test_paths);
        db.control("identity", &self.identity()).unwrap();
        db.control("generation", &0_u64).unwrap();
        db
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn repeat(len: u64) -> Vec<u8> {
    vec![b'x'; len as usize]
}
fn put(tx: &mut impl Transaction, key: &RowKey, bytes: &[u8]) -> Header {
    tx.put(RowInput {
        value_version: 1,
        key,
        fixed: &Fixed::None,
        value: bytes,
    })
    .unwrap()
}
fn value(tx: &mut impl Transaction, h: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    tx.read_value(h, &mut out).unwrap();
    out
}

/// [format] f8 owner replacement reclaims all superseded parts atomically.
#[test]
fn f8_owner_replacement_reclaims_all_superseded_parts_atomically() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("traversal".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = put(&mut tx, &key, &vec![b'a'; PART_BYTES * 2 + 1]);
    assert_eq!(h.parts, 3);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let smaller = put(&mut tx, &key, b"inline");
        assert_eq!(smaller.parts, 0);
        // An uncommitted generation rolls back BOTH the value and old parts.
    }
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert_eq!(tx.get(&key).unwrap().unwrap(), h);
    drop(tx);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, &vec![b'b'; PART_BYTES + 1]);
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.validate_parts().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"inline");
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    db.validate_parts().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    assert!(tx.delete(&key).unwrap());
    assert_eq!(tx.commit(3, 4), DurableCommitOutcome::Committed(4));
    db.validate_parts().unwrap();
}

/// [format] f8 64 mib admission checks before read allocation.
#[test]
fn f8_64_mib_admission_checks_before_read_allocation() {
    let key = raw_hold("large".into());
    let admitted = preflight(&RowInput {
        value_version: 1,
        key: &key,
        fixed: &Fixed::None,
        value: &repeat(VALUE_BYTES),
    })
    .unwrap();
    assert_eq!(admitted.parts, 256);
    assert_eq!(admitted.len, VALUE_BYTES);
    assert!(preflight(&RowInput {
        value_version: 1,
        key: &key,
        fixed: &Fixed::None,
        value: &repeat(VALUE_BYTES + 1)
    })
    .is_err());
}

/// [format] f8 json raw spelling hashes and positional neighbours survive.
#[test]
fn f8_json_raw_spelling_hashes_and_positional_neighbours_survive() {
    let raw = br#"{ "source_file_fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "raw": {"retry_after_unix_seconds":"mistyped"}, "positional":[7,null,8], "unicode":"\u0041" }"#;
    for chunk in [1, 3, 32, 32768] {
        let mut encoder = codec::Encoder::new(Vec::new());
        for bytes in raw.chunks(chunk) {
            encoder.write_all(bytes).unwrap();
        }
        let encoded = encoder.finish().unwrap();
        assert_eq!(encoded, raw);
        let mut out = Vec::new();
        codec::unpack(encoded.as_slice(), &mut out).unwrap();
        assert_eq!(out, raw);
    }
}

/// [format] header scan cannot hide corrupt value parts.
#[test]
fn header_scan_cannot_hide_corrupt_value_parts() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let key = traversal("traversal".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = put(&mut tx, &key, &vec![b'a'; PART_BYTES]);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    // Backend-local fault injection is defined below; no production raw SQL API.
    sqlite::damage_part_for_test(&mut db);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let page = tx
        .scan_prefix(
            RowPrefix {
                table: Table::Records,
            },
            None,
            128,
        )
        .unwrap();
    assert_eq!(page, vec![h.clone()]);
    assert!(tx.read_value(&h, &mut std::io::sink()).is_err());
}

/// [format] f8 orphan and dangling parts are damage without silent gc.
#[test]
fn f8_orphan_and_dangling_parts_are_damage_without_silent_gc() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    sqlite::orphan_part_for_test(&mut db);
    assert!(db.validate_parts().is_err());
    assert!(
        db.validate_parts().is_err(),
        "a validation must not delete evidence"
    );
}

/// [format] wrong fixed type and generation refuse without publishing.
#[test]
fn wrong_fixed_type_and_generation_refuse_without_publishing() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        assert!(tx
            .put(RowInput {
                value_version: 1,
                key: &file("x".into()),
                fixed: &Fixed::RequestSet {
                    commitment: [1; 32],
                    refs: 1
                },
                value: &[]
            })
            .is_err());
    }
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &test_record("new".into()), b"x");
    assert_eq!(tx.commit(7, 8), DurableCommitOutcome::NotPublished);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&test_record("new".into())).unwrap().is_none());
}

/// [format] f6 import is journal off and has no import wal.
#[test]
fn f6_import_is_journal_off_and_has_no_import_wal() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(
        &mut tx,
        &raw_hold("large".into()),
        &vec![b'a'; PART_BYTES * 3],
    );
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    assert_eq!(sqlite::wal_bytes_for_test(&db), Some(0));
    let identity = tmp.identity();
    db.finish_import().unwrap();
    let mut reopened = sqlite::Sqlite::open(&tmp.path(), &identity).unwrap();
    assert_eq!(reopened.read_control::<u64>("generation").unwrap(), Some(1));
    reopened.validate_parts().unwrap();
}

/// [regress] owner sidecar allows sqlite init migration publication and reopen.
#[test]
fn owner_sidecar_allows_sqlite_init_migration_publication_and_reopen() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let tmp = Scratch::new();
    fs::set_permissions(&tmp.0, fs::Permissions::from_mode(0o700)).unwrap();
    // As in runtime, CheckpointLock spans connection close, rename and reopen.
    let _checkpoint = super::super::CheckpointLock::acquire(&tmp.0.join("index.json")).unwrap();
    let published = tmp.0.join("index.v2.sqlite");
    let owner_path = tmp.0.join("index.v2.sqlite.owner");
    // The real create path runs journal_mode=OFF and migrations with ownership
    // held. A DB-inode flock fails here with SQLITE_BUSY on Darwin.
    let db = tmp.store();
    let owner = fs::symlink_metadata(&owner_path).unwrap();
    assert_eq!(owner.mode() & 0o777, 0o600);
    assert_eq!(owner.nlink(), 1);
    assert_ne!(owner.ino(), fs::metadata(tmp.path()).unwrap().ino());
    assert_eq!(
        sqlite::Sqlite::create_import(&tmp.path())
            .err()
            .unwrap()
            .to_string(),
        "state_v2_exclusive_owner_busy"
    );
    db.finish_import().unwrap();
    fs::rename(tmp.path(), &published).unwrap();
    let mut db = sqlite::Sqlite::open(&published, &tmp.identity()).unwrap();
    assert_eq!(db.stamp().unwrap().0, 0);
    assert_eq!(fs::metadata(&owner_path).unwrap().ino(), owner.ino());
    assert_eq!(
        sqlite::Sqlite::open(&published, &tmp.identity())
            .err()
            .unwrap()
            .to_string(),
        "state_v2_exclusive_owner_busy"
    );
    db.clean_checkpoint().unwrap();
    drop(db);
    let db = sqlite::Sqlite::open(&published, &tmp.identity()).unwrap();
    assert_eq!(db.stamp().unwrap().0, 0);
}

/// [format] owner sidecar rejects symlinks and hardlinks before db creation.
#[test]
fn owner_sidecar_rejects_symlinks_and_hardlinks_before_db_creation() {
    use std::os::unix::fs::PermissionsExt;

    for symlink in [true, false] {
        let tmp = Scratch::new();
        let target = tmp.0.join("target");
        fs::write(&target, b"unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = tmp.0.join("index.v2.sqlite.owner");
        if symlink {
            std::os::unix::fs::symlink(&target, &owner).unwrap();
        } else {
            fs::hard_link(&target, &owner).unwrap();
        }
        assert!(sqlite::Sqlite::create_import(&tmp.path()).is_err());
        assert!(!tmp.path().exists());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
    }
}

/// [format] f5 independent identity mismatch refuses before wal mutation.
#[test]
fn f5_independent_identity_mismatch_refuses_before_wal_mutation() {
    let tmp = Scratch::new();
    let db = tmp.store();
    db.finish_import().unwrap();
    let before = fs::read(tmp.path()).unwrap();
    let mut other = tmp.identity();
    other.db_id = "different-custody".into();
    assert!(sqlite::Sqlite::open(&tmp.path(), &other).is_err());
    assert_eq!(fs::read(tmp.path()).unwrap(), before);
    assert!(!tmp.0.join("index.v2.sqlite.import-wal").exists());
    assert!(!tmp.0.join("index.v2.sqlite.import-shm").exists());
}

/// [format] f6 pl in values requires purge even with hash only keys.
#[test]
fn f6_pl_in_values_requires_purge_even_with_hash_only_keys() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let key = raw_hold("h".repeat(64));
    let canary = b"unique-synthetic-private-value-canary-4f235";
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, canary);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    db.finish_import().unwrap();
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    db.path_extractor(test_paths);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"replacement");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    age_erasure(&mut db, 13 * 3600);
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    for suffix in ["", "-wal", "-shm"] {
        let p = tmp.0.join(format!("index.v2.sqlite.import{suffix}"));
        if p.exists() {
            let bytes = fs::read(p).unwrap();
            assert!(!bytes.windows(canary.len()).any(|w| w == canary));
        }
    }
}

/// [format] f6 passive complete can leave allocated wal and allows next write.
#[test]
fn f6_passive_complete_can_leave_allocated_wal_and_allows_next_write() {
    let tmp = Scratch::new();
    let db = tmp.store();
    db.finish_import().unwrap();
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    db.path_extractor(test_paths);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let key = RowKey::RequestSet(1);
    let fixed = Fixed::RequestSet {
        commitment: [1; 32],
        refs: 1,
    };
    tx.put(RowInput {
        value_version: 1,
        key: &key,
        fixed: &fixed,
        value: &repeat(WAL_PASSIVE_BYTES + 1),
    })
    .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let cp = db.checkpoint(CheckpointMode::Passive);
    assert_eq!(cp.state, CheckpointState::Complete);
    assert!(cp.wal_bytes.unwrap() > 0, "PASSIVE is not TRUNCATE");
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &test_record("N-test".into()), b"small");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
}

/// [format] f9 unknown top nested array tail and reserved money pause.
#[test]
fn f9_unknown_top_nested_array_tail_and_reserved_money_pause() {
    for (raw, expected) in [
        (
            r#"{"files":{},"future_custody":{"owed":true}}"#,
            codec::Pause::Unknown,
        ),
        (
            r#"{"files":{"/synthetic":{"size_bytes":1,"future_custody":true}}}"#,
            codec::Pause::Unknown,
        ),
        (
            r#"{"files":{"/synthetic":[1,2,null,"",null,null,0,null,null,null,null,null,false,null,false,false,null,null,null,null,null,null,7]}}"#,
            codec::Pause::Unknown,
        ),
        (
            r#"{"files":{},"claude_request_census":{"~lost":{"k":1}}}"#,
            codec::Pause::Unknown,
        ),
        (
            r#"{"files":{},"claude_copy_removals":{}}"#,
            codec::Pause::Unknown,
        ),
    ] {
        assert_eq!(
            codec::inventory(std::io::Cursor::new(raw)),
            Err(expected),
            "{raw}"
        );
    }
}

/// [format] f9 unknown plus malformed is a conversion refusal without writes.
#[test]
fn f9_unknown_plus_malformed_is_a_conversion_refusal_without_writes() {
    let raw = br#"{"files":{},"future_custody": { definitely malformed"#;
    assert_eq!(
        codec::inventory(std::io::Cursor::new(raw)),
        Err(codec::Pause::Unknown)
    );
    let tmp = Scratch::new();
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
}

/// [format] aborted journal off import is never finishable.
#[test]
fn aborted_journal_off_import_is_never_finishable() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        put(&mut tx, &traversal("traversal".into()), b"unpublished");
    }
    assert!(db.finish_import().is_err());
}

/// [format] independent identity is write once.
#[test]
fn independent_identity_is_write_once() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = RowKey::Meta("identity".into());
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        assert!(tx.delete(&key).is_err());
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    }
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut other = tmp.identity();
    other.db_id = "replacement".into();
    assert!(tx
        .put(RowInput {
            value_version: 1,
            key: &key,
            fixed: &Fixed::None,
            value: &control_json(&other).unwrap()
        })
        .is_err());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
}

/// [format] f6 deadline keeps writes live without resetting oldest purge.
#[test]
fn f6_deadline_keeps_writes_live_without_resetting_oldest_purge() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = test_record("private-value".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"first");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"second");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let since = db.read_control::<u64>("erasure_since").unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"third");
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(3));
    assert_eq!(db.read_control::<u64>("erasure_since").unwrap(), since);
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["vacuum_attempts"]
            .as_u64()
            .unwrap(),
        0
    );
    drop(db);
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    db.path_extractor(test_paths);
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(3));
    // PASSIVE and idle TRUNCATE alone cannot claim erasure.
    assert_eq!(
        db.checkpoint(CheckpointMode::IdleReclaim).state,
        CheckpointState::Complete
    );
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(3));
    age_erasure(&mut db, 13 * 3600);
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["vacuum_attempts"]
            .as_u64()
            .unwrap(),
        1
    );
}

/// [format] f8 vacuum churn removes deleted keys and pl values.
#[test]
fn f8_vacuum_churn_removes_deleted_keys_and_pl_values() {
    let tmp = Scratch::new();
    tmp.store().finish_import().unwrap();
    let database = tmp.0.join("index.v2.sqlite");
    fs::rename(tmp.path(), &database).unwrap();
    let mut db = sqlite::Sqlite::open(&database, &tmp.identity()).unwrap();
    db.path_extractor(test_paths);
    db.set_purge_policy(
        std::time::Duration::from_secs(86400),
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let markers: Vec<String> = (0..512)
        .map(|i| format!("synthetic-purge-marker-{i:06}-{}", "x".repeat(80 + i % 63)))
        .collect();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for (i, marker) in markers.iter().enumerate() {
        let key = raw_hold(format!("{i:06}"));
        put(&mut tx, &key, marker.as_bytes());
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for i in 0..512 {
        let key = raw_hold(format!("{i:06}"));
        if i % 7 == 0 {
            tx.delete(&key).unwrap();
        } else {
            put(&mut tx, &key, &vec![b'z'; 17 + i % 117]);
        }
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    // Remnants from removed backup writers must not outlive erasure debt.
    let backup = tmp.0.join("index.v2.sqlite.migration-backup");
    fs::write(&backup, markers.join("\n")).unwrap();
    let recovery = tmp.0.join("index.v2-recovery");
    fs::create_dir(&recovery).unwrap();
    let interrupted = recovery.join("generation-interrupted");
    fs::create_dir(&interrupted).unwrap();
    fs::write(interrupted.join("private-member"), markers.join("\n")).unwrap();
    age_erasure(&mut db, 13 * 3600);
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    assert!(!backup.exists());
    assert!(!recovery.exists());
    for suffix in ["", "-wal", "-shm"] {
        let path = tmp.0.join(format!("index.v2.sqlite{suffix}"));
        if path.exists() {
            let bytes = fs::read(path).unwrap();
            for marker in &markers {
                assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
            }
        }
    }
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["free_space_admitted"], true);
    assert!(stats["vacuum_latency_ms"].is_u64());
    assert!(stats["vacuum_wal_peak_bytes"].is_u64());
}

/// [format] request set candidates allow collisions and compare complete evidence.
#[test]
fn request_set_candidates_allow_collisions_and_compare_complete_evidence() {
    use interning::{intern_request_set, RequestEvidence};
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let base = RequestEvidence::Account {
        prefixes: "same-prefix",
        fingerprint: "a",
        identity_revision: None,
        hash_count: Some(1),
    };
    let a = intern_request_set(&mut tx, &base).unwrap();
    assert_eq!(intern_request_set(&mut tx, &base).unwrap(), a);
    let b = intern_request_set(
        &mut tx,
        &RequestEvidence::Account {
            prefixes: "same-prefix",
            fingerprint: "b",
            identity_revision: None,
            hash_count: Some(1),
        },
    )
    .unwrap();
    let c = intern_request_set(
        &mut tx,
        &RequestEvidence::Account {
            prefixes: "same-prefix",
            fingerprint: "a",
            identity_revision: Some(""),
            hash_count: Some(1),
        },
    )
    .unwrap();
    let d = intern_request_set(
        &mut tx,
        &RequestEvidence::Census {
            hashes: b"same-prefix",
            hash_count: Some(1),
        },
    )
    .unwrap();
    let e = intern_request_set(
        &mut tx,
        &RequestEvidence::Account {
            prefixes: "same-prefix",
            fingerprint: "a",
            identity_revision: None,
            hash_count: None,
        },
    )
    .unwrap();
    assert_eq!(
        [a, b, c, d, e]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        5
    );
    let header = tx.get(&RowKey::RequestSet(a)).unwrap().unwrap();
    let Fixed::RequestSet { commitment, .. } = &header.fixed else {
        panic!("set columns");
    };
    // Construct a distinct earlier candidate with the SAME lookup digest.
    // Full bytes, rather than lookup uniqueness, must distinguish it on reuse.
    tx.put(RowInput {
        value_version: 1,
        key: &RowKey::RequestSet(90),
        fixed: &Fixed::RequestSet {
            commitment: *commitment,
            refs: 1,
        },
        value: b"collision",
    })
    .unwrap();
    tx.put(RowInput {
        value_version: 1,
        key: &RowKey::Meta("next_request_set_id".into()),
        fixed: &Fixed::None,
        value: b"91",
    })
    .unwrap();
    let candidates = tx
        .request_set_candidates(commitment.as_slice().try_into().unwrap(), 0, 32)
        .unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(intern_request_set(&mut tx, &base).unwrap(), a);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    db.validate_parts().unwrap();
}

/// [format] colliding candidate before exact match is not aliased or overwritten.
#[test]
fn colliding_candidate_before_exact_match_is_not_aliased_or_overwritten() {
    use interning::{intern_request_set, RequestEvidence};
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let base = RequestEvidence::Account {
        prefixes: "prefixes",
        fingerprint: "full-set",
        identity_revision: Some("exact-revision"),
        hash_count: Some(8),
    };
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let a = intern_request_set(&mut tx, &base).unwrap();
    let exact = tx.get(&RowKey::RequestSet(a)).unwrap().unwrap();
    let stored = value(&mut tx, &exact);
    let fixed = exact.fixed.clone();
    // Both candidates remain. The first differs only in its LAST payload byte.
    tx.put(RowInput {
        value_version: 1,
        key: &RowKey::RequestSet(2),
        fixed: &fixed,
        value: &stored,
    })
    .unwrap();
    let mut collision = stored.clone();
    *collision.last_mut().unwrap() ^= 1;
    tx.put(RowInput {
        value_version: 1,
        key: &RowKey::RequestSet(a),
        fixed: &fixed,
        value: &collision,
    })
    .unwrap();
    tx.put(RowInput {
        value_version: 1,
        key: &RowKey::Meta("next_request_set_id".into()),
        fixed: &Fixed::None,
        value: b"3",
    })
    .unwrap();
    assert_eq!(intern_request_set(&mut tx, &base).unwrap(), 2);
    let wrong = tx.get(&RowKey::RequestSet(a)).unwrap().unwrap();
    assert_eq!(value(&mut tx, &wrong), collision);
    let right = tx.get(&RowKey::RequestSet(2)).unwrap().unwrap();
    assert_eq!(value(&mut tx, &right), stored);
    assert!(matches!(right.fixed, Fixed::RequestSet { refs: 2, .. }));
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
}

/// [format] f8 set last reference reclaims parts without reusing ids.
#[test]
fn f8_set_last_reference_reclaims_parts_without_reusing_ids() {
    use interning::{intern_request_set, release_request_set, RequestEvidence};
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let hashes = repeat(PART_BYTES as u64 + 31);
    let evidence = RequestEvidence::Census {
        hashes: &hashes,
        hash_count: None,
    };
    let id = intern_request_set(&mut tx, &evidence).unwrap();
    assert_eq!(intern_request_set(&mut tx, &evidence).unwrap(), id);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), None);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    release_request_set(&mut tx, id).unwrap();
    assert!(tx.get(&RowKey::RequestSet(id)).unwrap().is_some());
    release_request_set(&mut tx, id).unwrap();
    assert!(tx.get(&RowKey::RequestSet(id)).unwrap().is_none());
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    // Shared evidence may contain literal private strings. Last-reference
    // deletion conservatively marks debt even for this synthetic hash stream.
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    db.validate_parts().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let next = intern_request_set(&mut tx, &evidence).unwrap();
    assert!(next > id);
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    // Re-interning allocates a new ID without clearing the erasure obligation.
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
}

/// [format] f6 busy purge retains obligation paces retry and allows in deadline writes.
#[test]
fn f6_busy_purge_retains_obligation_paces_retry_and_allows_in_deadline_writes() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("private".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"old private bytes");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let reader = sqlite::reader_for_test(&db);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"new bytes");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    age_erasure(&mut db, 13 * 3600);
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    let attempted = serde_json::to_value(db.maintenance_stats()).unwrap()["vacuum_attempts"]
        .as_u64()
        .unwrap();
    assert_eq!(attempted, 1);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"still live");
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    drop(reader);
    age_erasure(&mut db, 13 * 3600);
    db.maintenance(true).unwrap();
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["vacuum_attempts"],
        attempted
    );
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(3));
    // Make the original deadline overdue, while the attempt remains in its
    // cooldown. Neither restart nor ordinary writes may claim erasure.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    db.control("erasure_since", &(now - 86401)).unwrap();
    db.maintenance(false).unwrap();
    drop(db.begin(TxnMode::Write).unwrap());
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["erasure_overdue"], true);
    assert_eq!(stats["vacuum_attempts"], attempted);
    drop(db);
    assert!(sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).is_ok());
}

/// [format] f6 restart between vacuum and metadata clear keeps pending debt.
#[test]
fn f6_restart_between_vacuum_and_metadata_clear_keeps_pending_debt() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = test_record("private".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"old");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert_eq!(
        db.checkpoint(CheckpointMode::Purge).state,
        CheckpointState::Complete
    );
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    drop(db);
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    db.path_extractor(test_paths);
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    age_erasure(&mut db, 13 * 3600);
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
}

/// [format] f6 overdue recovery overrides a future attempt clock.
#[test]
fn f6_overdue_recovery_overrides_a_future_attempt_clock() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = test_record("private".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"old");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    db.control("erasure_since", &(now - 86401)).unwrap();
    db.control("erasure_attempt", &(now + 3600)).unwrap();
    db.before_collection().unwrap();
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["vacuum_attempts"], 1);
    assert_eq!(stats["erasure_overdue"], false);
    assert_eq!(stats["erasure_late_completions"], 1);
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    drop(db);
    assert!(sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).is_ok());
}

/// [format] growth retention follows runtime custody through clones subsets and baselines.
#[test]
fn growth_retention_follows_runtime_custody_through_clones_subsets_and_baselines() {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    let mut committed = super::super::ScanIndex::default();
    assert!(!state_v2_growth_retention_active(&committed));
    let v1_bytes = serde_json::to_vec(&committed).unwrap();
    committed.v2_mut().persistence_v2 = Some(Arc::new(Runtime {
        active: true,
        session: std::sync::Mutex::new(None),
    }));
    assert!(state_v2_growth_retention_active(&committed));
    assert_eq!(v1_bytes, serde_json::to_vec(&committed).unwrap());
    let working = committed.clone();
    assert!(Arc::ptr_eq(
        working.v2().persistence_v2.as_ref().unwrap(),
        committed.v2().persistence_v2.as_ref().unwrap()
    ));
    let subset = working.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    assert!(state_v2_growth_retention_active(&subset));
    let mut baseline = super::super::ScanIndex::default();
    baseline.retain_persistence_baseline_from(&subset);
    assert!(state_v2_growth_retention_active(&baseline));
    baseline.retain_persistence_baseline_from(&super::super::ScanIndex::default());
    assert!(!state_v2_growth_retention_active(&baseline));
}
/// [format] c1 same key rewrites and path set diffs.
#[test]
fn c1_same_key_rewrites_and_path_set_diffs() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("queue".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, br#"["/a","/b"]"#);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, br#"["/b","/a","/c"]"#);
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), None);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    put(&mut tx, &key, br#"["/c","/b","/a"]"#);
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), None);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, br#"["/a","/c"]"#);
    assert_eq!(tx.commit(3, 4), DurableCommitOutcome::Committed(4));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(4));
}

/// [format] clean checkpoint is durable and next write marks dirty before mutation.
#[test]
fn clean_checkpoint_is_durable_and_next_write_marks_dirty_before_mutation() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(1));
    // A second owner cannot certify this owner's live connection clean.
    assert!(sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).is_err());
    db.clean_checkpoint().unwrap();
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(0));
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        put(&mut tx, &traversal("uncommitted".into()), b"rollback");
    }
    assert_eq!(db.read_control::<u8>("phase").unwrap(), Some(1));
    db.clean_checkpoint().unwrap();
    drop(db);
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    assert!(db
        .begin(TxnMode::Read)
        .unwrap()
        .get(&traversal("uncommitted".into()))
        .unwrap()
        .is_none());
}

/// [format] purge starts at twelve hours and busy source pauses at twenty.
#[test]
fn purge_starts_at_twelve_hours_and_busy_source_pauses_at_twenty() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("private".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"alias-old");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_success").unwrap(), None);
    age_erasure(&mut db, 13 * 3600);
    db.between_cycles(false).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_success").unwrap(), None);
    age_erasure(&mut db, 21 * 3600);
    db.maintenance(false).unwrap(); // hot paths cannot grant a pause
    assert_eq!(db.read_control::<u64>("erasure_success").unwrap(), None);
    db.between_cycles(false).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    assert_eq!(
        db.read_control::<u64>("erasure_purged_epoch").unwrap(),
        Some(2)
    );
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["maintenance_pauses"],
        1
    );
    // A new deletion keeps its debt, but deadline recovery overrides the
    // normal successful-run cooldown before collection is allowed again.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"new private value");
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    assert_eq!(tx.commit(3, 4), DurableCommitOutcome::Committed(4));
    age_erasure(&mut db, 25 * 3600);
    db.before_collection().unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["erasure_overdue"], false);
    assert_eq!(stats["erasure_late_completions"], 1);
    assert_eq!(stats["erasure_breaches"], 1);
}

/// [format] changed reference diff is atomic and daily drift holds.
#[test]
fn changed_reference_diff_is_atomic_and_daily_drift_holds() {
    use interning::{intern_request_set, RequestEvidence};
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let id = intern_request_set(
        &mut tx,
        &RequestEvidence::Census {
            hashes: &[7; PART_BYTES + 1],
            hash_count: None,
        },
    )
    .unwrap();
    let key = RowKey::RequestSet(id);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.diff_refs(std::slice::from_ref(&key), &[]).unwrap();
        assert!(tx.get(&key).unwrap().is_none());
        // Drop restores the shared value and all its chunks.
    }
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let header = tx.get(&key).unwrap().unwrap();
    tx.read_value(&header, &mut std::io::sink()).unwrap();
    drop(tx);
    fn no_refs(_: &Header, _: &dyn Value, _: &mut dyn FnMut(&RowKey) -> Result<()>) -> Result<()> {
        Ok(())
    }
    db.reference_extractor(no_refs);
    let error = db.maintenance(true).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReferenceDrift));
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["reference_drift"],
        1
    );
    assert!(db.stamp().is_err());
    assert!(db.begin(TxnMode::Write).is_err());
    drop(db);
    assert!(sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).is_err());
}

/// [format] one save commits all dirty rows above soft targets.
#[test]
fn one_save_commits_all_dirty_rows_above_soft_targets() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for row in 0..5_001 {
        put(&mut tx, &traversal(format!("dirty-{row}")), b"evidence");
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    assert!(db.save_over_target());
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for row in 0..5_001 {
        let key = traversal(format!("dirty-{row}"));
        let header = tx.get(&key).unwrap().unwrap();
        assert_eq!(value(&mut tx, &header), b"evidence");
    }
}
/// [format] ceiling rolls back every row and keeps committed headers.
#[test]
fn ceiling_rolls_back_every_row_and_keeps_committed_headers() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("first".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"old");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    sqlite::set_save_ceiling(&mut db, 1024);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"new");
    let error = tx
        .put(RowInput {
            key: &traversal("over-ceiling".into()),
            fixed: &Fixed::None,
            value_version: 1,
            value: &serde_json::to_vec(&"x".repeat(2048)).unwrap(),
        })
        .unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveCeiling));
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::NotPublished);
    assert_eq!(db.save_failure(), Some(Hold::SaveCeiling));
    assert_eq!(db.read_control::<u64>("generation").unwrap(), Some(1));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let header = tx.get(&key).unwrap().unwrap();
    assert_eq!(value(&mut tx, &header), b"old");
}
/// [format] sqlite full at a row or chunk write rolls back the complete save.
#[test]
fn sqlite_full_at_row_or_chunk_write_rolls_back_the_complete_save() {
    let chunked = serde_json::to_vec(&"x".repeat(PART_BYTES)).unwrap();
    for chunk_write in [false, true] {
        let tmp = Scratch::new();
        let mut db = tmp.live_store();
        let key = traversal("uncommitted".into());
        // SQLite's own page cap stands in for a full disk.
        sqlite::cap_pages(&db);
        let mut tx = db.begin(TxnMode::Write).unwrap();
        put(&mut tx, &key, b"evidence");
        let error = if chunk_write {
            tx.put(RowInput {
                value_version: 1,
                key: &traversal("chunked".into()),
                fixed: &Fixed::None,
                value: &chunked,
            })
            .unwrap_err()
        } else {
            // Inline rows fill the free page space, then need a new page.
            (0..)
                .find_map(|n| {
                    tx.put(RowInput {
                        value_version: 1,
                        key: &traversal(format!("row-{n}")),
                        fixed: &Fixed::None,
                        value: &[b'x'; 512],
                    })
                    .err()
                })
                .unwrap()
        };
        assert!(sqlite::disk_full(&error));
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
        assert_eq!(db.save_failure(), Some(Hold::SaveFull));
        assert_eq!(db.read_control::<u64>("generation").unwrap(), Some(0));
        assert!(db
            .begin(TxnMode::Read)
            .unwrap()
            .get(&key)
            .unwrap()
            .is_none());
    }
}

/// [regress] A COMMIT that SQLite refuses (transaction left open) is closed,
/// reopened and classified from the durable generation: NotPublished, no
/// reload demand, nothing visible, and the same save is retryable.
#[test]
fn refused_commit_reopens_and_classifies_not_published() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("uncommitted".into());
    sqlite::fence_commit_writing(&db, "generation");
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"evidence");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    assert!(!db.reload_required());
    assert_eq!(db.save_failure(), None);
    assert_eq!(db.read_control::<u64>("generation").unwrap(), Some(0));
    assert!(db
        .begin(TxnMode::Read)
        .unwrap()
        .get(&key)
        .unwrap()
        .is_none());
    // The fence was connection-local: the reopened store commits the retry.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"evidence");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
}

fn traversal(key: String) -> RowKey {
    RowKey::record("scan_state.traversal", key.into_bytes(), 0).unwrap()
}
fn file(key: String) -> RowKey {
    RowKey::record("file.progress", key.into_bytes(), 0).unwrap()
}
fn census(key: String) -> RowKey {
    RowKey::record("file.census", key.into_bytes(), 0).unwrap()
}
fn raw_hold(key: String) -> RowKey {
    RowKey::record("raw_hold.files", key.into_bytes(), 0).unwrap()
}
fn test_paths(h: &Header, v: &dyn Value, paths: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
    if let RowKey::Record { key_bytes, .. } = &h.key {
        paths(std::str::from_utf8(key_bytes)?)?;
    }
    let mut bytes = Vec::new();
    v.write(&mut bytes)?;
    if let Ok(strings) = serde_json::from_slice::<Vec<String>>(&bytes) {
        for s in strings {
            paths(&s)?;
        }
    } else if !bytes.is_empty() {
        paths(&String::from_utf8(bytes)?)?;
    }
    Ok(())
}
fn age_erasure(db: &mut sqlite::Sqlite, seconds: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    db.control("erasure_since", &now.saturating_sub(seconds))
        .unwrap();
}
/// [format] typed keys and json headers round trip every physical owner.
#[test]
fn typed_keys_and_json_headers_round_trip_every_physical_owner() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let rows = vec![
        (file("file".into()), Fixed::None),
        (census("file".into()), Fixed::None),
        (
            RowKey::record("account_window", b"family".to_vec(), 17).unwrap(),
            Fixed::None,
        ),
        (
            RowKey::record("usage.pending", b"family".to_vec(), 0).unwrap(),
            Fixed::None,
        ),
        (
            RowKey::RequestSet(4),
            Fixed::RequestSet {
                commitment: [5; 32],
                refs: 6,
            },
        ),
        (
            RowKey::record("accepted.activity", Vec::new(), 0).unwrap(),
            Fixed::None,
        ),
    ];
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for (k, f) in &rows {
        let h = tx
            .put(RowInput {
                value_version: 1,
                key: k,
                fixed: f,
                value: b"opaque\0bytes",
            })
            .unwrap();
        assert_eq!(value(&mut tx, &h), b"opaque\0bytes");
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for (k, f) in &rows {
        let h = tx.get(k).unwrap().unwrap();
        assert_eq!(&h.fixed, f);
        assert_eq!(value(&mut tx, &h), b"opaque\0bytes");
    }
}
/// [format] f8 damaged header refuses both lookup and scan before owned copy.
#[test]
fn f8_damaged_header_refuses_both_lookup_and_scan_before_owned_copy() {
    for oversized in [false, true] {
        let tmp = Scratch::new();
        let mut db = tmp.live_store();
        let key = file("file".into());
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            value_version: 1,
            key: &key,
            fixed: &Fixed::None,
            value: &[],
        })
        .unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        if oversized {
            sqlite::oversize_header_for_test(&mut db);
        } else {
            sqlite::corrupt_header_for_test(&mut db);
        }
        let mut tx = db.begin(TxnMode::Read).unwrap();
        assert!(tx.get(&key).is_err());
        assert!(tx
            .scan_prefix(
                RowPrefix {
                    table: Table::Records
                },
                None,
                8
            )
            .is_err());
    }
}
/// [format] format one physical columns match the four table contract.
#[test]
fn format_one_physical_columns_match_the_four_table_contract() {
    let tmp = Scratch::new();
    let db = tmp.store();
    let (tables, unique) = sqlite::schema_for_test(&db);
    assert_eq!(FORMAT, 1);
    assert_eq!(
        tables
            .iter()
            .map(|(name, cols)| (name.as_str(), cols.len()))
            .collect::<Vec<_>>(),
        [
            ("control", 4),
            ("records", 10),
            ("shared_values", 10),
            ("value_chunks", 6)
        ]
    );
    assert!(!unique);
    assert!(sqlite::text_key_refused_for_test(&db));
    assert!(RecordKind::parse("not.registered").is_err());
    assert!(RecordKind::parse("raw_hold.unknown").is_err());
}
/// [format] the two measured >1 MiB whole fields have bounded caps and raw holds stay exact.
#[test]
fn mutable_values_require_segmentation_and_raw_holds_stay_exact() {
    for kind in ["scan_state.traversal", "v1_field.birth_store"] {
        let key = RowKey::record(kind, b"family".to_vec(), 0).unwrap();
        for (size, ok) in [
            (MUTABLE_VALUE_BYTES + 1, true),
            (16 * 1024 * 1024, true),
            (16 * 1024 * 1024 + 1, false),
        ] {
            assert_eq!(
                preflight(&RowInput {
                    value_version: 1,
                    key: &key,
                    fixed: &Fixed::None,
                    value: &repeat(size)
                })
                .is_ok(),
                ok,
                "{kind}: {size}"
            );
        }
    }
    let mutable = file("family".into());
    let raw = raw_hold("family".into());
    for (key, size, ok) in [
        (&mutable, MUTABLE_VALUE_BYTES, true),
        (&mutable, MUTABLE_VALUE_BYTES + 1, false),
        (&raw, VALUE_BYTES, true),
        (&raw, VALUE_BYTES + 1, false),
    ] {
        assert_eq!(
            preflight(&RowInput {
                value_version: 1,
                key,
                fixed: &Fixed::None,
                value: &repeat(size)
            })
            .is_ok(),
            ok
        );
    }
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let bytes = vec![0xff, 0, 0xc3, 0x28, b' '];
    let h = put(&mut tx, &raw, &bytes);
    assert_eq!(value(&mut tx, &h), bytes);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
}
/// [format] extra chunks and shared record owner aliases are refused.
#[test]
fn extra_chunks_and_shared_record_owner_aliases_are_refused() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let rec = RowKey::record("family.requests", 1_u64.to_be_bytes().to_vec(), 0).unwrap();
    let shared = RowKey::RequestSet(1);
    assert_ne!(
        sqlite::owner_for_test(&rec),
        sqlite::owner_for_test(&shared)
    );
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = put(&mut tx, &rec, b"inline");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    sqlite::add_extra_part_for_test(&db, &rec);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.read_value(&h, &mut std::io::sink()).is_err());
}
/// [format] f8 corrupted refcount cannot reclaim evidence or commit sibling changes.
#[test]
fn f8_corrupted_refcount_cannot_reclaim_evidence_or_commit_sibling_changes() {
    use interning::{intern_request_set, release_request_set, RequestEvidence};
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let hashes = repeat(PART_BYTES as u64 + 1);
    let evidence = RequestEvidence::Census {
        hashes: &hashes,
        hash_count: None,
    };
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let id = intern_request_set(&mut tx, &evidence).unwrap();
    assert_eq!(intern_request_set(&mut tx, &evidence).unwrap(), id);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let parts = sqlite::part_count_for_test(&db);
    sqlite::damage_refs_for_test(&db, &RowKey::RequestSet(id));
    let sibling = traversal("sibling".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &sibling, b"rollback");
    assert!(release_request_set(&mut tx, id).is_err());
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::NotPublished);
    assert_eq!(sqlite::part_count_for_test(&db), parts);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&sibling).unwrap().is_none());
    assert!(tx.get(&RowKey::RequestSet(id)).is_err());
}
/// [format] private labels aliases and raw holds create erasure epochs.
#[test]
fn private_labels_aliases_and_raw_holds_create_erasure_epochs() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = file("file".into());
    let fixed = Fixed::None;
    for (g, text) in [(0, "private label"), (1, "changed label")] {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            value_version: 1,
            key: &key,
            fixed: &fixed,
            value: text.as_bytes(),
        })
        .unwrap();
        assert_eq!(tx.commit(g, g + 1), DurableCommitOutcome::Committed(g + 1));
    }
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
}
/// [format] positions and current pointer survive retirement without renumbering.
#[test]
fn positions_and_current_pointer_survive_retirement_without_renumbering() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let kind = "account_window";
    let root = b"family".to_vec();
    let f = Fixed::None;
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for pos in [17, 18, 19] {
        let k = RowKey::record(kind, root.clone(), pos).unwrap();
        tx.put(RowInput {
            value_version: 1,
            key: &k,
            fixed: &f,
            value: &[],
        })
        .unwrap();
    }
    let pointer = RowKey::record("account.current", root.clone(), 0).unwrap();
    put(&mut tx, &pointer, &19_u64.to_be_bytes());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&RowKey::record(kind, root.clone(), 17).unwrap())
        .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let k = RecordKind::parse(kind).unwrap();
    let after = RowKey::record(kind, root.clone(), 17).unwrap();
    let page = tx.scan_kind(&k, Some(&after), 1).unwrap();
    assert_eq!(page.len(), 1);
    assert!(matches!(page[0].key, RowKey::Record { position: 18, .. }));
    assert_eq!(tx.scan_kind(&k, None, 128).unwrap().len(), 2);
    for pos in [18, 19] {
        assert!(tx
            .get(&RowKey::record(kind, root.clone(), pos).unwrap())
            .unwrap()
            .is_some());
    }
    let h = tx.get(&pointer).unwrap().unwrap();
    assert_eq!(value(&mut tx, &h), 19_u64.to_be_bytes());
}

fn test_record(key: String) -> RowKey {
    RowKey::record("raw_hold.files", key.into_bytes(), 0).unwrap()
}

/// [format] an over-cap control refuses before its capability parse, and the
/// failed write cannot be ignored and then committed with a sibling row.
#[test]
fn oversized_control_refuses_before_parse_and_fails_the_save() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("traversal".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"sibling");
    let error = tx
        .put(RowInput {
            value_version: 1,
            key: &RowKey::Meta("minimum_writer_capability".into()),
            fixed: &Fixed::None,
            value: &repeat(CONTROL_BYTES + 1),
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "state_v2_value_admission");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    assert_eq!(db.read_control::<u64>("generation").unwrap(), Some(0));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&key).unwrap().is_none());
}
/// [format] key admission rejects invalid keys before SQLite reads.
#[test]
fn key_admission_rejects_invalid_keys_before_sqlite_reads() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let oversized = RowKey::record("file.entities", vec![b'x'; KEY_BYTES + 1], 0).unwrap();
    assert_eq!(
        tx.get(&oversized).unwrap_err().to_string(),
        "state_v2_key_admission"
    );
    let exhausted = RowKey::record("file.entities", vec![], u64::MAX).unwrap();
    assert!(tx.get(&exhausted).is_err());
    assert!(tx.get(&RowKey::Meta("unregistered".into())).is_err());
}

/// [format] overdue external reader is a breach and recovery precedes collection.
#[test]
fn overdue_external_reader_is_a_breach_and_recovery_precedes_collection() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("private".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"private prior value");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let reader = sqlite::reader_for_test(&db);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"replacement");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    age_erasure(&mut db, 25 * 3600);
    assert!(db.before_collection().is_err());
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["erasure_breaches"], 1);
    assert_eq!(stats["erasure_resume_refusals"], 1);
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    drop(reader);
    // Recovery does not wait for the failed attempt's one-hour backoff.
    db.before_collection().unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["erasure_late_completions"], 1);
    assert_eq!(stats["erasure_overdue"], false);
    assert_eq!(
        db.checkpoint(CheckpointMode::IdleReclaim).wal_bytes,
        Some(0)
    );
}

/// [format] space recovery after restart purges before collection despite recent failure.
#[test]
fn space_recovery_after_restart_purges_before_collection_despite_recent_failure() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = traversal("private".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"private prior value");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&key).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    age_erasure(&mut db, 25 * 3600);
    {
        sqlite::set_space_reader(&mut db, Some(|_| Some(0)));
        assert!(db.before_collection().is_err());
        assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
        assert_eq!(
            serde_json::to_value(db.maintenance_stats()).unwrap()["free_space_admitted"],
            false
        );
    }
    drop(db);
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    db.path_extractor(test_paths);
    // A recent persisted failure and reset in-memory timers cannot defer the
    // first post-recovery acquisition. No file collection precedes this call.
    db.before_collection().unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["erasure_late_completions"],
        1
    );
}

/// [format] external owner lock is counted without clearing overdue debt.
#[test]
fn external_owner_lock_is_counted_without_clearing_overdue_debt() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    db.control("erasure_pending", &1_u64).unwrap();
    age_erasure(&mut db, 25 * 3600);
    db.collection_lock_refused("external_lock");
    let stats = serde_json::to_value(db.maintenance_stats()).unwrap();
    assert_eq!(stats["erasure_breaches"], 1);
    assert_eq!(stats["erasure_vacuum_failed"]["external_lock"], 1);
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(1));
}

/// [regress] an ordinary failed idle purge retains debt without stopping collection or spinning.
#[test]
fn failed_idle_purge_keeps_paced_debt_without_stopping_collection() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    db.control("erasure_pending", &1_u64).unwrap();
    age_erasure(&mut db, 13 * 3600);
    {
        sqlite::set_space_reader(&mut db, Some(|_| Some(0)));
        db.maintenance(true).unwrap();
        let failures = db.read_control::<u64>("erasure_failures").unwrap();
        assert!(failures.is_some_and(|n| n > 0));
        for _ in 0..4 {
            db.before_collection().unwrap();
            db.maintenance(true).unwrap();
        }
        assert_eq!(
            db.read_control::<u64>("erasure_failures").unwrap(),
            failures
        );
        assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(1));
    }
    sqlite::set_space_reader(&mut db, None);
    // Under-deadline space recovery does not turn the idle failure into a
    // blocking wake recovery, and it still respects the saved retry clock.
    db.before_collection().unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(1));
    // Once due, a successful bounded opportunity can clear the same debt.
    drop(db);
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    db.control("erasure_attempt", &0_u64).unwrap();
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
}

/// [regress] repeated failed overdue recovery has bounded pauses and keeps its alarm/debt.
#[test]
fn repeated_overdue_recovery_failure_cannot_stop_collection_indefinitely() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    db.control("erasure_pending", &1_u64).unwrap();
    age_erasure(&mut db, 25 * 3600);
    sqlite::set_space_reader(&mut db, Some(|_| Some(0)));
    assert!(
        db.before_collection().is_err(),
        "overdue startup tries recovery first"
    );
    assert!((0..8).any(|_| db.before_collection().is_ok()));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(1));
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["erasure_overdue"],
        true
    );
    let failures = db.read_control::<u64>("erasure_failures").unwrap();
    db.before_collection().unwrap();
    assert_eq!(
        db.read_control::<u64>("erasure_failures").unwrap(),
        failures
    );
}

/// [format] serial scan propagates maintenance refusal without consuming custody.
#[test]
fn serial_scan_propagates_maintenance_refusal_without_consuming_custody() {
    let mut index = ScanIndex {
        generation: 17,
        ..Default::default()
    };
    index
        .confirmed_empty_files
        .insert("synthetic-private-path".into());
    let route = std::sync::Arc::new(Runtime {
        active: true,
        session: std::sync::Mutex::new(None),
    });
    index.v2_mut().persistence_v2 = Some(route.clone());
    let before = serde_json::to_vec(&index).unwrap();
    let result = super::super::scan_source_roots_with_test_limit(
        super::super::SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        "2026-10-30T12:00:00Z",
        30,
        10,
        false,
    );
    assert!(result.is_err());
    assert_eq!(before, serde_json::to_vec(&index).unwrap());
    assert!(std::sync::Arc::ptr_eq(
        index.v2().persistence_v2.as_ref().unwrap(),
        &route
    ));
}
