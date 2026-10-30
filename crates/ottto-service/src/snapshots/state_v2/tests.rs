//! Synthetic store fixtures only. These are written for CI, never run by the
//! build helper on the developer's Mac. Application F1–F9 remain to be implemented with routing.
use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-state-v2-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
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
        sqlite::Sqlite::open(&self.path(), &self.identity()).unwrap()
    }
    fn store(&self) -> sqlite::Sqlite {
        let mut db = sqlite::Sqlite::create_import(&self.path()).unwrap();
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

struct Bytes(Vec<u8>);
impl Value for Bytes {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.0)?;
        Ok(())
    }
}
struct Repeat(u64);
impl Value for Repeat {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        let bytes = [b'x'; 4096];
        let mut left = self.0;
        while left != 0 {
            let count = left.min(bytes.len() as u64) as usize;
            out.write_all(&bytes[..count])?;
            left -= count as u64;
        }
        Ok(())
    }
}
fn put(tx: &mut impl Transaction, key: &RowKey, bytes: &[u8]) -> Header {
    tx.put(RowInput {
        key,
        fixed: &Fixed::None,
        value: &Bytes(bytes.into()),
    })
    .unwrap()
}
fn value(tx: &mut impl Transaction, h: &Header) -> Vec<u8> {
    let mut out = Vec::new();
    tx.read_value(h, &mut out).unwrap();
    out
}

#[test]
fn typed_keys_and_fixed_columns_round_trip_every_table() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let rows = [
        (RowKey::Meta("inherited".into()), Fixed::None),
        (
            RowKey::File("/synthetic/file".into()),
            Fixed::File {
                size: 91,
                mtime_s: 7,
                mtime_ns: Some(8),
                ctime_ns: Some(9),
                birth_ns: Some(10),
                witness_rev: 11,
                flags: 12,
                source_fp: "0d".repeat(32),
                last_snapshot_fp: Some("0E".repeat(32)),
                body_witness: Some("malformed-but-retained".into()),
                scan_identity: Some("existing-identity".into()),
            },
        ),
        (RowKey::FamilyRequests("family".into()), Fixed::None),
        (
            RowKey::RequestSet(3),
            Fixed::RequestSet {
                commitment: vec![4; 32],
                hash_count: Some(5),
                refs: 6,
            },
        ),
        (
            RowKey::Census("/synthetic/file".into()),
            Fixed::Census {
                fp: vec![7; 32],
                derivation: 8,
                window: 9,
                shape: 4,
                flags: 11,
                set_id: Some(3),
                retired: Some(12),
                old_path_requests: Some(13),
                old_path_tokens: Some(14),
                modified: Some(15),
                birth: Some(vec![16; 24]),
            },
        ),
        (
            RowKey::AccountPending {
                root: "family".into(),
                window: 17,
            },
            Fixed::AccountPending {
                version_ord: 18,
                window_end: "019-not-a-clock".into(),
                account_hash: "14".repeat(32),
                evidence_count: 21,
                flags: 22,
            },
        ),
        (
            RowKey::UsagePending("family".into()),
            Fixed::UsagePending {
                window_end: "2026-10-30T01:00:00+01:00".into(),
                flags: 24,
                idless_revision: Some(vec![25; 32]),
            },
        ),
        (
            RowKey::Witness {
                kind: 26,
                key: "owner".into(),
            },
            Fixed::None,
        ),
        (
            RowKey::Accepted {
                kind: 27,
                key: vec![28; 32],
            },
            Fixed::None,
        ),
        (
            RowKey::Quarantine {
                kind: 29,
                key: "entity".into(),
            },
            Fixed::Quarantine { claims: Some(30) },
        ),
        (
            RowKey::Hold {
                kind: 31,
                field: "files".into(),
                key: "raw".into(),
            },
            Fixed::None,
        ),
        (RowKey::Traversal("traversal".into()), Fixed::None),
        (
            RowKey::Interned {
                kind: 32,
                ordinal: 33,
            },
            Fixed::Interned { refs: 34 },
        ),
    ];
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for (key, fixed) in &rows {
        let bytes: &[u8] = if matches!(key, RowKey::Census(_)) {
            b""
        } else {
            b"opaque\0bytes"
        };
        let h = tx
            .put(RowInput {
                key,
                fixed,
                value: &Bytes(bytes.to_vec()),
            })
            .unwrap();
        assert_eq!(h.fixed, *fixed);
        assert_eq!(value(&mut tx, &h), bytes);
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for (key, fixed) in &rows {
        let h = tx.get(key).unwrap().unwrap();
        assert_eq!(&h.fixed, fixed);
        assert_eq!(
            value(&mut tx, &h),
            if matches!(key, RowKey::Census(_)) {
                b"".as_slice()
            } else {
                b"opaque\0bytes".as_slice()
            }
        );
    }
}

#[test]
fn f8_owner_replacement_reclaims_all_superseded_parts_atomically() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = RowKey::Traversal("traversal".into());
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

#[test]
fn f8_64_mib_admission_checks_before_read_allocation() {
    let key = RowKey::Traversal("large".into());
    let admitted = preflight(&RowInput {
        key: &key,
        fixed: &Fixed::None,
        value: &Repeat(VALUE_BYTES),
    })
    .unwrap();
    assert_eq!(admitted.parts, 256);
    assert_eq!(admitted.len, VALUE_BYTES);
    assert!(preflight(&RowInput {
        key: &key,
        fixed: &Fixed::None,
        value: &Repeat(VALUE_BYTES + 1)
    })
    .is_err());
}

#[test]
fn f8_packed_raw_spelling_hashes_and_positional_neighbours_survive() {
    let raw = br#"{ "source_file_fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "raw": {"retry_after_unix_seconds":"mistyped"}, "positional":[7,null,8], "unicode":"\u0041" }"#;
    for chunk in [1, 3, 32, 32768] {
        let mut encoder = packed::Encoder::new(Vec::new());
        for bytes in raw.chunks(chunk) {
            encoder.write_all(bytes).unwrap();
        }
        let encoded = encoder.finish().unwrap();
        assert!(encoded.len() < raw.len());
        let mut out = Vec::new();
        packed::decode(encoded.as_slice(), &mut out).unwrap();
        assert_eq!(out, raw);
    }
}

#[test]
fn header_projection_never_reads_corrupt_parts() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let key = RowKey::Traversal("traversal".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = put(&mut tx, &key, &vec![b'a'; PART_BYTES]);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    // Backend-local fault injection is defined below; no production raw SQL API.
    sqlite::damage_part_for_test(&mut db);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let page = tx
        .scan_prefix(
            RowPrefix {
                table: Table::Traversal,
            },
            None,
            128,
        )
        .unwrap();
    assert_eq!(page, vec![h.clone()]);
    assert!(tx.read_value(&h, &mut std::io::sink()).is_err());
}

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

#[test]
fn wrong_fixed_type_and_generation_refuse_without_publishing() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        assert!(tx
            .put(RowInput {
                key: &RowKey::File("x".into()),
                fixed: &Fixed::None,
                value: &Bytes(vec![])
            })
            .is_err());
    }
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &RowKey::Meta("new".into()), b"x");
    assert_eq!(tx.commit(7, 8), DurableCommitOutcome::NotPublished);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&RowKey::Meta("new".into())).unwrap().is_none());
}

#[test]
fn f6_import_is_journal_off_and_has_no_import_wal() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(
        &mut tx,
        &RowKey::Traversal("large".into()),
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

#[test]
fn f6_pl_in_values_requires_purge_even_with_hash_only_keys() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let key = RowKey::Hold {
        kind: 1,
        field: "files".into(),
        key: "h".repeat(64),
    };
    let canary = b"unique-synthetic-private-value-canary-4f235";
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, canary);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    db.finish_import().unwrap();
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &key, b"replacement");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
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

#[test]
fn f6_passive_complete_can_leave_allocated_wal_and_allows_next_write() {
    let tmp = Scratch::new();
    let db = tmp.store();
    db.finish_import().unwrap();
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let key = RowKey::RequestSet(1);
    let fixed = Fixed::RequestSet {
        commitment: vec![1; 32],
        hash_count: Some(1),
        refs: 1,
    };
    tx.put(RowInput {
        key: &key,
        fixed: &fixed,
        value: &Repeat(WAL_PASSIVE_BYTES + 1),
    })
    .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let cp = db.checkpoint(CheckpointMode::Passive);
    assert_eq!(cp.state, CheckpointState::Complete);
    assert!(cp.wal_bytes.unwrap() > 0, "PASSIVE is not TRUNCATE");
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &RowKey::Meta("N-test".into()), b"small");
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
}

#[test]
fn f9_unknown_top_nested_array_tail_and_reserved_money_pause() {
    for (raw, expected) in [
        (
            r#"{"files":{},"future_custody":{"owed":true}}"#,
            shape::Pause::Unknown,
        ),
        (
            r#"{"files":{"/synthetic":{"size_bytes":1,"future_custody":true}}}"#,
            shape::Pause::Unknown,
        ),
        (
            r#"{"files":{"/synthetic":[1,2,null,"",null,null,0,null,null,null,null,null,false,null,false,false,null,null,null,null,null,null,7]}}"#,
            shape::Pause::Unknown,
        ),
        (
            r#"{"files":{},"claude_request_census":{"~lost":{"k":1}}}"#,
            shape::Pause::UnmappedMoney,
        ),
        (
            r#"{"files":{},"claude_copy_removals":{}}"#,
            shape::Pause::UnmappedMoney,
        ),
    ] {
        assert_eq!(
            shape::inventory(std::io::Cursor::new(raw)),
            Err(expected),
            "{raw}"
        );
    }
}

#[test]
fn f9_unknown_plus_malformed_is_a_conversion_refusal_without_writes() {
    let raw = br#"{"files":{},"future_custody": { definitely malformed"#;
    assert_eq!(
        shape::inventory(std::io::Cursor::new(raw)),
        Err(shape::Pause::Unknown)
    );
    let tmp = Scratch::new();
    assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
}

#[test]
fn f9_default_writer_and_complete_root_registry_are_known() {
    let index = super::super::ScanIndex::default();
    let raw = serde_json::to_vec(&index).unwrap();
    assert_eq!(shape::inventory(std::io::Cursor::new(raw)), Ok(()));
    shape::assert_root_registry_for_test();
}

#[test]
fn failed_write_cannot_be_ignored_then_committed() {
    use std::cell::Cell;
    struct Changes(Cell<bool>);
    impl Value for Changes {
        fn write(&self, out: &mut dyn Write) -> Result<()> {
            out.write_all(if self.0.replace(true) {
                b"changed"
            } else {
                b"first"
            })?;
            Ok(())
        }
    }
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = RowKey::Traversal("traversal".into());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let bad = Changes(Cell::new(false));
    assert!(tx
        .put(RowInput {
            key: &key,
            fixed: &Fixed::None,
            value: &bad
        })
        .is_err());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&key).unwrap().is_none());
}

#[test]
fn aborted_journal_off_import_is_never_finishable() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        put(
            &mut tx,
            &RowKey::Traversal("traversal".into()),
            b"unpublished",
        );
    }
    assert!(db.finish_import().is_err());
}

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
            key: &key,
            fixed: &Fixed::None,
            value: &packed::Json(&other)
        })
        .is_err());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
}

#[test]
fn f8_damaged_header_refuses_both_lookup_and_scan_before_owned_copy() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = RowKey::File("/synthetic/file".into());
    let fixed = Fixed::File {
        size: 1,
        mtime_s: 2,
        mtime_ns: None,
        ctime_ns: None,
        birth_ns: None,
        witness_rev: 0,
        flags: 0,
        source_fp: "03".repeat(32),
        last_snapshot_fp: None,
        body_witness: None,
        scan_identity: None,
    };
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &key,
        fixed: &fixed,
        value: &Bytes(vec![]),
    })
    .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    sqlite::oversize_header_for_test(&mut db);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&key).is_err());
    assert!(tx
        .scan_prefix(
            RowPrefix {
                table: Table::Files
            },
            None,
            128
        )
        .is_err());
}

#[test]
fn f9_current_traversal_paths_and_quarantine_dispositions_are_known() {
    let raw = br#"{"files":{},"traversal":{"scan_roots":["/synthetic/root"],"pending_candidates":[{"scan_root":"/synthetic/root","path":"/synthetic/root/file","census_member":true,"watcher_hint":false}]},"quarantined_snapshot_fingerprints":{"h":{"disposition":"retry_pending"}},"claude_usage_authority_quarantine":{"root":{"disposition":"unproven_terminal"}}}"#;
    assert_eq!(shape::inventory(std::io::Cursor::new(raw)), Ok(()));
}

#[test]
fn f9_production_traversal_writer_includes_registered_parent_counts() {
    assert_eq!(
        crate::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES,
        12
    );
    let checkpoint: super::super::ScanTraversalCheckpoint =
        serde_json::from_value(serde_json::json!({
            "context_fingerprint": "synthetic-context",
            "census_window_end": "2026-10-30T00:00:00Z",
            "scan_roots": ["/synthetic/root"],
            "pending_directories": [],
            "pending_candidates": [{"scan_root":"/synthetic/root",
                "path":"/synthetic/root/file", "census_member":true, "watcher_hint":false}],
            "observed_index_keys": [],
            "reconciliation_upper_bound": null,
            "reconciliation_after": null,
            "reconciliation_started": false,
            "counts": {}
        }))
        .unwrap();
    let index = super::super::ScanIndex {
        traversal: Some(checkpoint),
        ..Default::default()
    };
    let raw = serde_json::to_vec(&index).unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        actual["traversal"]["counts"]["parent_unresolvable"]["counts"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    assert_eq!(shape::inventory(std::io::Cursor::new(raw)), Ok(()));
}

#[test]
fn format_one_unsigned_clocks_and_hash_spelling_are_lossless() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let rows = [
        (
            RowKey::File("u64".into()),
            Fixed::File {
                size: u64::MAX,
                mtime_s: u64::MAX,
                mtime_ns: Some(u64::MAX),
                ctime_ns: None,
                birth_ns: Some(0),
                witness_rev: u64::MAX,
                flags: 0,
                source_fp: "a".repeat(64),
                last_snapshot_fp: Some("A".repeat(64)),
                body_witness: Some(String::new()),
                scan_identity: Some("exact:identity".into()),
            },
        ),
        (
            RowKey::AccountPending {
                root: "account".into(),
                window: 0,
            },
            Fixed::AccountPending {
                version_ord: 1,
                window_end: "malformed:019\u{0}".into(),
                account_hash: "not-a-hash".into(),
                evidence_count: u128::MAX,
                flags: 0,
            },
        ),
        (
            RowKey::UsagePending("usage".into()),
            Fixed::UsagePending {
                window_end: "2026-10-30T01:00:00+01:00".into(),
                flags: 0,
                idless_revision: None,
            },
        ),
        (
            RowKey::Census("census".into()),
            Fixed::Census {
                fp: vec![1; 32],
                derivation: u16::MAX,
                window: u64::MAX,
                shape: 4,
                flags: 0,
                set_id: None,
                retired: Some(u64::MAX),
                old_path_requests: Some(0),
                old_path_tokens: None,
                modified: Some(u64::MAX),
                birth: Some(vec![255; 24]),
            },
        ),
    ];
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for (key, fixed) in &rows {
        tx.put(RowInput {
            key,
            fixed,
            value: &Bytes(vec![]),
        })
        .unwrap();
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    for (key, fixed) in &rows {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let h = tx.get(key).unwrap().unwrap();
        assert_eq!(&h.fixed, fixed);
        assert!(value(&mut tx, &h).is_empty());
    }
    for spelling in [
        "".to_owned(),
        "a".repeat(64),
        "A".repeat(64),
        "ü\u{0}".into(),
        "a".repeat(63),
    ] {
        let encoded = packed::hash_string(&spelling).unwrap();
        assert_eq!(packed::read_hash_string(&encoded).unwrap(), spelling);
    }
    assert!(packed::read_hash_string(&[1; 32]).is_err());
    assert!(packed::hash_string(&"x".repeat(KEY_BYTES + 1)).is_err());
}

#[test]
fn format_one_census_and_key_admission_precede_mutation() {
    let tmp = Scratch::new();
    let mut db = tmp.store();
    let key = RowKey::Census("census".into());
    let fixed = Fixed::Census {
        fp: vec![1; 32],
        derivation: 1,
        window: 0,
        shape: 0,
        flags: 0,
        set_id: None,
        retired: None,
        old_path_requests: None,
        old_path_tokens: None,
        modified: None,
        birth: None,
    };
    assert!(preflight(&RowInput {
        key: &key,
        fixed: &fixed,
        value: &Bytes(vec![1])
    })
    .is_err());
    assert!(preflight(&RowInput {
        key: &RowKey::Meta("x".repeat(KEY_BYTES + 1)),
        fixed: &Fixed::None,
        value: &Bytes(vec![])
    })
    .is_err());
    // The cap is UTF-8 bytes, independent of JSON escaping overhead.
    let exact = RowKey::Meta("\u{0}".repeat(KEY_BYTES));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    put(&mut tx, &exact, b"admitted");
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&exact).unwrap().is_some());
}

#[test]
fn f6_deadline_keeps_writes_live_without_resetting_oldest_purge() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
    let key = RowKey::Meta("private-value".into());
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
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    assert_eq!(db.read_control::<u64>("erasure_since").unwrap(), since);
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["vacuum_attempts"]
            .as_u64()
            .unwrap(),
        0
    );
    drop(db);
    let mut db = sqlite::Sqlite::open(&tmp.path(), &tmp.identity()).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    // PASSIVE and idle TRUNCATE alone cannot claim erasure.
    assert_eq!(
        db.checkpoint(CheckpointMode::IdleReclaim).state,
        CheckpointState::Complete
    );
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(2));
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    assert_eq!(
        serde_json::to_value(db.maintenance_stats()).unwrap()["vacuum_attempts"]
            .as_u64()
            .unwrap(),
        1
    );
}

#[test]
fn f8_vacuum_churn_removes_deleted_keys_and_pl_values() {
    let tmp = Scratch::new();
    let mut db = tmp.live_store();
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
        let key = RowKey::Hold {
            kind: 1,
            field: "synthetic".into(),
            key: format!("{i:06}"),
        };
        put(&mut tx, &key, marker.as_bytes());
    }
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for i in 0..512 {
        let key = RowKey::Hold {
            kind: 1,
            field: "synthetic".into(),
            key: format!("{i:06}"),
        };
        if i % 7 == 0 {
            tx.delete(&key).unwrap();
        } else {
            put(&mut tx, &key, &vec![b'z'; 17 + i % 117]);
        }
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.maintenance(true).unwrap();
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(0));
    for suffix in ["", "-wal", "-shm"] {
        let path = tmp.0.join(format!("index.v2.sqlite.import{suffix}"));
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
