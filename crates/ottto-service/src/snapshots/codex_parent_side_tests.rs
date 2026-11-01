//! U1a-2a: Codex parent side verdicts, side scope and side requests (data
//! model, persistence and index lifecycle). No fixture content comes from a
//! provider account.
use super::*;

fn parsed() -> ParsedJsonlFile {
    ParsedJsonlFile {
        snapshots: Vec::new(),
        report: JsonlReadReport::default(),
        recognized_usage_drop_count: 0,
        cause: ownership::PARSER,
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        dropped_usage_record_count: 0,
        terminal_line_loss_count: 0,
        claude_compaction_unlinked_parent_count: 0,
        state_only_blocked_session_ids: BTreeSet::new(),
        codex_parent_session_ref: None,
        codex_parent_ledger_identity_used: None,
        codex_parent_resolution_pending: false,
        codex_parent_ownership_ledger: None,
        codex_parent_unresolvable: None,
        codex_parent_ledger_unusable: None,
        codex_parent_ledger_consulted: false,
        codex_parent_prefix_decided: None,
        codex_parent_proof_used: None,
        codex_parent_proof_refusal: None,
    }
}

fn side_request(state: SideRequestState) -> SideRequest {
    SideRequest {
        dev_ino: (16_777_232, 123_456_789),
        needed_extent: 4096,
        state,
        state_extent: 8192,
        state_ctime: (1_792_540_800, 5),
        attempt_extent: 8192,
        attempt_ctime: (1_792_540_800, 5),
        attempts: 2,
        not_before_unix_seconds: 1_792_540_920,
        needed_charge: None,
        referenced_epoch: 12,
    }
}

#[test]
fn side_verdict_lineage_and_cause_follow_p_own_fork_state() {
    // P is itself a fork whose parent ref overflowed: a deferral sets the
    // ownership hold, the cause and no pending flag.
    let mut deferred = parsed();
    deferred.codex_parent_session_ref = Some("grandparent".into());
    deferred.codex_parent_resolution_pending = true;
    deferred.defer_parent_resolution(CodexParentUnresolvable::DeferredRef);
    assert_eq!(
        codex_parent_side_verdict(&deferred),
        SideVerdict::Held {
            lineage: true,
            cause: CodexParentUnresolvable::DeferredRef.index() as u8,
        }
    );
    // The invalid-census keep discounts the hold lineage itself set.
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&deferred),
        SideVerdict::Settled
    );

    // Still pending: lineage with no evidence.
    let mut pending = parsed();
    pending.codex_parent_session_ref = Some("grandparent".into());
    pending.codex_parent_resolution_pending = true;
    assert_eq!(
        codex_parent_side_verdict(&pending),
        SideVerdict::Held {
            lineage: true,
            cause: CAUSE_NO_EVIDENCE,
        }
    );
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&pending),
        SideVerdict::Settled
    );

    // A cause without a parent ref is not lineage; a real ownership hold
    // with no lineage term survives the keep test.
    let mut unowned = parsed();
    unowned.ownership_incomplete_file_count = 1;
    assert_eq!(
        codex_parent_side_verdict(&unowned),
        SideVerdict::Held {
            lineage: false,
            cause: CAUSE_NO_EVIDENCE,
        }
    );
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&unowned),
        SideVerdict::Held {
            lineage: false,
            cause: CAUSE_NO_EVIDENCE,
        }
    );

    // Dropped usage records downgrade even a lineage-only hold.
    let mut lossy = deferred;
    lossy.dropped_usage_record_count = 1;
    assert!(matches!(
        codex_parent_side_verdict_without_lineage(&lossy),
        SideVerdict::Held { lineage: false, .. }
    ));
}

#[test]
fn side_verdict_serde_is_tagged_and_content_free() {
    let held = SideVerdict::Held {
        lineage: true,
        cause: 10,
    };
    let text = serde_json::to_string(&held).unwrap();
    assert_eq!(text, r#"{"kind":"held","lineage":true,"cause":10}"#);
    assert_eq!(serde_json::from_str::<SideVerdict>(&text).unwrap(), held);
    assert_eq!(
        serde_json::to_string(&SideVerdict::Settled).unwrap(),
        r#"{"kind":"settled"}"#
    );
}

#[test]
fn side_request_round_trips_and_is_bounded() {
    for state in [
        SideRequestState::Live,
        SideRequestState::Evicted,
        SideRequestState::Short { covered: 1024 },
        SideRequestState::Lossy,
        SideRequestState::Unsealed,
    ] {
        let value = side_request(state);
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains("needed_charge"), "{text}");
        assert_eq!(serde_json::from_str::<SideRequest>(&text).unwrap(), value);
        // Realistic values; fixed-size scalars only.
        assert!(text.len() <= 320, "{} {text}", text.len());
        assert_eq!(
            crate::heap_layout_bound::bound(&value, usize::MAX).map(|_| ()),
            crate::heap_layout_bound::layout_supported().then_some(())
        );
    }
    let extreme = SideRequest {
        dev_ino: (u64::MAX, u64::MAX),
        needed_extent: u64::MAX,
        state: SideRequestState::Short { covered: u64::MAX },
        state_extent: u64::MAX,
        state_ctime: (i64::MIN, i64::MIN),
        attempt_extent: u64::MAX,
        attempt_ctime: (i64::MIN, i64::MIN),
        attempts: u8::MAX,
        not_before_unix_seconds: u64::MAX,
        needed_charge: Some(usize::MAX),
        referenced_epoch: u64::MAX,
    };
    let text = serde_json::to_string(&extreme).unwrap();
    // D6(b): `"referenced_epoch":u64::MAX` adds 40 B: 439 → 479 B.
    assert!(text.len() <= 480, "{} {text}", text.len());
    assert_eq!(serde_json::from_str::<SideRequest>(&text).unwrap(), extreme);
}

#[test]
fn side_requests_persist_and_follow_the_index_lifecycle() {
    let empty = serde_json::to_value(ScanIndex::default()).unwrap();
    assert!(empty.get("codex_parent_side_requests").is_none());

    let mut index = ScanIndex::default();
    index
        .codex_parent_side_requests
        .insert("/p.jsonl".into(), side_request(SideRequestState::Live));
    let text = serde_json::to_string(&index).unwrap();
    let loaded: ScanIndex = serde_json::from_str(&text).unwrap();
    assert_eq!(
        loaded.codex_parent_side_requests,
        index.codex_parent_side_requests
    );
    if crate::heap_layout_bound::layout_supported() {
        assert!(
            crate::heap_layout_bound::bound(&index, usize::MAX).unwrap()
                > crate::heap_layout_bound::bound(&ScanIndex::default(), usize::MAX).unwrap()
        );
    }

    // A partial checkpoint carries the working requests.
    let subset =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        subset.codex_parent_side_requests,
        index.codex_parent_side_requests
    );

    // Replay clears them.
    index.prepare_historical_replay("replay-1".into());
    assert!(index.codex_parent_side_requests.is_empty());
}

#[test]
fn codex_side_pass_gates_on_the_previous_selected_save() {
    let cache = sampled_scan::SharedCache::default();
    let path = Path::new("/tmp/ottto-u1a2a/codex-index.json");
    let mut index = ScanIndex::default();
    let first = begin_codex_side_pass(&cache, path, &mut index);
    assert_eq!(first.ns, sampled_scan::side_ledger::namespace_of(path));
    assert!(first.gate.side_allowed && first.gate.first_in_process);
    // The pass did not save: the next one is gated, for this index only.
    assert!(
        !begin_codex_side_pass(&cache, path, &mut index)
            .gate
            .side_allowed
    );
    let other = Path::new("/tmp/ottto-u1a2a/other-index.json");
    assert!(
        begin_codex_side_pass(&cache, other, &mut index)
            .gate
            .side_allowed
    );
    // A partial checkpoint that carried the side fields opens it again.
    let mark = codex_side_save_mark(&cache, path);
    note_codex_side_pass_saved(&cache, path, false, mark);
    let next = begin_codex_side_pass(&cache, path, &mut index);
    assert!(next.gate.side_allowed && !next.gate.first_in_process);
    assert_eq!(index.codex_parent_side_requests, BTreeMap::new());
}

fn temp_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ottto-u1a2a-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("index.json")
}

fn open_stamp(value: serde_json::Value) -> sampled_scan::codex_cursor::OpenStamp {
    serde_json::from_value(value).unwrap()
}

/// `PrefixSeal` and `OpenStamp` at field extremes.
fn extreme_record() -> CodexParentSide {
    let seal = serde_json::json!({
        "stamp": {
            "length": u64::MAX,
            "device": u64::MAX,
            "inode": u64::MAX,
            "modified": [i64::MIN, i64::MIN],
            "changed": [i64::MIN, i64::MIN],
        },
        "scope": "f".repeat(64),
        "sample_len": u32::MAX,
        "head_sha256": "f".repeat(64),
        "boundary_sha256": "f".repeat(64),
        "verified_unix_seconds": u64::MAX,
        "sealed_unix_seconds": u64::MAX,
        "audit_debt_unix_seconds": u64::MAX,
    });
    CodexParentSide {
        verdict: SideVerdict::Held {
            lineage: false,
            cause: u8::MAX,
        },
        seal: serde_json::from_value(seal).unwrap(),
        parsed: open_stamp(serde_json::json!({
            "dev": u64::MAX,
            "ino": u64::MAX,
            "extent": u64::MAX,
            "modified": [i64::MIN, i64::MIN],
            "changed": [i64::MIN, i64::MIN],
        })),
        pace: Some(SidePace {
            not_before_unix_seconds: u64::MAX,
            attempts_floor: u8::MAX,
        }),
        generation: u64::MAX,
        referenced_epoch: u64::MAX,
    }
}

/// A realistic record: the real side scope and a captured stamp.
fn record(parsed: sampled_scan::codex_cursor::OpenStamp) -> CodexParentSide {
    let seal = serde_json::json!({
        "stamp": {
            "length": 4096,
            "device": 16_777_232,
            "inode": 123_456_789,
            "modified": [1_792_540_800, 5],
            "changed": [1_792_540_800, 5],
        },
        "scope": codex_parent_side_scope().0,
        "sample_len": 4096,
        "head_sha256": sha256_hex(&["head"]),
        "boundary_sha256": sha256_hex(&["boundary"]),
        "verified_unix_seconds": 1_792_540_800,
        "sealed_unix_seconds": 1_792_540_800,
    });
    CodexParentSide {
        verdict: SideVerdict::Settled,
        seal: serde_json::from_value(seal).unwrap(),
        parsed,
        pace: None,
        generation: 1,
        referenced_epoch: 0,
    }
}

const SIDE_RECORD_KEYS: &[&str] = &[
    // CodexParentSide
    "verdict",
    "seal",
    "parsed",
    "pace",
    "generation",
    "referenced_epoch",
    // SideVerdict
    "kind",
    "lineage",
    "cause",
    // PrefixSeal
    "stamp",
    "scope",
    "sample_len",
    "head_sha256",
    "boundary_sha256",
    "verified_unix_seconds",
    "sealed_unix_seconds",
    "audit_debt_unix_seconds",
    // FileStamp
    "length",
    "device",
    "inode",
    // FileStamp and OpenStamp
    "modified",
    "changed",
    // OpenStamp
    "dev",
    "ino",
    "extent",
    // SidePace
    "not_before_unix_seconds",
    "attempts_floor",
];

/// U-T53: every key is allowlisted, the only arrays are the 2-integer
/// `modified`/`changed` times, and every string is an enum tag or a
/// SHA-256 digest.
fn assert_content_free(value: &serde_json::Value, key: Option<&str>) {
    match value {
        serde_json::Value::Object(map) => {
            for (name, value) in map {
                assert!(SIDE_RECORD_KEYS.contains(&name.as_str()), "key {name}");
                assert_content_free(value, Some(name));
            }
        }
        serde_json::Value::Array(items) => {
            assert!(matches!(key, Some("modified" | "changed")), "array {key:?}");
            assert_eq!(items.len(), 2, "{key:?}");
            assert!(items.iter().all(serde_json::Value::is_i64), "{key:?}");
        }
        serde_json::Value::String(text) => assert!(
            (key == Some("kind") && ["settled", "held"].contains(&text.as_str()))
                || sha256_hex_is_well_formed(text),
            "{key:?}"
        ),
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {}
        serde_json::Value::Null => panic!("null at {key:?}"),
    }
}

#[test]
fn open_stamp_round_trips_as_content_free_scalars() {
    let path = temp_path("open-stamp").with_extension("jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let stamp =
        sampled_scan::codex_cursor::OpenStamp::capture(&File::open(&path).unwrap()).unwrap();
    let value = serde_json::to_value(&stamp).unwrap();
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from(["changed", "dev", "extent", "ino", "modified"])
    );
    assert_eq!(value["extent"], 3);
    assert_eq!(
        serde_json::from_value::<sampled_scan::codex_cursor::OpenStamp>(value.clone()).unwrap(),
        stamp
    );

    // Fail-closed: a missing field or a malformed time is an error.
    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("ino");
    assert!(serde_json::from_value::<sampled_scan::codex_cursor::OpenStamp>(missing).is_err());
    let mut malformed = value;
    malformed["changed"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<sampled_scan::codex_cursor::OpenStamp>(malformed).is_err());
}

#[test]
fn side_record_is_content_free_and_bounded() {
    // U-T53 / U-T40: compact ≤ 1.10 KiB per record at field extremes, key
    // excluded; the on-disk (pretty) difference at the record's real depth
    // ≤ 1.8 KiB.
    let extreme = extreme_record();
    let text = serde_json::to_string(&extreme).unwrap();
    assert!(text.len() <= 1126, "{} {text}", text.len());
    assert_eq!(
        serde_json::from_str::<CodexParentSide>(&text).unwrap(),
        extreme
    );
    assert_content_free(&serde_json::to_value(&extreme).unwrap(), None);

    let key = "/Users/someone/.codex/sessions/2026/10/21/\
               rollout-2026-10-21T05-43-00-0199f0a1-2b3c-7d4e-8f90-a1b2c3d4e5f6.jsonl";
    let mut index = ScanIndex::default();
    let without = serde_json::to_vec_pretty(&index).unwrap().len();
    index.codex_parent_side.insert(key.into(), extreme);
    let with = serde_json::to_vec_pretty(&index).unwrap().len();
    assert!(with - without <= 1843, "{}", with - without);

    let path = temp_path("record").with_extension("jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let parsed =
        sampled_scan::codex_cursor::OpenStamp::capture(&File::open(&path).unwrap()).unwrap();
    let realistic = record(parsed);
    let value = serde_json::to_value(&realistic).unwrap();
    assert!(value.get("pace").is_none());
    assert_content_free(&value, None);
    assert_eq!(
        serde_json::from_value::<CodexParentSide>(value).unwrap(),
        realistic
    );
    assert_eq!(
        crate::heap_layout_bound::bound(&realistic, usize::MAX).is_some(),
        crate::heap_layout_bound::layout_supported()
    );
}

#[test]
fn side_records_persist_decode_per_record_and_follow_the_index_lifecycle() {
    // No side state: none of the new keys, so the file is what a pre-2a
    // daemon writes.
    let empty = serde_json::to_value(ScanIndex::default()).unwrap();
    for key in [
        "codex_parent_side",
        "codex_parent_side_generation",
        "codex_parent_proof_wrap_epoch",
    ] {
        assert!(empty.get(key).is_none(), "{key}");
    }

    let mut index = ScanIndex::default();
    index
        .codex_parent_side
        .insert("/p.jsonl".into(), extreme_record());
    index.codex_parent_side_generation = 3;
    index.codex_parent_proof_wrap_epoch = 2;
    let path = temp_path("side-records");
    index.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(loaded.codex_parent_side, index.codex_parent_side);
    assert_eq!(loaded.codex_parent_side_generation, 3);
    assert_eq!(loaded.codex_parent_proof_wrap_epoch, 2);
    if crate::heap_layout_bound::layout_supported() {
        assert!(
            crate::heap_layout_bound::bound(&index, usize::MAX).unwrap()
                > crate::heap_layout_bound::bound(&ScanIndex::default(), usize::MAX).unwrap()
        );
    }

    // Decoded per record (design rev 2 R1-M5, rev 3 §1.7): an undecodable
    // record is dropped and P has no record (the fence's request path);
    // every other record and field loads, and the index is not quarantined.
    let mut value = serde_json::to_value(&loaded).unwrap();
    value["codex_parent_side"]["/q.jsonl"] = value["codex_parent_side"]["/p.jsonl"].clone();
    value["codex_parent_side"]["/p.jsonl"]["parsed"]["modified"] = serde_json::json!([1]);
    value["codex_parent_side"]["/r.jsonl"] = serde_json::json!({
        "verdict": { "kind": "newer" },
    });
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let lenient = ScanIndex::load(&path).unwrap();
    assert!(path.exists());
    assert_eq!(lenient.generation, loaded.generation);
    assert_eq!(
        lenient.codex_parent_side.keys().collect::<Vec<_>>(),
        ["/q.jsonl"]
    );
    assert_eq!(lenient.codex_parent_side["/q.jsonl"], extreme_record());
    assert_eq!(lenient.codex_parent_side_generation, 3);

    // A non-object field decodes as no records.
    value["codex_parent_side"] = serde_json::json!([1, 2]);
    let decoded: ScanIndex = serde_json::from_value(value).unwrap();
    assert!(decoded.codex_parent_side.is_empty());
    assert_eq!(decoded.codex_parent_proof_wrap_epoch, 2);

    // A partial checkpoint carries the working records and counters.
    let subset =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(subset.codex_parent_side, index.codex_parent_side);
    assert_eq!(subset.codex_parent_side_generation, 3);
    assert_eq!(subset.codex_parent_proof_wrap_epoch, 2);

    // Replay clears the records, never the monotone counters.
    index.prepare_historical_replay("replay-1".into());
    assert!(index.codex_parent_side.is_empty());
    assert_eq!(index.codex_parent_side_generation, 3);
    assert_eq!(index.codex_parent_proof_wrap_epoch, 2);
}

fn file_entry() -> ScanIndexEntry {
    ScanIndexEntry {
        codex_fragment: None,
        size_bytes: 42,
        modified_unix_seconds: 1_700_000_000,
        modified_unix_nanos: None,
        source_file_fingerprint: "sha256:test".to_string(),
        last_snapshot_fingerprint: None,
        last_upload_body_witness: None,
        effective_upload_body_witness_revision: 0,
        scan_identity_version: None,
        codex_joined_member_set: None,
        codex_captured_joined_member_set: None,
        codex_protected_owner: None,
        codex_applied_tier_receipt: None,
        codex_applied_tier_receipt_required: false,
        codex_captured_tier_receipt: None,
        codex_captured_tier_receipt_required: false,
        codex_captured_uncommitted: false,
        codex_counting_v2: false,
        codex_counting_owner: None,
        opened_changed_nanos: 0,
        opened_birth_nanos: 0,
        upload_context_receipt: None,
        evidence_owed: false,
    }
}

/// Test support for the D2 capacity controls outside `snapshots`.
impl ScanIndex {
    /// Adds `parents` side records and side requests at field extremes.
    pub(crate) fn add_codex_side_state_for_test(&mut self, parents: usize) {
        let request = SideRequest {
            dev_ino: (u64::MAX, u64::MAX),
            needed_extent: u64::MAX,
            state: SideRequestState::Short { covered: u64::MAX },
            state_extent: u64::MAX,
            state_ctime: (i64::MIN, i64::MIN),
            attempt_extent: u64::MAX,
            attempt_ctime: (i64::MIN, i64::MIN),
            attempts: u8::MAX,
            not_before_unix_seconds: u64::MAX,
            needed_charge: None,
            referenced_epoch: u64::MAX,
        };
        for n in 0..parents {
            let key = format!(
                "/Users/someone/.codex/sessions/2026/10/21/\
                 rollout-2026-10-21T05-43-00-0199f0a1-2b3c-7d4e-8f90-{n:012}.jsonl"
            );
            self.codex_parent_side.insert(key.clone(), extreme_record());
            self.codex_parent_side_requests.insert(key, request);
        }
    }

    /// (records, requests).
    pub(crate) fn codex_side_state_len_for_test(&self) -> (usize, usize) {
        (
            self.codex_parent_side.len(),
            self.codex_parent_side_requests.len(),
        )
    }
}

/// D4: requests decode per entry. A malformed entry is dropped and counted
/// once at `ScanIndex::load` (`side_request_rearm{decode_dropped}` →
/// `side_requests_rearmed`); every valid sibling keeps its exact pacing,
/// and a corrected save/reload persists only the valid entries.
#[test]
fn side_requests_decode_per_entry_and_drop_only_the_malformed_one() {
    let mut index = ScanIndex::default();
    index
        .codex_parent_side_requests
        .insert("/a.jsonl".into(), side_request(SideRequestState::Live));
    index.codex_parent_side_requests.insert(
        "/c.jsonl".into(),
        side_request(SideRequestState::Short { covered: 1024 }),
    );
    index
        .codex_parent_side
        .insert("/a.jsonl".into(), extreme_record());
    let mut value = serde_json::to_value(&index).unwrap();
    value["codex_parent_side_requests"]["/b.jsonl"] = serde_json::json!({
        "dev_ino": [1, 2],
        "state": { "kind": "newer" },
    });

    take_dropped_codex_side_requests();
    let decoded: ScanIndex = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(take_dropped_codex_side_requests(), 1);
    assert_eq!(
        decoded.codex_parent_side_requests,
        index.codex_parent_side_requests
    );
    assert_eq!(decoded.codex_parent_side, index.codex_parent_side);

    let path = temp_path("requests-mixed");
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let (loaded, counts) = crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
        ScanIndex::load(&path).unwrap()
    });
    assert_eq!(counts.side_requests_rearmed, 1);
    assert!(path.exists());
    assert_eq!(
        loaded.codex_parent_side_requests,
        index.codex_parent_side_requests
    );
    assert_eq!(loaded.codex_parent_side, index.codex_parent_side);

    // Corrected save/reload: only the valid entries persist, nothing drops.
    let mut loaded = loaded;
    loaded.save(&path).unwrap();
    assert!(!fs::read_to_string(&path).unwrap().contains("/b.jsonl"));
    let (reloaded, counts) =
        crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
            ScanIndex::load(&path).unwrap()
        });
    assert_eq!(counts.side_requests_rearmed, 0);
    assert_eq!(
        reloaded.codex_parent_side_requests,
        index.codex_parent_side_requests
    );
}

/// D4: all requests malformed still loads, and the rest of the index (ACK
/// fingerprints, held sessions, side records) is what the same file without
/// any request loads as. A legacy index without the map keeps the defaults.
/// The map's outer shape is not relaxed: a non-object still quarantines.
#[test]
fn malformed_or_absent_side_requests_leave_the_rest_of_the_index_alone() {
    let mut index = ScanIndex::default();
    index.accepted_snapshot_fingerprints.insert("a".repeat(64));
    index
        .codex_state_only_blocked_session_ids
        .insert("held-session".into());
    index
        .codex_parent_side
        .insert("/p.jsonl".into(), extreme_record());
    let legacy = serde_json::to_value(&index).unwrap();
    assert!(legacy.get("codex_parent_side_requests").is_none());
    let legacy_path = temp_path("requests-legacy");
    fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
    let (expected, counts) =
        crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
            ScanIndex::load(&legacy_path).unwrap()
        });
    assert_eq!(counts.side_requests_rearmed, 0);
    assert!(expected.codex_parent_side_requests.is_empty());
    assert!(expected
        .accepted_snapshot_fingerprints
        .contains(&"a".repeat(64)));

    let mut value = legacy.clone();
    value["codex_parent_side_requests"] = serde_json::json!({
        "/p.jsonl": 7,
        "/q.jsonl": { "state": { "kind": "live" } },
    });
    let path = temp_path("requests-all-malformed");
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let (loaded, counts) = crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
        ScanIndex::load(&path).unwrap()
    });
    assert_eq!(counts.side_requests_rearmed, 2);
    assert!(path.exists());
    assert_eq!(
        serde_json::to_value(&loaded).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );

    value["codex_parent_side_requests"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(
        ScanIndex::load(&path).is_err(),
        "an unsupported outer shape refuses in place"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Original syntax failure still exercises the existing quarantine contract.
    fs::write(&path, b"{\"files\":").unwrap();
    let rebuilt = ScanIndex::load(&path).unwrap();
    assert!(!path.exists());
    assert!(rebuilt.accepted_snapshot_fingerprints.is_empty());
}

/// D4: a dropped request is absent scheduling evidence only. Reloading the
/// same corrupt file in the same process never resets the ledger's charge
/// (C14 restores it every time), and the drop creates no record, so it can
/// never admit a child by itself.
#[test]
fn a_dropped_request_never_resets_the_ledger_charge_or_admits() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = sampled_scan::SharedCache::default();
    let path = temp_path("requests-ledger");
    let p_key = "/p.jsonl";
    let mut index = ScanIndex::default();
    index.files.insert(p_key.into(), file_entry());
    index.save(&path).unwrap();

    // The hydrated request has no loaded epoch: 0, unknown (D6(b)).
    let charged = SideRequest {
        attempts: 3,
        not_before_unix_seconds: 1_792_541_000,
        referenced_epoch: 0,
        ..side_request(SideRequestState::Live)
    };
    let key = sampled_scan::side_ledger::LedgerKey {
        ns: sampled_scan::side_ledger::namespace_of(&path),
        p: sampled_scan::side_ledger::parent_of(p_key),
        dev: charged.dev_ino.0,
        ino: charged.dev_ino.1,
    };
    let entry = sampled_scan::side_ledger::LedgerEntry::of_request(&charged);
    assert!(cache
        .side_ledger()
        .charge(key, entry, 1_792_540_900)
        .is_ok());

    let mut value = serde_json::to_value(ScanIndex::load(&path).unwrap()).unwrap();
    value["codex_parent_side_requests"] = serde_json::json!({});
    value["codex_parent_side_requests"][p_key] = serde_json::json!({ "dev_ino": "bad" });
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    for _ in 0..2 {
        let (mut loaded, counts) =
            crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
                ScanIndex::load(&path).unwrap()
            });
        assert_eq!(counts.side_requests_rearmed, 1);
        assert!(loaded.codex_parent_side_requests.is_empty());
        assert!(loaded.codex_parent_side.is_empty());
        begin_codex_side_pass(&cache, &path, &mut loaded);
        assert_eq!(loaded.codex_parent_side_requests[p_key], charged);
        assert!(loaded.codex_parent_side.is_empty());
        let held = *cache.side_ledger().get(&key).unwrap();
        assert!(held.same_projection(&entry));
    }
}

/// Row 32 / D6(b) fixtures: P's key carries its session id in its name.
const SWEPT: &str = "/s/rollout-2026-10-21T05-43-00-0199f0a1-2b3c-7d4e-8f90-000000000001.jsonl";

fn epoch_request(state: SideRequestState, referenced_epoch: u64) -> SideRequest {
    SideRequest {
        referenced_epoch,
        ..side_request(state)
    }
}

/// D6(b): an unset epoch keeps a request's bytes exactly (legacy identity);
/// a set one adds only its own member, and the request owns no heap.
#[test]
fn a_zero_request_epoch_keeps_the_legacy_bytes() {
    let legacy = epoch_request(SideRequestState::Live, 0);
    let text = serde_json::to_string(&legacy).unwrap();
    assert!(!text.contains("referenced_epoch"), "{text}");
    let decoded = serde_json::from_str::<SideRequest>(&text).unwrap();
    assert_eq!(decoded, legacy);
    assert_eq!(serde_json::to_string(&decoded).unwrap(), text);
    let stamped = serde_json::to_string(&epoch_request(SideRequestState::Live, 12)).unwrap();
    assert_eq!(
        stamped.len(),
        text.len() + r#","referenced_epoch":12"#.len()
    );
    // In memory: inline scalars only (≤ 128 B with the epoch).
    assert!(std::mem::size_of::<SideRequest>() <= 128);
    if crate::heap_layout_bound::layout_supported() {
        let mut index = ScanIndex::default();
        index
            .codex_parent_side_requests
            .insert(SWEPT.into(), legacy);
        let zero = crate::heap_layout_bound::bound(&index, usize::MAX).unwrap();
        index.codex_parent_side_requests.insert(
            SWEPT.into(),
            epoch_request(SideRequestState::Live, u64::MAX),
        );
        assert_eq!(
            crate::heap_layout_bound::bound(&index, usize::MAX).unwrap(),
            zero,
            "the epoch's value never changes the walked bound"
        );
    }
}
