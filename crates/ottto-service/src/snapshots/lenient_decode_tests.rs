use super::*;

fn fixture() -> ScanIndex {
    let mut index = ScanIndex::default();
    for n in 0..16 {
        let fingerprint = format!("{n:064x}");
        let key = format!("/synthetic/{n}.jsonl");
        index
            .files
            .insert(key.clone(), tests::manifest_index_entry(Some(&fingerprint)));
        index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([fingerprint.clone()]));
        index
            .snapshot_activity_at
            .insert(fingerprint.clone(), Some("2026-10-22T00:00:00Z".into()));
        index.accepted_snapshot_fingerprints.insert(fingerprint);
    }
    index.quarantined_snapshot_fingerprints.insert(
        "e".repeat(64),
        snapshot_quarantine_record(SnapshotSource::ClaudeCode),
    );
    index
}
fn raw_slot(bytes: &[u8], field: &str, key: &str) -> String {
    let root: BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_slice(bytes).unwrap();
    let slots: BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_str(root[field].get()).unwrap();
    slots[key].get().to_owned()
}
fn corrupt_count(root: &Path) -> usize {
    fs::read_dir(root)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
        .count()
}
fn assert_sibling(index: &ScanIndex) {
    assert_eq!(
        index.files["/synthetic/15.jsonl"].source_file_fingerprint,
        "source"
    );
    assert!(index
        .accepted_snapshot_fingerprints
        .contains(&format!("{:064x}", 15)));
    assert_eq!(
        index.snapshot_activity_at[&format!("{:064x}", 15)].as_deref(),
        Some("2026-10-22T00:00:00Z")
    );
}

#[test]
fn lenient_positive_matrix_load_and_both_cas_readers() {
    for (field, key, bad) in [
        ("snapshot_activity_at", format!("{:064x}", 1), "17"),
        ("snapshot_activity_at", format!("{:064x}", 1), "1e400"),
        ("snapshot_activity_at", format!("{:064x}", 1), "{}"),
        ("accepted_snapshot_fingerprints", String::new(), "17"),
        (
            "accepted_snapshot_fingerprints",
            String::new(),
            "{\"invalid\":true}",
        ),
    ] {
        for bounded in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-positive");
            let path = scratch.as_ref().join("index.json");
            let mut working = fixture();
            working.save(&path).unwrap();
            let mut value = serde_json::to_value(&working).unwrap();
            let sentinel = "HOSTILE_RAW_TOKEN";
            if field == "snapshot_activity_at" {
                value[field][&key] = Value::String(sentinel.into());
            } else {
                value[field]
                    .as_array_mut()
                    .unwrap()
                    .push(Value::String(sentinel.into()));
            }
            let bytes = serde_json::to_string(&value)
                .unwrap()
                .replace(&format!("\"{sentinel}\""), bad)
                .into_bytes();
            fs::write(&path, &bytes).unwrap();
            let before = scan_index_containment_lines_for_test().len();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(loaded.generation, working.generation);
            assert_sibling(&loaded);
            assert!(loaded.decode_holds.is_empty());
            assert_eq!(corrupt_count(scratch.as_ref()), 0);
            let lines = scan_index_containment_lines_for_test();
            assert!(lines[before..]
                .iter()
                .any(|line| line.contains("index kept")));
            assert!(lines[before..]
                .iter()
                .all(|line| !line.contains("HOSTILE") && !line.contains("synthetic")));
            if bounded {
                working.save_with_read_limit(&path, 1024 * 1024).unwrap();
            } else {
                working.save(&path).unwrap();
            }
            assert_sibling(&ScanIndex::load(&path).unwrap());
        }
    }
}

#[test]
fn lenient_opaque_holds_refuse_new_cas_then_round_trip_original_slot() {
    let cases = [
        (
            "files",
            "/synthetic/0.jsonl".to_owned(),
            serde_json::json!({"size_bytes": [], "codex_captured_uncommitted": true, "codex_protected_owner": "protected"}),
        ),
        (
            "quarantined_snapshot_fingerprints",
            "e".repeat(64),
            serde_json::json!({"disposition": "PRIVATE_FUTURE_DISPOSITION", "retry_after_unix_seconds": 0}),
        ),
        (
            "claude_usage_authority_quarantine",
            "family".into(),
            serde_json::json!({"proof_correction": {"owed_member_ids": {"unknown": true}}, "disposition": "unproven_terminal"}),
        ),
        (
            "claude_account_family_pending",
            "family".into(),
            serde_json::json!({"invalid": "false"}),
        ),
        (
            "claude_account_family_witnesses",
            "family".into(),
            serde_json::json!({"members": 17}),
        ),
        (
            "claude_usage_family_pending",
            "family".into(),
            serde_json::json!({"members": 17}),
        ),
        (
            "claude_usage_family_witnesses",
            "family".into(),
            serde_json::json!({"legacy_owners": [17]}),
        ),
    ];
    for (field, key, bad) in cases {
        for bounded in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-hold");
            let path = scratch.as_ref().join("index.json");
            let mut working = fixture();
            working.save(&path).unwrap();
            let generation = working.generation;
            let mut value = serde_json::to_value(&working).unwrap();
            if value.get(field).is_none() {
                value[field] = serde_json::json!({});
            }
            value[field][&key] = bad.clone();
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            let original_slot = raw_slot(&bytes, field, &key);
            fs::write(&path, &bytes).unwrap();
            let result = if bounded {
                working.save_with_read_limit(&path, 1024 * 1024)
            } else {
                working.save(&path)
            };
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("current_index_requires_reload"));
            assert_eq!(working.generation, generation);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(corrupt_count(scratch.as_ref()), 0);
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert!(!loaded.decode_holds.is_empty());
            assert_sibling(&loaded);
            assert_eq!(loaded.generation, generation);
            if field == "quarantined_snapshot_fingerprints" {
                loaded
                    .reason_reoffer_retries
                    .insert(key.clone(), "lease".into());
                assert!(!loaded.quarantine_requires_retry(&key));
                assert!(!loaded.quarantine_requires_retry_body(&key, "different-body"));
            } else if field == "files" {
                assert!(loaded.decode_holds_file(&key));
                assert!(loaded.decode_holds_entity(&format!("{:064x}", 0)));
                loaded.remove_file_entry(&key);
                assert!(loaded.file_snapshot_fingerprints.contains_key(&key));
            } else {
                assert!(loaded.decode_holds_family(&key));
            }
            let subset = loaded.committable_subset(&loaded, &BTreeSet::new(), &BTreeMap::new());
            assert!(subset.decode_holds.same_as(&loaded.decode_holds));
            let subset_bytes = serde_json::to_vec_pretty(&subset).unwrap();
            assert_eq!(raw_slot(&subset_bytes, field, &key), original_slot);
            loaded.resume_after_path = Some("unrelated-progress".into());
            if bounded {
                loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
            } else {
                loaded.save(&path).unwrap();
            }
            assert_eq!(
                raw_slot(&fs::read(&path).unwrap(), field, &key),
                original_slot
            );
            let restarted = ScanIndex::load(&path).unwrap();
            assert!(restarted.decode_holds.same_as(&loaded.decode_holds));
            assert_sibling(&restarted);
        }
    }
}

#[test]
fn lenient_control_matrix_refuses_without_quarantine_or_rewrite() {
    for field in [
        "schema_version",
        "generation",
        "accepted_snapshot_fingerprint_ledger_version",
        "codex_parent_side_generation",
        "codex_parent_proof_seq",
        "codex_parent_proof_wrap_epoch",
        "codex_proof_index_incarnation",
    ] {
        for bad in [
            "null",
            "{}",
            "-1",
            "1e400",
            "18446744073709551616000",
            "256",
            "2.0",
            "\"not-a-token\"",
        ] {
            // Some matrix values are valid native controls; test only hostile combinations.
            if matches!(
                field,
                "generation"
                    | "codex_parent_side_generation"
                    | "codex_parent_proof_seq"
                    | "codex_parent_proof_wrap_epoch"
            ) && bad == "256"
            {
                continue;
            }
            if field == "codex_proof_index_incarnation" && bad.starts_with('"') {
                continue;
            }
            for bounded in [false, true] {
                let scratch = crate::test_scratch::ScratchDir::new("lenient-controls");
                let path = scratch.as_ref().join("index.json");
                let mut working = fixture();
                working.save(&path).unwrap();
                let generation = working.generation;
                let mut value = serde_json::to_value(&working).unwrap();
                value[field] = Value::String("CONTROL_TOKEN".into());
                let bytes = serde_json::to_string(&value)
                    .unwrap()
                    .replace("\"CONTROL_TOKEN\"", bad)
                    .into_bytes();
                fs::write(&path, &bytes).unwrap();
                assert!(ScanIndex::load(&path).is_err(), "{field} {bad}");
                let result = if bounded {
                    working.save_with_read_limit(&path, 1024 * 1024)
                } else {
                    working.save(&path)
                };
                assert!(result.is_err(), "{field} {bad}");
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(working.generation, generation);
                assert_eq!(corrupt_count(scratch.as_ref()), 0);
            }
        }
    }
}

#[test]
fn lenient_native_retry_and_terminal_scalar_repairs() {
    for disposition in ["retry_pending", "unproven_terminal", "superseded_terminal"] {
        for leaf in ["failed_reconstruction_count", "retry_after_unix_seconds"] {
            for bad in ["300", "{}", "null", "-1", "1e400"] {
                let scratch = crate::test_scratch::ScratchDir::new("lenient-scalars");
                let path = scratch.as_ref().join("index.json");
                let mut working = fixture();
                working.save(&path).unwrap();
                let mut value = serde_json::to_value(&working).unwrap();
                let record = &mut value["quarantined_snapshot_fingerprints"]["e".repeat(64)];
                record["disposition"] = Value::String(disposition.into());
                record[leaf] = Value::String("BAD_SCALAR".into());
                let bytes = serde_json::to_string(&value)
                    .unwrap()
                    .replace("\"BAD_SCALAR\"", bad);
                fs::write(&path, bytes.as_bytes()).unwrap();
                let loaded = ScanIndex::load(&path).unwrap();
                assert!(loaded.decode_holds.is_empty());
                let repaired = &loaded.quarantined_snapshot_fingerprints[&"e".repeat(64)];
                assert_eq!(
                    repaired.witness,
                    working.quarantined_snapshot_fingerprints[&"e".repeat(64)].witness
                );
                assert!(snapshot_quarantine_deadline_is_bounded(repaired));
                if disposition == "retry_pending" {
                    assert!(
                        repaired.failed_reconstruction_count < MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                    );
                } else {
                    assert_ne!(
                        repaired.disposition,
                        SnapshotQuarantineDisposition::RetryPending
                    );
                }
                for bounded in [false, true] {
                    fs::write(&path, bytes.as_bytes()).unwrap();
                    let mut saving = working.clone();
                    if bounded {
                        let result = saving.save_with_read_limit(&path, 1024 * 1024);
                        if !loaded.decode_repairs_match(&working) {
                            assert!(result.is_err());
                        } else {
                            result.unwrap();
                        }
                    } else {
                        let result = saving.save(&path);
                        if !loaded.decode_repairs_match(&working) {
                            assert!(result.is_err());
                        } else {
                            result.unwrap();
                        }
                    }
                }
                assert_sibling(&loaded);
            }
        }
    }
}

#[test]
fn lenient_original_syntax_in_optional_census_still_quarantines() {
    for bad in [
        "{\"files\":{},\"claude_request_census\":{\"bad\":1e+}}",
        "{\"files\":{},\"claude_request_census\":{",
        "{\"files\":{}} {}",
    ] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-syntax");
        let path = scratch.as_ref().join("index.json");
        fs::write(&path, bad).unwrap();
        let mut working = ScanIndex::default();
        assert!(working.save(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
        let loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.files.is_empty());
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
        assert!(!path.exists());
    }
}

#[test]
fn lenient_budget_overflow_uses_existing_load_and_cas_outcomes() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-budget");
    let path = scratch.as_ref().join("index.json");
    let mut working = fixture();
    working.save(&path).unwrap();
    let mut value = serde_json::to_value(&working).unwrap();
    value["files"]["huge-held"] = serde_json::json!({"unknown": "x".repeat(32_000)});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(working.save(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let before = scan_index_containment_lines_for_test().len();
    assert!(ScanIndex::load(&path).unwrap().files.is_empty());
    assert_eq!(corrupt_count(scratch.as_ref()), 1);
    assert!(scan_index_containment_lines_for_test()[before..]
        .iter()
        .any(|line| line.contains("lenient_hold_budget_exceeded=1")));
}

#[test]
fn lenient_held_entity_is_absent_from_emission_and_manifest() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-publication");
    let path = scratch.as_ref().join("index.json");
    let held = "e".repeat(64);
    let mut index = fixture();
    index
        .file_snapshot_fingerprints
        .insert("/synthetic/0.jsonl".into(), BTreeSet::from([held.clone()]));
    index
        .snapshot_activity_at
        .insert(held.clone(), Some("2026-10-22T00:00:00Z".into()));
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    value["quarantined_snapshot_fingerprints"][&held]["disposition"] =
        Value::String("unknown".into());
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    let mut snapshot = tests::sample_session_artifact_item();
    snapshot.snapshot_fingerprint = held;
    assert!(loaded.decode_holds_snapshot(SnapshotSource::ClaudeCode, &snapshot));
    snapshot.snapshot_fingerprint = format!("{:064x}", 15);
    assert!(!loaded.decode_holds_snapshot(SnapshotSource::ClaudeCode, &snapshot));
    let manifest = loaded
        .manifest_for_window(
            SnapshotSource::ClaudeCode,
            "2026-10-01T00:00:00Z",
            "2026-11-01T00:00:00Z",
        )
        .unwrap();
    assert_eq!(manifest.entity_count, 15);
}

#[test]
fn lenient_legacy_defaults_duplicate_headers_and_generation_refusals() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-defaults");
    let path = scratch.as_ref().join("index.json");
    fs::write(&path, b"{\"files\":{}}").unwrap();
    let mut index = ScanIndex::load(&path).unwrap();
    assert_eq!(index.accepted_snapshot_fingerprint_ledger_version, 0);
    assert_eq!(index.generation, 0);
    let original = b"{\"files\":{},\"generation\":0,\"gener\\u0061tion\":0}";
    fs::write(&path, original).unwrap();
    assert!(ScanIndex::load(&path).is_err());
    assert!(index.save(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    fs::remove_file(&path).unwrap();
    index = fixture();
    index.save(&path).unwrap();
    let mut stale = index.clone();
    index.save(&path).unwrap();
    assert!(stale
        .save(&path)
        .unwrap_err()
        .to_string()
        .contains("changed concurrently"));
    fs::remove_file(&path).unwrap();
    assert!(index
        .save(&path)
        .unwrap_err()
        .to_string()
        .contains("disappeared concurrently"));
    index.generation = u64::MAX;
    fs::write(&path, serde_json::to_vec(&index).unwrap()).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(index
        .save(&path)
        .unwrap_err()
        .to_string()
        .contains("generation overflow"));
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
