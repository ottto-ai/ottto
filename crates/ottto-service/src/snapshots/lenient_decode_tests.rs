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
            let lines_before = scan_index_containment_lines_for_test().len();
            let mut loaded = ScanIndex::load(&path).unwrap();
            let lines = scan_index_containment_lines_for_test();
            assert_eq!(lines.len() - lines_before, 1);
            assert!(lines[lines_before].contains("decode_held=1"));
            assert!(!lines[lines_before].contains("PRIVATE_FUTURE_DISPOSITION"));
            assert!(!lines[lines_before].contains("synthetic"));
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
                assert!(loaded.decode_holds_indexed_entity(&key, &format!("{:064x}", 0)));
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
                    let result = if bounded {
                        saving.save_with_read_limit(&path, 1024 * 1024)
                    } else {
                        saving.save(&path)
                    };
                    // 300 seconds since the epoch is an ordinary due retry
                    // deadline, not malformed data. Every other matrix cell
                    // actually repairs negative state newly seen only at CAS.
                    if disposition == "retry_pending"
                        && leaf == "retry_after_unix_seconds"
                        && bad == "300"
                    {
                        result.unwrap();
                    } else {
                        assert!(result
                            .unwrap_err()
                            .to_string()
                            .contains("current_index_requires_reload"));
                        assert_eq!(fs::read(&path).unwrap(), bytes.as_bytes());
                        assert_eq!(saving.generation, working.generation);
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
    let mut loaded = ScanIndex::load(&path).unwrap();
    loaded.record_accepted_snapshot_fingerprints(&BTreeSet::from([held.clone()]));
    assert!(!loaded.accepted_snapshot_fingerprint_recorded(&held));
    assert!(!loaded.accepted_snapshot_fingerprints.contains(&held));
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

#[test]
fn lenient_authority_scalar_repair_and_held_family_correction_custody() {
    for terminal in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-authority");
        let path = scratch.as_ref().join("index.json");
        let mut index = fixture();
        if terminal {
            index.insert_unproven_terminal_claude_authority_for_test("family", &"1".repeat(64));
        } else {
            index.insert_retry_pending_claude_authority_for_test("family");
        }
        if terminal {
            let record = index
                .claude_usage_authority_quarantine
                .get_mut("family")
                .unwrap();
            record.contract = CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.into();
            record.proof_correction = Some(ClaudeAuthorityProofCorrection {
                proof_witness_fingerprint: record.proven_witness_fingerprint.clone(),
                owed_member_ids: BTreeSet::from(["family".into()]),
            });
        }
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value["claude_usage_authority_quarantine"]["family"]["failed_reconstruction_count"] =
            serde_json::json!(300);
        value["claude_usage_authority_quarantine"]["family"]["retry_after_unix_seconds"] =
            serde_json::json!(u64::MAX);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.decode_holds.is_empty());
        let record = &loaded.claude_usage_authority_quarantine["family"];
        assert_eq!(
            record.failed_reconstruction_count,
            if terminal {
                MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
            } else {
                MAX_CLAUDE_USAGE_AUTHORITY_FAILURES - 1
            }
        );
        assert_eq!(record.retry_after_unix_seconds, 0);
        assert_eq!(
            record.proof_correction,
            index.claude_usage_authority_quarantine["family"].proof_correction
        );
        loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
        // Losing a family witness must also freeze its intact correction debt.
        let mut value = serde_json::to_value(&loaded).unwrap();
        value["claude_usage_family_witnesses"]["family"]["legacy_owner_roots"] =
            serde_json::json!([17]);
        let bytes = serde_json::to_vec(&value).unwrap();
        let original = raw_slot(&bytes, "claude_usage_authority_quarantine", "family");
        fs::write(&path, &bytes).unwrap();
        let mut held = ScanIndex::load(&path).unwrap();
        assert!(held.decode_holds_family("family"));
        held.drop_unbound_claude_authority_records("test");
        held.save(&path).unwrap();
        assert_eq!(
            raw_slot(
                &fs::read(&path).unwrap(),
                "claude_usage_authority_quarantine",
                "family"
            ),
            original
        );
        assert_sibling(&held);
    }
}

#[test]
fn lenient_shape_caps_and_hold_count_preserve_original_disk() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-limits");
    let path = scratch.as_ref().join("index.json");
    let mut index = fixture();
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    value["unknown_large_shape"] =
        Value::Array(vec![Value::Null; crate::snapshot_retry::STATE_NODES]);
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(index.save_with_read_limit(&path, 1024 * 1024).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(index.save_with_read_limit(&path, bytes.len() - 1).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mut value = serde_json::to_value(&index).unwrap();
    value["unknown_padding"] = Value::String("p".repeat(1024 * 1024));
    for n in 0..4097 {
        value["files"][format!("held-{n}")] = Value::Bool(false);
    }
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(index.save(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(ScanIndex::load(&path).unwrap().files.is_empty());
    assert_eq!(corrupt_count(scratch.as_ref()), 1);
}

#[test]
fn lenient_load_and_selected_cas_allocation_receipt() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-allocations");
    let path = scratch.as_ref().join("index.json");
    let mut index = fixture();
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    for n in 0..64 {
        value["quarantined_snapshot_fingerprints"][format!("{n:064x}")] =
            serde_json::json!({"unknown": 1});
    }
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let (loaded, load) = crate::retry_allocation_probe::measure(|| ScanIndex::load(&path).unwrap());
    assert!(!loaded.decode_holds.is_empty());
    let ((working, committed, subset), cas) = crate::retry_allocation_probe::measure(|| {
        let working = ScanIndex::load(&path).unwrap();
        let committed = working.clone();
        let mut subset = working.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
        subset.save_with_read_limit(&path, 1024 * 1024).unwrap();
        (working, committed, subset)
    });
    assert!(working.decode_holds.same_as(&committed.decode_holds));
    assert!(subset.decode_holds.same_as(&loaded.decode_holds));
    eprintln!("lenient_decode_allocation_receipt load_requested_peak={} load_usable_peak={} selected_cas_with_three_graphs_requested_peak={} selected_cas_with_three_graphs_usable_peak={}", load.requested_peak, load.usable_peak, cas.requested_peak, cas.usable_peak);
}

#[test]
fn lenient_save_refuses_to_write_holds_that_would_exceed_restart_admission() {
    for bounded in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-output-admission");
        let path = scratch.as_ref().join("index.json");
        let mut index = fixture();
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value["files"]["opaque-large"] = serde_json::json!({"unknown": "x".repeat(8192)});
        value["unknown_padding"] = serde_json::json!("p".repeat(128 * 1024));
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert!(!loaded.decode_holds.is_empty());
        let generation = loaded.generation;
        let result = if bounded {
            loaded.save_with_read_limit(&path, 1024 * 1024)
        } else {
            loaded.save(&path)
        };
        assert!(result.is_err());
        assert_eq!(loaded.generation, generation);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
        assert!(!ScanIndex::load(&path).unwrap().decode_holds.is_empty());
    }
}

#[test]
fn lenient_unkeyed_or_unaddressable_debt_refuses_without_rebuild() {
    for field in [
        "files",
        "accepted_snapshot_fingerprints",
        "quarantined_snapshot_fingerprints",
        "claude_usage_family_pending",
    ] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-unkeyed");
        let path = scratch.as_ref().join("index.json");
        let mut index = fixture();
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value[field] = Value::Bool(false);
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(ScanIndex::load(&path).is_err());
        assert!(index.save(&path).is_err());
        assert!(index.save_with_read_limit(&path, 1024 * 1024).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
    }
    let scratch = crate::test_scratch::ScratchDir::new("lenient-unaddressable");
    let path = scratch.as_ref().join("index.json");
    let mut index = fixture();
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    value["quarantined_snapshot_fingerprints"]["damaged-identity"] =
        serde_json::json!({"disposition":"unknown"});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(ScanIndex::load(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(corrupt_count(scratch.as_ref()), 0);
}

#[test]
fn lenient_opaque_claude_file_also_freezes_family_correction() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-file-family");
    let path = scratch.as_ref().join("index.json");
    let mut index = fixture();
    index.insert_unproven_terminal_claude_authority_for_test("family", &"1".repeat(64));
    index.files.insert(
        "/synthetic/family.jsonl".into(),
        tests::manifest_index_entry(Some(&"a".repeat(64))),
    );
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    value["files"]["/synthetic/family.jsonl"]["size_bytes"] = serde_json::json!([]);
    let bytes = serde_json::to_vec(&value).unwrap();
    let original = raw_slot(&bytes, "claude_usage_authority_quarantine", "family");
    fs::write(&path, bytes).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.decode_holds_family("family"));
    loaded.save(&path).unwrap();
    assert_eq!(
        raw_slot(
            &fs::read(&path).unwrap(),
            "claude_usage_authority_quarantine",
            "family"
        ),
        original
    );
    assert_sibling(&loaded);
}

#[test]
fn repaired_records_can_advance_after_load_but_new_cas_damage_still_requires_reload() {
    for bounded in [false, true] {
        for changed_again in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-repair-provenance");
            let path = scratch.as_ref().join("index.json");
            let fingerprint = "e".repeat(64);
            let mut index = fixture();
            index.file_snapshot_fingerprints.insert(
                "/synthetic/0.jsonl".into(),
                BTreeSet::from([fingerprint.clone()]),
            );
            index
                .snapshot_activity_at
                .insert(fingerprint.clone(), Some("2026-10-22T00:00:00Z".into()));
            index.save(&path).unwrap();
            let mut value = serde_json::to_value(&index).unwrap();
            value["quarantined_snapshot_fingerprints"][&fingerprint]
                ["failed_reconstruction_count"] = serde_json::json!(300);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            loaded.retain_quarantined_fingerprints(&BTreeMap::new());
            loaded.record_accepted_snapshot_fingerprints(&BTreeSet::from([fingerprint.clone()]));
            assert!(!loaded
                .quarantined_snapshot_fingerprints
                .contains_key(&fingerprint));
            if changed_again {
                value["quarantined_snapshot_fingerprints"][&fingerprint]
                    ["failed_reconstruction_count"] = serde_json::json!(400);
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            fs::write(&path, &bytes).unwrap();
            let generation = loaded.generation;
            let result = if bounded {
                loaded.save_with_read_limit(&path, 1024 * 1024)
            } else {
                loaded.save(&path)
            };
            if changed_again {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("current_index_requires_reload"));
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(loaded.generation, generation);
            } else {
                result.unwrap();
                let reloaded = ScanIndex::load(&path).unwrap();
                assert!(reloaded.accepted_snapshot_fingerprint_recorded(&fingerprint));
                assert!(!reloaded
                    .quarantined_snapshot_fingerprints
                    .contains_key(&fingerprint));
            }
        }
        let scratch = crate::test_scratch::ScratchDir::new("lenient-authority-advance");
        let path = scratch.as_ref().join("index.json");
        let mut index = fixture();
        index.insert_retry_pending_claude_authority_for_test("family");
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value["claude_usage_authority_quarantine"]["family"]["failed_reconstruction_count"] =
            serde_json::json!(300);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        loaded.insert_unproven_terminal_claude_authority_for_test("family", &"1".repeat(64));
        if bounded {
            loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
        } else {
            loaded.save(&path).unwrap();
        }
        assert_eq!(
            ScanIndex::load(&path)
                .unwrap()
                .claude_usage_authority_quarantine["family"]
                .disposition,
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
        );
    }
}

#[test]
fn held_entity_finalization_keeps_file_membership_and_never_confirms_empty() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-pending-membership");
    let path = scratch.as_ref().join("index.json");
    let mut snapshot = tests::sample_session_artifact_item();
    snapshot.source_file_fingerprint = Some("source".into());
    let fingerprint = snapshot_fingerprint(SnapshotSource::Pi, &snapshot);
    let key = "/synthetic/0.jsonl".to_string();
    let mut index = fixture();
    index.files.get_mut(&key).unwrap().last_snapshot_fingerprint = Some("previous-group".into());
    index
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from([fingerprint.clone()]));
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    value["quarantined_snapshot_fingerprints"][&fingerprint] =
        serde_json::json!({"disposition": "unknown"});
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    let mut empty_index = ScanIndex::default();
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::Pi,
        &[scratch.as_ref().to_path_buf()],
        &mut empty_index,
        "2026-10-22T00:00:00Z",
        BACKFILL_WINDOW_DAYS,
        4,
        false,
    )
    .unwrap();
    scan.snapshots = vec![snapshot];
    scan.pending_finalization.push(PendingIndexFinalization {
        sampled_audit_verified: false,
        codex_pending_recovery: false,
        index_key: key.clone(),
        source_file_fingerprint: "source".into(),
        previous_snapshot_fingerprint: Some("previous-group".into()),
        previous_upload_body_witness: None,
        parse_complete: true,
        diagnostic_reason: FileReason::Complete,
        parsed_snapshot_count: 1,
        effective_upload_body_witness_revision: 0,
    });
    finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut loaded);
    assert!(scan.snapshots.is_empty());
    assert!(!scan.census_complete);
    assert!(!scan.pending_finalization[0].parse_complete);
    assert!(!loaded.confirmed_empty_files.contains(&key));
    assert_eq!(
        loaded.file_snapshot_fingerprints[&key],
        BTreeSet::from([fingerprint.clone()])
    );
    assert_eq!(
        loaded.files[&key].last_snapshot_fingerprint.as_deref(),
        Some("previous-group")
    );
    loaded.save(&path).unwrap();
    let restarted = ScanIndex::load(&path).unwrap();
    assert!(restarted.file_snapshot_fingerprints[&key].contains(&fingerprint));
    assert!(!restarted.confirmed_empty_files.contains(&key));
}

#[test]
fn held_scope_manifest_visits_are_linear_in_file_count() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-keyed-scope");
    let path = scratch.as_ref().join("index.json");
    let mut index = fixture();
    for n in 16..1024 {
        let key = format!("/synthetic/{n}.jsonl");
        let fingerprint = format!("{n:064x}");
        index
            .files
            .insert(key.clone(), tests::manifest_index_entry(Some(&fingerprint)));
        index
            .file_snapshot_fingerprints
            .insert(key, BTreeSet::from([fingerprint.clone()]));
        index
            .snapshot_activity_at
            .insert(fingerprint, Some("2026-10-22T00:00:00Z".into()));
    }
    index.save(&path).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
    // Many held files catch reverse scans hidden behind one outer lookup.
    for n in 0..128 {
        value["files"][format!("/synthetic/{n}.jsonl")] = serde_json::json!({"unknown": 1});
    }
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(loaded.decode_held_file_keys().count(), 128);
    lenient_decode::scope_visits_for_test(true);
    let manifest = loaded
        .manifest_for_window(
            SnapshotSource::Pi,
            "2026-10-01T00:00:00Z",
            "2026-11-01T00:00:00Z",
        )
        .unwrap();
    assert_eq!(manifest.entity_count, 1024 - 128);
    assert!(lenient_decode::scope_visits_for_test(false) <= 3 * 1024);
}

#[test]
fn controls_refuse_before_excess_damage_can_quarantine_the_index() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-control-priority");
    let path = scratch.as_ref().join("index.json");
    for (field, control) in [
        ("accepted_snapshot_fingerprint_ledger_version", "256"),
        ("generation", "\"unknown\""),
        ("codex_parent_proof_seq", "1e400"),
    ] {
        let bytes = format!(
            "{{\"files\":{{\"bad\":{{\"unknown\":\"{}\"}}}},\"{field}\":{control}}}",
            "x".repeat(32_000)
        );
        fs::write(&path, bytes.as_bytes()).unwrap();
        assert!(ScanIndex::load(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes.as_bytes());
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
    }
}

#[test]
fn repair_provenance_is_constant_for_many_scalar_repairs_and_authority_drops() {
    let mut retained_bytes = None;
    for count in [16, 512] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-fixed-provenance");
        let path = scratch.as_ref().join("index.json");
        let mut seed = fixture();
        for n in 0..count {
            seed.quarantined_snapshot_fingerprints.insert(
                format!("{n:064x}"),
                snapshot_quarantine_record(SnapshotSource::ClaudeCode),
            );
            seed.insert_retry_pending_claude_authority_for_test(&format!("digest-family-{n}"));
        }
        seed.save(&path).unwrap();
        let mut value = serde_json::to_value(&seed).unwrap();
        for n in 0..count {
            value["quarantined_snapshot_fingerprints"][format!("{n:064x}")]
                ["failed_reconstruction_count"] = serde_json::json!(255);
        }
        value["claude_usage_family_witnesses"] = serde_json::json!({});
        let original = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &original).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.decode_holds.is_empty());
        assert!(loaded.claude_usage_authority_quarantine.is_empty());
        let receipt = loaded.decode_holds.provenance_receipt();
        assert_eq!(receipt.1, (2 * count) as u64);
        assert_eq!(*retained_bytes.get_or_insert(receipt.0), receipt.0);
        assert!(receipt.0 <= 32);
        if crate::heap_layout_bound::layout_supported() {
            assert_eq!(
                crate::heap_layout_bound::completed_bound(&loaded.decode_holds, usize::MAX),
                Some(std::mem::size_of_val(&loaded.decode_holds))
            );
        }
        let (_, clone) = crate::retry_allocation_probe::measure(|| {
            loaded.decode_holds.clone_provenance_for_test()
        });
        assert_eq!(clone.allocations, 0);
        assert_eq!(clone.requested_peak, 0);
        assert_eq!(clone.usable_peak, 0);
        let (_, holds_clone) =
            crate::retry_allocation_probe::measure(|| loaded.decode_holds.clone());
        assert_eq!(holds_clone.allocations, 0);
        assert_eq!(holds_clone.requested_peak, 0);
        assert_eq!(holds_clone.usable_peak, 0);
        // Large corpus exercises ordinary CAS; selected CAS retains its 8192
        // node gate, so its independent damage test uses the smaller corpus.
        for bounded in [false, true]
            .into_iter()
            .filter(|bounded| !*bounded || count == 16)
        {
            for damage in ["quarantine", "authority"] {
                let mut saving = loaded.clone();
                let mut changed_value: Value = serde_json::from_slice(&original).unwrap();
                if damage == "quarantine" {
                    changed_value["quarantined_snapshot_fingerprints"][format!("{:064x}", 0)]
                        ["failed_reconstruction_count"] = serde_json::json!(254);
                } else {
                    changed_value["claude_usage_authority_quarantine"]["digest-family-0"]
                        ["failed_reconstruction_count"] = serde_json::json!(254);
                }
                let changed = serde_json::to_vec(&changed_value).unwrap();
                fs::write(&path, &changed).unwrap();
                let result = if bounded {
                    saving.save_with_read_limit(&path, 8 * 1024 * 1024)
                } else {
                    saving.save(&path)
                };
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("current_index_requires_reload"));
                assert_eq!(fs::read(&path).unwrap(), changed);
                assert_eq!(saving.generation, loaded.generation);
                fs::write(&path, &original).unwrap();
                saving.resume_after_path = Some("unrelated-progress".into());
                if bounded {
                    saving.save_with_read_limit(&path, 8 * 1024 * 1024).unwrap();
                } else {
                    saving.save(&path).unwrap();
                }
                assert_sibling(&ScanIndex::load(&path).unwrap());
            }
        }
        eprintln!("lenient_fixed_provenance_receipt records={} inline_bytes={} clone_requested_peak={} clone_usable_peak={}", 2 * count, receipt.0, clone.requested_peak, clone.usable_peak);
    }
}

#[test]
fn repair_only_published_holds_drop_without_heap_retirement() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-empty-hold-storage");
    let path = scratch.as_ref().join("index.json");
    let key = "b".repeat(64);
    let mut seed = fixture();
    seed.quarantined_snapshot_fingerprints.insert(
        key.clone(),
        snapshot_quarantine_record(SnapshotSource::ClaudeCode),
    );
    seed.save(&path).unwrap();
    let mut value = serde_json::to_value(&seed).unwrap();
    // Unlike a serde-valid scalar repair, this first allocates a raw hold map,
    // then removes its last slot during repair_held. Normalization must retire
    // its empty BTree root before the value escapes the decoder.
    value["quarantined_snapshot_fingerprints"][&key]["failed_reconstruction_count"] =
        serde_json::json!(300);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.decode_holds.is_empty());
    assert_eq!(loaded.decode_holds.provenance_receipt().1, 1);
    assert_sibling(&loaded);
    // The thread probe intentionally refuses negative live bytes. A leaked
    // pre-scope empty root would therefore fail this measurement itself.
    let (_, retired) = crate::retry_allocation_probe::measure(|| drop(loaded.decode_holds));
    assert_eq!(retired.deallocations, 0);
    assert_eq!(retired.requested_live, 0);
    assert_eq!(retired.usable_live, 0);
}

fn write_deep_optional(path: &Path, prefix: &[u8], depth: usize) -> usize {
    use std::io::Write;
    let mut file = BufWriter::new(File::create(path).unwrap());
    file.write_all(&prefix[..prefix.len() - 1]).unwrap();
    let field = b",\"claude_request_census\":";
    file.write_all(field).unwrap();
    for byte in [b'[', b']'] {
        let block = [byte; 8192];
        if byte == b']' {
            file.write_all(b"0").unwrap();
        }
        for _ in 0..depth / block.len() {
            file.write_all(&block).unwrap();
        }
        file.write_all(&block[..depth % block.len()]).unwrap();
    }
    file.write_all(b"}").unwrap();
    file.flush().unwrap();
    prefix.len() + field.len() + 2 * depth + 1
}

#[test]
fn streamed_million_deep_census_is_resource_unknown_with_bounded_allocations() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-deep-census");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.save(&path).unwrap();
    let prefix = fs::read(&path).unwrap();
    for depth in [128, 200, 256, 257, 1_000, 1_000_000] {
        let input_len = write_deep_optional(&path, &prefix, depth);
        // The retained main codec is the baseline for optional unknown/null.
        let (baseline, main) = crate::retry_allocation_probe::measure(|| {
            claude_request_census::decode_index(File::open(&path).unwrap()).unwrap()
        });
        assert!(baseline.claude_request_census.is_empty());
        let (loaded, load) =
            crate::retry_allocation_probe::measure(|| ScanIndex::load(&path).unwrap());
        assert!(loaded.claude_request_census.is_empty());
        assert_sibling(&loaded);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
        assert!(load.requested_peak <= main.requested_peak + 96 * 1024);
        assert!(load.usable_peak <= main.usable_peak + 128 * 1024);
        let mut ordinary = loaded.clone();
        let (result, cas) = crate::retry_allocation_probe::measure(|| ordinary.save(&path));
        result.unwrap();
        assert!(cas.requested_peak <= main.requested_peak + 192 * 1024);
        assert!(cas.usable_peak <= main.usable_peak + 256 * 1024);
        write_deep_optional(&path, &prefix, depth);
        let (input, input_read) = crate::retry_allocation_probe::measure(|| {
            crate::snapshot_retry::read_state(&path, input_len).unwrap()
        });
        assert_eq!(input.len(), input_len);
        drop(input);
        let mut bounded = loaded.clone();
        let (result, selected) = crate::retry_allocation_probe::measure(|| {
            bounded.save_with_read_limit(&path, input_len)
        });
        result.unwrap();
        assert!(
            selected.requested_peak <= input_read.requested_peak + main.requested_peak + 192 * 1024
        );
        assert!(selected.usable_peak <= input_read.usable_peak + main.usable_peak + 256 * 1024);
        let restarted = ScanIndex::load(&path).unwrap();
        assert_sibling(&restarted);
        assert!(restarted.claude_request_census.is_empty());
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
        eprintln!("lenient_deep_census_receipt depth={depth} main_requested={} main_usable={} load_requested={} load_usable={} cas_requested={} cas_usable={} input_requested={} input_usable={} selected_requested={} selected_usable={}", main.requested_peak, main.usable_peak, load.requested_peak, load.usable_peak, cas.requested_peak, cas.usable_peak, input_read.requested_peak, input_read.usable_peak, selected.requested_peak, selected.usable_peak);
    }
}

#[test]
fn main_depth_resource_refuses_but_admitted_bad_grammar_still_quarantines() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-depth-resource");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.save(&path).unwrap();
    let bytes = format!(
        "{{\"files\":{{}},\"unknown\":{}0{}}}",
        "[".repeat(1000),
        "]".repeat(1000)
    )
    .into_bytes();
    fs::write(&path, &bytes).unwrap();
    assert!(format!("{:#}", ScanIndex::load(&path).unwrap_err()).contains("resource cap"));
    for bounded in [false, true] {
        let result = if bounded {
            seed.save_with_read_limit(&path, bytes.len())
        } else {
            seed.save(&path)
        };
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
    }
    for invalid in [
        "{\"files\":{},\"unknown\":[}",
        "{\"files\":{},\"unknown\":[0 1]}",
        "{\"files\":{},\"claude_request_census\":[0,]}",
        "{\"files\":{},\"unknown\":01}",
        "{\"files\":{},\"unknown\":1e}",
    ] {
        fs::write(&path, invalid).unwrap();
        ScanIndex::load(&path).unwrap();
        assert!(!path.exists());
    }
}

#[test]
fn populated_valid_wire_matches_the_retained_native_codec() {
    let mut index = fixture();
    index.insert_retry_pending_claude_authority_for_test("valid-family");
    index.legacy_settlement_reconcile_after_fingerprint = Some(format!("{:064x}", 0));
    index.resume_after_path = Some("/synthetic/7.jsonl".into());
    let bytes = serde_json::to_vec_pretty(&index).unwrap();
    let native = claude_request_census::decode_index(std::io::Cursor::new(&bytes)).unwrap();
    let isolated =
        lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
    assert_eq!(serde_json::to_vec_pretty(&native).unwrap(), bytes);
    assert_eq!(serde_json::to_vec_pretty(&isolated).unwrap(), bytes);
}

#[test]
fn unbound_type_repair_freezes_siblings_without_retaining_repair_keys() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-fixed-provenance-hold");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.insert_retry_pending_claude_authority_for_test("family");
    seed.save(&path).unwrap();
    let mut value = serde_json::to_value(&seed).unwrap();
    value["claude_usage_family_witnesses"]["family"]["legacy_owner_roots"] =
        serde_json::json!(["different-owner"]);
    value["claude_usage_authority_quarantine"]["family"]["failed_reconstruction_count"] =
        serde_json::json!(300);
    let bytes = serde_json::to_vec(&value).unwrap();
    let authority = raw_slot(&bytes, "claude_usage_authority_quarantine", "family");
    let witness = raw_slot(&bytes, "claude_usage_family_witnesses", "family");
    fs::write(&path, &bytes).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.decode_holds_family("family"));
    assert!(loaded.claude_usage_authority_quarantine.is_empty());
    assert_eq!(loaded.decode_holds.provenance_receipt().1, 0);
    loaded.save(&path).unwrap();
    let saved = fs::read(&path).unwrap();
    assert_eq!(
        raw_slot(&saved, "claude_usage_authority_quarantine", "family"),
        authority
    );
    assert_eq!(
        raw_slot(&saved, "claude_usage_family_witnesses", "family"),
        witness
    );
}

#[test]
fn admitted_unknown_main_values_cross_serde_native_recursion_threshold() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-admitted-depth");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.save(&path).unwrap();
    let prefix = fs::read(&path).unwrap();
    for depth in [128, 200, 255] {
        let mut bytes = prefix[..prefix.len() - 1].to_vec();
        bytes.extend_from_slice(b",\"unknown\":");
        bytes.extend(std::iter::repeat(b'[').take(depth));
        bytes.push(b'0');
        bytes.extend(std::iter::repeat(b']').take(depth));
        bytes.push(b'}');
        fs::write(&path, &bytes).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert_sibling(&loaded);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
        // Selected CAS deliberately keeps its stricter preexisting depth-64
        // shape gate; ordinary load/CAS retain admitted unknown JSON values.
        assert!(loaded.save_with_read_limit(&path, bytes.len()).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        loaded.save(&path).unwrap();
        assert_sibling(&ScanIndex::load(&path).unwrap());
    }
}

#[test]
fn optional_resource_classification_precedes_earlier_bad_numeric_token() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-resource-before-syntax");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.save(&path).unwrap();
    let prefix = fs::read(&path).unwrap();
    let mut bytes = prefix[..prefix.len() - 1].to_vec();
    bytes.extend_from_slice(b",\"claude_request_census\":[01,");
    bytes.extend(std::iter::repeat(b'[').take(1000));
    bytes.push(b'0');
    bytes.extend(std::iter::repeat(b']').take(1000));
    bytes.extend_from_slice(b"]}");
    for bounded in [false, true] {
        fs::write(&path, &bytes).unwrap();
        let native = claude_request_census::decode_index(File::open(&path).unwrap()).unwrap();
        assert!(native.claude_request_census.is_empty());
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert_sibling(&loaded);
        assert!(loaded.claude_request_census.is_empty());
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
        if bounded {
            loaded.save_with_read_limit(&path, bytes.len()).unwrap();
        } else {
            loaded.save(&path).unwrap();
        }
        assert_sibling(&ScanIndex::load(&path).unwrap());
    }
}

#[test]
fn optional_raw_cap_counts_object_field_leading_whitespace() {
    use std::io::Write;
    let scratch = crate::test_scratch::ScratchDir::new("lenient-census-leading-whitespace");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.save(&path).unwrap();
    let prefix = fs::read(&path).unwrap();
    let mut file = BufWriter::new(File::create(&path).unwrap());
    file.write_all(&prefix[..prefix.len() - 1]).unwrap();
    file.write_all(b",\"claude_request_census_shadow\":")
        .unwrap();
    let spaces = claude_request_census::MAX_RAW_BYTES + 1;
    let chunk = [b' '; 8192];
    for _ in 0..spaces / chunk.len() {
        file.write_all(&chunk).unwrap();
    }
    file.write_all(&chunk[..spaces % chunk.len()]).unwrap();
    file.write_all(b"{\"o\":true}}").unwrap();
    file.flush().unwrap();
    drop(file);
    let native = claude_request_census::decode_index(File::open(&path).unwrap()).unwrap();
    assert!(native.claude_request_census_shadow.is_empty());
    let loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.claude_request_census_shadow.is_empty());
    assert_sibling(&loaded);
    assert_eq!(corrupt_count(scratch.as_ref()), 0);
}

#[test]
fn streamed_64_mib_record_key_refuses_before_key_allocation() {
    use std::io::{Read, Write};
    fn digest(path: &Path) -> [u8; 32] {
        let mut file = File::open(path).unwrap();
        let mut hash = Sha256::new();
        let mut bytes = [0; 8192];
        loop {
            let count = file.read(&mut bytes).unwrap();
            if count == 0 {
                return hash.finalize().into();
            }
            hash.update(&bytes[..count]);
        }
    }
    let scratch = crate::test_scratch::ScratchDir::new("lenient-oversize-record-key");
    let path = scratch.as_ref().join("index.json");
    let mut working = fixture();
    working.save(&path).unwrap();
    let generation = working.generation;
    let mut file = BufWriter::new(File::create(&path).unwrap());
    write!(file, "{{\"generation\":{generation},\"files\":{{\"").unwrap();
    let block = [b'k'; 8192];
    for _ in 0..64 * 1024 * 1024 / block.len() {
        file.write_all(&block).unwrap();
    }
    file.write_all(b"\":false}}").unwrap();
    file.flush().unwrap();
    drop(file);
    let input_len = fs::metadata(&path).unwrap().len() as usize;
    let original = digest(&path);
    let (result, cas) = crate::retry_allocation_probe::measure(|| working.save(&path));
    assert!(format!("{:#}", result.unwrap_err()).contains("lenient_hold_budget_exceeded"));
    assert!(cas.requested_peak < 256 * 1024);
    assert!(cas.usable_peak < 512 * 1024);
    assert_eq!(working.generation, generation);
    assert_eq!(digest(&path), original);
    assert_sibling(&working);
    // Selected CAS retains its preexisting input and normalization buffers.
    // Price those independently; no additional 64-MiB key String is allowed.
    let (input, input_read) = crate::retry_allocation_probe::measure(|| {
        crate::snapshot_retry::read_state(&path, input_len).unwrap()
    });
    let (normalized, normalization) = crate::retry_allocation_probe::measure(|| {
        claude_request_census::normalized_bounded_bytes(&input).unwrap()
    });
    drop(normalized);
    drop(input);
    let (result, selected) =
        crate::retry_allocation_probe::measure(|| working.save_with_read_limit(&path, input_len));
    assert!(format!("{:#}", result.unwrap_err()).contains("lenient_hold_budget_exceeded"));
    assert!(
        selected.requested_peak
            <= input_read.requested_peak + normalization.requested_peak + 256 * 1024
    );
    assert!(
        selected.usable_peak <= input_read.usable_peak + normalization.usable_peak + 512 * 1024
    );
    assert_eq!(working.generation, generation);
    assert_eq!(digest(&path), original);
    assert_eq!(corrupt_count(scratch.as_ref()), 0);
    let before = scan_index_containment_lines_for_test().len();
    let (loaded, load) = crate::retry_allocation_probe::measure(|| ScanIndex::load(&path).unwrap());
    assert!(loaded.files.is_empty());
    assert!(!path.exists());
    assert_eq!(corrupt_count(scratch.as_ref()), 1);
    let quarantined = fs::read_dir(scratch.as_ref())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
        .unwrap();
    assert_eq!(digest(&quarantined.path()), original);
    assert!(load.requested_peak < 256 * 1024);
    assert!(load.usable_peak < 512 * 1024);
    assert!(scan_index_containment_lines_for_test()[before..]
        .iter()
        .any(|line| line.contains("lenient_hold_budget_exceeded=1")
            && line.contains("fallback=prior_history_gated_rebuild_requires_712")));
    eprintln!("lenient_oversize_key_receipt key_bytes={} load_requested={} load_usable={} cas_requested={} cas_usable={} input_requested={} normalization_requested={} selected_requested={} selected_usable={}", 64 * 1024 * 1024, load.requested_peak, load.usable_peak, cas.requested_peak, cas.usable_peak, input_read.requested_peak, normalization.requested_peak, selected.requested_peak, selected.usable_peak);
}

#[test]
fn held_key_bytes_and_overhead_obey_running_and_restart_budgets() {
    for records in [1, 3] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-key-charge");
        let path = scratch.as_ref().join("index.json");
        let mut seed = fixture();
        seed.save(&path).unwrap();
        let mut value = serde_json::to_value(&seed).unwrap();
        for n in 0..records {
            value["files"][format!("{n}{}", "k".repeat(4096))] = Value::Bool(false);
        }
        value["unknown_padding"] = Value::String("p".repeat(48 * 1024));
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        if records == 3 {
            let error = lenient_decode::read(std::io::Cursor::new(&bytes), "cas", "unattributed")
                .unwrap_err();
            assert!(matches!(error, lenient_decode::Error::HoldBudget));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        } else {
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(loaded.decode_held_file_keys().count(), 1);
            assert_sibling(&loaded);
            // The original padding funded this key; canonical output does not.
            for bounded in [false, true] {
                let error = if bounded {
                    loaded.save_with_read_limit(&path, 1024 * 1024)
                } else {
                    loaded.save(&path)
                }
                .unwrap_err();
                assert!(format!("{error:#}").contains("lenient_hold_budget_exceeded"));
                assert_eq!(fs::read(&path).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn opaque_file_incidence_preserves_existing_acks_through_both_pruners_and_restart() {
    for exact_empty in [false, true] {
        for bounded in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-opaque-incidence-ack");
            let path = scratch.as_ref().join("index.json");
            let mut seed = fixture();
            let key = "/synthetic/0.jsonl";
            let ack = format!("{:064x}", 0);
            seed.file_snapshot_fingerprints.remove(key);
            if exact_empty {
                seed.file_snapshot_fingerprints
                    .insert(key.into(), BTreeSet::new());
            }
            seed.save(&path).unwrap();
            let mut value = serde_json::to_value(&seed).unwrap();
            value["files"][key] = Value::Bool(false);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert!(loaded.decode_holds_file(key));
            assert_eq!(loaded.decode_has_opaque_file_incidence(), !exact_empty);
            assert!(loaded.accepted_snapshot_fingerprints.contains(&ack));
            loaded.record_accepted_snapshot_fingerprints(&BTreeSet::new());
            assert_eq!(
                loaded.accepted_snapshot_fingerprints.contains(&ack),
                !exact_empty
            );
            loaded.retain_quarantined_fingerprints(&BTreeMap::new());
            assert_eq!(
                loaded.accepted_snapshot_fingerprints.contains(&ack),
                !exact_empty
            );
            let subset = loaded.committable_subset(&loaded, &BTreeSet::new(), &BTreeMap::new());
            assert_eq!(
                subset.accepted_snapshot_fingerprints.contains(&ack),
                !exact_empty
            );
            assert!(!loaded
                .eligible_snapshot_fingerprint_refs()
                .any(|fp| fp == ack));
            if bounded {
                loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
            } else {
                loaded.save(&path).unwrap();
            }
            let restarted = ScanIndex::load(&path).unwrap();
            assert_eq!(
                restarted.accepted_snapshot_fingerprints.contains(&ack),
                !exact_empty
            );
            assert_eq!(restarted.decode_has_opaque_file_incidence(), !exact_empty);
            assert_sibling(&restarted);
        }
    }
}

#[test]
fn opaque_file_incidence_blocks_both_legacy_seals_and_ack_reopening() {
    for version in [0, SNAPSHOT_ACCEPTED_LEDGER_UNPROVEN_VERSION] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-opaque-legacy-seal");
        let path = scratch.as_ref().join("index.json");
        let mut seed = fixture();
        seed.accepted_snapshot_fingerprint_ledger_version = version;
        seed.legacy_settlement_reconcile_after_fingerprint = Some(format!("{:064x}", 0));
        seed.file_snapshot_fingerprints.remove("/synthetic/0.jsonl");
        seed.save(&path).unwrap();
        let mut value = serde_json::to_value(&seed).unwrap();
        value["files"]["/synthetic/0.jsonl"] = Value::Bool(false);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        let accepted = loaded.accepted_snapshot_fingerprints.clone();
        let cursor = loaded.legacy_settlement_reconcile_after_fingerprint.clone();
        assert!(loaded
            .legacy_settlement_reconciliation_pending_fingerprints()
            .is_empty());
        let (armed, changed) =
            loaded.prepare_legacy_settlement_reconciliation(SnapshotSource::Codex, 50);
        assert!(armed.is_empty());
        assert!(!changed);
        assert_eq!(loaded.accepted_snapshot_fingerprint_ledger_version, version);
        loaded.finish_legacy_settlement_reconciliation();
        assert_eq!(loaded.accepted_snapshot_fingerprint_ledger_version, version);
        assert_eq!(loaded.accepted_snapshot_fingerprints, accepted);
        assert_eq!(loaded.legacy_settlement_reconcile_after_fingerprint, cursor);
        loaded.save(&path).unwrap();
        let restarted = ScanIndex::load(&path).unwrap();
        assert!(restarted.decode_has_opaque_file_incidence());
        assert_eq!(
            restarted.accepted_snapshot_fingerprint_ledger_version,
            version
        );
        assert_eq!(restarted.accepted_snapshot_fingerprints, accepted);
        if version == 0 {
            // Exact empty incidence resolves UNKNOWN even while the file is
            // held; it does not invent a fingerprint or automatic retry.
            loaded
                .file_snapshot_fingerprints
                .insert("/synthetic/0.jsonl".into(), BTreeSet::new());
            assert!(!loaded.decode_has_opaque_file_incidence());
            let (armed, changed) =
                loaded.prepare_legacy_settlement_reconciliation(SnapshotSource::Codex, 50);
            assert!(armed.is_empty());
            assert!(changed);
            assert_eq!(
                loaded.accepted_snapshot_fingerprint_ledger_version,
                SNAPSHOT_ACCEPTED_LEDGER_VERSION
            );
        }
    }
}
