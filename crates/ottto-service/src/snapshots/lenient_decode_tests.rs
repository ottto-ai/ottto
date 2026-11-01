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
    value["files"]["huge-held"] = serde_json::json!({"unknown": "x".repeat(2 * 1024 * 1024)});
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
fn lenient_save_refuses_to_write_holds_that_would_exceed_restart_admission() {
    for bounded in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-output-admission");
        let path = scratch.as_ref().join("index.json");
        let mut index = fixture();
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value["files"]["opaque-large"] =
            serde_json::json!({"unknown": "x".repeat(2 * 1024 * 1024)});
        value["unknown_padding"] = serde_json::json!("p".repeat(20 * 1024 * 1024));
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert!(!loaded.decode_holds.is_empty());
        let generation = loaded.generation;
        let result = if bounded {
            loaded.save_with_read_limit(&path, 32 * 1024 * 1024)
        } else {
            loaded.save(&path)
        };
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("lenient_hold_budget_exceeded"));
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
        withheld_content: None,
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

/// [money] An invalid optional census must not erase a sibling's durable ACK
/// during load, either CAS writer, or restart. Depth 257 crosses the decoder
/// limit with a small fixture; allocation measurements add no money behaviour.
#[test]
fn sibling_ack_survives_lenient_optional_decode_failure() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-census-sibling-ack");
    let path = scratch.as_ref().join("index.json");
    let mut seed = fixture();
    seed.files.retain(|key, _| key == "/synthetic/15.jsonl");
    seed.file_snapshot_fingerprints
        .retain(|key, _| key == "/synthetic/15.jsonl");
    let sibling = format!("{:064x}", 15);
    seed.snapshot_activity_at.retain(|key, _| key == &sibling);
    seed.accepted_snapshot_fingerprints
        .retain(|key| key == &sibling);
    seed.save(&path).unwrap();
    let prefix = fs::read(&path).unwrap();
    let input_len = write_deep_optional(&path, &prefix, 257);
    let loaded = ScanIndex::load(&path).unwrap();
    assert_sibling(&loaded);
    assert!(loaded.claude_request_census.is_empty());
    let mut ordinary = loaded.clone();
    ordinary.save(&path).unwrap();
    let restarted = ScanIndex::load(&path).unwrap();
    assert_sibling(&restarted);
    assert!(restarted.claude_request_census.is_empty());
    write_deep_optional(&path, &prefix, 257);
    let mut bounded = loaded;
    bounded.save_with_read_limit(&path, input_len).unwrap();
    let restarted = ScanIndex::load(&path).unwrap();
    assert_sibling(&restarted);
    assert!(restarted.claude_request_census.is_empty());
    assert_eq!(corrupt_count(scratch.as_ref()), 0);
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
        // Independent grammar cases each get their first rebuild; a shared
        // checkpoint would correctly refuse the second inside the cooldown.
        let scratch = crate::test_scratch::ScratchDir::new("lenient-admitted-bad-grammar");
        let path = scratch.as_ref().join("index.json");
        fs::write(&path, invalid).unwrap();
        ScanIndex::load(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
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
            if !exact_empty {
                let mut tentative = loaded.clone();
                tentative
                    .file_snapshot_fingerprints
                    .insert(key.into(), BTreeSet::new());
                assert!(!tentative.decode_has_opaque_file_incidence());
                let partial =
                    tentative.committable_subset(&loaded, &BTreeSet::new(), &BTreeMap::new());
                assert!(partial.decode_has_opaque_file_incidence());
                assert!(partial.accepted_snapshot_fingerprints.contains(&ack));
            }
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

#[test]
fn held_owner_range_survives_clone_original_drop_and_restart() {
    for valid in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-shared-owner-range");
        let path = scratch.as_ref().join("index.json");
        let mut seed = fixture();
        seed.save(&path).unwrap();
        let owner = if valid {
            codex_protected_owner("held-owner")
        } else {
            "invalid".into()
        };
        let key = "/synthetic/0.jsonl";
        let mut value = serde_json::to_value(&seed).unwrap();
        value["files"][key] =
            serde_json::json!({"size_bytes": [], "codex_protected_owner": &owner});
        let bytes = serde_json::to_vec(&value).unwrap();
        let original_slot = raw_slot(&bytes, "files", key);
        fs::write(&path, &bytes).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        let mut cloned = loaded.clone();
        drop(loaded);
        assert_eq!(
            cloned.decode_held_codex_owners().collect::<Vec<_>>(),
            vec![valid.then_some(owner.as_str())]
        );
        assert!(cloned.decode_holds_codex_owner("held-owner"));
        assert_eq!(cloned.decode_holds_codex_owner("unrelated-owner"), !valid);
        cloned.save(&path).unwrap();
        let restarted = ScanIndex::load(&path).unwrap();
        assert_eq!(
            restarted.decode_held_codex_owners().collect::<Vec<_>>(),
            vec![valid.then_some(owner.as_str())]
        );
        assert!(restarted.decode_holds_codex_owner("held-owner"));
        assert_eq!(
            restarted.decode_holds_codex_owner("unrelated-owner"),
            !valid
        );
        assert_eq!(
            raw_slot(&fs::read(&path).unwrap(), "files", key),
            original_slot
        );
        assert_sibling(&restarted);
    }
}

// SI R1: valid native empty/optional cells are explicit controls, not damage.
#[test]
fn si_strict_refusal_matrix_preserves_bytes_generation_and_sibling_binding() {
    let fields = [
        "session_account_bindings",
        "claude_account_deferred_holds",
        "claude_request_identity_contract",
        "claude_request_identity_contract_changed",
        "claude_stale_family_carry",
        "claude_owned_start_census",
        "claude_duplicate_request_owners",
        "codex_parent_ownership_refs",
        "codex_parent_ownership_ledgers",
        "bounded_sweep_had_unsettled_upload",
    ];
    for field in fields {
        for bad in [
            Value::Null,
            serde_json::json!(17),
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!("x"),
            if field == "claude_stale_family_carry" {
                serde_json::json!({"roots":[17]})
            } else {
                serde_json::json!({"bad":17})
            },
        ] {
            let mut seed = fixture();
            seed.generation = 37;
            seed.session_account_bindings.insert(
                "sibling-session".into(),
                SessionAccountBinding {
                    account_identifier_hash: "a".repeat(64),
                    workspace_identifier_hash: Some("b".repeat(64)),
                },
            );
            let mut value = serde_json::to_value(&seed).unwrap();
            value[field] = bad.clone();
            // serde permits empty maps/sets/struct sequences, strings for the
            // optional token, and null for Option. Pin those lawful cells too.
            let valid = match field {
                "claude_request_identity_contract" => bad.is_null() || bad.is_string(),
                "claude_request_identity_contract_changed"
                | "bounded_sweep_had_unsettled_upload" => false,
                "codex_parent_ownership_refs" => bad == serde_json::json!([]),
                "claude_stale_family_carry" => {
                    bad == serde_json::json!({}) || bad == serde_json::json!([])
                }
                _ => bad == serde_json::json!({}),
            };
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            assert_eq!(
                serde_json::from_slice::<ScanIndex>(&bytes).is_ok(),
                valid,
                "{field}: {bad}"
            );
            for bounded in [false, true] {
                let scratch = crate::test_scratch::ScratchDir::new("si-strict-refusal");
                let path = scratch.as_ref().join("index.json");
                fs::write(&path, &bytes).unwrap();
                let before = scan_index_containment_lines_for_test().len();
                let loaded = ScanIndex::load(&path);
                let mut working = seed.clone();
                let saved = if bounded {
                    working.save_with_read_limit(&path, 1024 * 1024)
                } else {
                    working.save(&path)
                };
                if valid {
                    assert!(loaded.is_ok(), "{field}: {bad}");
                    saved.unwrap();
                    continue;
                }
                assert!(loaded.is_err(), "{field}: {bad}");
                assert!(saved.is_err(), "{field}: {bad}");
                assert_eq!(working.generation, 37);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(corrupt_count(scratch.as_ref()), 0);
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap()["generation"],
                    37
                );
                let lines = scan_index_containment_lines_for_test();
                assert_eq!(
                    lines[before..]
                        .iter()
                        .filter(|s| s.contains("refusal_kind=strict_decode"))
                        .count(),
                    2
                );
                assert!(lines[before..]
                    .iter()
                    .all(|s| !s.contains("sibling-session") && !s.contains("bad")));
            }
        }
    }
    // Actual contained damage elsewhere permits commit without touching this
    // independent binding's canonical slot, through both CAS readers.
    for bounded in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("si-binding-control");
        let path = scratch.as_ref().join("index.json");
        let mut seed = fixture();
        seed.session_account_bindings.insert(
            "sibling-session".into(),
            SessionAccountBinding {
                account_identifier_hash: "a".repeat(64),
                workspace_identifier_hash: Some("b".repeat(64)),
            },
        );
        let mut value = serde_json::to_value(&seed).unwrap();
        value["files"]["/synthetic/0.jsonl"] = serde_json::json!(false);
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        let binding = raw_slot(&bytes, "session_account_bindings", "sibling-session");
        fs::write(&path, &bytes).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            raw_slot(
                &serde_json::to_vec_pretty(&loaded).unwrap(),
                "session_account_bindings",
                "sibling-session"
            ),
            binding
        );
        if bounded {
            loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
        } else {
            loaded.save(&path).unwrap();
        }
        assert_eq!(
            raw_slot(
                &fs::read(&path).unwrap(),
                "session_account_bindings",
                "sibling-session"
            ),
            binding
        );
    }
}

#[test]
fn si_unknown_contract_latches_through_observation_save_and_restart() {
    for bounded in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("si-unknown-contract");
        let path = scratch.as_ref().join("index.json");
        let mut seed = fixture();
        seed.claude_request_identity_contract = Some("FUTURE_UNKNOWN".into());
        seed.claude_request_identity_contract_changed = false;
        seed.save(&path).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            loaded.claude_request_identity_contract.as_deref(),
            Some("FUTURE_UNKNOWN")
        );
        assert!(!loaded.claude_request_identity_contract_changed);
        loaded.observe_claude_request_identity_contract(true);
        assert!(loaded.claude_request_identity_contract_changed);
        if bounded {
            loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
        } else {
            loaded.save(&path).unwrap();
        }
        let restarted = ScanIndex::load(&path).unwrap();
        assert!(restarted.claude_request_identity_contract_changed);
        assert_eq!(
            restarted.claude_request_identity_contract,
            loaded.claude_request_identity_contract
        );
        let generation = loaded.generation;
        let mut bad = serde_json::to_value(&loaded).unwrap();
        bad["claude_request_identity_contract"] = serde_json::json!(17);
        let bytes = serde_json::to_vec(&bad).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(ScanIndex::load(&path).is_err());
        assert!(if bounded {
            loaded.save_with_read_limit(&path, 1024 * 1024)
        } else {
            loaded.save(&path)
        }
        .is_err());
        assert_eq!(loaded.generation, generation);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 0);
    }
}

#[test]
fn hold_budget_floor_and_seven_day_rebuild_loop_guard() {
    // Small damage below the floor is contained, not a whole-source rebuild.
    let scratch = crate::test_scratch::ScratchDir::new("lenient-budget-floor");
    let path = scratch.as_ref().join("index.json");
    let mut value = serde_json::to_value(fixture()).unwrap();
    value["files"]["floor-held"] = serde_json::json!({"unknown": "x".repeat(128 * 1024)});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.decode_holds_file("floor-held"));
    assert_eq!(corrupt_count(scratch.as_ref()), 0);
    loaded.save(&path).unwrap();
    assert_eq!(
        raw_slot(&fs::read(&path).unwrap(), "files", "floor-held"),
        raw_slot(&bytes, "files", "floor-held")
    );
    assert!(ScanIndex::load(&path)
        .unwrap()
        .decode_holds_file("floor-held"));

    for previous_syntax in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-budget-loop");
        let path = scratch.as_ref().join("index.json");
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["files"]["excess-held"] = serde_json::json!({"unknown": "x".repeat(2 * 1024 * 1024)});
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(
            &path,
            if previous_syntax {
                b"{".as_slice()
            } else {
                bytes.as_slice()
            },
        )
        .unwrap();
        assert!(ScanIndex::load(&path).unwrap().files.is_empty());
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
        fs::write(&path, &bytes).unwrap();
        let before = scan_index_containment_lines_for_test().len();
        assert!(format!("{:#}", ScanIndex::load(&path).unwrap_err())
            .contains("lenient_hold_budget_exceeded"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
        assert!(scan_index_containment_lines_for_test()[before..]
            .iter()
            .any(|s| s.contains("refusal_kind=rebuild_loop")
                && s.contains("lenient_hold_budget_exceeded=1")
                && s.contains("alarm")));
        let now = SystemTime::now();
        assert!(scan_index_rebuilt_recently(&path, now).unwrap());
        assert!(!scan_index_rebuilt_recently(
            &path,
            now + std::time::Duration::from_secs(8 * 24 * 60 * 60)
        )
        .unwrap());
        assert!(!scan_index_rebuilt_recently(&scratch.as_ref().join("another.json"), now).unwrap());
    }
}

#[test]
fn user_repair_override_passes_the_guard_once_and_rearms_it() {
    let scratch = crate::test_scratch::ScratchDir::new("lenient-user-repair-override");
    let path = scratch.join("index.json");
    let source = SnapshotSource::Codex;
    let load = || ScanIndex::load_for_snapshot_source_with_origin(&path, source, scratch.as_ref());
    let refused = |damage: &[u8]| {
        let error = load().unwrap_err();
        assert!(
            error.downcast_ref::<ScanIndexRebuildLoop>().is_some(),
            "{error:#}"
        );
        assert!(scan_index_rebuild_paused(source));
        assert_eq!(fs::read(&path).unwrap(), damage);
    };
    fs::write(&path, b"{").unwrap();
    assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Quarantined);
    // A press with no pause arms nothing for a later incident.
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::NotPaused
    );
    // Hold-budget damage: its session-identity fields are strictly
    // recoverable, so a press may rebuild past the guard (SI-718-O1).
    let damage = whole_index_damage("budget");
    fs::write(&path, &damage).unwrap();
    refused(&damage);
    // The pause names its automatic retry: seven days after the witness.
    let week = 7 * 24 * 60 * 60;
    let retry = scan_index_rebuild_auto_retry_unix_seconds(source).unwrap();
    let now = unix_seconds_at(SystemTime::now());
    assert!(
        retry > now + week - 60 && retry <= now + week + 1,
        "{retry} vs {now}"
    );
    assert!(scan_index_rebuild_auto_retry_at(source).is_some());
    // Automatic retries never override: the source load keeps refusing.
    refused(&damage);

    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Armed
    );
    // The unattributed load (audit, retry driver) cannot spend the press.
    assert!(ScanIndex::load(&path)
        .unwrap_err()
        .downcast_ref::<ScanIndexRebuildLoop>()
        .is_some());
    assert_eq!(fs::read(&path).unwrap(), damage);
    // A second press inside 24 hours refuses, armed or spent.
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Cooldown
    );
    assert_eq!(scan_index_rebuild_manual_override_count(), 0);
    let before = scan_index_containment_lines_for_test().len();
    let (index, origin) = load().unwrap();
    assert_eq!(origin, ScanIndexLoadOrigin::Quarantined);
    assert!(index.files.is_empty());
    assert!(!scan_index_rebuild_paused(source));
    assert_eq!(scan_index_rebuild_manual_override_count(), 1);
    let lines = scan_index_containment_lines_for_test();
    let overrides = lines[before..]
        .iter()
        .filter(|line| line.contains("override=user_repair"))
        .collect::<Vec<_>>();
    assert_eq!(overrides.len(), 1);
    assert!(overrides[0].contains("scan_index_rebuild_manual_override=1"));
    assert!(overrides[0].contains("source=codex"));
    assert!(lines[before..]
        .iter()
        .any(|line| line.contains("fallback=gated_rebuild")
            && line.contains("history_policy=prior_history_gated_rebuild")));
    // The override witness keeps the damaged bytes and re-arms the clock.
    let witness = fs::read_dir(scratch.as_ref())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("index.corrupt.override.")
        })
        .unwrap();
    assert_eq!(fs::read(&witness).unwrap(), damage);
    assert_eq!(corrupt_count(scratch.as_ref()), 2);
    assert!(scan_index_rebuilt_recently(&path, SystemTime::now()).unwrap());

    // A fresh failure inside seven days of the override refuses again; the
    // spent press does not carry over.
    fs::write(&path, b"{  ").unwrap();
    refused(b"{  ");
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Cooldown
    );
    // The cooldown is the durable witness, so it survives a daemon restart.
    SCAN_INDEX_REBUILD_OVERRIDE.with(|cell| cell.set([ScanIndexRebuildOverrideState::NONE; 3]));
    refused(b"{  ");
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Cooldown
    );
    // After 24 hours one more press is allowed; the guard still refuses
    // every load that is not that press.
    refused(b"{  ");
    assert_eq!(
        arm_scan_index_rebuild_manual_override(
            source,
            SystemTime::now() + std::time::Duration::from_secs(25 * 60 * 60)
        ),
        ScanIndexRebuildOverride::Armed
    );
    assert_eq!(scan_index_rebuild_manual_override_count(), 1);
}

fn every_persisted_field_fixture() -> ScanIndex {
    let mut seed = fixture();
    seed.insert_retry_pending_claude_authority_for_test("valid-family");
    seed.codex_parent_prefix_proofs.insert(
        "child".into(),
        CodexParentProofState::Owed(CodexParentProofOwed::new(
            "parent".into(),
            1,
            CAUSE_NO_EVIDENCE,
            OwedOrigin::Lineage,
        )),
    );
    let mut value = serde_json::to_value(&seed).unwrap();
    // Explicit, non-default fixture for EVERY registry member. New fields must
    // add native evidence here as well as serializer/registry/dispatch entries.
    for &field in lenient_decode::FIELDS {
        let replacement = match field {
            "schema_version"
            | "files"
            | "snapshot_activity_at"
            | "accepted_snapshot_fingerprints"
            | "file_snapshot_fingerprints"
            | "quarantined_snapshot_fingerprints"
            | "claude_usage_family_witnesses"
            | "claude_usage_authority_quarantine"
            | "codex_parent_prefix_proofs"
            | "accepted_snapshot_fingerprint_ledger_version" => continue,
            "upload_ack_retirement_handoff" => serde_json::json!({
                "destination_namespace_hash":"c".repeat(64),
                "committed_generation":1,
                "bodies":{"d".repeat(64):"e".repeat(64)},
                "pending_bodies":{"a".repeat(64):"b".repeat(64)}
            }),
            "session_account_bindings" => {
                serde_json::json!({"session":{"account_identifier_hash":"account","workspace_identifier_hash":"workspace"}})
            }
            "terminal_jsonl_dispositions" => {
                serde_json::json!({"file":{"source_file_fingerprint":"fp","parser_generation":"generation","loss":{"over_line_cap_count":1}}})
            }
            "known_configured_scan_roots"
            | "legacy_unresolved_root_file_witnesses"
            | "codex_state_only_blocked_session_ids"
            | "codex_state_only_blocked_unattributed"
            | "codex_state_only_blocked_legacy"
            | "codex_parent_ownership_refs"
            | "confirmed_empty_files" => serde_json::json!(["member"]),
            "codex_state_only_snapshot_fingerprints" | "claude_account_deferred_holds" => {
                serde_json::json!({"session":"value"})
            }
            "codex_state_only_blocked_by_file" => serde_json::json!({"file":["session"]}),
            "codex_parent_ownership_ledgers" => {
                serde_json::json!({"parent":{"signatures":["signature"],"scan_complete":true}})
            }
            "codex_parent_side_requests" => {
                serde_json::json!({"parent":{"dev_ino":[1,2],"needed_extent":1,"state":{"kind":"live"},"state_extent":1,"state_ctime":[1,0],"attempt_extent":1,"attempt_ctime":[1,0],"attempts":1,"not_before_unix_seconds":1}})
            }
            "codex_parent_side" => serde_json::json!({"parent":{
                "verdict":{"kind":"settled"},"generation":1,"referenced_epoch":1,
                "parsed":{"dev":1,"ino":2,"extent":1,"modified":[1,0],"changed":[1,0]},
                "seal":{"stamp":{"length":1,"device":1,"inode":2,"modified":[1,0],"changed":[1,0]},
                    "scope":codex_parent_side_scope().0,"sample_len":1,"head_sha256":"a".repeat(64),"boundary_sha256":"b".repeat(64),"verified_unix_seconds":1,"sealed_unix_seconds":1}}}),
            "claude_desktop_title_files" => {
                serde_json::json!({"sidecar":{"cli_session_id":"session","title":"title","user_set":true}})
            }
            "claude_account_family_witnesses" => {
                serde_json::json!({"account-family":{"account_identifier_hash":"account","evidence_request_count":1,"members":{"member":1}}})
            }
            "claude_account_family_pending" => {
                serde_json::json!({"account-family":{"census_window_end":"2026-10-22T00:00:00Z","account_identifier_hash":"account","evidence_request_count":1,"members":{"member":1},"invalid":false}})
            }
            "claude_usage_family_pending" => {
                serde_json::json!({"pending-family":{"census_window_end":"2026-10-22T00:00:00Z","member_request_id_hashes":{"member":["hash"]},"invalid":false}})
            }
            "claude_request_census" => {
                serde_json::json!({"/synthetic/0.jsonl":{"v":claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,"fp":"a".repeat(64),"w":7,"s":"exact","b":"AAAAAAAAAAE="}})
            }
            "claude_request_census_shadow" => serde_json::json!({"o":true}),
            "reread_guard" => serde_json::json!({"closed":true}),
            "claude_desktop_store_inventory" => serde_json::json!("a".repeat(64)),
            "claude_retired_family_tombstones" => {
                serde_json::json!({"a".repeat(64): 1})
            }
            "claude_full_rearm_progress" => serde_json::json!({"structural_rearm_owed":true}),
            "codex_counting_evicted_legacy" => {
                serde_json::json!([{"owner":"b".repeat(64),"selected_v2":false}])
            }
            "codex_counting_tombstones" => {
                serde_json::json!({"a".repeat(64):{"evidence":"legacy_acked","retired_in":"2026-10-22T00:00:00Z"}})
            }
            "claude_duplicate_request_owners" => {
                serde_json::json!({"request":[{"root_session_id_hash":"root","source_session_id_hash":"session"}]})
            }
            "claude_owned_start_census" => {
                serde_json::json!({"member":{"marker_source_file_fingerprint":"fp"}})
            }
            "claude_desktop_census_witness" => {
                serde_json::json!({"completed_at_unix_seconds":1,"process_id":1,"inventory":"inventory"})
            }
            "accepted_rebuild_incidence" => {
                serde_json::json!({"/synthetic/carried.jsonl":["a".repeat(64)]})
            }
            "claude_stale_family_carry" => serde_json::json!({"roots":["carried-family"]}),
            "held_audit_progress" => serde_json::json!({
                "key":"/synthetic/0.jsonl", "due":7, "attempted":true
            }),
            "claude_money_birth_store" => {
                let mut store = claude_money_birth_store::BirthStore::default();
                store.record_observation("session", "/synthetic/0.jsonl", 1);
                serde_json::to_value(store).unwrap()
            }
            "claude_copy_removals" => {
                let mut removals = claude_request_money::copy_removals::CopyRemovals::default();
                removals.store(
                    claude_money_birth_store::location_key("/synthetic/copy.jsonl"),
                    BTreeMap::from([(
                        claude_money_birth_store::location_key("/synthetic/original.jsonl"),
                        BTreeSet::from([1, 2]),
                    )]),
                );
                serde_json::to_value(removals).unwrap()
            }
            "traversal" => {
                serde_json::json!({"context_fingerprint":"context","census_window_end":"2026-10-22T00:00:00Z","scan_roots":["/synthetic"],"pending_directories":[],"pending_candidates":[],"observed_index_keys":["file"],"reconciliation_upper_bound":"file","reconciliation_after":null,"reconciliation_started":true,"counts":{}})
            }
            "scan_residue_witness" => {
                serde_json::json!({"census_window_end":"2026-10-22T00:00:00Z","index_keys":["file"]})
            }
            "codex_state_only_blocked_attributed"
            | "claude_retired_family_tombstones_initialized"
            | "claude_retired_family_tombstones_uncertain"
            | "claude_duplicate_request_witness_overflowed"
            | "claude_request_identity_contract_changed"
            | "claude_desktop_store_sweep_had_errors"
            | "claude_desktop_identity_census_complete"
            | "claude_desktop_lineage_census_complete"
            | "bounded_sweep_had_unsettled_upload"
            | "context_curve_capability_enabled"
            | "claude_history_gate_loaded"
            | "claude_history_move_not_full"
            | "claude_history_move_released"
            | "accepted_incidence_pending_census" => serde_json::json!(true),
            "generation"
            | "codex_parent_side_generation"
            | "codex_parent_proof_wrap_epoch"
            | "codex_parent_proof_seq"
            | "claude_duplicate_fence_rearm_attempt"
            | "claude_duplicate_fence_next_full_rearm_unix_seconds"
            | "claude_desktop_store_retry_attempt"
            | "claude_desktop_store_retry_not_before_unix_seconds"
            | "bounded_sweep_unsettled_causes"
            | "context_curve_replay_epoch"
            | "accepted_rebuild_pending_since_unix_seconds"
            | "accepted_rebuild_last_alarm_unix_seconds"
            | "claude_history_cutoff_unix_seconds" => serde_json::json!(1),
            "legacy_settlement_reconcile_after_fingerprint" => serde_json::json!("0".repeat(64)),
            "upload_context_fingerprint"
            | "codex_parent_proof_cursor"
            | "codex_parent_side_cursor"
            | "codex_proof_index_incarnation"
            | "claude_request_identity_contract"
            | "claude_desktop_store_cursor"
            | "claude_desktop_store_upper_bound"
            | "resume_after_path"
            | "resume_upper_bound_path"
            | "resume_census_window_end"
            | "historical_replay_generation"
            | "completed_context_curve_replay_generation" => serde_json::json!("non-default"),
            _ => panic!("add a non-default native fixture for persisted field {field}"),
        };
        value[field] = replacement;
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn every_persisted_field_serializes_and_crosses_the_lenient_boundary() {
    let index = every_persisted_field_fixture();
    let bytes = serde_json::to_vec_pretty(&index).unwrap();
    let encoded: BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        encoded.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        lenient_decode::FIELDS
            .iter()
            .copied()
            .filter(|name| {
                !matches!(
                    *name,
                    "reread_guard"
                        | "claude_desktop_store_inventory"
                        | "context_curve_capability_enabled"
                        | "context_curve_replay_epoch"
                        | "completed_context_curve_replay_generation"
                )
            })
            .collect()
    );
    let decoded =
        lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
    assert!(decoded.decode_holds.is_empty());
    assert_eq!(serde_json::to_vec_pretty(&decoded).unwrap(), bytes);
}

/// [format] historical named and positional writers preserve appended v1 fields.
#[test]
fn main_and_pre_merge_e2_indexes_keep_appended_fields() {
    // Main shipped audit progress first. The earlier E2 writer saved a named
    // map with birth storage but no audit progress. Neither may lose custody.
    let seed = every_persisted_field_fixture();
    let current = serde_json::to_value(&seed).unwrap();
    let fields = lenient_decode::FIELDS;
    assert_eq!(
        &fields[fields.len() - 5..],
        &[
            "upload_ack_retirement_handoff",
            "held_audit_progress",
            "claude_money_birth_store",
            "claude_desktop_store_inventory",
            "claude_copy_removals",
        ]
    );
    for earlier_e2 in [false, true] {
        let mut legacy = current.clone();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("claude_copy_removals");
        legacy.as_object_mut().unwrap().remove(if earlier_e2 {
            "held_audit_progress"
        } else {
            "claude_money_birth_store"
        });
        let mut forms = vec![legacy.clone()];
        if !earlier_e2 {
            // The main positional schema ends at audit progress; appending E2
            // must leave every already-shipped position intact.
            forms.push(Value::Array(
                fields[..fields.len() - 3]
                    .iter()
                    .map(|name| legacy[*name].clone())
                    .collect(),
            ));
        }
        for form in forms {
            let bytes = serde_json::to_vec(&form).unwrap();
            let native: ScanIndex = serde_json::from_slice(&bytes).unwrap();
            let streaming =
                lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
            let bounded = lenient_decode::read_bounded(&bytes).unwrap();
            for decoded in [native, streaming, bounded] {
                assert!(decoded.decode_holds.is_empty());
                assert_sibling(&decoded);
                assert_eq!(
                    serde_json::to_value(&decoded).unwrap(),
                    legacy,
                    "legacy writer earlier_e2={earlier_e2}"
                );
            }
        }
    }
}

const DESKTOP_INVENTORY: &str = "claude_desktop_store_inventory";

#[test]
fn desktop_inventory_production_load_save_drops_key_with_exact_bytes_and_counts() {
    let scratch = crate::test_scratch::ScratchDir::new("desktop-inventory-load-save");
    let path = scratch.as_ref().join("index.json");
    let seed = fixture();
    let without = serde_json::to_string(&seed).unwrap();
    let load_and_save = |input: &str, inventory: Option<&str>| {
        fs::write(&path, input).unwrap();
        let before = claude_absence_counters_for_test().tombstone_decode_drops;
        let mut loaded = ScanIndex::load(&path).unwrap();
        let drops = claude_absence_counters_for_test().tombstone_decode_drops - before;
        assert_eq!(fs::read(&path).unwrap(), input.as_bytes());
        assert!(loaded.decode_holds.is_empty());
        assert_eq!(loaded.generation, seed.generation);
        assert_eq!(loaded.claude_desktop_store_inventory.as_deref(), inventory);
        loaded.save(&path).unwrap();
        let saved = fs::read(&path).unwrap();
        let value: Value = serde_json::from_slice(&saved).unwrap();
        assert!(value.get(DESKTOP_INVENTORY).is_none());
        (saved, drops)
    };
    let (baseline, drops) = load_and_save(&without, None);
    assert_eq!(drops, 0);
    let digest = "a".repeat(64);
    for (case, fields, inventory, expected_drops) in [
        (
            "valid",
            format!("\"{DESKTOP_INVENTORY}\":\"{digest}\""),
            Some(digest.as_str()),
            0,
        ),
        (
            "wrong-length",
            format!("\"{DESKTOP_INVENTORY}\":\"{}\"", "a".repeat(63)),
            None,
            1,
        ),
        (
            "duplicate",
            format!(
                "\"{DESKTOP_INVENTORY}\":\"{digest}\",\"{DESKTOP_INVENTORY}\":\"{}\"",
                "b".repeat(64)
            ),
            Some(digest.as_str()),
            1,
        ),
    ] {
        let input = format!("{{{fields},{}", &without[1..]);
        let (saved, drops) = load_and_save(&input, inventory);
        assert_eq!(saved, baseline, "{case}: production save bytes");
        assert_eq!(drops, expected_drops, "{case}: one count per dropped value");
    }
}

#[test]
fn desktop_inventory_keeps_existing_positional_index_slots() {
    let current = serde_json::to_value(every_persisted_field_fixture()).unwrap();
    let fields = lenient_decode::FIELDS;
    let tombstone_slot = fields.len() - 2;
    assert_eq!(fields[tombstone_slot], DESKTOP_INVENTORY);
    assert_eq!(fields[tombstone_slot + 1], "claude_copy_removals");
    let slot = |name: &&str| current[*name].clone();
    let shorter: Vec<Value> = fields[..tombstone_slot].iter().map(slot).collect();
    let mut legacy = current.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("claude_copy_removals");
    let mut full = shorter.clone();
    full.push(serde_json::json!("a".repeat(64)));
    full.push(current["claude_copy_removals"].clone());
    for (slots, expected) in [(shorter, &legacy), (full, &current)] {
        let bytes = serde_json::to_vec(&Value::Array(slots)).unwrap();
        let native: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        let streaming =
            lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
        let bounded = lenient_decode::read_bounded(&bytes).unwrap();
        for decoded in [native, streaming, bounded] {
            assert_eq!(serde_json::to_value(decoded).unwrap(), *expected);
        }
    }
}

/// [format] v1 keeps main's positional slots and skips v2-only growth custody.
#[test]
fn growth_retention_keeps_existing_positional_index_slots() {
    let current = serde_json::to_value(every_persisted_field_fixture()).unwrap();
    assert!(current.get("growth_retention").is_none());
    let fields = lenient_decode::FIELDS;
    assert_eq!(fields[85], "claude_money_birth_store");
    assert_eq!(fields[86], DESKTOP_INVENTORY);
    assert_eq!(fields[87], "claude_copy_removals");
    assert_eq!(fields.len(), 88);
    let positional = Value::Array(fields.iter().map(|name| current[*name].clone()).collect());
    let mut unknown = current.clone();
    unknown["growth_retention"] = serde_json::json!({"v2-only": {"owed": true}});
    for form in [positional, unknown] {
        let bytes = serde_json::to_vec(&form).unwrap();
        let native: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        let streaming =
            lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
        let bounded = lenient_decode::read_bounded(&bytes).unwrap();
        for decoded in [native, streaming, bounded] {
            assert!(decoded.v2.is_none());
            assert_eq!(serde_json::to_value(decoded).unwrap(), current);
        }
    }
}

#[test]
fn copy_removals_keep_existing_positional_index_slots() {
    let current = serde_json::to_value(every_persisted_field_fixture()).unwrap();
    let mut legacy = current.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("claude_copy_removals");
    let fields = lenient_decode::FIELDS;
    assert_eq!(fields.last(), Some(&"claude_copy_removals"));
    for (expected, slots) in [(&legacy, &fields[..fields.len() - 1]), (&current, fields)] {
        let bytes = serde_json::to_vec(&Value::Array(
            slots.iter().map(|name| expected[*name].clone()).collect(),
        ))
        .unwrap();
        let native: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        let streaming =
            lenient_decode::read(std::io::Cursor::new(&bytes), "load", "unattributed").unwrap();
        let bounded = lenient_decode::read_bounded(&bytes).unwrap();
        for decoded in [native, streaming, bounded] {
            assert_eq!(serde_json::to_value(decoded).unwrap(), *expected);
        }
    }
}

#[test]
#[serial_test::serial(source_manifests)]
fn actual_transcript_rescans_keep_file_and_family_holds_out_of_publication() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for family_slot in [false, true] {
            if source == SnapshotSource::Codex && family_slot {
                continue;
            }
            let scratch = crate::test_scratch::ScratchDir::new("lenient-real-rescan");
            let path = scratch.as_ref().join("index.json");
            let root = scratch.as_ref().join("projects");
            let session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
            fs::create_dir_all(&root).unwrap();
            let mut transcript_paths = Vec::new();
            if source == SnapshotSource::ClaudeCode {
                let file = root.join(format!("{session}.jsonl"));
                fs::write(&file, format!("{{\"timestamp\":\"2026-10-21T10:01:00Z\",\"sessionId\":\"{session}\",\"message\":{{\"id\":\"message\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":35,\"output_tokens\":8}}}}}}\n")).unwrap();
                transcript_paths.push(file);
            } else {
                for (name, response, input, total) in
                    [("a", "response-a", 100, 100), ("b", "response-b", 200, 300)]
                {
                    let file = root.join(format!("{name}.jsonl"));
                    let rows = codex_file_join::tests::member(session, response, input, total);
                    fs::write(
                        &file,
                        rows.iter()
                            .map(|row| serde_json::to_string(row).unwrap() + "\n")
                            .collect::<String>(),
                    )
                    .unwrap();
                    transcript_paths.push(file);
                }
            }
            let mut index = ScanIndex::default();
            let first = scan_source_roots(
                source,
                std::slice::from_ref(&root),
                &mut index,
                "2026-10-22T00:00:00Z",
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap();
            assert!(
                !first.snapshots.is_empty(),
                "healthy scan must exercise emission: {source:?}"
            );
            assert_eq!(first.scanned_file_count, transcript_paths.len());
            assert_eq!(index.files.len(), transcript_paths.len());
            let accepted = first
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect();
            index.record_accepted_snapshot_fingerprints(&accepted);
            let key = local_index_key(&transcript_paths[0]);
            if family_slot {
                // A prior, valid native family witness exists on disk before
                // corruption. The real scan supplies its member revision;
                // this fixture does not construct a hold or infer authority.
                index.claude_account_family_witnesses.insert(
                    session.into(),
                    ClaudeAccountFamilyWitness {
                        account_identifier_hash: "a".repeat(64),
                        evidence_request_count: 1,
                        members: BTreeMap::from([(
                            session.into(),
                            index.files[&key].modified_unix_seconds,
                        )]),
                        member_request_id_fingerprints: BTreeMap::new(),
                    },
                );
            }
            index.save(&path).unwrap();
            let (field, held_key) = if family_slot {
                ("claude_account_family_witnesses", session.to_owned())
            } else {
                ("files", key.clone())
            };
            let mut value = serde_json::to_value(&index).unwrap();
            assert!(
                value[field].get(&held_key).is_some(),
                "corrupt an existing persisted slot"
            );
            value[field][&held_key] = serde_json::json!({"members": [false], "opaque": "future"});
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            let original = raw_slot(&bytes, field, &held_key);
            fs::write(&path, &bytes).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert!(loaded.decode_holds_file(&key));
            // Pins the NewFile decision independently of the scan's earlier
            // candidate guard, including when the held native entry is absent.
            let candidate = CandidateFile {
                physical_identity: None,
                scan_root: root.clone(),
                path: transcript_paths[0].clone(),
                size_bytes: fs::metadata(&transcript_paths[0]).unwrap().len(),
                modified_unix_seconds: 0,
                modified_unix_nanos: 0,
                source_file_fingerprint: "different-revision".into(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
                withheld_content_stamp: None,
            };
            assert_eq!(
                loaded.candidate_decision_with_reason(&candidate),
                (CandidateDecision::Skip, None)
            );
            // Inspect real continuations too: selection must never queue a
            // held group, even if its boot guard would later catch it.
            let mut owned = OwnedSourceScan::new(
                source,
                std::slice::from_ref(&root),
                loaded.clone(),
                "2026-10-22T00:01:00Z",
                BACKFILL_WINDOW_DAYS,
                MAX_BACKFILL_FILES_PER_SOURCE,
                true,
                None,
                &[],
                false,
            );
            if source == SnapshotSource::ClaudeCode {
                // An owed family reparse bypasses the ordinary candidate
                // decision. The earlier hold guard must stop it independently.
                owned.forced_claude_family_reparses.insert(session.into());
            }
            let mut completed = None;
            for _ in 0..1000 {
                assert_eq!(
                    owned.census.parse_reasons[CandidateParseReason::NewFile as usize],
                    0
                );
                assert!(owned
                    .codex_join_groups
                    .iter()
                    .all(|group| group.members.iter().all(|member| !owned
                        .index
                        .decode_holds_file(&local_index_key(&member.path)))));
                match owned.step(None) {
                    OwnedSourceScanStep::Pending(next) => owned = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => {
                        completed = Some((index, scan));
                        break;
                    }
                }
            }
            let (mut rescanned_index, mut rescanned) = completed.expect("rescan finished");
            finalize_scan_after_policy(source, &mut rescanned, &mut rescanned_index);
            loaded = rescanned_index;
            if source == SnapshotSource::Codex {
                // A queued continuation must recheck custody at boot as well.
                // Install the actual disk-decoded hold at that boundary, while
                // preserving the continuation's live traversal.
                let mut queued = OwnedSourceScan::new(
                    source,
                    std::slice::from_ref(&root),
                    ScanIndex::default(),
                    "2026-10-22T00:01:00Z",
                    BACKFILL_WINDOW_DAYS,
                    MAX_BACKFILL_FILES_PER_SOURCE,
                    true,
                    None,
                    &[],
                    false,
                );
                let mut reached_queue = false;
                for _ in 0..1000 {
                    if !queued.codex_join_groups.is_empty() {
                        reached_queue = true;
                        break;
                    }
                    match queued.step(None) {
                        OwnedSourceScanStep::Pending(next) => queued = next,
                        OwnedSourceScanStep::Complete { .. } => panic!("group never queued"),
                    }
                }
                assert!(reached_queue);
                let traversal = queued.index.traversal.take();
                queued.index = loaded.clone();
                queued.index.traversal = traversal;
                let OwnedSourceScanStep::Pending(after) = queued.step(None) else {
                    panic!("boot yielded")
                };
                assert_eq!(after.scanned_file_count, 0);
                assert!(after.codex_join_active.is_none());
                assert!(after.active_file.is_none());
                assert!(after.snapshots.is_empty());
            }
            assert!(
                rescanned.snapshots.is_empty(),
                "held file/group emitted: {source:?} family={family_slot}"
            );
            assert_eq!(
                rescanned.scanned_file_count, 0,
                "no parse, including NewFile, may begin"
            );
            assert_eq!(rescanned.scanned_session_count, 0);
            // The selection guard must disclose the known held group before
            // generic missing-owner recovery can misclassify it as new loss.
            assert_eq!(rescanned.ownership_incomplete_file_count, 0);
            assert_eq!(rescanned.unreadable_path_count, 0);
            assert!(!rescanned.census_complete);
            assert!(
                !crate::snapshot_sync::decode_hold_manifest_published_for_test(
                    &mut loaded,
                    &path,
                    source,
                    rescanned.census_complete
                )
                .unwrap()
            );
            assert_eq!(
                raw_slot(&fs::read(&path).unwrap(), field, &held_key),
                original
            );
            let mut restarted = ScanIndex::load(&path).unwrap();
            assert!(restarted.decode_holds.same_as(&loaded.decode_holds));
            assert_eq!(
                raw_slot(
                    &serde_json::to_vec_pretty(&restarted).unwrap(),
                    field,
                    &held_key
                ),
                original
            );
            if family_slot {
                // A held-family file remains typed; exercise missing-file
                // reconciliation as well, so its exact incidence survives.
                let incidence = restarted.file_snapshot_fingerprints[&key].clone();
                fs::remove_file(&transcript_paths[0]).unwrap();
                let missing = scan_source_roots(
                    source,
                    std::slice::from_ref(&root),
                    &mut restarted,
                    "2026-10-22T00:02:00Z",
                    BACKFILL_WINDOW_DAYS,
                )
                .unwrap();
                assert!(missing.snapshots.is_empty());
                assert!(!missing.census_complete);
                assert!(restarted.files.contains_key(&key));
                if let Some(traversal) = restarted.traversal.as_mut() {
                    traversal.observed_index_keys.clear();
                    traversal.reconciliation_upper_bound = Some(key.clone());
                    traversal.reconciliation_after = None;
                } else {
                    // A fresh scan start owns the existing traversal shape.
                    let mut context = OwnedSourceScan::new(
                        source,
                        std::slice::from_ref(&root),
                        restarted.clone(),
                        "2026-10-22T00:03:00Z",
                        BACKFILL_WINDOW_DAYS,
                        MAX_BACKFILL_FILES_PER_SOURCE,
                        true,
                        None,
                        &[],
                        false,
                    );
                    restarted.traversal = context.index.traversal.take();
                    let traversal = restarted.traversal.as_mut().unwrap();
                    traversal.observed_index_keys.clear();
                    traversal.reconciliation_upper_bound = Some(key.clone());
                    traversal.reconciliation_after = None;
                }
                assert!(reconcile_missing_index_entries_with_limit(
                    &mut restarted,
                    1
                ));
                assert!(restarted.files.contains_key(&key));
                assert_eq!(restarted.file_snapshot_fingerprints[&key], incidence);
                restarted.save(&path).unwrap();
                assert_eq!(
                    raw_slot(&fs::read(&path).unwrap(), field, &held_key),
                    original
                );
            }
        }
    }
}

/// K1–K4: every reader shares fail-closed scalar repairs. An intact cutoff
/// must not hide a damaged move hold after this destination bootstraps.
#[test]
fn history_gate_damage_is_local_through_load_and_both_cas_readers() {
    for bad in [
        serde_json::json!("damaged"),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!([]),
        serde_json::json!({"bad": true}),
        serde_json::json!(null),
    ] {
        for damage_cutoff in [false, true] {
            for bounded in [false, true] {
                let scratch = crate::test_scratch::ScratchDir::new("history-gate-cas");
                let path = scratch.join("index.json");
                let mut working = fixture();
                working.claude_history_gate_loaded = true;
                working.claude_history_cutoff_unix_seconds = Some(1);
                working.save(&path).unwrap();
                let mut value = serde_json::to_value(&working).unwrap();
                value["claude_history_move_not_full"] = bad.clone();
                value["claude_history_move_released"] = bad.clone();
                if damage_cutoff {
                    value["claude_history_cutoff_unix_seconds"] = bad.clone();
                    value["claude_history_gate_loaded"] = bad.clone();
                }
                let bytes = serde_json::to_vec(&value).unwrap();
                fs::write(&path, &bytes).unwrap();
                let loaded = ScanIndex::load(&path).unwrap();
                // Inspect CAS decode results as well as the real save APIs:
                // a later overwrite must not conceal missing normalization.
                let current = if bounded {
                    claude_request_census::decode_bounded_index(&bytes).unwrap()
                } else {
                    lenient_decode::read_file(File::open(&path).unwrap(), "cas", "unattributed")
                        .unwrap()
                };
                for mut index in [loaded.clone(), current] {
                    assert_sibling(&index);
                    assert!(index.claude_history_move_not_full);
                    assert!(!index.claude_history_move_released);
                    if damage_cutoff {
                        assert_eq!(index.claude_history_cutoff_unix_seconds, None);
                        assert!(!index.claude_history_gate_loaded);
                    } else {
                        assert_eq!(index.claude_history_cutoff_unix_seconds, Some(1));
                        assert!(index.claude_history_gate_loaded);
                    }
                    index.note_claude_history_cutoff(PriorHistory::Here, false, false);
                    assert!(index.claude_history_gate_loaded);
                    assert!(index.claude_history_cutoff_unix_seconds.is_some());
                    assert_eq!(index.claude_no_list_policy, NoListPolicy::HoldMoveNotFull);
                }
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(corrupt_count(scratch.as_ref()), 0);
                let mut working = loaded;
                if bounded {
                    working.save_with_read_limit(&path, 1024 * 1024).unwrap();
                } else {
                    working.save(&path).unwrap();
                }
                let mut restarted = ScanIndex::load(&path).unwrap();
                assert_sibling(&restarted);
                assert_eq!(restarted.generation, working.generation);
                restarted.note_claude_history_cutoff(PriorHistory::Here, false, false);
                assert_eq!(
                    restarted.claude_no_list_policy,
                    NoListPolicy::HoldMoveNotFull
                );
                restarted.note_claude_history_cutoff(PriorHistory::Here, true, false);
                assert_eq!(restarted.claude_no_list_policy, NoListPolicy::Pace);
                assert!(!restarted.claude_history_move_not_full);
                assert!(restarted.claude_history_move_released);
                assert_eq!(corrupt_count(scratch.as_ref()), 0);
            }
        }
    }
}

// Every current failure shares one budget, regardless of the previous cause.
fn whole_index_damage(kind: &str) -> Vec<u8> {
    match kind {
        "syntax" => b"{".to_vec(),
        "budget" => {
            let mut value = serde_json::to_value(fixture()).unwrap();
            value["files"]["excess-held"] =
                serde_json::json!({"unknown": "x".repeat(2 * 1024 * 1024)});
            serde_json::to_vec(&value).unwrap()
        }
        "collision" => {
            let mut index = fixture();
            let key = "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4";
            index
                .codex_state_only_snapshot_fingerprints
                .insert(key.to_string(), "lower".to_string());
            index
                .codex_state_only_snapshot_fingerprints
                .insert(key.to_ascii_uppercase(), "upper".to_string());
            serde_json::to_vec(&index).unwrap()
        }
        _ => panic!("unknown synthetic damage"),
    }
}

#[test]
fn every_whole_index_rebuild_cause_shares_the_seven_day_guard() {
    for previous in ["budget", "syntax", "collision"] {
        for current in ["budget", "syntax", "collision"] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-all-rebuild-causes");
            let path = scratch.join("index.json");
            let previous_bytes = whole_index_damage(previous);
            fs::write(&path, &previous_bytes).unwrap();
            let before = scan_index_containment_lines_for_test().len();
            let (index, origin) =
                ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode)).unwrap();
            assert!(index.files.is_empty());
            assert!(matches!(origin, LoadOrigin::Quarantined));
            assert!(!path.exists());
            assert_eq!(corrupt_count(scratch.as_ref()), 1);
            let backup = fs::read_dir(scratch.as_ref())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .contains(".corrupt.")
                })
                .unwrap();
            assert_eq!(fs::read(&backup).unwrap(), previous_bytes);
            let lines = scan_index_containment_lines_for_test();
            let success = lines[before..]
                .iter()
                .filter(|line| line.contains("fallback=gated_rebuild"))
                .collect::<Vec<_>>();
            assert_eq!(success.len(), 1);
            assert!(success[0].contains("history_policy=prior_history_gated_rebuild"));

            let bytes = whole_index_damage(current);
            fs::write(&path, &bytes).unwrap();
            let before = scan_index_containment_lines_for_test().len();
            let error = ScanIndex::load_inner(&path, Some(SnapshotSource::ClaudeCode)).unwrap_err();
            assert!(
                error.downcast_ref::<ScanIndexRebuildLoop>().is_some(),
                "{previous} -> {current}: {error:#}"
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(fs::read(&backup).unwrap(), previous_bytes);
            assert_eq!(corrupt_count(scratch.as_ref()), 1);
            let lines = scan_index_containment_lines_for_test();
            assert!(!lines[before..]
                .iter()
                .any(|line| line.contains("fallback=gated_rebuild")));
            assert!(lines[before..]
                .iter()
                .any(|line| line.contains("refusal_kind=rebuild_loop")
                    && line.contains("source=claude_code")
                    && line.contains("source_paused=1")
                    && line.contains("index_kept=1")
                    && line.contains("alarm")));
        }
    }
}

#[test]
fn load_refuses_future_quarantine_stamp_and_rebuilds_after_seven_days() {
    let now = SystemTime::now();
    let now_nanos = now.duration_since(UNIX_EPOCH).unwrap().as_nanos();
    for current in ["budget", "syntax", "collision"] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-load-cooldown-time");
        let path = scratch.join("index.json");
        let bytes = whole_index_damage(current);
        fs::write(&path, &bytes).unwrap();
        // A future rename stamp remains a hold during clock rollback.
        let stamp = now_nanos + 24 * 60 * 60 * 1_000_000_000;
        let backup = scratch.join(format!("index.corrupt.123.{stamp}.json"));
        fs::write(&backup, b"prior witness").unwrap();
        let error = ScanIndex::load_inner_at(&path, None, now).unwrap_err();
        assert!(error.downcast_ref::<ScanIndexRebuildLoop>().is_some());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
        // The exact 7-day boundary is still protected.
        let boundary = UNIX_EPOCH
            + std::time::Duration::from_nanos(
                u64::try_from(stamp + SCAN_INDEX_REBUILD_COOLDOWN_NANOS).unwrap(),
            );
        assert!(ScanIndex::load_inner_at(&path, None, boundary)
            .unwrap_err()
            .downcast_ref::<ScanIndexRebuildLoop>()
            .is_some());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let before = scan_index_containment_lines_for_test().len();
        let (index, origin) =
            ScanIndex::load_inner_at(&path, None, boundary + std::time::Duration::from_nanos(1))
                .unwrap();
        assert!(index.files.is_empty());
        assert!(matches!(origin, LoadOrigin::Quarantined));
        assert!(!path.exists());
        assert_eq!(corrupt_count(scratch.as_ref()), 2);
        assert_eq!(fs::read(&backup).unwrap(), b"prior witness");
        assert!(scan_index_containment_lines_for_test()[before..]
            .iter()
            .any(|line| line.contains("fallback=gated_rebuild")));
    }
}

// SI-718-O1/O2: the user Repair override keeps the session-identity state the
// seven-day guard was protecting, and its cooldown is source-wide.
const OVERRIDE_OWNER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OVERRIDE_OWNER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn reset_override_state_for_restart() {
    SCAN_INDEX_REBUILD_OVERRIDE.with(|cell| cell.set([ScanIndexRebuildOverrideState::NONE; 3]));
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        note_scan_index_rebuild_paused(source, false);
    }
}

/// Hold-budget damage in the daemon's own field order (`files` before the
/// identity fields), with `tail` fields appended after every other field.
fn struct_order_budget_damage(index: &ScanIndex, tail: &str) -> Vec<u8> {
    let text = serde_json::to_string(index).unwrap();
    let excess = format!(
        "\"files\":{{\"excess-held\":{{\"unknown\":\"{}\"}},",
        "x".repeat(2 * 1024 * 1024)
    );
    assert!(text.contains("\"files\":{\"/synthetic/"));
    let text = text.replacen("\"files\":{", &excess, 1);
    format!("{}{tail}}}", &text[..text.len() - 1]).into_bytes()
}

/// An old owner A for `session`, a deferred hold, accepted fingerprints, the
/// contract token and latch, owned-start and stale-carry posture, duplicate
/// ownership and the closed duplicate fence.
fn override_identity_seed(session: &str, latch: bool) -> ScanIndex {
    let mut index = fixture();
    index.session_account_bindings.insert(
        sha256_hex(&["session_owner:v1", "machine-a", session]),
        SessionAccountBinding {
            account_identifier_hash: OVERRIDE_OWNER_A.into(),
            workspace_identifier_hash: Some("c".repeat(64)),
        },
    );
    index
        .claude_account_deferred_holds
        .insert("/synthetic/held.jsonl".into(), "d".repeat(64));
    index.claude_request_identity_contract = Some("prior-contract".into());
    index.claude_request_identity_contract_changed = latch;
    index.claude_owned_start_census = serde_json::from_value(
        serde_json::json!({"member":{"marker_source_file_fingerprint":"fp"}}),
    )
    .unwrap();
    index.claude_stale_family_carry =
        serde_json::from_value(serde_json::json!({"roots":["carried-family"]})).unwrap();
    index.claude_duplicate_request_owners = serde_json::from_value(serde_json::json!(
        {"request":[{"root_session_id_hash":"root","source_session_id_hash":"session"}]}
    ))
    .unwrap();
    index.claude_duplicate_request_witness_overflowed = true;
    // A replay this index had already completed.
    index.historical_replay_generation = Some("replay-generation".into());
    assert!(!index.accepted_snapshot_fingerprints.is_empty());
    index
}

fn as_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn assert_identity_carried(index: &ScanIndex, seed: &ScanIndex, context: &str) {
    assert_eq!(
        as_json(&index.session_account_bindings),
        as_json(&seed.session_account_bindings),
        "{context}"
    );
    assert_eq!(
        as_json(&index.claude_account_deferred_holds),
        as_json(&seed.claude_account_deferred_holds),
        "{context}"
    );
    assert_eq!(
        index.claude_request_identity_contract, seed.claude_request_identity_contract,
        "{context}"
    );
    assert!(index.claude_request_identity_contract_changed, "{context}");
    assert_eq!(
        as_json(&index.claude_owned_start_census),
        as_json(&seed.claude_owned_start_census),
        "{context}"
    );
    assert_eq!(
        as_json(&index.claude_stale_family_carry),
        as_json(&seed.claude_stale_family_carry),
        "{context}"
    );
    assert_eq!(
        as_json(&index.claude_duplicate_request_owners),
        as_json(&seed.claude_duplicate_request_owners),
        "{context}"
    );
    assert!(
        index.claude_duplicate_request_witness_overflowed,
        "{context}"
    );
    assert_eq!(
        index.accepted_snapshot_fingerprints, seed.accepted_snapshot_fingerprints,
        "{context}"
    );
    assert_eq!(
        index.historical_replay_generation, seed.historical_replay_generation,
        "{context}"
    );
    // The completed replay stays complete: no spurious replay preparation
    // clears the carried acknowledgements or owned-start census.
    let mut replayed = index.clone();
    assert!(
        !replayed.prepare_historical_replay("replay-generation".into()),
        "{context}"
    );
    assert_eq!(
        replayed.accepted_snapshot_fingerprints, seed.accepted_snapshot_fingerprints,
        "{context}"
    );
    assert_eq!(
        as_json(&replayed.claude_owned_start_census),
        as_json(&seed.claude_owned_start_census),
        "{context}"
    );
}

#[test]
fn malformed_upload_ack_retirement_handoff_keeps_index_identity_without_pause() {
    for bounded in [false, true] {
        for (case, damaged) in [
            ("null", serde_json::json!(null)),
            ("string", serde_json::json!("damaged-handoff")),
            (
                "negative-generation",
                serde_json::json!({
                    "destination_namespace_hash": "c".repeat(64),
                    "committed_generation": -1,
                    "bodies": {"d".repeat(64): "e".repeat(64)}
                }),
            ),
        ] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-ack-handoff");
            let path = scratch.join("index.json");
            let support = scratch.join("support");
            let source = SnapshotSource::ClaudeCode;
            let mut seed = override_identity_seed("handoff-owner", true);
            seed.save(&path).unwrap();
            let mut value = serde_json::to_value(&seed).unwrap();
            value["upload_ack_retirement_handoff"] = damaged;
            let bytes = serde_json::to_vec(&value).unwrap();
            fs::write(&path, &bytes).unwrap();

            let before = scan_index_containment_lines_for_test().len();
            let (mut loaded, origin) =
                ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support).unwrap();
            assert_eq!(origin, ScanIndexLoadOrigin::Loaded, "{case}");
            assert!(!scan_index_rebuild_paused(source), "{case}");
            assert!(loaded.upload_ack_retirement_handoff.is_none(), "{case}");
            assert_identity_carried(&loaded, &seed, case);
            assert_eq!(
                loaded.accepted_snapshot_fingerprints,
                seed.accepted_snapshot_fingerprints
            );
            assert_eq!(as_json(&loaded.files), as_json(&seed.files));
            assert_eq!(
                loaded.file_snapshot_fingerprints,
                seed.file_snapshot_fingerprints
            );
            assert_eq!(loaded.snapshot_activity_at, seed.snapshot_activity_at);
            assert_eq!(loaded.generation, seed.generation);
            assert!(loaded.decode_holds.is_empty(), "{case}");
            assert_eq!(
                fs::read(&path).unwrap(),
                bytes,
                "load never rewrites {case}"
            );
            assert_eq!(corrupt_count(&scratch), 0);
            assert!(
                !scan_index_containment_lines_for_test()[before..]
                    .iter()
                    .any(|line| line.contains("source_paused=1")),
                "{case}"
            );

            // Both CAS readers must accept the repaired cleanup field, too.
            if bounded {
                loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
            } else {
                loaded.save(&path).unwrap();
            }
            let reloaded = ScanIndex::load(&path).unwrap();
            assert!(reloaded.upload_ack_retirement_handoff.is_none());
            assert_identity_carried(&reloaded, &seed, case);
            assert_eq!(
                reloaded.accepted_snapshot_fingerprints,
                seed.accepted_snapshot_fingerprints
            );
            assert_eq!(
                reloaded.file_snapshot_fingerprints,
                seed.file_snapshot_fingerprints
            );
        }
    }
}

#[test]
fn user_repair_override_keeps_prior_identity_authoritative_through_failures() {
    let mut item = tests::valid_v6_batch_request().snapshots.remove(0);
    let session = item.source_session_id.clone();
    let owner_key = sha256_hex(&["session_owner:v1", "machine-a", &session]);
    let source = SnapshotSource::ClaudeCode;
    for (damage_kind, latch) in [("budget", true), ("collision", true), ("budget", false)] {
        let context = format!("{damage_kind} latch={latch}");
        reset_override_state_for_restart();
        let scratch = crate::test_scratch::ScratchDir::new("lenient-override-identity");
        let path = scratch.join("index.json");
        let support = scratch.join("support");
        let load = || ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support);
        // The first incident is the pre-existing gated rebuild.
        fs::write(&path, b"{").unwrap();
        assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Quarantined);

        let seed = override_identity_seed(&session, latch);
        let damage = match damage_kind {
            "budget" => struct_order_budget_damage(&seed, ""),
            _ => {
                let mut seed = seed.clone();
                let key = "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4";
                seed.codex_state_only_snapshot_fingerprints
                    .insert(key.to_string(), "lower".to_string());
                seed.codex_state_only_snapshot_fingerprints
                    .insert(key.to_ascii_uppercase(), "upper".to_string());
                serde_json::to_vec(&seed).unwrap()
            }
        };
        fs::write(&path, &damage).unwrap();
        let error = load().unwrap_err();
        assert!(
            error.downcast_ref::<ScanIndexRebuildLoop>().is_some(),
            "{context}: {error:#}"
        );
        assert_eq!(fs::read(&path).unwrap(), damage, "{context}");

        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::Armed
        );
        let overrides = scan_index_rebuild_manual_override_count();
        let before = scan_index_containment_lines_for_test().len();
        let (rebuilt, origin) = load().unwrap();
        assert_eq!(origin, ScanIndexLoadOrigin::Quarantined, "{context}");
        assert!(rebuilt.files.is_empty(), "{context}");
        assert_eq!(rebuilt.generation, 0, "{context}");
        assert_identity_carried(&rebuilt, &seed, &context);
        assert_eq!(scan_index_rebuild_manual_override_count(), overrides + 1);
        assert!(
            scan_index_containment_lines_for_test()[before..]
                .iter()
                .any(|line| line.contains("override=user_repair")
                    && line.contains("identity=carried"))
        );
        // The damaged bytes are the override witness.
        let witness = fs::read_dir(scratch.as_ref())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("index.corrupt.override.")
            })
            .unwrap();
        assert_eq!(fs::read(&witness).unwrap(), damage, "{context}");
        assert!(scan_index_override_stamp_path(&support, source).exists());

        // Post-override failure: the replacement cycle dies before any save.
        // The next load reads the carried rebuild, still fresh (generation 0,
        // no files), never an empty identity graph.
        drop(rebuilt);
        let (mut reloaded, origin) = load().unwrap();
        assert_eq!(origin, ScanIndexLoadOrigin::Loaded, "{context}");
        assert_eq!(reloaded.generation, 0, "{context}");
        assert!(reloaded.files.is_empty(), "{context}");
        assert!(!scan_index_rebuild_paused(source));
        assert_identity_carried(&reloaded, &seed, &context);

        // Post-override evidence: conflicting exact creator B defers and
        // never replaces the retained owner A.
        set_session_account_hash(&mut item, Some(OVERRIDE_OWNER_B));
        let deferred = reloaded.bind_session_accounts(
            SnapshotSource::ClaudeCode,
            "machine-a",
            &mut [item.clone()],
            &[],
        );
        assert!(deferred.contains(&session), "{context}");
        assert_eq!(
            reloaded.session_account_bindings[&owner_key].account_identifier_hash,
            OVERRIDE_OWNER_A
        );

        // A replacement page records acknowledgements and checkpoints a
        // partial commit: the carried ones have no file incidence yet and
        // are kept until a census re-derives it.
        assert!(reloaded.accepted_incidence_pending_census, "{context}");
        reloaded.record_accepted_snapshot_fingerprints(&BTreeSet::new());
        let partial =
            reloaded.committable_subset(&reloaded.clone(), &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            partial.accepted_snapshot_fingerprints, seed.accepted_snapshot_fingerprints,
            "{context}"
        );
        assert!(partial.accepted_incidence_pending_census, "{context}");

        // A settled upload saves; a stale writer's CAS then fails. A stays.
        let mut stale = reloaded.clone();
        reloaded.save(&path).unwrap();
        assert!(stale.save(&path).is_err(), "{context}");
        let mut restarted = load().unwrap().0;
        assert_eq!(restarted.generation, 1, "{context}");
        assert_identity_carried(&restarted, &seed, &context);
        assert!(restarted
            .bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "machine-a",
                &mut [item.clone()],
                &[]
            )
            .contains(&session));
        assert_eq!(
            restarted.session_account_bindings[&owner_key].account_identifier_hash,
            OVERRIDE_OWNER_A
        );
        // Only reconstructing each carried file retires its debt; census alone
        // proves neither reconstruction nor the release of history-held files.
        assert!(restarted.accepted_incidence_pending_census, "{context}");
        assert!(
            !restarted.accepted_rebuild_incidence.is_empty(),
            "{context}"
        );
        assert_eq!(
            restarted.accepted_rebuild_incidence,
            seed.file_snapshot_fingerprints
        );
        restarted.record_accepted_snapshot_fingerprints(&BTreeSet::new());
        assert_eq!(
            restarted.accepted_snapshot_fingerprints,
            seed.accepted_snapshot_fingerprints
        );
    }
}

#[test]
fn user_repair_override_refuses_when_identity_state_is_unrecoverable() {
    let source = SnapshotSource::ClaudeCode;
    for (case, damage) in [
        ("syntax", b"{ ".to_vec()),
        (
            "bindings",
            struct_order_budget_damage(&fixture(), ",\"session_account_bindings\":17"),
        ),
        (
            "latch",
            struct_order_budget_damage(
                &fixture(),
                ",\"claude_request_identity_contract_changed\":\"x\"",
            ),
        ),
        (
            "owned_start",
            struct_order_budget_damage(&fixture(), ",\"claude_owned_start_census\":17"),
        ),
    ] {
        reset_override_state_for_restart();
        let scratch = crate::test_scratch::ScratchDir::new("lenient-override-unrecoverable");
        let path = scratch.join("index.json");
        let support = scratch.join("support");
        let load = || ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support);
        let refused = || {
            let error = load().unwrap_err();
            assert!(
                error.downcast_ref::<ScanIndexRebuildLoop>().is_some(),
                "{case}: {error:#}"
            );
            assert!(scan_index_rebuild_paused(source));
            assert_eq!(fs::read(&path).unwrap(), damage, "{case}");
            error
        };
        fs::write(&path, b"{").unwrap();
        assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Quarantined);
        fs::write(&path, &damage).unwrap();
        // The whole-index failure wins over the strict field, so the guard
        // (not a strict refusal) is what pauses the source.
        refused();
        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::Armed
        );
        let overrides = scan_index_rebuild_manual_override_count();
        let refusals = scan_index_rebuild_override_identity_unrecoverable_count();
        let before = scan_index_containment_lines_for_test().len();
        let error = refused();
        assert!(
            format!("{error:#}").contains(SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE),
            "{case}: {error:#}"
        );
        assert_eq!(
            SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE,
            "scan_index_rebuild_override_identity_unrecoverable"
        );
        // No rebuild: no override witness, no stamp, counted and alarmed.
        assert_eq!(corrupt_count(scratch.as_ref()), 1, "{case}");
        assert!(!scan_index_override_stamp_path(&support, source).exists());
        assert_eq!(scan_index_rebuild_manual_override_count(), overrides);
        assert_eq!(
            scan_index_rebuild_override_identity_unrecoverable_count(),
            refusals + 1
        );
        let lines = scan_index_containment_lines_for_test();
        let alarms = lines[before..]
            .iter()
            .filter(|line| {
                line.contains("override_refused=scan_index_rebuild_override_identity_unrecoverable")
            })
            .collect::<Vec<_>>();
        assert_eq!(alarms.len(), 1, "{case}");
        assert!(alarms[0].contains(&format!(
            "scan_index_rebuild_override_identity_unrecoverable={}",
            refusals + 1
        )));
        assert!(alarms[0].contains("source=claude_code"));
        assert!(alarms[0].contains("source_paused=1"));
        assert!(alarms[0].contains("index_kept=1"));
        assert!(alarms[0].contains("alarm"));
        assert!(!lines[before..]
            .iter()
            .any(|line| line.contains("fallback=gated_rebuild")));
        assert_eq!(
            scan_index_rebuild_override_refusal(source),
            Some(SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE)
        );
        // Automatic loads keep refusing. A later press gives the SAME refusal,
        // never "already used": refusal did not spend the successful cooldown.
        refused();
        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::IdentityUnrecoverable
        );
        assert_eq!(
            scan_index_rebuild_override_identity_unrecoverable_count(),
            refusals + 1
        );
        assert_eq!(
            with_scan_index_rebuild_override(source, |state| state.last_override_unix_seconds),
            None
        );
        assert_eq!(fs::read(&path).unwrap(), damage, "{case}");
        assert!(!scan_index_override_stamp_path(&support, source).exists());
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
        // A compatible replacement clears the refusal. Another recoverable
        // incident can arm immediately, without waiting the 24-hour cooldown.
        fs::write(&path, serde_json::to_vec(&fixture()).unwrap()).unwrap();
        assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Loaded);
        fs::write(&path, struct_order_budget_damage(&fixture(), "")).unwrap();
        assert!(load().is_err());
        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::Armed
        );
    }
}

#[test]
fn user_repair_override_cooldown_is_source_wide_across_destinations() {
    reset_override_state_for_restart();
    let scratch = crate::test_scratch::ScratchDir::new("lenient-override-source-wide");
    let support = scratch.join("support");
    let destination = |namespace: &str| {
        let dir = support.join("snapshots/destinations").join(namespace);
        fs::create_dir_all(&dir).unwrap();
        dir.join("claude_code-scan-index-v3.json")
    };
    let (a, b) = (destination(&"a".repeat(64)), destination(&"b".repeat(64)));
    let source = SnapshotSource::ClaudeCode;
    let load =
        |path: &Path| ScanIndex::load_for_snapshot_source_with_origin(path, source, &support);
    let damage = struct_order_budget_damage(&fixture(), "");
    let refused = |path: &Path| {
        let error = load(path).unwrap_err();
        assert!(
            error.downcast_ref::<ScanIndexRebuildLoop>().is_some(),
            "{error:#}"
        );
        assert_eq!(fs::read(path).unwrap(), damage);
    };
    let pause = |path: &Path| {
        fs::write(path, b"{").unwrap();
        assert_eq!(load(path).unwrap().1, ScanIndexLoadOrigin::Quarantined);
        fs::write(path, &damage).unwrap();
        refused(path);
    };

    // Repair consumes the override under destination A.
    pause(&a);
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Armed
    );
    assert_eq!(load(&a).unwrap().1, ScanIndexLoadOrigin::Quarantined);
    let stamp = scan_index_override_stamp_path(&support, source);
    assert!(stamp.exists());
    assert!(!stamp.starts_with(support.join("snapshots/destinations")));

    // Restart, then re-pair: a new destination namespace with no override
    // witness of its own still sees A's override and cools for 24 hours.
    reset_override_state_for_restart();
    pause(&b);
    assert!(scan_index_rebuild_witness_stamps(&b)
        .unwrap()
        .newest_override
        .is_none());
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Cooldown
    );
    assert_eq!(
        SCAN_INDEX_REBUILD_OVERRIDE_COOLDOWN_CODE,
        "scan_index_rebuild_override_cooldown"
    );
    refused(&b);
    // 24 hours after A's override one press is allowed again.
    assert_eq!(
        arm_scan_index_rebuild_manual_override(
            source,
            SystemTime::now() + std::time::Duration::from_secs(25 * 60 * 60)
        ),
        ScanIndexRebuildOverride::Armed
    );

    // Clock rollback: a future source-wide stamp still cools.
    let future = unix_seconds_at(SystemTime::now()) + 48 * 60 * 60;
    fs::write(
        &stamp,
        format!("{{\"last_override_unix_seconds\":{future}}}"),
    )
    .unwrap();
    reset_override_state_for_restart();
    pause(&destination(&"c".repeat(64)));
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Cooldown
    );
    // A malformed stamp fails closed from its own mtime.
    fs::write(&stamp, b"not a stamp").unwrap();
    reset_override_state_for_restart();
    pause(&destination(&"d".repeat(64)));
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Cooldown
    );
    assert_eq!(
        arm_scan_index_rebuild_manual_override(
            source,
            SystemTime::now() + std::time::Duration::from_secs(25 * 60 * 60)
        ),
        ScanIndexRebuildOverride::Armed
    );
}

#[test]
fn carried_ack_debt_is_fixed_while_new_sibling_revisions_prune() {
    let seed = fixture();
    let mut rebuilt = ScanIndex::default();
    rebuilt.carry_identity_from(seed.clone()).unwrap();
    let initial_debt = rebuilt.accepted_rebuild_incidence.clone();
    let initial_size = rebuilt.carried_ack_debt_size();
    assert!(initial_size.0 > 0 && initial_size.1 > 0);
    assert!(initial_size.0 <= CARRIED_ACK_ENTRIES_MAX);
    assert!(initial_size.1 <= CARRIED_ACK_BYTES_MAX);
    // No census can finish, but an ordinary healthy sibling keeps changing.
    // Only the originally carried ACKs survive; superseded new ACKs do not.
    for revision in 100..200 {
        let fp = format!("{revision:064x}");
        rebuilt
            .file_snapshot_fingerprints
            .insert("healthy".into(), BTreeSet::from([fp.clone()]));
        rebuilt.record_accepted_snapshot_fingerprints(&BTreeSet::from([fp.clone()]));
        rebuilt.retain_quarantined_fingerprints(&BTreeMap::new());
        assert_eq!(rebuilt.accepted_rebuild_incidence, initial_debt);
        assert_eq!(rebuilt.carried_ack_debt_size(), initial_size);
        let mut expected = seed.accepted_snapshot_fingerprints.clone();
        expected.insert(fp);
        assert_eq!(rebuilt.accepted_snapshot_fingerprints, expected);
    }
    let scratch = crate::test_scratch::ScratchDir::new("carried-ack-bounded-restart");
    let path = scratch.join("index.json");
    rebuilt.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(reloaded.accepted_rebuild_incidence, initial_debt);
    assert_eq!(reloaded.carried_ack_debt_size(), initial_size);
    assert!(scan_index_containment_lines_for_test()
        .iter()
        .any(|line| line.contains(&format!(
            "scan_index_rebuild_carried_ack_debt_entries={}",
            initial_size.0
        )) && line.contains(&format!(
            "scan_index_rebuild_carried_ack_debt_bytes={}",
            initial_size.1
        ))));
}

#[test]
fn carried_ack_debt_admission_refuses_before_writes_and_counts_by_code() {
    let source = SnapshotSource::ClaudeCode;
    for byte_exhaustion in [false, true] {
        reset_override_state_for_restart();
        let scratch = crate::test_scratch::ScratchDir::new("carried-ack-admission");
        let path = scratch.join("index.json");
        let support = scratch.join("support");
        let load = || ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support);
        fs::write(&path, b"{").unwrap();
        assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Quarantined);
        let mut seed = fixture();
        if byte_exhaustion {
            // A key must be admitted before allocating/retaining its String.
            seed.file_snapshot_fingerprints.insert(
                "x".repeat(CARRIED_ACK_BYTES_MAX),
                BTreeSet::from(["0".repeat(64)]),
            );
        } else {
            seed.file_snapshot_fingerprints.insert(
                "many".into(),
                (0..CARRIED_ACK_ENTRIES_MAX)
                    .map(|n| format!("{n:064x}"))
                    .collect(),
            );
        }
        let damage = struct_order_budget_damage(&seed, "");
        fs::write(&path, &damage).unwrap();
        assert!(load()
            .unwrap_err()
            .downcast_ref::<ScanIndexRebuildLoop>()
            .is_some());
        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::Armed
        );
        let budget = scan_index_rebuild_override_refused_count(
            SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE,
        );
        let identity = scan_index_rebuild_override_identity_unrecoverable_count();
        let manual = scan_index_rebuild_manual_override_count();
        let error = load().unwrap_err();
        assert!(format!("{error:#}").contains(SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE));
        assert_eq!(fs::read(&path).unwrap(), damage);
        assert_eq!(corrupt_count(scratch.as_ref()), 1);
        assert!(!scan_index_override_stamp_path(&support, source).exists());
        assert_eq!(scan_index_rebuild_manual_override_count(), manual);
        assert_eq!(
            scan_index_rebuild_override_identity_unrecoverable_count(),
            identity
        );
        assert_eq!(
            scan_index_rebuild_override_refused_count(
                SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE
            ),
            budget + 1
        );
        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::Refused(SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE)
        );
        assert_eq!(
            scan_index_rebuild_override_refused_count(
                SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE
            ),
            budget + 1
        );
        assert_eq!(
            with_scan_index_rebuild_override(source, |state| state.last_override_unix_seconds),
            None
        );
    }
}

#[test]
fn override_persistence_refusal_leaves_cooldown_unspent() {
    reset_override_state_for_restart();
    let source = SnapshotSource::ClaudeCode;
    let scratch = crate::test_scratch::ScratchDir::new("override-write-refusal");
    let path = scratch.join("index.json");
    let support = scratch.join("support");
    let load = || ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support);
    fs::write(&path, b"{").unwrap();
    assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Quarantined);
    let damage = struct_order_budget_damage(&fixture(), "");
    fs::write(&path, &damage).unwrap();
    assert!(load()
        .unwrap_err()
        .downcast_ref::<ScanIndexRebuildLoop>()
        .is_some());
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Armed
    );
    let stamp = scan_index_override_stamp_path(&support, source);
    // A synthetic obstruction makes stamp staging fail before replacement.
    fs::create_dir_all(stamp.with_extension(format!("json.{}.tmp", std::process::id()))).unwrap();
    let before =
        scan_index_rebuild_override_refused_count(SCAN_INDEX_REBUILD_OVERRIDE_PERSISTENCE_CODE);
    let identity = scan_index_rebuild_override_identity_unrecoverable_count();
    let budget = scan_index_rebuild_override_refused_count(
        SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE,
    );
    let error = load().unwrap_err();
    assert!(format!("{error:#}").contains(SCAN_INDEX_REBUILD_OVERRIDE_PERSISTENCE_CODE));
    assert_eq!(fs::read(&path).unwrap(), damage);
    assert_eq!(corrupt_count(scratch.as_ref()), 1);
    assert!(!stamp.exists());
    assert_eq!(
        with_scan_index_rebuild_override(source, |state| state.last_override_unix_seconds),
        None
    );
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Refused(SCAN_INDEX_REBUILD_OVERRIDE_PERSISTENCE_CODE)
    );
    assert_eq!(
        scan_index_rebuild_override_refused_count(SCAN_INDEX_REBUILD_OVERRIDE_PERSISTENCE_CODE),
        before + 1
    );
    assert_eq!(
        scan_index_rebuild_override_identity_unrecoverable_count(),
        identity
    );
    assert_eq!(
        scan_index_rebuild_override_refused_count(
            SCAN_INDEX_REBUILD_OVERRIDE_CARRIED_ACK_BUDGET_CODE
        ),
        budget
    );
}

#[test]
fn override_does_not_carry_unproven_or_preledger_acks() {
    for version in [
        SNAPSHOT_ACCEPTED_LEDGER_PRE_LEDGER_VERSION,
        SNAPSHOT_ACCEPTED_LEDGER_UNPROVEN_VERSION,
    ] {
        let mut seed = fixture();
        seed.accepted_snapshot_fingerprint_ledger_version = version;
        let mut rebuilt = ScanIndex::default();
        rebuilt.carry_identity_from(seed).unwrap();
        assert!(rebuilt.accepted_snapshot_fingerprints.is_empty());
        assert!(rebuilt.accepted_rebuild_incidence.is_empty());
        assert!(!rebuilt.accepted_incidence_pending_census);
    }
}

#[test]
fn carried_ack_at_entry_cap_is_never_lost_or_reoffered() {
    let original = (0..CARRIED_ACK_ENTRIES_MAX - 1)
        .map(|n| format!("{n:064x}"))
        .collect::<BTreeSet<_>>();
    let mut seed = ScanIndex {
        accepted_snapshot_fingerprints: original.clone(),
        ..ScanIndex::default()
    };
    seed.file_snapshot_fingerprints
        .insert("original-held".into(), original.clone());
    let mut rebuilt = ScanIndex::default();
    rebuilt.carry_identity_from(seed).unwrap();
    assert_eq!(rebuilt.carried_ack_debt_size().0, CARRIED_ACK_ENTRIES_MAX);
    let frozen = rebuilt.accepted_rebuild_incidence.clone();
    for revision in 10000..10100 {
        let fp = format!("{revision:064x}");
        rebuilt
            .file_snapshot_fingerprints
            .insert("healthy-sibling".into(), BTreeSet::from([fp.clone()]));
        rebuilt.record_accepted_snapshot_fingerprints(&BTreeSet::from([fp]));
        rebuilt.retain_quarantined_fingerprints(&BTreeMap::new());
        assert_eq!(rebuilt.accepted_rebuild_incidence, frozen);
        assert!(original
            .iter()
            .all(|fp| rebuilt.accepted_snapshot_fingerprint_recorded(fp)));
        assert_eq!(
            original
                .difference(&rebuilt.accepted_snapshot_fingerprints)
                .count(),
            0,
            "no original ACK is offerable"
        );
        assert_eq!(
            rebuilt.accepted_snapshot_fingerprints.len(),
            original.len() + 1
        );
    }
    let scratch = crate::test_scratch::ScratchDir::new("carried-ack-at-cap");
    let path = scratch.join("index.json");
    rebuilt.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(reloaded.accepted_rebuild_incidence, frozen);
    assert_eq!(
        original
            .difference(&reloaded.accepted_snapshot_fingerprints)
            .count(),
        0
    );
}

/// SI O3: a real walk reaches its raw terminal without visiting a held family
/// member. Neither that terminal nor save/reload may retire the original carry.
#[test]
#[serial_test::serial(source_manifests)]
fn carried_ack_for_unvisited_family_hold_survives_until_reconstruction() {
    let scratch = crate::test_scratch::ScratchDir::new("carried-unvisited-family-hold");
    let root = scratch.join("projects");
    let path = scratch.join("index.json");
    let session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    fs::create_dir_all(&root).unwrap();
    let transcript = root.join(format!("{session}.jsonl"));
    fs::write(&transcript, format!("{{\"timestamp\":\"2026-10-21T10:01:00Z\",\"sessionId\":\"{session}\",\"message\":{{\"id\":\"message\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":35,\"output_tokens\":8}}}}}}\n")).unwrap();
    let original_transcript = fs::read(&transcript).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let scan = |index: &mut ScanIndex, at: &str| {
        scan_source_roots(
            source,
            std::slice::from_ref(&root),
            index,
            at,
            BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    };
    let mut seed = ScanIndex::default();
    let first = scan(&mut seed, "2026-10-22T00:00:00Z");
    assert_eq!(first.snapshots.len(), 1);
    let mut accepted = first
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    let actual_accepted = accepted.clone();
    // Fund the carried set exactly to its combined entry cap, including a
    // genuine emitted/ACKed body. Extra old revisions model retained history.
    let key = local_index_key(&transcript);
    accepted.extend((10000..10000 + CARRIED_ACK_ENTRIES_MAX - 2).map(|n| format!("{n:064x}")));
    seed.file_snapshot_fingerprints
        .insert(key.clone(), accepted.clone());
    seed.record_accepted_snapshot_fingerprints(&accepted);
    let mut rebuilt = ScanIndex::default();
    rebuilt.carry_identity_from(seed).unwrap();
    assert_eq!(rebuilt.carried_ack_debt_size().0, CARRIED_ACK_ENTRIES_MAX);
    let original_carry = rebuilt.accepted_rebuild_incidence.clone();
    rebuilt.save(&path).unwrap();
    let mut value = serde_json::to_value(&rebuilt).unwrap();
    value["claude_account_family_witnesses"] =
        serde_json::json!({session: {"members": [false], "opaque": "future"}});
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut held = ScanIndex::load(&path).unwrap();
    assert!(held.decode_holds_file(&key));
    let walk = scan(&mut held, "2026-10-22T00:01:00Z");
    assert!(!walk.census_complete);
    assert_eq!(
        walk.scanned_file_count, 0,
        "the held member was never visited"
    );
    assert!(walk.snapshots.is_empty());
    assert!(held.traversal.is_none(), "the raw walk really finished");
    held.record_accepted_snapshot_fingerprints(&BTreeSet::new());
    held.save(&path).unwrap();
    let restarted = ScanIndex::load(&path).unwrap();
    assert!(restarted.accepted_incidence_pending_census);
    assert_eq!(restarted.accepted_rebuild_incidence, original_carry);
    assert_eq!(restarted.accepted_snapshot_fingerprints, accepted);
    // Even an absent member cannot retire debt behind a family HOLD.
    fs::remove_file(&transcript).unwrap();
    let mut absent_held = restarted;
    let missing = scan(&mut absent_held, "2026-10-22T00:01:30Z");
    assert!(!missing.census_complete);
    assert!(missing.snapshots.is_empty());
    absent_held.record_accepted_snapshot_fingerprints(&BTreeSet::new());
    absent_held.save(&path).unwrap();
    let restarted = ScanIndex::load(&path).unwrap();
    assert_eq!(restarted.accepted_rebuild_incidence, original_carry);
    assert_eq!(restarted.accepted_snapshot_fingerprints, accepted);
    assert!(restarted.accepted_incidence_pending_census);
    fs::write(&transcript, original_transcript).unwrap();
    // A compatible repair understands/removes the bad witness; the missing
    // derived file entry now forces actual reconstruction on a healthy pass.
    let mut repaired = serde_json::to_value(&restarted).unwrap();
    repaired["claude_account_family_witnesses"] = serde_json::json!({});
    fs::write(&path, serde_json::to_vec(&repaired).unwrap()).unwrap();
    let mut healthy = ScanIndex::load(&path).unwrap();
    let release = scan(&mut healthy, "2026-10-22T00:02:00Z");
    assert!(release.census_complete);
    assert_eq!(release.scanned_file_count, 1);
    assert!(
        release.snapshots.is_empty(),
        "accepted body must not re-offer"
    );
    assert!(healthy.accepted_rebuild_incidence.is_empty());
    assert!(!healthy.accepted_incidence_pending_census);
    healthy.record_accepted_snapshot_fingerprints(&BTreeSet::new());
    healthy.save(&path).unwrap();
    assert_eq!(
        ScanIndex::load(&path)
            .unwrap()
            .accepted_snapshot_fingerprints,
        actual_accepted
    );
}

#[test]
fn carried_ack_age_survives_restart_and_alarms_without_eviction_until_release() {
    const START: u64 = 2_000_000_000;
    const WEEK: u64 = 7 * 24 * 60 * 60;
    let at = |seconds| UNIX_EPOCH + std::time::Duration::from_secs(seconds);
    for unknown in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("carried-ack-age");
        let root = scratch.join("projects");
        let path = scratch.join("index.json");
        let session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(format!("{session}.jsonl")), format!("{{\"timestamp\":\"2026-10-21T10:01:00Z\",\"sessionId\":\"{session}\",\"message\":{{\"id\":\"message\",\"model\":\"claude-opus-4-8\",\"usage\":{{\"input_tokens\":35,\"output_tokens\":8}}}}}}\n")).unwrap();
        let source = SnapshotSource::ClaudeCode;
        let scan = |index: &mut ScanIndex, now: &str| {
            scan_source_roots(
                source,
                std::slice::from_ref(&root),
                index,
                now,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap()
        };
        let mut seed = ScanIndex::default();
        let first = scan(&mut seed, "2026-10-22T00:00:00Z");
        assert_eq!(first.snapshots.len(), 1);
        let accepted = first
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        seed.record_accepted_snapshot_fingerprints(&accepted);
        if unknown {
            seed.file_snapshot_fingerprints.clear();
        }
        let mut carried = ScanIndex::default();
        carried.carry_identity_from(seed).unwrap();
        let original = carried.accepted_rebuild_incidence.clone();
        assert_eq!(original.contains_key(""), unknown);
        carried.note_carried_ack_census(source, false, at(START));
        carried.save(&path).unwrap();
        let mut carried = ScanIndex::load(&path).unwrap();
        assert_eq!(
            carried.accepted_rebuild_pending_since_unix_seconds,
            Some(START)
        );
        let before = scan_index_containment_lines_for_test().len();
        carried.note_carried_ack_census(source, false, at(START + WEEK + 1));
        carried.note_carried_ack_census(source, false, at(START + WEEK + 2));
        carried.save(&path).unwrap();
        let mut carried = ScanIndex::load(&path).unwrap();
        carried.note_carried_ack_census(source, false, at(START + WEEK + 3));
        let lines = scan_index_containment_lines_for_test();
        assert_eq!(
            lines[before..]
                .iter()
                .filter(|line| line.contains("carried_ack_pending_stalled=1"))
                .count(),
            1
        );
        assert!(lines[before..].iter().any(|line| line
            .starts_with("local snapshot census: source=claude_code ")
            && line.contains(&format!("carried_ack_pending_age_seconds={}", WEEK + 1))));
        assert_eq!(carried.accepted_rebuild_incidence, original);
        assert_eq!(carried.accepted_snapshot_fingerprints, accepted);
        // A future first/alarm stamp is retained across clock rollback, not
        // reset to a new pending period or allowed to underflow/re-alarm.
        carried.note_carried_ack_census(source, false, at(START - 1));
        assert_eq!(
            carried.accepted_rebuild_pending_since_unix_seconds,
            Some(START)
        );
        assert_eq!(
            carried.accepted_rebuild_last_alarm_unix_seconds,
            Some(START + WEEK + 1)
        );
        assert!(scan_index_containment_lines_for_test()
            .last()
            .unwrap()
            .ends_with("carried_ack_pending_age_seconds=0"));
        assert_eq!(
            scan_index_containment_lines_for_test()[before..]
                .iter()
                .filter(|line| line.contains("carried_ack_pending_stalled=1"))
                .count(),
            1
        );
        let mut recarried = ScanIndex::default();
        recarried.carry_identity_from(carried.clone()).unwrap();
        assert_eq!(
            recarried.accepted_rebuild_pending_since_unix_seconds,
            Some(START)
        );
        assert_eq!(
            recarried.accepted_rebuild_last_alarm_unix_seconds,
            Some(START + WEEK + 1)
        );
        // A partial save that still owes the original files keeps their clock.
        let partial =
            carried.committable_subset(&carried.clone(), &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            partial.accepted_rebuild_pending_since_unix_seconds,
            Some(START)
        );
        assert_eq!(
            partial.accepted_rebuild_last_alarm_unix_seconds,
            Some(START + WEEK + 1)
        );
        let release = scan(&mut carried, "2026-10-22T00:01:00Z");
        assert!(release.census_complete);
        assert_eq!(release.scanned_file_count, 1);
        assert!(
            release.snapshots.is_empty(),
            "age diagnostics must never re-offer an ACK"
        );
        if unknown {
            // Reconstructing a guessed file cannot retire unknown incidence.
            assert_eq!(carried.accepted_rebuild_incidence, original);
            assert_eq!(
                carried.accepted_rebuild_pending_since_unix_seconds,
                Some(START)
            );
            // Only an existing intentional replay release clears unknown debt.
            assert!(carried.prepare_historical_replay("age-test-release".into()));
        }
        assert!(carried.accepted_rebuild_incidence.is_empty());
        assert_eq!(carried.accepted_rebuild_pending_since_unix_seconds, None);
        assert_eq!(carried.accepted_rebuild_last_alarm_unix_seconds, None);
        carried.note_carried_ack_census(source, true, at(START + 2 * WEEK));
        assert!(scan_index_containment_lines_for_test()
            .last()
            .unwrap()
            .ends_with("carried_ack_pending_age_seconds=0"));
        assert_eq!(
            scan_index_containment_lines_for_test()[before..]
                .iter()
                .filter(|line| line.contains("carried_ack_pending_stalled=1"))
                .count(),
            1
        );
    }
}

#[test]
fn carried_ack_clock_scalars_bound_malformed_spans_across_load_cas_and_override() {
    for field in [
        "accepted_rebuild_pending_since_unix_seconds",
        "accepted_rebuild_last_alarm_unix_seconds",
    ] {
        for bounded in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("carried-ack-clock-span");
            let path = scratch.join("index.json");
            let mut carried = ScanIndex::default();
            carried.carry_identity_from(fixture()).unwrap();
            carried.accepted_rebuild_pending_since_unix_seconds = Some(u64::MAX);
            carried.accepted_rebuild_last_alarm_unix_seconds = Some(u64::MAX);
            carried.save(&path).unwrap();
            let valid = ScanIndex::load(&path).unwrap();
            assert_eq!(
                valid.accepted_rebuild_pending_since_unix_seconds,
                Some(u64::MAX)
            );
            assert_eq!(
                valid.accepted_rebuild_last_alarm_unix_seconds,
                Some(u64::MAX)
            );
            let mut value = serde_json::to_value(&carried).unwrap();
            value[field] = Value::String("x".repeat(2 * 1024 * 1024));
            let bytes = serde_json::to_vec(&value).unwrap();
            fs::write(&path, &bytes).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(serde_json::to_value(&loaded).unwrap().get(field), None);
            assert_eq!(
                loaded.accepted_snapshot_fingerprints,
                carried.accepted_snapshot_fingerprints
            );
            assert_eq!(
                loaded.accepted_rebuild_incidence,
                carried.accepted_rebuild_incidence
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
            let recovered =
                lenient_decode::read_identity_carry(File::open(&path).unwrap(), "claude_code")
                    .unwrap();
            assert_eq!(serde_json::to_value(&recovered).unwrap().get(field), None);
            assert_eq!(
                recovered.accepted_snapshot_fingerprints,
                carried.accepted_snapshot_fingerprints
            );
            if bounded {
                carried
                    .save_with_read_limit(&path, 4 * 1024 * 1024)
                    .unwrap();
            } else {
                carried.save(&path).unwrap();
            }
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(
                reloaded.accepted_snapshot_fingerprints,
                carried.accepted_snapshot_fingerprints
            );
            assert_eq!(
                reloaded.accepted_rebuild_incidence,
                carried.accepted_rebuild_incidence
            );
            assert_eq!(corrupt_count(scratch.as_ref()), 0);
        }
    }
}

// #705/#718 composition: retirement evidence remains fail-closed at every
// persistence boundary, alongside bindings, accepted ACKs and contract latch.
fn retired_family_decode_seed() -> ScanIndex {
    let mut index = override_identity_seed("retired-decode-owner", true);
    index
        .claude_retired_family_tombstones
        .insert("a".repeat(64), 7);
    index.claude_retired_family_tombstones_initialized = true;
    index
}

fn assert_retired_family_decode_identity(index: &ScanIndex, seed: &ScanIndex) {
    assert_eq!(
        index.session_account_bindings,
        seed.session_account_bindings
    );
    assert_eq!(
        index.accepted_snapshot_fingerprints,
        seed.accepted_snapshot_fingerprints
    );
    assert_eq!(
        index.claude_request_identity_contract,
        seed.claude_request_identity_contract
    );
    assert!(index.claude_request_identity_contract_changed);
    assert!(index.claude_retired_family_tombstones_initialized);
}

#[test]
fn retired_family_damage_keeps_identity_and_fence_on_load_and_both_cas_readers() {
    for bounded in [false, true] {
        for case in [
            "container",
            "entries",
            "missing",
            "cap",
            "initialized",
            "uncertain",
            "both_flags",
            "overflow",
        ] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-retired-family");
            let path = scratch.join("index.json");
            let mut seed = retired_family_decode_seed();
            seed.save(&path).unwrap();
            let mut stale = seed.clone();
            let mut value = serde_json::to_value(&seed).unwrap();
            let (expected, uncertain) = match case {
                "container" => {
                    value["claude_retired_family_tombstones"] = serde_json::json!([false]);
                    (BTreeMap::new(), true)
                }
                "entries" => {
                    value["claude_retired_family_tombstones"] = serde_json::json!({
                        "a".repeat(64): 7, "bad-root": 1, "b".repeat(64): "bad-time"
                    });
                    (BTreeMap::from([("a".repeat(64), 7)]), true)
                }
                "missing" => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .remove("claude_retired_family_tombstones");
                    (BTreeMap::new(), true)
                }
                "cap" => {
                    let entries = (0..=MAX_CLAUDE_RETIRED_FAMILY_TOMBSTONES)
                        .map(|n| (format!("{n:064x}"), n as u64))
                        .collect::<BTreeMap<_, _>>();
                    value["claude_retired_family_tombstones"] =
                        serde_json::to_value(&entries).unwrap();
                    (entries.into_iter().skip(1).collect(), true)
                }
                "initialized" => {
                    value["claude_retired_family_tombstones_initialized"] =
                        serde_json::json!({"bad": true});
                    (seed.claude_retired_family_tombstones.entries.clone(), false)
                }
                "uncertain" => {
                    value["claude_retired_family_tombstones_uncertain"] = serde_json::json!(null);
                    (seed.claude_retired_family_tombstones.entries.clone(), true)
                }
                "both_flags" => {
                    value["claude_retired_family_tombstones_initialized"] = serde_json::json!([]);
                    value["claude_retired_family_tombstones_uncertain"] = serde_json::json!(17);
                    value["claude_retired_family_tombstones"] = serde_json::json!({"bad-root": 1});
                    (BTreeMap::new(), true)
                }
                "overflow" => {
                    value["claude_retired_family_tombstones"] = serde_json::json!("overflow-token");
                    value["claude_retired_family_tombstones_initialized"] =
                        serde_json::json!("overflow-token");
                    value["claude_retired_family_tombstones_uncertain"] =
                        serde_json::json!("overflow-token");
                    (BTreeMap::new(), true)
                }
                _ => unreachable!(),
            };
            let bytes = serde_json::to_string(&value)
                .unwrap()
                .replace("\"overflow-token\"", "1e400")
                .into_bytes();
            fs::write(&path, &bytes).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert_retired_family_decode_identity(&loaded, &seed);
            assert_eq!(loaded.generation, seed.generation);
            assert_eq!(
                loaded.claude_retired_family_tombstones.entries, expected,
                "{case}"
            );
            assert_eq!(
                loaded.claude_retired_family_tombstones_uncertain, uncertain,
                "{case}"
            );
            assert!(loaded.decode_holds.is_empty(), "no opaque tombstone hold");
            let (daemon, origin) = ScanIndex::load_for_snapshot_source_with_origin(
                &path,
                SnapshotSource::ClaudeCode,
                &scratch.join("support"),
            )
            .unwrap();
            assert_eq!(origin, ScanIndexLoadOrigin::Loaded);
            assert_retired_family_decode_identity(&daemon, &seed);
            assert_eq!(daemon.claude_retired_family_tombstones.entries, expected);
            assert_eq!(daemon.claude_retired_family_tombstones_uncertain, uncertain);
            assert_eq!(
                fs::read(&path).unwrap(),
                bytes,
                "load never rewrites {case}"
            );
            assert_eq!(corrupt_count(&scratch), 0);
            let refused = if bounded {
                stale.save_with_read_limit(&path, 1024 * 1024)
            } else {
                stale.save(&path)
            };
            assert!(
                format!("{:#}", refused.unwrap_err()).contains("current_index_requires_reload"),
                "{case}"
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(stale.generation, seed.generation);
            if bounded {
                loaded.save_with_read_limit(&path, 1024 * 1024).unwrap();
            } else {
                loaded.save(&path).unwrap();
            }
            let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["claude_retired_family_tombstones_initialized"], true);
            assert_eq!(
                saved
                    .get("claude_retired_family_tombstones_uncertain")
                    .is_some(),
                uncertain
            );
            let restarted = ScanIndex::load(&path).unwrap();
            assert_retired_family_decode_identity(&restarted, &seed);
            assert_eq!(restarted.claude_retired_family_tombstones.entries, expected);
            assert_eq!(
                restarted.claude_retired_family_tombstones_uncertain,
                uncertain
            );
            assert_eq!(corrupt_count(&scratch), 0);
        }
    }
}

#[test]
fn duplicate_retired_family_root_fields_refuse_load_and_both_cas_without_quarantine() {
    for field in [
        "claude_retired_family_tombstones",
        "claude_retired_family_tombstones_initialized",
        "claude_retired_family_tombstones_uncertain",
    ] {
        for bounded in [false, true] {
            let scratch = crate::test_scratch::ScratchDir::new("lenient-retired-duplicate");
            let path = scratch.join("index.json");
            let mut seed = retired_family_decode_seed();
            seed.claude_retired_family_tombstones_uncertain = true;
            seed.save(&path).unwrap();
            let original = serde_json::to_string(&seed).unwrap();
            let encoded = serde_json::to_value(&seed).unwrap();
            let bytes = format!(
                "{},\"{field}\":{}}}",
                &original[..original.len() - 1],
                encoded[field]
            )
            .into_bytes();
            fs::write(&path, &bytes).unwrap();
            let error = ScanIndex::load(&path).unwrap_err();
            assert!(format!("{error:#}").contains("duplicate index field"));
            let result = if bounded {
                seed.save_with_read_limit(&path, 1024 * 1024)
            } else {
                seed.save(&path)
            };
            assert!(format!("{:#}", result.unwrap_err()).contains("duplicate index field"));
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(corrupt_count(&scratch), 0);
            assert!(seed.claude_request_identity_contract_changed);
            assert!(!seed.session_account_bindings.is_empty());
            assert!(!seed.accepted_snapshot_fingerprints.is_empty());
        }
    }
}

#[test]
fn repair_identity_carry_keeps_retirement_evidence_with_its_own_decode_policy() {
    for damaged in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("lenient-retired-carry");
        let path = scratch.join("index.json");
        let seed = retired_family_decode_seed();
        let mut value = serde_json::to_value(&seed).unwrap();
        if damaged {
            value["claude_retired_family_tombstones"]["bad-root"] = serde_json::json!(false);
            value["claude_retired_family_tombstones_initialized"] = serde_json::json!(null);
            value["claude_retired_family_tombstones_uncertain"] = serde_json::json!([]);
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let carry =
            lenient_decode::read_identity_carry(File::open(&path).unwrap(), "claude_code").unwrap();
        assert_retired_family_decode_identity(&carry, &seed);
        assert_eq!(
            carry.claude_retired_family_tombstones.entries,
            seed.claude_retired_family_tombstones.entries
        );
        assert_eq!(carry.claude_retired_family_tombstones_uncertain, damaged);
        let mut rebuilt = ScanIndex::default();
        rebuilt.carry_identity_from(carry).unwrap();
        assert_retired_family_decode_identity(&rebuilt, &seed);
        assert_eq!(
            rebuilt.claude_retired_family_tombstones.entries,
            seed.claude_retired_family_tombstones.entries
        );
        assert_eq!(rebuilt.claude_retired_family_tombstones_uncertain, damaged);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(corrupt_count(&scratch), 0);
    }
}

fn write_repair_collision(path: &Path, value: &mut Value) -> Vec<u8> {
    let key = "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4";
    value["codex_state_only_snapshot_fingerprints"] = serde_json::json!({
        key: "lower", key.to_ascii_uppercase(): "upper"
    });
    let bytes = serde_json::to_vec(value).unwrap();
    fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn user_repair_tombstone_loss_carries_identity_without_refusal_and_keeps_the_fence() {
    let source = SnapshotSource::ClaudeCode;
    for case in [
        "intact",
        "entries",
        "container",
        "missing_map",
        "cap",
        "uncertain",
        "no_marker",
        "false_marker",
        "damaged_marker",
        "pre_bridge",
    ] {
        reset_override_state_for_restart();
        let scratch = crate::test_scratch::ScratchDir::new("repair-retirement-loss");
        let path = scratch.join("index.json");
        let support = scratch.join("support");
        let load = || ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support);
        fs::write(&path, b"{").unwrap();
        assert_eq!(load().unwrap().1, ScanIndexLoadOrigin::Quarantined);
        let seed = retired_family_decode_seed();
        let mut value = serde_json::to_value(&seed).unwrap();
        let mut kept = seed.claude_retired_family_tombstones.entries.clone();
        match case {
            "intact" => {}
            "entries" => {
                value["claude_retired_family_tombstones"]["bad-root"] = serde_json::json!(false);
            }
            "container" => {
                value["claude_retired_family_tombstones"] = serde_json::json!([false]);
                kept.clear();
            }
            "missing_map" => {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("claude_retired_family_tombstones");
                kept.clear();
            }
            "cap" => {
                let all = (0..=MAX_CLAUDE_RETIRED_FAMILY_TOMBSTONES)
                    .map(|n| (format!("{n:064x}"), n as u64))
                    .collect::<BTreeMap<_, _>>();
                value["claude_retired_family_tombstones"] = serde_json::to_value(&all).unwrap();
                kept = all.into_iter().skip(1).collect();
            }
            "uncertain" => {
                value["claude_retired_family_tombstones_uncertain"] = serde_json::json!(true);
            }
            "no_marker" => {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("claude_retired_family_tombstones_initialized");
            }
            "false_marker" => {
                value["claude_retired_family_tombstones_initialized"] = serde_json::json!(false);
            }
            "damaged_marker" => {
                value["claude_retired_family_tombstones_initialized"] =
                    serde_json::json!({"lost":true});
            }
            "pre_bridge" => {
                for field in [
                    "claude_retired_family_tombstones",
                    "claude_retired_family_tombstones_initialized",
                    "claude_retired_family_tombstones_uncertain",
                ] {
                    value.as_object_mut().unwrap().remove(field);
                }
                kept.clear();
            }
            _ => unreachable!(),
        }
        let bytes = write_repair_collision(&path, &mut value);
        assert!(
            load()
                .unwrap_err()
                .downcast_ref::<ScanIndexRebuildLoop>()
                .is_some(),
            "{case}"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
            ScanIndexRebuildOverride::Armed
        );
        let count = scan_index_rebuild_manual_override_count();
        let (mut rebuilt, origin) = load().unwrap();
        assert_eq!(origin, ScanIndexLoadOrigin::Quarantined, "{case}");
        assert_eq!(
            scan_index_rebuild_manual_override_count(),
            count + 1,
            "Repair was not refused: {case}"
        );
        assert_retired_family_decode_identity(&rebuilt, &seed);
        assert_identity_carried(&rebuilt, &seed, case);
        assert_eq!(
            rebuilt.claude_retired_family_tombstones.entries, kept,
            "{case}"
        );
        assert_eq!(
            rebuilt.claude_retired_family_tombstones_uncertain,
            case != "intact",
            "{case}"
        );
        assert!(rebuilt.claude_history_unverified_in_process, "{case}");
        assert!(rebuilt.files.is_empty());
        assert_eq!(rebuilt.generation, 0);
        let saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["claude_retired_family_tombstones_initialized"], true);
        assert!(saved.get("claude_history_unverified_in_process").is_none());
        // A fence and an unrelated tombstone cannot alter identity tags or
        // suppress an exact-owner correction. Conflicting creator B still
        // defers; matching creator A still proceeds, with ACKs unchanged.
        let mut item = tests::valid_v6_batch_request().snapshots.remove(0);
        let session = item.source_session_id.clone();
        let key = sha256_hex(&["session_owner:v1", "machine-a", &session]);
        rebuilt.session_account_bindings.insert(
            key,
            SessionAccountBinding {
                account_identifier_hash: OVERRIDE_OWNER_A.into(),
                workspace_identifier_hash: None,
            },
        );
        let accepted = rebuilt.accepted_snapshot_fingerprints.clone();
        set_session_account_hash(&mut item, Some(OVERRIDE_OWNER_B));
        assert!(rebuilt
            .bind_session_accounts(source, "machine-a", &mut [item.clone()], &[])
            .contains(&session));
        set_session_account_hash(&mut item, Some(OVERRIDE_OWNER_A));
        item.request_evidence.push(SnapshotRequestEvidence {
            identity_basis: claude_request_identity::TELEMETRY.to_owned(),
            provider_workspace_hash: Some("d".repeat(64)),
            account_source: None,
        });
        let tags = as_json(&item.request_evidence);
        let mut items = [item];
        assert!(rebuilt
            .bind_session_accounts(source, "machine-a", &mut items, &[])
            .is_empty());
        assert_eq!(as_json(&items[0].request_evidence), tags);
        assert_eq!(rebuilt.accepted_snapshot_fingerprints, accepted);
        assert_eq!(rebuilt.session_account_bindings, {
            let mut bindings = seed.session_account_bindings.clone();
            bindings.insert(
                sha256_hex(&["session_owner:v1", "machine-a", &session]),
                SessionAccountBinding {
                    account_identifier_hash: OVERRIDE_OWNER_A.into(),
                    workspace_identifier_hash: None,
                },
            );
            bindings
        });
    }
}

#[test]
fn real_repair_override_marks_history_unverified_before_return_and_first_census() {
    reset_override_state_for_restart();
    restart_claude_reemission_stop_for_test();
    let scratch = crate::test_scratch::ScratchDir::new("repair-first-census");
    let path = scratch.join("index.json");
    let support = scratch.join("support");
    let source = SnapshotSource::ClaudeCode;
    fs::write(&path, b"{").unwrap();
    assert_eq!(
        ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support)
            .unwrap()
            .1,
        ScanIndexLoadOrigin::Quarantined
    );
    let seed = retired_family_decode_seed();
    let mut value = serde_json::to_value(&seed).unwrap();
    write_repair_collision(&path, &mut value);
    assert!(
        ScanIndex::load_for_snapshot_source_with_origin(&path, source, &support)
            .unwrap_err()
            .downcast_ref::<ScanIndexRebuildLoop>()
            .is_some()
    );
    assert_eq!(
        arm_scan_index_rebuild_manual_override(source, SystemTime::now()),
        ScanIndexRebuildOverride::Armed
    );
    // Forget the priming load: the real override must establish its own memo.
    forget_claude_unverified_history_indexes_for_test();
    let mut rebuilt = override_scan_index_rebuild_loop(
        &path,
        "codex_identity_collision",
        source,
        &support,
        SystemTime::now(),
    )
    .unwrap();
    assert!(
        rebuilt.claude_history_unverified_in_process,
        "before the outer source loader can help"
    );
    assert_retired_family_decode_identity(&rebuilt, &seed);
    assert_eq!(rebuilt.generation, 0);
    assert!(rebuilt.files.is_empty());
    rebuilt.insert_retry_pending_claude_authority_for_test("first-census-absent");
    let traversal: ScanTraversalCheckpoint = serde_json::from_value(serde_json::json!({
        "context_fingerprint":"context", "census_window_end":"2026-10-24T23:00:00Z",
        "scan_roots":[], "pending_directories":[], "pending_candidates":[],
        "observed_index_keys":[], "reconciliation_upper_bound":null,
        "reconciliation_after":null, "reconciliation_started":true, "counts":{}
    }))
    .unwrap();
    let before = claude_absence_counters_for_test().absent_families_retired;
    assert_eq!(
        rebuilt.retire_positively_absent_claude_families(&traversal, ""),
        Err(ClaudeAbsenceRetirementRefusal::UnverifiedHistory)
    );
    assert_eq!(
        claude_absence_counters_for_test().absent_families_retired,
        before
    );
    assert!(rebuilt
        .claude_authority_record_for_test("first-census-absent")
        .is_some());
    let mut control = rebuilt.clone();
    control.claude_history_unverified_in_process = false;
    assert_eq!(
        control.retire_positively_absent_claude_families(&traversal, ""),
        Ok(1)
    );
    // Generation and membership now look historic. Only the override's fresh
    // path memo can keep the subsequent ordinary load unverified.
    rebuilt.files.insert(
        "/synthetic/post-repair.jsonl".into(),
        tests::manifest_index_entry(Some(&"c".repeat(64))),
    );
    rebuilt.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert!(loaded.generation > 0 && !loaded.files.is_empty());
    assert!(loaded.claude_history_unverified_in_process);
    assert!(loaded
        .claude_authority_record_for_test("first-census-absent")
        .is_some());
}

#[test]
fn oversized_idless_marker_strings_refuse_before_reader_token_allocation() {
    let mut seed = fixture();
    seed.claude_usage_family_pending.insert(
        "family".into(),
        ClaudeUsageFamilyPending {
            census_window_end: "2026-10-25T00:00:00Z".into(),
            member_request_id_hashes: BTreeMap::new(),
            member_occurrences: BTreeMap::new(),
            invalid: true,
            idless_revision: Some([7; 32]),
            identity_contract: None,
            contract_unproven: false,
        },
    );
    let valid = serde_json::to_vec_pretty(&seed).unwrap();
    let loaded = lenient_decode::read(std::io::Cursor::new(&valid), "load", "claude_code").unwrap();
    assert_eq!(
        loaded.claude_usage_family_pending["family"].idless_revision,
        Some([7; 32])
    );
    for positional in [false, true] {
        let mut value = serde_json::to_value(&seed).unwrap();
        if positional {
            value["claude_usage_family_pending"]["family"] =
                serde_json::json!(["2026-10-25T00:00:00Z", {}, {}, true, vec![7; 32],]);
            let bytes = serde_json::to_vec(&value).unwrap();
            let loaded =
                lenient_decode::read(std::io::Cursor::new(&bytes), "load", "claude_code").unwrap();
            assert_eq!(
                loaded.claude_usage_family_pending["family"].idless_revision,
                Some([7; 32])
            );
            value["claude_usage_family_pending"]["family"][4] =
                Value::String("MARKER_PAYLOAD".into());
        } else {
            value["claude_usage_family_pending"]["family"]["idless_revision"] =
                Value::String("MARKER_PAYLOAD".into());
        }
        let template = serde_json::to_string(&value).unwrap();
        let payload = "x".repeat(16 * 1024 * 1024);
        for malformed in [
            format!("\"{payload}\""),
            format!("[\"{payload}\"]"),
            format!("{{\"{payload}\":0}}"),
        ] {
            let bytes = template
                .replace("\"MARKER_PAYLOAD\"", &malformed)
                .into_bytes();
            let (result, allocations) = crate::retry_allocation_probe::measure(|| {
                lenient_decode::read(std::io::Cursor::new(&bytes), "load", "claude_code")
            });
            // Optional optimization damage is normalized at its boundary;
            // it must not consume opaque debt or reset the identity index.
            let loaded = result.unwrap();
            assert!(loaded.claude_usage_family_pending["family"].invalid);
            assert_eq!(
                loaded.claude_usage_family_pending["family"].idless_revision,
                None
            );
            assert!(loaded.decode_holds.is_empty());
            assert!(
                allocations.requested_peak < 256 * 1024,
                "{}",
                allocations.requested_peak
            );
            assert!(
                allocations.usable_peak < 512 * 1024,
                "{}",
                allocations.usable_peak
            );
        }
    }
}

#[test]
fn damaged_idless_marker_load_and_save_preserve_all_identity_custody() {
    let mut seed = fixture();
    seed.claude_request_identity_contract = Some(claude_request_identity::COLLECTOR.to_owned());
    seed.claude_request_identity_contract_changed = true;
    seed.session_account_bindings.insert(
        "/synthetic/0.jsonl".into(),
        SessionAccountBinding {
            account_identifier_hash: "a".repeat(64),
            workspace_identifier_hash: Some("b".repeat(64)),
        },
    );
    let pending = ClaudeUsageFamilyPending {
        census_window_end: "2026-10-25T00:00:00Z".into(),
        member_request_id_hashes: BTreeMap::from([("family".into(), BTreeSet::new())]),
        member_occurrences: BTreeMap::new(),
        invalid: true,
        idless_revision: None,
        identity_contract: None,
        contract_unproven: false,
    };
    seed.claude_usage_family_pending
        .insert("family".into(), pending.clone());
    for positional in [false, true] {
        let mut value = serde_json::to_value(&seed).unwrap();
        if positional {
            value["claude_usage_family_pending"]["family"] = serde_json::json!([
                pending.census_window_end,
                pending.member_request_id_hashes,
                {},
                true,
                "MARKER"
            ]);
        } else {
            value["claude_usage_family_pending"]["family"]["idless_revision"] = "MARKER".into();
        }
        let template = serde_json::to_string(&value).unwrap();
        let oversized = "x".repeat(16 * 1024 * 1024);
        for marker in [
            format!("\"{oversized}\""),
            format!("[\"{oversized}\"]"),
            format!("{{\"{oversized}\":0}}"),
            "1e400".into(),
            "{\"wrong\":true}".into(),
        ] {
            let scratch = crate::test_scratch::ScratchDir::new("idless-marker-identity");
            let path = scratch.join("index.json");
            fs::write(&path, template.replace("\"MARKER\"", &marker)).unwrap();
            let mut loaded = ScanIndex::load(&path).expect("field damage cannot quarantine index");
            for round in 0..2 {
                assert_eq!(corrupt_count(scratch.as_ref()), 0);
                assert!(loaded.decode_holds.is_empty());
                assert_eq!(loaded.claude_usage_family_pending["family"], pending);
                assert_eq!(
                    loaded.session_account_bindings,
                    seed.session_account_bindings
                );
                assert_eq!(
                    loaded.accepted_snapshot_fingerprints,
                    seed.accepted_snapshot_fingerprints
                );
                assert_eq!(
                    loaded.file_snapshot_fingerprints,
                    seed.file_snapshot_fingerprints
                );
                assert_eq!(
                    loaded.claude_request_identity_contract,
                    seed.claude_request_identity_contract
                );
                assert!(loaded.claude_request_identity_contract_changed);
                assert_eq!(
                    serde_json::to_value(&loaded.files).unwrap(),
                    serde_json::to_value(&seed.files).unwrap()
                );
                assert!(
                    !claude_stale_carry_start_admitted(&loaded),
                    "BASE; no proof from marker damage"
                );
                if round == 0 {
                    loaded
                        .save(&path)
                        .expect("normalized index retains CAS custody");
                    loaded = ScanIndex::load(&path).unwrap();
                }
            }
        }
    }
}

#[test]
fn legacy_nested_positional_traversal_counts_keep_their_original_slots() {
    // The old short sequence meant discovered=7, not a guard admission.
    // Also exercise the full legacy sequence, including its structured slots.
    let legacy = [
        "discovered_file_count",
        "directory_entry_cap_exceeded_count",
        "symlink_rejected_count",
        "unreadable_path_count",
        "unreadable_causes",
        "parent_unresolvable",
        "oversized_file_count",
        "disappeared_file_count",
        "malformed_json_line_count",
        "invalid_utf8_line_count",
        "over_line_cap_count",
        "recognized_usage_drop_count",
        "ownership_incomplete_file_count",
        "zero_snapshot_usage_evidence_count",
        "dropped_usage_record_count",
        "terminal_over_line_cap_count",
        "terminal_recognized_usage_drop_count",
        "terminal_dropped_usage_record_count",
        "terminal_ownership_incomplete_file_count",
        "terminal_zero_snapshot_usage_evidence_count",
    ];
    for full in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("nested-counts-sequence");
        let path = scratch.join("index.json");
        let defaults = serde_json::to_value(ScanTraversalCounts::default()).unwrap();
        let mut expected = defaults.clone();
        let slots = legacy
            .iter()
            .take(if full { legacy.len() } else { 1 })
            .enumerate()
            .map(|(n, name)| {
                let value = if defaults[*name].is_number() {
                    serde_json::json!(n + 7)
                } else {
                    defaults[*name].clone()
                };
                expected[*name] = value.clone();
                value
            })
            .collect::<Vec<_>>();
        let mut root = serde_json::to_value(ScanIndex::default()).unwrap();
        root["traversal"] = serde_json::json!({
            "context_fingerprint":"context", "census_window_end":"2026-10-24T23:00:00Z",
            "scan_roots":[], "pending_directories":[], "pending_candidates":[],
            "observed_index_keys":[], "reconciliation_upper_bound":null,
            "reconciliation_after":null, "reconciliation_started":true, "counts":slots
        });
        fs::write(&path, serde_json::to_vec(&root).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).expect("legacy nested sequence loads");
        let counts = &loaded.traversal.as_ref().unwrap().counts;
        assert_eq!(serde_json::to_value(counts).unwrap(), expected);
        assert_eq!(counts.discovered_file_count, 7);
        assert_eq!(counts.has_retryable_problems(), full);
        loaded
            .save(&path)
            .expect("legacy checkpoint can still CAS-save");
        let reopened = ScanIndex::load(&path).unwrap();
        assert_eq!(
            serde_json::to_value(&reopened.traversal.as_ref().unwrap().counts).unwrap(),
            expected
        );
    }
}

/// [format] Retired evidence cannot reset live census, move slots or select
/// another read.
#[test]
fn retired_reread_guard_keeps_legacy_map_and_full_array_custody() {
    let seed = every_persisted_field_fixture();
    let expected = serde_json::to_vec(&seed).unwrap();
    let census = serde_json::to_vec(&seed.claude_request_census).unwrap();
    let fields = lenient_decode::FIELDS;
    assert_eq!(fields[81], "reread_guard");
    assert_eq!(fields[82], "codex_counting_evicted_legacy");
    assert_eq!(fields[83], "upload_ack_retirement_handoff");
    assert_eq!(fields[84], "held_audit_progress");
    assert_eq!(fields[85], "claude_money_birth_store");
    let count_fields = [
        "discovered_file_count",
        "directory_entry_cap_exceeded_count",
        "symlink_rejected_count",
        "unreadable_path_count",
        "unreadable_causes",
        "parent_unresolvable",
        "oversized_file_count",
        "disappeared_file_count",
        "malformed_json_line_count",
        "invalid_utf8_line_count",
        "over_line_cap_count",
        "recognized_usage_drop_count",
        "ownership_incomplete_file_count",
        "zero_snapshot_usage_evidence_count",
        "dropped_usage_record_count",
        "terminal_over_line_cap_count",
        "terminal_recognized_usage_drop_count",
        "terminal_dropped_usage_record_count",
        "terminal_ownership_incomplete_file_count",
        "terminal_zero_snapshot_usage_evidence_count",
        "unchanged_reread_admitted",
        "reread_budget_refused",
        "causes",
        "caps",
        "codex_roster_refresh_visited",
        "codex_roster_growth_enqueued",
    ];
    let mut old = serde_json::to_value(&seed).unwrap();
    old["reread_guard"] = serde_json::json!({
        "closed":true, "observed_reads":999, "wall_high_water":u64::MAX,
        "tripwire":{"indexed":1,"planned":999,"cause_counts":[1,2,3]},
        "refused":{"legacy": [1,2]}, "growth_full":{"legacy":9}
    });
    old["traversal"]["counts"]["unchanged_reread_admitted"] = serde_json::json!(41);
    old["traversal"]["counts"]["reread_budget_refused"] = serde_json::json!(43);
    old["traversal"]["counts"]["codex_roster_refresh_visited"] = serde_json::json!(45);
    old["traversal"]["counts"]["codex_roster_growth_enqueued"] = serde_json::json!(47);
    let mut forms = vec![serde_json::to_string(&old).unwrap()];
    // Full nested counter sequence, including nonzero retired slots 20/21
    // and 24/25 (the seed's causes and caps are empty).
    old["traversal"]["counts"] = Value::Array(
        count_fields
            .iter()
            .map(|name| match *name {
                "causes" => serde_json::to_value(ownership::Counts::default()).unwrap(),
                "caps" => serde_json::to_value(CapCounts::default()).unwrap(),
                _ => old["traversal"]["counts"][*name].clone(),
            })
            .collect(),
    );
    forms.push(
        serde_json::to_string(&Value::Array(
            fields.iter().map(|name| old[*name].clone()).collect(),
        ))
        .unwrap(),
    );
    let prefix = forms[0].strip_suffix('}').unwrap().to_owned();
    for key in ["reread_guard", "\\u0072eread_guard"] {
        forms.push(format!("{prefix},\"{key}\":\"wrong shape\"}}"));
    }
    for depth in [65, 300] {
        forms.push(format!(
            "{prefix},\"reread_guard\":{}0{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        ));
    }
    forms.push(format!(
        "{prefix},\"reread_guard\":\"{}\"}}",
        "x".repeat(claude_request_census::MAX_RAW_BYTES + 1)
    ));
    let scratch = crate::test_scratch::ScratchDir::new("retired-reread-custody");
    for (number, form) in forms.iter().enumerate() {
        let bytes = form.as_bytes();
        let path = scratch.join(format!("old-{number}.json"));
        fs::write(&path, bytes).unwrap();
        let drops_before = claude_absence_counters_for_test().tombstone_decode_drops;
        let native = claude_request_census::decode_index(bytes).expect("native legacy decode");
        let streaming = lenient_decode::read(std::io::Cursor::new(bytes), "load", "unattributed")
            .expect("no extra positional field");
        let bounded = lenient_decode::read_bounded(bytes).unwrap();
        let disk = ScanIndex::load(&path).expect("no reset");
        assert_eq!(
            claude_absence_counters_for_test().tombstone_decode_drops,
            drops_before,
            "retired reread_guard duplicates stay silently ignored"
        );
        for mut decoded in [native, streaming, bounded, disk] {
            assert!(decoded.decode_holds.is_empty(), "no quarantine");
            assert_eq!(
                serde_json::to_vec(&decoded.claude_request_census).unwrap(),
                census
            );
            assert_eq!(
                serde_json::to_vec(&decoded).unwrap(),
                expected,
                "every surviving selection, hold, checkpoint and successor field unchanged"
            );
            for (key, entry) in &seed.files {
                let candidate = CandidateFile {
                    physical_identity: None,
                    scan_root: PathBuf::from("/synthetic"),
                    path: PathBuf::from(key),
                    size_bytes: entry.size_bytes,
                    modified_unix_seconds: entry.modified_unix_seconds,
                    modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
                    source_file_fingerprint: entry.source_file_fingerprint.clone(),
                    legacy_source_file_fingerprint: String::new(),
                    legacy_config_reconciliation_required: false,
                    opened_object_identity: String::new(),
                    fingerprint_changed_nanos: 0,
                    fingerprint_birth_nanos: 0,
                    withheld_content_stamp: None,
                };
                assert_eq!(
                    decoded.candidate_decision_with_reason_at(&candidate, 0),
                    seed.candidate_decision_with_reason_at(&candidate, 0),
                    "retired over-budget/bad-clock evidence cannot select a reread"
                );
            }
            assert!(
                !decoded
                    .traversal
                    .as_ref()
                    .unwrap()
                    .counts
                    .has_retryable_problems(),
                "nonzero retired refusal must not request another read"
            );
            assert_eq!(
                decoded.files.keys().collect::<Vec<_>>(),
                seed.files.keys().collect::<Vec<_>>()
            );
            fs::write(&path, bytes).unwrap();
            decoded.save(&path).expect("CAS keeps generation custody");
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(
                serde_json::to_vec(&reloaded.claude_request_census).unwrap(),
                census
            );
            let saved = fs::read_to_string(&path).unwrap();
            for retired in [
                "reread_guard",
                "unchanged_reread_admitted",
                "reread_budget_refused",
                "codex_roster_refresh_visited",
                "codex_roster_growth_enqueued",
            ] {
                assert!(!saved.contains(&format!("\"{retired}\":")));
            }
        }
    }
    assert_eq!(corrupt_count(scratch.as_ref()), 0);
}

/// Previous (0.1.201) ScanIndex and ScanTraversalCounts both use serde(default).
/// Pin the absent-field downgrade contract while preserving the census bytes.
#[test]
fn retired_reread_new_writer_keeps_previous_default_contract() {
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct PreviousCounts {
        discovered_file_count: usize,
        unchanged_reread_admitted: u64,
        reread_budget_refused: u64,
    }
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct PreviousTraversal {
        counts: PreviousCounts,
    }
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct PreviousIndex {
        claude_request_census: claude_request_census::ClaudeRequestCensus,
        reread_guard: Option<Value>,
        traversal: Option<PreviousTraversal>,
    }
    let seed = every_persisted_field_fixture();
    let bytes = serde_json::to_vec(&seed).unwrap();
    let old: PreviousIndex = serde_json::from_slice(&bytes).expect("old defaults accept new map");
    assert!(old.reread_guard.is_none());
    let counts = old.traversal.unwrap().counts;
    assert_eq!(
        counts.discovered_file_count,
        seed.traversal
            .as_ref()
            .unwrap()
            .counts
            .discovered_file_count
    );
    assert_eq!(counts.unchanged_reread_admitted, 0);
    assert_eq!(counts.reread_budget_refused, 0);
    assert_eq!(
        serde_json::to_vec(&old.claude_request_census).unwrap(),
        serde_json::to_vec(&seed.claude_request_census).unwrap()
    );
}

/// Pin the previous 0.1.201 map/default entry contract cited by
/// retired_reread_new_writer_keeps_previous_default_contract. Quiet retirement
/// writes the existing plain identity, not an unknown field or marker shape.
#[test]
fn quiet_retired_index_loads_under_previous_entry_defaults() {
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct PreviousEntry {
        size_bytes: u64,
        modified_unix_seconds: u64,
        source_file_fingerprint: String,
        last_snapshot_fingerprint: Option<String>,
        scan_identity_version: Option<String>,
    }
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct PreviousIndex {
        schema_version: u16,
        files: BTreeMap<String, PreviousEntry>,
    }
    let mut index = fixture();
    let key = "/synthetic/0.jsonl";
    let before = index.files[key].clone();
    assert!(index.stage_sampled_audit(
        key,
        &before.source_file_fingerprint,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: 100
        }
    ));
    assert!(index.retire_quiet_audit(key, &before.source_file_fingerprint));
    let scratch = crate::test_scratch::ScratchDir::new("retired-previous-index");
    let path = scratch.join("index.json");
    index.save(&path).unwrap();
    let old: PreviousIndex = serde_json::from_slice(&fs::read(&path).unwrap())
        .expect("previous default map decoder accepts cleared marker");
    assert_eq!(old.schema_version, SCAN_INDEX_SCHEMA_VERSION);
    assert_eq!(old.files.len(), index.files.len());
    let entry = &old.files[key];
    assert_eq!(
        entry.scan_identity_version.as_deref(),
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    );
    assert_eq!(entry.size_bytes, before.size_bytes);
    assert_eq!(entry.modified_unix_seconds, before.modified_unix_seconds);
    assert_eq!(
        entry.source_file_fingerprint,
        before.source_file_fingerprint
    );
    assert_eq!(
        entry.last_snapshot_fingerprint,
        before.last_snapshot_fingerprint
    );
    assert_eq!(
        ScanIndex::load(&path).unwrap().files[key].unverified_deadline(),
        None
    );
}

// Pin every positional slot, including the decode-and-drop inventory tombstone.
#[test]
fn scan_index_full_positional_field_order_is_pinned() {
    assert_eq!(
        lenient_decode::FIELDS,
        &[
            "schema_version",
            "generation",
            "upload_context_fingerprint",
            "files",
            "session_account_bindings",
            "terminal_jsonl_dispositions",
            "known_configured_scan_roots",
            "legacy_unresolved_root_file_witnesses",
            "codex_state_only_snapshot_fingerprints",
            "codex_state_only_blocked_session_ids",
            "codex_state_only_blocked_by_file",
            "codex_state_only_blocked_unattributed",
            "codex_state_only_blocked_legacy",
            "codex_state_only_blocked_attributed",
            "codex_parent_ownership_refs",
            "codex_parent_ownership_ledgers",
            "codex_parent_side_requests",
            "codex_parent_side",
            "codex_parent_side_generation",
            "codex_parent_proof_wrap_epoch",
            "codex_parent_prefix_proofs",
            "codex_parent_proof_cursor",
            "codex_parent_side_cursor",
            "codex_parent_proof_seq",
            "codex_proof_index_incarnation",
            "claude_desktop_title_files",
            "claude_account_family_witnesses",
            "claude_account_family_pending",
            "claude_usage_family_witnesses",
            "claude_usage_family_pending",
            "claude_request_census",
            "claude_request_census_shadow",
            "claude_usage_authority_quarantine",
            "claude_retired_family_tombstones",
            "claude_retired_family_tombstones_initialized",
            "claude_retired_family_tombstones_uncertain",
            "claude_duplicate_request_owners",
            "claude_duplicate_request_witness_overflowed",
            "claude_owned_start_census",
            "claude_account_deferred_holds",
            "claude_duplicate_fence_rearm_attempt",
            "claude_duplicate_fence_next_full_rearm_unix_seconds",
            "claude_full_rearm_progress",
            "claude_request_identity_contract",
            "claude_request_identity_contract_changed",
            "claude_desktop_store_cursor",
            "claude_desktop_store_upper_bound",
            "claude_desktop_store_sweep_had_errors",
            "claude_desktop_identity_census_complete",
            "claude_desktop_lineage_census_complete",
            "claude_desktop_census_witness",
            "claude_desktop_store_retry_attempt",
            "claude_desktop_store_retry_not_before_unix_seconds",
            "resume_after_path",
            "resume_upper_bound_path",
            "resume_census_window_end",
            "bounded_sweep_had_unsettled_upload",
            "bounded_sweep_unsettled_causes",
            "traversal",
            "claude_stale_family_carry",
            "scan_residue_witness",
            "historical_replay_generation",
            "context_curve_capability_enabled",
            "context_curve_replay_epoch",
            "completed_context_curve_replay_generation",
            "confirmed_empty_files",
            "file_snapshot_fingerprints",
            "snapshot_activity_at",
            "accepted_snapshot_fingerprints",
            "accepted_snapshot_fingerprint_ledger_version",
            "legacy_settlement_reconcile_after_fingerprint",
            "quarantined_snapshot_fingerprints",
            "claude_history_cutoff_unix_seconds",
            "claude_history_gate_loaded",
            "claude_history_move_not_full",
            "claude_history_move_released",
            "accepted_incidence_pending_census",
            "accepted_rebuild_incidence",
            "accepted_rebuild_pending_since_unix_seconds",
            "accepted_rebuild_last_alarm_unix_seconds",
            "codex_counting_tombstones",
            "reread_guard", // TOMBSTONE: decode-and-drop; preserve the legacy positional slot.
            "codex_counting_evicted_legacy",
            "upload_ack_retirement_handoff",
            "held_audit_progress",
            "claude_money_birth_store",
            "claude_desktop_store_inventory", // Decoded and ignored; never serialized.
            "claude_copy_removals",
        ]
    );
}
