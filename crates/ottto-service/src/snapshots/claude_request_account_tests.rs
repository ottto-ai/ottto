pub(crate) fn output(name: &str, item: &SnapshotItem) {
    if let Some(dir) = std::env::var_os("OTTTO_REQUEST_ACCOUNT_TEST_OUTPUT") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).unwrap();
        let mut batch = valid_v6_batch_request();
        batch.source = "claude_code".into();
        batch.upload_policy = SnapshotUploadPolicy {
            session_attribution_enabled: true,
            session_attribution_labels_enabled: true,
            ..Default::default()
        };
        batch.snapshots = vec![item.clone()];
        fs::write(dir.join(name), serde_json::to_vec_pretty(&batch).unwrap()).unwrap();
        batch.upload_policy = SnapshotUploadPolicy::default();
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut batch.snapshots,
            batch.upload_policy,
        );
        fs::write(
            dir.join(name.replace(".json", "-policy-off.json")),
            serde_json::to_vec_pretty(&batch).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn claude_p92_clock_qualification_and_all_bucket_coverage() {
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, items) = claude_account_family_fixture();
    let path = dir
        .join(&root)
        .join("subagents/agent-a4d1585d310070d0f.jsonl");
    let mut record: Value =
        serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
    record["timestamp"] = json!("2026-10-08T12:20:00+03:00");
    let parse = |records: &[Value]| {
        fs::write(
            &path,
            records
                .iter()
                .map(|r| serde_json::to_string(r).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        parse_claude_code_jsonl_file(&path, "2026-10-09T10:00:00Z", "synthetic-source".into())
            .unwrap()
            .remove(0)
    };
    let api = vec![complete_api_row(&root, "req_5", 5, 10, 1, 0)];
    let traces = vec![complete_trace_row(&root, "req_5", "a4d1585d310070d0f")];
    let mut original = parse(&[record.clone()]);
    assert!(d1_subagent_account_specimen(&mut original, &api, &traces));
    assert_eq!(
        original.usage_buckets[0].bucket_start,
        "2026-10-08T09:00:00Z"
    );
    assert_eq!(
        original.usage_buckets[0].first_activity_at.as_deref(),
        Some("2026-10-08T09:20:00Z")
    );
    output("native-clock-complete.json", &original);
    for case in [
        "missing",
        "malformed",
        "partial_missing",
        "altered_first",
        "altered_last",
        "auxiliary_count",
        "auxiliary_zero",
        "missing_occurrence",
        "cached_deserialized",
        "multiple_iterations",
    ] {
        let mut item = original.clone();
        match case {
            "multiple_iterations" => {
                let mut collapsed = record.clone();
                collapsed["message"]["usage"]["iterations"] = json!([
                    {"input_tokens":10,"output_tokens":1},
                    {"input_tokens":10,"output_tokens":1}
                ]);
                item = parse(&[collapsed]);
                assert!(!item.claude_context_curve_request_index_complete);
            }
            "missing" => {
                let user = json!({"type":"user","timestamp":"2026-10-08T09:20:00Z","sessionId":root,"agentId":"a4d1585d310070d0f","isSidechain":true,"message":{"role":"user","content":"synthetic"}});
                let mut no_clock = record.clone();
                no_clock.as_object_mut().unwrap().remove("timestamp");
                item = parse(&[user, no_clock]);
            }
            "malformed" => {
                item.claude_usage_occurrences
                    .get_mut("req_5")
                    .unwrap()
                    .timestamp = Some("bad".into())
            }
            "partial_missing" => {
                let mut first = record.clone();
                first["message"]["id"] = json!("same-response");
                let mut second = first.clone();
                second.as_object_mut().unwrap().remove("timestamp");
                second["message"]["usage"]["output_tokens"] = json!(2);
                item = parse(&[first, second]);
                assert_eq!(item.request_count, 1);
                assert!(
                    item.claude_usage_occurrences["req_5"].timestamp.is_some(),
                    "fold carries earlier stamp"
                );
                assert!(
                    !item.claude_usage_occurrences["req_5"].event_clock_complete,
                    "pre-fold qualification preserves missing origin"
                );
            }
            "altered_first" => {
                item.usage_buckets[0].first_activity_at = Some("2026-10-08T09:30:00Z".into())
            }
            "altered_last" => item.usage_buckets[0].last_activity_at = None,
            "auxiliary_zero" => {
                let rows = [
                    api[0].clone(),
                    complete_api_row(&root, "req_aux_zero", 6, 0, 0, 0),
                ];
                assert!(rebuild_claude_reported_usage(
                    &mut item,
                    &rows,
                    &BTreeSet::new(),
                    None
                ));
                assert_eq!(
                    item.request_count, 2,
                    "zero-token auxiliary event is counted"
                );
            }
            "auxiliary_count" => item.request_count += 1,
            "missing_occurrence" => item.claude_usage_occurrences.clear(),
            "cached_deserialized" => {
                let legacy = serde_json::to_value(&item).unwrap();
                assert!(legacy.get("claude_usage_occurrences").is_none());
                item.claude_usage_occurrences.clear();
            }
            _ => unreachable!(),
        }
        let usage = item.input_tokens;
        let output_tokens = item.output_tokens;
        let creator = item.session_account_evidence.clone();
        assert!(
            !d1_subagent_account_specimen(&mut item, &api, &traces),
            "{case}"
        );
        assert_eq!(item.provenance.collector, claude_request_accounts::UNKNOWN);
        assert_eq!(item.input_tokens, usage);
        assert_eq!(item.output_tokens, output_tokens);
        assert_eq!(item.session_account_evidence, creator);
        if matches!(
            case,
            "missing" | "malformed" | "partial_missing" | "altered_first" | "altered_last"
        ) {
            assert!(
                exact_session_account_hash(&item).is_some(),
                "independent factual account survives {case}"
            );
        }
        if case == "missing" {
            output("native-clock-unknown.json", &item);
        }
    }
    // Every bucket participates, including an earlier original historical hour.
    let mut earlier = record.clone();
    earlier["requestId"] = json!("req_6");
    earlier["timestamp"] = json!("2026-10-03T08:55:00Z");
    let mut two = parse(&[earlier, record.clone()]);
    let two_api = vec![
        api[0].clone(),
        complete_api_row(&root, "req_6", 6, 10, 1, 0),
    ];
    let two_trace = vec![
        traces[0].clone(),
        complete_trace_row(&root, "req_6", "a4d1585d310070d0f"),
    ];
    assert!(d1_subagent_account_specimen(&mut two, &two_api, &two_trace));
    assert_eq!(
        two.usage_buckets[0].first_activity_at.as_deref(),
        Some("2026-10-03T08:55:00Z")
    );
    two.claude_usage_occurrences
        .get_mut("req_6")
        .unwrap()
        .event_clock_complete = false;
    assert!(
        !d1_subagent_account_specimen(&mut two, &two_api, &two_trace),
        "earlier bucket cannot be skipped"
    );
    assert_eq!(items[1].request_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_claude_p92_clock_qualification_and_all_bucket_coverage() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, items) = claude_account_family_fixture();
    let path = dir
        .join(&root)
        .join("subagents/agent-a4d1585d310070d0f.jsonl");
    let mut record: Value =
        serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
    record["timestamp"] = json!("2026-10-08T12:20:00+03:00");
    let parse = |records: &[Value]| {
        fs::write(
            &path,
            records
                .iter()
                .map(|r| serde_json::to_string(r).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        parse_claude_code_jsonl_file(&path, "2026-10-09T10:00:00Z", "synthetic-source".into())
            .unwrap()
            .remove(0)
    };
    let api = vec![complete_api_row(&root, "req_5", 5, 10, 1, 0)];
    let traces = vec![complete_trace_row(&root, "req_5", "a4d1585d310070d0f")];
    let mut original = parse(&[record.clone()]);
    assert!(d1_subagent_account_specimen(&mut original, &api, &traces));
    assert_eq!(
        original.usage_buckets[0].bucket_start,
        "2026-10-08T09:00:00Z"
    );
    assert_eq!(
        original.usage_buckets[0].first_activity_at.as_deref(),
        Some("2026-10-08T09:20:00Z")
    );
    output("native-clock-complete.json", &original);
    for case in [
        "missing",
        "malformed",
        "partial_missing",
        "altered_first",
        "altered_last",
        "auxiliary_count",
        "auxiliary_zero",
        "missing_occurrence",
        "cached_deserialized",
        "multiple_iterations",
    ] {
        let mut item = original.clone();
        match case {
            "multiple_iterations" => {
                let mut collapsed = record.clone();
                collapsed["message"]["usage"]["iterations"] = json!([
                    {"input_tokens":10,"output_tokens":1},
                    {"input_tokens":10,"output_tokens":1}
                ]);
                item = parse(&[collapsed]);
                assert!(!item.claude_context_curve_request_index_complete);
            }
            "missing" => {
                let user = json!({"type":"user","timestamp":"2026-10-08T09:20:00Z","sessionId":root,"agentId":"a4d1585d310070d0f","isSidechain":true,"message":{"role":"user","content":"synthetic"}});
                let mut no_clock = record.clone();
                no_clock.as_object_mut().unwrap().remove("timestamp");
                item = parse(&[user, no_clock]);
            }
            "malformed" => {
                item.claude_usage_occurrences
                    .get_mut("req_5")
                    .unwrap()
                    .timestamp = Some("bad".into())
            }
            "partial_missing" => {
                let mut first = record.clone();
                first["message"]["id"] = json!("same-response");
                let mut second = first.clone();
                second.as_object_mut().unwrap().remove("timestamp");
                second["message"]["usage"]["output_tokens"] = json!(2);
                item = parse(&[first, second]);
                assert_eq!(item.request_count, 1);
                assert!(
                    item.claude_usage_occurrences["req_5"].timestamp.is_some(),
                    "fold carries earlier stamp"
                );
                assert!(
                    !item.claude_usage_occurrences["req_5"].event_clock_complete,
                    "pre-fold qualification preserves missing origin"
                );
            }
            "altered_first" => {
                item.usage_buckets[0].first_activity_at = Some("2026-10-08T09:30:00Z".into())
            }
            "altered_last" => item.usage_buckets[0].last_activity_at = None,
            "auxiliary_zero" => {
                let rows = [
                    api[0].clone(),
                    complete_api_row(&root, "req_aux_zero", 6, 0, 0, 0),
                ];
                assert!(rebuild_claude_reported_usage(
                    &mut item,
                    &rows,
                    &BTreeSet::new(),
                    None
                ));
                assert_eq!(
                    item.request_count, 2,
                    "zero-token auxiliary event is counted"
                );
            }
            "auxiliary_count" => item.request_count += 1,
            "missing_occurrence" => item.claude_usage_occurrences.clear(),
            "cached_deserialized" => {
                let legacy = serde_json::to_value(&item).unwrap();
                assert!(legacy.get("claude_usage_occurrences").is_none());
                item.claude_usage_occurrences.clear();
            }
            _ => unreachable!(),
        }
        let usage = item.input_tokens;
        let output_tokens = item.output_tokens;
        let creator = item.session_account_evidence.clone();
        assert!(
            !d1_subagent_account_specimen(&mut item, &api, &traces),
            "{case}"
        );
        assert_eq!(item.provenance.collector, claude_request_accounts::UNKNOWN);
        assert_eq!(item.input_tokens, usage);
        assert_eq!(item.output_tokens, output_tokens);
        assert_eq!(item.session_account_evidence, creator);
        if matches!(
            case,
            "missing" | "malformed" | "partial_missing" | "altered_first" | "altered_last"
        ) {
            assert!(
                exact_session_account_hash(&item).is_some(),
                "independent factual account survives {case}"
            );
        }
        if case == "missing" {
            output("native-clock-unknown.json", &item);
        }
    }
    // Every bucket participates, including an earlier original historical hour.
    let mut earlier = record.clone();
    earlier["requestId"] = json!("req_6");
    earlier["timestamp"] = json!("2026-10-03T08:55:00Z");
    let mut two = parse(&[earlier, record.clone()]);
    let two_api = vec![
        api[0].clone(),
        complete_api_row(&root, "req_6", 6, 10, 1, 0),
    ];
    let two_trace = vec![
        traces[0].clone(),
        complete_trace_row(&root, "req_6", "a4d1585d310070d0f"),
    ];
    assert!(d1_subagent_account_specimen(&mut two, &two_api, &two_trace));
    assert_eq!(
        two.usage_buckets[0].first_activity_at.as_deref(),
        Some("2026-10-03T08:55:00Z")
    );
    two.claude_usage_occurrences
        .get_mut("req_6")
        .unwrap()
        .event_clock_complete = false;
    assert!(
        !d1_subagent_account_specimen(&mut two, &two_api, &two_trace),
        "earlier bucket cannot be skipped"
    );
    assert_eq!(items[1].request_count, 1);
    fs::remove_dir_all(dir).unwrap();
}

pub(crate) fn claude_request_account_mixed_fixture(
    count: usize,
    reported: bool,
) -> (
    PathBuf,
    SnapshotItem,
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    if crate::snapshots::ClaudeTerminalOffForTest::active() {
        return terminal_off_on_claude_request_account_mixed_fixture(count, reported);
    }
    let (dir, root, _) = claude_account_family_fixture();
    fs::remove_dir_all(dir.join(&root)).unwrap();
    let path = dir.join(format!("{root}.jsonl"));
    let full = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        full.lines().take(count).collect::<Vec<_>>().join("\n") + "\n",
    )
    .unwrap();
    let mut items =
        parse_claude_code_jsonl_file(&path, "2026-08-02T07:10:00Z", "synthetic-source".into())
            .unwrap();
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    items[0].session_account_evidence = Some(SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: Some(a.clone()),
        provider_workspace_hash: Some("c".repeat(64)),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some("complete"),
        source_created_at: Some("2026-08-02T06:59:00Z".into()),
    });
    let rows = (1..=count)
        .map(|i| {
            let mut row = complete_api_row(&root, &format!("req_{i}"), i as u64, 10, 10, 0);
            row.account_identifier_hash = Some(if i <= 2 { a.clone() } else { b.clone() });
            row.request_identity = Some(crate::claude_local_otel::ClaudeRequestIdentityEvidence {
                identity_hash_scheme: "provider-sha256:v1".into(),
                account: crate::claude_local_otel::ClaudeIdentityAttributeEvidence {
                    origin: crate::claude_local_otel::ClaudeIdentityAttributeOrigin::LogRecord,
                    disposition: crate::claude_local_otel::ClaudeIdentityDisposition::Complete,
                    resource_hash: None,
                    log_record_hash: row.account_identifier_hash.clone(),
                },
                organization: crate::claude_local_otel::ClaudeIdentityAttributeEvidence {
                    origin: crate::claude_local_otel::ClaudeIdentityAttributeOrigin::LogRecord,
                    disposition: crate::claude_local_otel::ClaudeIdentityDisposition::Complete,
                    resource_hash: None,
                    log_record_hash: Some(if i <= 2 {
                        "c".repeat(64)
                    } else {
                        "d".repeat(64)
                    }),
                },
                disposition: crate::claude_local_otel::ClaudeIdentityDisposition::Complete,
            });
            row.cost_usd_micros = Some(1_000_000);
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            row
        })
        .collect();
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([(root.clone(), rows)]),
        ..Default::default()
    };
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(
            root,
            (1..=count)
                .map(|i| complete_trace_row(&items[0].source_session_id, &format!("req_{i}"), ""))
                .collect(),
        )]),
        ..Default::default()
    };
    if reported {
        let mut index = ScanIndex::default();
        index
            .files
            .insert(local_index_key(&path), manifest_index_entry(None));
        apply_claude_reported_usage_with_index(
            &mut items,
            &api,
            &trace,
            &mut index,
            true,
            "2026-08-02T07:10:00Z",
        );
        assert_eq!(
            items[0].usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
    }
    items[0].snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &items[0]);
    let mut root_item = items.remove(0);
    root_item.source_file_fingerprint = Some("e".repeat(64));
    (dir, root_item, api, trace)
}

pub(crate) fn terminal_off_on_claude_request_account_mixed_fixture(
    count: usize,
    reported: bool,
) -> (
    PathBuf,
    SnapshotItem,
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let (dir, root, _) = claude_account_family_fixture();
    fs::remove_dir_all(dir.join(&root)).unwrap();
    let path = dir.join(format!("{root}.jsonl"));
    let full = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        full.lines().take(count).collect::<Vec<_>>().join("\n") + "\n",
    )
    .unwrap();
    let mut items =
        parse_claude_code_jsonl_file(&path, "2026-08-02T07:10:00Z", "synthetic-source".into())
            .unwrap();
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    items[0].session_account_evidence = Some(SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: Some(a.clone()),
        provider_workspace_hash: Some("c".repeat(64)),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some("complete"),
        source_created_at: Some("2026-08-02T06:59:00Z".into()),
    });
    let rows = (1..=count)
        .map(|i| {
            let mut row = complete_api_row(&root, &format!("req_{i}"), i as u64, 10, 10, 0);
            row.account_identifier_hash = Some(if i <= 2 { a.clone() } else { b.clone() });
            row.request_identity = Some(crate::claude_local_otel::ClaudeRequestIdentityEvidence {
                identity_hash_scheme: "provider-sha256:v1".into(),
                account: crate::claude_local_otel::ClaudeIdentityAttributeEvidence {
                    origin: crate::claude_local_otel::ClaudeIdentityAttributeOrigin::LogRecord,
                    disposition: crate::claude_local_otel::ClaudeIdentityDisposition::Complete,
                    resource_hash: None,
                    log_record_hash: row.account_identifier_hash.clone(),
                },
                organization: crate::claude_local_otel::ClaudeIdentityAttributeEvidence {
                    origin: crate::claude_local_otel::ClaudeIdentityAttributeOrigin::LogRecord,
                    disposition: crate::claude_local_otel::ClaudeIdentityDisposition::Complete,
                    resource_hash: None,
                    log_record_hash: Some(if i <= 2 {
                        "c".repeat(64)
                    } else {
                        "d".repeat(64)
                    }),
                },
                disposition: crate::claude_local_otel::ClaudeIdentityDisposition::Complete,
            });
            row.cost_usd_micros = Some(1_000_000);
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            row
        })
        .collect();
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([(root.clone(), rows)]),
        ..Default::default()
    };
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(
            root,
            (1..=count)
                .map(|i| complete_trace_row(&items[0].source_session_id, &format!("req_{i}"), ""))
                .collect(),
        )]),
        ..Default::default()
    };
    if reported {
        let mut index = ScanIndex::default();
        index
            .files
            .insert(local_index_key(&path), manifest_index_entry(None));
        apply_claude_reported_usage_with_index(
            &mut items,
            &api,
            &trace,
            &mut index,
            true,
            "2026-08-02T07:10:00Z",
        );
        if claude_terminal_off() {
            assert!(items[0].usage_accounting_contract.is_none());
            let root = claude_snapshot_family_root(&items[0]);
            index.restore_historical_claude_family_for_test(&root, &api, &trace, false);
            apply_claude_reported_usage_with_index(
                &mut items,
                &api,
                &trace,
                &mut index,
                false,
                "2026-08-02T07:10:00Z",
            );
        }
        assert_eq!(
            items[0].usage_accounting_contract.as_deref(),
            Some("session_exclusive_reported_usage:v1")
        );
    }
    items[0].snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &items[0]);
    let mut root_item = items.remove(0);
    root_item.source_file_fingerprint = Some("e".repeat(64));
    (dir, root_item, api, trace)
}

#[test]
fn claude_p92_mixed_body_capability_and_restart_refusals() {
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, mut mixed, api, trace) = claude_request_account_mixed_fixture(4, true);
    let (prior_dir, mut prior, _, _) = claude_request_account_mixed_fixture(2, true);
    let before = serde_json::to_value(&mixed).unwrap();
    let qualification =
        claude_request_accounts::apply(std::slice::from_mut(&mut mixed), &api, &trace);
    assert!(qualification.mixed.permits(&mixed));
    assert_eq!(mixed.provenance.collector, claude_request_accounts::MIXED);
    assert_eq!(
        mixed.cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("4")
    );
    for field in [
        "model_usage",
        "usage_buckets",
        "cost",
        "request_count",
        "session_account_evidence",
        "usage_accounting_contract",
    ] {
        assert_eq!(
            serde_json::to_value(&mixed).unwrap()[field],
            before[field],
            "{field}"
        );
    }
    output("native-mixed-qualified.json", &mixed);
    output("native-mixed-prior.json", &prior);
    let mut index = ScanIndex::default();
    assert!(index
        .bind_session_accounts(
            SnapshotSource::ClaudeCode,
            "machine",
            std::slice::from_mut(&mut prior),
            &[]
        )
        .is_empty());
    let owner = index.session_account_bindings.clone();
    assert!(
        index
            .bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "machine",
                &mut [mixed.clone()],
                &[]
            )
            .contains(&mixed.source_session_id),
        "marker-only default binder is unchanged"
    );
    assert!(index
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut [mixed.clone()],
            &[],
            &qualification.mixed
        )
        .is_empty());
    assert_eq!(index.session_account_bindings, owner);
    assert!(
        index.accepted_snapshot_fingerprints.is_empty(),
        "fresh eligibility does not mint acceptance"
    );
    let index_path = dir.join("index.json");
    index.save(&index_path).unwrap();
    let mut restarted = ScanIndex::load(&index_path).unwrap();
    assert!(
        restarted
            .bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "machine",
                &mut [mixed.clone()],
                &[]
            )
            .contains(&mixed.source_session_id),
        "restart cannot restore ephemeral capability"
    );
    let mut fresh = mixed.clone();
    let again = claude_request_accounts::apply(std::slice::from_mut(&mut fresh), &api, &trace);
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut [fresh.clone()],
            &[],
            &again.mixed
        )
        .is_empty());
    assert_eq!(
        serde_json::to_value(&fresh).unwrap(),
        serde_json::to_value(&mixed).unwrap(),
        "same proof reconstructs exact candidate"
    );
    for case in [
        "unproven",
        "missing_creator",
        "creator_conflict",
        "single_account",
        "known_hour_account",
        "api_route",
        "child_namespace",
        "duplicate_api",
        "missing_trace",
        "unchecked_identity",
        "invalid_fingerprint",
        "marker_only",
    ] {
        let mut item = mixed.clone();
        let mut a = api.clone();
        let mut t = trace.clone();
        match case {
            "unproven" => item.usage_accounting_contract = None,
            "missing_creator" => item.session_account_evidence = None,
            "creator_conflict" => {
                item.session_account_evidence
                    .as_mut()
                    .unwrap()
                    .identity_disposition = Some("conflict")
            }
            "single_account" => {
                for row in a.evidence.values_mut().flatten() {
                    row.account_identifier_hash = Some("a".repeat(64));
                    row.fingerprint.clear();
                    row.fingerprint = format!(
                        "sha256:{:x}",
                        Sha256::digest(serde_json::to_vec(row).unwrap())
                    );
                }
            }
            "known_hour_account" => {
                item.usage_buckets[0].model_usage[0].account_identifier_hash = Some("a".repeat(64))
            }
            "api_route" => item.model_usage[0].billing_channel = Some("api".into()),
            "child_namespace" => item.source_session_id += "_agent-child",
            "duplicate_api" => {
                let r = a.evidence[&mixed.source_session_id][0].clone();
                a.evidence
                    .get_mut(&mixed.source_session_id)
                    .unwrap()
                    .push(r);
            }
            "missing_trace" => {
                t.evidence.get_mut(&mixed.source_session_id).unwrap().pop();
            }
            "unchecked_identity" => {
                a.evidence.get_mut(&mixed.source_session_id).unwrap()[0].account_identity_checked =
                    false
            }
            "invalid_fingerprint" => {
                a.evidence.get_mut(&mixed.source_session_id).unwrap()[0].fingerprint = "bad".into()
            }
            "marker_only" => a.evidence.clear(),
            _ => unreachable!(),
        }
        assert!(
            !qualification.mixed.permits(&item)
                || matches!(
                    case,
                    "single_account"
                        | "duplicate_api"
                        | "missing_trace"
                        | "unchecked_identity"
                        | "invalid_fingerprint"
                        | "marker_only"
                )
        );
        let new = claude_request_accounts::apply(std::slice::from_mut(&mut item), &a, &t);
        assert!(!new.mixed.permits(&item), "refuse {case}");
        assert!(
            restarted
                .bind_session_accounts_with_mixed(
                    SnapshotSource::ClaudeCode,
                    "machine",
                    &mut [item],
                    &[],
                    &new.mixed
                )
                .contains(&mixed.source_session_id)
                || case == "child_namespace"
        );
    }
    // Mixed certifies accounts, never time. Losing local clock proof does not
    // invalidate the genuine reported body or invent a request-login binding.
    let mut clockless = mixed.clone();
    for o in clockless.claude_usage_occurrences.values_mut() {
        o.event_clock_complete = false;
    }
    assert!(
        claude_request_accounts::apply(std::slice::from_mut(&mut clockless), &api, &trace)
            .mixed
            .permits(&clockless)
    );
    // Rebuild a genuine two-hour body through the same native proof path.
    // The exception is independent of model/hour aggregation and splits no money.
    let path = dir.join(format!("{}.jsonl", mixed.source_session_id));
    let changed = fs::read_to_string(&path)
        .unwrap()
        .replace("07:00:03Z", "08:20:00Z");
    fs::write(&path, changed).unwrap();
    let mut multihour =
        parse_claude_code_jsonl_file(&path, "2026-08-02T08:30:00Z", "synthetic-source".into())
            .unwrap();
    multihour[0].session_account_evidence = mixed.session_account_evidence.clone();
    let mut census = ScanIndex::default();
    census
        .files
        .insert(local_index_key(&path), manifest_index_entry(None));
    apply_claude_reported_usage_with_index(
        &mut multihour,
        &api,
        &trace,
        &mut census,
        true,
        "2026-08-02T08:30:00Z",
    );
    assert_eq!(
        multihour[0].usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_eq!(multihour[0].usage_buckets.len(), 2);
    let proof = claude_request_accounts::apply(&mut multihour, &api, &trace);
    assert!(proof.mixed.permits(&multihour[0]));
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut multihour,
            &[],
            &proof.mixed
        )
        .is_empty());
    assert_eq!(
        multihour[0]
            .cost
            .as_ref()
            .unwrap()
            .total_cost_usd
            .as_deref(),
        Some("4")
    );
    output("native-mixed-multihour.json", &multihour[0]);
    // An independently changed creator cannot release this retained A owner.
    multihour[0]
        .session_account_evidence
        .as_mut()
        .unwrap()
        .account_identifier_hash = Some("b".repeat(64));
    multihour[0]
        .session_account_evidence
        .as_mut()
        .unwrap()
        .provider_workspace_hash = Some("d".repeat(64));
    let proof = claude_request_accounts::apply(&mut multihour, &api, &trace);
    assert!(proof.mixed.permits(&multihour[0]));
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut multihour,
            &[],
            &proof.mixed
        )
        .contains(&mixed.source_session_id));
    fs::remove_dir_all(dir).unwrap();
    fs::remove_dir_all(prior_dir).unwrap();
}

#[test]
fn terminal_off_on_claude_p92_mixed_body_capability_and_restart_refusals() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, mut mixed, api, trace) = claude_request_account_mixed_fixture(4, true);
    let (prior_dir, mut prior, _, _) = claude_request_account_mixed_fixture(2, true);
    let before = serde_json::to_value(&mixed).unwrap();
    let qualification =
        claude_request_accounts::apply(std::slice::from_mut(&mut mixed), &api, &trace);
    assert!(qualification.mixed.permits(&mixed));
    assert_eq!(mixed.provenance.collector, claude_request_accounts::MIXED);
    assert_eq!(
        mixed.cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("4")
    );
    for field in [
        "model_usage",
        "usage_buckets",
        "cost",
        "request_count",
        "session_account_evidence",
        "usage_accounting_contract",
    ] {
        assert_eq!(
            serde_json::to_value(&mixed).unwrap()[field],
            before[field],
            "{field}"
        );
    }
    output("native-mixed-qualified.json", &mixed);
    output("native-mixed-prior.json", &prior);
    let mut index = ScanIndex::default();
    assert!(index
        .bind_session_accounts(
            SnapshotSource::ClaudeCode,
            "machine",
            std::slice::from_mut(&mut prior),
            &[]
        )
        .is_empty());
    let owner = index.session_account_bindings.clone();
    assert!(
        index
            .bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "machine",
                &mut [mixed.clone()],
                &[]
            )
            .contains(&mixed.source_session_id),
        "marker-only default binder is unchanged"
    );
    assert!(index
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut [mixed.clone()],
            &[],
            &qualification.mixed
        )
        .is_empty());
    assert_eq!(index.session_account_bindings, owner);
    assert!(
        index.accepted_snapshot_fingerprints.is_empty(),
        "fresh eligibility does not mint acceptance"
    );
    let index_path = dir.join("index.json");
    index.save(&index_path).unwrap();
    let mut restarted = ScanIndex::load(&index_path).unwrap();
    assert!(
        restarted
            .bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "machine",
                &mut [mixed.clone()],
                &[]
            )
            .contains(&mixed.source_session_id),
        "restart cannot restore ephemeral capability"
    );
    let mut fresh = mixed.clone();
    let again = claude_request_accounts::apply(std::slice::from_mut(&mut fresh), &api, &trace);
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut [fresh.clone()],
            &[],
            &again.mixed
        )
        .is_empty());
    assert_eq!(
        serde_json::to_value(&fresh).unwrap(),
        serde_json::to_value(&mixed).unwrap(),
        "same proof reconstructs exact candidate"
    );
    for case in [
        "unproven",
        "missing_creator",
        "creator_conflict",
        "single_account",
        "known_hour_account",
        "api_route",
        "child_namespace",
        "duplicate_api",
        "missing_trace",
        "unchecked_identity",
        "invalid_fingerprint",
        "marker_only",
    ] {
        let mut item = mixed.clone();
        let mut a = api.clone();
        let mut t = trace.clone();
        match case {
            "unproven" => item.usage_accounting_contract = None,
            "missing_creator" => item.session_account_evidence = None,
            "creator_conflict" => {
                item.session_account_evidence
                    .as_mut()
                    .unwrap()
                    .identity_disposition = Some("conflict")
            }
            "single_account" => {
                for row in a.evidence.values_mut().flatten() {
                    row.account_identifier_hash = Some("a".repeat(64));
                    row.fingerprint.clear();
                    row.fingerprint = format!(
                        "sha256:{:x}",
                        Sha256::digest(serde_json::to_vec(row).unwrap())
                    );
                }
            }
            "known_hour_account" => {
                item.usage_buckets[0].model_usage[0].account_identifier_hash = Some("a".repeat(64))
            }
            "api_route" => item.model_usage[0].billing_channel = Some("api".into()),
            "child_namespace" => item.source_session_id += "_agent-child",
            "duplicate_api" => {
                let r = a.evidence[&mixed.source_session_id][0].clone();
                a.evidence
                    .get_mut(&mixed.source_session_id)
                    .unwrap()
                    .push(r);
            }
            "missing_trace" => {
                t.evidence.get_mut(&mixed.source_session_id).unwrap().pop();
            }
            "unchecked_identity" => {
                a.evidence.get_mut(&mixed.source_session_id).unwrap()[0].account_identity_checked =
                    false
            }
            "invalid_fingerprint" => {
                a.evidence.get_mut(&mixed.source_session_id).unwrap()[0].fingerprint = "bad".into()
            }
            "marker_only" => a.evidence.clear(),
            _ => unreachable!(),
        }
        assert!(
            !qualification.mixed.permits(&item)
                || matches!(
                    case,
                    "single_account"
                        | "duplicate_api"
                        | "missing_trace"
                        | "unchecked_identity"
                        | "invalid_fingerprint"
                        | "marker_only"
                )
        );
        let new = claude_request_accounts::apply(std::slice::from_mut(&mut item), &a, &t);
        assert!(!new.mixed.permits(&item), "refuse {case}");
        assert!(
            restarted
                .bind_session_accounts_with_mixed(
                    SnapshotSource::ClaudeCode,
                    "machine",
                    &mut [item],
                    &[],
                    &new.mixed
                )
                .contains(&mixed.source_session_id)
                || case == "child_namespace"
        );
    }
    // Mixed certifies accounts, never time. Losing local clock proof does not
    // invalidate the genuine reported body or invent a request-login binding.
    let mut clockless = mixed.clone();
    for o in clockless.claude_usage_occurrences.values_mut() {
        o.event_clock_complete = false;
    }
    assert!(
        claude_request_accounts::apply(std::slice::from_mut(&mut clockless), &api, &trace)
            .mixed
            .permits(&clockless)
    );
    // Rebuild a genuine two-hour body through the same native proof path.
    // The exception is independent of model/hour aggregation and splits no money.
    let path = dir.join(format!("{}.jsonl", mixed.source_session_id));
    let changed = fs::read_to_string(&path)
        .unwrap()
        .replace("07:00:03Z", "08:20:00Z");
    fs::write(&path, changed).unwrap();
    let mut multihour =
        parse_claude_code_jsonl_file(&path, "2026-08-02T08:30:00Z", "synthetic-source".into())
            .unwrap();
    multihour[0].session_account_evidence = mixed.session_account_evidence.clone();
    let mut census = ScanIndex::default();
    census
        .files
        .insert(local_index_key(&path), manifest_index_entry(None));
    apply_claude_reported_usage_with_index(
        &mut multihour,
        &api,
        &trace,
        &mut census,
        true,
        "2026-08-02T08:30:00Z",
    );
    assert!(
        multihour[0].usage_accounting_contract.is_none(),
        "a new cohort receives no terminal proof"
    );
    // Account-binding coverage below consumes an independently reconstructed
    // old-reader witness, as the earlier single-hour controls do. No release
    // completion override, token/cost change or guessed account is involved.
    let root = claude_snapshot_family_root(&multihour[0]);
    census.restore_historical_claude_family_for_test(&root, &api, &trace, false);
    apply_claude_reported_usage_with_index(
        &mut multihour,
        &api,
        &trace,
        &mut census,
        false,
        "2026-08-02T08:30:00Z",
    );
    assert_eq!(
        multihour[0].usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_eq!(multihour[0].usage_buckets.len(), 2);
    let proof = claude_request_accounts::apply(&mut multihour, &api, &trace);
    assert!(proof.mixed.permits(&multihour[0]));
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut multihour,
            &[],
            &proof.mixed
        )
        .is_empty());
    assert_eq!(
        multihour[0]
            .cost
            .as_ref()
            .unwrap()
            .total_cost_usd
            .as_deref(),
        Some("4")
    );
    output("native-mixed-multihour.json", &multihour[0]);
    // An independently changed creator cannot release this retained A owner.
    multihour[0]
        .session_account_evidence
        .as_mut()
        .unwrap()
        .account_identifier_hash = Some("b".repeat(64));
    multihour[0]
        .session_account_evidence
        .as_mut()
        .unwrap()
        .provider_workspace_hash = Some("d".repeat(64));
    let proof = claude_request_accounts::apply(&mut multihour, &api, &trace);
    assert!(proof.mixed.permits(&multihour[0]));
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut multihour,
            &[],
            &proof.mixed
        )
        .contains(&mixed.source_session_id));
    fs::remove_dir_all(dir).unwrap();
    fs::remove_dir_all(prior_dir).unwrap();
}

fn h296_root_evidence() -> (
    PathBuf,
    SnapshotItem,
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let (dir, root, mut items) = claude_account_family_fixture();
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([(
            root.clone(),
            (1..=5).map(|i| complete_api_row(&root, &format!("req_{i}"), i, 10, if i == 5 { 1 } else { 10 }, 0)).collect(),
        )]),
        ..Default::default()
    };
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(
            root.clone(),
            (1..=5).map(|i| complete_trace_row(&root, &format!("req_{i}"), if i == 5 { "a4d1585d310070d0f" } else { "" })).collect(),
        )]),
        ..Default::default()
    };
    let mut root_item = items.remove(0);
    root_item.source_file_fingerprint = Some("e".repeat(64));
    (dir, root_item, api, trace)
}

fn h296_trace_refingerprint(row: &mut crate::claude_local_otel::ClaudeTraceOwnershipEvidence) {
    row.fingerprint.clear();
    row.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(row).unwrap()));
}

#[test]
fn claude_h296_root_and_child_have_independent_exact_request_logins() {
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, mut api, trace) = h296_root_evidence();
    let child_path = dir.join(&root.source_session_id).join("subagents/agent-a4d1585d310070d0f.jsonl");
    let child = parse_claude_code_jsonl_file(&child_path, "2026-08-02T07:01:00Z", "child-fp".into()).unwrap().remove(0);
    let child_row = api.evidence.get_mut(&root.source_session_id).unwrap().last_mut().unwrap();
    child_row.account_identifier_hash = Some("b".repeat(64));
    child_row.fingerprint.clear();
    child_row.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&child_row).unwrap()));
    let mut items = [root.clone(), child];
    let creator = items[0].session_account_evidence.clone();
    let usage = (items[0].input_tokens, items[0].output_tokens, items[0].request_count, items[0].cost.clone());
    let result = claude_request_accounts::apply(&mut items, &api, &trace);
    assert_eq!(result.coverage, [claude_request_accounts::Coverage::Complete; 2]);
    assert_eq!(exact_session_account_hash(&items[0]), Some("a".repeat(64)));
    assert_eq!(exact_session_account_hash(&items[1]), Some("b".repeat(64)));
    assert_eq!(items[0].request_count, 4, "child-owned request never contributes to root");
    assert_eq!(items[0].session_account_evidence, creator);
    assert_eq!((items[0].input_tokens, items[0].output_tokens, items[0].request_count, items[0].cost.clone()), usage);
    assert!(items.iter().all(|item| item.provenance.collector == claude_request_accounts::COMPLETE));
    output("native-root-complete.json", &items[0]);
    let bytes = serde_json::to_vec(&items[0]).unwrap();
    claude_request_accounts::apply(&mut items, &api, &trace);
    assert_eq!(serde_json::to_vec(&items[0]).unwrap(), bytes, "exact proof re-evaluation is a no-op");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_claude_h296_root_and_child_have_independent_exact_request_logins() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, mut api, trace) = h296_root_evidence();
    let child_path = dir.join(&root.source_session_id).join("subagents/agent-a4d1585d310070d0f.jsonl");
    let child = parse_claude_code_jsonl_file(&child_path, "2026-08-02T07:01:00Z", "child-fp".into()).unwrap().remove(0);
    let child_row = api.evidence.get_mut(&root.source_session_id).unwrap().last_mut().unwrap();
    child_row.account_identifier_hash = Some("b".repeat(64));
    child_row.fingerprint.clear();
    child_row.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&child_row).unwrap()));
    let mut items = [root.clone(), child];
    let creator = items[0].session_account_evidence.clone();
    let usage = (items[0].input_tokens, items[0].output_tokens, items[0].request_count, items[0].cost.clone());
    let result = claude_request_accounts::apply(&mut items, &api, &trace);
    assert_eq!(result.coverage, [claude_request_accounts::Coverage::Complete; 2]);
    assert_eq!(exact_session_account_hash(&items[0]), Some("a".repeat(64)));
    assert_eq!(exact_session_account_hash(&items[1]), Some("b".repeat(64)));
    assert_eq!(items[0].request_count, 4, "child-owned request never contributes to root");
    assert_eq!(items[0].session_account_evidence, creator);
    assert_eq!((items[0].input_tokens, items[0].output_tokens, items[0].request_count, items[0].cost.clone()), usage);
    assert!(items.iter().all(|item| item.provenance.collector == claude_request_accounts::COMPLETE));
    output("native-root-complete.json", &items[0]);
    let bytes = serde_json::to_vec(&items[0]).unwrap();
    claude_request_accounts::apply(&mut items, &api, &trace);
    assert_eq!(serde_json::to_vec(&items[0]).unwrap(), bytes, "exact proof re-evaluation is a no-op");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn claude_h296_root_refuses_partial_no_otel_owners_and_collisions() {
    let (dir, original, api, trace) = h296_root_evidence();
    for case in ["no_otel", "partial", "unhealthy", "duplicate_api", "duplicate_trace", "child_owner", "client_collision", "wrong_namespace", "malformed_root", "partial_index", "unknown_cached"] {
        let mut item = original.clone();
        let mut api = api.clone();
        let mut trace = trace.clone();
        match case {
            "no_otel" => api.evidence.clear(),
            "partial" => { api.evidence.get_mut(&item.source_session_id).unwrap().remove(0); }
            "unhealthy" => api.health.malformed_lines = 1,
            "duplicate_api" => { let rows = api.evidence.get_mut(&item.source_session_id).unwrap(); rows.push(rows[0].clone()); }
            "duplicate_trace" => { let rows = trace.evidence.get_mut(&item.source_session_id).unwrap(); rows.push(rows[0].clone()); }
            "child_owner" | "client_collision" | "wrong_namespace" => {
                let row = &mut trace.evidence.get_mut(&item.source_session_id).unwrap()[0];
                match case {
                    "child_owner" => row.agent_id = "a4d1585d310070d0f".into(),
                    "client_collision" => row.client_request_id = "another-request".into(),
                    _ => row.session_id = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5".into(),
                }
                h296_trace_refingerprint(row);
            }
            "malformed_root" => item.source_session_id = "unsupported-root".into(),
            "partial_index" => item.claude_context_curve_request_index_complete = false,
            "unknown_cached" => {
                item.provenance.collector = claude_request_accounts::COMPLETE.into();
                let wire = serde_json::to_value(&item).unwrap();
                assert!(wire.get("claude_usage_request_ids").is_none());
                assert!(wire.get("claude_usage_occurrences").is_none());
                item.claude_usage_request_ids.clear();
                item.claude_usage_occurrences.clear();
            }
            _ => unreachable!(),
        }
        let usage = (item.input_tokens, item.output_tokens, item.request_count, item.cost.clone());
        let creator = item.session_account_evidence.clone();
        let result = claude_request_accounts::apply(std::slice::from_mut(&mut item), &api, &trace);
        assert_ne!(result.coverage, [claude_request_accounts::Coverage::Complete], "{case}");
        assert_eq!(item.provenance.collector, claude_request_accounts::UNKNOWN, "{case}");
        assert_eq!(item.session_account_evidence, creator, "{case}");
        assert_eq!((item.input_tokens, item.output_tokens, item.request_count, item.cost.clone()), usage, "{case}");
        assert!(!result.mixed.permits(&item), "single-login refusal has no mixed release capability");
        if case == "partial" { output("native-root-unknown.json", &item); }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_claude_h296_root_refuses_partial_no_otel_owners_and_collisions() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (dir, original, api, trace) = h296_root_evidence();
    for case in ["no_otel", "partial", "unhealthy", "duplicate_api", "duplicate_trace", "child_owner", "client_collision", "wrong_namespace", "malformed_root", "partial_index", "unknown_cached"] {
        let mut item = original.clone();
        let mut api = api.clone();
        let mut trace = trace.clone();
        match case {
            "no_otel" => api.evidence.clear(),
            "partial" => { api.evidence.get_mut(&item.source_session_id).unwrap().remove(0); }
            "unhealthy" => api.health.malformed_lines = 1,
            "duplicate_api" => { let rows = api.evidence.get_mut(&item.source_session_id).unwrap(); rows.push(rows[0].clone()); }
            "duplicate_trace" => { let rows = trace.evidence.get_mut(&item.source_session_id).unwrap(); rows.push(rows[0].clone()); }
            "child_owner" | "client_collision" | "wrong_namespace" => {
                let row = &mut trace.evidence.get_mut(&item.source_session_id).unwrap()[0];
                match case {
                    "child_owner" => row.agent_id = "a4d1585d310070d0f".into(),
                    "client_collision" => row.client_request_id = "another-request".into(),
                    _ => row.session_id = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5".into(),
                }
                h296_trace_refingerprint(row);
            }
            "malformed_root" => item.source_session_id = "unsupported-root".into(),
            "partial_index" => item.claude_context_curve_request_index_complete = false,
            "unknown_cached" => {
                item.provenance.collector = claude_request_accounts::COMPLETE.into();
                let wire = serde_json::to_value(&item).unwrap();
                assert!(wire.get("claude_usage_request_ids").is_none());
                assert!(wire.get("claude_usage_occurrences").is_none());
                item.claude_usage_request_ids.clear();
                item.claude_usage_occurrences.clear();
            }
            _ => unreachable!(),
        }
        let usage = (item.input_tokens, item.output_tokens, item.request_count, item.cost.clone());
        let creator = item.session_account_evidence.clone();
        let result = claude_request_accounts::apply(std::slice::from_mut(&mut item), &api, &trace);
        assert_ne!(result.coverage, [claude_request_accounts::Coverage::Complete], "{case}");
        assert_eq!(item.provenance.collector, claude_request_accounts::UNKNOWN, "{case}");
        assert_eq!(item.session_account_evidence, creator, "{case}");
        assert_eq!((item.input_tokens, item.output_tokens, item.request_count, item.cost.clone()), usage, "{case}");
        assert!(!result.mixed.permits(&item), "single-login refusal has no mixed release capability");
        if case == "partial" { output("native-root-unknown.json", &item); }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn claude_h296_root_clocks_and_creator_conflicts_stay_separate() {
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, original, api, trace) = h296_root_evidence();
    for case in ["missing_clock", "observer_fallback", "hour_minimum", "missing_hour", "creator_conflict", "creator_other_account", "unsupported_route", "multiple_logins"] {
        let mut item = original.clone(); let mut api = api.clone();
        match case {
            "missing_clock" => item.claude_usage_occurrences.get_mut("req_1").unwrap().timestamp = None,
            "observer_fallback" => item.claude_usage_occurrences.get_mut("req_1").unwrap().event_clock_complete = false,
            "hour_minimum" => item.usage_buckets[0].first_activity_at = Some("2026-08-02T07:00:01Z".into()),
            "missing_hour" => item.usage_buckets.clear(),
            "creator_conflict" | "creator_other_account" => {
                item.session_account_evidence = Some(SessionAccountEvidence { provider:"anthropic", account_identifier_hash:Some("b".repeat(64)), provider_workspace_hash:Some("c".repeat(64)), identity_hash_scheme:"provider-sha256:v1", evidence_source:"claude_desktop_original:v1", identity_disposition:Some(if case == "creator_conflict" {"conflict"} else {"complete"}), source_created_at:Some("2026-08-02T06:59:00Z".into()) });
            }
            "unsupported_route" => item.model_usage[0].billing_channel = Some("api".into()),
            "multiple_logins" => {
                let row = &mut api.evidence.get_mut(&item.source_session_id).unwrap()[0]; row.account_identifier_hash = Some("b".repeat(64)); row.fingerprint.clear(); row.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&row).unwrap()));
            }
            _ => unreachable!(),
        }
        let creator = item.session_account_evidence.clone(); let usage = (item.input_tokens,item.output_tokens,item.request_count,item.cost.clone());
        let result = claude_request_accounts::apply(std::slice::from_mut(&mut item), &api, &trace);
        assert_ne!(result.coverage, [claude_request_accounts::Coverage::Complete], "{case}");
        assert_eq!(item.provenance.collector, claude_request_accounts::UNKNOWN, "{case}");
        assert_eq!(item.session_account_evidence, creator, "{case}");
        assert_eq!((item.input_tokens,item.output_tokens,item.request_count,item.cost.clone()), usage, "{case}");
        if case == "observer_fallback" { assert_eq!(exact_session_account_hash(&item), Some("a".repeat(64)), "clock loss does not erase independently proved account"); }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_claude_h296_root_clocks_and_creator_conflicts_stay_separate() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, original, api, trace) = h296_root_evidence();
    for case in ["missing_clock", "observer_fallback", "hour_minimum", "missing_hour", "creator_conflict", "creator_other_account", "unsupported_route", "multiple_logins"] {
        let mut item = original.clone(); let mut api = api.clone();
        match case {
            "missing_clock" => item.claude_usage_occurrences.get_mut("req_1").unwrap().timestamp = None,
            "observer_fallback" => item.claude_usage_occurrences.get_mut("req_1").unwrap().event_clock_complete = false,
            "hour_minimum" => item.usage_buckets[0].first_activity_at = Some("2026-08-02T07:00:01Z".into()),
            "missing_hour" => item.usage_buckets.clear(),
            "creator_conflict" | "creator_other_account" => {
                item.session_account_evidence = Some(SessionAccountEvidence { provider:"anthropic", account_identifier_hash:Some("b".repeat(64)), provider_workspace_hash:Some("c".repeat(64)), identity_hash_scheme:"provider-sha256:v1", evidence_source:"claude_desktop_original:v1", identity_disposition:Some(if case == "creator_conflict" {"conflict"} else {"complete"}), source_created_at:Some("2026-08-02T06:59:00Z".into()) });
            }
            "unsupported_route" => item.model_usage[0].billing_channel = Some("api".into()),
            "multiple_logins" => {
                let row = &mut api.evidence.get_mut(&item.source_session_id).unwrap()[0]; row.account_identifier_hash = Some("b".repeat(64)); row.fingerprint.clear(); row.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&row).unwrap()));
            }
            _ => unreachable!(),
        }
        let creator = item.session_account_evidence.clone(); let usage = (item.input_tokens,item.output_tokens,item.request_count,item.cost.clone());
        let result = claude_request_accounts::apply(std::slice::from_mut(&mut item), &api, &trace);
        assert_ne!(result.coverage, [claude_request_accounts::Coverage::Complete], "{case}");
        assert_eq!(item.provenance.collector, claude_request_accounts::UNKNOWN, "{case}");
        assert_eq!(item.session_account_evidence, creator, "{case}");
        assert_eq!((item.input_tokens,item.output_tokens,item.request_count,item.cost.clone()), usage, "{case}");
        if case == "observer_fallback" { assert_eq!(exact_session_account_hash(&item), Some("a".repeat(64)), "clock loss does not erase independently proved account"); }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn claude_h296_root_production_enrichment_keeps_child_separate() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, api, trace) = h296_root_evidence();
    let support = dir.join("support");
    let digest = format!("{:x}", Sha256::digest(root.source_session_id.as_bytes()));
    for (kind, rows) in [
        ("claude-code-effort", api.evidence[&root.source_session_id].iter().map(|row| serde_json::to_value(row).unwrap()).collect::<Vec<_>>()),
        ("claude-code-trace-ownership", trace.evidence[&root.source_session_id].iter().map(|row| serde_json::to_value(row).unwrap()).collect::<Vec<_>>()),
    ] {
        let path = support.join("local-otel").join(kind).join(format!("{digest}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, rows.iter().map(|row| row.to_string()+"\n").collect::<String>()).unwrap();
    }
    let mut index = ScanIndex::default();
    let mut scan = scan_source_roots_with_test_limit(SnapshotSource::ClaudeCode, std::slice::from_ref(&dir), &mut index, "2026-08-02T07:10:00Z", 7, 100, false).unwrap();
    assert!(scan.census_complete);
    let creator = scan.snapshots.iter().find(|item| item.source_session_id == root.source_session_id).unwrap().session_account_evidence.clone();
    let (_, withheld, stats) = crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
    assert!(!withheld);
    assert_eq!(stats.own_request_complete_root_count, 1);
    assert_eq!(stats.own_request_unknown_root_count, 0);
    let qualified = scan.snapshots.iter().find(|item| item.source_session_id == root.source_session_id).unwrap();
    assert_eq!(qualified.provenance.collector, claude_request_accounts::COMPLETE);
    assert_eq!(qualified.request_count, 4);
    assert_eq!(qualified.claude_usage_request_ids.len(), 4);
    assert!(!qualified.claude_usage_request_ids.contains("req_5"));
    assert_eq!(qualified.session_account_evidence, creator);
    assert!(qualified.session_account_evidence.as_ref().is_some_and(|original| original.identity_disposition == Some("missing")), "request account never manufactures original creator");
    assert_eq!(qualified.usage_accounting_contract.as_deref(), Some("session_exclusive_reported_usage:v1"));
    assert_eq!(qualified.cost.as_ref().unwrap().total_cost_usd.as_deref(), Some("0.0004"));
    assert_eq!(scan.snapshots.iter().find(|item| item.source_session_id != root.source_session_id).unwrap().request_count, 1);
    assert!(index.accepted_snapshot_fingerprints.is_empty(), "qualification is not an ACK");
    output("native-root-production.json", qualified);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_claude_h296_root_production_enrichment_keeps_child_separate() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, api, trace) = h296_root_evidence();
    let support = dir.join("support");
    let digest = format!("{:x}", Sha256::digest(root.source_session_id.as_bytes()));
    for (kind, rows) in [
        (
            "claude-code-effort",
            api.evidence[&root.source_session_id]
                .iter()
                .map(|row| serde_json::to_value(row).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "claude-code-trace-ownership",
            trace.evidence[&root.source_session_id]
                .iter()
                .map(|row| serde_json::to_value(row).unwrap())
                .collect::<Vec<_>>(),
        ),
    ] {
        let path = support
            .join("local-otel")
            .join(kind)
            .join(format!("{digest}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            rows.iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    let mut index = ScanIndex::default();
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&dir),
        &mut index,
        "2026-08-02T07:10:00Z",
        7,
        100,
        false,
    )
    .unwrap();
    assert!(!scan.census_complete);
    let creator = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == root.source_session_id)
        .unwrap()
        .session_account_evidence
        .clone();
    // Current cohort cannot mint the legacy reported proof. Restore a
    // controlled historical proof for the independent enrichment/ACK contract.
    apply_claude_reported_usage_with_index(
        &mut scan.snapshots,
        &api,
        &trace,
        &mut index,
        false,
        "2026-08-02T07:10:00Z",
    );
    index.restore_historical_claude_family_for_test(&root.source_session_id, &api, &trace, false);
    let (_, withheld, stats) =
        crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
    assert!(!withheld);
    assert_eq!(stats.own_request_complete_root_count, 1);
    assert_eq!(stats.own_request_unknown_root_count, 0);
    let qualified = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == root.source_session_id)
        .unwrap();
    assert_eq!(
        qualified.provenance.collector,
        claude_request_accounts::COMPLETE
    );
    assert_eq!(qualified.request_count, 4);
    assert_eq!(qualified.claude_usage_request_ids.len(), 4);
    assert!(!qualified.claude_usage_request_ids.contains("req_5"));
    assert_eq!(qualified.session_account_evidence, creator);
    assert!(
        qualified
            .session_account_evidence
            .as_ref()
            .is_some_and(|original| original.identity_disposition == Some("missing")),
        "request account never manufactures original creator"
    );
    assert_eq!(
        qualified.usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_eq!(
        qualified.cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("0.0004")
    );
    assert_eq!(
        scan.snapshots
            .iter()
            .find(|item| item.source_session_id != root.source_session_id)
            .unwrap()
            .request_count,
        1
    );
    assert!(
        index.accepted_snapshot_fingerprints.is_empty(),
        "qualification is not an ACK"
    );
    output("native-root-production.json", qualified);
    fs::remove_dir_all(dir).unwrap();
}

/// Contract 5 is always on: with no cohort token anywhere, a Claude page
/// builds contract-5 bodies, the same bytes every run. Was
/// `claude_contract5_bodies_need_this_cycles_cohort_permit`, whose
/// tokenless and denied cycles kept today's (`COMPLETE`) bytes.
#[test]
fn claude_contract5_bodies_need_no_cohort_token() {
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::claude_request_identity as identity;
    let (dir, root, api, trace) = h296_root_evidence();
    let support = dir.join("support");
    let digest = format!("{:x}", Sha256::digest(root.source_session_id.as_bytes()));
    for (kind, rows) in [
        ("claude-code-effort", api.evidence[&root.source_session_id].iter().map(|row| serde_json::to_value(row).unwrap()).collect::<Vec<_>>()),
        ("claude-code-trace-ownership", trace.evidence[&root.source_session_id].iter().map(|row| serde_json::to_value(row).unwrap()).collect::<Vec<_>>()),
    ] {
        let path = support.join("local-otel").join(kind).join(format!("{digest}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, rows.iter().map(|row| row.to_string()+"\n").collect::<String>()).unwrap();
    }
    let run = || {
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots_with_test_limit(SnapshotSource::ClaudeCode, std::slice::from_ref(&dir), &mut index, "2026-08-02T07:10:00Z", 7, 100, false).unwrap();
        crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
        scan.snapshots
    };
    let collector = |items: &[SnapshotItem]| items.iter().find(|item| item.source_session_id == root.source_session_id).unwrap().provenance.collector.clone();
    let first = run();
    assert_eq!(collector(&first), identity::COLLECTOR);
    assert_eq!(serde_json::to_vec(&run()).unwrap(), serde_json::to_vec(&first).unwrap());
    fs::remove_dir_all(dir).unwrap();
}

/// Contract 5 is always on: with no cohort token anywhere, a Claude page
/// builds contract-5 bodies, the same bytes every run. Was
/// `claude_contract5_bodies_need_this_cycles_cohort_permit`, whose
/// tokenless and denied cycles kept today's (`COMPLETE`) bytes.
#[test]
fn terminal_off_on_claude_contract5_bodies_need_no_cohort_token() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::claude_request_identity as identity;
    let (dir, root, api, trace) = h296_root_evidence();
    let support = dir.join("support");
    let digest = format!("{:x}", Sha256::digest(root.source_session_id.as_bytes()));
    for (kind, rows) in [
        ("claude-code-effort", api.evidence[&root.source_session_id].iter().map(|row| serde_json::to_value(row).unwrap()).collect::<Vec<_>>()),
        ("claude-code-trace-ownership", trace.evidence[&root.source_session_id].iter().map(|row| serde_json::to_value(row).unwrap()).collect::<Vec<_>>()),
    ] {
        let path = support.join("local-otel").join(kind).join(format!("{digest}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, rows.iter().map(|row| row.to_string()+"\n").collect::<String>()).unwrap();
    }
    let run = || {
        let _preview = crate::snapshots::TerminalOffDiscoveryPreviewForTest::begin();
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots_with_test_limit(SnapshotSource::ClaudeCode, std::slice::from_ref(&dir), &mut index, "2026-08-02T07:10:00Z", 7, 100, false).unwrap();
        crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
        scan.snapshots
    };
    let collector = |items: &[SnapshotItem]| items.iter().find(|item| item.source_session_id == root.source_session_id).unwrap().provenance.collector.clone();
    let first = run();
    assert_eq!(collector(&first), identity::COLLECTOR);
    assert_eq!(serde_json::to_vec(&run()).unwrap(), serde_json::to_vec(&first).unwrap());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn claude_h296_root_requires_original_clocks_in_every_hour_before_fold() {
    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, _) = claude_account_family_fixture();
    let path = dir.join(format!("{root}.jsonl"));
    let first: Value = serde_json::from_str(fs::read_to_string(&path).unwrap().lines().next().unwrap()).unwrap();
    let mut later = first.clone();
    later["requestId"] = json!("req_later"); later["timestamp"] = json!("2026-08-02T08:20:00Z");
    let parse = |records: &[Value]| {
        fs::write(&path, records.iter().map(|r| r.to_string()+"\n").collect::<String>()).unwrap();
        parse_claude_code_jsonl_file(&path, "2026-08-02T09:00:00Z", "f".repeat(64)).unwrap().remove(0)
    };
    let mut item = parse(&[first.clone(), later.clone()]);
    let api = [complete_api_row(&root, "req_1", 1, 10, 10, 0), complete_api_row(&root, "req_later", 2, 10, 10, 0)];
    let trace = [complete_trace_row(&root, "req_1", ""), complete_trace_row(&root, "req_later", "")];
    assert!(d1_subagent_account_specimen(&mut item, &api, &trace));
    assert_eq!(item.usage_buckets.len(), 2);
    output("native-root-multihour.json", &item);
    item.claude_usage_occurrences.get_mut("req_1").unwrap().event_clock_complete = false;
    assert!(!d1_subagent_account_specimen(&mut item, &api, &trace), "earliest hour cannot borrow the later stamp");
    let mut partial = first.clone(); partial.as_object_mut().unwrap().remove("timestamp");
    partial["message"]["usage"]["output_tokens"] = json!(11);
    let mut folded = parse(&[first.clone(), partial]);
    assert!(!d1_subagent_account_specimen(&mut folded, &api[..1], &trace[..1]), "unstamped progressive partial cannot borrow the first clock");
    let mut iterations = first;
    iterations["message"]["usage"]["iterations"] = json!([{"input_tokens":10,"output_tokens":1},{"input_tokens":10,"output_tokens":1}]);
    let mut collapsed = parse(&[iterations]);
    assert!(!d1_subagent_account_specimen(&mut collapsed, &api[..1], &trace[..1]), "collapsed calls require exact count/index coverage");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_claude_h296_root_requires_original_clocks_in_every_hour_before_fold() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // D1 session-account qualification and binding; E2 keeps per-request account partitions.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let (dir, root, _) = claude_account_family_fixture();
    let path = dir.join(format!("{root}.jsonl"));
    let first: Value = serde_json::from_str(fs::read_to_string(&path).unwrap().lines().next().unwrap()).unwrap();
    let mut later = first.clone();
    later["requestId"] = json!("req_later"); later["timestamp"] = json!("2026-08-02T08:20:00Z");
    let parse = |records: &[Value]| {
        fs::write(&path, records.iter().map(|r| r.to_string()+"\n").collect::<String>()).unwrap();
        parse_claude_code_jsonl_file(&path, "2026-08-02T09:00:00Z", "f".repeat(64)).unwrap().remove(0)
    };
    let mut item = parse(&[first.clone(), later.clone()]);
    let api = [complete_api_row(&root, "req_1", 1, 10, 10, 0), complete_api_row(&root, "req_later", 2, 10, 10, 0)];
    let trace = [complete_trace_row(&root, "req_1", ""), complete_trace_row(&root, "req_later", "")];
    assert!(d1_subagent_account_specimen(&mut item, &api, &trace));
    assert_eq!(item.usage_buckets.len(), 2);
    output("native-root-multihour.json", &item);
    item.claude_usage_occurrences.get_mut("req_1").unwrap().event_clock_complete = false;
    assert!(!d1_subagent_account_specimen(&mut item, &api, &trace), "earliest hour cannot borrow the later stamp");
    let mut partial = first.clone(); partial.as_object_mut().unwrap().remove("timestamp");
    partial["message"]["usage"]["output_tokens"] = json!(11);
    let mut folded = parse(&[first.clone(), partial]);
    assert!(!d1_subagent_account_specimen(&mut folded, &api[..1], &trace[..1]), "unstamped progressive partial cannot borrow the first clock");
    let mut iterations = first;
    iterations["message"]["usage"]["iterations"] = json!([{"input_tokens":10,"output_tokens":1},{"input_tokens":10,"output_tokens":1}]);
    let mut collapsed = parse(&[iterations]);
    assert!(!d1_subagent_account_specimen(&mut collapsed, &api[..1], &trace[..1]), "collapsed calls require exact count/index coverage");
    fs::remove_dir_all(dir).unwrap();
}
