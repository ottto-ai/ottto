fn output(name: &str, item: &SnapshotItem) {
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
    ] {
        let mut item = original.clone();
        match case {
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
                    &BTreeSet::new()
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
    (dir, items.remove(0), api, trace)
}

#[test]
fn claude_p92_mixed_body_capability_and_restart_refusals() {
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
