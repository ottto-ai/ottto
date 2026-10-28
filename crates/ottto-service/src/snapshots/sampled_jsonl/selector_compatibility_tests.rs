// Test-only overlay: this exact file also compiles against the unchanged base.
mod selector_compatibility_tests {
    use super::*;

    fn fields() -> Value {
        json!({"serviceTier":" Priority ","speed":"normal","batchMode":true,
            "dataResidency":"US","contextLengthBucket":"long","cache_write_ttl_seconds":3600,
            "fastMode":true,"gatewayProvider":"bedrock","modelProvider":"anthropic",
            "authMode":"API Key","billingChannel":"subscription","planType":"pro","planWindowBucket":20598})
    }

    fn rate_limits() -> Value {
        json!({"plan_type":"pro","primary":{"used_percent":35.5,"window_minutes":300,"resets_at":1779667300u64},
            "secondary":{"used_percent":2.0,"window_minutes":10080,"resets_at":1779667300u64},
            "credits":{"has_credits":true,"unlimited":false,"balance":"12.50"}})
    }

    fn lines(source: SnapshotSource) -> Vec<String> {
        let lines = match source {
            SnapshotSource::ClaudeCode => claude_lines(2, 2),
            _ => codex_lines(),
        };
        lines
            .into_iter()
            .map(|line| {
                let mut value: Value = serde_json::from_str(&line).unwrap();
                value["selector_context"] = fields();
                if source == SnapshotSource::Codex
                    && value.pointer("/payload/type").and_then(Value::as_str) == Some("token_count")
                {
                    value["payload"]["rate_limits"] = rate_limits();
                }
                value.to_string()
            })
            .collect()
    }

    fn row_receipt(selector: &SelectorCapture) -> Value {
        let (key, context, sources) = build_row_identity("gpt-5.2", selector, Some("high"));
        let row = model_usage_from_row(
            &key,
            &BucketRowAccumulator {
                selector_context: context,
                selector_sources: sources,
                usage: UsageTotals {
                    input_tokens: 100,
                    output_tokens: 3,
                    request_count: 1,
                    ..Default::default()
                },
                reasoning_effort: Some("high".into()),
            },
        );
        json!({"identity":format!("{key:?}"),"row_bytes":serde_json::to_vec(&row).unwrap()})
    }

    #[test]
    fn valid_native_bodies_records_tier_and_plan_receipt() {
        let (bytes, counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            let mut receipts = BTreeMap::new();
            for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
                let scratch = if let Some(root) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_ROOT") {
                    let dir = PathBuf::from(root)
                        .join("selector-native")
                        .join(source.api_slug());
                    if dir.exists() {
                        fs::remove_dir_all(&dir).unwrap();
                    }
                    fs::create_dir_all(&dir).unwrap();
                    Scratch(dir)
                } else {
                    Scratch::new("selector-compatibility")
                };
                let path = scratch.write("selector.jsonl", &lines(source));
                let (reduction, _) = full_read(&path, source);
                let body = encode(
                    &reduction,
                    crate::durable_tail_store::RECORD_BYTES,
                    line_cap(),
                )
                .unwrap();
                let selector = match source {
                    SnapshotSource::ClaudeCode => {
                        claude_code_selector_from_line(&json!({"selector_context":fields()}))
                    }
                    _ => codex_selector_from_line(
                        &json!({"selector_context":fields(),"payload":{"rate_limits":rate_limits()}}),
                    ),
                };
                assert_eq!(
                    selector
                        .context
                        .get("plan_window_bucket")
                        .map(String::as_str),
                    Some("20598")
                );
                assert_eq!(
                    selector.context.get("cache_ttl").map(String::as_str),
                    Some("3600")
                );
                assert_eq!(
                    selector.context.get("auth_mode").map(String::as_str),
                    Some("api_key")
                );
                assert_eq!(
                    selector.context.get("speed_mode").map(String::as_str),
                    Some("standard")
                );
                let mut replay = codex_file_join::TierReplay::new(None, false, "fixture".into());
                let event = json!({"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":codex_usage(100)}}});
                replay.observe(&event);
                let tier = replay
                    .selector(
                        &event,
                        &mut selector.clone(),
                        &SelectorCapture::default(),
                        Some("gpt-5.2"),
                        Some("high"),
                        Some("turn-1"),
                    )
                    .unwrap();
                assert_eq!(tier.0.len(), 64);
                let usage = UsageTotals {
                    input_tokens: 100,
                    output_tokens: 3,
                    ..Default::default()
                };
                let pi_digest = pi_usage_occurrence_digest(
                    Some("gpt-5.2"),
                    &usage,
                    &selector,
                    Some("2026-10-20T10:00:00Z"),
                );
                receipts.insert(source.api_slug(), json!({"context":selector.context,"sources":selector.sources,
                "record_body":body,"emitted_body":serde_json::to_vec(&cold_items(&path,source)).unwrap(),
                "row":row_receipt(&selector),"codex_applied_tier_v1":tier,"pi_occurrence":pi_digest}));

                if source == SnapshotSource::Codex {
                    let mut parser = parser(&path, source);
                    while !parser.step().unwrap() {}
                    let identity =
                        opened_object_identity(source, &mut File::open(&path).unwrap()).unwrap();
                    let mut snapshots = parser
                        .finish_with_repository_identity(
                            &identity,
                            &path,
                            COLLECTED,
                            "fp".into(),
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                        .unwrap()
                        .snapshots;
                    assert!(!snapshots.is_empty());
                    // Exercise detected uses' actual input contract. Emitted wire rows still
                    // strip this key; restoring it to uploads is outside this change.
                    for snapshot in &mut snapshots {
                        for bucket in &mut snapshot.usage_buckets {
                            for row in &mut bucket.model_usage {
                                row.selector_context.insert(
                                    "plan_window_bucket".into(),
                                    selector.context["plan_window_bucket"].clone(),
                                );
                            }
                        }
                    }
                    let detected = crate::detected_uses::aggregate_detected_uses(&snapshots);
                    assert!(!detected.is_empty());
                    assert!(detected
                        .iter()
                        .all(|row| row.plan_fingerprint.as_deref() == Some("pro::20598")));
                    receipts.insert("plan", serde_json::to_value(&detected).unwrap());
                }
            }
            serde_json::to_vec(&receipts).unwrap()
        });
        let counts = serde_json::to_value(counts).unwrap();
        for name in [
            "selector_key_rejected_unknown",
            "selector_key_rejected_format",
        ] {
            assert_eq!(counts.get(name).and_then(Value::as_u64).unwrap_or(0), 0);
        }
        if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
            let dir = PathBuf::from(out).join("selector");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("compatibility.json"), &bytes).unwrap();
        }
        println!(
            "SELECTOR_COMPATIBILITY VERIFIED bytes={} sha256={:x}",
            bytes.len(),
            Sha256::digest(&bytes)
        );
    }
}
