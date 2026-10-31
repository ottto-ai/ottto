// Synthetic fixtures construct receiver-valid totals explicitly. The older
// emitter's mixed-presence bug is outside this allocator change.
fn sticky_receiver_totals(item: &mut SnapshotItem) {
    let mut costs = BTreeMap::<RowKey, [Option<u128>; 5]>::new();
    let mut counts = [0u64; 8];
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let money = costs
                .entry(row_key_from_model_usage(row))
                .or_insert([None; 5]);
            for (slot, value) in money.iter_mut().zip([
                &row.cost_usd,
                &row.input_cost_usd,
                &row.output_cost_usd,
                &row.cache_read_cost_usd,
                &row.cache_creation_cost_usd,
            ]) {
                if let Some(value) = value {
                    *slot = Some(slot.unwrap_or(0) + parse_usd_picos(value));
                }
            }
            for (total, value) in counts.iter_mut().zip([
                row.input_tokens,
                row.output_tokens,
                row.cache_read_tokens,
                row.cache_creation_5m_tokens,
                row.cache_creation_1h_tokens,
                row.reasoning_output_tokens,
                row.unattributed_total_tokens,
                row.request_count,
            ]) {
                *total += value;
            }
        }
    }
    let mut totals = [None; 5];
    for row in &mut item.model_usage {
        let money = costs.get(&row_key_from_model_usage(row)).unwrap();
        for (slot, value) in [
            &mut row.cost_usd,
            &mut row.input_cost_usd,
            &mut row.output_cost_usd,
            &mut row.cache_read_cost_usd,
            &mut row.cache_creation_cost_usd,
        ]
        .into_iter()
        .zip(money)
        {
            *slot = value.map(usd_picos_string);
        }
        for (slot, value) in totals.iter_mut().zip(money) {
            if let Some(value) = value {
                *slot = Some(slot.unwrap_or(0) + value);
            }
        }
    }
    [
        item.input_tokens,
        item.output_tokens,
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.reasoning_output_tokens,
        item.unattributed_total_tokens,
        item.request_count,
    ] = counts;
    item.cost = totals.iter().any(Option::is_some).then(|| SnapshotCost {
        total_cost_usd: totals[0].map(usd_picos_string),
        input_cost_usd: totals[1].map(usd_picos_string),
        output_cost_usd: totals[2].map(usd_picos_string),
        cache_read_cost_usd: totals[3].map(usd_picos_string),
        cache_creation_cost_usd: totals[4].map(usd_picos_string),
        evidence_source: "synthetic".into(),
    });
}
fn sticky_apply(
    item: &mut SnapshotItem,
    proof: &[Contribution],
    accepted: &identity::AcceptedBuckets,
) -> Result<Tagged, identity::Ineligible> {
    sticky_receiver_totals(item);
    identity::apply_with_accepted_for_test(item, proof, accepted)
}

// Sticky accepted-key budget, using synthetic proof only.
fn sticky_session(hours: usize) -> (SnapshotItem, Vec<Contribution>) {
    let mut item = one_row_item(&[(2, None)]);
    item.request_identity_refusals = 0;
    let mut row = item.model_usage[0].clone();
    row.model = format!("claude-synthetic-{}", "x".repeat(110));
    row.input_tokens = 3;
    row.request_count = 3;
    let start = OffsetDateTime::parse("2026-09-01T00:00:00Z", &Rfc3339).unwrap();
    let mut contributions = Vec::new();
    item.usage_buckets = (0..hours)
        .map(|hour| {
            let at = (start + time::Duration::hours(hour as i64))
                .format(&Rfc3339)
                .unwrap();
            for part in 0..3 {
                let key = (hour / 24) % 4 + part * 4;
                let mut one = row.clone();
                one.input_tokens = 1;
                one.request_count = 1;
                contributions.push(Contribution {
                    bucket_start: at.clone(),
                    row_key: row_key_from_model_usage(&row),
                    usage: holder_usage(&one, None),
                    identity: RequestIdentity::Tagged(AuthorityKey {
                        login: Some(format!("{key:064x}")),
                        org: Some(format!("{:064x}", key + 32)),
                        basis: identity::TELEMETRY,
                    }),
                });
            }
            SnapshotUsageBucket {
                bucket_start: at,
                model_usage: vec![row.clone()],
                first_activity_at: None,
                last_activity_at: None,
            }
        })
        .collect();
    item.collected_at = item.usage_buckets.last().unwrap().bucket_start.clone();
    row.input_tokens *= hours as u64;
    row.request_count *= hours as u64;
    item.input_tokens = row.input_tokens;
    item.request_count = row.request_count;
    item.output_tokens = 0;
    item.cache_read_tokens = 0;
    item.cache_creation_5m_tokens = 0;
    item.cache_creation_1h_tokens = 0;
    item.reasoning_output_tokens = 0;
    item.unattributed_total_tokens = 0;
    item.cost = None;
    item.source_started_at = Some(item.usage_buckets[0].bucket_start.clone());
    item.source_last_activity_at = Some(item.collected_at.clone());
    item.source_ended_at = None;
    item.model_usage = vec![row];
    (item, contributions)
}
fn sticky_tagged(row: &SnapshotModelUsage) -> bool {
    row.evidence_ref.is_some()
        || row
            .identity_parts
            .as_ref()
            .is_some_and(|parts| parts.iter().any(|part| part.evidence_ref.is_some()))
}
type StickyAuthority = (Option<String>, String, Option<String>);
type StickyShares = BTreeMap<(RowKey, Option<StickyAuthority>), ([u64; 8], [Option<u128>; 5])>;

fn sticky_assert_reconciled(item: &SnapshotItem) {
    // Mirror receiver _identity_share_totals, including the untagged residual.
    let shares = |rows: Vec<&SnapshotModelUsage>| {
        let mut totals = StickyShares::new();
        let mut add = |row: &SnapshotModelUsage,
                       login: &Option<String>,
                       reference: Option<u16>,
                       counts: [u64; 8],
                       costs: [Option<&str>; 5]| {
            let identity = reference.map(|reference| {
                let evidence = &item.request_evidence[usize::from(reference)];
                (
                    login.clone(),
                    evidence.identity_basis.clone(),
                    evidence.provider_workspace_hash.clone(),
                )
            });
            let (total, money) = totals
                .entry((row_key_from_model_usage(row), identity))
                .or_insert(([0; 8], [None; 5]));
            for (total, amount) in total.iter_mut().zip(counts) {
                *total += amount;
            }
            for (total, amount) in money.iter_mut().zip(costs) {
                if let Some(amount) = amount {
                    *total = Some(total.unwrap_or(0) + parse_usd_picos(amount));
                }
            }
        };
        for row in rows {
            if let Some(parts) = &row.identity_parts {
                for p in parts {
                    add(
                        row,
                        &p.account_identifier_hash,
                        p.evidence_ref,
                        [
                            p.input_tokens,
                            p.output_tokens,
                            p.cache_read_tokens,
                            p.cache_creation_5m_tokens,
                            p.cache_creation_1h_tokens,
                            p.reasoning_output_tokens,
                            p.unattributed_total_tokens,
                            p.request_count,
                        ],
                        [
                            p.cost_usd.as_deref(),
                            p.input_cost_usd.as_deref(),
                            p.output_cost_usd.as_deref(),
                            p.cache_read_cost_usd.as_deref(),
                            p.cache_creation_cost_usd.as_deref(),
                        ],
                    );
                }
            } else {
                add(
                    row,
                    &row.account_identifier_hash,
                    row.evidence_ref,
                    [
                        row.input_tokens,
                        row.output_tokens,
                        row.cache_read_tokens,
                        row.cache_creation_5m_tokens,
                        row.cache_creation_1h_tokens,
                        row.reasoning_output_tokens,
                        row.unattributed_total_tokens,
                        row.request_count,
                    ],
                    [
                        row.cost_usd.as_deref(),
                        row.input_cost_usd.as_deref(),
                        row.output_cost_usd.as_deref(),
                        row.cache_read_cost_usd.as_deref(),
                        row.cache_creation_cost_usd.as_deref(),
                    ],
                );
            }
        }
        totals
    };
    assert_eq!(
        shares(item.model_usage.iter().collect()),
        shares(
            item.usage_buckets
                .iter()
                .flat_map(|b| &b.model_usage)
                .collect()
        )
    );
    let mut references = BTreeSet::new();
    for row in item
        .model_usage
        .iter()
        .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
    {
        references.extend(row.evidence_ref);
        for part in row.identity_parts.iter().flatten() {
            references.extend(part.evidence_ref);
        }
    }
    assert_eq!(
        references,
        (0..item.request_evidence.len() as u16).collect()
    );
    sticky_assert_parts_priced(item);
    assert!(identity::item_bytes(item) <= identity::MAX_ITEM_BYTES);
    // Exercise the real upload wrapper, including semantic_envelope. A bare
    // SnapshotItem at 640 KiB is not an uploadable wire item.
    let mut request = valid_v6_batch_request();
    request.source = "claude_code".into();
    request.upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };
    request.snapshots = vec![item.clone()];
    let wire = serde_json::to_value(&request).unwrap();
    assert!(wire["snapshots"][0]["semantic_envelope"].is_object());
    assert!(serde_json::to_vec(&wire["snapshots"][0]).unwrap().len() <= identity::MAX_ITEM_BYTES);
}
#[test]
fn sticky_budget_preserves_accepted_old_bucket_and_refuses_new_when_full() {
    let (mut first, proof) = sticky_session(24 * 24);
    let mut accepted = identity::AcceptedBuckets::for_test();
    let result = sticky_apply(&mut first, &proof, &accepted).unwrap();
    assert!(matches!(result, Tagged::Sent { .. }));
    assert!(
        first.request_identity_refusals > 0,
        "synthetic long body crosses byte cap"
    );
    sticky_assert_reconciled(&first);
    accepted.record(&serde_json::to_value(&first).unwrap());
    let (mut second, proof) = sticky_session(24 * 24 + 1);
    sticky_apply(&mut second, &proof, &accepted).unwrap();
    assert!(
        sticky_tagged(&second.usage_buckets[575].model_usage[0]),
        "previously accepted older hour survives"
    );
    assert!(
        !sticky_tagged(&second.usage_buckets[576].model_usage[0]),
        "new never-accepted hour is refused"
    );
    let lost = second
        .usage_buckets
        .iter()
        .filter(|b| !sticky_tagged(&b.model_usage[0]))
        .count();
    assert_eq!(second.request_identity_refusals, lost as u64);
    assert!(
        second.model_usage[0].identity_parts.is_some(),
        "mandatory reconciled top-level shares"
    );
    assert_eq!(
        second
            .claude_account_display
            .as_ref()
            .unwrap()
            .current
            .status,
        identity::CURRENT_UNKNOWN
    );
    let display = second.claude_account_display.as_ref().unwrap();
    assert_eq!(display.current.status, identity::CURRENT_UNKNOWN);
    assert!(display.history.iter().all(|entry| !entry.current));
    assert_eq!(
        display
            .history
            .iter()
            .filter(|entry| entry.account_identifier_hash.is_some())
            .map(|entry| entry.request_count)
            .sum::<u64>(),
        second
            .usage_buckets
            .iter()
            .filter(|bucket| sticky_tagged(&bucket.model_usage[0]))
            .map(|bucket| bucket.model_usage[0].request_count)
            .sum::<u64>(),
        "retained rows still prove their named account history",
    );
    sticky_assert_reconciled(&second);
    let (mut again, proof) = sticky_session(24 * 24 + 1);
    sticky_apply(&mut again, &proof, &accepted).unwrap();
    assert_eq!(second.snapshot_fingerprint, again.snapshot_fingerprint);
    assert_eq!(
        serde_json::to_vec(&second).unwrap(),
        serde_json::to_vec(&again).unwrap()
    );
    let before = serde_json::to_vec(&second).unwrap();
    let (measured, logs) = crate::local_resource_diagnostics::capture(|| {
        identity::measure_identity_cap(&second, &accepted).unwrap()
    });
    assert!(logs.is_empty());
    assert_eq!(serde_json::to_vec(&second).unwrap(), before);
    assert!(measured.accepted_retained > 0);
    assert_eq!(measured.item_bytes, identity::item_bytes(&second));
}
/// [money] [regress] #909 P0 (05f7bf85: 582 hours over 6 accounts, untagged
/// baseline over the cap): the context curve and cache observations are shed
/// before any money tag. Every accepted share keeps its tag; totals unchanged.
#[test]
fn sticky_budget_sheds_curve_and_cache_before_stripping_any_tag() {
    let (mut item, mut proof) = sticky_session(48);
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    let clean = stripped(&item);
    let overhead = identity::item_bytes(&item) - identity::item_bytes(&clean);
    let (mut padded, filler) =
        sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - overhead - 1_024);
    proof.extend(filler);
    let mut first = padded.clone();
    assert!(matches!(
        sticky_apply(&mut first, &proof, &accepted).unwrap(),
        Tagged::Sent { .. }
    ));
    assert_eq!(first.request_identity_refusals, 0);
    assert!(first.request_evidence.len() >= 2, "several accounts");
    accepted.record(&serde_json::to_value(&first).unwrap());
    let mut expected = padded.clone();
    sticky_apply(&mut expected, &proof, &accepted).unwrap();

    padded.context_curve = Some(max_fractional_context_curve_fixture());
    let curve_points = padded.context_curve.as_ref().unwrap().retained_point_count;
    let upsert = crate::snapshots::cache_adapter_tests::cache_fixture_item()
        .cache_observations
        .unwrap()
        .operations
        .remove(0);
    padded.cache_observations = Some(cache_observations::CacheObservations {
        schema_version: 1,
        operations: (0..cache_observations::MAX_OPERATIONS)
            .map(|n| {
                let mut operation = upsert.clone();
                let cache_observations::Operation::Upsert { observation } = &mut operation else {
                    panic!("fixture upsert");
                };
                observation.event_id = format!("cache:{n:064x}");
                operation
            })
            .collect(),
        coverage: "complete".into(),
        omitted_observation_count: Some(0),
    });
    assert!(
        identity::item_bytes(&padded) > identity::MAX_ITEM_BYTES,
        "untagged baseline with display leaves is over the cap"
    );
    let (result, records) = crate::local_resource_diagnostics::capture(|| {
        sticky_apply(&mut padded, &proof, &accepted).unwrap()
    });
    assert!(matches!(result, Tagged::Sent { .. }));
    assert!(identity::item_bytes(&padded) <= identity::MAX_ITEM_BYTES);
    let shed = records
        .iter()
        .find_map(|row| row["counts"].get("claude_request_identity_last_over_cap_components"))
        .expect("a fitting shed is recorded");
    let bytes = |key: &str| shed[key].as_u64().unwrap();
    assert!(bytes("after_shed") <= identity::MAX_ITEM_BYTES as u64);
    assert_eq!(
        ["context_curve", "cache_observations", "identity", "usage_buckets", "rest"]
            .map(bytes)
            .iter()
            .sum::<u64>(),
        bytes("item")
    );
    assert!(padded.context_curve.as_ref().unwrap().retained_point_count < curve_points);
    let cache = padded.cache_observations.take().unwrap();
    assert_eq!(cache.coverage, "partial");
    assert!(cache.operations.len() < cache_observations::MAX_OPERATIONS);
    assert_eq!(cache.omitted_observation_count, None);
    sticky_assert_reconciled(&padded);
    // Only the display leaves changed: tags, shares, refusals and totals match.
    padded.context_curve = None;
    padded.snapshot_fingerprint = expected.snapshot_fingerprint.clone();
    assert_eq!(
        serde_json::to_value(&padded).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
}
#[test]
fn sticky_overflow_protects_open_hour_drops_oldest_as_differs_and_restores_only_held_proof() {
    let (mut first, proof) = sticky_session(576);
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&first).unwrap());
    let oldest = first
        .usage_buckets
        .iter()
        .position(|b| sticky_tagged(&b.model_usage[0]))
        .unwrap();
    let (mut grown, mut proof) = sticky_session(576);
    // Three new keys force overflow regardless of a partial bucket's byte
    // margin, while keeping the global key and per-row part caps valid.
    for login in ['c', 'd', 'e'] {
        let mut extra = proof.last().unwrap().clone();
        extra.identity = RequestIdentity::Tagged(AuthorityKey {
            login: Some(login.to_string().repeat(64)),
            org: Some("f".repeat(64)),
            basis: identity::TELEMETRY,
        });
        proof.push(extra);
    }
    grown.model_usage[0].input_tokens += 3;
    grown.model_usage[0].request_count += 3;
    grown.usage_buckets[575].model_usage[0].input_tokens += 3;
    grown.usage_buckets[575].model_usage[0].request_count += 3;
    let _ = identity::take_identity_counts();
    sticky_apply(&mut grown, &proof, &accepted).unwrap();
    let counts = serde_json::to_value(identity::take_identity_counts()).unwrap();
    assert!(
        counts["identity_cap"]["accepted_overflow"]["differs"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        counts["identity_cap"]["accepted_overflow"]["same_as_parent"],
        0
    );
    assert!(sticky_tagged(&grown.usage_buckets[575].model_usage[0]));
    assert!(!sticky_tagged(&grown.usage_buckets[oldest].model_usage[0]));
    sticky_assert_reconciled(&grown);
    accepted.record(&serde_json::to_value(&grown).unwrap());
    // The L ledger remembers the stripped bucket, but stores no authority.
    let (mut restored, proof) = sticky_session(576);
    sticky_apply(&mut restored, &proof, &accepted).unwrap();
    assert!(sticky_tagged(
        &restored.usage_buckets[oldest].model_usage[0]
    ));
    let (mut no_proof, mut proof) = sticky_session(576);
    for c in &mut proof {
        if c.bucket_start == no_proof.usage_buckets[oldest].bucket_start {
            c.identity = RequestIdentity::Missing;
        }
    }
    sticky_apply(&mut no_proof, &proof, &accepted).unwrap();
    assert!(!sticky_tagged(
        &no_proof.usage_buckets[oldest].model_usage[0]
    ));
    assert!(no_proof.request_identity_refusals > 0);
    sticky_assert_reconciled(&no_proof);
}
#[test]
fn sticky_missing_state_uses_current_proof_and_counts_unknown() {
    let (mut item, proof) = sticky_session(576);
    let missing = identity::AcceptedBuckets::for_test();
    let _ = identity::take_identity_counts();
    sticky_apply(&mut item, &proof, &missing).unwrap();
    let counts = serde_json::to_value(identity::take_identity_counts()).unwrap();
    assert_eq!(counts["identity_cap"]["accepted_state_unknown"], 1);
    assert!(sticky_tagged(&item.usage_buckets[575].model_usage[0]));
    assert!(!sticky_tagged(&item.usage_buckets[0].model_usage[0]));
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_budget_refolds_exact_money_and_keeps_part_cap_window() {
    let (mut item, mut proof) = sticky_session(576);
    for c in &mut proof {
        c.usage.costs = UsageCosts {
            observed: true,
            reported: true,
            total: Some(1_000_000),
            ..Default::default()
        };
    }
    for bucket in &mut item.usage_buckets {
        bucket.model_usage[0].cost_usd = Some("0.000003".into());
    }
    item.model_usage[0].cost_usd = Some(usd_picos_string(576 * 3 * 1_000_000));
    sticky_apply(&mut item, &proof, &identity::AcceptedBuckets::for_test()).unwrap();
    assert!(item.request_identity_refusals > 0);
    sticky_assert_reconciled(&item);

    let (mut item, proof) = sticky_session(1100);
    let (result, rows) = crate::local_resource_diagnostics::capture(|| {
        sticky_apply(&mut item, &proof, &identity::AcceptedBuckets::for_test()).unwrap()
    });
    assert!(matches!(result, Tagged::Sent { .. }));
    assert!(rows
        .iter()
        .any(
            |row| row["counts"]["claude_request_identity_over_cap"]["parts_per_item"]
                .as_u64()
                .unwrap_or(0)
                > 0
        ));
    assert!(sticky_tagged(&item.usage_buckets[1099].model_usage[0]));
    assert_eq!(
        item.request_identity_refusals,
        item.usage_buckets
            .iter()
            .filter(|bucket| !sticky_tagged(&bucket.model_usage[0]))
            .count() as u64
    );
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_bucket_hint_does_not_refuse_a_legitimately_missing_sibling_row() {
    let requests = [
        display_request(
            Some("max"),
            HOUR_10,
            1,
            login_key(OWNER_A),
            Some("2026-09-01T10:01:00Z"),
        ),
        display_request(
            Some("pro"),
            HOUR_10,
            1,
            RequestIdentity::Missing,
            Some("2026-09-01T10:02:00Z"),
        ),
    ];
    let (mut item, timed) = display_item(&requests);
    let proof = timed
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    assert_eq!(item.request_identity_refusals, 0);
    let measured = identity::measure_identity_cap(&item, &accepted).unwrap();
    assert_eq!(measured.item_bytes, identity::item_bytes(&item));
}

#[test]
fn sticky_partial_body_displays_only_the_kept_newest_own_account() {
    let (mut item, mut proof) = sticky_session(576);
    proof.truncate(proof.len() - 2);
    item.model_usage[0].input_tokens -= 2;
    item.model_usage[0].request_count -= 2;
    item.usage_buckets[575].model_usage[0].input_tokens -= 2;
    item.usage_buckets[575].model_usage[0].request_count -= 2;
    item.input_tokens -= 2;
    item.request_count -= 2;
    sticky_apply(&mut item, &proof, &identity::AcceptedBuckets::for_test()).unwrap();
    assert!(item.request_identity_refusals > 0);
    let display = item.claude_account_display.as_ref().unwrap();
    assert_eq!(display.current.status, identity::CURRENT_KNOWN);
    assert_eq!(
        display.current.account_identifier_hash,
        Some(format!("{:064x}", 3))
    );
    assert_eq!(
        display
            .history
            .iter()
            .map(|entry| entry.request_count)
            .sum::<u64>(),
        item.request_count
    );
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_partial_money_absence_cannot_emit_unreconciled_known_cost_shares() {
    let (mut item, mut proof) = sticky_session(576);
    for (hour, bucket) in item.usage_buckets.iter_mut().enumerate() {
        // Missing hours do not erase present money. The newest priced
        // bucket remains eligible without an unpriced companion.
        let reported = ![0, 24, 48].contains(&hour);
        bucket.model_usage[0].cost_usd = reported.then(|| "0.000003".into());
        for c in &mut proof[hour * 3..hour * 3 + 3] {
            c.usage.costs = UsageCosts {
                observed: true,
                reported,
                total: reported.then_some(1_000_000),
                ..Default::default()
            };
        }
    }
    sticky_receiver_totals(&mut item);
    let result = sticky_apply(&mut item, &proof, &identity::AcceptedBuckets::for_test()).unwrap();
    assert!(matches!(result, Tagged::Sent { .. }));
    assert!(item.request_identity_refusals > 0);
    assert!(sticky_tagged(&item.usage_buckets[575].model_usage[0]));
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_size_budget_matches_real_wire_with_optional_envelope_components() {
    let (item, _) = sticky_session(2);
    for activity in [false, true] {
        for cache_head in [false, true] {
            let mut request = valid_v6_batch_request();
            request.source = "claude_code".into();
            request.upload_policy = SnapshotUploadPolicy {
                session_titles_enabled: false,
                workspace_labels_enabled: false,
                session_artifacts_enabled: false,
                session_attribution_enabled: false,
                session_attribution_labels_enabled: false,
            };
            let mut item = item.clone();
            item.cache_base_head_etag = cache_head.then(|| "a".repeat(64));
            item.activity_summary = activity.then(|| SnapshotActivitySummary {
                capability_collection_version: None,
                tool_calls: 1,
                shell_commands: 0,
                patch_operations: 0,
                changed_files: 0,
                lines_added: 0,
                lines_deleted: 0,
                web_searches: 0,
                mcp_calls: 0,
                subagent_spawns: 0,
                tool_counts: vec![],
                mcp_tool_counts: vec![],
                capability_counts: vec![],
                capability_buckets: vec![],
                skills: vec![],
            });
            let budgeted = identity::item_bytes(&item);
            request.snapshots = vec![item];
            let wire = serde_json::to_value(&request).unwrap();
            assert_eq!(
                budgeted,
                serde_json::to_vec(&wire["snapshots"][0]).unwrap().len(),
                "activity={activity}, cache_head={cache_head}",
            );
        }
    }
}

#[test]
fn sticky_recovery_cannot_promote_an_upstream_inherited_partition_to_proof() {
    let (mut item, proof) = sticky_session(2);
    let mut grouping = identity::Grouping::new(2);
    for c in &proof {
        grouping.add(&c.bucket_start, &c.row_key, &c.usage, c.identity.as_ref());
    }
    grouping.lose_upstream_proof_for_test();
    let result = identity::apply_grouped(&mut item, grouping).unwrap();
    assert!(matches!(result, Tagged::Fallback { .. }));
    assert_eq!(item.request_identity_refusals, 2);
    assert!(item.request_evidence.is_empty());
    assert!(item
        .usage_buckets
        .iter()
        .all(|bucket| !sticky_tagged(&bucket.model_usage[0])));
}

#[test]
fn sticky_unencodable_open_bucket_does_not_erase_independent_older_accepted_proof() {
    let (mut item, mut proof) = sticky_session(2);
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    let mut accepted_body = serde_json::to_value(&item).unwrap();
    accepted_body["usage_buckets"].as_array_mut().unwrap().pop();
    accepted.record(&accepted_body);
    // Seventeen distinct own keys in the current bucket cannot be represented
    // by one row, but the older accepted bucket remains complete and tiny.
    for n in 12..26 {
        let mut extra = proof.last().unwrap().clone();
        extra.identity = RequestIdentity::Tagged(AuthorityKey {
            login: Some(format!("{n:064x}")),
            org: None,
            basis: identity::TELEMETRY,
        });
        proof.push(extra);
        item.model_usage[0].input_tokens += 1;
        item.model_usage[0].request_count += 1;
        item.usage_buckets[1].model_usage[0].input_tokens += 1;
        item.usage_buckets[1].model_usage[0].request_count += 1;
    }
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    assert!(sticky_tagged(&item.usage_buckets[0].model_usage[0]));
    assert!(!sticky_tagged(&item.usage_buckets[1].model_usage[0]));
    assert_eq!(item.request_identity_refusals, 1);
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_complete_accepted_set_is_checked_before_intermediate_money_fit() {
    let (mut item, mut proof) = sticky_session(97);
    for (hour, bucket) in item.usage_buckets.iter_mut().enumerate() {
        let reported = ![0, 24, 48, 72].contains(&hour);
        bucket.model_usage[0].cost_usd = reported.then(|| "0.000003".into());
        for c in &mut proof[hour * 3..hour * 3 + 3] {
            c.usage.costs = UsageCosts {
                observed: true,
                reported,
                total: reported.then_some(1_000_000),
                ..Default::default()
            };
        }
    }
    sticky_receiver_totals(&mut item);
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    sticky_assert_reconciled(&item);
    let measured = identity::measure_identity_cap(&item, &accepted).unwrap();
    assert_eq!(measured.accepted_retained, 97);
    assert_eq!(measured.accepted_overflow.differs, 0);
    assert_eq!(measured.item_bytes, identity::item_bytes(&item));
}

fn sticky_assert_joint_pair_survives(large_parts: bool) {
    let requests = [
        display_request(Some("max"), HOUR_10, 1, login_key(OWNER_A), Some(HOUR_10)),
        display_request(Some("max"), HOUR_11, 1, login_key(OWNER_A), Some(HOUR_11)),
        display_request(
            Some("pro"),
            "2026-09-01T12:00:00Z",
            1,
            login_key(OWNER_A),
            Some("2026-09-01T12:00:00Z"),
        ),
    ];
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T12:05:00Z".into();
    let mut proof = timed
        .into_iter()
        .map(|(proof, _)| proof)
        .collect::<Vec<_>>();
    if large_parts {
        let prototype = proof.pop().unwrap();
        let row = item.usage_buckets[2].model_usage.pop().unwrap();
        item.model_usage
            .retain(|row| row.subscription_product.as_deref() != Some("pro"));
        for n in 0..99 {
            let mut row = row.clone();
            row.model = format!("claude-large-{n:02}");
            item.model_usage.push(row.clone());
            item.usage_buckets[2].model_usage.push(row.clone());
            let mut c = prototype.clone();
            c.row_key = row_key_from_model_usage(&row);
            proof.push(c);
        }
    }
    item.usage_buckets[0].model_usage[0].cost_usd = Some("0.000001".into());
    proof[0].usage.costs = UsageCosts {
        observed: true,
        reported: true,
        total: Some(1_000_000),
        ..Default::default()
    };
    proof[1].usage.costs = UsageCosts {
        observed: true,
        reported: false,
        ..Default::default()
    };
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    let mut accepted_body = serde_json::to_value(&item).unwrap();
    accepted_body["usage_buckets"].as_array_mut().unwrap().pop();
    accepted.record(&accepted_body);
    let extras = if large_parts { 15 } else { 16 };
    let prototypes = proof[2..].to_vec();
    for prototype in prototypes {
        for n in 0..extras {
            let mut extra = prototype.clone();
            extra.identity = RequestIdentity::Tagged(AuthorityKey {
                login: Some(format!("{n:064x}")),
                org: None,
                basis: identity::TELEMETRY_LOGIN,
            });
            proof.push(extra);
        }
    }
    for row in item
        .model_usage
        .iter_mut()
        .filter(|row| row.subscription_product.as_deref() == Some("pro"))
    {
        row.input_tokens += extras;
        row.request_count += extras;
    }
    for row in &mut item.usage_buckets[2].model_usage {
        row.input_tokens += extras;
        row.request_count += extras;
    }
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    assert!(sticky_tagged(&item.usage_buckets[0].model_usage[0]));
    assert!(sticky_tagged(&item.usage_buckets[1].model_usage[0]));
    assert!(item.usage_buckets[2]
        .model_usage
        .iter()
        .all(|row| !sticky_tagged(row)));
    assert_eq!(
        item.request_identity_refusals,
        if large_parts { 99 } else { 1 }
    );
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_unencodable_bucket_preserves_a_jointly_reconcilable_accepted_pair() {
    sticky_assert_joint_pair_survives(false);
}
#[test]
fn sticky_individually_over_parts_bucket_preserves_joint_accepted_money_proof() {
    sticky_assert_joint_pair_survives(true);
}

fn sticky_pad_to_bytes(clean: &SnapshotItem, target: usize) -> (SnapshotItem, Vec<Contribution>) {
    let mut filler = clean.usage_buckets[0].model_usage[0].clone();
    filler.model = "claude-filler".into();
    filler.input_tokens = 1;
    filler.request_count = 1;
    filler.cost_usd = None;
    filler.input_cost_usd = None;
    filler.output_cost_usd = None;
    filler.cache_read_cost_usd = None;
    filler.cache_creation_cost_usd = None;
    let start = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
    let with_fillers = |count: usize| {
        let mut candidate = clean.clone();
        let mut top = filler.clone();
        top.input_tokens = count as u64;
        top.request_count = count as u64;
        candidate.model_usage.push(top);
        candidate.input_tokens += count as u64;
        candidate.request_count += count as u64;
        for hour in 0..count {
            candidate.usage_buckets.push(SnapshotUsageBucket {
                bucket_start: (start + time::Duration::hours(hour as i64))
                    .format(&Rfc3339)
                    .unwrap(),
                model_usage: vec![filler.clone()],
                first_activity_at: None,
                last_activity_at: None,
            });
        }
        candidate
    };
    // A bounded binary search pads with valid untagged hourly rows. Three
    // bounded display labels fill the final sub-bucket byte gap exactly.
    let (mut low, mut high) = (1usize, 5_000usize - clean.usage_buckets.len());
    while low < high {
        let middle = (low + high).div_ceil(2);
        if identity::item_bytes(&with_fillers(middle)) <= target {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let mut padded = with_fillers(low);
    let mut gap = target - identity::item_bytes(&padded);
    for label in [
        &mut padded.session_display_name,
        &mut padded.workspace_display_label,
        &mut padded.repository_label,
    ] {
        let take = gap.min(254);
        label.as_mut().unwrap().push_str(&"x".repeat(take));
        gap -= take;
    }
    assert_eq!(gap, 0);
    assert_eq!(identity::item_bytes(&padded), target);
    let filler_proof = padded
        .usage_buckets
        .iter()
        .skip(clean.usage_buckets.len())
        .map(|bucket| Contribution {
            bucket_start: bucket.bucket_start.clone(),
            row_key: row_key_from_model_usage(&filler),
            usage: holder_usage(&filler, None),
            identity: RequestIdentity::Missing,
        })
        .collect();
    (padded, filler_proof)
}

fn sticky_assert_collective_byte_pair(newer_bad: bool, refusal_gap: bool) {
    let bad_hour = if newer_bad {
        "2026-09-01T12:00:00Z"
    } else {
        "2026-09-01T09:00:00Z"
    };
    let mut requests = vec![
        display_request(Some("max"), HOUR_10, 1, login_key(OWNER_A), Some(HOUR_10)),
        display_request(Some("max"), HOUR_11, 1, login_key(OWNER_A), Some(HOUR_11)),
        display_request(
            Some("pro"),
            bad_hour,
            1,
            if newer_bad {
                login_org('a', Some('c'), identity::TELEMETRY)
            } else {
                login_key(OWNER_A)
            },
            Some(bad_hour),
        ),
        display_request(
            Some(if newer_bad { "team" } else { "pro" }),
            bad_hour,
            1,
            if newer_bad {
                login_org('d', Some('e'), identity::TELEMETRY)
            } else {
                login_key(D64)
            },
            Some(bad_hour),
        ),
    ];
    if refusal_gap {
        requests.truncate(2);
        for (plan, org) in [("pro", 'c'), ("team", 'e'), ("enterprise", 'f')] {
            requests.push(display_request(
                Some(plan),
                bad_hour,
                1,
                RequestIdentity::Tagged(AuthorityKey {
                    login: None,
                    org: Some(org.to_string().repeat(64)),
                    basis: identity::TRANSCRIPT_ORG,
                }),
                Some(bad_hour),
            ));
        }
    }
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T12:05:00Z".into();
    item.input_tokens = requests.len() as u64;
    item.request_count = requests.len() as u64;
    item.output_tokens = 0;
    item.cache_read_tokens = 0;
    item.cache_creation_5m_tokens = 0;
    item.cache_creation_1h_tokens = 0;
    item.reasoning_output_tokens = 0;
    item.unattributed_total_tokens = 0;
    item.cost = None;
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    let mut clean = stripped(&item);
    clean.provenance.collector = identity::COLLECTOR.into();
    let base = identity::item_bytes(&clean);
    let bad_rows = if refusal_gap {
        3
    } else if newer_bad {
        2
    } else {
        1
    };
    let extra = |kept: usize| {
        let mut candidate = clean.clone();
        let mut shares = proof.clone();
        for share in shares.iter_mut().skip(kept) {
            share.identity = RequestIdentity::Missing;
        }
        sticky_apply(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::for_test(),
        )
        .unwrap();
        candidate.request_identity_refusals = bad_rows + u64::from(kept == 1);
        identity::item_bytes(&candidate) - base
    };
    let pair_extra = extra(2);
    let single_extra = extra(1);
    assert!(
        pair_extra < single_extra,
        "the complete top row collapses to Single"
    );
    let headroom = if refusal_gap {
        let mut candidate = clean.clone();
        let mut latest = proof.clone();
        for c in latest.iter_mut().take(2) {
            c.identity = RequestIdentity::Missing;
        }
        sticky_apply(
            &mut candidate,
            &latest,
            &identity::AcceptedBuckets::for_test(),
        )
        .unwrap();
        let no_refusal_extra = identity::item_bytes(&candidate) - base;
        candidate.request_identity_refusals = 2;
        let refused_extra = identity::item_bytes(&candidate) - base;
        assert!(pair_extra < no_refusal_extra + 1);
        assert!(no_refusal_extra + 1 < single_extra);
        assert!(no_refusal_extra + 1 < refused_extra);
        no_refusal_extra + 1
    } else {
        (pair_extra + single_extra) / 2
    };
    let target = identity::MAX_ITEM_BYTES - headroom;
    let (mut padded, filler_proof) = sticky_pad_to_bytes(&clean, target);
    assert!(target + pair_extra <= identity::MAX_ITEM_BYTES);
    assert!(target + single_extra > identity::MAX_ITEM_BYTES);
    proof.extend(filler_proof);
    sticky_apply(&mut padded, &proof, &accepted).unwrap();
    let bad_index = if newer_bad { 2 } else { 0 };
    for (index, bucket) in padded.usage_buckets.iter().take(3).enumerate() {
        assert!(bucket
            .model_usage
            .iter()
            .all(|row| sticky_tagged(row) == (index != bad_index)));
    }
    assert_eq!(padded.request_identity_refusals, bad_rows);
    sticky_assert_reconciled(&padded);
}

#[test]
fn sticky_byte_cap_keeps_joint_accepted_pair_when_an_older_bucket_cannot_fit() {
    sticky_assert_collective_byte_pair(false, false);
}
#[test]
fn sticky_byte_cap_keeps_joint_accepted_pair_when_open_bucket_metadata_cannot_fit() {
    sticky_assert_collective_byte_pair(true, false);
}

#[test]
fn sticky_byte_cap_charges_unavoidable_refusal_metadata_before_open_priority() {
    sticky_assert_collective_byte_pair(true, true);
}

#[test]
fn sticky_already_refused_rows_cannot_inflate_the_bound_and_evict_a_fitting_open_bucket() {
    let mut requests = Vec::new();
    // Nine rows already carry a refusal and a proved share. Removing their
    // tags must not turn nine mandatory refusals into a fictitious tenth.
    for at in [
        "2026-09-01T00:00:00Z",
        "2026-09-01T01:00:00Z",
        "2026-09-01T02:00:00Z",
        "2026-09-01T03:00:00Z",
        "2026-09-01T04:00:00Z",
        "2026-09-01T05:00:00Z",
        "2026-09-01T06:00:00Z",
        "2026-09-01T07:00:00Z",
        "2026-09-01T08:00:00Z",
    ] {
        requests.push(display_request(
            Some("pro"),
            at,
            1,
            login_key(OWNER_A),
            Some(at),
        ));
        requests.push(display_request(
            Some("pro"),
            at,
            1,
            RequestIdentity::Refused(Refusal::Pending),
            Some(at),
        ));
    }
    requests.push(display_request(
        Some("max"),
        HOUR_10,
        1,
        login_key(D64),
        Some(HOUR_10),
    ));
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T10:05:00Z".into();
    item.input_tokens = 19;
    item.request_count = 19;
    item.output_tokens = 0;
    item.cache_read_tokens = 0;
    item.cache_creation_5m_tokens = 0;
    item.cache_creation_1h_tokens = 0;
    item.reasoning_output_tokens = 0;
    item.unattributed_total_tokens = 0;
    item.cost = None;
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    let mut clean = stripped(&item);
    clean.provenance.collector = identity::COLLECTOR.into();
    let mut open_only = clean.clone();
    let mut open_proof = proof.clone();
    for c in open_proof.iter_mut().take(18) {
        if matches!(c.identity, RequestIdentity::Tagged(_)) {
            c.identity = RequestIdentity::Missing;
        }
    }
    sticky_apply(
        &mut open_only,
        &open_proof,
        &identity::AcceptedBuckets::for_test(),
    )
    .unwrap();
    assert_eq!(open_only.request_identity_refusals, 9);
    let extra = identity::item_bytes(&open_only) - identity::item_bytes(&clean);
    let (mut padded, filler_proof) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - extra);
    proof.extend(filler_proof);
    sticky_apply(&mut padded, &proof, &accepted).unwrap();
    assert!(sticky_tagged(&padded.usage_buckets[9].model_usage[0]));
    assert!(padded.usage_buckets[..9]
        .iter()
        .all(|bucket| !sticky_tagged(&bucket.model_usage[0])));
    assert_eq!(padded.request_identity_refusals, 9);
    assert_eq!(identity::item_bytes(&padded), identity::MAX_ITEM_BYTES);
    sticky_assert_reconciled(&padded);
}

#[test]
fn sticky_unreconcilable_newer_accepted_money_does_not_erase_an_older_joint_pair() {
    let requests = [
        display_request(Some("max"), HOUR_10, 1, login_key(OWNER_A), Some(HOUR_10)),
        display_request(Some("max"), HOUR_11, 1, login_key(OWNER_A), Some(HOUR_11)),
        display_request(
            Some("pro"),
            "2026-09-01T12:00:00Z",
            1,
            login_key(D64),
            Some("2026-09-01T12:00:00Z"),
        ),
    ];
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T12:05:00Z".into();
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    for index in [0, 2] {
        item.usage_buckets[index].model_usage[0].cost_usd = Some("0.000001".into());
        proof[index].usage.costs = UsageCosts {
            observed: true,
            reported: true,
            total: Some(1_000_000),
            ..Default::default()
        };
    }
    proof[1].usage.costs = UsageCosts {
        observed: true,
        reported: false,
        ..Default::default()
    };
    item.model_usage
        .iter_mut()
        .find(|row| row.subscription_product.as_deref() == Some("pro"))
        .unwrap()
        .cost_usd = Some("0.000001".into());
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    sticky_assert_reconciled(&item);
    accepted.record(&serde_json::to_value(&item).unwrap());
    // A new unpriced, untagged pro row cannot poison D64's own known share.
    let mut unpriced = item.usage_buckets[2].clone();
    unpriced.bucket_start = "2026-09-01T09:00:00Z".into();
    let row = &mut unpriced.model_usage[0];
    row.account_identifier_hash = None;
    row.evidence_ref = None;
    row.identity_parts = None;
    row.cost_usd = None;
    let mut usage = proof[2].usage.clone();
    usage.costs = UsageCosts {
        observed: true,
        reported: false,
        ..Default::default()
    };
    proof.push(Contribution {
        bucket_start: unpriced.bucket_start.clone(),
        row_key: row_key_from_model_usage(row),
        usage,
        identity: RequestIdentity::Missing,
    });
    item.usage_buckets.push(unpriced);
    let pro = item
        .model_usage
        .iter_mut()
        .find(|row| row.subscription_product.as_deref() == Some("pro"))
        .unwrap();
    pro.input_tokens += 1;
    pro.request_count += 1;
    sticky_receiver_totals(&mut item);
    let mut clean = stripped(&item);
    clean.provenance.collector = identity::COLLECTOR.into();
    let mut pair = clean.clone();
    let mut pair_proof = proof.clone();
    pair_proof[2].identity = RequestIdentity::Missing;
    sticky_apply(
        &mut pair,
        &pair_proof,
        &identity::AcceptedBuckets::for_test(),
    )
    .unwrap();
    pair.request_identity_refusals = 1;
    sticky_assert_reconciled(&pair);
    let extra = identity::item_bytes(&pair) - identity::item_bytes(&clean);
    let (mut padded, filler_proof) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - extra);
    proof.extend(filler_proof);
    sticky_apply(&mut padded, &proof, &accepted).unwrap();
    assert!(sticky_tagged(&padded.usage_buckets[0].model_usage[0]));
    assert!(sticky_tagged(&padded.usage_buckets[1].model_usage[0]));
    assert!(!sticky_tagged(&padded.usage_buckets[2].model_usage[0]));
    assert_eq!(padded.request_identity_refusals, 1);
    sticky_assert_reconciled(&padded);
}

fn sticky_assert_money_companions_survive_eviction(reported_current: bool) {
    let requests = [
        display_request(Some("max"), HOUR_10, 1, login_key(OWNER_A), Some(HOUR_10)),
        display_request(Some("pro"), HOUR_11, 1, login_key(D64), Some(HOUR_11)),
        display_request(
            Some("max"),
            "2026-09-01T12:00:00Z",
            1,
            login_key(OWNER_A),
            Some("2026-09-01T12:00:00Z"),
        ),
    ];
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T12:05:00Z".into();
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    if reported_current {
        item.usage_buckets[2].model_usage[0].cost_usd = Some("0.000001".into());
        proof[2].usage.costs = UsageCosts {
            observed: true,
            reported: true,
            total: Some(1_000_000),
            ..Default::default()
        };
        proof[0].usage.costs = UsageCosts {
            observed: true,
            reported: false,
            ..Default::default()
        };
    }
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    let mut clean = stripped(&item);
    clean.provenance.collector = identity::COLLECTOR.into();
    let extra = |pair: bool| {
        let mut candidate = clean.clone();
        let mut shares = proof.clone();
        for (index, share) in shares.iter_mut().enumerate() {
            if (index == 1) == pair {
                share.identity = RequestIdentity::Missing;
            }
        }
        sticky_apply(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::for_test(),
        )
        .unwrap();
        candidate.request_identity_refusals = if pair { 1 } else { 2 };
        identity::item_bytes(&candidate) - identity::item_bytes(&clean)
    };
    let headroom = extra(true).max(extra(false)) + 1;
    assert!(identity::item_bytes(&item) - identity::item_bytes(&clean) > headroom);
    let (mut padded, filler_proof) =
        sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - headroom);
    proof.extend(filler_proof);
    sticky_apply(&mut padded, &proof, &accepted).unwrap();
    assert!(sticky_tagged(&padded.usage_buckets[0].model_usage[0]));
    assert!(!sticky_tagged(&padded.usage_buckets[1].model_usage[0]));
    assert!(sticky_tagged(&padded.usage_buckets[2].model_usage[0]));
    assert_eq!(padded.request_identity_refusals, 1);
    sticky_assert_reconciled(&padded);
}
#[test]
fn sticky_protected_current_money_keeps_its_old_unpriced_companion_over_a_middle_bucket() {
    sticky_assert_money_companions_survive_eviction(true);
}
#[test]
fn sticky_re_admission_completes_top_rows_atomically_when_single_buckets_cannot_fit() {
    sticky_assert_money_companions_survive_eviction(false);
}

#[test]
fn sticky_cache_retractions_are_budgeted_before_retaining_identity_parts() {
    let (mut item, mut proof) = sticky_session(24);
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    item.cache_observations = Some(cache_observations::CacheObservations {
        schema_version: 1,
        operations: vec![],
        coverage: "complete".into(),
        omitted_observation_count: Some(0),
    });
    let cache_fixture = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let observation = cache_fixture.cache_observations_state.unwrap()["observations"][0].clone();
    let prior = json!({"observations":(0..32).map(|n| {
        let mut row = observation.clone();
        row["event_id"] = json!(format!("cache:{n:064x}"));
        row
    }).collect::<Vec<_>>()});
    let accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    let clean = stripped(&item);
    let overhead = identity::item_bytes(&item) - identity::item_bytes(&clean);
    let (mut padded, filler) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - overhead);
    proof.extend(filler);
    let mut unreserved = padded.clone();
    sticky_apply(&mut unreserved, &proof, &accepted).unwrap();
    assert_eq!(identity::item_bytes(&unreserved), identity::MAX_ITEM_BYTES);
    prepare_cache_observations(&mut unreserved, Some(&prior));
    assert_eq!(
        unreserved
            .cache_observations
            .as_ref()
            .unwrap()
            .operations
            .len(),
        32,
        "reconciled patch: {:?}",
        unreserved.cache_observations
    );
    assert!(identity::item_bytes(&unreserved) > identity::MAX_ITEM_BYTES);

    let mut projected = padded.clone();
    prepare_cache_observations(&mut projected, Some(&prior));
    let reserved = identity::item_bytes(&projected) - identity::item_bytes(&padded);
    identity::apply_with_reserved_bytes_for_test(&mut padded, &proof, &accepted, reserved).unwrap();
    assert!(sticky_tagged(&padded.usage_buckets[23].model_usage[0]));
    let refused = padded.usage_buckets[..24]
        .iter()
        .filter(|bucket| !sticky_tagged(&bucket.model_usage[0]))
        .count();
    assert!(refused > 0);
    assert_eq!(padded.request_identity_refusals, refused as u64);
    prepare_cache_observations(&mut padded, Some(&prior));
    assert_eq!(
        padded.cache_observations.as_ref().unwrap().operations.len(),
        32
    );
    sticky_assert_reconciled(&padded);
}

#[test]
fn sticky_current_bucket_tries_a_smaller_alternative_money_witness() {
    let mut requests = vec![
        display_request(Some("max"), HOUR_10, 1, login_key(OWNER_A), Some(HOUR_10)),
        display_request(Some("max"), HOUR_11, 1, login_key(OWNER_A), Some(HOUR_11)),
        display_request(
            Some("max"),
            "2026-09-01T12:00:00Z",
            1,
            login_key(OWNER_A),
            Some("2026-09-01T12:00:00Z"),
        ),
        display_request(
            Some("max"),
            "2026-09-01T09:00:00Z",
            1,
            RequestIdentity::Missing,
            None,
        ),
    ];
    for plan in ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"] {
        requests.push(display_request(
            Some(plan),
            HOUR_11,
            1,
            login_key(D64),
            Some(HOUR_11),
        ));
    }
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T12:05:00Z".into();
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    for share in &mut proof {
        share.usage.costs = UsageCosts {
            observed: true,
            reported: false,
            ..Default::default()
        };
    }
    item.usage_buckets[3].model_usage[0].cost_usd = Some("0.000001".into());
    proof[2].usage.costs = UsageCosts {
        observed: true,
        reported: true,
        total: Some(1_000_000),
        ..Default::default()
    };
    // The untagged 09:00 share is priced too. Otherwise the final "max" top
    // row's untagged part would lack the cost its row carries, which the
    // receiver rejects and the allocator now sends untagged.
    item.usage_buckets[0].model_usage[0].cost_usd = Some("0.000001".into());
    proof[3].usage.costs = proof[2].usage.costs.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    let clean = stripped(&item);
    let extra = |small_witness: bool| {
        let mut candidate = clean.clone();
        let mut shares = proof.clone();
        for share in &mut shares {
            if (share.bucket_start == HOUR_11 && small_witness)
                || (share.bucket_start == HOUR_10 && !small_witness)
            {
                share.identity = RequestIdentity::Missing;
            }
        }
        sticky_apply(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::for_test(),
        )
        .unwrap();
        candidate.request_identity_refusals = if small_witness { 9 } else { 1 };
        sticky_assert_reconciled(&candidate);
        identity::item_bytes(&candidate) - identity::item_bytes(&clean)
    };
    let headroom = extra(true);
    assert!(extra(false) > headroom);
    let (mut padded, filler) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - headroom);
    proof.extend(filler);
    sticky_apply(&mut padded, &proof, &accepted).unwrap();
    assert!(
        sticky_tagged(&padded.usage_buckets[1].model_usage[0]),
        "small old witness"
    );
    assert!(padded.usage_buckets[2]
        .model_usage
        .iter()
        .all(|row| !sticky_tagged(row)));
    assert!(
        sticky_tagged(&padded.usage_buckets[3].model_usage[0]),
        "protected current hour"
    );
    assert_eq!(padded.request_identity_refusals, 9);
    sticky_assert_reconciled(&padded);
}

#[test]
fn sticky_current_bucket_completes_one_shared_row_before_their_union() {
    const CURRENT: &str = "2026-09-01T12:00:00Z";
    let mut requests = vec![
        display_request(Some("max"), HOUR_10, 1, login_key(OWNER_A), Some(HOUR_10)),
        display_request(Some("pro"), HOUR_11, 1, login_key(D64), Some(HOUR_11)),
        display_request(Some("max"), CURRENT, 1, login_key(OWNER_A), Some(CURRENT)),
        display_request(
            Some("shared"),
            CURRENT,
            1,
            login_key(OWNER_A),
            Some(CURRENT),
        ),
    ];
    let (mut first, timed) = display_item(&requests);
    let proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&first).unwrap());
    for at in [
        "2026-09-01T00:00:00Z",
        "2026-09-01T01:00:00Z",
        "2026-09-01T02:00:00Z",
        "2026-09-01T03:00:00Z",
        "2026-09-01T04:00:00Z",
        "2026-09-01T05:00:00Z",
        "2026-09-01T06:00:00Z",
        "2026-09-01T07:00:00Z",
    ] {
        requests.push(display_request(
            Some("shared"),
            at,
            1,
            login_key(OWNER_A),
            Some(at),
        ));
    }
    let (mut item, timed) = display_item(&requests);
    item.collected_at = "2026-09-01T12:05:00Z".into();
    item.session_display_name = Some("x".into());
    item.workspace_display_label = Some("x".into());
    item.repository_label = Some("x".into());
    let mut proof = timed.into_iter().map(|(c, _)| c).collect::<Vec<_>>();
    let clean = stripped(&item);
    // X completion is current + hour 10. The union also pulls eight new Y
    // buckets, whose extra tags exceed the room freed by completing X.
    let extra = |mode: u8| {
        let mut candidate = clean.clone();
        let mut shares = proof.clone();
        let mut refused = 0;
        for share in &mut shares {
            let keep = share.bucket_start == CURRENT
                || (mode != 0 && share.bucket_start == HOUR_10)
                || (mode == 2 && share.bucket_start != HOUR_11);
            if !keep {
                share.identity = RequestIdentity::Missing;
                refused += 1;
            }
        }
        sticky_apply(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::for_test(),
        )
        .unwrap();
        candidate.request_identity_refusals = refused;
        sticky_assert_reconciled(&candidate);
        identity::item_bytes(&candidate) - identity::item_bytes(&clean)
    };
    let headroom = extra(1);
    assert!(extra(0) > headroom, "current alone cannot fit");
    assert!(extra(2) > headroom, "union unnecessarily adds Y buckets");
    let (mut padded, filler) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - headroom);
    proof.extend(filler);
    sticky_apply(&mut padded, &proof, &accepted).unwrap();
    assert!(padded.usage_buckets[..8]
        .iter()
        .all(|bucket| !sticky_tagged(&bucket.model_usage[0])));
    assert!(sticky_tagged(&padded.usage_buckets[8].model_usage[0]));
    assert!(!sticky_tagged(&padded.usage_buckets[9].model_usage[0]));
    assert!(padded.usage_buckets[10]
        .model_usage
        .iter()
        .all(sticky_tagged));
    assert_eq!(padded.request_identity_refusals, 9);
    sticky_assert_reconciled(&padded);
}

#[test]
fn sticky_accepted_share_retag_and_missing_sibling_are_refused_after_restart() {
    let (original, proof) = sticky_session(1);
    let mut first = original.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&first).unwrap());
    let accepted: identity::AcceptedBuckets =
        identity::AcceptedBuckets::restore_for_test(&serde_json::to_vec(&accepted).unwrap());
    for retag in [false, true] {
        let mut next = original.clone();
        let mut changed = proof.clone();
        changed[1].identity = if retag {
            login_key(D64)
        } else {
            RequestIdentity::Missing
        };
        identity::take_identity_counts();
        sticky_apply(&mut next, &changed, &accepted).unwrap();
        assert_eq!(next.request_identity_refusals, 1);
        let parts = next.usage_buckets[0].model_usage[0]
            .identity_parts
            .as_ref()
            .unwrap();
        assert_eq!(
            parts
                .iter()
                .filter(|part| part.evidence_ref.is_some())
                .count(),
            2
        );
        assert_eq!(
            parts
                .iter()
                .find(|part| part.evidence_ref.is_none())
                .unwrap()
                .request_count,
            1
        );
        assert!(parts
            .iter()
            .all(|part| part.account_identifier_hash.as_deref() != Some(D64)));
        let counts =
            serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
        assert_eq!(counts["accepted_share_changed"], 1);
        assert_eq!(counts["retained_buckets"], 0);
        sticky_assert_reconciled(&next);
        let mut repeat = original.clone();
        sticky_apply(&mut repeat, &changed, &accepted).unwrap();
        assert_eq!(repeat.snapshot_fingerprint, next.snapshot_fingerprint);
        assert_eq!(
            serde_json::to_value(&repeat).unwrap(),
            serde_json::to_value(&next).unwrap()
        );
    }
    let mut unchanged = original.clone();
    identity::take_identity_counts();
    sticky_apply(&mut unchanged, &proof, &accepted).unwrap();
    assert_eq!(unchanged.request_identity_refusals, 0);
    let counts =
        serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
    assert_eq!(counts["accepted_share_changed"], 0);
    assert_eq!(counts["retained_buckets"], 1);
}

#[test]
fn sticky_new_untagged_presence_does_not_bless_a_later_missing_share() {
    let (original, proof) = sticky_session(1);
    let mut first = original.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&first).unwrap());
    let mut changed = proof.clone();
    changed[1].identity = RequestIdentity::Missing;
    let mut next = original.clone();
    sticky_apply(&mut next, &changed, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&next).unwrap());
    next.request_identity_refusals = 0;
    sticky_apply(&mut next, &changed, &accepted).unwrap();
    assert_eq!(next.request_identity_refusals, 1);
    sticky_assert_reconciled(&next);
}

fn sticky_price_fixture(item: &mut SnapshotItem, proof: &mut [Contribution]) {
    sticky_price_rows(item, proof, |hour, field| (hour + field) % 4 != 0);
}
fn sticky_price_rows(
    item: &mut SnapshotItem,
    proof: &mut [Contribution],
    priced: impl Fn(usize, usize) -> bool,
) {
    for (hour, bucket) in item.usage_buckets.iter_mut().enumerate() {
        let row = &mut bucket.model_usage[0];
        let money = std::array::from_fn::<_, 5, _>(|field| {
            priced(hour, field).then_some((field as u128 + 1) * 1_000_000)
        });
        for (slot, value) in [
            &mut row.cost_usd,
            &mut row.input_cost_usd,
            &mut row.output_cost_usd,
            &mut row.cache_read_cost_usd,
            &mut row.cache_creation_cost_usd,
        ]
        .into_iter()
        .zip(money)
        {
            *slot = value.map(|value| usd_picos_string(3 * value));
        }
        for c in &mut proof[hour * 3..hour * 3 + 3] {
            c.usage.costs = UsageCosts {
                observed: true,
                reported: true,
                total: money[0],
                input: money[1],
                output: money[2],
                cache_read: money[3],
                cache_creation: money[4],
            };
        }
    }
    sticky_receiver_totals(item);
}
fn sticky_wire(item: SnapshotItem) -> Value {
    let mut request = valid_v6_batch_request();
    request.source = "claude_code".into();
    request.upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };
    request.snapshots = vec![item];
    serde_json::to_value(request).unwrap()
}
/// #909's emitted cases. `seed` may pre-load ledger state into every
/// accepted set (option (ii) gate-off proof: it must not change a byte).
fn sticky_golden_cases(seed: &dyn Fn(&mut identity::AcceptedBuckets)) -> Value {
    let fresh = || {
        let mut state = identity::AcceptedBuckets::for_test();
        seed(&mut state);
        state
    };
    let mut cases = BTreeMap::new();
    let (mut mixed, mut proof) = sticky_session(4);
    sticky_price_fixture(&mut mixed, &mut proof);
    // All eight counters, and independent presence of all five cost fields.
    for c in &mut proof {
        c.usage.output_tokens = 8;
        c.usage.cache_read_tokens = 3;
        c.usage.cache_creation_5m_tokens = 4;
        c.usage.cache_creation_1h_tokens = 5;
        c.usage.reasoning_output_tokens = 6;
        c.usage.unattributed_total_tokens = 7;
    }
    for bucket in &mut mixed.usage_buckets {
        let row = &mut bucket.model_usage[0];
        row.output_tokens = 24;
        row.cache_read_tokens = 9;
        row.cache_creation_5m_tokens = 12;
        row.cache_creation_1h_tokens = 15;
        row.reasoning_output_tokens = 18;
        row.unattributed_total_tokens = 21;
    }
    let row = &mut mixed.model_usage[0];
    row.output_tokens = 96;
    row.cache_read_tokens = 36;
    row.cache_creation_5m_tokens = 48;
    row.cache_creation_1h_tokens = 60;
    row.reasoning_output_tokens = 72;
    row.unattributed_total_tokens = 84;
    sticky_apply(&mut mixed, &proof, &fresh()).unwrap();
    sticky_assert_reconciled(&mixed);
    cases.insert("mixed_presence", sticky_wire(mixed));

    let (mut window, mut proof) = sticky_session(576);
    sticky_price_fixture(&mut window, &mut proof);
    sticky_apply(&mut window, &proof, &fresh()).unwrap();
    assert!(window.request_identity_refusals > 0);
    assert!(sticky_tagged(&window.usage_buckets[575].model_usage[0]));
    sticky_assert_reconciled(&window);
    cases.insert("window", sticky_wire(window));

    let (mut original, mut original_proof) = sticky_session(24);
    original.session_display_name = Some("x".into());
    original.workspace_display_label = Some("x".into());
    original.repository_label = Some("x".into());
    original.session_display_name_source = Some("session_index".into());
    original.workspace_label_source = Some("user_approved".into());
    original.repository_label_source = Some("user_approved".into());
    sticky_price_fixture(&mut original, &mut original_proof);
    let mut tagged = original.clone();
    let mut accepted = fresh();
    sticky_apply(&mut tagged, &original_proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&tagged).unwrap());
    let clean = stripped(&tagged);
    let overhead = identity::item_bytes(&tagged) - identity::item_bytes(&clean);
    let (mut overflow, filler) =
        sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - overhead / 2);
    let mut proof = original_proof.clone();
    proof.extend(filler);
    sticky_apply(&mut overflow, &proof, &accepted).unwrap();
    assert!(overflow.request_identity_refusals > 0);
    sticky_assert_reconciled(&overflow);
    accepted.record(&serde_json::to_value(&overflow).unwrap());
    cases.insert("accepted_overflow", sticky_wire(overflow));
    let accepted: identity::AcceptedBuckets =
        identity::AcceptedBuckets::restore_for_test(&serde_json::to_vec(&accepted).unwrap());
    sticky_apply(&mut original, &original_proof, &accepted).unwrap();
    assert_eq!(original.request_identity_refusals, 0);
    sticky_assert_reconciled(&original);
    cases.insert("restore_from_held_proof", sticky_wire(original));
    let (mut changed, mut proof) = sticky_session(4);
    sticky_price_fixture(&mut changed, &mut proof);
    let mut first = changed.clone();
    let mut accepted = fresh();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(first).unwrap());
    // Complementary cost presence makes every top-level untagged cost known.
    // A single absent-only untagged cost cannot form a receiver-valid Parts row.
    proof[1].identity = login_key(D64);
    proof[4].identity = login_key(D64);
    sticky_apply(&mut changed, &proof, &accepted).unwrap();
    assert_eq!(changed.request_identity_refusals, 2);
    assert!(changed.usage_buckets[0].model_usage[0]
        .identity_parts
        .as_ref()
        .unwrap()
        .iter()
        .any(|part| part.evidence_ref.is_none()));
    sticky_assert_reconciled(&changed);
    cases.insert("accepted_share_changed", sticky_wire(changed));
    // The original single-changed-bucket shape the receiver rejected: the
    // untagged share's only bucket lacks costs its priced top row carries.
    let (mut unpriced, proof) = sticky_unpriced_share_shape(false);
    let accepted = sticky_unpriced_share_ledger(&unpriced);
    assert_eq!(
        sticky_apply(&mut unpriced, &proof, &accepted).unwrap(),
        Tagged::Sent { refusals: 4 }
    );
    assert!(unpriced.request_evidence.is_empty());
    assert!(!sticky_any_tagged(&unpriced));
    sticky_assert_reconciled(&unpriced);
    cases.insert("unpriced_part_untagged", sticky_wire(unpriced));
    // Reported zero is known money: the same retag with hour 0's costs
    // reported as zero keeps its parts, the untagged share carrying "0".
    let (mut zero, mut proof) = sticky_session(4);
    sticky_price_fixture(&mut zero, &mut proof);
    let row = &mut zero.usage_buckets[0].model_usage[0];
    row.cost_usd = Some("0".into());
    row.cache_creation_cost_usd = Some("0".into());
    for c in &mut proof[..3] {
        c.usage.costs.total = Some(0);
        c.usage.costs.cache_creation = Some(0);
    }
    let mut first = zero.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(first).unwrap());
    proof[1].identity = login_key(D64);
    assert_eq!(
        sticky_apply(&mut zero, &proof, &accepted).unwrap(),
        Tagged::Sent { refusals: 1 }
    );
    let untagged = zero.model_usage[0]
        .identity_parts
        .as_ref()
        .unwrap()
        .iter()
        .find(|part| part.evidence_ref.is_none())
        .unwrap();
    assert_eq!(untagged.cost_usd.as_deref(), Some("0"));
    assert_eq!(untagged.cache_creation_cost_usd.as_deref(), Some("0"));
    sticky_assert_reconciled(&zero);
    cases.insert("zero_priced_part_kept", sticky_wire(zero));
    serde_json::to_value(cases).unwrap()
}
#[test]
fn sticky_emitted_wire_goldens_match_receiver_contract_cases() {
    use base64::Engine;
    use sha2::Digest;
    use std::io::Write;
    let actual = sticky_golden_cases(&|_| {});
    let fixture = include_str!("fixtures/claude_identity_cap_emitted.json");
    let expected: Value = serde_json::from_str(fixture).unwrap();
    for case in [
        "mixed_presence",
        "window",
        "accepted_overflow",
        "restore_from_held_proof",
        "accepted_share_changed",
    ] {
        assert_eq!(
            actual[case], expected[case],
            "existing golden changed: {case}; STOP and report"
        );
    }
    if actual != expected {
        // Bootstrap/update on Linux CI only. The compact compressed receipt
        // is lossless; committing it never requires running tests on the Mac.
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&serde_json::to_vec(&actual).unwrap())
            .unwrap();
        eprintln!(
            "E2_IDENTITY_GOLDEN_GZIP_BASE64={}",
            base64::engine::general_purpose::STANDARD.encode(gzip.finish().unwrap())
        );
        panic!("emitted identity goldens changed; regenerate from the CI receipt");
    }
    let manifest: Value = serde_json::from_str(include_str!(
        "fixtures/claude_identity_cap_emitted.manifest.json"
    ))
    .unwrap();
    assert_eq!(
        manifest["sha256"],
        format!("{:x}", sha2::Sha256::digest(fixture.as_bytes()))
    );
}

#[test]
fn sticky_rotated_or_unavailable_key_counts_unknown_without_share_changed_refusals() {
    let (original, proof) = sticky_session(1);
    let mut first = original.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&first).unwrap());
    let bytes = serde_json::to_vec(&accepted).unwrap();
    for key in [None, Some([0x43; 32])] {
        let mut restored: identity::AcceptedBuckets = serde_json::from_slice(&bytes).unwrap();
        restored.bind_test_key(key);
        let mut next = original.clone();
        let mut changed = proof.clone();
        changed[1].identity = login_key(D64);
        identity::take_identity_counts();
        sticky_apply(&mut next, &changed, &restored).unwrap();
        let counts = serde_json::to_value(identity::take_identity_counts()).unwrap();
        assert_eq!(counts["identity_cap"]["accepted_state_unknown"], 1);
        assert_eq!(counts["identity_cap"]["accepted_share_changed"], 0);
        assert_eq!(next.request_identity_refusals, 0);
        sticky_assert_reconciled(&next);
    }
}

#[test]
fn sticky_new_model_and_previously_untagged_rows_gain_proof_without_retaging_refusals() {
    for previously_present in [false, true] {
        let (mut original, proof) = sticky_session(1);
        let mut added_row = original.usage_buckets[0].model_usage[0].clone();
        added_row.model = "claude-new-model".into();
        let mut added_proof = proof.clone();
        for c in &mut added_proof {
            c.row_key.model = added_row.model.clone();
        }
        let mut first = original.clone();
        let mut first_proof = proof.clone();
        if previously_present {
            first.model_usage.push(added_row.clone());
            first.usage_buckets[0].model_usage.push(added_row.clone());
            let mut missing = added_proof.clone();
            for c in &mut missing {
                c.identity = RequestIdentity::Missing;
            }
            first_proof.extend(missing);
        }
        let mut accepted = identity::AcceptedBuckets::for_test();
        sticky_apply(&mut first, &first_proof, &accepted).unwrap();
        accepted.record(&serde_json::to_value(first).unwrap());
        original.model_usage.push(added_row.clone());
        original.usage_buckets[0].model_usage.push(added_row);
        let mut current_proof = proof.clone();
        current_proof.extend(added_proof);
        for _ in 0..2 {
            let mut current = original.clone();
            identity::take_identity_counts();
            sticky_apply(&mut current, &current_proof, &accepted).unwrap();
            assert_eq!(current.request_identity_refusals, 0);
            assert!(current.usage_buckets[0]
                .model_usage
                .iter()
                .all(sticky_tagged));
            let counts = serde_json::to_value(identity::take_identity_counts()).unwrap();
            assert_eq!(counts["identity_cap"]["accepted_share_changed"], 0);
            sticky_assert_reconciled(&current);
            accepted.record(&serde_json::to_value(current).unwrap());
        }
    }
}
#[test]
fn sticky_missing_presence_resolves_to_the_same_accepted_tagged_set_without_repeated_refusals() {
    let (original, mut proof) = sticky_session(1);
    proof[2].identity = RequestIdentity::Missing;
    let mut first = original.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(first).unwrap());
    proof[2].identity = proof[0].identity.clone();
    for _ in 0..2 {
        let mut current = original.clone();
        identity::take_identity_counts();
        sticky_apply(&mut current, &proof, &accepted).unwrap();
        assert_eq!(current.request_identity_refusals, 0);
        let parts = current.usage_buckets[0].model_usage[0]
            .identity_parts
            .as_ref()
            .unwrap();
        assert!(parts.iter().all(|part| part.evidence_ref.is_some()));
        let counts = serde_json::to_value(identity::take_identity_counts()).unwrap();
        assert_eq!(counts["identity_cap"]["accepted_share_changed"], 0);
        sticky_assert_reconciled(&current);
        accepted.record(&serde_json::to_value(current).unwrap());
    }
}

/// Receiver `_validate_identity_parts` presence: per cost field, a part has
/// it exactly when its row (top rollup or bucket row) has it.
fn sticky_assert_parts_priced(item: &SnapshotItem) {
    let costs = |values: [&Option<String>; 5]| values.map(Option::is_some);
    for row in item
        .model_usage
        .iter()
        .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
    {
        let row_costs = costs([
            &row.cost_usd,
            &row.input_cost_usd,
            &row.output_cost_usd,
            &row.cache_read_cost_usd,
            &row.cache_creation_cost_usd,
        ]);
        for part in row.identity_parts.iter().flatten() {
            assert_eq!(
                costs([
                    &part.cost_usd,
                    &part.input_cost_usd,
                    &part.output_cost_usd,
                    &part.cache_read_cost_usd,
                    &part.cache_creation_cost_usd,
                ]),
                row_costs,
                "identity part cost presence differs from its row: {}",
                row.model
            );
        }
    }
}

fn sticky_any_tagged(item: &SnapshotItem) -> bool {
    item.model_usage
        .iter()
        .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
        .any(sticky_tagged)
}

fn sticky_money(item: &SnapshotItem) -> Value {
    let today = stripped(item);
    serde_json::to_value((&today.model_usage, &today.usage_buckets, &today.cost)).unwrap()
}

/// Four priced hours; hour 0 lacks total and cache-creation cost. With
/// `second_model`, a fully priced second model row shares every bucket and
/// authority key. Proof index 1 is hour 0's second share of the first model.
fn sticky_unpriced_share_base(second_model: bool) -> (SnapshotItem, Vec<Contribution>) {
    let (mut item, mut proof) = sticky_session(4);
    sticky_price_fixture(&mut item, &mut proof);
    if second_model {
        let mut row = item.model_usage[0].clone();
        row.model = "claude-second-model".into();
        let key = row_key_from_model_usage(&row);
        let mut second = proof.clone();
        for c in &mut second {
            c.row_key = key.clone();
            c.usage.costs = UsageCosts {
                observed: true,
                reported: true,
                total: Some(1_000_000),
                input: Some(2_000_000),
                output: Some(3_000_000),
                cache_read: Some(4_000_000),
                cache_creation: Some(5_000_000),
            };
        }
        for bucket in &mut item.usage_buckets {
            let mut bucket_row = bucket.model_usage[0].clone();
            bucket_row.model = row.model.clone();
            for (field, slot) in [
                &mut bucket_row.cost_usd,
                &mut bucket_row.input_cost_usd,
                &mut bucket_row.output_cost_usd,
                &mut bucket_row.cache_read_cost_usd,
                &mut bucket_row.cache_creation_cost_usd,
            ]
            .into_iter()
            .enumerate()
            {
                *slot = Some(usd_picos_string(3 * (field as u128 + 1) * 1_000_000));
            }
            bucket.model_usage.push(bucket_row);
        }
        item.model_usage.push(row);
        proof.extend(second);
    }
    (item, proof)
}

/// The accepted ledger after the base body's stored-body ACK.
fn sticky_unpriced_share_ledger(item: &SnapshotItem) -> identity::AcceptedBuckets {
    let (_, proof) = sticky_unpriced_share_base(item.model_usage.len() > 1);
    let mut accepted = identity::AcceptedBuckets::for_test();
    let mut first = item.clone();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    assert!(sticky_any_tagged(&first));
    accepted.record(&serde_json::to_value(first).unwrap());
    accepted
}

/// The accepted base with hour 0's second share retagged to a new login.
fn sticky_unpriced_share_shape(second_model: bool) -> (SnapshotItem, Vec<Contribution>) {
    let (item, mut proof) = sticky_unpriced_share_base(second_model);
    proof[1].identity = login_key(D64);
    (item, proof)
}

#[test]
fn sticky_unpriced_share_strips_only_its_model_row_and_counts_accepted_differs() {
    let (original, proof) = sticky_unpriced_share_shape(true);
    let accepted = sticky_unpriced_share_ledger(&original);
    let (_, base_proof) = sticky_unpriced_share_base(true);
    let mut unchanged = original.clone();
    sticky_apply(&mut unchanged, &base_proof, &accepted).unwrap();
    assert!(sticky_tagged(&unchanged.model_usage[0]));
    let mut next = original.clone();
    identity::take_identity_counts();
    let result = sticky_apply(&mut next, &proof, &accepted).unwrap();
    // Hour 0 was already refused for its share change; hours 1-3 lose tags.
    assert_eq!(result, Tagged::Sent { refusals: 4 });
    assert_eq!(next.request_identity_refusals, 4);
    let counts =
        serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
    assert_eq!(counts["unpriced_part_untagged"], 1);
    assert_eq!(counts["accepted_overflow"]["differs"], 1);
    assert_eq!(counts["accepted_overflow"]["same_as_parent"], 0);
    assert_eq!(counts["accepted_share_changed"], 1);
    assert_eq!(counts["retained_buckets"], 3);
    assert_eq!(counts["accepted_state_unknown"], 0);
    // The violating model row is untagged at both grains.
    assert!(!sticky_tagged(&next.model_usage[0]));
    assert!(next
        .usage_buckets
        .iter()
        .all(|b| !sticky_tagged(&b.model_usage[0])));
    // The other model row and its evidence keep their exact bytes.
    assert_eq!(
        serde_json::to_value(&next.model_usage[1]).unwrap(),
        serde_json::to_value(&unchanged.model_usage[1]).unwrap()
    );
    for (bucket, before) in next.usage_buckets.iter().zip(&unchanged.usage_buckets) {
        assert!(sticky_tagged(&bucket.model_usage[1]));
        assert_eq!(
            serde_json::to_value(&bucket.model_usage[1]).unwrap(),
            serde_json::to_value(&before.model_usage[1]).unwrap()
        );
    }
    assert_eq!(
        serde_json::to_value(&next.request_evidence).unwrap(),
        serde_json::to_value(&unchanged.request_evidence).unwrap()
    );
    // Money is byte-equal to the untagged baseline.
    assert_eq!(sticky_money(&next), sticky_money(&unchanged));
    sticky_assert_reconciled(&next);
    let mut repeat = original.clone();
    sticky_apply(&mut repeat, &proof, &accepted).unwrap();
    assert_eq!(
        serde_json::to_value(&repeat).unwrap(),
        serde_json::to_value(&next).unwrap()
    );
}

#[test]
fn sticky_unpriced_missing_share_without_accepted_state_strips_without_differs() {
    let (mut item, mut proof) = sticky_unpriced_share_base(false);
    proof[1].identity = RequestIdentity::Missing;
    let mut baseline = item.clone();
    sticky_receiver_totals(&mut baseline);
    identity::take_identity_counts();
    let result = sticky_apply(&mut item, &proof, &identity::AcceptedBuckets::for_test()).unwrap();
    assert_eq!(result, Tagged::Sent { refusals: 4 });
    assert!(item.request_evidence.is_empty());
    assert!(!sticky_any_tagged(&item));
    assert_eq!(sticky_money(&item), sticky_money(&baseline));
    let counts =
        serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
    assert_eq!(counts["unpriced_part_untagged"], 1);
    assert_eq!(counts["accepted_overflow"]["differs"], 0);
    assert_eq!(counts["accepted_state_unknown"], 1);
    assert_eq!(
        counts["accepted_state_unknown_cause"]["untracked_session"],
        1
    );
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_unpriced_share_after_budget_selection_is_stripped_from_the_final_rows() {
    // Only the newest hour is priced. Every key is priced once all buckets
    // stay; a partial selection leaves an unpriced untagged remainder.
    let (mut item, mut proof) = sticky_session(24);
    for (hour, bucket) in item.usage_buckets.iter_mut().enumerate() {
        let reported = hour == 23;
        bucket.model_usage[0].cost_usd = reported.then(|| "0.000003".into());
        for c in &mut proof[hour * 3..hour * 3 + 3] {
            c.usage.costs = UsageCosts {
                observed: true,
                reported,
                total: reported.then_some(1_000_000),
                ..Default::default()
            };
        }
    }
    let ledger = identity::AcceptedBuckets::for_test();
    let mut full = item.clone();
    sticky_apply(&mut full, &proof, &ledger).unwrap();
    assert!(full
        .usage_buckets
        .iter()
        .all(|b| sticky_tagged(&b.model_usage[0])));
    let tagged_bytes = identity::item_bytes(&full);
    let clean_bytes = identity::item_bytes(&stripped(&full));
    let reserve = identity::MAX_ITEM_BYTES - clean_bytes - (tagged_bytes - clean_bytes) / 2;
    sticky_receiver_totals(&mut item);
    identity::take_identity_counts();
    let result =
        identity::apply_with_reserved_bytes_for_test(&mut item, &proof, &ledger, reserve).unwrap();
    assert_eq!(result, Tagged::Sent { refusals: 24 });
    assert!(item.request_evidence.is_empty());
    assert!(!sticky_any_tagged(&item));
    assert_eq!(sticky_money(&item), sticky_money(&full));
    let counts =
        serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
    assert_eq!(counts["unpriced_part_untagged"], 1);
    // Budget selection ran: it refused never-accepted buckets that did not fit.
    assert!(counts["refused_new_buckets"].as_u64().unwrap() > 0);
    sticky_assert_reconciled(&item);
}

#[test]
fn sticky_unknown_accepted_state_is_split_by_cause() {
    let (original, proof) = sticky_session(1);
    let unknown = |accepted: &identity::AcceptedBuckets| {
        let mut next = original.clone();
        identity::take_identity_counts();
        sticky_apply(&mut next, &proof, accepted).unwrap();
        sticky_assert_reconciled(&next);
        let counts =
            serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
        let causes = counts["accepted_state_unknown_cause"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, count)| count.as_u64() != Some(0))
            .map(|(cause, count)| (cause.clone(), count.as_u64().unwrap()))
            .collect::<Vec<_>>();
        (counts["accepted_state_unknown"].as_u64().unwrap(), causes)
    };
    let one = |cause: &str| (1, vec![(cause.to_owned(), 1)]);
    let mut accepted = identity::AcceptedBuckets::for_test();
    assert_eq!(unknown(&accepted), one("untracked_session"));
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&first).unwrap());
    assert_eq!(unknown(&accepted), (0, vec![]));
    let bytes = serde_json::to_vec(&accepted).unwrap();
    let mut hints: Value = serde_json::from_slice(&bytes).unwrap();
    for state in hints.as_object_mut().unwrap().values_mut() {
        state["incomplete"] = json!(true);
    }
    let incomplete =
        identity::AcceptedBuckets::restore_for_test(&serde_json::to_vec(&hints).unwrap());
    assert_eq!(unknown(&incomplete), one("incomplete"));
    let mut no_key: identity::AcceptedBuckets = serde_json::from_slice(&bytes).unwrap();
    no_key.bind_test_key(None);
    assert_eq!(unknown(&no_key), one("no_key"));
    let mut rotated: identity::AcceptedBuckets = serde_json::from_slice(&bytes).unwrap();
    rotated.bind_test_key(Some([0x43; 32]));
    assert_eq!(unknown(&rotated), one("epoch_changed"));
    // The next pass under the same rotated key has no hints for the session.
    rotated.bind_test_key(Some([0x43; 32]));
    assert_eq!(unknown(&rotated), one("untracked_session"));
}

#[test]
fn sticky_frozen_row_moved_to_a_new_row_key_counts_vanished_without_changing_the_body() {
    let (original, proof) = sticky_session(1);
    let mut first = original.clone();
    let mut accepted = identity::AcceptedBuckets::for_test();
    sticky_apply(&mut first, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(first).unwrap());
    let mut control = original.clone();
    identity::take_identity_counts();
    sticky_apply(&mut control, &proof, &accepted).unwrap();
    let counts =
        serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
    assert_eq!(counts["accepted_row_vanished"], 0);
    // Late effort resolution moves the accepted usage to a new row key.
    let mut moved = original.clone();
    for row in moved.model_usage.iter_mut().chain(
        moved
            .usage_buckets
            .iter_mut()
            .flat_map(|b| b.model_usage.iter_mut()),
    ) {
        row.reasoning_effort = Some("high".into());
    }
    let key = row_key_from_model_usage(&moved.model_usage[0]);
    let mut moved_proof = proof.clone();
    for c in &mut moved_proof {
        c.row_key = key.clone();
    }
    let mut unhinted = moved.clone();
    sticky_apply(
        &mut unhinted,
        &moved_proof,
        &identity::AcceptedBuckets::for_test(),
    )
    .unwrap();
    identity::take_identity_counts();
    sticky_apply(&mut moved, &moved_proof, &accepted).unwrap();
    let counts =
        serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
    assert_eq!(counts["accepted_row_vanished"], 1);
    assert_eq!(counts["accepted_share_changed"], 0);
    // Counts only: identity and money equal the body built without hints.
    assert_eq!(moved.request_identity_refusals, 0);
    assert!(sticky_tagged(&moved.usage_buckets[0].model_usage[0]));
    for (left, right) in [
        (
            serde_json::to_value(&moved.model_usage).unwrap(),
            serde_json::to_value(&unhinted.model_usage).unwrap(),
        ),
        (
            serde_json::to_value(&moved.usage_buckets).unwrap(),
            serde_json::to_value(&unhinted.usage_buckets).unwrap(),
        ),
        (
            serde_json::to_value(&moved.request_evidence).unwrap(),
            serde_json::to_value(&unhinted.request_evidence).unwrap(),
        ),
    ] {
        assert_eq!(left, right);
    }
    sticky_assert_reconciled(&moved);
}

#[test]
fn sticky_no_emitted_rollup_or_bucket_part_omits_a_cost_its_row_carries() {
    // C9: with share protection off (no key), without hints and with
    // hints, no top rollup or bucket row may carry a part lacking a cost its
    // row carries. Presence is absent, reported zero or positive per field.
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (mut stripped_cases, mut kept_parts_cases) = (0, 0);
    for case in 0..96 {
        let (mut item, mut proof) = sticky_session(4);
        let presence = next();
        for (hour, bucket) in item.usage_buckets.iter_mut().enumerate() {
            let money = std::array::from_fn::<_, 5, _>(|field| {
                match (presence >> ((hour * 5 + field) * 2)) & 3 {
                    0 => None,
                    1 => Some(0),
                    _ => Some((field as u128 + 1) * 1_000_000),
                }
            });
            let row = &mut bucket.model_usage[0];
            for (slot, value) in [
                &mut row.cost_usd,
                &mut row.input_cost_usd,
                &mut row.output_cost_usd,
                &mut row.cache_read_cost_usd,
                &mut row.cache_creation_cost_usd,
            ]
            .into_iter()
            .zip(money)
            {
                *slot = value.map(|value| usd_picos_string(3 * value));
            }
            for c in &mut proof[hour * 3..hour * 3 + 3] {
                c.usage.costs = UsageCosts {
                    observed: true,
                    reported: money.iter().any(Option::is_some),
                    total: money[0],
                    input: money[1],
                    output: money[2],
                    cache_read: money[3],
                    cache_creation: money[4],
                };
            }
        }
        let mut ledger = identity::AcceptedBuckets::for_test();
        match case % 3 {
            0 => ledger.bind_test_key(None),
            1 => {}
            _ => {
                let mut first = item.clone();
                sticky_apply(&mut first, &proof, &ledger).unwrap();
                ledger.record(&serde_json::to_value(first).unwrap());
            }
        }
        let mutation = next();
        if case % 8 != 0 {
            for (index, c) in proof.iter_mut().enumerate() {
                match (mutation >> (index * 3)) & 7 {
                    0 => c.identity = RequestIdentity::Missing,
                    1 => c.identity = login_key(D64),
                    _ => {}
                }
            }
        }
        let mut baseline = item.clone();
        sticky_receiver_totals(&mut baseline);
        identity::take_identity_counts();
        sticky_apply(&mut item, &proof, &ledger)
            .unwrap_or_else(|error| panic!("case {case}: {error:?}"));
        let counts =
            serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone();
        stripped_cases += usize::from(counts["unpriced_part_untagged"].as_u64() == Some(1));
        kept_parts_cases += usize::from(item.model_usage[0].identity_parts.is_some());
        sticky_assert_reconciled(&item);
        assert_eq!(sticky_money(&item), sticky_money(&baseline), "case {case}");
    }
    assert!(stripped_cases > 0 && kept_parts_cases > 0);
}

// Settled-history segments (`session_history_segments:v1`), on the sticky
// fixture with one account per day, so accounts change across windows.

/// Each bucket row's money placement (money-check placement fields, evidence
/// resolved through its own item's table), keyed by bucket and row; a row
/// carried by two pieces fails.
fn segment_placement(pieces: &[&SnapshotItem]) -> BTreeMap<(String, RowKey), Value> {
    let mut placement = BTreeMap::new();
    for item in pieces {
        let resolve = |reference: Option<u16>| {
            reference.map(|reference| {
                let evidence = &item.request_evidence[usize::from(reference)];
                json!([evidence.identity_basis, evidence.provider_workspace_hash])
            })
        };
        for bucket in &item.usage_buckets {
            for row in &bucket.model_usage {
                let parts = row.identity_parts.as_ref().map(|parts| {
                    parts
                        .iter()
                        .map(|part| {
                            json!([part.account_identifier_hash, resolve(part.evidence_ref),
                                part.input_tokens, part.request_count, part.cost_usd])
                        })
                        .collect::<Vec<_>>()
                });
                let value = json!({
                    "account_identifier_hash": row.account_identifier_hash,
                    "evidence": resolve(row.evidence_ref),
                    "identity_parts": parts,
                    "identity_retained": row.identity_retained,
                    "auth_mode": row.auth_mode,
                    "billing_channel": row.billing_channel,
                    "billing_provider": row.billing_provider,
                    "subscription_product": row.subscription_product,
                    "counts": [row.input_tokens, row.output_tokens, row.request_count],
                    "cost_usd": row.cost_usd,
                });
                assert!(
                    placement
                        .insert((bucket.bucket_start.clone(), row_key_from_model_usage(row)), value)
                        .is_none(),
                    "a bucket row is in exactly one entity"
                );
            }
        }
    }
    placement
}

/// A sticky session whose every request on day `d` ran on account `d % 3`,
/// except that the first six hours of each 7-day window keep the previous
/// window's last account (the whole-session carry, decided before any cut).
/// Grown until its untagged body crosses the cut trigger.
fn segment_session() -> (SnapshotItem, Vec<Contribution>, i64) {
    segment_session_until(24 * 21, |item, _| {
        identity::item_bytes(item) > crate::snapshots::history_segments::TRIGGER_BYTES
    })
}

/// `segment_session` from `hours`, grown a day at a time until `done`.
fn segment_session_until(
    hours: usize,
    done: impl Fn(&SnapshotItem, &[Contribution]) -> bool,
) -> (SnapshotItem, Vec<Contribution>, i64) {
    let week = 7 * 86_400;
    for hours in (hours..).step_by(24) {
        let (mut item, mut proof) = sticky_session(hours);
        for contribution in &mut proof {
            let at = OffsetDateTime::parse(&contribution.bucket_start, &Rfc3339)
                .unwrap()
                .unix_timestamp();
            let carried = at.rem_euclid(week) < 6 * 3_600;
            let day = (if carried { at - 6 * 3_600 } else { at }) / 86_400;
            let key = day.rem_euclid(3) as u64;
            contribution.identity = RequestIdentity::Tagged(AuthorityKey {
                login: Some(format!("{key:064x}")),
                org: Some(format!("{:064x}", key + 32)),
                basis: identity::TELEMETRY,
            });
        }
        sticky_receiver_totals(&mut item);
        if done(&item, &proof) {
            let last = OffsetDateTime::parse(&item.collected_at, &Rfc3339)
                .unwrap()
                .unix_timestamp();
            return (item, proof, last + 3_600);
        }
    }
    unreachable!()
}

/// `segment_session` whose first `days` days from 2026-09-03 (a window
/// start) run `models` models per hour, each on 16 accounts: that window is
/// over the per-item parts cap once tagged, the rest of the session is not.
fn hot_session(days: i64, models: usize) -> (SnapshotItem, Vec<Contribution>, i64) {
    let (mut item, mut proof, now) = segment_session();
    let first = OffsetDateTime::parse("2026-09-03T00:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp();
    let hot = |start: &str| {
        let at = OffsetDateTime::parse(start, &Rfc3339)
            .unwrap()
            .unix_timestamp();
        (first..first + days * 86_400).contains(&at)
    };
    let base = item.model_usage[0].clone();
    let rows = (0..models)
        .map(|model| {
            let mut row = base.clone();
            if model > 0 {
                row.model = format!("{}-{model}", base.model);
            }
            row.input_tokens = 16;
            row.request_count = 16;
            row
        })
        .collect::<Vec<_>>();
    proof.retain(|contribution| !hot(&contribution.bucket_start));
    for bucket in &mut item.usage_buckets {
        if !hot(&bucket.bucket_start) {
            continue;
        }
        bucket.model_usage = rows.clone();
        for row in &rows {
            let mut one = row.clone();
            one.input_tokens = 1;
            one.request_count = 1;
            for key in 0..16u64 {
                proof.push(Contribution {
                    bucket_start: bucket.bucket_start.clone(),
                    row_key: row_key_from_model_usage(row),
                    usage: holder_usage(&one, None),
                    identity: RequestIdentity::Tagged(AuthorityKey {
                        login: Some(format!("{key:064x}")),
                        org: Some(format!("{:064x}", key + 32)),
                        basis: identity::TELEMETRY,
                    }),
                });
            }
        }
    }
    let mut top = BTreeMap::<String, SnapshotModelUsage>::new();
    for row in item.usage_buckets.iter().flat_map(|bucket| &bucket.model_usage) {
        let total = top.entry(row.model.clone()).or_insert_with(|| {
            let mut total = row.clone();
            total.input_tokens = 0;
            total.request_count = 0;
            total
        });
        total.input_tokens += row.input_tokens;
        total.request_count += row.request_count;
    }
    item.model_usage = top.into_values().collect();
    sticky_receiver_totals(&mut item);
    (item, proof, now)
}

fn segment_pieces(live: &SnapshotItem) -> Vec<&SnapshotItem> {
    live.history_cut.iter().chain([live]).collect()
}

/// Per bucket, the (account, workspace) pairs its rows must carry.
type SegmentTruth = BTreeMap<String, std::collections::BTreeSet<(Option<String>, Option<String>)>>;

/// Ground truth from the scan's own requests (carry already applied).
fn segment_truth(proof: &[Contribution]) -> SegmentTruth {
    let mut truth = SegmentTruth::new();
    for contribution in proof {
        if let RequestIdentity::Tagged(key) = &contribution.identity {
            truth
                .entry(contribution.bucket_start.clone())
                .or_default()
                .insert((key.login.clone(), key.org.clone()));
        }
    }
    truth
}

/// What every piece's bucket rows carry, resolved on its own evidence table.
fn segment_identities(pieces: &[&SnapshotItem]) -> SegmentTruth {
    let mut found = SegmentTruth::new();
    for item in pieces {
        let org = |reference: Option<u16>| {
            reference.and_then(|reference| {
                item.request_evidence[usize::from(reference)]
                    .provider_workspace_hash
                    .clone()
            })
        };
        for bucket in &item.usage_buckets {
            let set = found.entry(bucket.bucket_start.clone()).or_default();
            for row in &bucket.model_usage {
                match &row.identity_parts {
                    Some(parts) => {
                        for part in parts {
                            set.insert((
                                part.account_identifier_hash.clone(),
                                org(part.evidence_ref),
                            ));
                        }
                    }
                    None => {
                        set.insert((row.account_identifier_hash.clone(), org(row.evidence_ref)));
                    }
                }
            }
        }
    }
    found
}

/// [money] Valid big history finishes: whole, this session is over the item
/// limit once tagged, so today it loses identity; cut, every bucket row keeps
/// its exact account and workspace (the requests' own identities) in exactly
/// one entity, each piece reconciles on its own evidence table, and totals
/// conserve. The scan's boundary carry is proven end to end by the
/// segmented pipeline oracle.
#[test]
fn settled_history_cut_keeps_whole_session_placement() {
    let (full, proof, now) = segment_session();
    let accepted = identity::AcceptedBuckets::for_test();
    let segments = identity::AcceptedBuckets::segments_for_test();
    let mut whole = full.clone();
    identity::apply_cut_for_test(&mut whole, &proof, &accepted, &segments, None).unwrap();
    assert!(whole.history_cut.is_empty() && whole.history_segments.is_none());
    let mut live = full.clone();
    identity::apply_cut_for_test(&mut live, &proof, &accepted, &segments, Some(now)).unwrap();
    let pieces = segment_pieces(&live);
    assert!(pieces.len() >= 3, "several settled windows were cut");
    assert_eq!(segment_identities(&pieces), segment_truth(&proof));
    let through = live.history_segments.as_ref().unwrap();
    assert_eq!(through.count, live.history_cut.len() as u64);
    let through = OffsetDateTime::parse(&through.through, &Rfc3339).unwrap();
    for segment in &live.history_cut {
        let window = segment.history_segment.as_ref().unwrap();
        assert_eq!(window.of, live.source_session_id);
        let start = OffsetDateTime::parse(&window.window_start, &Rfc3339).unwrap();
        let end = OffsetDateTime::parse(&window.window_end, &Rfc3339).unwrap();
        assert_eq!(start.unix_timestamp().rem_euclid(7 * 86_400), 0);
        assert_eq!((end - start).whole_days(), 7);
        assert!(end <= through && end.unix_timestamp() <= now - 72 * 3_600);
        assert_eq!(
            segment.source_session_id,
            format!(
                "{}#w{:04}{:02}{:02}",
                live.source_session_id,
                start.year(),
                u8::from(start.month()),
                start.day()
            )
        );
        assert!(segment.session_display_name.is_none() && segment.context_curve.is_none());
    }
    assert!(live
        .usage_buckets
        .iter()
        .all(|bucket| OffsetDateTime::parse(&bucket.bucket_start, &Rfc3339).unwrap() >= through));
    let mut totals = [0u64; 3];
    for piece in &pieces {
        sticky_assert_reconciled(piece);
        for (total, value) in totals
            .iter_mut()
            .zip([piece.input_tokens, piece.request_count, piece.model_usage[0].input_tokens])
        {
            *total += value;
        }
    }
    assert_eq!(
        totals,
        [full.input_tokens, full.request_count, full.model_usage[0].input_tokens]
    );
}

/// [money] #909 ledger across the cut: after the group ACK each segment entry
/// and the live entry keep exactly their own buckets, and a re-cut tagged
/// from those entries places every row as before.
#[test]
fn settled_history_cut_tags_from_own_entry_then_live() {
    let (full, proof, now) = segment_session();
    let mut accepted = identity::AcceptedBuckets::for_test();
    let mut segments = identity::AcceptedBuckets::segments_for_test();
    let mut live = full.clone();
    identity::apply_cut_for_test(&mut live, &proof, &accepted, &segments, Some(now)).unwrap();
    assert_eq!(segment_identities(&segment_pieces(&live)), segment_truth(&proof));
    for segment in &live.history_cut {
        segments.record(&serde_json::to_value(segment).unwrap());
    }
    accepted.record(&serde_json::to_value(&live).unwrap());
    for piece in segment_pieces(&live) {
        let ledger = if piece.history_segment.is_some() {
            &segments
        } else {
            &accepted
        };
        assert_eq!(
            ledger.get(&piece.source_session_id).unwrap().len(),
            piece.usage_buckets.len(),
            "each entity keeps exactly its own buckets"
        );
    }
    let mut again = full.clone();
    identity::apply_cut_for_test(&mut again, &proof, &accepted, &segments, Some(now)).unwrap();
    assert_eq!(
        segment_placement(&segment_pieces(&again)),
        segment_placement(&segment_pieces(&live))
    );
}

/// [money] The trigger is the body as it would be sent: a session under the
/// trigger untagged but over it once tagged is cut, with every row's
/// identity kept.
#[test]
fn settled_history_cut_measures_the_tagged_body() {
    let accepted = identity::AcceptedBuckets::for_test();
    let segments = identity::AcceptedBuckets::segments_for_test();
    let trigger = crate::snapshots::history_segments::TRIGGER_BYTES;
    let tagged_bytes = |item: &SnapshotItem, proof: &[Contribution]| {
        let mut whole = item.clone();
        identity::apply_cut_for_test(&mut whole, proof, &accepted, &segments, None).unwrap();
        identity::item_bytes(&whole)
    };
    let (full, proof, now) =
        segment_session_until(24 * 14, |item, proof| tagged_bytes(item, proof) > trigger);
    assert!(identity::item_bytes(&full) <= trigger, "untagged it is under");
    let mut live = full.clone();
    identity::apply_cut_for_test(&mut live, &proof, &accepted, &segments, Some(now)).unwrap();
    assert!(live.history_segments.is_some() && !live.history_cut.is_empty());
    assert_eq!(segment_identities(&segment_pieces(&live)), segment_truth(&proof));
}

/// [money] A window over a size cap once tagged halves at whole days until
/// each piece keeps its identity: never stripped, placement exact.
#[test]
fn settled_history_window_over_a_size_cap_halves() {
    let (full, proof, now) = hot_session(3, 2);
    let accepted = identity::AcceptedBuckets::for_test();
    let segments = identity::AcceptedBuckets::segments_for_test();
    let mut whole = full.clone();
    let uncut = identity::apply_cut_for_test(&mut whole, &proof, &accepted, &segments, None);
    assert!(matches!(uncut, Ok(Tagged::Fallback { .. })), "whole it strips");
    let mut live = full.clone();
    let (tagged, held) =
        identity::apply_cut_held_for_test(&mut live, &proof, &accepted, &segments, Some(now));
    assert!(matches!(tagged, Ok(Tagged::Sent { .. })));
    assert!(held.is_empty());
    let windows = live
        .history_cut
        .iter()
        .map(|segment| {
            let window = segment.history_segment.as_ref().unwrap();
            (window.window_start.as_str(), window.window_end.as_str())
        })
        .collect::<Vec<_>>();
    for halved in [
        ("2026-09-03T00:00:00Z", "2026-09-04T00:00:00Z"),
        ("2026-09-04T00:00:00Z", "2026-09-06T00:00:00Z"),
        ("2026-09-06T00:00:00Z", "2026-09-10T00:00:00Z"),
    ] {
        assert!(windows.contains(&halved), "{halved:?} in {windows:?}");
    }
    assert_eq!(segment_identities(&segment_pieces(&live)), segment_truth(&proof));
    for piece in segment_pieces(&live) {
        sticky_assert_reconciled(piece);
    }
}

/// [money] A window still over a size cap at one day holds the session for
/// this pass (counted, delayed): nothing of it is cut or sent stripped as
/// segments, and the caller's hold keeps the whole body off the wire.
#[test]
fn settled_history_day_over_a_size_cap_holds_the_session() {
    let (full, proof, now) = hot_session(1, 6);
    let accepted = identity::AcceptedBuckets::for_test();
    let segments = identity::AcceptedBuckets::segments_for_test();
    let mut item = full.clone();
    let (tagged, held) =
        identity::apply_cut_held_for_test(&mut item, &proof, &accepted, &segments, Some(now));
    assert!(matches!(tagged, Ok(Tagged::Fallback { .. })));
    assert_eq!(held, BTreeSet::from([full.source_session_id.clone()]));
    assert!(item.history_cut.is_empty() && item.history_segments.is_none());
}

/// [off=main] Without the capability nothing is cut: the same bytes as an
/// ordinary tagging pass.
#[test]
fn settled_history_cut_off_keeps_main_bytes() {
    let (full, proof, _) = segment_session();
    let accepted = identity::AcceptedBuckets::for_test();
    let mut off = full.clone();
    identity::apply_cut_for_test(
        &mut off,
        &proof,
        &accepted,
        &identity::AcceptedBuckets::segments_for_test(),
        None,
    )
    .unwrap();
    let mut main = full;
    identity::apply_with_accepted_for_test(&mut main, &proof, &accepted).unwrap();
    assert_eq!(
        serde_json::to_vec(&off).unwrap(),
        serde_json::to_vec(&main).unwrap()
    );
    assert!(off.history_cut.is_empty());
}
