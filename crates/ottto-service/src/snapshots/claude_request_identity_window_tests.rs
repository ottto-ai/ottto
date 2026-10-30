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
                .or_insert(([0; 8], [Some(0); 5]));
            for (total, amount) in total.iter_mut().zip(counts) {
                *total += amount;
            }
            for (total, amount) in money.iter_mut().zip(costs) {
                *total = total
                    .zip(amount.map(parse_usd_picos))
                    .map(|(sum, amount)| sum + amount);
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
    let mut accepted = identity::AcceptedBuckets::default();
    let result = identity::apply_with_accepted_for_test(&mut first, &proof, &accepted).unwrap();
    assert!(matches!(result, Tagged::Sent { .. }));
    assert!(
        first.request_identity_refusals > 0,
        "synthetic long body crosses byte cap"
    );
    sticky_assert_reconciled(&first);
    accepted.record(&serde_json::to_value(&first).unwrap());
    let (mut second, proof) = sticky_session(24 * 24 + 1);
    identity::apply_with_accepted_for_test(&mut second, &proof, &accepted).unwrap();
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
    identity::apply_with_accepted_for_test(&mut again, &proof, &accepted).unwrap();
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
#[test]
fn sticky_overflow_protects_open_hour_drops_oldest_as_differs_and_restores_only_held_proof() {
    let (mut first, proof) = sticky_session(576);
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut first, &proof, &accepted).unwrap();
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
    identity::apply_with_accepted_for_test(&mut grown, &proof, &accepted).unwrap();
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
    identity::apply_with_accepted_for_test(&mut restored, &proof, &accepted).unwrap();
    assert!(sticky_tagged(
        &restored.usage_buckets[oldest].model_usage[0]
    ));
    let (mut no_proof, mut proof) = sticky_session(576);
    for c in &mut proof {
        if c.bucket_start == no_proof.usage_buckets[oldest].bucket_start {
            c.identity = RequestIdentity::Missing;
        }
    }
    identity::apply_with_accepted_for_test(&mut no_proof, &proof, &accepted).unwrap();
    assert!(!sticky_tagged(
        &no_proof.usage_buckets[oldest].model_usage[0]
    ));
    assert!(no_proof.request_identity_refusals > 0);
    sticky_assert_reconciled(&no_proof);
}
#[test]
fn sticky_missing_state_uses_current_proof_and_counts_unknown() {
    let (mut item, proof) = sticky_session(576);
    let missing = identity::AcceptedBuckets::default();
    let _ = identity::take_identity_counts();
    identity::apply_with_accepted_for_test(&mut item, &proof, &missing).unwrap();
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
    identity::apply_with_accepted_for_test(
        &mut item,
        &proof,
        &identity::AcceptedBuckets::default(),
    )
    .unwrap();
    assert!(item.request_identity_refusals > 0);
    sticky_assert_reconciled(&item);

    let (mut item, proof) = sticky_session(1100);
    let (result, rows) = crate::local_resource_diagnostics::capture(|| {
        identity::apply_with_accepted_for_test(
            &mut item,
            &proof,
            &identity::AcceptedBuckets::default(),
        )
        .unwrap()
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
    identity::apply_with_accepted_for_test(
        &mut item,
        &proof,
        &identity::AcceptedBuckets::default(),
    )
    .unwrap();
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
        // The newest day's authority has no unpriced companion. Other
        // authorities do, so recovery must preserve their reconciled shares
        // while refusing the newest bucket's unreconcilable known costs.
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
    item.model_usage[0].cost_usd = None;
    let result = identity::apply_with_accepted_for_test(
        &mut item,
        &proof,
        &identity::AcceptedBuckets::default(),
    )
    .unwrap();
    assert!(matches!(result, Tagged::Sent { .. }));
    assert!(item.request_identity_refusals > 0);
    assert!(!sticky_tagged(&item.usage_buckets[575].model_usage[0]));
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
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
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
    item.model_usage[0].cost_usd = None;
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
    accepted.record(&serde_json::to_value(&item).unwrap());
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
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
        identity::apply_with_accepted_for_test(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::default(),
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
        identity::apply_with_accepted_for_test(
            &mut candidate,
            &latest,
            &identity::AcceptedBuckets::default(),
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
    identity::apply_with_accepted_for_test(&mut padded, &proof, &accepted).unwrap();
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
    identity::apply_with_accepted_for_test(
        &mut open_only,
        &open_proof,
        &identity::AcceptedBuckets::default(),
    )
    .unwrap();
    assert_eq!(open_only.request_identity_refusals, 9);
    let extra = identity::item_bytes(&open_only) - identity::item_bytes(&clean);
    let (mut padded, filler_proof) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - extra);
    proof.extend(filler_proof);
    identity::apply_with_accepted_for_test(&mut padded, &proof, &accepted).unwrap();
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
    pro.cost_usd = None;
    let mut clean = stripped(&item);
    clean.provenance.collector = identity::COLLECTOR.into();
    let mut pair = clean.clone();
    let mut pair_proof = proof.clone();
    pair_proof[2].identity = RequestIdentity::Missing;
    identity::apply_with_accepted_for_test(
        &mut pair,
        &pair_proof,
        &identity::AcceptedBuckets::default(),
    )
    .unwrap();
    pair.request_identity_refusals = 1;
    sticky_assert_reconciled(&pair);
    let extra = identity::item_bytes(&pair) - identity::item_bytes(&clean);
    let (mut padded, filler_proof) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - extra);
    proof.extend(filler_proof);
    identity::apply_with_accepted_for_test(&mut padded, &proof, &accepted).unwrap();
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
        identity::apply_with_accepted_for_test(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::default(),
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
    identity::apply_with_accepted_for_test(&mut padded, &proof, &accepted).unwrap();
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
    let prior = json!({"observations":(0..32)
        .map(|n| json!({"event_id":format!("cache:{n:064x}")})).collect::<Vec<_>>()});
    let accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
    let clean = stripped(&item);
    let overhead = identity::item_bytes(&item) - identity::item_bytes(&clean);
    let (mut padded, filler) = sticky_pad_to_bytes(&clean, identity::MAX_ITEM_BYTES - overhead);
    proof.extend(filler);
    let mut unreserved = padded.clone();
    identity::apply_with_accepted_for_test(&mut unreserved, &proof, &accepted).unwrap();
    assert_eq!(identity::item_bytes(&unreserved), identity::MAX_ITEM_BYTES);
    prepare_cache_observations(&mut unreserved, Some(&prior));
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
    let mut accepted = identity::AcceptedBuckets::default();
    identity::apply_with_accepted_for_test(&mut item, &proof, &accepted).unwrap();
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
        identity::apply_with_accepted_for_test(
            &mut candidate,
            &shares,
            &identity::AcceptedBuckets::default(),
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
    identity::apply_with_accepted_for_test(&mut padded, &proof, &accepted).unwrap();
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
