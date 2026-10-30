fn retained_session(hours: usize) -> (SnapshotItem, Vec<Contribution>) {
    let (mut item, proof) = sticky_session(hours);
    item.usage_accounting_contract = Some("claude_request_owned_usage:v1".into());
    item.removed_request_count = Some(0);
    item.removed_usage = Some(ClaudeRemovedUsage::default());
    item.telemetry_owned_complete = Some(true);
    // Scans always fingerprint before tagging; the budget measures this length.
    item.snapshot_fingerprint = "a".repeat(64);
    (item, proof)
}
// Option (ii): `identity_retained` markers over the witnessed proved-row
// ledger (SOURCE rule (ii) Addendum 1, Lead B Addendum 1). Synthetic proof only.
fn retained_state() -> identity::AcceptedBuckets {
    let mut state = identity::AcceptedBuckets::for_test();
    state.set_retained_enabled(true);
    state
}
/// Production settles the #909 ledger first, then the witnessed proved rows.
fn retained_ack(state: &mut identity::AcceptedBuckets, item: &SnapshotItem, missing: &[&str]) {
    let body = serde_json::to_value(item).unwrap();
    state.record(&body);
    let missing = missing
        .iter()
        .map(|start| start.to_string())
        .collect::<Vec<_>>();
    state.record_proved(&body, true, &missing);
}
fn retained_counts() -> Value {
    serde_json::to_value(identity::take_identity_counts()).unwrap()["identity_cap"].clone()
}
fn retained_count(counts: &Value, name: &str) -> u64 {
    counts[name].as_u64().unwrap_or(0)
}
fn retained_marked(item: &SnapshotItem) -> Vec<bool> {
    item.usage_buckets
        .iter()
        .map(|bucket| bucket.model_usage.iter().any(|row| row.identity_retained))
        .collect()
}
/// A row is either freshly tagged or marked, never both; top rows never mark.
fn retained_assert_exclusive(item: &SnapshotItem) {
    for row in item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
    {
        if row.identity_retained {
            assert!(!sticky_tagged(row), "marker and tag on one row");
            assert!(row.evidence_ref.is_none() && row.identity_parts.is_none());
            let wire = serde_json::to_string(row).unwrap();
            assert!(wire.contains(r#""identity_retained":true"#));
        } else {
            assert!(!serde_json::to_string(row)
                .unwrap()
                .contains("identity_retained"));
        }
    }
    assert!(item.model_usage.iter().all(|row| !row.identity_retained));
}
/// Hour 1 of a two-hour session carries `keys` distinct fresh logins.
fn retained_wide_open_hour(
    original: &SnapshotItem,
    proof: &[Contribution],
    keys: u64,
) -> (SnapshotItem, Vec<Contribution>) {
    let mut item = original.clone();
    let mut proof = proof[..3].to_vec();
    let row = &mut item.usage_buckets[1].model_usage[0];
    row.input_tokens = keys;
    row.request_count = keys;
    let mut one = row.clone();
    one.input_tokens = 1;
    one.request_count = 1;
    for login in 0..keys {
        proof.push(Contribution {
            bucket_start: item.usage_buckets[1].bucket_start.clone(),
            row_key: row_key_from_model_usage(&one),
            usage: holder_usage(&one, None),
            identity: RequestIdentity::Tagged(AuthorityKey {
                login: Some(format!("{:064x}", 100 + login)),
                org: Some("f".repeat(64)),
                basis: identity::TELEMETRY,
            }),
        });
    }
    item.model_usage[0].input_tokens = 3 + keys;
    item.model_usage[0].request_count = 3 + keys;
    (item, proof)
}

#[test]
fn retained_marker_on_closed_proved_rows_and_fresh_tags_for_the_open_hour() {
    let (original, proof) = retained_session(4);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    assert!(first
        .usage_buckets
        .iter()
        .all(|bucket| sticky_tagged(&bucket.model_usage[0])));
    assert_eq!(retained_marked(&first), vec![false; 4]);
    retained_ack(&mut state, &first, &[]);
    identity::take_identity_counts();
    let mut second = original.clone();
    assert_eq!(
        sticky_apply(&mut second, &proof, &state).unwrap(),
        Tagged::Sent { refusals: 0 }
    );
    assert_eq!(retained_marked(&second), vec![true, true, true, false]);
    assert!(sticky_tagged(&second.usage_buckets[3].model_usage[0]));
    for bucket in &second.usage_buckets[..3] {
        // Full amounts, no tags, not a refusal.
        assert_eq!(bucket.model_usage[0].request_count, 3);
        assert_eq!(bucket.model_usage[0].input_tokens, 3);
    }
    assert_eq!(second.request_identity_refusals, 0);
    let counts = retained_counts();
    assert_eq!(retained_count(&counts, "retained_marker_rows"), 3);
    assert_eq!(retained_count(&counts, "accepted_state_unknown"), 0);
    assert_eq!(retained_count(&counts, "accepted_share_changed"), 0);
    retained_assert_exclusive(&second);
    sticky_assert_reconciled(&second);
    let leaf = identity::semantic_leaf(&second);
    assert_eq!(leaf["usage_buckets"][0][0], json!({"retained": true}));
    assert_eq!(leaf["refused"], json!(false));
    assert_ne!(second.snapshot_fingerprint, first.snapshot_fingerprint);
    // An ACKed marker keeps the server-held proof: the next revision repeats.
    retained_ack(&mut state, &second, &[]);
    let mut third = original.clone();
    sticky_apply(&mut third, &proof, &state).unwrap();
    assert_eq!(
        serde_json::to_vec(&third).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    // Restart keeps the keyed ledger; it still holds no identity material.
    let bytes = serde_json::to_vec(&state).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(&format!("{:064x}", 0)));
    let mut restored = identity::AcceptedBuckets::restore_for_test(&bytes);
    restored.set_retained_enabled(true);
    let mut after_restart = original.clone();
    sticky_apply(&mut after_restart, &proof, &restored).unwrap();
    assert_eq!(
        after_restart.snapshot_fingerprint,
        second.snapshot_fingerprint
    );
}

#[test]
fn retained_different_proof_sends_fresh_tags_counted_and_latest_proof_wins() {
    let (original, proof) = retained_session(4);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    // Hour 1, part 0: A -> B.
    let mut changed = proof.clone();
    changed[3].identity = login_key(D64);
    identity::take_identity_counts();
    let mut second = original.clone();
    sticky_apply(&mut second, &changed, &state).unwrap();
    assert_eq!(retained_marked(&second), vec![true, false, true, false]);
    let row = &second.usage_buckets[1].model_usage[0];
    assert!(row
        .identity_parts
        .as_ref()
        .unwrap()
        .iter()
        .any(|part| part.account_identifier_hash.as_deref() == Some(D64)));
    assert_eq!(second.request_identity_refusals, 0);
    let counts = retained_counts();
    assert_eq!(retained_count(&counts, "accepted_share_changed"), 1);
    assert_eq!(retained_count(&counts, "retained_marker_rows"), 2);
    retained_assert_exclusive(&second);
    sticky_assert_reconciled(&second);
    // B enters on its own ACK; then it is marked like any proved row.
    retained_ack(&mut state, &second, &[]);
    let mut third = original.clone();
    sticky_apply(&mut third, &changed, &state).unwrap();
    assert_eq!(retained_marked(&third), vec![true, true, true, false]);
    // Back to A is a change again: never a marker over a different proof.
    let mut back = original.clone();
    sticky_apply(&mut back, &proof, &state).unwrap();
    assert_eq!(retained_marked(&back), vec![true, false, true, false]);
    assert!(sticky_tagged(&back.usage_buckets[1].model_usage[0]));
    // Growth in a closed hour (late requests) is new proof, not a marker.
    let mut grown = original.clone();
    let mut grown_proof = proof.clone();
    grown_proof.push(grown_proof[0].clone());
    grown.usage_buckets[0].model_usage[0].input_tokens += 1;
    grown.usage_buckets[0].model_usage[0].request_count += 1;
    grown.model_usage[0].input_tokens += 1;
    grown.model_usage[0].request_count += 1;
    sticky_apply(&mut grown, &grown_proof, &state).unwrap();
    assert!(!grown.usage_buckets[0].model_usage[0].identity_retained);
    assert!(sticky_tagged(&grown.usage_buckets[0].model_usage[0]));
    retained_assert_exclusive(&grown);
    sticky_assert_reconciled(&grown);
}

#[test]
fn retained_marker_defers_when_the_transcript_no_longer_proves_the_row() {
    let (original, proof) = retained_session(4);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    for lost in [
        RequestIdentity::Missing,
        RequestIdentity::Refused(Refusal::Pending),
    ] {
        let mut changed = proof.clone();
        for contribution in &mut changed[..3] {
            contribution.identity = lost.clone();
        }
        let mut next = original.clone();
        sticky_apply(&mut next, &changed, &state).unwrap();
        assert_eq!(retained_marked(&next), vec![true, true, true, false]);
        // Deferring is not claiming: no refusal, no inherited tag.
        assert_eq!(next.request_identity_refusals, 0);
        retained_assert_exclusive(&next);
        sticky_assert_reconciled(&next);
    }
    // A never-proved row without proof stays on today's untagged rule.
    let mut never = proof.clone();
    for contribution in &mut never[..3] {
        contribution.identity = RequestIdentity::Refused(Refusal::Pending);
    }
    let mut unproved = original.clone();
    let empty = retained_state();
    sticky_apply(&mut unproved, &never, &empty).unwrap();
    assert!(!unproved.usage_buckets[0].model_usage[0].identity_retained);
    assert_eq!(unproved.request_identity_refusals, 1);
}

#[test]
fn retained_proof_missing_leaves_the_set_and_the_next_revision_re_tags_when_it_fits() {
    let (original, proof) = retained_session(2);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    let mut second = original.clone();
    sticky_apply(&mut second, &proof, &state).unwrap();
    assert_eq!(retained_marked(&second), vec![true, false]);
    identity::take_identity_counts();
    let hour_zero = second.usage_buckets[0].bucket_start.clone();
    retained_ack(&mut state, &second, &[&hour_zero]);
    assert_eq!(
        retained_count(&retained_counts(), "retained_proof_missing_received"),
        1
    );
    let before_retag = state.clone();
    // Fit: the bucket competes in the ordinary allocator and is re-tagged.
    let mut third = original.clone();
    sticky_apply(&mut third, &proof, &state).unwrap();
    assert_eq!(retained_marked(&third), vec![false, false]);
    assert!(sticky_tagged(&third.usage_buckets[0].model_usage[0]));
    assert_eq!(third.request_identity_refusals, 0);
    let counts = retained_counts();
    assert_eq!(retained_count(&counts, "retained_missing_unfit"), 0);
    retained_assert_exclusive(&third);
    sticky_assert_reconciled(&third);
    // Its witnessed ACK proves it again, so the marker returns.
    retained_ack(&mut state, &third, &[]);
    let mut fourth = original.clone();
    sticky_apply(&mut fourth, &proof, &state).unwrap();
    assert_eq!(retained_marked(&fourth), vec![true, false]);

    // Unfit (Lead B Addendum 1): newer fresh proof fills the unchanged
    // 16-key cap first. Counted; the bucket keeps today's untagged/refused
    // rule. No hold, no cap increase, no marker without server proof.
    let (mut wide, wide_proof) = retained_wide_open_hour(&original, &proof, 16);
    identity::take_identity_counts();
    sticky_apply(&mut wide, &wide_proof, &before_retag).unwrap();
    assert_eq!(retained_marked(&wide), vec![false, false]);
    assert!(!sticky_tagged(&wide.usage_buckets[0].model_usage[0]));
    assert!(sticky_tagged(&wide.usage_buckets[1].model_usage[0]));
    assert_eq!(wide.request_identity_refusals, 1);
    let counts = retained_counts();
    assert_eq!(retained_count(&counts, "retained_missing_unfit"), 1);
    retained_assert_exclusive(&wide);
    sticky_assert_reconciled(&wide);
}

#[test]
fn retained_unwitnessed_ack_never_adds_and_a_cleared_set_re_tags() {
    let (original, proof) = retained_session(3);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    let body = serde_json::to_value(&first).unwrap();
    // Count-only/legacy or unwitnessed stored ACK: #909 ledger only.
    state.record(&body);
    state.record_proved(&body, false, &[]);
    let mut second = original.clone();
    sticky_apply(&mut second, &proof, &state).unwrap();
    assert_eq!(retained_marked(&second), vec![false; 3]);
    assert_eq!(
        serde_json::to_vec(&second).unwrap(),
        serde_json::to_vec(&first).unwrap()
    );
    // Namespace / historical replay generation change clears the whole set.
    retained_ack(&mut state, &first, &[]);
    let mut marked = original.clone();
    sticky_apply(&mut marked, &proof, &state).unwrap();
    assert_eq!(retained_marked(&marked), vec![true, true, false]);
    identity::take_identity_counts();
    state.clear_retained();
    assert_eq!(
        retained_count(&retained_counts(), "retained_set_cleared"),
        1
    );
    let mut cleared = original.clone();
    sticky_apply(&mut cleared, &proof, &state).unwrap();
    assert_eq!(retained_marked(&cleared), vec![false; 3]);
    assert_eq!(
        serde_json::to_vec(&cleared).unwrap(),
        serde_json::to_vec(&first).unwrap()
    );
}

#[test]
fn retained_gate_off_is_byte_identical_to_the_909_goldens() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/claude_identity_cap_emitted.json")).unwrap();
    // Gate off with every golden body's rows proved: not one byte changes.
    let seeded = sticky_golden_cases(&|state| {
        assert!(!state.retained_enabled());
        for case in fixture.as_object().unwrap().values() {
            state.record_proved(&case["snapshots"][0], true, &[]);
        }
        assert!(!state.is_empty());
    });
    assert_eq!(seeded, sticky_golden_cases(&|_| {}));
    // #909 pins these bytes; its own test owns the remaining receipt cases.
    for case in [
        "mixed_presence",
        "window",
        "accepted_overflow",
        "restore_from_held_proof",
    ] {
        assert_eq!(seeded[case], fixture[case], "{case}");
    }
    // Gate on with no proved rows yet: the plain recent window equals #909's.
    let (mut window, mut proof) = retained_session(576);
    sticky_price_fixture(&mut window, &mut proof);
    let mut baseline = window.clone();
    sticky_apply(&mut baseline, &proof, &identity::AcceptedBuckets::for_test()).unwrap();
    sticky_apply(&mut window, &proof, &retained_state()).unwrap();
    assert_eq!(sticky_wire(window), sticky_wire(baseline));
}

#[test]
fn retained_window_converges_on_markers_under_the_unchanged_caps() {
    let (mut original, mut proof) = retained_session(576);
    sticky_price_fixture(&mut original, &mut proof);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    let tagged = |item: &SnapshotItem| {
        item.usage_buckets
            .iter()
            .filter(|bucket| sticky_tagged(&bucket.model_usage[0]))
            .count()
    };
    let first_tagged = tagged(&first);
    assert!(first.request_identity_refusals > 0);
    retained_ack(&mut state, &first, &[]);
    let mut second = original.clone();
    sticky_apply(&mut second, &proof, &state).unwrap();
    let marked = retained_marked(&second).iter().filter(|m| **m).count();
    assert_eq!(
        marked,
        first_tagged - 1,
        "every closed proved row is marked"
    );
    // Proved rows now cost only marker bytes, so more fresh proof fits.
    assert!(tagged(&second) > 1);
    assert!(second.request_identity_refusals < first.request_identity_refusals);
    assert!(identity::item_bytes(&second) <= identity::MAX_ITEM_BYTES);
    retained_assert_exclusive(&second);
    sticky_assert_reconciled(&second);
}

#[test]
fn retained_fallback_keeps_only_the_newest_markers_that_fit() {
    const MARKER: usize = r#","identity_retained":true"#.len();
    let (original, proof) = retained_session(4);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    let reserved = |item: &mut SnapshotItem, extra: usize| {
        sticky_receiver_totals(item);
        identity::apply_with_reserved_bytes_for_test(item, &proof, &state, extra)
    };
    // No room beside the stripped body: each proved row is a stripped refusal.
    let mut bare = original.clone();
    assert!(matches!(
        reserved(&mut bare, identity::MAX_ITEM_BYTES).unwrap(),
        Tagged::Fallback { .. }
    ));
    assert_eq!(retained_marked(&bare), vec![false; 4]);
    assert_eq!(bare.request_identity_refusals, 4);
    // Room for exactly one marker: the newest closed proved row keeps it.
    let extra = identity::MAX_ITEM_BYTES - identity::item_bytes(&bare) - MARKER;
    let mut one = original.clone();
    identity::take_identity_counts();
    assert!(matches!(
        reserved(&mut one, extra).unwrap(),
        Tagged::Fallback { .. }
    ));
    assert_eq!(retained_marked(&one), vec![false, false, true, false]);
    assert_eq!(one.request_identity_refusals, 3);
    assert_eq!(identity::item_bytes(&one) + extra, identity::MAX_ITEM_BYTES);
    assert_eq!(
        retained_count(&retained_counts(), "retained_marker_rows"),
        1
    );
    retained_assert_exclusive(&one);
    sticky_assert_reconciled(&one);
}

/// Exact emitted bodies with markers for the backend companion receiver test.
fn retained_golden_cases() -> Value {
    let mut cases = BTreeMap::new();
    let (mut original, mut proof) = retained_session(4);
    // Every cost everywhere: an unpriced rollup would strip these markers.
    sticky_price_rows(&mut original, &mut proof, |_, _| true);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    let mut marked = original.clone();
    sticky_apply(&mut marked, &proof, &state).unwrap();
    sticky_assert_reconciled(&marked);
    assert_eq!(retained_marked(&marked), vec![true, true, true, false]);
    assert!(sticky_tagged(&marked.usage_buckets[3].model_usage[0]));
    cases.insert("marker_closed_rows_open_hour_fresh_proving", sticky_wire(first.clone()));
    cases.insert("marker_with_changed_proof_fresh_proving", sticky_wire(first.clone()));
    cases.insert("marker_closed_rows_open_hour_fresh", sticky_wire(marked));
    let mut changed_proof = proof.clone();
    changed_proof[3].identity = login_key(D64);
    let mut changed = original.clone();
    sticky_apply(&mut changed, &changed_proof, &state).unwrap();
    sticky_assert_reconciled(&changed);
    assert_eq!(retained_marked(&changed), vec![true, false, true, false]);
    cases.insert("marker_with_changed_proof_fresh", sticky_wire(changed));

    let (mut window, mut window_proof) = retained_session(576);
    sticky_price_rows(&mut window, &mut window_proof, |_, _| true);
    let mut window_state = retained_state();
    let mut tagged = window.clone();
    sticky_apply(&mut tagged, &window_proof, &window_state).unwrap();
    retained_ack(&mut window_state, &tagged, &[]);
    sticky_apply(&mut window, &window_proof, &window_state).unwrap();
    assert!(retained_marked(&window).iter().any(|marked| *marked));
    cases.insert("marker_window_proving", sticky_wire(tagged));
    cases.insert("marker_window", sticky_wire(window));

    let (two, two_proof) = retained_session(2);
    let mut two_state = retained_state();
    let mut first = two.clone();
    sticky_apply(&mut first, &two_proof, &two_state).unwrap();
    retained_ack(&mut two_state, &first, &[]);
    let mut second = two.clone();
    sticky_apply(&mut second, &two_proof, &two_state).unwrap();
    let hour_zero = second.usage_buckets[0].bucket_start.clone();
    retained_ack(&mut two_state, &second, &[&hour_zero]);
    let (mut unfit, unfit_proof) = retained_wide_open_hour(&two, &two_proof, 16);
    sticky_apply(&mut unfit, &unfit_proof, &two_state).unwrap();
    cases.insert("missing_proof_retag_unfit_proving", sticky_wire(first.clone()));
    cases.insert("missing_proof_retag_fit_proving", sticky_wire(first));
    cases.insert("missing_proof_retag_unfit", sticky_wire(unfit));
    let mut retag = two.clone();
    sticky_apply(&mut retag, &two_proof, &two_state).unwrap();
    cases.insert("missing_proof_retag_fit", sticky_wire(retag));
    let (login, login_proof) = retained_login_session();
    let mut login_state = retained_state();
    let mut login_first = login.clone();
    sticky_apply(&mut login_first, &login_proof, &login_state).unwrap();
    retained_ack(&mut login_state, &login_first, &[]);
    let mut login_marked = login.clone();
    sticky_apply(&mut login_marked, &login_proof, &login_state).unwrap();
    assert!(login_marked.usage_buckets[0].model_usage[0].identity_retained);
    assert_eq!(login_marked.usage_buckets[0].model_usage[0].account_identifier_hash.as_deref(), Some(OWNER_A));
    cases.insert("login_marker_with_hash_proving", sticky_wire(login_first.clone()));
    cases.insert("login_marker_with_hash", sticky_wire(login_marked));
    let mut contract5 = login.clone();
    contract5.usage_accounting_contract = None;
    contract5.removed_request_count = None;
    contract5.removed_usage = None;
    contract5.telemetry_owned_complete = None;
    sticky_apply(&mut contract5, &login_proof, &login_state).unwrap();
    assert!(contract5.usage_buckets.iter().all(|b| b.model_usage.iter().all(|r| !r.identity_retained && sticky_tagged(r))));
    cases.insert("contract5_fresh_proving", sticky_wire(contract5.clone()));
    cases.insert("contract5_fresh", sticky_wire(contract5));
    // Force a capacity refusal after witnessed proof; the marker is excluded.
    let mut refusal = login.clone();
    let mut changed = login_proof.clone();
    for contribution in &mut changed[..3] { contribution.identity = login_key(D64); }
    identity::apply_with_reserved_bytes_for_test(&mut refusal, &changed, &login_state, identity::MAX_ITEM_BYTES).unwrap();
    assert!(!refusal.usage_buckets[0].model_usage[0].identity_retained);
    assert!(!sticky_tagged(&refusal.usage_buckets[0].model_usage[0]));
    assert!(refusal.request_identity_refusals > 0);
    cases.insert("counted_refusal_after_proof_proving", sticky_wire(login_first));
    cases.insert("counted_refusal_after_proof", sticky_wire(refusal));
    // r7's strip wins over proof: refused and counted, never marked.
    let (mut unpriced, mut unpriced_proof) = retained_session(4);
    sticky_price_fixture(&mut unpriced, &mut unpriced_proof);
    let mut unpriced_state = retained_state();
    let mut unpriced_first = unpriced.clone();
    sticky_apply(&mut unpriced_first, &unpriced_proof, &unpriced_state).unwrap();
    retained_ack(&mut unpriced_state, &unpriced_first, &[]);
    identity::take_identity_counts();
    sticky_apply(&mut unpriced, &unpriced_proof, &unpriced_state).unwrap();
    assert_eq!(retained_marked(&unpriced), vec![false; 4]);
    assert!(unpriced.usage_buckets.iter().all(|b| !sticky_tagged(&b.model_usage[0])));
    assert_eq!(retained_count(&retained_counts(), "unpriced_part_untagged"), 1);
    assert_eq!(unpriced.request_identity_refusals, 4);
    cases.insert("unpriced_strip_after_proof_proving", sticky_wire(unpriced_first));
    cases.insert("unpriced_strip_after_proof", sticky_wire(unpriced));
    serde_json::to_value(cases).unwrap()
}

/// Wire bound and the receiver presence rule on every emitted item.
fn retained_assert_golden_shape(cases: &Value) {
    for (name, case) in cases.as_object().unwrap() {
        let item = &case["snapshots"][0];
        let bytes = serde_json::to_vec(item).unwrap().len();
        assert!(bytes <= identity::MAX_ITEM_BYTES, "{name}: {bytes}");
        // A part carries exactly the costs its row carries, at both levels.
        let bucket_rows = item["usage_buckets"].as_array().unwrap().iter();
        let rows = item["model_usage"]
            .as_array()
            .unwrap()
            .iter()
            .chain(bucket_rows.flat_map(|bucket| bucket["model_usage"].as_array().unwrap()));
        for row in rows {
            for part in row["identity_parts"].as_array().into_iter().flatten() {
                for cost in [
                    "cost_usd",
                    "input_cost_usd",
                    "output_cost_usd",
                    "cache_read_cost_usd",
                    "cache_creation_cost_usd",
                ] {
                    assert_eq!(part[cost].is_null(), row[cost].is_null(), "{name}: {cost}");
                }
            }
        }
    }
}

#[test]
fn retained_emitted_wire_goldens_for_the_receiver_contract() {
    use base64::Engine;
    use sha2::Digest;
    use std::io::Write;
    let actual = retained_golden_cases();
    let fixture = include_str!("fixtures/claude_identity_retained_emitted.json");
    let expected: Value = serde_json::from_str(fixture).unwrap();
    if actual != expected {
        // Bootstrap/update on Linux CI only, from the lossless receipt.
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&serde_json::to_vec(&actual).unwrap())
            .unwrap();
        eprintln!(
            "E2_RETAINED_GOLDEN_GZIP_BASE64={}",
            base64::engine::general_purpose::STANDARD.encode(gzip.finish().unwrap())
        );
        retained_assert_golden_shape(&actual);
        panic!("emitted retained-marker goldens changed; regenerate from the CI receipt");
    }
    retained_assert_golden_shape(&actual);
    let manifest: Value = serde_json::from_str(include_str!(
        "fixtures/claude_identity_retained_emitted.manifest.json"
    ))
    .unwrap();
    assert_eq!(
        manifest["sha256"],
        format!("{:x}", sha2::Sha256::digest(fixture.as_bytes()))
    );
}

fn retained_login_session() -> (SnapshotItem, Vec<Contribution>) {
    let (item, mut proof) = retained_session(2);
    for c in &mut proof { c.identity = login_key(OWNER_A); }
    (item, proof)
}

#[test]
fn retained_login_hash_is_ack_bound_even_when_transcript_proof_disappears() {
    let (original, proof) = retained_login_session();
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    assert_eq!(first.usage_buckets[0].model_usage[0].account_identifier_hash.as_deref(), Some(OWNER_A));
    retained_ack(&mut state, &first, &[]);
    let mut restored = identity::AcceptedBuckets::restore_for_test(&serde_json::to_vec(&state).unwrap());
    restored.set_retained_enabled(true);
    let mut missing = proof.clone();
    for c in &mut missing { c.identity = RequestIdentity::Missing; }
    let mut marked = original.clone();
    sticky_apply(&mut marked, &missing, &restored).unwrap();
    for bucket in &marked.usage_buckets {
        let row = &bucket.model_usage[0];
        assert!(row.identity_retained);
        assert_eq!(row.account_identifier_hash.as_deref(), Some(OWNER_A));
        assert!(!sticky_tagged(row));
    }
    // Contract 5 always uses fresh tags even with capability + witnessed state.
    let mut legacy = original.clone();
    legacy.usage_accounting_contract = None;
    legacy.removed_request_count = None;
    legacy.removed_usage = None;
    legacy.telemetry_owned_complete = None;
    sticky_apply(&mut legacy, &proof, &restored).unwrap();
    assert!(legacy.usage_buckets.iter().all(|b| !b.model_usage[0].identity_retained && sticky_tagged(&b.model_usage[0])));
    sticky_assert_reconciled(&legacy);
}

#[test]
fn retained_marker_and_unpriced_strip_compose_at_both_grains() {
    let (mut original, mut proof) = retained_session(4);
    sticky_price_fixture(&mut original, &mut proof);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    identity::take_identity_counts();
    let mut next = original.clone();
    sticky_apply(&mut next, &proof, &state).unwrap();
    sticky_assert_reconciled(&next);
    retained_assert_exclusive(&next);
    let counts = retained_counts();
    assert!(retained_count(&counts, "unpriced_part_untagged") > 0);
    assert!(next.usage_buckets.iter().all(|b| !b.model_usage[0].identity_retained && !sticky_tagged(&b.model_usage[0])));
    // Marker rows themselves have no parts; a fully deferred closed body is safe.
    let mut closed = original.clone();
    closed.collected_at = "2026-09-02T00:00:00Z".into();
    identity::take_identity_counts();
    sticky_apply(&mut closed, &proof, &state).unwrap();
    assert!(retained_marked(&closed).iter().all(|marked| *marked));
    assert_eq!(retained_count(&retained_counts(), "unpriced_part_untagged"), 0);
    sticky_assert_reconciled(&closed);
}

#[test]
fn retained_capped_rows_send_fresh_tags_through_the_normal_caps() {
    let (mut original, proof) = retained_session(1_024 + 2);
    let mut state = retained_state();
    let mut body = original.clone();
    // Smaller model spelling + a single login makes this maximum-row body fit.
    let model = "claude-synthetic";
    for row in body.model_usage.iter_mut().chain(body.usage_buckets.iter_mut().flat_map(|b| &mut b.model_usage)) { row.model = model.into(); }
    original = body.clone();
    let mut proof = proof;
    for c in &mut proof { c.row_key.model = model.into(); c.identity = login_key(OWNER_A); }
    sticky_apply(&mut body, &proof, &state).unwrap();
    // The entire source can exceed the wire cap, so prove compact fixture rows
    // directly only for rows the emitted body's ACK actually carried.
    identity::take_identity_counts();
    retained_ack(&mut state, &body, &[]);
    assert_eq!(retained_count(&retained_counts(), "proved_rows_capped"), 2);
    assert!(state.proved_rows_for_test(&body.source_session_id).unwrap().0 <= 1_024);
    let mut next = original;
    sticky_apply(&mut next, &proof, &state).unwrap();
    assert!(sticky_tagged(&next.usage_buckets[0].model_usage[0]));
    assert!(!next.usage_buckets[0].model_usage[0].identity_retained);
    assert!(identity::item_bytes(&next) <= identity::MAX_ITEM_BYTES);
    sticky_assert_reconciled(&next);
}

#[test]
fn retained_lost_replacement_then_missing_proof_is_a_counted_refusal() {
    let (original, proof) = retained_login_session();
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    let mut changed = proof.clone();
    for c in &mut changed[..3] { c.identity = login_key(D64); }
    let mut replacement = original.clone();
    sticky_apply(&mut replacement, &changed, &state).unwrap();
    assert!(state.invalidate_replaced(&serde_json::to_value(replacement).unwrap()));
    // Share hints evict independently; the unsettled replacement must not.
    state.forget_share_hints_for_test(&original.source_session_id);
    for c in &mut changed[..3] { c.identity = RequestIdentity::Missing; }
    let mut missing = original;
    sticky_apply(&mut missing, &changed, &state).unwrap();
    let row = &missing.usage_buckets[0].model_usage[0];
    assert!(!row.identity_retained && !sticky_tagged(row));
    assert!(missing.request_identity_refusals > 0);
    sticky_assert_reconciled(&missing);
}

/// Lead B F1: a copy-prefix row marked `copy_unproven` and its unmarked own
/// twin share a bucket and every other key field. #909 freezes, and #944
/// proves, each under the daemon's partitioned RowKey: no false refusal, no
/// silent re-tag, and the unmarked row keeps its key when no marked row is
/// sent (capability off).
#[test]
fn copy_unproven_twin_rows_freeze_and_prove_separately() {
    for retained in [false, true] {
        let (mut item, _) = retained_session(1);
        // A closed hour, so an unchanged witnessed proof marks.
        item.collected_at = "2026-09-02T00:00:00Z".into();
        let own = item.usage_buckets[0].model_usage[0].clone();
        let mut copy = own.clone();
        copy.copy_unproven = true;
        item.usage_buckets[0].model_usage = vec![copy.clone(), own.clone()];
        item.model_usage = vec![copy.clone(), own.clone()];
        let start = item.usage_buckets[0].bucket_start.clone();
        let proof = |rows: &[(&SnapshotModelUsage, u64)]| {
            rows.iter()
                .map(|(row, login)| Contribution {
                    bucket_start: start.clone(),
                    row_key: row_key_from_model_usage(row),
                    usage: holder_usage(row, None),
                    identity: RequestIdentity::Tagged(AuthorityKey {
                        login: Some(format!("{login:064x}")),
                        org: Some(format!("{:064x}", login + 32)),
                        basis: identity::TELEMETRY,
                    }),
                })
                .collect::<Vec<_>>()
        };
        let mut state = if retained {
            retained_state()
        } else {
            identity::AcceptedBuckets::for_test()
        };
        let mut first = item.clone();
        sticky_apply(&mut first, &proof(&[(&copy, 1), (&own, 2)]), &state).unwrap();
        retained_ack(&mut state, &first, &[]);
        identity::take_identity_counts();
        let mut again = item.clone();
        sticky_apply(&mut again, &proof(&[(&copy, 1), (&own, 2)]), &state).unwrap();
        let counts = retained_counts();
        assert_eq!(retained_count(&counts, "accepted_share_changed"), 0, "no false refusal");
        assert_eq!(again.request_identity_refusals, 0);
        if retained {
            assert!(
                again.usage_buckets[0].model_usage.iter().all(|row| row.identity_retained),
                "each row carries its own witnessed proof"
            );
            assert_eq!(retained_count(&counts, "retained_marker_rows"), 2);
            continue;
        }
        // The marked row's authority changes: its own frozen share refuses it.
        let mut moved = item.clone();
        sticky_apply(&mut moved, &proof(&[(&copy, 3), (&own, 2)]), &state).unwrap();
        assert_eq!(
            retained_count(&retained_counts(), "accepted_share_changed"),
            1,
            "never a silent re-tag"
        );
        assert_eq!(moved.request_identity_refusals, 1);
        // No marked row (capability off): the own row finds its unchanged key.
        let mut own_only = item.clone();
        own_only.usage_buckets[0].model_usage = vec![own.clone()];
        own_only.model_usage = vec![own.clone()];
        sticky_apply(&mut own_only, &proof(&[(&own, 2)]), &state).unwrap();
        let counts = retained_counts();
        assert_eq!(retained_count(&counts, "accepted_share_changed"), 0);
        assert_eq!(retained_count(&counts, "accepted_row_vanished"), 1);
        assert_eq!(own_only.request_identity_refusals, 0);
    }
}
