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
            assert!(row.account_identifier_hash.is_none());
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
    let (original, proof) = sticky_session(4);
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
    let (original, proof) = sticky_session(4);
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
    let (original, proof) = sticky_session(4);
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
    let (original, proof) = sticky_session(2);
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
    let (original, proof) = sticky_session(3);
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
    let (mut window, mut proof) = sticky_session(576);
    sticky_price_fixture(&mut window, &mut proof);
    sticky_apply(&mut window, &proof, &retained_state()).unwrap();
    assert_eq!(sticky_wire(window), fixture["window"]);
}

#[test]
fn retained_window_converges_on_markers_under_the_unchanged_caps() {
    let (mut original, mut proof) = sticky_session(576);
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
    let (original, proof) = sticky_session(4);
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
    let (mut original, mut proof) = sticky_session(4);
    sticky_price_fixture(&mut original, &mut proof);
    let mut state = retained_state();
    let mut first = original.clone();
    sticky_apply(&mut first, &proof, &state).unwrap();
    retained_ack(&mut state, &first, &[]);
    let mut marked = original.clone();
    sticky_apply(&mut marked, &proof, &state).unwrap();
    assert_eq!(retained_marked(&marked), vec![true, true, true, false]);
    cases.insert("marker_closed_rows_open_hour_fresh", sticky_wire(marked));
    let mut changed_proof = proof.clone();
    changed_proof[3].identity = login_key(D64);
    let mut changed = original.clone();
    sticky_apply(&mut changed, &changed_proof, &state).unwrap();
    assert_eq!(retained_marked(&changed), vec![true, false, true, false]);
    cases.insert("marker_with_changed_proof_fresh", sticky_wire(changed));

    let (mut window, mut window_proof) = sticky_session(576);
    sticky_price_fixture(&mut window, &mut window_proof);
    let mut window_state = retained_state();
    let mut tagged = window.clone();
    sticky_apply(&mut tagged, &window_proof, &window_state).unwrap();
    retained_ack(&mut window_state, &tagged, &[]);
    sticky_apply(&mut window, &window_proof, &window_state).unwrap();
    cases.insert("marker_window", sticky_wire(window));

    let (two, two_proof) = sticky_session(2);
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
    cases.insert("missing_proof_retag_unfit", sticky_wire(unfit));
    let mut retag = two.clone();
    sticky_apply(&mut retag, &two_proof, &two_state).unwrap();
    cases.insert("missing_proof_retag_fit", sticky_wire(retag));
    for case in cases.values() {
        assert!(
            serde_json::to_vec(&case["snapshots"][0]).unwrap().len() <= identity::MAX_ITEM_BYTES
        );
    }
    serde_json::to_value(cases).unwrap()
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
        panic!("emitted retained-marker goldens changed; regenerate from the CI receipt");
    }
    let manifest: Value = serde_json::from_str(include_str!(
        "fixtures/claude_identity_retained_emitted.manifest.json"
    ))
    .unwrap();
    assert_eq!(
        manifest["sha256"],
        format!("{:x}", sha2::Sha256::digest(fixture.as_bytes()))
    );
}
