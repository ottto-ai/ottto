use super::*;

fn accounts(item: &SnapshotItem) -> BTreeSet<String> {
    let raw = value(item).unwrap();
    let mut accounts = BTreeSet::new();
    for row in raw["model_usage"].as_array().unwrap() {
        let parts = row.get("identity_parts").and_then(Value::as_array);
        for part in parts.map_or(std::slice::from_ref(row), Vec::as_slice) {
            if let Some(key) = part["account_identifier_hash"].as_str() {
                accounts.insert(key.to_owned());
            }
        }
    }
    accounts
}

// Exercise the relay's shared append path, including a mixed provider export.
pub(super) fn relay_append(c: &Corpus, sessions: &[&str]) -> (usize, usize) {
    let attributes = |session: &str| {
        [
            ("session.id", session),
            ("request_id", "mixed-next"),
            ("client_request_id", "client-mixed-next"),
            ("model", "claude-haiku-4-5"),
            ("query_source", "sdk"),
            ("input_tokens", "17"),
            ("output_tokens", "19"),
        ]
        .map(|(key, value)| json!({"key":key,"value":{"stringValue":value}}))
    };
    let stamp = nanos(AT).to_string();
    let logs = json!({"resourceLogs":[{"scopeLogs":[{"logRecords":sessions.iter().map(|session|
        json!({"timeUnixNano":stamp,"body":{"stringValue":"claude_code.api_request"},
            "attributes":attributes(session)})).collect::<Vec<_>>()}]}]});
    let traces = json!({"resourceSpans":[{"scopeSpans":[{"spans":sessions.iter().map(|session|
        json!({"name":"claude_code.llm_request","startTimeUnixNano":stamp,
            "attributes":attributes(session)})).collect::<Vec<_>>()}]}]});
    (
        otel::capture_claude_api_request_logs(
            &c.support,
            &encode(&logs).unwrap(),
            "application/json",
        )
        .unwrap(),
        otel::capture_claude_llm_request_traces(
            &c.support,
            &encode(&traces).unwrap(),
            "application/json",
        )
        .unwrap(),
    )
}

pub(super) fn mixed_smoke() {
    let (c, mut p, accepted) = accepted_case("otel-only-mixed-smoke-money");
    let generation = otel::telemetry_generation(&c.support, ROOT).unwrap();
    let reserved = crate::claude_spawn_gate::internal_session_id();
    assert_eq!(relay_append(&c, &[&reserved]), (0, 0));
    assert_eq!(
        otel::telemetry_generation(&c.support, ROOT).unwrap(),
        generation
    );
    assert!(notice(&c).is_empty());
    p.settle_telemetry_root(ROOT);
    let mut p = restore(&p);
    assert_eq!(relay_append(&c, &[&reserved, ROOT]), (1, 1));
    assert_eq!(notice(&c), BTreeSet::from([ROOT.into()]));
    reemit(&c, &mut p, &accepted, Mode::Restart);
    assert_eq!(otel::telemetry_stems(&c.support).unwrap().len(), 1);
}

pub(super) fn scope_hold() {
    let (c, mut p, accepted) = accepted_case("otel-only-unknown-scope");
    assert_eq!(relay_append(&c, &[ROOT]), (1, 1));
    let mut indices = Vec::new();
    for failed in [false, true] {
        let mut raw = value(ScanIndex::default()).unwrap();
        raw["traversal"] = json!({"context_fingerprint":"held", "census_window_end":AT,
                "scan_roots":[c.root], "pending_directories":[{"scan_root":c.root,"path":c.root.join(ROOT)}],
                "pending_candidates":[], "observed_index_keys":[], "reconciliation_upper_bound":null,
                "reconciliation_after":null,"reconciliation_started":false,
                "unhealthy_retry_attempt":u8::from(failed),"counts":{"unreadable_path_count":u64::from(failed)}});
        indices.push(serde_json::from_value::<ScanIndex>(raw).unwrap());
    }
    let mut raw = value(ScanIndex::default()).unwrap();
    raw["claude_usage_family_witnesses"] = json!({ROOT:{"members":[false],"opaque":"future"}});
    let path = c.base.join("held-index.json");
    fs::write(&path, encode(&raw).unwrap()).unwrap();
    indices.push(ScanIndex::load(&path).unwrap());
    for index in indices {
        let (absent, backed) = crate::snapshots::claude_request_money::e2::telemetry_scope(
            &index,
            &BTreeSet::from([ROOT.into()]),
        );
        assert!(!absent.contains(ROOT) && !backed.contains(ROOT));
        let mut next = restore(&p);
        let mut scan = empty_scan(&c);
        let reads = otel::evidence_read_counts_for_test();
        next.seed_telemetry(
            &c.support,
            &hint(),
            &mut scan,
            &index,
            &c.base.join("held-progress.json"),
        )
        .unwrap();
        assert!(scan.snapshots.is_empty());
        assert_eq!(reads, otel::evidence_read_counts_for_test());
        held(&accepted, &next);
    }
    reemit(&c, &mut p, &accepted, Mode::Ram);
}

pub(super) fn presence() {
    let c = Corpus::new("otel-only-presence");
    let mut a = tagged("priced-a", 11, 7);
    a.reasoning_output_tokens = 9;
    a.query_source = "sdk".into();
    a = signed(a);
    let b = tagged("priced-b", 12, 14);
    let mut unknown = api("unpriced-gap", 13, 130);
    unknown.cost_usd_micros = None;
    unknown = signed(unknown);
    pair(&c, &[a.clone(), b, unknown, a]);
    let mut p = progress();
    let built = build(&c, &mut p);
    let item = &built.scan.snapshots[0];
    let counts = [
        item.request_count,
        item.input_tokens,
        item.output_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.reasoning_output_tokens,
    ];
    assert_eq!(counts, [3, 36, 36, 15, 6, 9]);
    assert_eq!(
        accounts(item),
        BTreeSet::from(["1".repeat(64), "2".repeat(64)])
    );
    assert!(item
        .request_evidence
        .iter()
        .all(|e| e.provider_workspace_hash.is_some()));
    let cold = send(&built, &mut p, Mode::ColdFull);
    compare_modes(&c, &cold, &[Mode::Ram, Mode::DiskRestore, Mode::Restart]);
    // Login-only, invalid and entirely missing evidence never invent a start binding.
    for row in [
        tagged_api("login-only", 7, Some(&"a".repeat(64))),
        tagged_api("invalid", 7, None),
        api("unknown", 7, 70),
    ] {
        pair(&c, &[row]);
        let mut next = progress();
        let built = build(&c, &mut next);
        assert_eq!(built.scan.snapshots[0].request_count, 1);
        assert!(built.scan.snapshots[0].session_account_evidence.is_none());
        let full = send(&built, &mut next, Mode::ColdFull);
        compare_modes(&c, &full, &[Mode::Restart]);
    }
}

pub(super) fn dark() {
    let (c, p, _) = accepted_case("otel-only-off-matrix");
    for (field, replacement) in [
        ("claude_otel_only_sessions_contract", json!(null)),
        ("claude_otel_only_sessions_contract", json!("unknown")),
        ("claude_otel_only_pairing_floor", json!(null)),
        ("claude_otel_only_pairing_floor", json!("invalid")),
        ("local_usage_reconciliation_enabled", json!(false)),
        ("snapshot_head_cas_required", json!(false)),
        ("source", json!("codex")),
        ("source", json!("pi")),
        ("claude_otel_only_pairing_ceiling", json!("invalid")),
        (
            "claude_otel_only_pairing_ceiling",
            json!("2026-08-02T06:00:00Z"),
        ),
        (
            "claude_otel_only_sessions_contract",
            json!({"unexpected":true}),
        ),
        ("claude_otel_only_pairing_floor", json!({"unexpected":true})),
        (
            "claude_otel_only_pairing_ceiling",
            json!({"unexpected":true}),
        ),
    ] {
        let mut raw = hint_json();
        raw[field] = replacement;
        let h = crate::snapshot_client::decode_activity_hint(raw).unwrap();
        assert!(crate::snapshot_sync::telemetry_only::advertised(&h).is_none());
        let mut next = restore(&p);
        let before = value(&next).unwrap();
        let reads = otel::evidence_read_counts_for_test();
        let built = page(&c, &mut next, &h, WireBudget::default());
        assert!(built.scan.snapshots.is_empty());
        assert_eq!(reads, otel::evidence_read_counts_for_test());
        assert_eq!(before, value(&next).unwrap());
        assert!(send(&built, &mut next, Mode::Restart).batches.is_empty());
    }
}

pub(super) fn pairing() {
    let c = Corpus::new("otel-only-pairing-boundaries");
    for (at, ceiling, emits) in [
        ("2026-08-02T06:30:00Z", None, false),
        ("2026-08-02T06:30:00.000000001Z", None, true),
        (AT, Some("2026-08-02T07:05:10Z"), false),
        (AT, Some("2026-08-02T07:05:10.000000001Z"), true),
    ] {
        let mut row = api("boundary", 11, 110);
        row.observed_at = at.into();
        pair(&c, &[signed(row)]);
        let mut h = hint();
        h.claude_otel_only_pairing_ceiling = ceiling.map(str::to_owned);
        let mut p = progress();
        let built = page(&c, &mut p, &h, WireBudget::default());
        assert_eq!(!built.scan.snapshots.is_empty(), emits, "{at} {ceiling:?}");
        if at == "2026-08-02T06:30:00Z" {
            assert!(!candidate(&p), "pre-T settlement");
        }
        files_held(&c);
    }
    for incomplete in [false, true] {
        pair(&c, &[]);
        if incomplete {
            append(&c, false, &trace("unmatched", ""));
        }
        let mut p = progress();
        assert!(build(&c, &mut p).scan.snapshots.is_empty());
        assert_eq!(
            candidate(&p),
            incomplete,
            "empty settles; mismatched trace stays owed"
        );
    }
    positive(&c);
    let mut p = progress();
    let built = build(&c, &mut p);
    let accepted = send(&built, &mut p, Mode::ColdFull);
    let bytes = fs::read(member(&c, false)).unwrap();
    fs::remove_file(member(&c, false)).unwrap();
    let held = build(&c, &mut p);
    assert!(held.scan.snapshots.is_empty());
    assert_held(ROOT, &accepted, &held_route(&accepted, &p), &accepted);
    fs::write(member(&c, false), bytes).unwrap();
    let repaired = build(&c, &mut p);
    assert_eq!(
        snapshot_upload_body_witness(&repaired.scan.snapshots[0]),
        accepted.accepted[ROOT].witness
    );
    suppressed(&repaired, &mut p);
    assert_held(ROOT, &accepted, &held_route(&accepted, &p), &accepted);
    let mut h = hint();
    h.claude_otel_only_pairing_floor = Some("2026-08-02T06:59:00Z".into());
    assert!(page(&c, &mut p, &h, WireBudget::default())
        .scan
        .snapshots
        .is_empty());
    assert_no_smaller_reemit(ROOT, &accepted, &held_route(&accepted, &p), &accepted, true);
}

pub(super) fn save_failure() {
    let c = Corpus::new("otel-save-notice");
    otel::telemetry_notices::configure(&c.support, true).unwrap();
    assert_eq!(relay_append(&c, &[ROOT]), (1, 1));
    let bad = c.base.join("not-a-directory");
    fs::write(&bad, b"file").unwrap();
    let mut p = progress();
    let mut scan = empty_scan(&c);
    for (path, success) in [
        (bad.join("progress.json"), false),
        (c.base.join("saved.json"), true),
    ] {
        assert_eq!(
            p.seed_telemetry(&c.support, &hint(), &mut scan, &ScanIndex::default(), &path)
                .is_ok(),
            success
        );
        assert_eq!(notice(&c).contains(ROOT), !success);
        if !success {
            let pending = notice(&c);
            assert_eq!(relay_append(&c, &[COPY]), (1, 1));
            assert!(notice(&c).is_superset(&pending));
            assert_eq!(notice(&c), BTreeSet::from([ROOT.into(), COPY.into()]));
        } else {
            assert!(notice(&c).is_empty());
        }
    }
    assert!(candidate(&p)); // Direct-append growth is checked by grow().
}

pub(super) fn refusal() {
    let c = Corpus::new("otel-only-refusal");
    positive(&c);
    for permanent in [false, true] {
        let mut p = progress();
        let built = build(&c, &mut p);
        let fp = built.scan.snapshots[0].snapshot_fingerprint.clone();
        let _ = upload(&built.scan.snapshots, &mut p, |items| {
            let mut response = crate::snapshot_sync::head_conflict_answer_tests::empty_ack();
            response.rejected_entities = items
                .iter()
                .map(|item| crate::snapshot_client::SnapshotEntityRejection {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    reason: "invalid".into(),
                    detail: "synthetic refusal".into(),
                    permanent,
                    occurrence_count: 1,
                })
                .collect();
            Ok(response)
        });
        assert!(!p.accepted_body_witnesses.contains_key(&fp));
        let candidate = candidate(&p);
        assert_eq!(
            candidate, !permanent,
            "only a validated permanent refusal settles scheduling"
        );
        files_held(&c);
    }
}

pub(super) fn wire(built: &mut Page) {
    let item = &mut built.scan.snapshots[0];
    item.workspace_hash = Some("must-not-leak-workspace".into());
    item.source_file_fingerprint = Some("must-not-leak-file".into());
    item.session_display_name = Some("must-not-leak-title".into());
    let wire = value(request(&built.scan.snapshots)).unwrap();
    let item = &wire["snapshots"][0];
    let allowed = "evidence_basis source_session_id snapshot_fingerprint status input_tokens output_tokens cache_read_tokens cache_creation_5m_tokens cache_creation_1h_tokens reasoning_output_tokens unattributed_total_tokens request_count usage_accounting_contract removed_request_count removed_usage telemetry_owned_complete resolver_conflict_count model_usage usage_buckets cost initiator source_started_at source_ended_at source_last_activity_at collected_at provenance request_evidence request_identity_refusals semantic_envelope content_hash".split_whitespace().collect::<BTreeSet<_>>();
    assert!(item
        .as_object()
        .unwrap()
        .keys()
        .all(|key| allowed.contains(key.as_str())));
    assert_eq!(item["cache_creation_5m_tokens"], 20);
    assert_eq!(item["cache_creation_1h_tokens"], 8);
    assert_eq!(item["evidence_basis"], "otel_only");
    assert_eq!(item["initiator"], "unknown");
    assert_eq!(
        item["provenance"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["collector", "input_token_scope"])
    );
    assert!(!wire.to_string().contains("must-not-leak"));
}

pub(super) fn takeover() {
    let mut c = Corpus::new("otel-only-takeover-delete");
    positive(&c);
    let mut p = progress();
    let only = build(&c, &mut p);
    let accepted = send(&only, &mut p, Mode::ColdFull);
    let before_takeover = restore(&p);
    let path = c.root(ROOT, &line(ROOT, "before", AT, 11));
    let mut transcript = build(&c, &mut p);
    assert!(transcript_only(&transcript));
    assert!(!candidate(&p));
    assert_eq!(total(&transcript), 4);
    let replacement = cas_takeover(&transcript, &mut p, Mode::Ram);
    // Native share hints retain prior accepted keys across revisions.
    // Both acquisition routes must start with that same ACK history.
    let mut full = restore(&before_takeover);
    let mut off = hint();
    off.claude_otel_only_sessions_contract = None;
    let reference = page(&c, &mut full, &off, WireBudget::default());
    assert_equivalent(
        &cas_takeover(&reference, &mut full, Mode::ColdFull),
        &replacement,
    );
    assert_ne!(
        replacement.accepted[ROOT].witness,
        accepted.accepted[ROOT].witness
    );
    assert_eq!(replacement.accepted.len(), 1);
    assert!(replacement.accepted.contains_key(ROOT));
    let again = build(&c, &mut p);
    suppressed(&again, &mut p);
    let prior = settled_index(&c, &mut transcript, &p);
    fs::remove_file(path).unwrap();
    let mut next = progress();
    let after = retained(&c, &mut next, prior, 1);
    assert!(
        transcript_only(&after),
        "local deletion cannot create a telemetry downgrade"
    );
    assert!(p
        .accepted_body_witnesses
        .values()
        .any(|value| value == &accepted.accepted[ROOT].witness));
}

fn cas_takeover(page: &Page, p: &mut Progress, mode: Mode) -> RouteResult {
    use crate::snapshot_sync::head_conflict_answer_tests as cas;
    let key = cache_session_key(ROOT);
    let prior = p.accepted_body_witnesses.clone();
    let stale = "1".repeat(64);
    p.accepted_cache_heads.insert(key.clone(), stale.clone());
    for accepted in [false, true] {
        let mut offered = Vec::new();
        let (result, wires) = cas::cycle_with_transport(
            p,
            &page.scan.snapshots,
            1000 + u64::from(accepted),
            |_| 0,
            |_| true,
            |request, _| {
                offered = request.snapshots.clone();
                assert_eq!(offered.len(), 1);
                Ok(if accepted {
                    cas::accepted(&offered[0], &"2".repeat(64))
                } else {
                    cas::conflict(&offered[0], &cas::challenge(0xc))
                })
            },
        );
        let envelope = cas::envelope(&wires[0]);
        if !accepted {
            assert_eq!(
                result.unwrap(),
                ResumableUploadResult::Deferred {
                    count: 1,
                    isolated: 1
                }
            );
            assert_eq!(
                p.accepted_body_witnesses, prior,
                "conflict earns no custody"
            );
            assert_eq!(envelope["base_head_etag"], stale);
            assert_eq!(p.accepted_cache_heads[&key], stale);
            *p = restore(p);
            assert_eq!(
                p.head_conflict_challenges[&key].challenge,
                cas::challenge(0xc)
            );
        } else {
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
            assert_eq!(envelope["conflict_head_challenge"], cas::challenge(0xc));
            assert_eq!(envelope["forced_full_rescan"], true);
            assert!(envelope.get("base_head_etag").is_none());
            assert_eq!(p.accepted_cache_heads[&key], "2".repeat(64));
            assert!(!p.head_conflict_challenges.contains_key(&key));
            return delivered(&offered, p, mode, wires.iter().map(canonical).collect());
        }
    }
    unreachable!("accepted cycle returns the verified route")
}
