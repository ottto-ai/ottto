use super::*;
use std::io::Write;

fn signed(mut row: otel::ClaudeLocalOtelEvidence) -> otel::ClaudeLocalOtelEvidence {
    row.fingerprint.clear();
    row.fingerprint_check = Default::default();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn pair(c: &Corpus, rows: &[otel::ClaudeLocalOtelEvidence]) {
    let traces = rows
        .iter()
        .map(|row| (row.request_id.clone(), trace(&row.request_id, "")))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    c.evidence(rows, &traces);
}
fn restore(state: &SnapshotUploadProgress) -> SnapshotUploadProgress {
    let mut state: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(state).unwrap()).unwrap();
    state
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    state
}
fn member(c: &Corpus, api: bool) -> PathBuf {
    c.support
        .join("local-otel")
        .join(if api {
            "claude-code-effort"
        } else {
            "claude-code-trace-ownership"
        })
        .join(format!("{}.jsonl", otel::telemetry_stem(ROOT)))
}
fn accounts(item: &SnapshotItem) -> BTreeSet<String> {
    let raw = serde_json::to_value(item).unwrap();
    raw["model_usage"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|row| {
            row.get("identity_parts")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .chain(std::iter::once(row))
                .filter_map(|part| {
                    part.get("account_identifier_hash")?
                        .as_str()
                        .map(str::to_owned)
                })
        })
        .collect()
}

#[test]
fn priced_unpriced_dedup_cache_reasoning_and_identity_presence() {
    with_e2(|| {
        let c = Corpus::new("otel-only-presence");
        let mut a = full_identity(
            tagged_api("priced-a", 11, Some(&"a".repeat(64))),
            &"c".repeat(64),
        );
        a.reasoning_output_tokens = 9;
        a.query_source = "sdk".into();
        a = signed(a);
        let b = full_identity(
            tagged_api("priced-b", 12, Some(&"b".repeat(64))),
            &"d".repeat(64),
        );
        let mut unknown = api("unpriced-gap", 13, 130);
        unknown.cost_usd_micros = None;
        unknown = signed(unknown);
        pair(&c, &[a.clone(), b, unknown, a]);
        let mut p = progress();
        let built = page(&c, &mut p, &hint(), WireBudget::default());
        let item = &built.scan.snapshots[0];
        assert_eq!(
            (item.request_count, item.input_tokens, item.output_tokens),
            (3, 36, 36)
        );
        assert_eq!(
            (
                item.cache_creation_5m_tokens,
                item.cache_creation_1h_tokens,
                item.reasoning_output_tokens
            ),
            (15, 6, 9)
        );
        assert_eq!(
            accounts(item),
            BTreeSet::from(["a".repeat(64), "b".repeat(64)])
        );
        assert!(item
            .request_evidence
            .iter()
            .all(|e| e.provider_workspace_hash.is_some()));
        let cold = send(&built, &mut p, Mode::ColdFull);
        for mode in [Mode::Ram, Mode::DiskRestore, Mode::Restart] {
            let mut next = progress();
            let built = page(&c, &mut next, &hint(), WireBudget::default());
            money_oracle::assert_equivalent(&cold, &send(&built, &mut next, mode));
        }
        // Login-only, invalid and entirely missing evidence never invent a start binding.
        for row in [
            tagged_api("login-only", 7, Some(&"a".repeat(64))),
            tagged_api("invalid", 7, None),
            api("unknown", 7, 70),
        ] {
            pair(&c, &[row]);
            let mut next = progress();
            let built = page(&c, &mut next, &hint(), WireBudget::default());
            assert_eq!(built.scan.snapshots[0].request_count, 1);
            assert!(built.scan.snapshots[0].session_account_evidence.is_none());
            let full = send(&built, &mut next, Mode::ColdFull);
            let mut next = progress();
            let other = page(&c, &mut next, &hint(), WireBudget::default());
            money_oracle::assert_equivalent(&full, &send(&other, &mut next, Mode::Restart));
        }
    });
}

#[test]
fn dark_and_withdrawn_hints_do_no_evidence_io_or_progress_mutation() {
    with_e2(|| {
        let c = Corpus::new("otel-only-off-matrix");
        positive(&c);
        let mut p = progress();
        let built = page(&c, &mut p, &hint(), WireBudget::default());
        send(&built, &mut p, Mode::ColdFull);
        let mut variants = vec![];
        let mut h = hint();
        h.claude_otel_only_sessions_contract = None;
        variants.push(h);
        let mut h = hint();
        h.claude_otel_only_sessions_contract = Some("future".into());
        variants.push(h);
        let mut h = hint();
        h.claude_otel_only_pairing_floor = Some("malformed".into());
        variants.push(h);
        let mut h = hint();
        h.claude_otel_only_pairing_ceiling = Some("malformed".into());
        variants.push(h);
        let mut h = hint();
        h.local_usage_reconciliation_enabled = false;
        variants.push(h);
        let mut h = hint();
        h.snapshot_head_cas_required = false;
        variants.push(h);
        for h in variants {
            let mut next = restore(&p);
            let before = serde_json::to_value(&next).unwrap();
            let reads = otel::evidence_read_counts_for_test();
            let built = page(&c, &mut next, &h, WireBudget::default());
            assert!(built.scan.snapshots.is_empty());
            assert_eq!(reads, otel::evidence_read_counts_for_test());
            assert_eq!(before, serde_json::to_value(&next).unwrap());
            assert!(send(&built, &mut next, Mode::Restart).batches.is_empty());
        }
    });
}

#[test]
fn pairing_boundaries_repair_and_healthy_empty_are_distinct_from_faults() {
    with_e2(|| {
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
            assert!(
                member(&c, true).exists() && member(&c, false).exists(),
                "no telemetry file deletion"
            );
        }
        pair(&c, &[]);
        let mut p = progress();
        assert!(page(&c, &mut p, &hint(), WireBudget::default())
            .scan
            .snapshots
            .is_empty());
        assert!(
            serde_json::to_value(&p).unwrap()["telemetry_only"]["candidates"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        positive(&c);
        let mut p = progress();
        let built = page(&c, &mut p, &hint(), WireBudget::default());
        let accepted = send(&built, &mut p, Mode::ColdFull);
        let bytes = std::fs::read(member(&c, false)).unwrap();
        std::fs::remove_file(member(&c, false)).unwrap();
        let held = page(&c, &mut p, &hint(), WireBudget::default());
        assert!(held.scan.snapshots.is_empty());
        money_oracle::assert_held(ROOT, &accepted, &held_route(&accepted, &p), &accepted);
        std::fs::write(member(&c, false), bytes).unwrap();
        let repaired = page(&c, &mut p, &hint(), WireBudget::default());
        money_oracle::assert_equivalent(&accepted, &send(&repaired, &mut p, Mode::Restart));
        let mut h = hint();
        h.claude_otel_only_pairing_floor = Some("2026-08-02T06:59:00Z".into());
        assert!(page(&c, &mut p, &h, WireBudget::default())
            .scan
            .snapshots
            .is_empty());
        money_oracle::assert_no_smaller_reemit(
            ROOT,
            &accepted,
            &held_route(&accepted, &p),
            &accepted,
            true,
        );
    });
}

#[test]
fn trace_first_growth_without_notices_and_restart_transaction_windows() {
    with_e2(|| {
        let c = Corpus::new("otel-only-trace-first-restarts");
        positive(&c);
        let mut p = progress();
        let built = page(&c, &mut p, &hint(), WireBudget::default());
        let before_ack = restore(&p);
        let cold = send(&built, &mut p, Mode::ColdFull);
        // A lost response or a crash before local progress commit retries the exact body.
        for _ in 0..2 {
            let mut next = restore(&before_ack);
            let retry = page(&c, &mut next, &hint(), WireBudget::default());
            money_oracle::assert_equivalent(&cold, &send(&retry, &mut next, Mode::Restart));
        }
        let path = c.base.join("committed-progress.json");
        p.save(&path).unwrap();
        let mut committed = SnapshotUploadProgress::load(
            &path,
            &p.destination_namespace_hash,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        committed
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        let reads = otel::evidence_read_counts_for_test();
        let (quiet, io) = oracle::observe_codex_quiet(|| {
            page(&c, &mut committed, &hint(), WireBudget::default())
        });
        assert_eq!(reads, otel::evidence_read_counts_for_test());
        let mut route = send(&quiet, &mut committed, Mode::Restart);
        route.io = io;
        money_oracle::assert_quiet_restart_zero_bytes(&route);
        assert!(otel::telemetry_notices::pending(&c.support)
            .unwrap()
            .is_empty());
        std::fs::OpenOptions::new()
            .append(true)
            .open(member(&c, false))
            .unwrap()
            .write_all(
                (serde_json::to_string(&trace("trace-first", "")).unwrap() + "\n").as_bytes(),
            )
            .unwrap();
        let held = page(&c, &mut committed, &hint(), WireBudget::default());
        assert!(held.scan.snapshots.is_empty());
        money_oracle::assert_held(ROOT, &cold, &held_route(&cold, &committed), &cold);
        std::fs::OpenOptions::new()
            .append(true)
            .open(member(&c, true))
            .unwrap()
            .write_all(
                (serde_json::to_string(&api("trace-first", 20, 200)).unwrap() + "\n").as_bytes(),
            )
            .unwrap();
        let grown = page(&c, &mut committed, &hint(), WireBudget::default());
        assert_eq!(grown.scan.snapshots[0].request_count, 5);
        let mut reference = progress();
        let full = page(&c, &mut reference, &hint(), WireBudget::default());
        let full = send(&full, &mut reference, Mode::ColdFull);
        money_oracle::assert_no_smaller_reemit(
            ROOT,
            &cold,
            &send(&grown, &mut committed, Mode::Ram),
            &full,
            false,
        );
    });
}

#[test]
fn admission_save_failure_keeps_pending_notice_and_saved_candidate_detects_growth() {
    with_e2(|| {
        let c = Corpus::new("otel-only-save-notice");
        let stamp = nanos(AT).to_string();
        let log = json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":stamp,
            "body":{"stringValue":"claude_code.api_request"},"attributes":[
                {"key":"session.id","value":{"stringValue":ROOT}},
                {"key":"model","value":{"stringValue":"claude-haiku-4-5"}},
                {"key":"request_id","value":{"stringValue":"notice"}},
                {"key":"input_tokens","value":{"intValue":"1"}}]}]}]}]});
        otel::telemetry_notices::configure(&c.support, true).unwrap();
        assert_eq!(
            otel::capture_claude_api_request_logs(
                &c.support,
                &serde_json::to_vec(&log).unwrap(),
                "application/json"
            )
            .unwrap(),
            1
        );
        let bad = c.base.join("not-a-directory");
        std::fs::write(&bad, b"file").unwrap();
        let mut p = progress();
        let mut scan = c
            .raw(
                &E2ScanFixture::capturing_identity(),
                ScanIndex::default(),
                100,
                false,
                &[],
            )
            .scan;
        assert!(p
            .seed_telemetry(
                &c.support,
                &hint(),
                &mut scan,
                &ScanIndex::default(),
                &bad.join("progress.json")
            )
            .is_err());
        assert!(otel::telemetry_notices::pending(&c.support)
            .unwrap()
            .contains(ROOT));
        p.seed_telemetry(
            &c.support,
            &hint(),
            &mut scan,
            &ScanIndex::default(),
            &c.base.join("saved.json"),
        )
        .unwrap();
        assert!(otel::telemetry_notices::pending(&c.support)
            .unwrap()
            .is_empty());
        // Existing growth tests append directly without notices: no new stat or
        // full telemetry-directory walk is needed after forget(saved_roots).
        assert!(
            serde_json::to_value(&p).unwrap()["telemetry_only"]["candidates"]
                .get(ROOT)
                .is_some()
        );
    });
}

#[test]
fn permanent_refusal_releases_scheduling_but_never_existing_ack_or_files() {
    with_e2(|| {
        let c = Corpus::new("otel-only-refusal");
        positive(&c);
        for permanent in [false, true] {
            let mut p = progress();
            let built = page(&c, &mut p, &hint(), WireBudget::default());
            let fp = built.scan.snapshots[0].snapshot_fingerprint.clone();
            let _ = upload(&built.scan.snapshots, &mut p, |items| {
                let mut response = ack(items)?;
                response.accepted = 0;
                response.sessions_reconciled = 0;
                response.accepted_entities.clear();
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
            let candidate = serde_json::to_value(&p).unwrap()["telemetry_only"]["candidates"]
                .get(ROOT)
                .is_some();
            assert_eq!(
                candidate, !permanent,
                "only a validated permanent refusal settles scheduling"
            );
            assert!(member(&c, true).exists() && member(&c, false).exists());
        }
    });
}

#[test]
fn wire_contract_excludes_transcript_and_local_metadata() {
    with_e2(|| {
        let c = Corpus::new("otel-only-wire-golden");
        positive(&c);
        let mut p = progress();
        let mut built = page(&c, &mut p, &hint(), WireBudget::default());
        let item = &mut built.scan.snapshots[0];
        item.workspace_hash = Some("must-not-leak-workspace".into());
        item.source_file_fingerprint = Some("must-not-leak-file".into());
        item.session_display_name = Some("must-not-leak-title".into());
        let wire = serde_json::to_value(request(&built.scan.snapshots)).unwrap();
        let item = &wire["snapshots"][0];
        let allowed = BTreeSet::from([
            "evidence_basis",
            "source_session_id",
            "snapshot_fingerprint",
            "status",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
            "usage_accounting_contract",
            "removed_request_count",
            "removed_usage",
            "telemetry_owned_complete",
            "resolver_conflict_count",
            "model_usage",
            "usage_buckets",
            "cost",
            "initiator",
            "source_started_at",
            "source_ended_at",
            "source_last_activity_at",
            "collected_at",
            "provenance",
            "request_evidence",
            "request_identity_refusals",
            "semantic_envelope",
            "content_hash",
        ]);
        assert!(item
            .as_object()
            .unwrap()
            .keys()
            .all(|key| allowed.contains(key.as_str())));
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
    });
}

#[test]
fn transcript_twins_off_page_holders_and_takeover_preserve_existing_money() {
    with_e2(|| {
        for content_twin in [false, true] {
            let mut c = Corpus::new("otel-only-twin-composition");
            positive(&c);
            let content = line(COPY, "before", AT, 11);
            c.root(COPY, &content);
            c.write_at(
                &format!(
                    "other/{}.jsonl",
                    if content_twin {
                        "9338a80a-f36e-4cbc-a5bb-50fc66430ba5"
                    } else {
                        COPY
                    }
                ),
                &content,
                "2026-08-02T07:00:00Z",
            );
            let mut p = progress();
            let mut full = page(&c, &mut p, &hint(), WireBudget::default());
            let synthetic = full
                .scan
                .snapshots
                .iter()
                .find(|item| item.evidence_basis == Some("otel_only"))
                .unwrap();
            assert_eq!(
                synthetic.request_count, 3,
                "a copy carrier holds its request independently of emitted bodies"
            );
            let cold = send(&full, &mut p, Mode::ColdFull);
            let saved = c.reload(&mut full.index);
            let mut next = progress();
            let other = page_from(&c, &mut next, &hint(), WireBudget::default(), saved, 100);
            // Unchanged transcript carriers may be omitted: only newly offered
            // telemetry money is compared with the same cold entity, and the
            // retained native census must continue vetoing the copied request.
            assert_eq!(
                other
                    .scan
                    .snapshots
                    .iter()
                    .find(|item| item.evidence_basis == Some("otel_only"))
                    .unwrap()
                    .request_count,
                3
            );
            let mut fresh = progress();
            let reference = page(&c, &mut fresh, &hint(), WireBudget::default());
            money_oracle::assert_equivalent(&cold, &send(&reference, &mut fresh, Mode::Restart));
        }
        let mut c = Corpus::new("otel-only-takeover-delete");
        positive(&c);
        let mut p = progress();
        let only = page(&c, &mut p, &hint(), WireBudget::default());
        let accepted = send(&only, &mut p, Mode::ColdFull);
        let path = c.root(ROOT, &line(ROOT, "before", AT, 11));
        let mut transcript = page(&c, &mut p, &hint(), WireBudget::default());
        assert!(transcript
            .scan
            .snapshots
            .iter()
            .all(|item| item.evidence_basis.is_none()));
        assert!(
            serde_json::to_value(&p).unwrap()["telemetry_only"]["candidates"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            transcript
                .scan
                .snapshots
                .iter()
                .map(|item| item.request_count)
                .sum::<u64>(),
            4
        );
        let prior = c.reload(&mut transcript.index);
        std::fs::remove_file(path).unwrap();
        let mut next = progress();
        let after = page_from(&c, &mut next, &hint(), WireBudget::default(), prior, 1);
        assert!(
            after
                .scan
                .snapshots
                .iter()
                .all(|item| item.evidence_basis.is_none()),
            "local deletion cannot create a telemetry downgrade"
        );
        assert!(p
            .accepted_body_witnesses
            .values()
            .any(|value| value == &accepted.accepted[ROOT].witness));
    });
}
