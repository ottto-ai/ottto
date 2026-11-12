// Real evidence chunks, native finalization, wire preflight and entity ACK.
use super::state_v2_money_tests::tagged_api;
use super::*;
use crate::claude_local_otel as otel;
use crate::snapshots::claude_request_identity::WireBudget;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as oracle, money_oracle, Mode, RouteResult,
};

fn hint() -> crate::snapshot_client::ActivityHintResponse {
    crate::snapshot_client::decode_activity_hint(json!({
        "source":"claude_code", "server_time":AT, "record_count_15m":0,
        "record_count_24h":0, "local_usage_reconciliation_enabled":true,
        "backfill_window_days":30, "recommended_scan_after":AT,
        "snapshot_head_cas_required":true,
        "claude_otel_only_sessions_contract":"claude_otel_only_sessions:v1",
        "claude_otel_only_pairing_floor":"2026-08-02T06:00:00Z"
    }))
    .unwrap()
}
fn progress() -> SnapshotUploadProgress {
    let mut value = e2_progress();
    value
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    value.telemetry_only = Some(
        serde_json::from_value(json!({
            "floor":nanos("2026-08-02T06:00:00Z"), "start":nanos("2026-08-02T06:30:00Z"),
            "candidates":{ROOT:{}}
        }))
        .unwrap(),
    );
    value
}
fn full_identity(
    mut row: otel::ClaudeLocalOtelEvidence,
    organization: &str,
) -> otel::ClaudeLocalOtelEvidence {
    use otel::{ClaudeIdentityAttributeOrigin as Origin, ClaudeIdentityDisposition as Disposition};
    if let Some(identity) = row.request_identity.as_mut() {
        let identity = std::sync::Arc::make_mut(identity);
        identity.organization.origin = Origin::LogRecord;
        identity.organization.disposition = Disposition::Complete;
        identity.organization.log_record_hash = Some(organization.into());
        identity.disposition = Disposition::Complete;
    }
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn positive(c: &Corpus) {
    let rows = [
        full_identity(
            tagged_api("before", 11, Some(&"a".repeat(64))),
            &"c".repeat(64),
        ),
        full_identity(
            tagged_api("after", 12, Some(&"b".repeat(64))),
            &"d".repeat(64),
        ),
        api("gap", 13, 130), // No identity: preserve the evidence gap.
        full_identity(
            tagged_api("side-call", 14, Some(&"b".repeat(64))),
            &"d".repeat(64),
        ),
    ];
    c.evidence(
        &rows,
        &[
            trace("before", ""),
            trace("after", ""),
            trace("gap", ""),
            trace("side-call", ""),
        ],
    );
}
fn page(
    c: &Corpus,
    progress: &mut SnapshotUploadProgress,
    hint: &crate::snapshot_client::ActivityHintResponse,
    budget: WireBudget<'_>,
) -> Page {
    page_from(c, progress, hint, budget, ScanIndex::default(), 100)
}
fn page_from(
    c: &Corpus,
    progress: &mut SnapshotUploadProgress,
    hint: &crate::snapshot_client::ActivityHintResponse,
    budget: WireBudget<'_>,
    index: ScanIndex,
    limit: usize,
) -> Page {
    let scanner = E2ScanFixture::capturing_identity();
    let mut page = c.raw(&scanner, index, limit, false, &[]);
    let window = progress
        .seed_telemetry(
            &c.support,
            hint,
            &mut page.scan,
            &page.index,
            &c.base.join("progress.json"),
        )
        .unwrap();
    for item in &mut page.scan.snapshots {
        item.collected_at = AT.into();
    }
    let mut ledger = progress.telemetry_only.take();
    let (disposition, _, stats) = apply_claude_local_evidence_to_scan_with_ledger_and_budget(
        &c.support,
        &mut page.scan,
        &mut page.index,
        Some(&progress.accepted_identity_buckets),
        budget,
        window.zip(ledger.as_deref_mut()),
    );
    progress.telemetry_only = ledger;
    page.disposition = disposition;
    page.stats = stats;
    page.finish();
    progress.bind_telemetry_bodies(&c.support, &mut page.scan.snapshots);
    page
}
fn send(page: &Page, progress: &mut SnapshotUploadProgress, mode: Mode) -> RouteResult {
    let (result, batches, _) = upload(&page.scan.snapshots, progress, ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let mut route = RouteResult::emitted(
        mode,
        SnapshotSource::ClaudeCode,
        batches,
        &page.scan.snapshots,
    );
    for item in &page.scan.snapshots {
        assert!(progress.contains_body(
            &item.snapshot_fingerprint,
            &snapshot_upload_body_witness(item)
        ));
        route.accepted.insert(
            item.source_session_id.clone(),
            oracle::Accepted {
                body: serde_json::to_value(item).unwrap(),
                witness: snapshot_upload_body_witness(item),
            },
        );
    }
    route.accepted_identity_buckets = Some(
        serde_json::to_value(
            page.scan
                .snapshots
                .iter()
                .map(|item| {
                    (
                        &item.source_session_id,
                        progress
                            .accepted_identity_buckets
                            .get(&item.source_session_id),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap(),
    );
    route
}
fn held_route(prior: &RouteResult, progress: &SnapshotUploadProgress) -> RouteResult {
    for accepted in prior.accepted.values() {
        let fingerprint = accepted.body["snapshot_fingerprint"].as_str().unwrap();
        assert!(
            progress.contains_body(fingerprint, &accepted.witness),
            "native accepted ledger keeps prior body"
        );
    }
    let mut route = RouteResult::emitted(Mode::Restart, SnapshotSource::ClaudeCode, vec![], &[]);
    route.accepted = prior.accepted.clone();
    route.accepted_identity_buckets = prior.accepted_identity_buckets.clone();
    route
}

#[test]
fn telemetry_only_cold_ram_restore_and_restart_preserve_switch_gap_and_side_call() {
    with_e2(|| {
        let c = Corpus::new("otel-only-oracle-modes");
        positive(&c);
        let mut base = progress();
        let cold_page = page(&c, &mut base, &hint(), WireBudget::default());
        assert_eq!(cold_page.scan.snapshots.len(), 1);
        let cold = send(&cold_page, &mut base, Mode::ColdFull);
        println!(
            "OTEL_ONLY_RECEIVER_GOLDEN {}",
            serde_json::to_string(&request(&cold_page.scan.snapshots)).unwrap()
        );
        assert_eq!(cold_page.scan.snapshots[0].request_count, 4);
        assert!(!cold_page.scan.snapshots[0].request_evidence.is_empty());
        for mode in [Mode::Ram, Mode::DiskRestore, Mode::Restart] {
            let mut restored = progress();
            if !matches!(mode, Mode::Ram) {
                restored = serde_json::from_slice(&serde_json::to_vec(&restored).unwrap()).unwrap();
                restored
                    .accepted_identity_buckets
                    .bind_test_key(Some([0x42; 32]));
            }
            let other = page(&c, &mut restored, &hint(), WireBudget::default());
            money_oracle::assert_equivalent(&cold, &send(&other, &mut restored, mode));
        }
        let restored: SnapshotUploadProgress =
            serde_json::from_slice(&serde_json::to_vec(&base).unwrap()).unwrap();
        let mut restored = restored;
        restored
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        let reads = otel::evidence_read_counts_for_test();
        let (quiet, io) =
            oracle::observe_codex_quiet(|| page(&c, &mut restored, &hint(), WireBudget::default()));
        assert_eq!(
            otel::evidence_read_counts_for_test(),
            reads,
            "no API or trace body re-read"
        );
        let mut quiet = send(&quiet, &mut restored, Mode::Restart);
        quiet.io = io;
        money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    });
}

#[test]
fn telemetry_only_incomplete_growth_and_oversize_stay_held_with_prior_money() {
    with_e2(|| {
        let c = Corpus::new("otel-only-oracle-holds");
        positive(&c);
        let mut accepted = progress();
        let baseline = page(&c, &mut accepted, &hint(), WireBudget::default());
        let cold = send(&baseline, &mut accepted, Mode::ColdFull);
        for member in ["claude-code-effort", "claude-code-trace-ownership"] {
            positive(&c);
            let path = c
                .support
                .join("local-otel")
                .join(member)
                .join(format!("{}.jsonl", otel::telemetry_stem(ROOT)));
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(b"{broken\n")
                .unwrap();
            let mut retry: SnapshotUploadProgress =
                serde_json::from_slice(&serde_json::to_vec(&accepted).unwrap()).unwrap();
            retry
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            let held = page(&c, &mut retry, &hint(), WireBudget::default());
            assert!(held.scan.snapshots.is_empty());
            assert!(
                serde_json::to_value(&retry).unwrap()["telemetry_only"]["candidates"]
                    .get(ROOT)
                    .is_some()
            );
            money_oracle::assert_held(ROOT, &cold, &held_route(&cold, &retry), &cold);
            money_oracle::assert_no_smaller_reemit(
                ROOT,
                &cold,
                &held_route(&cold, &retry),
                &cold,
                true,
            );
        }
        positive(&c);
        let before = crate::local_resource_diagnostics::identity_over_cap_counts_for_test();
        let mut retry: SnapshotUploadProgress =
            serde_json::from_slice(&serde_json::to_vec(&accepted).unwrap()).unwrap();
        retry
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        let held = page(
            &c,
            &mut retry,
            &hint(),
            WireBudget {
                max_item_bytes: 128,
                reservation: None,
            },
        );
        assert!(
            held.scan.snapshots.is_empty(),
            "no oversized or identity-stripped body sent"
        );
        let after = crate::local_resource_diagnostics::identity_over_cap_counts_for_test();
        assert!(
            after[7] > before[7],
            "existing identity-held counter increments"
        );
        assert!(
            serde_json::to_value(&retry).unwrap()["telemetry_only"]["candidates"]
                .get(ROOT)
                .is_some()
        );
        money_oracle::assert_held(ROOT, &cold, &held_route(&cold, &retry), &cold);
        // The ordinary authority/evidence bounds also hold this case rather
        // than stripping identities to make a smaller receiver-compatible body.
        use std::io::Write;
        for ordinal in 0..33 {
            let request = format!("over-cap-{ordinal}");
            let row = full_identity(
                tagged_api(&request, 11, Some(&format!("{:064x}", ordinal + 200))),
                &"c".repeat(64),
            );
            for (api, json) in [
                (true, serde_json::to_string(&row).unwrap()),
                (false, serde_json::to_string(&trace(&request, "")).unwrap()),
            ] {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(cases::member(&c, api))
                    .unwrap()
                    .write_all((json + "\n").as_bytes())
                    .unwrap();
            }
        }
        let before = crate::local_resource_diagnostics::identity_over_cap_counts_for_test();
        let held = page(&c, &mut retry, &hint(), WireBudget::default());
        assert!(
            held.scan.snapshots.is_empty(),
            "authority cap cannot strip tags"
        );
        assert!(
            crate::local_resource_diagnostics::identity_over_cap_counts_for_test()[7] > before[7]
        );
        money_oracle::assert_held(ROOT, &cold, &held_route(&cold, &retry), &cold);
    });
}

#[test]
fn telemetry_only_off_pre_t_and_transcript_takeover() {
    with_e2(|| {
        let c = Corpus::new("otel-only-scope-oracle");
        positive(&c);
        let mut off = hint();
        off.claude_otel_only_sessions_contract = None;
        let mut disabled = progress();
        let before = serde_json::to_value(&disabled).unwrap();
        let reads = otel::evidence_read_counts_for_test();
        let dark = page(&c, &mut disabled, &off, WireBudget::default());
        assert!(dark.scan.snapshots.is_empty());
        assert_eq!(otel::evidence_read_counts_for_test(), reads);
        assert_eq!(
            serde_json::to_value(&disabled).unwrap(),
            before,
            "OFF writes no ledger state"
        );
        let mut early = progress();
        let mut raw = serde_json::to_value(&early).unwrap();
        raw["telemetry_only"]["start"] = json!(nanos(AT));
        early = serde_json::from_value(raw).unwrap();
        assert!(page(&c, &mut early, &hint(), WireBudget::default())
            .scan
            .snapshots
            .is_empty());
        assert!(
            serde_json::to_value(&early).unwrap()["telemetry_only"]["candidates"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        let mut c = c;
        c.root(ROOT, &line(ROOT, "before", AT, 11));
        let mut taken = progress();
        let transcript = page(&c, &mut taken, &hint(), WireBudget::default());
        assert!(transcript
            .scan
            .snapshots
            .iter()
            .all(|item| item.evidence_basis.is_none()));
        assert!(
            serde_json::to_value(&taken).unwrap()["telemetry_only"]["candidates"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        let mut main = progress();
        let ordinary = page(&c, &mut main, &off, WireBudget::default());
        money_oracle::assert_equivalent(
            &send(&ordinary, &mut main, Mode::ColdFull),
            &send(&transcript, &mut taken, Mode::Ram),
        );
    });
}

/// [format] Exit the writing process before the old source opens the store;
/// the runtime registry deliberately retains the exclusive SQLite owner.
#[test]
fn telemetry_only_previous_release_source_round_trip() {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Linux")
    {
        return;
    }
    let dir = test_dir("otel-only-carry-orchestration");
    let child = |stage: &str, root: &Path| {
        // libtest's exact names omit the crate component of module_path!().
        let test = format!(
            "{}::telemetry_only_carry_child",
            module_path!().split_once("::").unwrap().1
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env("OTTTO_OTEL_CARRY_STAGE", stage)
            .env("OTTTO_OTEL_CARRY_ROOT", root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "carry {stage}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    for tag in ["v0.1.239", "v0.1.244"] {
        let root = dir.join(tag);
        std::fs::create_dir_all(&root).unwrap();
        child("write", &root);
        let index_path = std::fs::read_to_string(root.join("index-path.txt")).unwrap();
        let result = std::process::Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../scripts/test_telemetry_only_carry.py"),
            )
            .arg(tag)
            .arg(index_path.trim())
            .status()
            .unwrap();
        assert!(result.success(), "pinned source round trip {tag}");
        child("verify", &root);
        println!("TELEMETRY_ONLY_ROLL_FORWARD_VERIFIED {tag}");
    }
}

#[test]
fn telemetry_only_carry_child() {
    let Ok(stage) = std::env::var("OTTTO_OTEL_CARRY_STAGE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("OTTTO_OTEL_CARRY_ROOT").unwrap());
    with_e2(|| {
        if stage == "write" {
            let c = Corpus::new("otel-only-carry-child");
            positive(&c);
            let scanner = E2ScanFixture::capturing_identity();
            let index = scanner.routed(ScanIndex::default(), &c.base);
            let index_path = crate::snapshots::e2_pipeline_scan_fixture::route_of(&index).unwrap();
            let path = snapshot_upload_progress_path(&index_path);
            let mut state = SnapshotUploadProgress::load_for_index(
                &index,
                &index_path,
                &path,
                &format!("{:064x}", 99),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap();
            state
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            state.telemetry_only = progress().telemetry_only;
            let built = page(&c, &mut state, &hint(), WireBudget::default());
            send(&built, &mut state, Mode::ColdFull);
            let key = cache_session_key(ROOT);
            state
                .accepted_cache_states
                .insert(key.clone(), json!({"observations":[]}));
            state.accepted_cache_heads.insert(key, "a".repeat(64));
            state.save(&path).unwrap();
            // The row owner releases resident hints after COMMIT. Compare the
            // durable row on both sides, not an evicted writer-side cache.
            state.load_identity([ROOT]).unwrap();
            assert!(state.accepted_identity_buckets.get(ROOT).is_some());
            let expected = (
                state.accepted_body_witnesses.clone(),
                state.accepted_cache_states.clone(),
                state.accepted_cache_heads.clone(),
                serde_json::to_value(&state.accepted_identity_buckets).unwrap(),
            );
            std::fs::write(
                root.join("expected.json"),
                serde_json::to_vec(&expected).unwrap(),
            )
            .unwrap();
            std::fs::write(root.join("index-path.txt"), index_path.to_str().unwrap()).unwrap();
            std::mem::forget(c); // Keep this synthetic store for the next process.
        } else {
            assert_eq!(stage, "verify");
            let index_path =
                PathBuf::from(std::fs::read_to_string(root.join("index-path.txt")).unwrap());
            let index = ScanIndex::load(&index_path).unwrap();
            let mut state = SnapshotUploadProgress::load_for_index(
                &index,
                &index_path,
                &snapshot_upload_progress_path(&index_path),
                &format!("{:064x}", 99),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap();
            state
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            state.load_identity([ROOT]).unwrap();
            assert!(state.telemetry_only.is_none());
            let actual = serde_json::to_value((
                state.accepted_body_witnesses.clone(),
                state.accepted_cache_states.clone(),
                state.accepted_cache_heads.clone(),
                serde_json::to_value(&state.accepted_identity_buckets).unwrap(),
            ))
            .unwrap();
            let expected: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("expected.json")).unwrap())
                    .unwrap();
            assert_eq!(actual, expected, "all known custody survives old save/drop");
        }
    });
}

#[test]
fn telemetry_only_growth_is_cumulative_and_truncation_cannot_reemit_smaller() {
    with_e2(|| {
        let c = Corpus::new("otel-only-growth-oracle");
        positive(&c);
        let mut live = progress();
        let baseline = page(&c, &mut live, &hint(), WireBudget::default());
        let prior = send(&baseline, &mut live, Mode::ColdFull);
        let api_path = c
            .support
            .join("local-otel/claude-code-effort")
            .join(format!("{}.jsonl", otel::telemetry_stem(ROOT)));
        let trace_path = c
            .support
            .join("local-otel/claude-code-trace-ownership")
            .join(format!("{}.jsonl", otel::telemetry_stem(ROOT)));
        let api_bytes = std::fs::read(&api_path).unwrap();
        let trace_bytes = std::fs::read(&trace_path).unwrap();
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&api_path)
            .unwrap()
            .write_all((serde_json::to_string(&api("growth", 20, 200)).unwrap() + "\n").as_bytes())
            .unwrap();
        let incomplete = page(&c, &mut live, &hint(), WireBudget::default());
        assert!(
            incomplete.scan.snapshots.is_empty(),
            "API-only append owes matching trace"
        );
        money_oracle::assert_held(ROOT, &prior, &held_route(&prior, &live), &prior);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&trace_path)
            .unwrap()
            .write_all((serde_json::to_string(&trace("growth", "")).unwrap() + "\n").as_bytes())
            .unwrap();
        let mut reference = progress();
        let full = page(&c, &mut reference, &hint(), WireBudget::default());
        let full = send(&full, &mut reference, Mode::ColdFull);
        let grown = page(&c, &mut live, &hint(), WireBudget::default());
        assert_eq!(grown.scan.snapshots[0].request_count, 5);
        let grown = send(&grown, &mut live, Mode::Ram);
        money_oracle::assert_no_smaller_reemit(ROOT, &prior, &grown, &full, false);
        std::fs::write(api_path, api_bytes).unwrap();
        std::fs::write(trace_path, trace_bytes).unwrap();
        let truncated = page(&c, &mut live, &hint(), WireBudget::default());
        assert!(
            truncated.scan.snapshots.is_empty(),
            "shorter members stay owed"
        );
        money_oracle::assert_no_smaller_reemit(
            ROOT,
            &grown,
            &held_route(&grown, &live),
            &full,
            true,
        );
    });
}

/// [oracle] Composition with copy-family ownership: roots in another folder
/// and their subagents are positive holders, including when their body is not
/// the telemetry root's carrier. No request can be emitted by both entities.
#[test]
fn telemetry_only_composes_with_cross_folder_and_subagent_holders() {
    with_e2(|| {
        for (relative, remaining) in [
            (format!("{COPY}.jsonl"), 3),
            (format!("other/{COPY}.jsonl"), 3),
            (format!("other/{COPY}/subagents/agent-000.jsonl"), 3),
            (format!("forks/{COPY}.jsonl"), 1),
        ] {
            let mut c = Corpus::new("otel-only-holder-composition");
            positive(&c);
            c.write_at(
                &relative,
                &line(COPY, "before", AT, 11),
                "2026-08-02T07:00:00Z",
            );
            if remaining == 1 {
                // Both forks copy the parent's last response, then make
                // independent requests. Only the gap remains telemetry-only.
                for (agent, request, tokens) in [(0, "after", 12), (1, "side-call", 14)] {
                    c.write_at(
                        &format!("forks/{COPY}/subagents/agent-{agent:03}.jsonl"),
                        &(line(COPY, "before", AT, 11) + &line(COPY, request, AT, tokens)),
                        AT,
                    );
                }
            }
            let mut full_progress = progress();
            let full = page(&c, &mut full_progress, &hint(), WireBudget::default());
            let only = full
                .scan
                .snapshots
                .iter()
                .find(|item| item.evidence_basis == Some("otel_only"))
                .unwrap();
            assert_eq!(
                only.request_count, remaining,
                "positive holders exclude their API requests: {relative}"
            );
            assert_eq!(
                full.scan
                    .snapshots
                    .iter()
                    .map(|item| item.request_count)
                    .sum::<u64>(),
                4,
                "request conservation"
            );
            let cold = send(&full, &mut full_progress, Mode::ColdFull);
            let mut restored = progress();
            let other = page(&c, &mut restored, &hint(), WireBudget::default());
            money_oracle::assert_equivalent(&cold, &send(&other, &mut restored, Mode::DiskRestore));
        }
    });
}

mod cases {
    include!("oracle_cases.rs");
}
