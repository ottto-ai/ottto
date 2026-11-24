use super::state_v2_money_tests::tagged_api;
use super::E2ScanFixture as Scanner;
use super::*;
use crate::claude_local_otel as otel;
use crate::local_resource_diagnostics::identity_over_cap_counts_for_test as caps;
use crate::snapshot_client::ActivityHintResponse as Hint;
use crate::snapshot_sync::SnapshotUploadProgress as Progress;
use crate::snapshots::claude_request_identity::WireBudget;
use crate::snapshots::sampled_scan::transition_fixture::{self as oracle, Mode, RouteResult};
use crate::snapshots::SnapshotSource::ClaudeCode as Claude;
use oracle::money_oracle::{
    assert_carried_equivalent, assert_equivalent, assert_held, assert_no_smaller_reemit,
    assert_quiet_restart_zero_bytes,
};
use otel::ClaudeLocalOtelEvidence as Api;
use serde_json::{from_slice as decode, to_value as value, to_vec as encode, Value};
use std::fs;

fn signed(mut row: Api) -> Api {
    row.fingerprint.clear();
    row.fingerprint_check = Default::default();
    row.fingerprint = format!("sha256:{:x}", Sha256::digest(encode(&row).unwrap()));
    row
}
fn pair(c: &Corpus, rows: &[Api]) {
    let traces = rows
        .iter()
        .map(|row| (row.request_id.clone(), trace(&row.request_id, "")))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    c.evidence(rows, &traces);
}
fn restore(p: &Progress) -> Progress {
    let mut p: Progress = decode(&encode(p).unwrap()).unwrap();
    p.finish_load(snapshot_quarantine_witness(Claude));
    p.accepted_identity_buckets.bind_test_key(Some([0x42; 32]));
    p
}
fn member(c: &Corpus, api: bool) -> PathBuf {
    let kind = if api { "effort" } else { "trace-ownership" };
    let stem = otel::telemetry_stem(ROOT);
    c.support
        .join(format!("local-otel/claude-code-{kind}/{stem}.jsonl"))
}
fn build(c: &Corpus, p: &mut Progress) -> Page {
    page(c, p, &hint(), WireBudget::default())
}
fn candidate(p: &Progress) -> bool {
    value(p).unwrap()["telemetry_only"]["candidates"]
        .get(ROOT)
        .is_some()
}
fn append(c: &Corpus, api: bool, value: &impl Serialize) {
    let line = serde_json::to_string(value).unwrap();
    super::append(&member(c, api), &format!("{line}\n"));
}
fn reference(c: &Corpus) -> RouteResult {
    let mut p = progress();
    send(&build(c, &mut p), &mut p, Mode::ColdFull)
}
fn held(cold: &RouteResult, p: &Progress) {
    assert!(candidate(p));
    assert_held(ROOT, cold, &held_route(cold, p), cold);
}
fn quiet(c: &Corpus, p: &mut Progress, index: ScanIndex) {
    let reads = otel::evidence_read_counts_for_test();
    let (page, io) = oracle::observe_codex_quiet(|| retained(c, p, index, 100));
    assert_eq!(reads, otel::evidence_read_counts_for_test());
    let mut r = send(&page, p, Mode::Restart);
    r.io = io;
    assert_quiet_restart_zero_bytes(&r);
}
fn accepted_case(name: &str) -> (Corpus, Progress, RouteResult) {
    let c = Corpus::new(name);
    positive(&c);
    let mut p = progress();
    let cold = send(&build(&c, &mut p), &mut p, Mode::ColdFull);
    (c, p, cold)
}
fn owed(page: &Page, p: &Progress, prior: &RouteResult) {
    assert!(page.scan.snapshots.is_empty());
    held(prior, p);
}
fn paged(cold: &RouteResult, page: &Page, p: &mut Progress, prior: (&RouteResult, &Progress)) {
    let mut route = send(page, p, Mode::Restart);
    for (id, body) in held_route(prior.0, prior.1).accepted {
        route.accepted.entry(id).or_insert(body);
    }
    assert_carried_equivalent(cold, &route);
}
fn reemit(c: &Corpus, p: &mut Progress, prior: &RouteResult, mode: Mode) {
    let page = build(c, p);
    assert_eq!(only(&page).request_count, 5);
    let full = reference(c);
    assert_no_smaller_reemit(ROOT, prior, &send(&page, p, mode), &full, false);
}
fn grow(c: &Corpus, p: &mut Progress, prior: &RouteResult, api_first: bool) {
    let original = [
        fs::read(member(c, true)).unwrap(),
        fs::read(member(c, false)).unwrap(),
    ];
    let rows = [
        value(trace("growth", "")).unwrap(),
        value(api("growth", 20, 200)).unwrap(),
    ];
    append(c, api_first, &rows[usize::from(api_first)]);
    owed(&build(c, p), p, prior);
    append(c, !api_first, &rows[usize::from(!api_first)]);
    let next = build(c, p);
    assert_eq!(only(&next).request_count, 5);
    let full = reference(c);
    let grown = send(&next, p, Mode::Ram);
    assert_no_smaller_reemit(ROOT, prior, &grown, &full, false);
    for (side, bytes) in [true, false].into_iter().zip(original) {
        fs::write(member(c, side), bytes).unwrap();
    }
    let truncated = build(c, p);
    assert!(truncated.scan.snapshots.is_empty());
    assert!(candidate(p));
    assert_no_smaller_reemit(ROOT, &grown, &held_route(&grown, p), &full, true);
}
fn routed_progress(index: &ScanIndex, path: &Path) -> Progress {
    let mut p = Progress::load_for_index(
        index,
        path,
        &snapshot_upload_progress_path(path),
        &format!("{:064x}", 99),
        snapshot_quarantine_witness(Claude),
    )
    .unwrap();
    p.accepted_identity_buckets.bind_test_key(Some([0x42; 32]));
    p.load_identity([ROOT]).unwrap();
    p
}
fn custody(state: &Progress) -> Value {
    json!([
        state.accepted_body_witnesses,
        state.accepted_cache_states,
        state.accepted_cache_heads,
        state.accepted_identity_buckets
    ])
}
fn settled_index(c: &Corpus, page: &mut Page, p: &Progress) -> ScanIndex {
    settle_index_after_upload(&mut page.index, &page.committed, p);
    accept_upload_context_acks_for_test(
        &mut page.index,
        &page.scan.snapshots,
        &p.fresh_context_body_acks,
    );
    c.reload(&mut page.index)
}
fn only(page: &Page) -> &SnapshotItem {
    let item = body(page, ROOT).unwrap();
    assert_eq!(item.evidence_basis, Some("otel_only"));
    item
}
fn compare_modes(c: &Corpus, cold: &RouteResult, modes: &[Mode]) {
    for &mode in modes {
        let mut p = progress();
        if !matches!(mode, Mode::Ram) {
            p = restore(&p);
        }
        assert_equivalent(cold, &send(&build(c, &mut p), &mut p, mode));
    }
}
fn suppressed(page: &Page, p: &mut Progress) {
    let (result, batches, _) = upload(&page.scan.snapshots, p, ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    assert!(
        batches.is_empty(),
        "exact ACK suppresses the identical body"
    );
}
fn transcript_only(page: &Page) -> bool {
    let items = &page.scan.snapshots;
    items.iter().all(|i| i.evidence_basis.is_none())
}
fn hint_json() -> Value {
    json!({
        "source":"claude_code", "server_time":AT, "record_count_15m":0,
        "record_count_24h":0, "local_usage_reconciliation_enabled":true,
        "backfill_window_days":30, "recommended_scan_after":AT,
        "snapshot_head_cas_enabled":true, "snapshot_head_cas_required":false,
        "claude_otel_only_sessions_contract":"claude_otel_only_sessions:v1",
        "claude_otel_only_pairing_floor":"2026-08-02T06:00:00Z",
        "session_request_account_source_contract":"session_request_account_source:v1"
    })
}
fn hint() -> Hint {
    crate::snapshot_client::decode_activity_hint(hint_json()).unwrap()
}

fn progress() -> Progress {
    let mut value = restore(&e2_progress());
    value.telemetry_only = Some(
        serde_json::from_value(json!({
            "floor":nanos("2026-08-02T06:00:00Z"), "start":nanos("2026-08-02T06:30:00Z"),
            "candidates":{ROOT:{}}
        }))
        .unwrap(),
    );
    value
}
fn positive(c: &Corpus) {
    pair(
        c,
        &[
            tagged("before", 11, 7),
            tagged("after", 12, 14),
            api("gap", 13, 130),
            tagged("side-call", 14, 14),
        ],
    );
}
fn tagged(id: &str, tokens: u64, key: u32) -> Api {
    let hex = |n| char::from_digit(n, 16).unwrap();
    api_login(ROOT, id, tokens, hex(key % 6), Some(hex(key / 6)))
}
fn page(c: &Corpus, progress: &mut Progress, hint: &Hint, budget: WireBudget<'_>) -> Page {
    page_from(c, progress, hint, budget, ScanIndex::default(), 100)
}
fn empty_scan(c: &Corpus) -> SourceScanResult {
    let scanner = Scanner::capturing_identity();
    c.raw(&scanner, ScanIndex::default(), 100, false, &[]).scan
}
fn notice(c: &Corpus) -> BTreeSet<String> {
    otel::telemetry_notices::pending(&c.support).unwrap()
}
fn retained(c: &Corpus, p: &mut Progress, index: ScanIndex, limit: usize) -> Page {
    page_from(c, p, &hint(), WireBudget::default(), index, limit)
}
fn notice_progress_path(c: &Corpus, progress: &mut Progress) -> PathBuf {
    if let Some(rows) = &progress.rows {
        return snapshot_upload_progress_path(rows.index_path_for_test());
    }
    let index_path = c
        .base
        .join("snapshots/destinations")
        .join(&progress.destination_namespace_hash)
        .join("claude_code-scan-index-v3.json");
    let index = if index_path.exists() {
        ScanIndex::load(&index_path).unwrap()
    } else {
        crate::snapshots::e2_pipeline_scan_fixture::seed_index_for_test(
            &ScanIndex::default(),
            &index_path,
        )
    };
    let path = snapshot_upload_progress_path(&index_path);
    let placeholder = Progress::new(
        progress.destination_namespace_hash.clone(),
        snapshot_quarantine_witness(Claude),
    );
    let working = std::mem::replace(progress, placeholder);
    *progress =
        crate::snapshot_sync::tests::route_fixture_progress(&index, &index_path, &path, working);
    path
}

fn page_from(
    c: &Corpus,
    progress: &mut Progress,
    hint: &Hint,
    budget: WireBudget<'_>,
    index: ScanIndex,
    limit: usize,
) -> Page {
    let scanner = Scanner::capturing_identity();
    let mut page = c.raw(&scanner, index, limit, false, &[]);
    let path = if crate::snapshot_sync::telemetry_only::advertised(hint).is_some() {
        notice_progress_path(c, progress)
    } else {
        c.base.join("progress.json")
    };
    let window = progress
        .seed_telemetry(&c.support, hint, &mut page.scan, &page.index, &path)
        .unwrap();
    for item in &mut page.scan.snapshots {
        item.collected_at = AT.into();
    }
    // Native notice saves release resident hints, as the service finish then
    // reloads the current page's identity rows before applying evidence.
    progress
        .load_identity(
            page.scan
                .snapshots
                .iter()
                .map(|item| item.source_session_id.as_str()),
        )
        .unwrap();
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
fn send(page: &Page, progress: &mut Progress, mode: Mode) -> RouteResult {
    let (result, batches, _) = upload(&page.scan.snapshots, progress, ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    delivered(&page.scan.snapshots, progress, mode, batches)
}
fn delivered(
    items: &[SnapshotItem],
    p: &Progress,
    mode: Mode,
    batches: Vec<Vec<u8>>,
) -> RouteResult {
    let mut route = RouteResult::emitted(mode, Claude, batches, items);
    let mut identities = BTreeMap::new();
    for item in items {
        let id = &item.source_session_id;
        let witness = snapshot_upload_body_witness(item);
        assert!(p.contains_body(&item.snapshot_fingerprint, &witness));
        route.accepted.insert(
            id.clone(),
            oracle::Accepted {
                body: value(item).unwrap(),
                witness,
            },
        );
        identities.insert(id, p.accepted_identity_buckets.get(id));
    }
    route.accepted_identity_buckets = Some(value(identities).unwrap());
    route
}
fn held_route(prior: &RouteResult, progress: &Progress) -> RouteResult {
    for accepted in prior.accepted.values() {
        let fingerprint = accepted.body["snapshot_fingerprint"].as_str().unwrap();
        assert!(
            progress.contains_body(fingerprint, &accepted.witness),
            "native accepted ledger keeps prior body"
        );
    }
    let mut route = RouteResult::emitted(Mode::Restart, Claude, vec![], &[]);
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
        let mut cold_page = build(&c, &mut base);
        assert_eq!(cold_page.scan.snapshots.len(), 1);
        let cold = send(&cold_page, &mut base, Mode::ColdFull);
        let native = value(request(&cold_page.scan.snapshots)).unwrap();
        let golden: Value = serde_json::from_str(include_str!("receiver_golden.json")).unwrap();
        let released: Value =
            serde_json::from_str(include_str!("receiver_golden_0_1_248.json")).unwrap();
        assert_eq!(
            native, golden,
            "default serialization pins the native batch"
        );
        let mut old_wire = native.clone();
        assert_eq!(
            old_wire
                .as_object_mut()
                .unwrap()
                .remove("head_cas_contract"),
            Some(json!("snapshot_head_etag:v1"))
        );
        // Keep the released daemon sample frozen. Compare every other field.
        let mut released_without_v1 = released.clone();
        let envelope = released_without_v1["snapshots"][0]["semantic_envelope"]
            .as_object_mut()
            .unwrap();
        assert_eq!(
            envelope.remove("revision_contract_version"),
            Some(json!("snapshot_revision:v1"))
        );
        assert!(envelope.remove("revision_hash").unwrap().is_string());
        assert_eq!(
            old_wire, released_without_v1,
            "only the batch declaration and v1 revision fields change"
        );
        println!(
            "OTEL_ONLY_RECEIVER_GOLDEN {}",
            serde_json::to_string(&request(&cold_page.scan.snapshots)).unwrap()
        );
        let item = &cold_page.scan.snapshots[0];
        let components = crate::snapshots::snapshot_semantic_component_hashes(Claude, item);
        assert_eq!(
            value(&components).unwrap(),
            released["snapshots"][0]["semantic_envelope"]["component_hashes"]
        );
        let mut transcript_basis = item.clone();
        transcript_basis.evidence_basis = None;
        assert_eq!(
            components["usage_accounting"],
            crate::snapshots::snapshot_semantic_component_hashes(Claude, &transcript_basis)
                ["usage_accounting"],
            "evidence basis stays outside the usage component"
        );
        assert_eq!(cold_page.scan.snapshots[0].request_count, 4);
        assert!(!cold_page.scan.snapshots[0].request_evidence.is_empty());
        compare_modes(&c, &cold, &[Mode::Ram, Mode::DiskRestore, Mode::Restart]);
        cases::wire(&mut cold_page);
        let mut restored = restore(&base);
        quiet(&c, &mut restored, ScanIndex::default());
    });
}

fn pair_hold() {
    let (c, p, cold) = accepted_case("otel-held-matrix");
    for case in ["api", "trace", "bytes", "authority"] {
        positive(&c);
        let mut budget = WireBudget::default();
        match case {
            "api" | "trace" => super::append(&member(&c, case == "api"), "{broken\n"),
            "bytes" => budget.max_item_bytes = 128,
            _ => {
                for n in 0..33 {
                    let id = format!("over-cap-{n}");
                    append(&c, true, &tagged(&id, 11, n));
                    append(&c, false, &trace(&id, ""));
                }
            }
        }
        let mut retry = restore(&p);
        let before = caps();
        let next = page(&c, &mut retry, &hint(), budget);
        owed(&next, &retry, &cold);
        if matches!(case, "bytes" | "authority") {
            assert!(caps()[7] > before[7]);
        }
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
            let scanner = Scanner::capturing_identity();
            let index = scanner.routed(ScanIndex::default(), &c.base);
            let index_path = crate::snapshots::e2_pipeline_scan_fixture::route_of(&index).unwrap();
            let path = snapshot_upload_progress_path(&index_path);
            let mut state = routed_progress(&index, &index_path);
            state.telemetry_only = progress().telemetry_only;
            let built = build(&c, &mut state);
            send(&built, &mut state, Mode::ColdFull);
            let key = cache_session_key(ROOT);
            state
                .accepted_cache_states
                .insert(key.clone(), json!({"observations":[]}));
            state.accepted_cache_heads.insert(key, "a".repeat(64));
            state.save(&path).unwrap();
            state.load_identity([ROOT]).unwrap();
            assert!(state.accepted_identity_buckets.get(ROOT).is_some());
            fs::write(
                root.join("manifest.json"),
                encode(&(&index_path, &c.base, custody(&state))).unwrap(),
            )
            .unwrap();
            std::mem::forget(c); // Keep this synthetic store for the next process.
        } else {
            assert!(matches!(stage.as_str(), "checkpoint" | "verify"));
            let (index_path, base, expected): (PathBuf, PathBuf, Value) =
                decode(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
            let index = ScanIndex::load(&index_path).unwrap();
            let mut state = routed_progress(&index, &index_path);
            let telemetry = value(&state.telemetry_only).unwrap();
            let telemetry_path = root.join("telemetry.json");
            if stage == "checkpoint" {
                assert!(
                    candidate(&state),
                    "candidate and ACK committed before graph save"
                );
            } else {
                let expected_telemetry: Value =
                    decode(&fs::read(&telemetry_path).unwrap()).unwrap();
                assert_eq!(
                    telemetry, expected_telemetry,
                    "refused old reader preserves telemetry scheduling"
                );
            }
            let c = Corpus {
                root: base.join("projects"),
                support: base.join("support"),
                base,
                births: BTreeMap::new(),
            };
            quiet(&c, &mut state, index);
            std::mem::forget(c);
            assert_eq!(
                value(&state.telemetry_only).unwrap(),
                telemetry,
                "quiet pass preserves telemetry scheduling"
            );
            if stage == "checkpoint" {
                fs::write(&telemetry_path, encode(&telemetry).unwrap()).unwrap();
            }
            state.load_identity([ROOT]).unwrap();
            assert_eq!(
                custody(&state),
                expected,
                "all known custody survives refused old reader and current resume"
            );
        }
    });
}

fn growth() {
    for first in [true, false] {
        let c = Corpus::new("otel-growth-orders");
        positive(&c);
        let mut p = progress();
        let built = build(&c, &mut p);
        let before_ack = restore(&p);
        let cold = send(&built, &mut p, Mode::ColdFull);
        for _ in 0..2 {
            let mut retry = restore(&before_ack);
            assert_equivalent(
                &cold,
                &send(&build(&c, &mut retry), &mut retry, Mode::Restart),
            );
        }
        let path = notice_progress_path(&c, &mut p);
        p.save(&path).unwrap();
        let index_path = p.rows.as_ref().unwrap().index_path_for_test().to_owned();
        p = routed_progress(&ScanIndex::load(&index_path).unwrap(), &index_path);
        quiet(&c, &mut p, ScanIndex::default());
        assert!(notice(&c).is_empty());
        grow(&c, &mut p, &cold, first);
    }
}

/// Native holders, including off-page copies, never duplicate telemetry requests.
fn carriers() {
    for kind in [
        "main",
        "folder",
        "child",
        "forks",
        "twin",
        "resume",
        "correction",
    ] {
        eprintln!("OTEL_ONLY_ORACLE_CARRIER {kind}");
        let mut c = Corpus::new("otel-holder-table");
        positive(&c);
        let before = line_by(COPY, "before", AT, 11, OLD_WRITER);
        let relative = match kind {
            "folder" => format!("other/{COPY}.jsonl"),
            "child" => format!("other/{COPY}/subagents/agent-000.jsonl"),
            "forks" => format!("forks/{COPY}.jsonl"),
            _ => file(COPY),
        };
        let path = c.write_at(&relative, &before, "2026-08-02T07:00:00Z");
        if matches!(kind, "twin" | "resume" | "correction") {
            let session = if kind == "twin" { COPY } else { THIRD };
            let own = if kind == "resume" {
                line_by(session, "after", "2026-08-02T07:03:10Z", 12, RESUME_WRITER)
            } else {
                String::new()
            };
            c.write_at(
                &format!("other/{session}.jsonl"),
                &(line_by(session, "before", AT, 11, OLD_WRITER) + &own),
                "2026-08-02T07:03:00Z",
            );
        }
        if kind == "forks" {
            for (agent, id, tokens) in [(0, "after", 12), (1, "side-call", 14)] {
                c.write_at(
                    &format!("forks/{COPY}/subagents/agent-{agent:03}.jsonl"),
                    &(before.clone() + &line(COPY, id, AT, tokens)),
                    AT,
                );
            }
        }
        let remaining = match kind {
            "forks" => 1,
            "resume" => 2,
            _ => 3,
        };
        let mut p = progress();
        let mut index = ScanIndex::default();
        if kind == "correction" {
            let scanner = Scanner::capturing_identity();
            let old = crate::snapshots::with_max_gated_claude_revision(2, || {
                ready(&c, &scanner, index.clone(), 100, false)
            });
            index = settle(&c, &index, old, &mut e2_progress());
        }
        let mut full = retained(&c, &mut p, index.clone(), 100);
        assert_eq!(only(&full).request_count, remaining, "{kind}");
        // Main counts unproven all-copy twins twice; preserve its exact bodies.
        let mut off = hint();
        off.claude_otel_only_sessions_contract = None;
        let native = page_from(&c, &mut progress(), &off, WireBudget::default(), index, 100);
        let mut bodies = full.scan.snapshots.clone();
        bodies.retain(|i| i.evidence_basis.is_none());
        let count = total(&native) + remaining;
        let expected = (canonical(&native.scan.snapshots), count);
        assert_eq!((canonical(&bodies), total(&full)), expected, "{kind}");
        let cold = send(&full, &mut p, Mode::ColdFull);
        let saved = settled_index(&c, &mut full, &p);
        if kind != "forks" {
            let mut index = saved.clone();
            assert!(index.re_owe_effective_upload_body_witness_revision(path.to_str().unwrap(), 2));
            // An accepted same-session holder now proves the twin's copy.
            // Compare paged and full reads from that same accepted state.
            let corrected = (kind == "twin").then(|| {
                let mut state = progress();
                let reference = retained(&c, &mut state, index.clone(), 100);
                let copy = body(&reference, COPY).unwrap();
                assert_eq!(
                    (copy.request_count, copy.removed_request_count),
                    (1, Some(1))
                );
                send(&reference, &mut state, Mode::ColdFull)
            });
            let mut fresh = progress();
            let other = retained(&c, &mut fresh, index, 1);
            assert_eq!(
                only(&other).request_count,
                remaining,
                "retained off-page holder: {kind}"
            );
            let transcripts = other
                .scan
                .snapshots
                .iter()
                .filter(|i| i.evidence_basis.is_none());
            assert_eq!(transcripts.count(), 1, "singleton/twin-only page");
            if kind == "resume" {
                assert!(body(&other, THIRD).is_none(), "resumed holder is off-page");
            }
            paged(
                corrected.as_ref().unwrap_or(&cold),
                &other,
                &mut fresh,
                (&cold, &p),
            );
        }
        if kind == "correction" {
            assert_eq!(cases::relay_append(&c, &[ROOT]), (1, 1));
            let mut fresh = progress();
            let next = retained(&c, &mut fresh, saved, 1);
            assert_eq!(
                only(&next).request_count,
                remaining + 1,
                "correction then notice retains holder veto"
            );
            paged(&reference(&c), &next, &mut fresh, (&cold, &p));
        } else if kind == "forks" {
            compare_modes(&c, &cold, &[Mode::DiskRestore]);
        }
    }
}

#[test]
fn telemetry_only_oracle_matrix() {
    with_e2(|| {
        for (name, run) in [
            ("save_failure", cases::save_failure as fn()),
            ("dark", cases::dark as fn()),
            ("mixed_smoke", cases::mixed_smoke as fn()),
            ("pairing", cases::pairing as fn()),
            ("refusal", cases::refusal as fn()),
            ("presence", cases::presence as fn()),
            ("scope_hold", cases::scope_hold as fn()),
            ("takeover", cases::takeover as fn()),
            ("carriers", carriers as fn()),
            ("growth", growth as fn()),
            ("pair_hold", pair_hold as fn()),
        ] {
            eprintln!("OTEL_ONLY_ORACLE_CASE {name}");
            run();
        }
    });
}
mod cases {
    include!("oracle_cases.rs");
}

// Native telemetry bodies through the shared class packer, ACK validator and
// receiver-shaped head store; no separate upload or recovery path.
fn head_page(
    p: &mut Progress,
    items: &[SnapshotItem],
    store: &mut crate::snapshot_sync::tests::class_split_tests::HeadStore,
) -> (Result<ResumableUploadResult>, Vec<Value>) {
    crate::snapshot_sync::head_conflict_answer_tests::cycle_with_transport(
        p,
        items,
        current_unix_seconds(),
        snapshot_upload_batch_class,
        |_| false,
        |request, wire| {
            assert_eq!(request.source, Claude.api_slug());
            if request
                .snapshots
                .iter()
                .any(|item| crate::snapshot_client::declares_head_cas(item))
            {
                assert_eq!(
                    wire,
                    &value(request.wire_with_head_cas()).unwrap(),
                    "default and client wire agree"
                );
            }
            Ok(store.post(request, wire))
        },
    )
}

#[test]
fn telemetry_class_isolates_normal_claude_requests_without_changing_their_bytes() {
    with_e2(|| {
        use crate::snapshot_sync::tests::class_split_tests::HeadStore;
        let mut c = Corpus::new("otel-only-class-isolation");
        positive(&c);
        let mut p = progress();
        let telemetry = only(&build(&c, &mut p)).clone();
        c.root(COPY, &line(COPY, "transcript", AT, 11));
        let native = build(&c, &mut p);
        let mut ordinary = body(&native, COPY).unwrap().clone();
        ordinary.cache_observations = None;
        ordinary.cache_observations_state = None;
        let mut patched = ordinary.clone();
        patched.source_session_id = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5".into();
        let cache = crate::snapshot_sync::head_conflict_answer_tests::item();
        patched.cache_observations = cache.cache_observations;
        patched.cache_observations_state = cache.cache_observations_state;
        patched.snapshot_fingerprint = crate::snapshots::snapshot_fingerprint(Claude, &patched);
        let normal = [ordinary.clone(), patched.clone()];
        let mut store = HeadStore::default();
        // An existing ordinary head must still accept without CAS or a base.
        store.seed(&ordinary.source_session_id);
        let mut control_store = store.clone();
        let mut control = restore(&p);
        let (result, normal_wires) = head_page(&mut control, &normal, &mut control_store);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        let (result, wires) = head_page(&mut p, &[patched, telemetry, ordinary], &mut store);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(wires.len(), 3);
        assert_eq!(
            canonical(&wires[..2]),
            canonical(&normal_wires),
            "normal requests keep their bytes"
        );
        assert!(wires[0].get("head_cas_contract").is_none());
        assert!(wires[1].get("cache_state_ack_contract").is_some());
        assert_eq!(wires[2]["head_cas_contract"], "snapshot_head_etag:v1");
        assert!(wires[2].get("cache_state_ack_contract").is_none());
        assert!(wires[2]["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["evidence_basis"] == "otel_only"));
        for item in normal {
            assert_eq!(
                p.accepted_body_witnesses[&item.snapshot_fingerprint],
                control.accepted_body_witnesses[&item.snapshot_fingerprint]
            );
        }
    });
}

#[test]
fn telemetry_growth_uses_saved_ack_then_rebuilds_to_answer_a_conflict_without_a_patch() {
    with_e2(|| {
        use crate::snapshot_sync::head_conflict_answer_tests::envelope;
        use crate::snapshot_sync::tests::class_split_tests::HeadStore;
        for cache_enabled in [false, true] {
            for keep_base in [false, true] {
                let c = Corpus::new("otel-only-head-replacement");
                positive(&c);
                let mut p = progress();
                let first = build(&c, &mut p);
                let mut store = HeadStore::default();
                let (result, wires) = head_page(&mut p, &first.scan.snapshots, &mut store);
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                assert!(envelope(&wires[0]).get("base_head_etag").is_none());
                let key = cache_session_key(ROOT);
                let first_head = p.accepted_cache_heads[&key].clone();
                append(&c, true, &api("head-growth", 20, 200));
                append(&c, false, &trace("head-growth", ""));
                let mut grown = build(&c, &mut p);
                for item in &mut grown.scan.snapshots {
                    prepare_snapshot_cache_for_upload(item, &p, cache_enabled, false);
                    assert_eq!(item.cache_base_head_etag.as_ref(), Some(&first_head));
                    assert!(item.cache_observations.is_none());
                    assert!(item.cache_observations_state.is_none());
                }
                let (result, wires) = head_page(&mut p, &grown.scan.snapshots, &mut store);
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                assert_eq!(envelope(&wires[0])["base_head_etag"], first_head);
                let saved_head = p.accepted_cache_heads[&key].clone();
                append(&c, true, &api("conflict-growth", 21, 210));
                append(&c, false, &trace("conflict-growth", ""));
                let grown = build(&c, &mut p);
                let prior = p.accepted_body_witnesses.clone();
                // A concurrent stored head makes the saved predecessor stale.
                store.seed(ROOT);
                let (result, wires) = head_page(&mut p, &grown.scan.snapshots, &mut store);
                assert_eq!(
                    result.unwrap(),
                    ResumableUploadResult::Deferred {
                        count: 1,
                        isolated: 1,
                        identity_503: 0
                    }
                );
                assert_eq!(envelope(&wires[0])["base_head_etag"], saved_head);
                assert_eq!(p.accepted_body_witnesses, prior, "conflict credits nothing");
                let challenge = p.head_conflict_challenges[&key].clone();
                assert_eq!(p.accepted_cache_heads[&key], saved_head);
                p = restore(&p);
                if !keep_base {
                    p.accepted_cache_heads.remove(&key);
                }
                let reads = otel::evidence_read_counts_for_test();
                let mut rebuilt = build(&c, &mut p);
                assert_ne!(
                    reads,
                    otel::evidence_read_counts_for_test(),
                    "fresh evidence rebuild"
                );
                assert_eq!(only(&rebuilt).request_count, 6);
                for item in &mut rebuilt.scan.snapshots {
                    prepare_snapshot_cache_for_upload(item, &p, cache_enabled, false);
                }
                let mut projected = only(&rebuilt).clone();
                let reserve = identity_cache_wire_reserve(&projected, &p, false);
                attach_head_conflict_answers(
                    std::slice::from_mut(&mut projected),
                    &p,
                    u64::MAX,
                    |_| false,
                );
                assert_eq!(
                    crate::snapshots::claude_request_identity::item_bytes(only(&rebuilt)) + reserve,
                    crate::snapshots::claude_request_identity::item_bytes(&projected)
                );
                let (result, wires) = head_page(&mut p, &rebuilt.scan.snapshots, &mut store);
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                let answer = envelope(&wires[0]);
                assert_eq!(answer["conflict_head_challenge"], challenge.challenge);
                assert_eq!(
                    answer["rescan_from_revision_hash"],
                    challenge.stale_revision_v2_hash
                );
                assert_eq!(answer["forced_full_rescan"], true);
                assert!(answer.get("base_head_etag").is_none());
                assert!(wires[0]["snapshots"][0].get("cache_observations").is_none());
                assert!(wires[0].get("cache_state_ack_contract").is_none());
                assert!(p.accepted_cache_states.is_empty());
                assert!(p.head_conflict_challenges.is_empty());
                assert!(p.contains_body(
                    &only(&rebuilt).snapshot_fingerprint,
                    &snapshot_upload_body_witness(only(&rebuilt))
                ));
            }
        }
    });
}

/// [format] A real telemetry-only row sends no counted request position on
/// the wire, even with every one of them set on its body.
#[test]
fn telemetry_only_row_sends_no_counted_request_position() {
    with_e2(|| {
        let c = Corpus::new("otel-only-counted-positions");
        positive(&c);
        let page = build(&c, &mut progress());
        let mut item = only(&page).clone();
        item.context_request_count = Some(12);
        item.compaction_events = vec![crate::snapshots::SnapshotCompactionEvent {
            at: "2026-10-07T10:00:00Z".into(),
            before: Some(1_000),
            after: Some(100),
            request_index: Some(4),
            trigger: None,
        }];
        item.session_start = Some(Box::new(crate::snapshots::SnapshotSessionStart {
            counted_request_10_context_tokens: Some(1_000),
            counted_request_20_context_tokens: Some(2_000),
            counted_request_50_context_tokens: Some(5_000),
            ..Default::default()
        }));
        assert!(crate::snapshots::has_counted_request_positions(&item));
        let wire = encode(&request(std::slice::from_ref(&item))).unwrap();
        let wire = String::from_utf8(wire).unwrap();
        assert!(wire.contains("\"evidence_basis\":\"otel_only\""));
        for key in [
            "context_request_count",
            "request_index",
            "counted_request_10_context_tokens",
            "counted_request_20_context_tokens",
            "counted_request_50_context_tokens",
        ] {
            assert!(!wire.contains(key), "{key}");
        }
    });
}
