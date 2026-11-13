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
use std::process::Command;

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
        let mut p = if matches!(mode, Mode::Ram) {
            progress()
        } else {
            restore(&progress())
        };
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
fn files_held(c: &Corpus) {
    assert!(member(c, true).exists() && member(c, false).exists());
}
fn hint_json() -> Value {
    json!({
        "source":"claude_code", "server_time":AT, "record_count_15m":0,
        "record_count_24h":0, "local_usage_reconciliation_enabled":true,
        "backfill_window_days":30, "recommended_scan_after":AT,
        "snapshot_head_cas_required":true,
        "claude_otel_only_sessions_contract":"claude_otel_only_sessions:v1",
        "claude_otel_only_pairing_floor":"2026-08-02T06:00:00Z"
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
        println!(
            "OTEL_ONLY_RECEIVER_GOLDEN {}",
            serde_json::to_string(&request(&cold_page.scan.snapshots)).unwrap()
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
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env("OTTTO_OTEL_CARRY_STAGE", stage)
            .env("OTTTO_OTEL_CARRY_ROOT", root)
            .output()
            .unwrap();
        assert!(output.status.success(), "carry {stage}: {output:?}");
    };
    for tag in ["v0.1.239", "v0.1.244"] {
        let root = dir.join(tag);
        fs::create_dir_all(&root).unwrap();
        child("write", &root);
        child("checkpoint", &root);
        let (index_path, _, _): (PathBuf, PathBuf, Value) =
            decode(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let result = Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../scripts/test_telemetry_only_carry.py"),
            )
            .arg(tag)
            .arg(index_path)
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
            // The row owner releases resident hints after COMMIT. Compare the
            // durable row on both sides, not an evicted writer-side cache.
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
            if stage == "checkpoint" {
                assert!(
                    candidate(&state),
                    "candidate and ACK committed before graph save"
                );
                let c = Corpus {
                    root: base.join("projects"),
                    support: base.join("support"),
                    base,
                    births: BTreeMap::new(),
                };
                quiet(&c, &mut state, index);
                std::mem::forget(c);
            } else {
                assert!(state.telemetry_only.is_none());
            }
            state.load_identity([ROOT]).unwrap();
            assert_eq!(
                custody(&state),
                expected,
                "all known custody survives old save/drop"
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
        let path = c.base.join("committed.json");
        p.save(&path).unwrap();
        p = Progress::load(
            &path,
            &p.destination_namespace_hash,
            snapshot_quarantine_witness(Claude),
        )
        .unwrap();
        p.accepted_identity_buckets.bind_test_key(Some([0x42; 32]));
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
        "content-twin",
        "resume",
        "correction",
    ] {
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
        if matches!(kind, "twin" | "content-twin" | "resume" | "correction") {
            let session = if kind == "twin" { COPY } else { THIRD };
            let own = if kind == "resume" {
                line_by(session, "after", "2026-08-02T07:03:10Z", 12, RESUME_WRITER)
            } else {
                String::new()
            };
            c.write_at(
                &format!("other/{session}.jsonl"),
                &(if kind == "resume" {
                    line_by(session, "before", AT, 11, OLD_WRITER)
                } else {
                    before.clone()
                } + &own),
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
            // Native revision-2 acquisition/ACK, then revision-3 correction,
            // then a relay notice. The retained census must survive both.
            let scanner = Scanner::capturing_identity();
            let old = crate::snapshots::with_max_gated_claude_revision(2, || {
                ready(&c, &scanner, index.clone(), 100, false)
            });
            index = settle(&c, &index, old, &mut e2_progress());
        }
        let mut full = retained(&c, &mut p, index, 100);
        assert_eq!(only(&full).request_count, remaining, "{kind}");
        assert_eq!(total(&full), 4, "request conservation: {kind}");
        let cold = send(&full, &mut p, Mode::ColdFull);
        let saved = settled_index(&c, &mut full, &p);
        if kind != "forks" {
            let mut index = saved.clone();
            assert!(index.re_owe_effective_upload_body_witness_revision(path.to_str().unwrap(), 2));
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
            paged(&cold, &other, &mut fresh, (&cold, &p));
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
