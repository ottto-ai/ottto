// MONEY Design E2 benchmark at M4 size. Manual only: the "Money E2 benchmark"
// job in ci.yml (workflow_dispatch with money_e2_bench) runs each mode below
// in its own process and gates the receipts; ordinary test runs skip it
// (`#[ignore]`). Fixtures are synthetic; no provider, credential or live
// state is read.
//
// Modes (OTTTO_E2_BENCH_MODE):
// - hook: print which E2 hook this build carries (live, stub or reference).
// - prepare: write the M4-shaped corpus and its OTEL sidecars once.
// - arm: one full traversal of the corpus through the production cycle
//   (`SnapshotCycleOwner` in the source rotation: prepare_sync_source, the
//   owned native scan, finish_sync_source under source_finish), page by page
//   until the census completes, against an in-process accept-all backend;
//   then FINISHES appends to the largest file, one page each. Arm
//   (OTTTO_E2_BENCH_ARM) is reference (the pre-E2 build), dark or on.
// - reread: the switch-on lever through the production cycle: today's daemon
//   (gate off, body-witness revision 2) stamps the corpus, then the switch-on
//   (gate on, revision 3) pages until every file carries revision 3, then
//   one more whole walk must read no file.
// - history: one whole-history page (up to 2,000 files / 1 GiB) per arm on
//   a corpus stamped at revision 2, in a fresh process (peak footprint).
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use super::super::loopback_backend::{Backend, EnvVarGuard, synthetic_device, thread_cpu_us};
use std::time::{Duration, Instant, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// The pre-E2 reference build. The job swaps the candidate hook below for
/// this module in its second checkout, which has no E2 path to gate.
#[allow(dead_code)]
mod reference_hook {
    pub(super) const STATE: &str = "reference";

    pub(super) fn with_gate<T>(on: bool, run: impl FnOnce() -> T) -> T {
        assert!(!on, "the reference build has no E2 gate");
        run()
    }

    pub(super) fn with_revision<T>(_revision: u64, _run: impl FnOnce() -> T) -> T {
        unreachable!("the reference hook cannot override the compiled revision")
    }

    pub(super) fn item_storage(_items: &[crate::snapshots::SnapshotItem]) -> serde_json::Value {
        serde_json::Value::Null
    }

    pub(super) fn drain_counts() -> serde_json::Value {
        serde_json::Value::Object(Default::default())
    }

    pub(super) fn take_stages() -> serde_json::Value {
        serde_json::Value::Object(Default::default())
    }

    pub(super) fn take_diag() -> serde_json::Value {
        serde_json::Value::Object(Default::default())
    }

    pub(super) fn with_staged_births<T>(
        _births: std::collections::BTreeMap<String, u64>,
        run: impl FnOnce() -> T,
    ) -> T {
        run()
    }

    pub(super) fn with_switch_on<T>(
        on: bool,
        _support: &std::path::Path,
        run: impl FnOnce() -> T,
    ) -> T {
        assert!(!on, "the reference build has no switch-on");
        run()
    }

    /// The reread probe (switch-on) runs on the candidate build only.
    pub(super) fn with_history_byte_budget<T>(_budget: u64, _run: impl FnOnce() -> T) -> T {
        unreachable!("the reference build has no switch-on reread")
    }
}

// MONEY_E2_BENCH_HOOK_BEGIN
mod e2_hook {
    pub(super) const STATE: &str = "live";
    pub(super) use crate::snapshots::claude_request_money::e2::bench_seam::{
        drain_counts, take_diag, take_stages, with_gate, with_staged_births,
    };

    pub(super) fn with_revision<T>(revision: u64, run: impl FnOnce() -> T) -> T {
        crate::snapshots::with_max_gated_claude_revision(revision, || {
            crate::snapshot_sync::with_claude_cycle_revision(revision, run)
        })
    }

    pub(super) fn item_storage(items: &[crate::snapshots::SnapshotItem]) -> serde_json::Value {
        let folds = items.iter().filter_map(|item| item.claude_money.as_deref());
        let (mut count, mut bytes) = (0, 0usize);
        for fold in folds {
            count += 1;
            bytes += crate::heap_layout_bound::completed_bound(fold, usize::MAX).unwrap_or(0);
        }
        serde_json::json!({"folds": count, "fold_bound_bytes": bytes})
    }

    /// The gate-on arm as PR C ships it: revision 3 active (its policy row
    /// carries the request-owned literal; revision 2 denies every literal
    /// at the upload guard) and an installed, empty exclusions list
    /// (revision 3 holds all history without one).
    pub(super) fn with_switch_on<T>(
        on: bool,
        support: &std::path::Path,
        run: impl FnOnce() -> T,
    ) -> T {
        if !on {
            return run();
        }
        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            "",
        )
        .unwrap();
        with_revision(3, run)
    }

    /// The history page byte budget (the reference's seam is private).
    pub(super) fn with_history_byte_budget<T>(budget: u64, run: impl FnOnce() -> T) -> T {
        crate::snapshots::with_body_witness_adoption_byte_budget(budget, run)
    }
}
// MONEY_E2_BENCH_HOOK_END

/// The E2 counters on the native_collection_page line (design-e2-final.md).
const E2_KEYS: [&str; 7] = [
    "fold_us",
    "responses",
    "copy_skipped",
    "disclosed",
    "unmatched_1h",
    "side_call_root_fallback",
    "resolver_conflicts",
];

// M4 shape (sizing-m4.md and report-d section 3; counts only, 2026-10-25).
const FILES: usize = 13_424;
const EMPTY_FILES: usize = 2_357;
const RESPONSES: usize = 774_157;
/// The five largest request counts; the first is the largest file.
const LARGEST: [usize; 5] = [56_492, 27_018, 18_160, 14_678, 13_998];
/// Members of every family over 50 members (the M4 has 17; one of 736).
const LARGE_FAMILIES: [usize; 16] = [
    736, 244, 182, 175, 133, 110, 100, 92, 85, 78, 72, 66, 61, 57, 54, 52,
];
const MID_FAMILIES: usize = 50;
const SMALL_FAMILIES: usize = 42;
const PAIR_FAMILIES: usize = 58;
/// Request lines held by a second file (774,157 occurrences, 768,103 unique).
const COPIED_LINES: usize = 6_054;
const PREFIX_COPIES: usize = 31;
const BLOCK_COPIES: usize = 7;
const PATH_TWINS: usize = 4;
/// Copies written by a Claude Code version outside the copy allowlist: they
/// count, and are disclosed.
const UNKNOWN_WRITER_COPIES: usize = 3;
const UNKNOWN_WRITER_LINES: usize = 40;
/// Sub-agent files written in one burst (every line but the last predates
/// birth). Exempt from the copy rule; they count in full.
const BURST_AGENTS: usize = 6;
/// Transcript requests with a compatible OTEL row, and OTEL rows with no
/// transcript line (side calls).
const OTEL_MATCHED: usize = 141_108;
const OTEL_SIDE_CALLS: usize = 8_509;
/// Every this-many OTEL rows reports one more output token than its
/// transcript line: an explicit mismatch, disclosed, never attached.
const OTEL_MISMATCH_EVERY: u64 = 997;
/// 17.95 GiB over 13,715 indexed files, scaled to FILES.
const CORPUS_BYTES: f64 = 18.86e9;
/// The M4's largest transcript (256 MiB).
const LARGEST_FILE_BYTES: f64 = 268_435_456.0;
/// JSON bytes of one request's two lines before its padding.
const LINE_OVERHEAD: usize = 1_150;
/// In the draft E2 copy allowlist (2.1.309, 2.1.310).
const COPY_WRITER: &str = "2.1.309";
const UNKNOWN_WRITER: &str = "2.0.99";
const SPAN_MS: i64 = 47 * 86_400_000;
const PROJECT_GROUPS: usize = 1_261;
const FINISHES: usize = 3;
/// Root births a run stages when the file system could not take them.
const STAGED_BIRTHS: &str = "staged-root-births.json";
const MAX_PAGES: usize = 400;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_f64(name: &str) -> f64 {
    env(name).map_or(1.0, |value| value.parse().expect("a number"))
}

fn rfc3339(unix_ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_ms) * 1_000_000)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn session(file: usize) -> String {
    format!("{file:08x}-e2be-4000-8000-{file:012x}")
}

fn agent_id(file: usize) -> String {
    format!("{file:016x}")
}

fn request_id(origin: usize, k: usize) -> String {
    format!("req_e2_{origin:x}_{k:x}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Root,
    Empty,
    Agent {
        root: usize,
        burst: bool,
    },
    /// `lines` requests copied from `source` (a prefix, or a block after a
    /// bridge line), then own lines, written by `writer`.
    Copy {
        source: usize,
        lines: usize,
        block: bool,
        writer: &'static str,
    },
    /// The same session and file name as `source` in another project.
    Twin {
        source: usize,
        lines: usize,
    },
}

struct Plan {
    kind: Kind,
    own: usize,
    birth_ms: i64,
    step_ms: i64,
    pad: usize,
    otel: bool,
}

impl Plan {
    fn request_ms(&self, k: usize) -> i64 {
        self.birth_ms + 1_000 + k as i64 * self.step_ms
    }

    fn end_ms(&self) -> i64 {
        self.request_ms(self.own)
    }

    fn copied(&self) -> usize {
        match self.kind {
            Kind::Copy { lines, .. } | Kind::Twin { lines, .. } => lines,
            _ => 0,
        }
    }

    fn lines(&self) -> usize {
        self.own + self.copied()
    }
}

fn step_for(own: usize) -> i64 {
    (7 * 86_400_000 / own.max(1) as i64).clamp(1_000, 30_000)
}

/// Deterministic M4-shaped plan. `scale` shrinks counts, `bytes_scale`
/// shrinks bytes per line only.
fn plan(scale: f64, bytes_scale: f64, start: i64) -> Vec<Plan> {
    let n = |x: usize| ((x as f64 * scale).round() as usize).max(1);
    let new = |kind, birth_ms| Plan {
        kind,
        own: 0,
        birth_ms,
        step_ms: 1_000,
        pad: 0,
        otel: false,
    };
    let mut out = LARGEST
        .map(|own| Plan {
            own: n(own),
            ..new(Kind::Root, start)
        })
        .into_iter()
        .collect::<Vec<_>>();
    let mut sizes = LARGE_FAMILIES.to_vec();
    sizes.extend((0..MID_FAMILIES).map(|k| 6 + k * 13 % 45));
    sizes.extend((0..SMALL_FAMILIES).map(|k| 3 + k % 3));
    sizes.extend(std::iter::repeat(2).take(PAIR_FAMILIES));
    let families = n(sizes.len());
    let mut bursts = 0;
    for size in sizes.into_iter().take(families) {
        let root = out.len();
        let birth = start + (root as i64 * 7_919 % 997) * (SPAN_MS / 2 / 997);
        out.push(new(Kind::Root, birth));
        for member in 1..n(size).max(2) {
            bursts += 1;
            out.push(new(
                Kind::Agent {
                    root,
                    burst: bursts <= BURST_AGENTS,
                },
                birth + member as i64 * 60_000,
            ));
        }
    }
    // Copies come from the largest files (the M4's top holders).
    let copies = PREFIX_COPIES + BLOCK_COPIES + PATH_TWINS;
    let weights = (0..copies)
        .map(|i| 1.0 / (i + 2) as f64)
        .collect::<Vec<_>>();
    let weight_sum = weights.iter().sum::<f64>();
    for (i, weight) in weights.iter().enumerate() {
        let source = i % LARGEST.len();
        let lines =
            ((weight / weight_sum * n(COPIED_LINES) as f64) as usize).clamp(1, out[source].own);
        let kind = if i < PREFIX_COPIES + BLOCK_COPIES {
            Kind::Copy {
                source,
                lines,
                block: i >= PREFIX_COPIES,
                writer: COPY_WRITER,
            }
        } else {
            Kind::Twin { source, lines }
        };
        out.push(Plan {
            own: 40 + 10 * i,
            ..new(kind, 0)
        });
    }
    for i in 0..UNKNOWN_WRITER_COPIES {
        let source = i % LARGEST.len();
        out.push(new(
            Kind::Copy {
                source,
                lines: UNKNOWN_WRITER_LINES.min(out[source].own),
                block: false,
                writer: UNKNOWN_WRITER,
            },
            0,
        ));
    }
    for _ in 0..n(EMPTY_FILES) {
        let file = out.len();
        out.push(new(Kind::Empty, start + file as i64 * 60_000));
    }
    while out.len() < n(FILES) {
        let file = out.len();
        let birth = start + (file as i64 * 7_919 % 4_999) * (SPAN_MS / 2 / 4_999);
        out.push(new(Kind::Root, birth));
    }
    // Heavy-tailed own counts for every file not sized above.
    let free = (LARGEST.len()..out.len())
        .filter(|&f| matches!(out[f].kind, Kind::Root | Kind::Agent { .. }))
        .collect::<Vec<_>>();
    let fixed = out.iter().map(Plan::lines).sum::<usize>();
    let budget = n(RESPONSES).saturating_sub(fixed) as f64;
    let weight = |rank: usize, f: usize| {
        let agent = matches!(out[f].kind, Kind::Agent { .. });
        (if agent { 0.25 } else { 1.0 }) / ((rank + 10) as f64).powf(0.9)
    };
    let ranked = free
        .iter()
        .enumerate()
        .map(|(i, &f)| (f, weight(i * 7_919 % free.len(), f)))
        .collect::<Vec<_>>();
    let sum = ranked.iter().map(|(_, w)| w).sum::<f64>();
    let cap = out[LARGEST.len() - 1].own;
    for (f, w) in ranked {
        out[f].own = ((w / sum * budget) as usize).clamp(1, cap);
    }
    for p in &mut out {
        p.step_ms = step_for(p.own);
    }
    // Copies are born after the copied extent of their source.
    let births = out
        .iter()
        .map(|p| match p.kind {
            Kind::Copy { source, lines, .. } | Kind::Twin { source, lines } => {
                Some(out[source].request_ms(lines) + 120_000)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for (p, birth) in out.iter_mut().zip(births) {
        if let Some(birth) = birth {
            p.birth_ms = birth;
            p.step_ms = p.step_ms.min(5_000);
        }
    }
    // Realistic bytes per line: the corpus total over all request lines, no
    // file above the M4's largest transcript.
    let target = CORPUS_BYTES * scale * bytes_scale;
    let largest = LARGEST_FILE_BYTES * bytes_scale;
    let lines = out.iter().map(Plan::lines).sum::<usize>() as f64;
    let per = target / lines;
    let capped = |p: &Plan| p.lines() > 0 && per * p.lines() as f64 > largest;
    let capped_bytes = out.iter().filter(|p| capped(p)).count() as f64 * largest;
    let open_lines = out
        .iter()
        .filter(|p| !capped(p))
        .map(Plan::lines)
        .sum::<usize>() as f64;
    let open_per = ((target - capped_bytes) / open_lines.max(1.0)).max(0.0);
    for p in &mut out {
        let bytes = if capped(p) {
            largest / p.lines() as f64
        } else {
            open_per
        };
        p.pad = (bytes as usize).saturating_sub(LINE_OVERHEAD).max(64);
    }
    // OTEL: whole families, the 736-member one first, until the M4 share of
    // matched requests; never the largest files or copies.
    let mut family_requests = vec![0; out.len()];
    for (f, p) in out.iter().enumerate() {
        family_requests[family_root(f, &out)] += p.own;
    }
    let mut matched = 0;
    let selected = (LARGEST.len()..out.len())
        .filter(|&f| out[f].kind == Kind::Root && (f == LARGEST.len() || f % 3 == 0))
        .take_while(|&f| {
            let more = matched < n(OTEL_MATCHED);
            matched += family_requests[f];
            more
        })
        .collect::<Vec<_>>();
    for f in selected {
        out[f].otel = true;
    }
    out
}

fn family_root(file: usize, plans: &[Plan]) -> usize {
    match plans[file].kind {
        Kind::Agent { root, .. } => root,
        Kind::Twin { source, .. } => source,
        _ => file,
    }
}

fn project(file: usize, plans: &[Plan]) -> String {
    match plans[file].kind {
        Kind::Agent { root, .. } => project(root, plans),
        Kind::Twin { .. } => "-repo-twin-moved".into(),
        _ if file < LARGEST.len() => "-repo-0".into(),
        _ => format!("-repo-{}", file % PROJECT_GROUPS),
    }
}

fn path_of(root: &Path, file: usize, plans: &[Plan]) -> PathBuf {
    let dir = root.join(project(file, plans));
    match plans[file].kind {
        Kind::Agent { root, .. } => dir
            .join(session(root))
            .join("subagents")
            .join(format!("agent-{}.jsonl", agent_id(file))),
        _ => dir.join(format!("{}.jsonl", session(family_root(file, plans)))),
    }
}

struct Tokens {
    model: &'static str,
    input: u64,
    output: u64,
    cache_read: u64,
    cache_creation: u64,
}

fn tokens(origin: usize, k: usize) -> Tokens {
    let id = origin as u64 * 1_000_003 + k as u64;
    Tokens {
        model: if k % 5 == 0 {
            "claude-haiku-4-5"
        } else {
            "claude-opus-4-6"
        },
        input: 3 + id % 7,
        output: 200 + id * 13 % 1_800,
        cache_read: 40_000 + id * 997 % 110_000,
        cache_creation: 1_000 + id * 31 % 4_000,
    }
}

struct Line<'a> {
    session: &'a str,
    agent: Option<&'a str>,
    writer: &'a str,
    pad: &'a str,
}

/// One request (a tool-result user line and its assistant reply) of
/// `origin`'s `k`-th own request at `at_ms`. Returns its bytes.
fn write_request(
    out: &mut impl Write,
    line: &Line<'_>,
    origin: usize,
    k: usize,
    at_ms: i64,
) -> u64 {
    let usage = tokens(origin, k);
    let request = request_id(origin, k);
    let common = |kind: &str, uuid: String, at: i64| {
        let mut row = serde_json::json!({
            "parentUuid": null,
            "isSidechain": line.agent.is_some(),
            "userType": "external",
            "cwd": "/repo/e2-bench",
            "sessionId": line.session,
            "version": line.writer,
            "gitBranch": "main",
            "type": kind,
            "uuid": uuid,
            "timestamp": rfc3339(at),
        });
        if let Some(agent) = line.agent {
            row["agentId"] = agent.into();
        }
        row
    };
    let mut user = common("user", format!("u-{origin:x}-{k:x}"), at_ms - 1_000);
    user["message"] = serde_json::json!({"role": "user", "content": [{
        "type": "tool_result",
        "tool_use_id": format!("toolu_{origin:x}_{k:x}"),
        "content": line.pad,
    }]});
    let mut assistant = common("assistant", format!("a-{origin:x}-{k:x}"), at_ms);
    assistant["parentUuid"] = format!("u-{origin:x}-{k:x}").into();
    assistant["requestId"] = request.into();
    assistant["message"] = serde_json::json!({
        "id": format!("msg_e2_{origin:x}_{k:x}"),
        "type": "message",
        "role": "assistant",
        "model": usage.model,
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": usage.input,
            "output_tokens": usage.output,
            "cache_read_input_tokens": usage.cache_read,
            "cache_creation_input_tokens": usage.cache_creation,
            "cache_creation": {
                "ephemeral_5m_input_tokens": usage.cache_creation,
                "ephemeral_1h_input_tokens": 0
            },
            "service_tier": "standard"
        }
    });
    let mut bytes = serde_json::to_vec(&user).unwrap();
    bytes.push(b'\n');
    serde_json::to_writer(&mut bytes, &assistant).unwrap();
    bytes.push(b'\n');
    out.write_all(&bytes).unwrap();
    bytes.len() as u64
}

/// One OTEL api_request row for `request` on `root_session`, compatible with
/// its transcript line unless `mismatch`.
fn otel_row(
    root_session: &str,
    request: &str,
    usage: &Tokens,
    at_ms: i64,
    sequence: u64,
    mismatch: bool,
) -> String {
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: root_session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: rfc3339(at_ms + 500),
        model: usage.model.into(),
        effort: "high".into(),
        query_source: "user".into(),
        app_version: COPY_WRITER.into(),
        event_sequence: Some(sequence),
        cost_usd_micros: Some(20_000 + sequence * 71 % 80_000),
        input_tokens: usage.input,
        output_tokens: usage.output + u64::from(mismatch),
        cache_read_tokens: usage.cache_read,
        cache_creation_tokens: usage.cache_creation,
        request_count: 1,
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    serde_json::to_string(&row).unwrap() + "\n"
}

fn trace_row(root_session: &str, request: &str, agent: &str, at_ms: i64) -> String {
    let mut row = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        session_id: root_session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        agent_id: agent.into(),
        observed_at: rfc3339(at_ms + 500),
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    serde_json::to_string(&row).unwrap() + "\n"
}

/// Set birth (creation) and modification times. APFS keeps the explicit
/// creation time; elsewhere birth stays "now" and the manifest says so.
fn set_times(path: &Path, birth_ms: i64, modified_ms: i64) -> bool {
    let at = |ms: i64| UNIX_EPOCH + Duration::from_millis(ms as u64);
    let file = std::fs::File::options().write(true).open(path).unwrap();
    let times = std::fs::FileTimes::new()
        .set_accessed(at(modified_ms))
        .set_modified(at(modified_ms));
    #[cfg(target_os = "macos")]
    let times = {
        use std::os::macos::fs::FileTimesExt;
        times.set_created(at(birth_ms))
    };
    #[cfg(not(target_os = "macos"))]
    let _ = birth_ms;
    file.set_times(times).unwrap();
    cfg!(target_os = "macos")
}

fn projects(base: &Path) -> PathBuf {
    base.join("home").join(".claude").join("projects")
}

/// Write the corpus, its OTEL sidecars (base/otel, copied into each run's
/// support directory) and return the manifest.
fn prepare(base: &Path, scale: f64, bytes_scale: f64) -> serde_json::Value {
    let root = projects(base);
    let end_ms = (OffsetDateTime::now_utc().unix_timestamp() - 86_400) * 1_000;
    let start = end_ms - SPAN_MS;
    let plans = plan(scale, bytes_scale, start);
    // An empty Desktop store, so the census can complete.
    std::fs::create_dir_all(
        base.join("home/Library/Application Support/Claude/claude-code-sessions"),
    )
    .unwrap();
    let mut bytes = 0u64;
    let mut request_lines = 0u64;
    let mut family_sizes = BTreeMap::<usize, usize>::new();
    let mut birth_controlled = false;
    let mut root_births = BTreeMap::<String, u64>::new();
    for (file, plan) in plans.iter().enumerate() {
        let path = path_of(&root, file, &plans);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let own_session = session(family_root(file, &plans));
        let agent = matches!(plan.kind, Kind::Agent { .. }).then(|| agent_id(file));
        let writer = match plan.kind {
            Kind::Copy { writer, .. } => writer,
            _ => COPY_WRITER,
        };
        let pad = "x".repeat(plan.pad);
        let line = Line {
            session: &own_session,
            agent: agent.as_deref(),
            writer,
            pad: &pad,
        };
        let mut own = |out: &mut std::io::BufWriter<std::fs::File>,
                       range: std::ops::Range<usize>| {
            for k in range {
                let at = match plan.kind {
                    Kind::Agent { burst: true, .. } if k + 1 < plan.own => {
                        plan.birth_ms - 60_000 + k as i64
                    }
                    _ => plan.request_ms(k),
                };
                bytes += write_request(out, &line, file, k, at);
            }
        };
        let copy = |out: &mut std::io::BufWriter<std::fs::File>, source: usize, lines: usize| {
            (0..lines)
                .map(|k| write_request(out, &line, source, k, plans[source].request_ms(k)))
                .sum::<u64>()
        };
        match plan.kind {
            Kind::Root | Kind::Agent { .. } => own(&mut out, 0..plan.own),
            Kind::Empty => {
                let summary = serde_json::json!({"type": "summary", "summary": "e2 bench", "leafUuid": format!("leaf-{file:x}")});
                writeln!(out, "{summary}").unwrap();
            }
            Kind::Copy {
                source,
                lines,
                block: false,
                ..
            }
            | Kind::Twin { source, lines } => {
                let copied = copy(&mut out, source, lines);
                own(&mut out, 0..plan.own);
                bytes += copied;
            }
            Kind::Copy {
                source,
                lines,
                block: true,
                ..
            } => {
                let half = plan.own / 2;
                own(&mut out, 0..half);
                let bridge = serde_json::json!({"type": "bridge-session", "timestamp": rfc3339(plan.request_ms(half)), "sessionId": own_session});
                writeln!(out, "{bridge}").unwrap();
                let copied = copy(&mut out, source, lines);
                own(&mut out, half..plan.own);
                bytes += copied;
            }
        }
        out.flush().unwrap();
        drop(out);
        request_lines += plan.lines() as u64;
        birth_controlled = set_times(&path, plan.birth_ms, plan.end_ms());
        if !matches!(plan.kind, Kind::Agent { .. }) {
            root_births.insert(
                path.to_string_lossy().into_owned(),
                u64::try_from(i128::from(plan.birth_ms) * 1_000_000).unwrap(),
            );
        }
        // Path twins join their source's family; every other file but an
        // agent starts one.
        *family_sizes.entry(family_root(file, &plans)).or_default() += 1;
    }
    // Linux cannot set creation time: the runs stage these root births in
    // its place (test seam), so copy decisions see the planned births.
    let staged_births = if birth_controlled {
        0
    } else {
        std::fs::write(
            base.join(STAGED_BIRTHS),
            serde_json::to_vec(&root_births).unwrap(),
        )
        .unwrap();
        root_births.len()
    };
    drop(root_births);
    // OTEL sidecars, one per OTEL family root: every member request (agent
    // requests with a trace row naming the agent), explicit mismatches, and
    // side calls with no transcript line.
    let otel = base.join("otel");
    let api_dir = otel.join(crate::claude_local_otel::STORE_DIR);
    let trace_dir = otel.join("local-otel/claude-code-trace-ownership");
    std::fs::create_dir_all(&api_dir).unwrap();
    std::fs::create_dir_all(&trace_dir).unwrap();
    let otel_requests = plans
        .iter()
        .enumerate()
        .filter(|(f, p)| {
            plans[family_root(*f, &plans)].otel && matches!(p.kind, Kind::Root | Kind::Agent { .. })
        })
        .map(|(_, p)| p.own)
        .sum::<usize>()
        .max(1);
    let side_every =
        (otel_requests / ((OTEL_SIDE_CALLS as f64 * scale).round() as usize).max(1)).max(1);
    let (mut matched_rows, mut mismatch_rows, mut side_rows, mut otel_families) =
        (0u64, 0u64, 0u64, 0u64);
    let mut sequence = 0u64;
    for root in (0..plans.len()).filter(|&f| plans[f].otel) {
        otel_families += 1;
        let root_session = session(root);
        let digest = format!("{:x}.jsonl", Sha256::digest(root_session.as_bytes()));
        let mut api =
            std::io::BufWriter::new(std::fs::File::create(api_dir.join(&digest)).unwrap());
        let mut trace =
            std::io::BufWriter::new(std::fs::File::create(trace_dir.join(&digest)).unwrap());
        let members =
            std::iter::once(root)
                .chain((0..plans.len()).filter(
                    |&f| matches!(plans[f].kind, Kind::Agent { root: r, .. } if r == root),
                ));
        for member in members {
            let agent = (member != root).then(|| agent_id(member));
            for k in 0..plans[member].own {
                sequence += 1;
                let request = request_id(member, k);
                let at = match plans[member].kind {
                    Kind::Agent { burst: true, .. } if k + 1 < plans[member].own => {
                        plans[member].birth_ms - 60_000 + k as i64
                    }
                    _ => plans[member].request_ms(k),
                };
                let mismatch = sequence % OTEL_MISMATCH_EVERY == 0;
                api.write_all(
                    otel_row(
                        &root_session,
                        &request,
                        &tokens(member, k),
                        at,
                        sequence,
                        mismatch,
                    )
                    .as_bytes(),
                )
                .unwrap();
                if let Some(agent) = &agent {
                    trace
                        .write_all(trace_row(&root_session, &request, agent, at).as_bytes())
                        .unwrap();
                }
                matched_rows += u64::from(!mismatch);
                mismatch_rows += u64::from(mismatch);
                if sequence % side_every as u64 == 0 {
                    // A side call: an API request the transcript never wrote.
                    let side = format!("req_e2_side_{member:x}_{k:x}");
                    sequence += 1;
                    api.write_all(
                        otel_row(
                            &root_session,
                            &side,
                            &tokens(member, k + 1_000_000),
                            at + 200,
                            sequence,
                            false,
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                    if let Some(agent) = &agent {
                        trace
                            .write_all(trace_row(&root_session, &side, agent, at + 200).as_bytes())
                            .unwrap();
                    }
                    side_rows += 1;
                }
            }
        }
        api.flush().unwrap();
        trace.flush().unwrap();
    }
    let count = |f: &dyn Fn(&Plan) -> bool| plans.iter().filter(|p| f(p)).count();
    let lines_of = |f: &dyn Fn(&Plan) -> bool| {
        plans
            .iter()
            .filter(|p| f(p))
            .map(Plan::copied)
            .sum::<usize>()
    };
    let allowlisted_copies = lines_of(&|p| {
        matches!(
            p.kind,
            Kind::Copy {
                writer: COPY_WRITER,
                ..
            } | Kind::Twin { .. }
        )
    });
    let unknown_writer_lines = lines_of(&|p| {
        matches!(
            p.kind,
            Kind::Copy {
                writer: UNKNOWN_WRITER,
                ..
            }
        )
    });
    let twin_lines = lines_of(&|p| matches!(p.kind, Kind::Twin { .. }));
    let sizes = family_sizes.values().copied().collect::<Vec<_>>();
    let histogram = [
        (1, 1),
        (2, 2),
        (3, 5),
        (6, 50),
        (51, 500),
        (501, usize::MAX),
    ]
    .map(|(lo, hi)| sizes.iter().filter(|&&s| (lo..=hi).contains(&s)).count());
    let largest_path = path_of(&root, 0, &plans);
    let full_counts = (scale - 1.0).abs() < f64::EPSILON;
    serde_json::json!({
        "scale": scale,
        "bytes_scale": bytes_scale,
        "full_shape_counts": full_counts,
        "full_shape_bytes": full_counts && (bytes_scale - 1.0).abs() < f64::EPSILON,
        "corpus_end_unix_ms": end_ms,
        "files": plans.len(),
        "bytes": bytes,
        "request_lines": request_lines,
        "empty_files": count(&|p| p.kind == Kind::Empty),
        "agent_files": count(&|p| matches!(p.kind, Kind::Agent { .. })),
        "burst_agent_files": count(&|p| matches!(p.kind, Kind::Agent { burst: true, .. })),
        "copy_files": count(&|p| matches!(p.kind, Kind::Copy { .. })),
        "twin_files": count(&|p| matches!(p.kind, Kind::Twin { .. })),
        "allowlisted_copied_lines": allowlisted_copies,
        "unknown_writer_files": count(&|p| matches!(p.kind, Kind::Copy { writer: UNKNOWN_WRITER, .. })),
        "unknown_writer_lines": unknown_writer_lines,
        "families": sizes.len(),
        "family_members_max": sizes.iter().max(),
        "family_members_histogram_1_2_3to5_6to50_51to500_over500": histogram,
        "largest_requests": plans[0].own,
        "largest_birth_ms": plans[0].birth_ms,
        "largest_modified_ms": plans[0].end_ms(),
        "largest_bytes": std::fs::metadata(&largest_path).unwrap().len(),
        "largest_path": largest_path,
        "otel_families": otel_families,
        "otel_matched_rows": matched_rows,
        "otel_mismatch_rows": mismatch_rows,
        "otel_side_call_rows": side_rows,
        "birth_controlled": birth_controlled,
        "staged_root_births": staged_births,
        // What a correct E2 fold reports over one traversal (each file once).
        // Gate on: every copy is skipped, unknown-writer copies included
        // (owner ruling 2: an all-copied cross-session file is skipped by its
        // request ids, no writer certificate needed); disclosed is only the
        // rows whose telemetry contradicts the transcript (resolver refused).
        // No response total: gate on co-reads each twin's (large) source on
        // the twin's page, so it folds those responses twice (work, not
        // decisions; every decision counts once).
        "expected": {
            "copy_skipped": allowlisted_copies + unknown_writer_lines,
            "disclosed": mismatch_rows,
        },
        // Dark cannot co-read or stage path twins (gate-on only), so a twin's
        // copied lines are unprovable there: counted and disclosed.
        "expected_dark": {
            "responses": request_lines,
            "copy_skipped": allowlisted_copies + unknown_writer_lines - twin_lines,
            "disclosed": mismatch_rows + twin_lines as u64,
        },
    })
}

/// Physical footprint now (after asking malloc to return free pages) and
/// its lifetime peak, from task_vm_info rev3.
#[cfg(target_os = "macos")]
fn footprint_sample(relieve: bool) -> (u64, u64) {
    #[repr(C)]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
        min_address: u64,
        max_address: u64,
        ledger_phys_footprint_peak: i64,
        // The rest of rev3: the kernel fills the peak only for a full rev3 count.
        _ledger_rest: [i64; 20],
    }
    extern "C" {
        static mach_task_self_: u32;
        fn task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
        fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
    }
    let mut vm = TaskVmInfo::default();
    let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
    // SAFETY: a null zone asks every zone to return free pages; TASK_VM_INFO
    // (22) fills at most `count` words of `vm`.
    let status = unsafe {
        if relieve {
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
        task_info(
            mach_task_self_,
            22,
            (&mut vm as *mut TaskVmInfo).cast(),
            &mut count,
        )
    };
    assert_eq!(status, 0, "task_info(TASK_VM_INFO)");
    (
        vm.phys_footprint,
        vm.ledger_phys_footprint_peak.max(0) as u64,
    )
}

#[cfg(not(target_os = "macos"))]
fn footprint_sample(_relieve: bool) -> (u64, u64) {
    (0, 0)
}

fn footprint() -> (u64, u64) {
    footprint_sample(true)
}

// Bench-only attribution. Never relieve malloc in a timed window: that would
// hide retention and change the allocation pattern being measured.
#[cfg(target_os = "macos")]
fn malloc_stats() -> serde_json::Value {
    #[repr(C)]
    #[derive(Default)]
    struct Stats {
        blocks: u32,
        live: usize,
        high_water: usize,
        reserved: usize,
    }
    extern "C" {
        fn malloc_zone_statistics(zone: *mut std::ffi::c_void, stats: *mut Stats);
    }
    let mut stats = Stats::default();
    // SAFETY: null sums all zones; the SDK's malloc_statistics_t layout above.
    unsafe {
        malloc_zone_statistics(std::ptr::null_mut(), &mut stats);
    }
    serde_json::json!({"live_bytes": stats.live, "reserved_bytes": stats.reserved,
        "high_water_bytes": stats.high_water, "blocks": stats.blocks})
}
#[cfg(not(target_os = "macos"))]
fn malloc_stats() -> serde_json::Value {
    serde_json::Value::Null
}

thread_local! {
    static ATTRIBUTION: std::cell::RefCell<Option<BTreeMap<&'static str, serde_json::Value>>> = const { std::cell::RefCell::new(None) };
}

pub(in crate::snapshot_sync) fn bench_mark(label: &'static str, items: &[SnapshotItem]) {
    ATTRIBUTION.with(|cell| {
        let mut cell = cell.borrow_mut();
        let Some(marks) = cell.as_mut() else { return; };
        let (now, peak) = footprint_sample(false);
        let heap = malloc_stats();
        let sum_bound = |f: fn(&SnapshotItem) -> Option<usize>| items.iter().filter_map(f).sum::<usize>();
        marks.insert(label, serde_json::json!({"cpu_us": thread_cpu_us(), "footprint_bytes": now,
            "footprint_peak_bytes": peak, "malloc": heap, "items": items.len(),
            "occurrence_bound_bytes": sum_bound(|item| crate::heap_layout_bound::completed_bound(&item.claude_usage_occurrences, usize::MAX)),
            "bucket_bound_bytes": sum_bound(|item| crate::heap_layout_bound::completed_bound(&item.usage_buckets, usize::MAX)),
            "e2": e2_hook::item_storage(items)}));
    });
}

fn bench_timed<T>(label: &'static str, run: impl FnOnce() -> T) -> T {
    if !ATTRIBUTION.with(|cell| cell.borrow().is_some()) {
        return run();
    }
    let cpu = thread_cpu_us();
    let start = Instant::now();
    let value = run();
    let cpu = thread_cpu_us() - cpu;
    ATTRIBUTION.with(|cell| {
        if let Some(marks) = cell.borrow_mut().as_mut() {
            let row = marks
                .entry(label)
                .or_insert_with(|| serde_json::json!({"cpu_us": 0, "wall_us": 0, "calls": 0}));
            for (key, delta) in [
                ("cpu_us", cpu),
                ("wall_us", start.elapsed().as_micros() as u64),
                ("calls", 1),
            ] {
                row[key] = serde_json::json!(row[key].as_u64().unwrap() + delta);
            }
        }
    });
    value
}

/// (user + system CPU microseconds of every thread, lifetime max RSS bytes).
fn rusage() -> (u64, u64) {
    // SAFETY: getrusage fills the zeroed struct.
    let usage = unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
        usage
    };
    let us = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64;
    let rss = usage.ru_maxrss as u64 * if cfg!(target_os = "macos") { 1 } else { 1_024 };
    (us(usage.ru_utime) + us(usage.ru_stime), rss)
}

/// The production owner, observing the completed scan before its finish.
struct BenchOwner<'a> {
    last_sample: Instant,
    inner: SnapshotCycleOwner<'a>,
    census_complete: Option<bool>,
    scanned_files: usize,
    index_path: Option<PathBuf>,
}

impl crate::source_rotation::Owner for BenchOwner<'_> {
    type Source = SnapshotSource;
    type Frame = SourcePreparation;
    type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        remaining: Option<usize>,
    ) -> anyhow::Result<Option<SourcePreparation>> {
        bench_timed("owner.prepare", || self.inner.prepare(source, remaining))
    }
    fn validate(&mut self, frame: &SourcePreparation) -> anyhow::Result<()> {
        self.inner.validate(frame)
    }
    fn step(
        &mut self,
        frame: SourcePreparation,
        remaining: Option<usize>,
    ) -> crate::source_rotation::Step<SourcePreparation, Self::Completed> {
        let value = bench_timed("owner.step", || self.inner.step(frame, remaining));
        // Sample physical peaks at cooperative parser boundaries, at most 10 Hz.
        if ATTRIBUTION.with(|cell| cell.borrow().is_some())
            && self.last_sample.elapsed() >= Duration::from_millis(100)
        {
            self.last_sample = Instant::now();
            let (now, peak) = footprint_sample(false);
            ATTRIBUTION.with(|cell| {
                if let Some(marks) = cell.borrow_mut().as_mut() {
                    let prior = marks.get("scan.sample_peak").and_then(|r| r["footprint_bytes"].as_u64()).unwrap_or(0);
                    if now > prior { marks.insert("scan.sample_peak", serde_json::json!({"footprint_bytes": now, "footprint_peak_bytes": peak, "malloc": malloc_stats()})); }
                }
            });
        }
        value
    }
    fn bound(&self, frame: &SourcePreparation, limit: usize) -> Option<usize> {
        bench_timed("owner.bound", || self.inner.bound(frame, limit))
    }
    fn finish(
        &mut self,
        completed: Self::Completed,
        remaining: Option<usize>,
    ) -> anyhow::Result<()> {
        self.census_complete = Some(completed.2.census_complete);
        self.scanned_files = completed.2.scanned_file_count;
        self.index_path = Some(completed.0.index_path.clone());
        bench_mark("scan.complete", &completed.2.snapshots);
        ATTRIBUTION.with(|cell| {
            if let Some(marks) = cell.borrow_mut().as_mut() {
                let index_bound =
                    crate::heap_layout_bound::completed_bound(&completed.1, usize::MAX);
                marks.insert(
                    "scan.index",
                    serde_json::json!({"bound_bytes": index_bound}),
                );
            }
        });
        let result = bench_timed("owner.finish", || self.inner.finish(completed, remaining));
        bench_mark("finish.done", &[]);
        result
    }
    fn outcome(&mut self, source: SnapshotSource, result: anyhow::Result<()>) {
        self.inner.outcome(source, result)
    }
    fn monotonic(&self) -> Duration {
        self.inner.monotonic()
    }
    fn parked(&mut self, bytes: usize) {
        self.inner.parked(bytes)
    }
    fn retained_bound(&self, limit: usize) -> Option<usize> {
        self.inner.retained_bound(limit)
    }
    fn discard_retained(&mut self) {
        self.inner.discard_retained()
    }
    fn boundary(&mut self, busy: impl Iterator<Item = SnapshotSource>) {
        self.inner.boundary(busy)
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// One measured window's E2 counters: every collection line in it, plus what
/// the next line would have carried.
fn window_counts(records: &[serde_json::Value]) -> BTreeMap<String, u64> {
    let mut total = BTreeMap::new();
    let drained = e2_hook::drain_counts();
    for counts in records
        .iter()
        .filter(|r| r["stage"] == "native_collection_page")
        .map(|r| &r["counts"])
        .chain(std::iter::once(&drained))
    {
        for key in E2_KEYS {
            if let Some(value) = counts.get(key).and_then(serde_json::Value::as_u64) {
                *total.entry(key.to_string()).or_default() += value;
            }
        }
    }
    total
}

fn stage(records: &[serde_json::Value], name: &str) -> serde_json::Value {
    let rows = records
        .iter()
        .filter(|r| r["stage"] == name)
        .collect::<Vec<_>>();
    let sum = |field: &str| {
        rows.iter()
            .filter_map(|r| r["observation"][field].as_u64())
            .sum::<u64>()
    };
    let count = |field: &str| {
        rows.iter()
            .filter_map(|r| r["counts"][field].as_u64())
            .sum::<u64>()
    };
    serde_json::json!({
        "records": rows.len(),
        "wall_us": sum("wall_elapsed_us"),
        "cpu_us": sum("shared_process_cpu_delta_us"),
        "serialized_body_bytes": count("serialized_body_bytes"),
        "scanned_files": count("scanned_files"),
    })
}

struct Harness {
    backend: Backend,
    cadence: IdentityPipelineCadence,
    home: PathBuf,
    support: PathBuf,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    transport: crate::net_resilience::TransportCycleOutcome,
    retry: live_snapshot_retry::LiveRetryOwner,
    /// The scan index the last page saved.
    index_path: Option<PathBuf>,
    _guards: Vec<EnvVarGuard>,
    _native: crate::snapshots::claude_native_comparison::TestScope,
}

impl Harness {
    /// A fresh daemon state for one run: support, secrets and index start
    /// empty; the corpus is shared and read only.
    fn new(base: &Path, run: &Path) -> Self {
        let support = run.join("support");
        let secrets = run.join("secrets");
        assert!(!run.exists(), "every run starts from an empty state");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        copy_tree(&base.join("otel"), &support);
        let native = crate::snapshots::claude_native_comparison::enable_for_test();
        let cadence = IdentityPipelineCadence::new();
        let backend = Backend::start();
        let (device, guards) = synthetic_device(&support, &secrets, &backend.url, vec!["claude_code".into()]).unwrap();
        Self {
            client: SnapshotApiClient::new(backend.url.clone()),
            backend,
            cadence,
            home: base.join("home"),
            support,
            device,
            daemon: test_daemon("otm_test"),
            transport: crate::net_resilience::TransportCycleOutcome::default(),
            retry: live_snapshot_retry::LiveRetryOwner::closed(),
            index_path: None,
            _guards: guards,
            _native: native,
        }
    }

    /// One production cycle (one page) with its process wall/CPU, the
    /// backend's CPU taken out, and its local_resources records.
    fn page(&mut self) -> serde_json::Value {
        ATTRIBUTION.with(|cell| {
            *cell.borrow_mut() =
                (env("OTTTO_E2_BENCH_MODE").as_deref() == Some("attribution")).then(BTreeMap::new)
        });
        bench_mark("page.begin", &[]);
        self.cadence.next_due_cycle();
        let witness = self.daemon.snapshot_scan_account_witness().unwrap();
        let collection = || AgentStatusCollection {
            snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
            source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        };
        let (cpu_before, _) = rusage();
        let backend_before = self.backend.stats.cpu_us.load(Ordering::Relaxed);
        let batches_before = self.backend.stats.batches.load(Ordering::Relaxed);
        let started = Instant::now();
        let (observed, records) = crate::local_resource_diagnostics::capture(|| {
            crate::agent_status_refresh::with_test_collection(collection(), || {
                let mut failed = Vec::new();
                let mut owner = BenchOwner {
                    last_sample: Instant::now(),
                    inner: SnapshotCycleOwner {
                        retry: &mut self.retry,
                        account_witness: witness,
                        client: &self.client,
                        device: &self.device,
                        device_secret: "device-secret",
                        machine_id: "otm_test",
                        home: &self.home,
                        support_dir: &self.support,
                        daemon: &self.daemon,
                        transport_cycle: &mut self.transport,
                        failed_sources: &mut failed,
                        started: Instant::now(),
                        codex_started: None,
                    },
                    census_complete: None,
                    scanned_files: 0,
                    index_path: None,
                };
                crate::source_rotation::run(
                    &mut owner,
                    &[SnapshotSource::ClaudeCode],
                    crate::source_rotation::PARKED_BUDGET,
                );
                let observed = (
                    owner.census_complete,
                    owner.scanned_files,
                    owner.index_path.take(),
                );
                drop(owner);
                assert!(failed.is_empty(), "the Claude page failed (see stderr)");
                observed
            })
        });
        let wall_us = started.elapsed().as_micros() as u64;
        let (cpu_after, _) = rusage();
        let backend_cpu = self.backend.stats.cpu_us.load(Ordering::Relaxed) - backend_before;
        let (census_complete, scanned_files, index_path) = observed;
        let index_path = index_path.expect("the page completed its scan");
        self.index_path = Some(index_path.clone());
        let e2 = window_counts(&records);
        bench_mark("page.before_relief", &[]);
        let (footprint_now, _) = footprint();
        bench_mark("page.after_relief", &[]);
        let attribution = ATTRIBUTION.with(|cell| cell.borrow_mut().take());
        serde_json::json!({
            "attribution": attribution,
            "census_complete": census_complete,
            "scanned_files": scanned_files,
            "wall_us": wall_us,
            "process_cpu_us": cpu_after - cpu_before,
            "backend_cpu_us": backend_cpu,
            "cpu_us": (cpu_after - cpu_before).saturating_sub(backend_cpu),
            "batches": self.backend.stats.batches.load(Ordering::Relaxed) - batches_before,
            "stages": {
                "native_collection_page": stage(&records, "native_collection_page"),
                "source_finish": stage(&records, "source_finish"),
                "snapshot_batch_call": stage(&records, "snapshot_batch_call"),
            },
            "e2": e2,
            // Test builds only: disclosures and holds by reason, and the
            // E2 page passes' share of fold_us (µs; the rest is per file).
            "e2_diag": e2_hook::take_diag(),
            "e2_stages_us": e2_hook::take_stages(),
            "phys_footprint_after_bytes": footprint_now,
            "index_bytes": std::fs::metadata(&index_path).map_or(0, |m| m.len()),
        })
    }
}

/// Restores the largest file after its appends, also on a panic, so the next
/// arm reads the prepared corpus.
struct Restore {
    path: PathBuf,
    len: u64,
    birth_ms: i64,
    modified_ms: i64,
}

impl Restore {
    fn now(&self) {
        let file = std::fs::File::options()
            .write(true)
            .open(&self.path)
            .unwrap();
        file.set_len(self.len).unwrap();
        drop(file);
        set_times(&self.path, self.birth_ms, self.modified_ms);
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        self.now();
    }
}

fn sum_field(pages: &[serde_json::Value], field: &str) -> u64 {
    pages.iter().filter_map(|p| p[field].as_u64()).sum()
}

/// The reference arm runs the pre-E2 build; dark and on the candidate.
fn check_arm(arm: &str) {
    match arm {
        "reference" => assert_eq!(
            e2_hook::STATE,
            "reference",
            "the reference arm runs the pre-E2 build"
        ),
        "dark" | "on" => assert_ne!(
            e2_hook::STATE,
            "reference",
            "candidate arms run the candidate build"
        ),
        other => panic!("OTTTO_E2_BENCH_ARM must be reference, dark or on, got {other:?}"),
    }
}

fn arm(base: &Path, manifest: &serde_json::Value, arm: &str) -> serde_json::Value {
    check_arm(arm);
    let tag = env("OTTTO_E2_BENCH_TAG").unwrap_or_else(|| arm.to_string());
    let largest = PathBuf::from(manifest["largest_path"].as_str().unwrap());
    let plans_end = manifest["corpus_end_unix_ms"].as_i64().unwrap();
    let restore = Restore {
        len: manifest["largest_bytes"].as_u64().unwrap(),
        birth_ms: manifest["largest_birth_ms"].as_i64().unwrap(),
        modified_ms: manifest["largest_modified_ms"].as_i64().unwrap(),
        path: largest.clone(),
    };
    // Input reset: a previous run that died mid-append left extra bytes.
    restore.now();
    // Native stack sampling belongs only to the separate diagnostic process.
    // A missing sampler is recorded, never changes a performance receipt.
    let mut sampler = None;
    if cfg!(target_os = "macos") && env("OTTTO_E2_BENCH_MODE").as_deref() == Some("attribution") {
        if let Some(output) = env("OTTTO_E2_BENCH_OUTPUT") {
            let path = PathBuf::from(output).with_file_name(format!("e2-sample-{tag}.txt"));
            sampler = std::process::Command::new("/usr/bin/sample")
                .args([
                    std::process::id().to_string(),
                    "60".into(),
                    "10".into(),
                    "-file".into(),
                    path.to_string_lossy().into_owned(),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
        }
    }
    let footprint_start = footprint();
    let mut harness = Harness::new(base, &base.join("runs").join(&tag));
    let support = base.join("runs").join(&tag).join("support");
    let receipt = e2_hook::with_gate(arm == "on", || {
        e2_hook::with_switch_on(arm == "on", &support, || {
            let mut pages = Vec::new();
            loop {
                let page = harness.page();
                let complete = page["census_complete"] == true;
                pages.push(page);
                if complete {
                    break;
                }
                assert!(
                    pages.len() < MAX_PAGES,
                    "the traversal completes within {MAX_PAGES} pages"
                );
            }
            let (footprint_steady, _) = footprint();
            let mut traversal_e2 = BTreeMap::<String, u64>::new();
            for page in &pages {
                for (key, value) in page["e2"].as_object().unwrap() {
                    *traversal_e2.entry(key.clone()).or_default() += value.as_u64().unwrap();
                }
            }
            // One page per append to the largest file: never retained (over the
            // cache entry size), so each is a full read and a whole native finalize.
            let mut finishes = Vec::new();
            for n in 0..FINISHES {
                let mut out = std::fs::File::options()
                    .append(true)
                    .open(&largest)
                    .unwrap();
                let pad = "x".repeat(256);
                let line = Line {
                    session: &session(0),
                    agent: None,
                    writer: COPY_WRITER,
                    pad: &pad,
                };
                write_request(
                    &mut out,
                    &line,
                    0,
                    2_000_000 + n,
                    plans_end + n as i64 * 60_000,
                );
                drop(out);
                finishes.push(harness.page());
            }
            restore.now();
            let stats = &harness.backend.stats;
            let mut fingerprints = std::mem::take(&mut *stats.fingerprints.lock().unwrap());
            fingerprints.sort();
            let (_, footprint_peak) = footprint();
            let (_, max_rss) = rusage();
            serde_json::json!({
                "mode": "arm",
                "arm": arm,
                "tag": tag,
                "hook": e2_hook::STATE,
                "pages": pages.len(),
                "traversal": {
                    "wall_us": sum_field(&pages, "wall_us"),
                    "cpu_us": sum_field(&pages, "cpu_us"),
                    "process_cpu_us": sum_field(&pages, "process_cpu_us"),
                    "backend_cpu_us": sum_field(&pages, "backend_cpu_us"),
                    "e2": traversal_e2,
                },
                "page_receipts": pages,
                "finishes": finishes,
                "uploads": {
                    "batches": stats.batches.load(Ordering::Relaxed),
                    "items": stats.items.load(Ordering::Relaxed),
                    "literal_items": stats.literal_items.load(Ordering::Relaxed),
                    "body_bytes": stats.body_bytes.load(Ordering::Relaxed),
                    "fingerprint_digest": format!("{:x}", Sha256::digest(fingerprints.join("\n"))),
                },
                "index_bytes": finishes.last().and_then(|f| f["index_bytes"].as_u64()),
                "phys_footprint_start_bytes": footprint_start.0,
                "phys_footprint_steady_bytes": footprint_steady,
                "phys_footprint_peak_bytes": footprint_peak,
                "max_rss_bytes": max_rss,
            })
        })
    });
    if let Some(mut sampler) = sampler {
        let _ = sampler.wait();
    }
    receipt
}

/// Scan-level history pages (the production activation reads the compiled
/// revision, 2 here), shared by `reread` and `history`.
struct HistoryScan {
    root: PathBuf,
    collected_at: String,
}

impl HistoryScan {
    fn new(base: &Path) -> Self {
        Self {
            root: projects(base),
            collected_at: current_rfc3339(),
        }
    }

    fn scan(&self, index: &mut ScanIndex, revision: u64) -> SourceScanResult {
        index.activate_upload_context("ctx-e2-bench".into());
        index.activate_effective_upload_body_witness_revision(revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            index,
            &self.collected_at,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            crate::snapshots::MAX_BACKFILL_FILES_PER_SOURCE,
            true,
        )
        .expect("history scan")
    }

    /// One accepted page at `revision`.
    fn page(&self, index: &mut ScanIndex, revision: u64) -> SourceScanResult {
        let previous = index.clone();
        let mut scan = self.scan(index, revision);
        crate::snapshots::finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, index);
        let accepted = scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        *index = index.committable_subset(&previous, &accepted, &BTreeMap::new());
        scan
    }

    fn stamped(index: &ScanIndex, revision: u64) -> usize {
        index
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision >= revision)
            .count()
    }

    /// History sent long ago at revision 2, then an installed, empty
    /// protected list so owed history is paced. Returns the stamped files.
    fn stamp(&self, index: &mut ScanIndex, support: &Path) -> usize {
        let mut indexed = 0;
        for _ in 0..MAX_PAGES {
            drop(self.page(index, 2));
            if Self::stamped(index, 2) == indexed {
                break;
            }
            indexed = Self::stamped(index, 2);
        }
        assert!(indexed > 0, "the corpus is stamped at revision 2");
        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            "",
        )
        .unwrap();
        index.load_claude_reemission_exclusions(support);
        indexed
    }

    /// One timed revision-3 page under the caller's raised policy table.
    fn upgrade_page(&self, index: &mut ScanIndex) -> serde_json::Value {
        let owed = index
            .files
            .iter()
            .filter(|(_, entry)| entry.effective_upload_body_witness_revision < 3)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let before = Self::stamped(index, 3);
        let (cpu_before, _) = rusage();
        let started = Instant::now();
        let scan = self.page(index, 3);
        let wall_us = started.elapsed().as_micros() as u64;
        let (cpu_after, _) = rusage();
        let items = scan.snapshots.len();
        let reads = scan.scanned_file_count;
        drop(scan);
        let upgraded = Self::stamped(index, 3) - before;
        let mut upgraded_keys = owed
            .iter()
            .filter(|key| {
                index
                    .files
                    .get(*key)
                    .is_some_and(|entry| entry.effective_upload_body_witness_revision >= 3)
            })
            .map(|key| {
                key.strip_prefix(self.root.to_str().unwrap())
                    .unwrap_or(key)
                    .to_owned()
            })
            .collect::<Vec<_>>();
        upgraded_keys.sort();
        let bytes = owed
            .iter()
            .filter_map(|key| index.files.get(key))
            .filter(|entry| entry.effective_upload_body_witness_revision >= 3)
            .map(|entry| entry.size_bytes)
            .sum::<u64>();
        serde_json::json!({
            "files": upgraded,
            "reads": reads,
            "file_set_digest": format!("{:x}", Sha256::digest(upgraded_keys.join("\n"))),
            "bytes": bytes,
            "items": items,
            "wall_us": wall_us,
            "cpu_us": cpu_after - cpu_before,
        })
    }
}

/// The files below `revision`, and their bytes.
fn below(index: &ScanIndex, revision: u64) -> (u64, u64) {
    index
        .files
        .values()
        .filter(|entry| entry.effective_upload_body_witness_revision < revision)
        .fold((0, 0), |(files, bytes), entry| {
            (files + 1, bytes + entry.size_bytes)
        })
}

/// The switch-on lever through the production cycle, as PR C reaches the
/// M4: today's daemon (gate off, body-witness revision 2) sends the corpus
/// and pages until a whole walk reads no file (the first traversal's own
/// re-read included); then the switch-on (gate on, revision 3, an installed
/// empty list) pages until every file carries revision 3, and then until the
/// walk in flight and one whole walk after it complete, which must read no
/// file (no second re-read). A whole walk that upgrades no file is a stall.
/// Below full byte scale the history byte budget scales with the corpus, so
/// the page count keeps the M4 shape; request lines keep a minimum size, so
/// the largest file shrinks less: below ~0.15 its path-twin pair (one group,
/// 2 x 260 MB at full scale) no longer fits a page and never upgrades.
fn reread(base: &Path, manifest: &serde_json::Value) -> serde_json::Value {
    let run = base.join("runs").join("reread");
    let support = run.join("support");
    let files = manifest["files"].as_u64().unwrap() as usize;
    let bytes_scale = manifest["bytes_scale"].as_f64().unwrap_or(1.0);
    // HISTORY_UPGRADE_BYTES_PER_PAGE (1 GiB), scaled with the corpus bytes.
    let byte_budget = (bytes_scale < 1.0).then_some(((1u64 << 30) as f64 * bytes_scale) as u64);
    let mut harness = Harness::new(base, &run);
    let load = |harness: &Harness| {
        ScanIndex::load(
            harness
                .index_path
                .as_deref()
                .expect("a page saved the index"),
        )
        .expect("the saved index loads")
    };
    // Whole walks until one reads no file.
    let walk_until_settled = |harness: &mut Harness, pages: &mut Vec<serde_json::Value>| {
        let mut reads = 0;
        loop {
            assert!(
                pages.len() < MAX_PAGES,
                "the walks settle within {MAX_PAGES} pages"
            );
            let page = harness.page();
            reads += page["scanned_files"].as_u64().unwrap();
            let complete = page["census_complete"] == true;
            pages.push(page);
            if complete {
                if reads == 0 {
                    break;
                }
                reads = 0;
            }
        }
    };
    let mut stamp_pages = Vec::new();
    e2_hook::with_gate(false, || {
        e2_hook::with_revision(2, || walk_until_settled(&mut harness, &mut stamp_pages))
    });
    let stamp_index = load(&harness);
    assert_eq!(
        HistoryScan::stamped(&stamp_index, 3),
        0,
        "stamp walks must precede the flip"
    );
    let stamped = HistoryScan::stamped(&stamp_index, 2);
    assert_eq!(
        stamped, files,
        "every fixture file must be stamped before switch-on"
    );
    drop(stamp_index);
    e2_hook::with_gate(true, || {
        e2_hook::with_switch_on(true, &support, || {
            let mut switch_on = || {
                let mut pages = Vec::new();
                let mut before = load(&harness);
                let (mut walk_files, mut stalled) = (0, false);
                while HistoryScan::stamped(&before, 3) < stamped && pages.len() < MAX_PAGES {
                    let mut page = harness.page();
                    let after = load(&harness);
                    let (owed_before, bytes_before) = below(&before, 3);
                    let (owed_after, bytes_after) = below(&after, 3);
                    page["files"] = serde_json::json!(owed_before.saturating_sub(owed_after));
                    page["bytes"] = serde_json::json!(bytes_before.saturating_sub(bytes_after));
                    walk_files += owed_before.saturating_sub(owed_after);
                    let walk_complete = page["census_complete"] == true;
                    pages.push(page);
                    before = after;
                    if walk_complete {
                        stalled = walk_files == 0;
                        if stalled {
                            break;
                        }
                        walk_files = 0;
                    }
                }
                let complete = HistoryScan::stamped(&before, 3) >= stamped;
                let mut settle = Vec::new();
                if complete {
                    let mut walks = 0;
                    while walks < 2 {
                        assert!(settle.len() < MAX_PAGES, "the walks complete");
                        let page = harness.page();
                        walks += usize::from(page["census_complete"] == true);
                        settle.push(page);
                    }
                }
                let (remaining_files, remaining_bytes) = below(&load(&harness), 3);
                let (_, max_rss) = rusage();
                serde_json::json!({
                    "mode": "reread",
                    "hook": e2_hook::STATE,
                    "revision": "2->3 through the production cycle (PR C's body-witness lever, test seams with_max_gated_claude_revision(3) and with_claude_cycle_revision(3))",
                    "files": files,
                    "stamped_files": stamped,
                    "bytes": manifest["bytes"],
                    "byte_budget": byte_budget.unwrap_or(1 << 30),
                    "stamp_pages": stamp_pages.len(),
                    "complete": complete,
                    "stalled": stalled,
                    "remaining": { "files": remaining_files, "bytes": remaining_bytes },
                    "pages": pages.len(),
                    "reading_pages": pages.iter().filter(|page| page["files"].as_u64() > Some(0)).count(),
                    "wall_us": sum_field(&pages, "wall_us"),
                    "cpu_us": sum_field(&pages, "cpu_us"),
                    "reads": sum_field(&pages, "scanned_files"),
                    "page_receipts": pages,
                    "settle_pages": settle.len(),
                    "settle_reads": sum_field(&settle, "scanned_files"),
                    "settle_batches": sum_field(&settle, "batches"),
                    "sync_interval_s": SNAPSHOT_SYNC_INTERVAL.as_secs(),
                    "max_rss_bytes": max_rss,
                })
            };
            match byte_budget {
                Some(budget) => e2_hook::with_history_byte_budget(budget, switch_on),
                None => switch_on(),
            }
        })
    })
}

/// Fix the cohort before any arm runs. Use the candidate's actual paced
/// selection, then expose exactly those files through a hard-linked scan root.
/// A physical root restriction also works in the pre-E2 reference, where
/// revision marks do not prevent unrelated pending traversal reads. Hard links
/// preserve bytes, timestamps and opened-object birth without copying content.
fn plan_history_cohort(base: &Path) {
    let support = base.join("runs").join("history-plan");
    let scan = HistoryScan::new(base);
    let mut index = ScanIndex::default();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        e2_hook::with_gate(false, || {
            e2_hook::with_revision(2, || scan.stamp(&mut index, &support))
        });
        e2_hook::with_gate(true, || {
            e2_hook::with_revision(3, || scan.upgrade_page(&mut index))
        });
    });
    let keys = index
        .files
        .iter()
        .filter(|(_, entry)| entry.effective_upload_body_witness_revision >= 3)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    assert!(!keys.is_empty(), "the planned history page reads files");
    let root = base.join("history-cohort");
    assert!(!root.exists(), "prepare creates the history cohort once");
    let source_root = projects(base);
    let mut relative = Vec::new();
    let mut bytes = 0u64;
    for key in keys {
        let source = Path::new(&key);
        let path = source
            .strip_prefix(&source_root)
            .expect("a fixture transcript");
        let target = root.join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::hard_link(source, &target).unwrap();
        bytes += std::fs::metadata(&target).unwrap().len();
        relative.push(path.to_string_lossy().into_owned());
    }
    assert!(
        relative.len() <= 2_000 && bytes <= 1 << 30,
        "one paced history page"
    );
    std::fs::write(
        base.join("history-cohort.json"),
        serde_json::to_vec(&relative).unwrap(),
    )
    .unwrap();
}

/// One whole-history page (the paced upgrade's largest page: up to 2,000
/// files / 1 GiB) per arm, in a fresh process: stamp the same physical cohort
/// at revision 2, then one timed revision-3 page. This scanner microbenchmark
/// measures identical transcript work, not full-corpus directory/index overhead.
/// The full traversal and production-cycle reread still use the entire corpus.
fn history(base: &Path, arm: &str) -> serde_json::Value {
    check_arm(arm);
    let tag = env("OTTTO_E2_BENCH_TAG").unwrap_or_else(|| arm.to_string());
    let support = base.join("runs").join(format!("history-{tag}"));
    assert!(!support.exists(), "every run starts from an empty state");
    let scan = HistoryScan {
        root: base.join("history-cohort"),
        collected_at: current_rfc3339(),
    };
    e2_hook::with_gate(arm == "on", || {
        crate::snapshots::with_no_list_cutoff(u64::MAX, || {
            let mut index = ScanIndex::default();
            let mut stamp = || e2_hook::with_gate(false, || scan.stamp(&mut index, &support));
            let stamped = if arm == "reference" {
                stamp()
            } else {
                e2_hook::with_revision(2, stamp)
            };
            assert_eq!(
                HistoryScan::stamped(&index, 3),
                0,
                "history starts before the flip"
            );
            let cohort: std::collections::BTreeSet<String> = serde_json::from_slice(
                &std::fs::read(base.join("history-cohort.json"))
                    .expect("prepare plans the matched history cohort"),
            )
            .unwrap();
            assert_eq!(
                stamped,
                cohort.len(),
                "the stamped physical cohort is exact"
            );
            let mut keys = cohort
                .iter()
                .map(|path| format!("/{path}"))
                .collect::<Vec<_>>();
            keys.sort();
            let expected_digest = format!("{:x}", Sha256::digest(keys.join("\n")));
            let (footprint_before, _) = footprint();
            let _ = e2_hook::drain_counts();
            let _ = e2_hook::take_stages();
            let page = crate::snapshots::with_max_gated_claude_revision(3, || {
                scan.upgrade_page(&mut index)
            });
            assert!(
                page["files"].as_u64() > Some(0),
                "MONEY_E2_BENCH history page upgraded no file: {page}"
            );
            assert_eq!(
                page["files"].as_u64(),
                Some(cohort.len() as u64),
                "every arm upgrades the planned cohort"
            );
            assert_eq!(
                page["reads"], page["files"],
                "every history file is read once"
            );
            assert_eq!(
                page["file_set_digest"].as_str(),
                Some(expected_digest.as_str()),
                "every arm reads the same file set"
            );
            let stages = e2_hook::take_stages();
            let e2 = e2_hook::drain_counts();
            let (footprint_after, footprint_peak) = footprint();
            let (_, max_rss) = rusage();
            serde_json::json!({
                "mode": "history",
                "arm": arm,
                "tag": tag,
                "hook": e2_hook::STATE,
                "stamped_files": stamped,
                "page": page,
                "e2": e2,
                "stages_us": stages,
                "phys_footprint_before_bytes": footprint_before,
                "phys_footprint_after_bytes": footprint_after,
                "phys_footprint_peak_bytes": footprint_peak,
                "max_rss_bytes": max_rss,
            })
        })
    })
}

#[test]
#[ignore = "manual: the Money E2 benchmark job in ci.yml"]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn money_e2_bench_receipt() {
    let mode = env("OTTTO_E2_BENCH_MODE").unwrap_or_default();
    if mode == "hook" {
        // Own line: libtest has already printed "test <name> ... ".
        eprintln!("\nMONEY_E2_BENCH_HOOK {}", e2_hook::STATE);
        return;
    }
    let base = PathBuf::from(env("OTTTO_E2_BENCH_ROOT").expect("OTTTO_E2_BENCH_ROOT"));
    let manifest_path = base.join("manifest.json");
    let receipt = match mode.as_str() {
        "prepare" => {
            assert!(!base.join("home").exists(), "prepare into an empty root");
            let scale = env_f64("OTTTO_E2_BENCH_SCALE");
            let bytes_scale = env_f64("OTTTO_E2_BENCH_BYTES_SCALE");
            for value in [scale, bytes_scale] {
                assert!(
                    value > 0.0 && value <= 1.0,
                    "scale {value} must be in (0, 1]"
                );
            }
            let manifest = prepare(&base, scale, bytes_scale);
            std::fs::write(
                &manifest_path,
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
            let births = std::fs::read(base.join(STAGED_BIRTHS))
                .ok()
                .map(|bytes| serde_json::from_slice(&bytes).unwrap())
                .unwrap_or_default();
            e2_hook::with_staged_births(births, || plan_history_cohort(&base));
            manifest
        }
        "arm" | "attribution" | "reread" | "history" => {
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&manifest_path).expect("prepare first"))
                    .unwrap();
            let arm_name = env("OTTTO_E2_BENCH_ARM").unwrap_or_default();
            // OTTTO_E2_BENCH_STAGED_BIRTHS=0 keeps the file system's births
            // (Linux: every root then looks all-copied, a stress shape).
            let mut births = std::fs::read(base.join(STAGED_BIRTHS))
                .ok()
                .filter(|_| env("OTTTO_E2_BENCH_STAGED_BIRTHS").as_deref() != Some("0"))
                .map(|bytes| serde_json::from_slice::<BTreeMap<String, u64>>(&bytes).unwrap())
                .unwrap_or_default();
            // Linux stages births by absolute path. Preserve that evidence
            // for the relocated hard links too; full-corpus modes keep their
            // original mapping. Natural-birth Mac runs bypass this branch.
            if mode == "history" && !births.is_empty() {
                let cohort: Vec<PathBuf> = serde_json::from_slice(
                    &std::fs::read(base.join("history-cohort.json")).unwrap(),
                )
                .unwrap();
                for relative in cohort {
                    let source = projects(&base).join(&relative);
                    if let Some(&birth) = births.get(source.to_string_lossy().as_ref()) {
                        let target = base.join("history-cohort").join(relative);
                        births.insert(target.to_string_lossy().into_owned(), birth);
                    }
                }
            }
            let staged = births.len();
            let mut receipt = e2_hook::with_staged_births(births, || match mode.as_str() {
                "arm" | "attribution" => arm(&base, &manifest, &arm_name),
                "history" => history(&base, &arm_name),
                _ => reread(&base, &manifest),
            });
            receipt["staged_root_births"] = serde_json::json!(staged);
            receipt
        }
        other => panic!("unknown OTTTO_E2_BENCH_MODE {other:?}"),
    };
    let tag = format!("MONEY_E2_BENCH_{}", mode.to_uppercase());
    let mut summary = receipt.clone();
    if let Some(object) = summary.as_object_mut() {
        object.remove("page_receipts");
    }
    eprintln!("\n{tag} {}", serde_json::to_string(&summary).unwrap());
    if let Some(output) = env("OTTTO_E2_BENCH_OUTPUT") {
        std::fs::write(output, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    }
    // Exactly one separate diagnostic process per arm, after the canonical
    // receipt was captured. Never feed these CPU/footprint values to the gate.
    if mode == "arm" && env("OTTTO_E2_BENCH_TAG").is_some_and(|tag| tag.ends_with("-0")) {
        let tag = env("OTTTO_E2_BENCH_TAG").unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "snapshot_sync::tests::money_e2_bench_tests::money_e2_bench_receipt",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("OTTTO_E2_BENCH_MODE", "attribution")
            .env("OTTTO_E2_BENCH_TAG", format!("attribution-{tag}"));
        if let Some(output) = env("OTTTO_E2_BENCH_OUTPUT") {
            let path = PathBuf::from(output);
            child.env(
                "OTTTO_E2_BENCH_OUTPUT",
                path.with_file_name(format!("e2-attribution-{tag}.json")),
            );
        }
        assert!(
            child.status().expect("start diagnostic process").success(),
            "attribution process succeeds"
        );
    }
    // After the receipt line and file: the gate reads both either way.
    assert!(
        mode != "reread" || receipt["complete"] == true,
        "MONEY_E2_BENCH reread incomplete after {} pages (stalled={}): remaining {}",
        receipt["pages"],
        receipt["stalled"],
        receipt["remaining"]
    );
    assert!(
        mode != "reread" || receipt["settle_reads"] == 0,
        "MONEY_E2_BENCH reread read {} files again in the {} pages after it completed",
        receipt["settle_reads"],
        receipt["settle_pages"]
    );
}
