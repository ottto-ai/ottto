//! The real-scale gate: state size, memory, CPU and writes of a daily run
//! over a fixture shaped like one developer Mac's last 60 days of
//! transcripts (counts and sizes only, no content).
//!
//! Run by hand, in release, one phase per process (each phase measures its
//! own peak memory):
//!
//! ```text
//! export COMPOSITION_SCALE_DIR=<an empty folder>
//! run() { COMPOSITION_SCALE_PHASE=$1 COMPOSITION_SCALE_DAY=${2:-1} cargo test --release \
//!   -p ottto-service --lib real_scale_gate -- --ignored --nocapture; }
//! run build; run prepare 1; run daily 1; run prepare 2; run daily 2; run load
//! ```
//!
//! - `build`: 60 days of transcripts in the main scope (8000 Claude
//!   transcripts, a quarter of them subagents; 440 Codex rollouts) and an idle
//!   second scope, each last modified on its last day, then one run that
//!   reads them all (the catch-up a long install would have spread over 60
//!   days).
//! - `prepare`: one day of new lines: new transcripts at real sizes, lines
//!   appended to sessions still going, and one Codex rollout of about
//!   700 MiB.
//! - `daily`: the daily run over that day, with uploads. The first daily
//!   run compacts idle files in changed shards; the second shows a steady day.
//! - `load`: the memory each scope's state takes once loaded.

use super::*;
use std::io::{BufWriter, Write};

/// Quantiles of a per-transcript count: (fraction, value), increasing.
type Quantiles = &'static [(f64, f64)];

// Measured on one Mac (60 days; 11,054 Claude transcripts, 700 sampled;
// 439 Codex rollouts).
const TOOL_USES: Quantiles = &[
    (0.0, 1.0),
    (0.5, 42.0),
    (0.75, 81.0),
    (0.9, 142.0),
    (0.99, 638.0),
    (1.0, 1500.0),
];
const DISTINCT_FILES: Quantiles = &[
    (0.0, 1.0),
    (0.5, 18.0),
    (0.75, 41.0),
    (0.9, 76.0),
    (0.99, 189.0),
    (1.0, 400.0),
];
const ATTACHMENTS: Quantiles = &[
    (0.0, 2.0),
    (0.5, 57.0),
    (0.75, 108.0),
    (0.9, 170.0),
    (0.99, 566.0),
    (1.0, 1500.0),
];
const DAYS: Quantiles = &[(0.0, 1.0), (0.9, 1.0), (0.99, 4.0), (1.0, 8.0)];
/// Transcript sizes, KiB (Claude).
const CLAUDE_KIB: Quantiles = &[
    (0.0, 8.0),
    (0.5, 833.0),
    (0.75, 1387.0),
    (0.9, 2105.0),
    (0.99, 8515.0),
    (1.0, 20000.0),
];
/// Rollout sizes, KiB (Codex), below the few very large ones.
const CODEX_KIB: Quantiles = &[
    (0.0, 8.0),
    (0.5, 1173.0),
    (0.75, 2313.0),
    (0.9, 3991.0),
    (1.0, 8192.0),
];

/// Attachment types, as a session's lines carry them (about 13 kinds each).
const ATTACHMENT_TYPES: [&str; 16] = [
    "task_reminder",
    "todo_reminder",
    "hook_success",
    "hook_additional_context",
    "file",
    "edited_text_file",
    "skill_listing",
    "deferred_tools_delta",
    "date_change",
    "plan_mode",
    "critical_system_reminder",
    "already_read_file",
    "queued_command",
    "task_status",
    "mcp_instructions_delta",
    "async_hook_response",
];
const ADDON_SERVERS: [(&str, &str); 4] = [
    ("github", "search_code"),
    ("linear", "list_issues"),
    ("claude_in_chrome", "navigate"),
    ("docs", "fetch_page"),
];

/// Distinct repository files the sessions read from.
const POOL: usize = 4000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn draw(&mut self, quantiles: Quantiles) -> u64 {
        let u = self.unit();
        for pair in quantiles.windows(2) {
            let ((p0, v0), (p1, v1)) = (pair[0], pair[1]);
            if u <= p1 {
                let t = if p1 > p0 { (u - p0) / (p1 - p0) } else { 1.0 };
                return (v0 + t * (v1 - v0)).round() as u64;
            }
        }
        quantiles.last().map_or(0, |last| last.1 as u64)
    }

    /// A repository file: a few are read by most sessions, most by few.
    fn pool_file(&mut self) -> usize {
        ((POOL as f64).powf(self.unit()) as usize).saturating_sub(1)
    }
}

/// A session id shaped like a real one (36 characters), fixed by `seed`.
fn uuid(seed: u64) -> String {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        rng.next() as u32,
        rng.next() as u16,
        rng.next() & 0xfff,
        (rng.next() & 0x3fff) | 0x8000,
        rng.next() & 0xffff_ffff_ffff
    )
}

/// Seeds of each group's session ids.
const MAIN: u64 = 1_000_000;
const IDLE: u64 = 2_000_000;
const DAILY: u64 = 3_000_000;
const CODEX: u64 = 4_000_000;
const DAILY_CODEX: u64 = 5_000_000;

/// Daily runs the build prepares files for.
const DAILY_RUNS: i64 = 2;

fn daily_seed(group: u64, day: i64, n: usize) -> u64 {
    group + day as u64 * 100_000 + n as u64
}

/// A project folder name as Claude Code writes it (the workspace path with
/// separators replaced), so transcript paths are as long as real ones
/// (about 180 characters).
const PROJECT: &str =
    "-Users-developer-src-github-com-example-org-example-repository-with-a-long-name-and-worktree";

/// Set a file's modification time to `secs` (unix seconds).
fn set_mtime(path: &Path, secs: i64) {
    let time = std::time::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

fn pool_name(index: usize) -> String {
    match index {
        0 => "AGENTS.md".to_string(),
        1 => "Cargo.toml".to_string(),
        index if index % 7 == 0 => format!("docs/area{}/notes{index}.md", index % 31),
        index => format!("crates/part{}/src/module{index}.rs", index % 53),
    }
}

/// Days and clock shared by the phases.
#[derive(serde::Serialize, serde::Deserialize)]
struct Clock {
    /// When the build started (unix seconds): every fixture line is dated
    /// after it, so nothing reads as copied history.
    now0: i64,
}

impl Clock {
    /// Unix seconds at the end of fixture day `offset`.
    fn end_of(&self, offset: i64) -> i64 {
        // Place fixture mtimes 20 minutes before the next UTC day, even
        // when the simulated next-day wake occurs just after midnight.
        self.day(offset + 1)
            .midnight()
            .assume_utc()
            .unix_timestamp()
            - 20 * 60
    }

    fn day(&self, offset: i64) -> Date {
        (OffsetDateTime::from_unix_timestamp(self.now0).unwrap() + time::Duration::days(offset))
            .date()
    }

    /// The build's run: the day after the 60 fixture days.
    fn build_now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.now0).unwrap() + time::Duration::days(61)
    }

    /// The daily run `day` days after the build's.
    fn daily_now(&self, day: i64) -> OffsetDateTime {
        self.build_now() + time::Duration::days(day)
    }
}

fn stamp(day: Date, second: u64) -> String {
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        super::super::super::measure::date_ymd(day),
        (second / 3600) % 24,
        (second / 60) % 60,
        second % 60
    )
}

struct Writer {
    out: BufWriter<File>,
    bytes: u64,
}

impl Writer {
    fn open(path: &Path, append: bool) -> Self {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = fs::OpenOptions::new()
            .create(true)
            .append(append)
            .write(true)
            .truncate(!append)
            .open(path)
            .unwrap();
        Self {
            out: BufWriter::new(file),
            bytes: 0,
        }
    }

    fn line(&mut self, value: &Value) {
        let text = value.to_string();
        self.out.write_all(text.as_bytes()).unwrap();
        self.out.write_all(b"\n").unwrap();
        self.bytes += text.len() as u64 + 1;
    }
}

/// One Claude transcript's lines (or a day of lines appended to one).
struct ClaudeSession<'a> {
    session: &'a str,
    sidechain: bool,
    cwd: &'a str,
    first_day: Date,
    days: u64,
    tool_uses: u64,
    attachments: u64,
    files: Vec<usize>,
    output_chars: usize,
    /// Distinguishes appended lines' ids.
    tag: &'a str,
}

fn write_claude(out: &mut Writer, rng: &mut Rng, shape: &ClaudeSession) {
    let output = "x".repeat(shape.output_chars);
    let file = |rng: &mut Rng| -> String {
        let index = shape.files[rng.below(shape.files.len() as u64) as usize];
        pool_name(index)
    };
    let common = |kind: &str, n: u64, day: Date| {
        json!({"type": kind, "uuid": format!("{}-{}-{n}-{kind}", shape.session, shape.tag),
            "sessionId": shape.session, "isSidechain": shape.sidechain, "cwd": shape.cwd,
            "timestamp": stamp(day, n * 7 % 86_000)})
    };
    let day_of_use = |n: u64| {
        shape.first_day + time::Duration::days((n * shape.days / shape.tool_uses.max(1)) as i64)
    };
    let mut record = common("attachment", 0, shape.first_day);
    record["attachment"] = json!({"type": "instructions", "files": [
        {"type": "Project", "path": format!("{}/CLAUDE.md", shape.cwd), "content": "p".repeat(2_000)},
        {"type": "AutoMem", "path": "/memory/MEMORY.md", "content": "m".repeat(1_500)}]});
    out.line(&record);
    let every = (shape.tool_uses / shape.attachments.max(1)).max(1);
    let mut attachments_left = shape.attachments;
    for n in 1..=shape.tool_uses {
        let day = day_of_use(n);
        if n % 20 == 1 {
            let mut prompt = common("user", n * 10, day);
            prompt["message"] =
                json!({"role": "user", "content": "please continue with the next step"});
            out.line(&prompt);
        }
        if attachments_left > 0 && n % every == 0 {
            attachments_left -= 1;
            let kind = ATTACHMENT_TYPES[rng.below(13) as usize + (n % 4) as usize];
            let mut record = common("attachment", n * 10 + 1, day);
            record["attachment"] = match kind {
                "file" | "edited_text_file" | "already_read_file" => json!({"type": kind,
                    "filename": format!("{}/{}", shape.cwd, file(rng)), "content": "c".repeat(400)}),
                "queued_command" => {
                    json!({"type": kind, "commandMode": "prompt", "prompt": "and also this"})
                }
                kind => json!({"type": kind, "content": "r".repeat(300)}),
            };
            out.line(&record);
        }
        let pick = rng.below(1000);
        let id = format!("t{}-{n}", shape.tag);
        let (name, input) = if pick < 15 {
            let (server, tool) = ADDON_SERVERS[rng.below(4) as usize];
            (format!("mcp__{server}__{tool}"), json!({"q": "x"}))
        } else if pick < 35 {
            (
                "Read".to_string(),
                json!({"file_path": format!("{}/{}", shape.cwd, file(rng))}),
            )
        } else if pick < 140 {
            let tool = ["Edit", "Write", "TodoWrite", "Grep", "Glob"][rng.below(5) as usize];
            (tool.to_string(), json!({"pattern": "x"}))
        } else {
            let (a, b) = (file(rng), file(rng));
            let command = match rng.below(10) {
                0..=2 => format!("cat {a}"),
                3 => format!("sed -n 1,120p {a}"),
                4 => format!("nl -ba {a} | sed -n 40,90p"),
                5 => "rg -n \"fn \" crates".to_string(),
                6 => "git status --short".to_string(),
                7 => format!("git diff -- {a}"),
                8 => "cargo test -p crate-a".to_string(),
                _ => format!("head -50 {a} && tail -20 {b}"),
            };
            ("Bash".to_string(), json!({"command": command}))
        };
        let mut call = common("assistant", n * 10 + 2, day);
        call["message"] = json!({"id": format!("m{}-{n}", shape.tag),
            "content": [{"type": "tool_use", "id": id, "name": name, "input": input}]});
        out.line(&call);
        let mut result = common("user", n * 10 + 3, day);
        result["message"] =
            json!({"content": [{"type": "tool_result", "tool_use_id": id, "content": output}]});
        out.line(&result);
    }
}

/// One Codex rollout's lines: code cells whose commands read files, some
/// add-on calls, prompts.
#[allow(clippy::too_many_arguments)]
fn write_codex(
    out: &mut Writer,
    rng: &mut Rng,
    session: &str,
    cwd: &str,
    day: Date,
    cells: u64,
    output_chars: usize,
    with_head: bool,
) {
    let output = "y".repeat(output_chars);
    let at = |n: u64| stamp(day, n * 3 % 86_000);
    if with_head {
        out.line(&json!({"timestamp": at(0), "type": "session_meta", "payload": {"id": session, "cwd": cwd}}));
        out.line(&json!({"timestamp": at(0), "type": "response_item", "payload": {"type": "message", "role": "developer",
            "content": [{"type": "input_text", "text": format!("<environment_context>{cwd}</environment_context>")},
                {"type": "input_text", "text": "d".repeat(3_000)}]}}));
    }
    let files: Vec<usize> = (0..rng.draw(DISTINCT_FILES))
        .map(|_| rng.pool_file())
        .collect();
    for n in 1..=cells {
        if n % 15 == 1 {
            out.line(&json!({"timestamp": at(n), "type": "response_item", "payload": {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "next step please"}]}}));
        }
        let call_id = format!("{session}-c{n}-{}", rng.below(1 << 40));
        let path = pool_name(files[rng.below(files.len() as u64) as usize]);
        out.line(&json!({"timestamp": at(n), "type": "response_item", "payload": {"type": "custom_tool_call",
            "name": "exec", "call_id": call_id, "input": format!("tools.exec_command({{cmd: 'cat {path}'}})")}}));
        out.line(&json!({"timestamp": at(n), "type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "command": ["zsh", "-lc", format!("cat {path}")], "cwd": cwd,
            "parsed_cmd": [{"type": "read", "path": path}], "aggregated_output": output}}}));
        if rng.below(50) == 0 {
            let (server, tool) = ADDON_SERVERS[rng.below(4) as usize];
            out.line(&json!({"timestamp": at(n), "type": "event_msg", "payload": {"type": "item_completed", "item": {
                "type": "McpToolCall", "server": server, "tool": tool,
                "result": {"content": [{"type": "text", "text": "result"}]}}}}));
        }
        out.line(&json!({"timestamp": at(n), "type": "response_item", "payload": {"type": "custom_tool_call_output",
            "call_id": call_id, "output": output}}));
        if n % 5 == 0 {
            out.line(&json!({"timestamp": at(n), "type": "response_item", "payload": {"type": "agent_message", "content": []}}));
        }
    }
}

/// A transcript shape drawn from the measured quantiles.
fn claude_shape<'a>(
    rng: &mut Rng,
    session: &'a str,
    sidechain: bool,
    cwd: &'a str,
    first_day: Date,
    tag: &'a str,
    output_chars: usize,
) -> ClaudeSession<'a> {
    let files = (0..rng.draw(DISTINCT_FILES).max(1))
        .map(|_| rng.pool_file())
        .collect();
    ClaudeSession {
        session,
        sidechain,
        cwd,
        first_day,
        days: rng.draw(DAYS).max(1),
        tool_uses: rng.draw(TOOL_USES).max(1),
        attachments: rng.draw(ATTACHMENTS),
        files,
        output_chars,
        tag,
    }
}

struct Layout {
    dir: PathBuf,
}

impl Layout {
    fn claude(&self) -> PathBuf {
        self.dir.join("claude")
    }
    fn codex(&self) -> PathBuf {
        self.dir.join("codex")
    }
    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }
    fn workspace(&self, idle: bool) -> String {
        let name = if idle { "workspace-idle" } else { "workspace" };
        self.dir.join(name).to_string_lossy().into_owned()
    }
    /// A Claude transcript (a subagent's when `agent` is set).
    fn claude_file(&self, scope: &str, session: &str, agent: Option<usize>) -> PathBuf {
        let project = self
            .claude()
            .join("projects")
            .join(format!("{PROJECT}-{scope}"));
        match agent {
            Some(n) => project.join(format!("{session}/subagents/agent-a{n:016x}.jsonl")),
            None => project.join(format!("{session}.jsonl")),
        }
    }
    fn codex_file(&self, session: &str) -> PathBuf {
        self.codex().join(format!(
            "sessions/2026/01/01/rollout-2026-01-01T00-00-00-{session}.jsonl"
        ))
    }
    fn daily_claude(&self, day: i64, n: usize) -> PathBuf {
        self.claude_file("main", &uuid(daily_seed(DAILY, day, n)), None)
    }
    fn daily_codex(&self, day: i64, n: usize) -> PathBuf {
        self.codex_file(&uuid(daily_seed(DAILY_CODEX, day, n)))
    }
}

/// An uploader that keeps only the payload sizes.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Counting {
    uploads: u64,
    bytes: u64,
}

impl Uploader for Counting {
    fn upload(&mut self, request: &Value) -> anyhow::Result<UploadReceipt> {
        self.uploads += 1;
        self.bytes += request.to_string().len() as u64;
        Ok(UploadReceipt::default())
    }
}

fn max_rss_bytes() -> u64 {
    // SAFETY: getrusage fills the struct it is given.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}

type ScaleResults = Vec<(Source, SourceStats, Counting)>;

fn run_both(layout: &Layout, now: OffsetDateTime) -> ScaleResults {
    let mut out = Vec::new();
    for (source, root) in [
        (Source::Claude, layout.claude()),
        (Source::Codex, layout.codex()),
    ] {
        fs::create_dir_all(&root).unwrap();
        let mut resolver = FolderResolver::default();
        let mut run = Run {
            start_verdicts: Default::default(),
            state_dir: layout.state(),
            now,
            deadline: Instant::now() + RUN_WALL_CAP,
            resolver: &mut resolver,
            repair_left: REPAIR_BYTES_PER_DAY,
        };
        let mut counting = Counting::default();
        let target = UploadTarget {
            uploader: &mut counting,
            machine_id: "machine-scale",
            destination: "device|machine|api",
            labels_enabled: true,
            details_enabled: false,
        };
        let scan = || run_source(&mut run, source, std::slice::from_ref(&root), Some(target));
        let stats = if std::env::var_os("COMPOSITION_SCALE_HEAP").is_some() {
            let (stats, heap) = crate::retry_allocation_probe::measure(scan);
            println!(
                "[heap] {}: requested_live={} usable_live={} requested_peak={} usable_peak={}",
                source.label(),
                heap.requested_live,
                heap.usable_live,
                heap.requested_peak,
                heap.usable_peak
            );
            stats
        } else {
            scan()
        };
        out.push((source, stats, counting));
    }
    out
}

/// Every state file: (name, bytes, modified).
fn state_files(layout: &Layout) -> BTreeMap<String, (u64, std::time::SystemTime)> {
    let mut files = BTreeMap::new();
    for dir in [layout.state(), layout.state().join("scopes")] {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let metadata = entry.metadata().unwrap();
            if metadata.is_file() {
                files.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    (metadata.len(), metadata.modified().unwrap()),
                );
            }
        }
    }
    files
}

fn report(
    phase: &str,
    layout: &Layout,
    baseline: u64,
    results: &[(Source, SourceStats, Counting)],
) {
    // Conservative peak bound: count the worker as well as the parent,
    // even if their individual high-water marks did not overlap.
    let worker_peak = if phase == "scan" && std::env::var_os("COMPOSITION_SCALE_INLINE").is_none() {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: getrusage fills the provided record; the worker was reaped.
        unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) };
        usage.ru_maxrss as u64 * if cfg!(target_os = "macos") { 1 } else { 1024 }
    } else {
        0
    };
    let peak = max_rss_bytes() + worker_peak;
    let (state_read, written) = super::super::checkpoint::IO_BYTES.with(|io| io.get());
    println!(
        "[{phase}] bytes_read={} bytes_written={} bytes_fsynced={}",
        state_read, written, written
    );
    println!(
        "[{phase}] rss_after_mib={:.2} rss_after_above_start_mib={:.2}",
        rss_bytes() as f64 / 1048576.0,
        rss_bytes().saturating_sub(baseline) as f64 / 1048576.0
    );
    println!(
        "[{phase}] peak_rss_above_start_mib={:.1} (start {:.1} MiB, peak {:.1} MiB)",
        (peak.saturating_sub(baseline)) as f64 / 1048576.0,
        baseline as f64 / 1048576.0,
        peak as f64 / 1048576.0
    );
    for (source, stats, counting) in results {
        println!(
            "[{phase}] {}: bytes_new_mib={:.1} bytes_repair_mib={:.1} files_read={} lines={} cpu_s={:.2} wall_s={:.2} \
             peak_accounted_mib={:.1} state_written_mib={:.2} scopes_committed={} uploads={} upload_kib={:.1} \
             unnamed_files={} name_lookups_skipped={} cut={}",
            source.label(),
            stats.bytes_new as f64 / 1048576.0,
            stats.bytes_repair as f64 / 1048576.0,
            stats.files_read,
            stats.lines.lines,
            stats.cpu_micros as f64 / 1e6,
            stats.wall_micros as f64 / 1e6,
            stats.peak_accounted_bytes as f64 / 1048576.0,
            stats.state_bytes as f64 / 1048576.0,
            stats.scopes_committed,
            counting.uploads,
            counting.bytes as f64 / 1024.0,
            stats.lines.unnamed_files,
            stats.name_lookups_skipped,
            stats.cut,
        );
    }
    for (name, (bytes, _)) in state_files(layout) {
        println!(
            "[{phase}] state {name}: {:.2} MiB",
            bytes as f64 / 1048576.0
        );
    }
}

#[test]
#[ignore]
fn real_scale_gate() {
    let Ok(dir) = std::env::var("COMPOSITION_SCALE_DIR") else {
        println!("set COMPOSITION_SCALE_DIR and COMPOSITION_SCALE_PHASE");
        return;
    };
    let phase = std::env::var("COMPOSITION_SCALE_PHASE").unwrap_or_default();
    let number = |name: &str, default: usize| -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    let claude_files = number("COMPOSITION_SCALE_CLAUDE_FILES", 8000);
    let idle_files = number("COMPOSITION_SCALE_IDLE_FILES", 400);
    let codex_files = number("COMPOSITION_SCALE_CODEX_FILES", 440);
    let daily_claude = number("COMPOSITION_SCALE_DAILY_CLAUDE", claude_files / 60);
    let daily_codex = number("COMPOSITION_SCALE_DAILY_CODEX", 7);
    let big_mib = number("COMPOSITION_SCALE_BIG_CODEX_MIB", 700);
    // Which daily run `prepare` and `daily` are for (1 or 2).
    let day = number("COMPOSITION_SCALE_DAY", 1).clamp(1, DAILY_RUNS as usize) as i64;
    let layout = Layout {
        dir: PathBuf::from(dir),
    };
    let clock_path = layout.dir.join("clock.json");
    let baseline = rss_bytes();
    super::super::checkpoint::IO_BYTES.with(|io| io.set((0, 0)));
    if phase == "scan" {
        let clock: Clock = serde_json::from_slice(&fs::read(&clock_path).unwrap()).unwrap();
        let now = if std::env::var("COMPOSITION_SCALE_BUILD").is_ok() {
            clock.build_now()
        } else {
            clock.daily_now(day)
        };
        if std::env::var_os("COMPOSITION_SCALE_CHILD").is_some() {
            serde_json::from_reader::<_, ()>(std::io::stdin().lock()).unwrap();
            super::super::harvest::set_utility_qos();
            let results = run_both(&layout, now);
            let io = super::super::checkpoint::IO_BYTES.with(|io| io.get());
            super::super::harvest::write_worker_reply(&(results, io)).unwrap();
            return;
        }
        if std::env::var_os("COMPOSITION_SCALE_HEAP").is_some() {
            report_allocator("before");
        }
        let cpu = process_cpu_micros(libc::RUSAGE_SELF) + process_cpu_micros(libc::RUSAGE_CHILDREN);
        let started = Instant::now();
        let results = if std::env::var_os("COMPOSITION_SCALE_INLINE").is_some() {
            run_both(&layout, now)
        } else {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["real_scale_gate", "--ignored", "--nocapture"])
                .env("COMPOSITION_SCALE_CHILD", "1");
            let (results, io): (ScaleResults, (u64, u64)) =
                super::super::harvest::run_worker_process(&mut command, &()).unwrap();
            super::super::checkpoint::IO_BYTES.with(|counter| counter.set(io));
            results
        };
        super::super::harvest::release_memory();
        let cpu =
            process_cpu_micros(libc::RUSAGE_SELF) + process_cpu_micros(libc::RUSAGE_CHILDREN) - cpu;
        println!(
            "[scan] total_cpu_s={:.3} total_wall_s={:.3}",
            cpu as f64 / 1e6,
            started.elapsed().as_secs_f64()
        );
        if std::env::var_os("COMPOSITION_SCALE_HEAP").is_some() {
            report_allocator("after");
        }
        report("scan", &layout, baseline, &results);
        return;
    }
    match phase.as_str() {
        "build" => {
            assert!(!layout.state().exists(), "build into an empty folder");
            // Reuse an explicit fixture clock when recreating transcripts
            // for a saved daily checkpoint, without replaying earlier scans.
            let clock: Clock = fs::read(&clock_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Clock {
                    now0: OffsetDateTime::now_utc().unix_timestamp(),
                });
            fs::create_dir_all(&layout.dir).unwrap();
            fs::write(&clock_path, serde_json::to_vec(&clock).unwrap()).unwrap();
            for workspace in [layout.workspace(false), layout.workspace(true)] {
                fs::create_dir_all(workspace).unwrap();
            }
            // Pins first, so every fixture file is born after the last scan.
            run_both(
                &layout,
                OffsetDateTime::from_unix_timestamp(clock.now0).unwrap(),
            );
            let mut rng = Rng(0x5eed_cafe_f00d_0001);
            let mut written = 0u64;
            for (scope, count, idle, seed) in [
                ("main", claude_files, false, MAIN),
                ("idle", idle_files, true, IDLE),
            ] {
                let cwd = layout.workspace(idle);
                for n in 0..count {
                    // A quarter are subagents of the session before them.
                    let sidechain = n % 4 == 3;
                    let session = uuid(seed + if sidechain { n - 1 } else { n } as u64);
                    let path = layout.claude_file(scope, &session, sidechain.then_some(n));
                    let offset = 1 + (n * 60 / count.max(1)) as i64;
                    let shape = claude_shape(
                        &mut rng,
                        &session,
                        sidechain,
                        &cwd,
                        clock.day(offset),
                        "b",
                        120,
                    );
                    let mut out = Writer::open(&path, false);
                    write_claude(&mut out, &mut rng, &shape);
                    written += out.bytes;
                    drop(out);
                    // Last written on its last day.
                    set_mtime(&path, clock.end_of(offset + shape.days as i64 - 1));
                }
            }
            for n in 0..codex_files.saturating_sub(daily_codex) {
                let cwd = layout.workspace(false);
                let day = clock.day(1 + (n * 60 / codex_files.max(1)) as i64);
                let target = rng.draw(CODEX_KIB) * 1024;
                let cells = (target / 4_000).max(2);
                let session = uuid(CODEX + n as u64);
                let path = layout.codex_file(&session);
                let mut out = Writer::open(&path, false);
                write_codex(&mut out, &mut rng, &session, &cwd, day, cells, 1_500, true);
                written += out.bytes;
                drop(out);
                set_mtime(
                    &path,
                    clock.end_of(1 + (n * 60 / codex_files.max(1)) as i64),
                );
            }
            // The daily runs' new transcripts exist (empty) before this run,
            // as a session started just before a run does.
            for day in 1..=DAILY_RUNS {
                for n in 0..daily_claude {
                    Writer::open(&layout.daily_claude(day, n), false);
                }
                for n in 0..daily_codex {
                    Writer::open(&layout.daily_codex(day, n), false);
                }
            }
            println!("[build] fixture_mib={:.1}", written as f64 / 1048576.0);
            if std::env::var("COMPOSITION_SCALE_GENERATE_ONLY").is_ok() {
                return;
            }
            let results = run_both(&layout, clock.build_now());
            report("build", &layout, baseline, &results);
        }
        "prepare" => {
            let clock: Clock = serde_json::from_slice(&fs::read(&clock_path).unwrap()).unwrap();
            let mut rng = Rng(0x5eed_cafe_f00d_0002 + day as u64);
            let today = clock.day(60 + day);
            let cwd = layout.workspace(false);
            let mut written = 0u64;
            // New sessions at real sizes.
            for n in 0..daily_claude {
                let session = uuid(daily_seed(DAILY, day, n));
                let mut shape = claude_shape(&mut rng, &session, false, &cwd, today, "d", 0);
                // About 400 bytes of each line are not tool output.
                let lines = shape.tool_uses * 2 + shape.attachments + shape.tool_uses / 20 + 1;
                let target = rng.draw(CLAUDE_KIB) * 1024;
                shape.output_chars =
                    (target.saturating_sub(lines * 400) / shape.tool_uses.max(1)) as usize;
                shape.days = 1;
                let mut out = Writer::open(&layout.daily_claude(day, n), true);
                write_claude(&mut out, &mut rng, &shape);
                written += out.bytes;
                drop(out);
                set_mtime(&layout.daily_claude(day, n), clock.end_of(60 + day));
            }
            // Sessions still going from the day before.
            for n in (0..claude_files).rev().filter(|n| n % 4 != 3).take(20) {
                let session = uuid(MAIN + n as u64);
                let path = layout.claude_file("main", &session, None);
                let mut shape = claude_shape(&mut rng, &session, false, &cwd, today, "a", 1_200);
                shape.days = 1;
                let mut out = Writer::open(&path, true);
                write_claude(&mut out, &mut rng, &shape);
                written += out.bytes;
                drop(out);
                set_mtime(&path, clock.end_of(60 + day));
            }
            for n in 0..daily_codex {
                let path = layout.daily_codex(day, n);
                let mut out = Writer::open(&path, true);
                let (cells, output) = if n == 0 && day == 1 {
                    // About `big_mib`: each cell writes its output twice.
                    ((big_mib as u64 * 1048576) / (2 * 65_536 + 600), 65_536)
                } else {
                    ((rng.draw(CODEX_KIB) * 1024 / 4_000).max(2), 1_500)
                };
                write_codex(
                    &mut out,
                    &mut rng,
                    &uuid(daily_seed(DAILY_CODEX, day, n)),
                    &cwd,
                    today,
                    cells,
                    output,
                    true,
                );
                written += out.bytes;
                drop(out);
                set_mtime(&path, clock.end_of(60 + day));
            }
            println!("[prepare] new_mib={:.1}", written as f64 / 1048576.0);
        }
        "daily" => {
            let clock: Clock = serde_json::from_slice(&fs::read(&clock_path).unwrap()).unwrap();
            let before = state_files(&layout);
            let results = run_both(&layout, clock.daily_now(day));
            report("daily", &layout, baseline, &results);
            let after = state_files(&layout);
            let rewritten: Vec<&String> = after
                .iter()
                .filter(|(name, entry)| before.get(*name) != Some(*entry))
                .map(|(name, _)| name)
                .collect();
            println!("[daily] state files written: {rewritten:?}");
        }
        "load" => {
            // The memory one scope's state takes once loaded (largest
            // first: the peak only shows the largest).
            let mut entries: Vec<_> = fs::read_dir(layout.state().join("scopes"))
                .unwrap()
                .flatten()
                .collect();
            entries.sort_by_key(|entry| std::cmp::Reverse(entry.metadata().unwrap().len()));
            for entry in entries {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(stem) = name
                    .strip_suffix(".json")
                    .filter(|stem| !stem.contains('.'))
                else {
                    continue;
                };
                for source in [Source::Claude, Source::Codex] {
                    let Some(scope_id) = stem.strip_prefix(&format!("{}-", source.label())) else {
                        continue;
                    };
                    let before = max_rss_bytes();
                    let scope = load_scope(&entry.path(), source, scope_id)
                        .unwrap()
                        .unwrap();
                    println!(
                        "[load] {name}: file {:.2} MiB, accounted {:.1} MiB, rss growth {:.1} MiB",
                        entry.metadata().unwrap().len() as f64 / 1048576.0,
                        scope.accounted_bytes() as f64 / 1048576.0,
                        max_rss_bytes().saturating_sub(before) as f64 / 1048576.0
                    );
                }
            }
        }
        other => {
            println!("unknown COMPOSITION_SCALE_PHASE {other:?}: build, prepare, daily or load")
        }
    }
}

fn process_cpu_micros(who: i32) -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage fills the provided record.
    assert_eq!(unsafe { libc::getrusage(who, &mut usage) }, 0);
    (usage.ru_utime.tv_sec as u64 + usage.ru_stime.tv_sec as u64) * 1_000_000
        + usage.ru_utime.tv_usec as u64
        + usage.ru_stime.tv_usec as u64
}

/// Native live storage distinguishes allocator caches from Rust-owned state.
fn report_allocator(phase: &str) {
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        #[derive(Default)]
        struct MallocStatistics {
            blocks_in_use: u32,
            size_in_use: usize,
            max_size_in_use: usize,
            size_allocated: usize,
        }
        extern "C" {
            fn malloc_zone_statistics(zone: *mut std::ffi::c_void, stats: *mut MallocStatistics);
        }
        let mut stats = MallocStatistics::default();
        // SAFETY: null sums all zones; stats has the public malloc_statistics_t layout.
        unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
        println!(
            "[allocator-{phase}] blocks_in_use={} native_live={} native_reserved={}",
            stats.blocks_in_use, stats.size_in_use, stats.size_allocated
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = phase;
}

/// Current resident pages, independent of the process high-water mark.
fn rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        // proc_pidinfo returns a public process task-info record. The first
        // two u64 fields are virtual_size and resident_size.
        extern "C" {
            fn proc_pidinfo(
                pid: i32,
                flavor: i32,
                arg: u64,
                buffer: *mut std::ffi::c_void,
                size: i32,
            ) -> i32;
        }
        let mut fields = [0u64; 16];
        // SAFETY: the buffer has room for the 96-byte proc_taskinfo record.
        let got = unsafe {
            proc_pidinfo(
                std::process::id() as i32,
                4,
                0,
                fields.as_mut_ptr().cast(),
                std::mem::size_of_val(&fields) as i32,
            )
        };
        assert!(got >= 16);
        fields[1]
    }
    #[cfg(not(target_os = "macos"))]
    {
        max_rss_bytes()
    }
}
