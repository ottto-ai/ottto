//! Counts/bytes/times only. Reuse #799 and its bounded process sampler.
use super::catalogue::scan_index_fields;
use super::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

#[derive(Default, Serialize)]
struct Stats {
    latest: BTreeMap<&'static str, serde_json::Value>,
    cpu_per_pass_us: Distribution,
    save_dirty_rows: Distribution,
    save_dirty_bytes: Distribution,
    rss_bytes: Rss,
    stage_memory: BTreeMap<&'static str, MemoryWindow>,
    retained_heap_bytes: BTreeMap<&'static str, RetainedHeap>,
    decoded_per_pass: Decoded,
    bytes_written_per_pass: Option<u64>,
    import_peak_rss_bytes: Option<u64>,
}
#[derive(Default, Serialize)]
struct Rss {
    steady: Option<u64>,
    peak: Option<u64>,
}
#[derive(Default, Serialize)]
struct Distribution {
    p50: Option<u64>,
    p95: Option<u64>,
    max: Option<u64>,
    #[serde(skip)]
    samples: Vec<u64>,
    #[serde(skip)]
    cursor: usize,
}
impl Distribution {
    fn observe(&mut self, n: u64) {
        if self.samples.len() < 128 {
            self.samples.push(n);
        } else {
            self.samples[self.cursor] = n;
        }
        self.cursor = (self.cursor + 1) % 128;
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        self.p50 = Some(sorted[(sorted.len() * 50).div_ceil(100) - 1]);
        self.p95 = Some(sorted[(sorted.len() * 95).div_ceil(100) - 1]);
        self.max = Some(self.max.unwrap_or(0).max(n));
    }
}
fn stats() -> &'static Mutex<Stats> {
    static STATS: OnceLock<Mutex<Stats>> = OnceLock::new();
    STATS.get_or_init(|| Mutex::new(Stats::default()))
}
pub(super) fn event(name: &'static str, value: &impl Serialize) {
    if name == "route" {
        if let Ok(value) = serde_json::to_value(value) {
            PASS.with(|pass| pass.borrow_mut().active = matches!(value.as_str(), Some("v2")));
        }
    }
    #[cfg(test)]
    if let Ok(value) = serde_json::to_value(value) {
        THREAD_EVENTS.with(|events| events.borrow_mut().insert(name, value));
    }
    if let Ok(mut stats) = stats().lock() {
        let value = serde_json::to_value(value);
        if let Ok(value) = &value {
            stats.latest.insert(name, value.clone());
        }
        // In a pass, each event still prints, but only its own value.
        if in_pass() {
            if let Ok(value) = value {
                crate::local_resource_diagnostics::claude_state_v2(&serde_json::json!({
                    "latest": { name: value }
                }));
            }
        } else {
            crate::local_resource_diagnostics::claude_state_v2(&*stats);
        }
    }
}
/// Window, memory, heap and save-work samples taken in this thread's pass fold
/// into the one full row `plateau` prints; outside a pass they print at once.
fn publish(stats: &Stats) {
    if !in_pass() {
        crate::local_resource_diagnostics::claude_state_v2(stats);
    }
}
fn in_pass() -> bool {
    PASS.with(|pass| pass.borrow().active)
}
/// Test evidence only: the latest value of a content-free event.
#[cfg(test)]
pub(super) fn latest_for_test(name: &str) -> Option<serde_json::Value> {
    stats().lock().ok()?.latest.get(name).cloned()
}
#[cfg(test)]
thread_local! {
    static THREAD_EVENTS: std::cell::RefCell<BTreeMap<&'static str, serde_json::Value>> =
        Default::default();
    static THREAD_CHECKPOINTS: std::cell::RefCell<Vec<(&'static str, serde_json::Value)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
/// Test evidence only: takes this thread's latest value of an event, so a
/// concurrent test cannot supply or overwrite it.
#[cfg(test)]
pub(in super::super) fn take_thread_event_for_test(name: &str) -> Option<serde_json::Value> {
    THREAD_EVENTS.with(|events| events.borrow_mut().remove(name))
}
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Save,
    Hydrate,
    Import,
}
pub(super) struct Stage {
    kind: Kind,
    probe: crate::local_resource_diagnostics::StateV2Probe,
    finished: bool,
}
impl Stage {
    pub(super) fn new(kind: Kind) -> Self {
        if matches!(kind, Kind::Hydrate) {
            start_hydrate();
        }
        Self {
            kind,
            probe: crate::local_resource_diagnostics::StateV2Probe::begin(),
            finished: false,
        }
    }
    fn record(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (cpu, steady, peak) = self.probe.finish();
        if let Ok(mut stats) = stats().lock() {
            match self.kind {
                Kind::Import => {
                    stats.import_peak_rss_bytes = peak;
                }
                Kind::Save | Kind::Hydrate => {
                    stats.rss_bytes.steady = steady;
                    stats.rss_bytes.peak = stats.rss_bytes.peak.into_iter().chain(peak).max();
                }
            }
            if matches!(self.kind, Kind::Save | Kind::Hydrate) {
                let (current, peak) = self.probe.memory();
                stats.stage_memory.insert(
                    if matches!(self.kind, Kind::Save) {
                        "save"
                    } else {
                        "hydrate"
                    },
                    MemoryWindow {
                        current,
                        peak,
                        cpu_us: cpu,
                        wall_us: Some(self.probe.wall_us()),
                        ..Default::default()
                    },
                );
            }
            publish(&stats);
        }
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        self.record();
    }
}

fn start_hydrate() {
    // The first adopted load has no active runtime at prepare entry.
    // Start its v2 window here, after publication has been verified.
    if !PASS.with(|pass| pass.borrow().started) {
        pass_start();
    }
    PASS.with(|pass| pass.borrow_mut().active = true);
    initialize_pass();
}
/// Instantaneous counts-only checkpoints; CPU is cumulative process CPU, so
/// adjacent readings can be subtracted even across ACK work outside hydrate.
pub(super) fn hydrate_checkpoint(
    name: &'static str,
    save_digests: usize,
    cx: Option<&kinds::KindCx>,
) {
    if !PASS.with(|pass| pass.borrow().active) {
        return;
    }
    initialize_pass();
    let cpu = crate::local_resource_diagnostics::state_v2_cpu();
    let window = MemoryWindow {
        current: crate::local_resource_diagnostics::state_v2_memory(),
        process_cpu_us: cpu.and_then(|c| c.cpu_user_us.checked_add(c.cpu_sys_us)),
        cpu,
        save_digests: Some(save_digests),
        // Hydrate-owned maps; no key/value walks or serialized size estimates.
        kind_cx_entries: cx.map(|cx| cx.presence.len() + cx.digests.len()),
        ..Default::default()
    };
    #[cfg(test)]
    THREAD_CHECKPOINTS.with(|checkpoints| {
        checkpoints
            .borrow_mut()
            .push((name, serde_json::to_value(&window).unwrap()));
    });
    record_memory(name, window);
}

pub(super) fn baseline(path: &Path) {
    let age = std::fs::metadata(super::fence::sibling(path, ".v1-readonly"))
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok());
    event("baseline_age_s", &age.map(|d| d.as_secs()));
    event(
        "baseline_14day_escalation_alarm",
        &age.map(|age| age >= Duration::from_secs(14 * 86400)),
    );
}

/// Process-attributed physical writes; other daemon work may contribute. No
/// estimate is substituted when the platform cannot supply a measurement.
pub(super) fn process_written_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v2>::uninit();
        if unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V2,
                usage.as_mut_ptr().cast(),
            )
        } == 0
        {
            return Some(unsafe { usage.assume_init() }.ri_diskio_byteswritten);
        }
        None
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/io")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("write_bytes:")?.trim().parse().ok())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

#[derive(Clone, Copy, Default, Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
struct Decoded {
    rows: u64,
    headers: u64,
    chunks: u64,
}
#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
struct Pass {
    active: bool,
    started: bool,
    cpu_start: Option<u64>,
    written_start: Option<u64>,
    decoded: Decoded,
    acquire_sampled: bool,
    initialized: bool,
}
thread_local! {
    static PASS: std::cell::RefCell<Pass> = std::cell::RefCell::new(Pass::default());
}
pub(in super::super) fn pass_start() {
    PASS.with(|pass| {
        *pass.borrow_mut() = Pass {
            started: true,
            active: true,
            cpu_start: crate::local_resource_diagnostics::state_v2_cpu_us(),
            written_start: process_written_bytes(),
            ..Default::default()
        }
    });
}
/// Failed v2 hydration cannot carry a baseline into a later preparation.
pub(super) fn abort_pass() {
    PASS.with(|pass| *pass.borrow_mut() = Pass::default());
}
pub(in super::super) fn phase(name: &'static str) {
    if !PASS.with(|pass| pass.borrow().active) {
        return;
    }
    initialize_pass();
    record_memory(
        name,
        MemoryWindow {
            current: crate::local_resource_diagnostics::state_v2_memory(),
            ..Default::default()
        },
    );
}
fn record_memory(name: &'static str, window: MemoryWindow) {
    if let Ok(mut stats) = stats().lock() {
        stats.stage_memory.insert(name, window);
        publish(&stats);
    }
}

pub(in super::super) fn acquired(index: &ScanIndex) {
    if !super::state_v2_growth_retention_active(index) {
        return;
    }
    let first = PASS.with(|pass| {
        let mut pass = pass.borrow_mut();
        pass.active = true;
        !std::mem::replace(&mut pass.acquire_sampled, true)
    });
    if first {
        phase("acquire");
    }
}
pub(in super::super) fn retained_pass_end(index: &ScanIndex) {
    if super::state_v2_growth_retention_active(index) {
        retained(index, "active_graph");
    }
}
pub(in super::super) fn plateau() {
    if !PASS.with(|pass| pass.borrow().active) {
        return;
    }
    phase("post_pass_plateau");
    PASS.with(|pass| {
        let mut pass = pass.borrow_mut();
        if !pass.active {
            return;
        }
        if let Ok(mut stats) = stats().lock() {
            if let Some(cpu) = pass
                .cpu_start
                .take()
                .zip(crate::local_resource_diagnostics::state_v2_cpu_us())
                .and_then(|(a, b)| b.checked_sub(a))
            {
                stats.cpu_per_pass_us.observe(cpu);
            }
            stats.bytes_written_per_pass = pass
                .written_start
                .take()
                .zip(process_written_bytes())
                .and_then(|(a, b)| b.checked_sub(a));
            stats.decoded_per_pass = pass.decoded;
            crate::local_resource_diagnostics::claude_state_v2(&*stats);
        }
        pass.active = false;
        pass.started = false;
    });
}
/// Successful physical decodes, including repeated reads for checks/encoding.
/// Thread-local counters never carry record keys and reset at prepare.
pub(super) fn decoded(rows: u64, headers: u64, chunks: u64) {
    PASS.with(|pass| {
        let mut pass = pass.borrow_mut();
        pass.decoded.rows = pass.decoded.rows.saturating_add(rows);
        pass.decoded.headers = pass.decoded.headers.saturating_add(headers);
        pass.decoded.chunks = pass.decoded.chunks.saturating_add(chunks);
    });
}

#[derive(Default, Serialize)]
struct RetainedHeap {
    census: Option<u64>,
    side_maps: Option<u64>,
    files: Option<u64>,
    /// Request hashes the census holds, and the one occupancy alarm: at
    /// least 75% of `CLAUDE_REQUEST_CENSUS_HASH_ALARM_BASE`. Nothing is capped.
    census_hashes: u64,
    census_occupancy_alarm: bool,
}
/// Existing requested-layout accounting, excluding inline stack slots. Shared
/// Arc buffers are conservatively charged to each owning graph. No JSON size
/// is substituted for heap, and opaque/unsupported layouts remain unavailable.
fn heap<T: crate::heap_layout_bound::HeapLayoutBound>(value: &T) -> Option<u64> {
    crate::heap_layout_bound::completed_bound(value, usize::MAX)?
        .checked_sub(std::mem::size_of_val(value))?
        .try_into()
        .ok()
}
pub(super) fn retained(index: &ScanIndex, owner: &'static str) {
    initialize_pass();
    let observation = retained_heap(index);
    if let Ok(mut stats) = stats().lock() {
        stats.retained_heap_bytes.insert(owner, observation);
        publish(&stats);
    }
}
fn retained_heap(index: &ScanIndex) -> RetainedHeap {
    let hashes = index.claude_request_census.hash_total();
    RetainedHeap {
        census: heap(&index.claude_request_census),
        files: heap(&index.files),
        side_maps: side_maps(index),
        census_hashes: hashes as u64,
        census_occupancy_alarm: hashes
            >= super::super::claude_request_census::CLAUDE_REQUEST_CENSUS_HASH_ALARM_BASE / 4 * 3,
    }
}
fn side_maps(index: &ScanIndex) -> Option<u64> {
    let mut bytes = if index.v2.is_some() {
        std::mem::size_of::<super::IndexState>() as u64
    } else {
        0
    };
    bytes = bytes.checked_add(heap(&index.v2().growth_retention)?)?;
    macro_rules! side {
        ($f:ident, $g:ident, $store:tt, $kinds:tt, side) => {
            bytes = bytes.checked_add(heap(&index.$f)?)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each side);
    Some(bytes)
}

#[derive(Default, Serialize)]
struct MemoryWindow {
    current: crate::local_resource_diagnostics::StateV2Memory,
    peak: crate::local_resource_diagnostics::StateV2Memory,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_cpu_us: Option<u64>,
    /// Hydrate checkpoints only: cumulative user/system CPU and page faults.
    #[serde(flatten)]
    cpu: Option<crate::local_resource_diagnostics::StateV2Cpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    save_digests: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind_cx_entries: Option<usize>,
    /// Process CPU and wall across the stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wall_us: Option<u64>,
}
/// RAII stage window; fixed label, two bounded shared samplers, no identifiers.
pub(in super::super) struct Window {
    name: &'static str,
    probe: crate::local_resource_diagnostics::StateV2Probe,
}
impl Window {
    pub(in super::super) fn begin(name: &'static str) -> Option<Self> {
        if !PASS.with(|p| p.borrow().active) {
            return None;
        }
        initialize_pass();
        Some(Self {
            name,
            probe: crate::local_resource_diagnostics::StateV2Probe::begin(),
        })
    }
}
impl Drop for Window {
    fn drop(&mut self) {
        let (cpu, _, _) = self.probe.finish();
        let (current, peak) = self.probe.memory();
        if let Ok(mut stats) = stats().lock() {
            stats.stage_memory.insert(
                self.name,
                MemoryWindow {
                    current,
                    peak,
                    cpu_us: cpu,
                    wall_us: Some(self.probe.wall_us()),
                    ..Default::default()
                },
            );
            publish(&stats);
        }
    }
}
fn initialize_pass() {
    let first = PASS.with(|pass| !std::mem::replace(&mut pass.borrow_mut().initialized, true));
    if first {
        if let Ok(mut stats) = stats().lock() {
            stats.stage_memory.clear();
            stats.retained_heap_bytes.clear();
        }
    }
}

pub(in super::super) fn acquire_window(index: &ScanIndex) -> Option<Window> {
    if !super::state_v2_growth_retention_active(index) || PASS.with(|p| p.borrow().acquire_sampled)
    {
        return None;
    }
    Window::begin("acquire")
}

/// One bounded sample per save attempt; rejected work is visible too. Gauges
/// share the claude_state_v2 diagnostic row and contain counts/bytes only.
pub(super) fn save_work(rows: u64, bytes: u64) {
    if let Ok(mut stats) = stats().lock() {
        stats.save_dirty_rows.observe(rows);
        stats.save_dirty_bytes.observe(bytes);
        publish(&stats);
    }
    row_cap_save();
}

thread_local! {
    static ROW_CAP: std::cell::RefCell<Option<(u64, String)>> = const { std::cell::RefCell::new(None) };
}
/// Logical row bytes as a percent of the row's sizing target. Only written
/// rows are seen: digest-unchanged rows skip the write and the check.
pub(super) fn row_cap(kind: &str, bytes: u64, target: u64) {
    let percent = bytes.saturating_mul(100) / target.max(1);
    ROW_CAP.with(|max| {
        let mut max = max.borrow_mut();
        if !matches!(&*max, Some((p, _)) if *p >= percent) {
            *max = Some((percent, kind.to_owned()));
        }
    });
}
pub(super) fn row_cap_reset() {
    ROW_CAP.with(|max| max.borrow_mut().take());
}
/// One gauge per save or import that wrote rows: the largest percent and its
/// catalogue kind name. The alarm warns at 75% of the target and stays an
/// alarm past 100%; it never refuses.
pub(super) fn row_cap_save() {
    if let Some((percent, kind)) = ROW_CAP.with(|max| max.borrow_mut().take()) {
        event(
            "row_cap_max",
            &serde_json::json!({ "percent": percent, "kind": kind }),
        );
        if percent >= 75 {
            event("row_cap_alarm", &percent);
        }
    }
}

#[cfg(test)]
mod ops_tests {
    use super::*;

    /// [behaviour] Cold and reused loads emit the hydrate checkpoints in order.
    #[test]
    fn hydrate_checkpoints_follow_load_order() {
        let root = crate::test_scratch::canonical_private_dir("hydrate-checkpoints");
        let parent = root.join("snapshots/destinations").join("a".repeat(64));
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("claude_code-test-scan-index.json");
        let progress = serde_json::to_vec(&serde_json::json!({
            "schema_version": 3,
            "destination_namespace_hash": "a".repeat(64),
        }))
        .unwrap();
        abort_pass();
        THREAD_CHECKPOINTS.with(|checkpoints| checkpoints.borrow_mut().clear());
        ScanIndex::load(&path).unwrap();
        // Cold loads/checkpoints must not open or initialize a pass window.
        hydrate_checkpoint("hydrate_route_entry", 0, None);
        assert_eq!(PASS.with(|pass| pass.borrow().clone()), Pass::default());
        THREAD_CHECKPOINTS.with(|checkpoints| assert!(checkpoints.borrow().is_empty()));
        for cold in [true, false] {
            pass_start();
            THREAD_CHECKPOINTS.with(|checkpoints| checkpoints.borrow_mut().clear());
            let loaded = if cold {
                super::super::money_test_support::publish(&ScanIndex::default(), &path, &progress)
            } else {
                ScanIndex::load(&path).unwrap()
            };
            let checkpoints = THREAD_CHECKPOINTS
                .with(|checkpoints| std::mem::take(&mut *checkpoints.borrow_mut()));
            assert_eq!(
                checkpoints
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>(),
                [
                    "hydrate_route_entry",
                    "hydrate_after_ack",
                    "hydrate_after_catalogue",
                    "hydrate_after_misc",
                    "hydrate_after_files",
                    "hydrate_after_accounts",
                    "hydrate_after_decode",
                    "hydrate_after_baseline",
                    "hydrate_exit",
                ]
            );
            for (name, sample) in checkpoints {
                assert!(sample["current"].is_object());
                assert!(sample["save_digests"].is_u64());
                if name == "hydrate_after_baseline" || name == "hydrate_exit" {
                    assert!(sample["save_digests"].as_u64().unwrap() > 0);
                    assert!(sample["kind_cx_entries"].is_u64());
                }
                if cfg!(any(target_os = "macos", target_os = "linux")) {
                    assert!(sample["process_cpu_us"].is_u64());
                    let split = ["cpu_user_us", "cpu_sys_us"].map(|f| sample[f].as_u64().unwrap());
                    assert_eq!(
                        split[0] + split[1],
                        sample["process_cpu_us"].as_u64().unwrap()
                    );
                    assert!(sample["minor_faults"].is_u64() && sample["major_faults"].is_u64());
                }
            }
            drop(loaded);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    /// [regress] Nested growth custody loads preserve measurements already
    /// accumulated by the enclosing preparation/acquisition pass.
    #[test]
    fn nested_load_preserves_enclosing_pass_diagnostics() {
        let root = crate::test_scratch::canonical_private_dir("nested-v2-pass");
        let parent = root.join("snapshots/destinations").join("a".repeat(64));
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("claude_code-test-scan-index.json");
        let progress = serde_json::to_vec(&serde_json::json!({
            "schema_version": 3,
            "destination_namespace_hash": "a".repeat(64),
        }))
        .unwrap();
        let index =
            super::super::money_test_support::publish(&ScanIndex::default(), &path, &progress);
        pass_start();
        phase("prepare");
        decoded(13, 0, 0);
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            ScanIndex::load(&path).unwrap();
            plateau();
        });
        let record = records
            .iter()
            .rev()
            .find(|record| record["stage"] == "claude_state_v2")
            .unwrap();
        assert!(record["counts"]["decoded_per_pass"]["rows"]
            .as_u64()
            .is_some_and(|rows| rows >= 13));
        drop(index);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// [behaviour] In a pass, an event prints a row with only its own value
    /// and stage, memory and save-work samples print nothing until the one
    /// full pass-end row; outside a pass every change prints the full row.
    #[test]
    fn pass_samples_fold_into_the_pass_end_row() {
        let previous = PASS.with(|pass| {
            std::mem::replace(
                &mut *pass.borrow_mut(),
                Pass {
                    active: true,
                    ..Default::default()
                },
            )
        });
        let (_, pass_rows) = crate::local_resource_diagnostics::capture(|| {
            event("hold", &"synthetic_hold");
            drop(Window::begin("save"));
            phase("prepare");
            save_work(1, 1);
            decoded(5, 0, 0);
            event("hold", &"none");
            plateau();
        });
        let (_, outside) = crate::local_resource_diagnostics::capture(|| {
            event("hold", &"none");
            save_work(1, 1);
        });
        PASS.with(|pass| *pass.borrow_mut() = previous);
        let rows = |records: Vec<serde_json::Value>| {
            records
                .into_iter()
                .filter(|record| record["stage"] == "claude_state_v2")
                .map(|record| record["counts"].clone())
                .collect::<Vec<_>>()
        };
        let pass_rows = rows(pass_rows);
        assert_eq!(pass_rows.len(), 3, "{pass_rows:?}");
        assert_eq!(
            pass_rows[..2],
            [
                serde_json::json!({"latest": {"hold": "synthetic_hold"}}),
                serde_json::json!({"latest": {"hold": "none"}}),
            ]
        );
        let full = &pass_rows[2];
        assert_eq!(full["decoded_per_pass"]["rows"], 5);
        assert!(full["stage_memory"].is_object() && full["latest"].is_object());
        assert!(full["save_dirty_rows"]["max"].is_u64());
        let outside = rows(outside);
        assert_eq!(outside.len(), 2, "{outside:?}");
        assert!(outside
            .iter()
            .all(|row| row["stage_memory"].is_object() && row["save_dirty_rows"]["max"].is_u64()));
    }

    /// [regress] The outer save window preserves CPU/wall in the pass-end record.
    #[test]
    fn stage_windows_carry_cpu_and_wall() {
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            let previous = PASS.with(|pass| {
                std::mem::replace(
                    &mut *pass.borrow_mut(),
                    Pass {
                        active: true,
                        ..Default::default()
                    },
                )
            });
            {
                let _window = Window::begin("save").unwrap();
                drop(Stage::new(Kind::Save));
            }
            save_work(1, 1);
            plateau();
            PASS.with(|pass| *pass.borrow_mut() = previous);
            let mut window = crate::local_resource_diagnostics::StageSum::begin(
                "claude_code",
                "evidence_cross_root",
            );
            window.time(|| std::hint::black_box((0..10_000_u64).sum::<u64>()));
        });
        let save = records
            .iter()
            .rev()
            .find(|record| record["stage"] == "claude_state_v2")
            .map(|record| &record["counts"]["stage_memory"]["save"])
            .unwrap();
        let cross = records
            .iter()
            .find(|record| record["stage"] == "evidence_cross_root")
            .map(|record| &record["observation"])
            .unwrap();
        assert!(save["wall_us"].is_u64() && cross["wall_elapsed_us"].is_u64());
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(save["cpu_us"].is_u64() && cross["shared_process_cpu_delta_us"].is_u64());
        }
    }

    /// [behaviour] Claude passes with no route preserve even stale active v2 telemetry state.
    #[test]
    fn off_claude_passes_do_not_touch_v2_telemetry() {
        // Stale state from a different source must not authorize these bridges.
        let previous = PASS.with(|pass| {
            std::mem::replace(
                &mut *pass.borrow_mut(),
                Pass {
                    active: true,
                    cpu_start: Some(7),
                    written_start: Some(13),
                    initialized: true,
                    ..Default::default()
                },
            )
        });
        let before = PASS.with(|pass| pass.borrow().clone());
        let (result, records) = crate::local_resource_diagnostics::capture(|| {
            crate::local_resource_diagnostics::source_prepare(
                "claude_code",
                || {
                    crate::local_resource_diagnostics::source_finish("claude_code", false, || {
                        Ok(17)
                    })
                },
                |_| false,
            )
        });
        let after = PASS.with(|pass| std::mem::replace(&mut *pass.borrow_mut(), previous));
        assert_eq!(result.unwrap(), 17);
        assert_eq!(after, before);
        assert_eq!(
            records
                .iter()
                .map(|r| r["stage"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["source_finish", "source_prepare"]
        );
    }

    /// [behaviour] The existing state_v2 line flags census occupancy at 75%
    /// of the alarm base.
    #[test]
    fn state_v2_line_flags_census_occupancy_at_75pct() {
        use super::super::super::claude_request_census::{
            ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
            CLAUDE_REQUEST_CENSUS_HASH_ALARM_BASE as BASE,
        };
        for (hashes, alarm) in [(BASE / 4 * 3 - 1, false), (BASE / 4 * 3, true)] {
            let mut index = ScanIndex::default();
            index.claude_request_census.insert_for_test(
                "/synthetic/projects/a.jsonl",
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    ClaudeRequestCensusShape::Exact,
                    (0..hashes as u64).collect(),
                ),
            );
            let observation = retained_heap(&index);
            assert_eq!(observation.census_hashes, hashes as u64);
            assert_eq!(observation.census_occupancy_alarm, alarm, "{hashes}");
            let json = serde_json::to_value(&observation).unwrap();
            assert_eq!(json["census_occupancy_alarm"], alarm);
        }
    }
}
