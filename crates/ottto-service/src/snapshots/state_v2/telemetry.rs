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
        if let Ok(value) = serde_json::to_value(value) {
            stats.latest.insert(name, value);
        }
        crate::local_resource_diagnostics::claude_state_v2(&*stats);
    }
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
}
/// Test evidence only: takes this thread's latest value of an event, so a
/// concurrent test cannot supply or overwrite it.
#[cfg(test)]
pub(in super::super) fn take_thread_event_for_test(name: &str) -> Option<serde_json::Value> {
    THREAD_EVENTS.with(|events| events.borrow_mut().remove(name))
}
/// Cumulative process-lifetime count, kept in the same inventory as events.
pub(super) fn count(name: &'static str, n: u64) {
    if let Ok(mut stats) = stats().lock() {
        let total = stats
            .latest
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .saturating_add(n);
        stats.latest.insert(name, total.into());
        crate::local_resource_diagnostics::claude_state_v2(&*stats);
    }
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
            // The first adopted load has no active runtime at prepare entry.
            // Start its v2 window here, after publication has been verified.
            if !PASS.with(|pass| pass.borrow().started) {
                pass_start();
            }
            PASS.with(|pass| pass.borrow_mut().active = true);
            initialize_pass();
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
        let (_cpu, steady, peak) = self.probe.finish();
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
                    MemoryWindow { current, peak },
                );
            }
            crate::local_resource_diagnostics::claude_state_v2(&*stats);
        }
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        self.record();
    }
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
    let memory = crate::local_resource_diagnostics::state_v2_memory();
    if let Ok(mut stats) = stats().lock() {
        stats.stage_memory.insert(
            name,
            MemoryWindow {
                current: memory,
                peak: Default::default(),
            },
        );
        crate::local_resource_diagnostics::claude_state_v2(&*stats);
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
    account_pending: Option<u64>,
    usage_pending: Option<u64>,
    #[serde(rename = "family.requests")]
    family_requests: Option<u64>,
    census: Option<u64>,
    side_maps: Option<u64>,
    files: Option<u64>,
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
        crate::local_resource_diagnostics::claude_state_v2(&*stats);
    }
}
fn retained_heap(index: &ScanIndex) -> RetainedHeap {
    // Cold: only this pass's loaded families hold request hashes in RAM.
    use super::super::usage_pending::UsagePending;
    let evidence = match &index.claude_usage_family_pending {
        UsagePending::Resident(families) => families,
        UsagePending::Cold(cold) => cold.loaded(),
    };
    let family_requests = evidence.values().try_fold(0_u64, |sum, p| {
        sum.checked_add(heap(&p.member_request_id_hashes)?)
    });
    let usage_pending = heap(&index.claude_usage_family_pending)
        .zip(family_requests)
        .and_then(|(all, requests)| all.checked_sub(requests));
    RetainedHeap {
        account_pending: heap(&index.claude_account_family_pending),
        usage_pending,
        family_requests,
        census: heap(&index.claude_request_census),
        files: heap(&index.files),
        side_maps: side_maps(index),
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

#[derive(Serialize)]
struct MemoryWindow {
    current: crate::local_resource_diagnostics::StateV2Memory,
    peak: crate::local_resource_diagnostics::StateV2Memory,
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
        let (current, peak) = self.probe.memory();
        if let Ok(mut stats) = stats().lock() {
            stats
                .stage_memory
                .insert(self.name, MemoryWindow { current, peak });
            crate::local_resource_diagnostics::claude_state_v2(&*stats);
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
        crate::local_resource_diagnostics::claude_state_v2(&*stats);
    }
    row_cap_save();
}

thread_local! {
    static ROW_CAP: std::cell::RefCell<Option<(u64, String)>> = const { std::cell::RefCell::new(None) };
}
/// Logical row bytes as a percent of the row's admission cap. Only written
/// rows are seen: digest-unchanged rows skip the write and the cap check.
pub(super) fn row_cap(kind: &str, bytes: u64, cap: u64) {
    let percent = bytes.saturating_mul(100) / cap.max(1);
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
/// catalogue kind name. The alarm warns at 75% of the cap; it never refuses.
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
        super::super::erase_tree(&root).unwrap();
        std::fs::remove_dir_all(root).unwrap();
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

    /// [behaviour] family requests heap is separate and diagnostics never contain its text.
    #[test]
    fn family_requests_heap_is_separate_and_diagnostics_never_contain_its_text() {
        let mut index = ScanIndex::default();
        index.claude_usage_family_pending.insert(
            "synthetic-private-family".into(),
            super::super::super::ClaudeUsageFamilyPending {
                census_window_end: "synthetic-window".into(),
                member_request_id_hashes: BTreeMap::from([(
                    "synthetic-private-member".into(),
                    std::collections::BTreeSet::from(["synthetic-private-request".repeat(256)]),
                )]),
                member_occurrences: BTreeMap::new(),
                invalid: false,
                idless_revision: None,
                identity_contract: None,
                contract_unproven: false,
            },
        );
        let observation = retained_heap(&index);
        if crate::heap_layout_bound::layout_supported() {
            assert!(observation.family_requests.unwrap() > 4096);
            assert!(observation.usage_pending.unwrap() > 0);
            assert_eq!(
                observation.usage_pending.unwrap() + observation.family_requests.unwrap(),
                heap(&index.claude_usage_family_pending).unwrap()
            );
        } else {
            assert!(observation.usage_pending.is_none());
            assert!(observation.family_requests.is_none());
        }
        let json = serde_json::to_string(&observation).unwrap();
        assert!(!json.contains("synthetic-private"));
        assert!(json.contains("family.requests"));
    }
}
