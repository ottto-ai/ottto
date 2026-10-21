//! P1-RETAIN R0: a sampled Tail/Unchanged singleton's completion-time release
//! of residents ranked below its copy's re-admission rank (shape F), and the
//! diagnostic packet's
//! refusal buckets. Its own block, apart from the shared appends above.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{observe, observed, Counts};
use crate::session_attribution::SessionAttributionContext;
use sampled_jsonl::{classify_refusal, Bucket, Refusal, RefusalView};
use sampled_scan::test_hooks::{self, Decision, Point, Probe};
use sampled_scan::{ReleaseOutcome, RetainBudget};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

type Victims = Vec<(String, (i64, i64), usize)>;
type Hook = Box<dyn FnMut()>;
type OnActive = Box<dyn FnOnce(&OwnedSourceScan)>;

static SEQ: AtomicU64 = AtomicU64::new(0);

const REDUCTION: usize = UnreadableCause::Reduction as usize;
const SCOPE_OBJECT: usize = UnreadableCause::ScopeObject as usize;
/// The Codex fixture's session, a UUID launch worker.
const CODEX_SESSION: &str = "019fa111-2222-7333-8444-555555555555";

/// One scan root and file of `rows` usage rows whose paths have the same
/// length in every world, so two worlds built alike measure alike.
fn scan_fixture(source: SnapshotSource, rows: usize, modified: SystemTime) -> ScanFixture {
    let dir = std::env::temp_dir().join(format!(
        "ottto-r0-{:010}-{:010}",
        std::process::id(),
        SEQ.fetch_add(1, AtomicOrdering::Relaxed)
    ));
    let root = match source {
        SnapshotSource::Codex => dir.join("home/.codex/sessions"),
        SnapshotSource::ClaudeCode => dir.join("home/.claude/projects"),
        _ => unreachable!(),
    };
    fs::create_dir_all(&root).unwrap();
    let (name, header) = match source {
        SnapshotSource::Codex => (
            "rollout-2026-10-07T10-00-00-019fa111-2222-7333-8444-555555555555.jsonl",
            json!({"type":"session_meta","payload":{"id":CODEX_SESSION}}),
        ),
        SnapshotSource::ClaudeCode => (
            "native-tail-fixture.jsonl",
            json!({"type":"user","sessionId":"native-tail-fixture", "timestamp":"2026-10-07T10:00:00Z", "message":{"role":"user","content":"Synthetic test"}}),
        ),
        _ => unreachable!(),
    };
    let fixture = ScanFixture {
        dir,
        file: Fixture(root.join(name)),
        root,
    };
    fixture.file.append(&header);
    for id in 0..rows {
        fixture.file.append(&usage(
            source,
            100 + 10 * id as u64,
            id,
            &format!("fixture-model-{id}"),
        ));
    }
    set_modified(&fixture, modified);
    fixture
}

fn set_modified(fixture: &ScanFixture, at: SystemTime) {
    OpenOptions::new()
        .write(true)
        .open(&fixture.file.0)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(at))
        .unwrap();
}

fn key(fixture: &ScanFixture) -> String {
    local_index_key(&fixture.file.0)
}

/// Resident keys in victim order, through a poisoned lock too.
fn victims(cache: &sampled_scan::SharedCache) -> Victims {
    match cache.retained() {
        Ok(retained) => retained.victims(),
        Err(poisoned) => poisoned.into_inner().victims(),
    }
}

fn resident_keys(cache: &sampled_scan::SharedCache) -> Vec<String> {
    victims(cache).into_iter().map(|(key, _, _)| key).collect()
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// The default change: one more usage row.
fn append_row(fixture: &ScanFixture, source: SnapshotSource) {
    fixture.file.append(&usage(
        source,
        100 + 10 * INCUMBENT_ROWS as u64,
        1_000,
        "fixture-model-tail",
    ));
}

/// A line no parser reads as usage: the parsed snapshots do not change.
fn append_ignored(fixture: &ScanFixture, _: SnapshotSource) {
    fixture.file.append(&json!({"type":"ignored"}));
}

/// An ignored line without its line terminator: unsealed, and no usage.
fn append_unterminated_ignored(fixture: &ScanFixture, _: SnapshotSource) {
    append_bytes(&fixture.file.0, b"{\"type\":\"ignored\"}");
}

/// A valid usage row without its line terminator.
fn append_unterminated(fixture: &ScanFixture, source: SnapshotSource) {
    let row = serde_json::to_vec(&usage(source, 590, 1_000, "fixture-model-tail")).unwrap();
    append_bytes(&fixture.file.0, &row);
}

/// A line that is not JSON: a lossy read.
fn append_malformed(fixture: &ScanFixture, _: SnapshotSource) {
    append_bytes(&fixture.file.0, b"{\"type\":\"assistant\",\n");
}

/// (h1): positive usage evidence in an envelope no provider parser reads.
fn append_unknown_evidence(fixture: &ScanFixture, _: SnapshotSource) {
    fixture
        .file
        .append(&json!({"unknown":{"nested":{"usage":{"future":{"request_count":1}}}}}));
}

/// (h2): a Claude response whose activity timestamp does not parse.
fn append_malformed_timestamp(fixture: &ScanFixture, source: SnapshotSource) {
    let mut row = usage(source, 590, 1_000, "fixture-model-tail");
    row["timestamp"] = json!("not-a-timestamp");
    fixture.file.append(&row);
}

/// T-R0c (Claude): 100 assistant records of 50 browser `tool_use` blocks
/// each, every block with its own id, so the active walk passes its 4,096
/// visits. Usage rows alone do not: the parser's walk is constant in its
/// row count (pinned by
/// `sampled_native_large_history_has_constant_step_charge_and_conservative_clones`;
/// CI measured 4,000 rows, then 1,500 usage hours, both under it). Each
/// capability call's id is kept in an uncapped set walked per entry.
fn append_many(fixture: &ScanFixture, source: SnapshotSource) {
    assert_eq!(source, SnapshotSource::ClaudeCode);
    for record in 0..100_usize {
        let blocks = (0..50_usize)
            .map(|block| {
                json!({"type":"tool_use", "id":format!("toolu_r0_{record:03}_{block:02}"),
                    "name":"mcp__claude-in-chrome__navigate", "input":{}})
            })
            .collect::<Vec<_>>();
        fixture.file.append(
            &json!({"type":"assistant", "sessionId":"native-tail-fixture",
            "timestamp":"2026-10-07T11:00:00Z", "message":{"id":format!("response-r0-{record}"),
            "role":"assistant", "model":"fixture-model-tail", "content":blocks}}),
        );
    }
}

const OLDER: usize = 3;
/// The incumbent's rows: enough state that `2K + max(A, ins_extra)` covers
/// its own resident copy plus one older resident, so the calibrated budget
/// never refuses a step without an active file (base `ClearNoActive`).
const INCUMBENT_ROWS: usize = 48;

/// How a world is built.
#[derive(Clone, Copy)]
struct Spec {
    /// Strictly older residents, `older_rows` usage rows each.
    older: usize,
    older_rows: usize,
    /// The incumbent's rows at its first (Full) read.
    rows: usize,
    /// The change its continued (Tail) read finds.
    change: fn(&ScanFixture, SnapshotSource),
    /// The (state, entry) budgets the cache is built at, so the insert's own
    /// limits are the scaled ones; the default budgets otherwise.
    cache: Option<(usize, usize)>,
    /// Build the cache at the calibrated state budget (`calibrated`).
    scaled_cache: bool,
    /// R0's insert term in place of the measured one (test seam).
    ins_extra: Option<usize>,
    /// Continue with an attribution context: a launch root and a launch
    /// event for the Codex session.
    attribution: bool,
    /// T-R0b-hint (i): the older residents' mtimes are in the future (their
    /// admitted hints are clipped to admission time), and the incumbent is
    /// written and admitted after them; no newer resident.
    fresh: bool,
}
const SPEC: Spec = Spec {
    older: OLDER,
    older_rows: 1,
    rows: INCUMBENT_ROWS,
    change: append_row,
    cache: None,
    scaled_cache: false,
    ins_extra: None,
    attribution: false,
    fresh: false,
};

/// The world a release row continues: one more usage row (Codex), or one
/// ignored line (Claude). A Claude usage row grows the finalization charge
/// past `K = F_prev`, so Q-PR15's conservative guard refuses its release
/// (`r0_claude_usage_tail_releases_nothing_q_pr15`); the release mechanics
/// are pinned for Claude on a change that guard admits (T-R0b″ is its
/// control).
fn releasing(source: SnapshotSource) -> Spec {
    match source {
        SnapshotSource::ClaudeCode => Spec {
            change: append_ignored,
            ..SPEC
        },
        _ => SPEC,
    }
}

/// A launch root with one launch event for `CODEX_SESSION`, as
/// `launch_demand_tests` builds it.
struct LaunchHome(PathBuf);
impl LaunchHome {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "ottto-r0-launch-{:010}-{:010}",
            std::process::id(),
            SEQ.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let raw = json!({"schema":"agent_launch.v1",
            "controller_session_ref":"a9789dcf-1e4a-4a6e-8abd-f30094efb269",
            "worker_session_ref":CODEX_SESSION, "relationship_kind":"launched",
            "workflow_ref":null, "pr_ref":null, "launch_ts":"2026-09-20T10:00:00Z",
            "capture_source":"launcher_event:opus_cli_agent", "evidence":"direct"})
        .to_string();
        let reduced = crate::launch_events::validate_event(&raw).unwrap();
        let dir = home.join(".ottto/launch-events/processed");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!(
                "{}.json",
                crate::launch_events::event_digest(&reduced)
            )),
            raw,
        )
        .unwrap();
        Self(home)
    }
    fn context(&self, source: SnapshotSource) -> SessionAttributionContext {
        use base64::Engine;
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32]);
        SessionAttributionContext::from_activity_hint(
            source,
            &self.0,
            true,
            Some(&key),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap()
    }
}
impl Drop for LaunchHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Strictly older residents (three by default), one newer one, and an
/// incumbent whose retained copy the next scan continues as a Tail. Every
/// resident has the same shape, so each frees the same bytes.
struct World {
    source: SnapshotSource,
    spec: Spec,
    base: SystemTime,
    cache: Arc<sampled_scan::SharedCache>,
    older: Vec<ScanFixture>,
    newer: Option<ScanFixture>,
    incumbent: ScanFixture,
    /// The incumbent's admitted victim-order hint.
    incumbent_hint: (i64, i64),
    index: ScanIndex,
    /// What the incumbent's first (Full) completion was granted (Q-PR13b).
    first: Vec<Decision>,
    attribution: Option<(Rc<SessionAttributionContext>, LaunchHome)>,
    /// Changes `next_read_at` has appended.
    appended: usize,
}
impl World {
    fn new(source: SnapshotSource) -> Self {
        Self::build(source, SPEC)
    }
    fn build(source: SnapshotSource, spec: Spec) -> Self {
        let base = SystemTime::now() - Duration::from_secs(3_600);
        let cache = Arc::new(match spec.cache {
            Some((state, entry)) => {
                sampled_scan::with_test_budgets(state, entry, sampled_scan::SharedCache::default)
            }
            None => sampled_scan::SharedCache::default(),
        });
        let older_at = |i: u64| {
            if spec.fresh {
                SystemTime::now() + Duration::from_secs(86_400 + i)
            } else {
                base + Duration::from_secs(i)
            }
        };
        let older = (0..spec.older as u64)
            .map(|i| resident(source, &cache, spec.older_rows, older_at(i)))
            .collect();
        let newer =
            (!spec.fresh).then(|| resident(source, &cache, 1, base + Duration::from_secs(2_000)));
        if spec.fresh {
            // Written after the residents' admission clocks.
            std::thread::sleep(Duration::from_millis(20));
        }
        let incumbent = scan_fixture(
            source,
            spec.rows,
            if spec.fresh {
                SystemTime::now()
            } else {
                base + Duration::from_secs(1_000)
            },
        );
        test_hooks::clear();
        let (index, _, _) = production_scan(
            &incumbent,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "mixed-files",
        );
        let first = test_hooks::decisions();
        test_hooks::clear();
        let incumbent_hint = victims(&cache)
            .into_iter()
            .find(|(k, _, _)| *k == key(&incumbent))
            .unwrap_or_else(|| panic!("precondition: the incumbent is resident {source:?}"))
            .1;
        (spec.change)(&incumbent, source);
        set_modified(
            &incumbent,
            if spec.fresh {
                SystemTime::now()
            } else {
                base + Duration::from_secs(1_001)
            },
        );
        let attribution = spec.attribution.then(|| {
            let home = LaunchHome::new();
            (Rc::new(home.context(source)), home)
        });
        Self {
            source,
            spec,
            base,
            cache,
            older,
            newer,
            incumbent,
            incumbent_hint,
            index,
            first,
            attribution,
            appended: 0,
        }
    }
    fn older_keys(&self, count: usize) -> Vec<String> {
        assert!(count <= self.older.len());
        self.older.iter().take(count).map(key).collect()
    }
    fn newer_key(&self) -> String {
        key(self.newer.as_ref().expect("a newer resident"))
    }
    fn inserted(&self) -> bool {
        resident_keys(&self.cache).contains(&key(&self.incumbent))
    }
}

fn resident(
    source: SnapshotSource,
    cache: &Arc<sampled_scan::SharedCache>,
    rows: usize,
    modified: SystemTime,
) -> ScanFixture {
    let fixture = scan_fixture(source, rows, modified);
    production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "mixed-files",
    );
    assert!(
        cache.retained_checkpoint(&key(&fixture)).is_some(),
        "precondition: resident {source:?}"
    );
    fixture
}

/// What one continued scan of the incumbent did.
struct Run {
    probe: Probe,
    decisions: Vec<Decision>,
    buckets: Vec<Bucket>,
    /// Residents before the scan, without the incumbent.
    before: Victims,
    /// Counts after revalidation, before `retain_reduction`: the step starts
    /// and the completion budget, before any release.
    before_retain: Option<Counts>,
    /// Residents and counts when retention returned, before `finish`.
    at_retain: Option<(Victims, Counts)>,
    counts: Counts,
    result: SourceScanResult,
    /// The first active file's taken hint (`Active.retained_hint`).
    active_hint: Option<Option<(i64, i64)>>,
    /// Census unreadable causes, by ordinal.
    unreadable: Vec<usize>,
    /// Failed `finish` error chains.
    finish_errors: Vec<String>,
    /// Step starts of a shape-F active at a zero copy budget (counted only
    /// with `Opts::count_zero_budget`).
    zero_budget_steps: usize,
}

/// How a continued scan runs.
#[derive(Default)]
struct Opts {
    /// (state, entry) budgets; the defaults otherwise.
    budgets: Option<(usize, usize)>,
    hooks: Vec<(Point, Hook)>,
    /// Called once, between the steps, when the active file first exists.
    on_active: Option<OnActive>,
    /// Measure each shape-F step start's copy budget as the scan does.
    count_zero_budget: bool,
}

struct Completed {
    index: ScanIndex,
    result: SourceScanResult,
    active_hint: Option<Option<(i64, i64)>>,
    zero_budget_steps: usize,
}

fn complete(
    mut scan: OwnedSourceScan,
    context: Option<&SessionAttributionContext>,
    mut on_active: Option<OnActive>,
    count_zero_budget: bool,
) -> Completed {
    let mut active_hint = None;
    let mut zero_budget_steps = 0;
    for _ in 0..10_000 {
        if scan.active_file.is_some() {
            if active_hint.is_none() {
                active_hint = Some(
                    scan.active_file
                        .as_deref()
                        .and_then(|active| active.sampling.as_ref())
                        .and_then(|sampling| sampling.retained_hint),
                );
            }
            if let Some(on_active) = on_active.take() {
                on_active(&scan);
            }
        }
        // After `on_active`: the step below starts on what the hook left.
        if count_zero_budget
            && scan
                .active_file
                .as_deref()
                .is_some_and(sampled_scan::borrows_only_retained_reduction)
            && scan.sampled_copy_parts().0 == 0
        {
            zero_budget_steps += 1;
        }
        match scan.step(context) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                index,
                scan: result,
                ..
            } => {
                return Completed {
                    index,
                    result,
                    active_hint,
                    zero_budget_steps,
                }
            }
        }
    }
    panic!("the scan did not complete");
}

/// Continues the incumbent as `opts` says. Hooks run in order after the
/// recorder of `at_retain`.
fn run(world: &mut World, opts: Opts) -> Run {
    let Opts {
        budgets,
        hooks,
        on_active,
        count_zero_budget,
    } = opts;
    test_hooks::clear();
    test_hooks::set_ins_extra(world.spec.ins_extra);
    let before_retain = Rc::new(RefCell::new(None));
    let seen_before = Rc::clone(&before_retain);
    test_hooks::set(Point::BeforeRetain, move || {
        *seen_before.borrow_mut() = Some(observed().unwrap());
    });
    let at_retain = Rc::new(RefCell::new(None));
    let cache = Arc::clone(&world.cache);
    let seen = Rc::clone(&at_retain);
    test_hooks::set(Point::AfterRetain, move || {
        *seen.borrow_mut() = Some((victims(&cache), observed().unwrap()));
    });
    for (point, hook) in hooks {
        test_hooks::set(point, hook);
    }
    // The scan takes the incumbent's own copy first: it is never a victim.
    let incumbent = key(&world.incumbent);
    let before = victims(&world.cache)
        .into_iter()
        .filter(|(key, _, _)| *key != incumbent)
        .collect();
    let index = std::mem::take(&mut world.index);
    let context = world
        .attribution
        .as_ref()
        .map(|(context, _)| Rc::clone(context));
    let scan = || {
        complete(
            cached_scan(&world.incumbent, world.source, index, &world.cache, |_| {}),
            context.as_deref(),
            on_active,
            count_zero_budget,
        )
    };
    let (completed, counts) = observe(|| match budgets {
        Some((state, entry)) => sampled_scan::with_test_budgets(state, entry, scan),
        None => scan(),
    });
    world.index = completed.index;
    let run = Run {
        probe: test_hooks::last_probe(),
        decisions: test_hooks::decisions(),
        buckets: test_hooks::buckets(),
        before,
        before_retain: before_retain.borrow_mut().take(),
        at_retain: at_retain.borrow_mut().take(),
        counts,
        result: completed.result,
        active_hint: completed.active_hint,
        unreadable: test_hooks::unreadable(),
        finish_errors: test_hooks::finish_errors(),
        zero_budget_steps: completed.zero_budget_steps,
    };
    test_hooks::clear();
    eprintln!(
        "R0 {:?}: probe {:?}, decisions {:?}, buckets {:?}",
        world.source, run.probe, run.decisions, run.buckets
    );
    run
}

/// An uncalibrated world's measure, and the bytes one older resident frees.
fn probe_spec(source: SnapshotSource, spec: Spec) -> (Probe, usize) {
    let mut world = World::build(source, spec);
    let run = run(&mut world, Opts::default());
    let older_keys = world.older_keys(spec.older);
    let older: Vec<usize> = run
        .before
        .iter()
        .filter(|(key, _, _)| older_keys.contains(key))
        .map(|(_, _, freed)| *freed)
        .collect();
    assert_eq!(
        older.len(),
        spec.older,
        "precondition: older residents {source:?}"
    );
    assert!(
        older.iter().all(|freed| *freed == older[0] && *freed > 0),
        "precondition: same-shape residents free the same bytes {older:?}"
    );
    eprintln!("R0 {source:?}: one older resident frees {}", older[0]);
    (run.probe, older[0])
}

/// `probe_spec` of the `releasing` world with `count` older residents.
fn probe_world(source: SnapshotSource, count: usize) -> (Probe, usize) {
    probe_spec(
        source,
        Spec {
            older: count,
            ..releasing(source)
        },
    )
}

/// The state budget at which a world like the probed one needs `need`.
fn state_for_need(probe: &Probe, need: usize) -> usize {
    let resident = sampled_scan::state_bytes() - probe.remaining;
    (resident + 2 * probe.k.unwrap() + probe.a.max(probe.ins_extra))
        .checked_sub(need)
        .filter(|state| *state > resident)
        .unwrap_or_else(|| panic!("need {need} is past 2K + max(A, ins_extra): {probe:?}"))
}

/// The measured preconditions: a world built alike measured alike, and the
/// calibrated budget produced the intended need. Asserted before any
/// victim-set comparison names fixtures.
fn assert_calibrated(
    source: SnapshotSource,
    expected: &Probe,
    run: &Run,
    state: usize,
    need: usize,
) {
    let real = &run.probe;
    // Up to the budget decision; a later step may see a poisoned lock.
    if let Some((_, phase)) = run.at_retain.as_ref() {
        assert_eq!(
            (
                phase.clear_no_active,
                phase.clear_full_resident_bound_unknown,
                phase.clear_entries_released,
            ),
            (0, 0, 0),
            "precondition: no base clear at the calibrated budget {source:?} state {state} need {need}"
        );
    }
    assert_eq!(
        (
            real.a,
            real.ins_extra,
            real.clone,
            real.finalization_prev,
            real.k
        ),
        (
            expected.a,
            expected.ins_extra,
            expected.clone,
            expected.finalization_prev,
            expected.k
        ),
        "precondition: the calibrated world measured like the probe {source:?}"
    );
    let resident = sampled_scan::state_bytes() - expected.remaining;
    assert_eq!(
        real.remaining,
        state - resident,
        "precondition: the same residents {source:?}"
    );
    assert_eq!(
        real.need,
        Some(need),
        "precondition: the intended need {source:?}"
    );
}

/// A world built like `spec`, continued at the state budget that gives
/// `need` against `probe` (entry budget `entry`), with the calibration
/// asserted.
fn calibrated_at(
    source: SnapshotSource,
    spec: Spec,
    probe: &Probe,
    need: usize,
    entry: usize,
    opts: impl FnOnce(&World) -> Opts,
) -> (World, Run, usize) {
    let state = state_for_need(probe, need);
    let spec = if spec.scaled_cache {
        Spec {
            cache: Some((state, crate::transcript_cache::entry_bytes())),
            ..spec
        }
    } else {
        spec
    };
    let mut world = World::build(source, spec);
    let opts = Opts {
        budgets: Some((state, entry)),
        ..opts(&world)
    };
    let run = run(&mut world, opts);
    assert_calibrated(source, probe, &run, state, need);
    (world, run, state)
}

fn calibrated(
    source: SnapshotSource,
    spec: Spec,
    probe: &Probe,
    need: usize,
    opts: impl FnOnce(&World) -> Opts,
) -> (World, Run) {
    let entry = crate::transcript_cache::entry_bytes();
    let (world, run, _) = calibrated_at(source, spec, probe, need, entry, opts);
    (world, run)
}

/// The residents of `run.before` without `evicted`.
fn without(run: &Run, evicted: &[String]) -> Victims {
    run.before
        .iter()
        .filter(|(key, _, _)| !evicted.contains(key))
        .cloned()
        .collect()
}

/// A hook appending one usage row to the incumbent.
fn appender(world: &World) -> Hook {
    let path = world.incumbent.file.0.clone();
    let row = usage(world.source, 7, 2_000, "fixture-model-late");
    Box::new(move || {
        let mut line = serde_json::to_vec(&row).unwrap();
        line.push(b'\n');
        append_bytes(&path, &line);
    })
}

/// One later read of the incumbent, at the default budgets.
struct NextRead {
    /// `Full(StateMissing)` reads.
    state_missing: usize,
    /// Tail reads.
    tails: usize,
    /// Every sampled read of the file (Full, Tail and Unchanged).
    reads: usize,
    counts: Counts,
}

/// Past every unhealthy-retry deadline after a `NOW` scan: one hour (the
/// delay's ceiling) and one second later.
const PAST_RETRY: &str = "2026-10-07T13:00:01Z";

/// A scan of the incumbent observed at `collected_at`, after one more usage
/// row when `append`. A `cached_scan` whose clock is not `NOW`.
fn next_read_at(world: &mut World, collected_at: &str, append: bool) -> NextRead {
    if append {
        // A fresh response id and a later mtime on each append.
        let step = world.appended;
        world.appended += 1;
        world.incumbent.file.append(&usage(
            world.source,
            100 + 10 * (INCUMBENT_ROWS as u64 + 1),
            1_001 + step,
            "fixture-model-next",
        ));
        set_modified(
            &world.incumbent,
            world.base + Duration::from_secs(1_002 + step as u64),
        );
    }
    let index = std::mem::take(&mut world.index);
    let scan = OwnedSourceScan::new(
        world.source,
        std::slice::from_ref(&world.incumbent.root),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(Arc::clone(&world.cache), Scope("mixed-files".into()));
    let ((state_missing, tails, reads), counts) = observe(|| {
        let mut scan = scan;
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(context) = scan.sampling.as_ref() {
                modes = (
                    context.full_reasons
                        [crate::transcript_acquisition::FullReason::StateMissing.slot()],
                    context.tail_files,
                    context.full_files + context.tail_files + context.unchanged_files,
                );
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, .. } => {
                    world.index = index;
                    return modes;
                }
            }
        }
        panic!("the next read did not complete");
    });
    NextRead {
        state_missing,
        tails,
        reads,
        counts,
    }
}

/// The next change after a run: one more row, read at the default budgets.
/// Returns its `Full(StateMissing)` and Tail selections.
fn next_change(world: &mut World) -> (usize, usize) {
    let next = next_read_at(world, NOW, true);
    (next.state_missing, next.tails)
}

/// T-R0a and Q-PR13b: with room, a Tail completion is granted its insert-aware
/// budget, releases nothing, and is retained beside every resident; a Full
/// singleton is granted an exact completion measure.
#[test]
fn r0_tail_with_room_is_granted_and_releases_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut world = World::new(source);
        assert!(
            matches!(
                world.first.as_slice(),
                [Decision::Granted {
                    budget,
                    resident_measured: true,
                    active_measured: true,
                }] if *budget > 0
            ),
            "Q-PR13b: a Full singleton's exact completion budget {source:?}: {:?}",
            world.first
        );
        let run = run(&mut world, Opts::default());
        let probe = run.probe;
        assert_eq!(probe.need, None, "{source:?}");
        assert!(
            probe.finalization_prev > 0,
            "β: the Full insert's finalization charge reaches the Tail {source:?}"
        );
        assert_eq!(
            probe.k,
            probe.clone.map(|clone| clone.max(probe.finalization_prev)),
            "K = max(C, F_prev) {source:?}"
        );
        assert_eq!(
            probe.b_ins,
            (probe.remaining - probe.a.max(probe.ins_extra)) / 2,
            "{source:?}"
        );
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: probe.b_ins,
                resident_measured: true,
                active_measured: true,
            }],
            "{source:?}"
        );
        let counts = run.counts;
        assert_eq!(
            (
                counts.insert_entries_evicted,
                counts.clear_other_active,
                counts.clear_entries_released,
                counts.retention_bound_refused,
                counts.insert_admitted,
            ),
            (0, 0, 0, 0, 1),
            "{source:?}"
        );
        let after = resident_keys(&world.cache);
        for resident in world
            .older
            .iter()
            .chain(world.newer.as_ref())
            .chain([&world.incumbent])
        {
            assert!(after.contains(&key(resident)), "{source:?}");
        }
        assert!(run.buckets.is_empty(), "{source:?}");
    }
}

/// No release-phase eviction at a step start, and none in the insert after a
/// completion's release: the step-start phase (`before_retain`) evicted
/// nothing, and `run.counts` adds no eviction to the phase at retention.
fn assert_step_start_and_insert_evict_nothing(run: &Run, row: &str) {
    let before = run.before_retain.as_ref().expect("revalidation passed");
    assert_eq!(
        (
            before.copy_refusal_admission_evicted,
            before.copy_refusal_entries_evicted,
            before.clear_entries_released,
            before.insert_entries_evicted,
        ),
        (0, 0, 0, 0),
        "Q-PR14: a shape-F step start evicted {row}"
    );
    let (_, phase) = run.at_retain.as_ref().expect("retention ran");
    let counts = &run.counts;
    assert_eq!(
        (
            counts.copy_refusal_admission_evicted,
            counts.copy_refusal_entries_evicted,
            counts.insert_entries_evicted,
            counts.insert_self_evicted,
        ),
        (phase.copy_refusal_admission_evicted, 0, 0, 0),
        "after retention, no further eviction {row}"
    );
}

/// T-R0b: under pressure, the completion releases exactly the shortest
/// strictly-older-hint prefix that covers its need (k = 1, then k = 2), only
/// after retention's non-budget gates, counted as `CopyRefusalAdmissionEvicted`
/// (`Release::CopyAdmission`), and nothing at a step start (Q-PR14) or in the
/// insert. Codex's usage row; Claude's ignored line (`releasing`): a Claude
/// usage row is refused without a release (Q-PR15,
/// `r0_claude_usage_tail_releases_nothing_q_pr15`).
#[test]
fn r0_tail_under_pressure_releases_the_exact_older_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        for (need, released) in [(freed, 1), (freed + 1, 2)] {
            let (world, run) =
                calibrated(source, releasing(source), &probe, need, |_| Opts::default());
            assert_eq!(
                run.decisions,
                vec![Decision::Deferred {
                    raw: run.probe.b_ins,
                    budget_after: probe.k.unwrap(),
                }],
                "{source:?} k={released}"
            );
            assert!(!run.probe.finalization_guard, "{source:?}");
            let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
            assert_eq!(
                at_retain,
                without(&run, &world.older_keys(released)),
                "the exact prefix {source:?} k={released}"
            );
            assert!(
                at_retain.iter().any(|(k, _, _)| *k == world.newer_key()),
                "a newer resident never leaves {source:?}"
            );
            assert_eq!(
                (
                    phase.copy_refusal_admission_evicted,
                    phase.insert_entries_evicted,
                    phase.retention_produced,
                    phase.retention_bound_refused,
                    phase.retention_unsealed_eof,
                    phase.clear_other_active,
                    phase.clear_full_resident_bound_unknown,
                    phase.clear_entries_released,
                ),
                (released as u64, 0, 1, 0, 0, 0, 0, 0),
                "{source:?} k={released}"
            );
            assert!(phase.copy_refusal_bytes_released > 0, "{source:?}");
            assert_step_start_and_insert_evict_nothing(&run, &format!("{source:?} k={released}"));
            assert_eq!(
                (
                    world.inserted(),
                    run.counts.insert_admitted,
                    run.counts.retention_finalization_bound_refused,
                ),
                (true, 1, 0),
                "{source:?} k={released}"
            );
            assert!(run.buckets.is_empty(), "{source:?}");
        }
    }
}

/// Q-PR15 (b), the positive-budget band regression and residual (b)'s new
/// outcome: a Claude Tail whose new usage row grows the finalization charge
/// past `K = F_prev > C`. Its previous finalization charge rides in `K` and
/// its usage witness grew since the take, so the conservative guard refuses
/// the optional release: `Granted { b_ins }` with `b_ins > 0`, no `Deferred`.
/// The clone fits `b_ins`, the finalization charge does not
/// (`RetentionFinalizationBoundRefused`), and every resident is unchanged:
/// zero evictions at the step starts, at retention and at the insert (k = 1
/// and k = 2 needs). Before Q-PR15 this released the prefix and then dropped
/// the copy. The next change reads `Full(StateMissing)`.
#[test]
fn r0_claude_usage_tail_releases_nothing_q_pr15() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let (probe, freed) = probe_spec(source, SPEC);
    assert!(
        probe.finalization_prev > probe.clone.unwrap(),
        "precondition: Claude's K is F_prev {probe:?}"
    );
    for need in [freed, freed + 1] {
        let (mut world, run) = calibrated(source, SPEC, &probe, need, |_| Opts::default());
        assert!(
            run.probe.finalization_guard,
            "the guard refused need {need}"
        );
        assert!(run.probe.b_ins > 0, "a positive budget need {need}");
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: run.probe.b_ins,
                resident_measured: true,
                active_measured: true,
            }],
            "need {need}"
        );
        let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, run.before, "need {need}");
        assert_eq!(phase.copy_refusal_admission_evicted, 0, "need {need}");
        assert_step_start_and_insert_evict_nothing(&run, &format!("need {need}"));
        assert_eq!(
            (
                run.counts.retention_produced,
                run.counts.retention_bound_refused,
                run.counts.retention_finalization_bound_refused,
                run.counts.insert_admitted,
            ),
            (1, 0, 1, 0),
            "need {need}"
        );
        assert_eq!(
            victims(&world.cache),
            run.before,
            "residents unchanged {need}"
        );
        assert!(!world.inserted(), "need {need}");
        assert!(run.buckets.is_empty(), "need {need}");
        assert_eq!(next_change(&mut world), (1, 0), "next change need {need}");
    }
}

/// R2-M2: T-R0b on a cache built at the calibrated state budget, with the
/// real insert term (no seam), Codex, k = 1 and k = 2: the exact prefix at
/// `AfterRetain`, then no insert-phase eviction, the copy admitted, and the
/// residents, the copy's finalization charge and the cursor state within that
/// state budget.
#[test]
fn r0_tail_scaled_cache_inserts_after_the_exact_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let (probe, freed) = probe_world(source, OLDER);
    let spec = Spec {
        scaled_cache: true,
        ..SPEC
    };
    let entry = crate::transcript_cache::entry_bytes();
    for (need, released) in [(freed, 1), (freed + 1, 2)] {
        let (world, run, state) =
            calibrated_at(source, spec, &probe, need, entry, |_| Opts::default());
        let row = format!("scaled k={released}");
        assert!(
            matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
            "{row}"
        );
        assert_released_then_inserted(&world, &run, &world.older_keys(released), &row);
        // The shared cache's bound: the retained copies plus the cursor state.
        let shared =
            crate::heap_layout_bound::bound(&*world.cache, usize::MAX).expect("bounded residents");
        let finalization = world
            .cache
            .take(&key(&world.incumbent))
            .expect("the copy")
            .finalization_charge;
        assert!(
            finalization > 0 && shared + finalization <= state,
            "{row}: bound(retained) + cursor {shared} + F {finalization} > state {state}"
        );
    }
}

/// The combined Q-PR14 control: a shape-F Tail at a zero copy budget under
/// real pressure, Claude on an ignored line (`releasing`), larger older
/// residents. Before the take the residents and the incumbent's own copy fit
/// the state budget (16 KiB spare), so M1's no-active evict-to-fit (main)
/// has nothing to do. Its copy (CI: 307,425 bytes) exceeds the active's walk
/// A (282,994), so without growth after the take the F step's budget stays
/// positive: once the active exists, cursor state grows (`witness_parent`,
/// as the production growth sites do) until `remaining` is below A. Its step
/// starts then meet a zero budget and evict nothing (no
/// `CopyRefusalAdmissionEvicted`, no evict-to-fit, no clear, no cursor
/// reservation); its completion releases exactly the feasible older prefix,
/// and the copy is inserted. The cache is the default (unscaled) one, so the
/// "insert adds nothing" check here cannot fail on the insert's own limit;
/// the scaled insert is pinned by
/// `r0_tail_scaled_cache_inserts_after_the_exact_prefix`. Claude only, not
/// cross-source end-to-end proof: Codex is not constructed by this fixture
/// (its cursor's own K6 admissions, `admit_locked`, release residents in
/// global victim order until their charge fits, which CI measured keeping
/// `remaining` at 915,065 bytes, above A, at every tighter state budget). The
/// Codex shape-F step start is pinned at function level only (the #654 guard
/// matrix's Tail row). K6 admissions still evict in global order during a
/// Codex F read (`CursorReservationEntriesEvicted`, main's behaviour); Q-PR14
/// covers M1's paths only.
#[test]
fn r0_shape_f_zero_budget_releases_only_at_completion() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    const OLDER_BIG: usize = 6;
    let spec = Spec {
        older: OLDER_BIG,
        older_rows: INCUMBENT_ROWS,
        ..releasing(source)
    };
    let (probe, freed) = probe_spec(source, spec);
    let mut world = World::build(source, spec);
    let incumbent = key(&world.incumbent);
    let copy = victims(&world.cache)
        .into_iter()
        .find(|(key, _, _)| *key == incumbent)
        .map(|(_, _, freed)| freed)
        .expect("precondition: the incumbent's copy is resident");
    let room = probe.a.max(probe.ins_extra);
    // `remaining` before the growth: the copy plus 16 KiB, so the residents
    // with the copy fit before the take. The growth then leaves at most
    // `room − 96 KiB` (its charge is at least its identity's bytes).
    let before_growth = copy + 16 * 1024;
    let growth = (before_growth + 96 * 1024)
        .checked_sub(room)
        .expect("precondition: growth is needed");
    let state = sampled_scan::state_bytes() - probe.remaining + before_growth;
    let entry = crate::transcript_cache::entry_bytes();
    eprintln!("R0_ZERO_BUDGET copy={copy} room={room} state={state} growth={growth} {probe:?}");
    let at_active = Rc::new(RefCell::new(None));
    let seen = Rc::clone(&at_active);
    let cache = Arc::clone(&world.cache);
    let grow = move |_: &OwnedSourceScan| {
        let before = observed().unwrap();
        let admitted = cache.witness_parent(
            &Scope("r0-zero-budget".into()),
            "r0-zero-budget-scope",
            "r0-zero-budget-parent",
            sampled_scan::codex_cursor::ParentWitness {
                cause: CodexParentUnresolvable::NoLedger,
                identity: Some("w".repeat(growth)),
                waits_on: None,
            },
        );
        *seen.borrow_mut() = Some((admitted, before, observed().unwrap()));
    };
    let run = run(
        &mut world,
        Opts {
            budgets: Some((state, entry)),
            on_active: Some(Box::new(grow) as OnActive),
            count_zero_budget: true,
            ..Opts::default()
        },
    );
    let (admitted, before, after) = at_active.borrow_mut().take().expect("the growth ran");
    assert!(admitted, "precondition: the growth is admitted");
    let evictions = |counts: &Counts| {
        (
            counts.copy_refusal_admission_evicted,
            counts.copy_refusal_entries_evicted,
            counts.cursor_reservation_entries_evicted,
            counts.insert_entries_evicted,
            counts.clear_entries_released,
        )
    };
    assert_eq!(
        (evictions(&before), evictions(&after)),
        ((0, 0, 0, 0, 0), (0, 0, 0, 0, 0)),
        "precondition: nothing evicted before the take or by the growth {before:?} {after:?}"
    );
    let start = run.before_retain.expect("revalidation ran");
    assert_eq!(
        evictions(&start),
        (0, 0, 0, 0, 0),
        "zero step-start eviction {start:?}"
    );
    assert!(
        run.zero_budget_steps >= 1,
        "precondition: a shape-F step start met a zero copy budget {:?}",
        run.probe
    );
    assert_eq!(run.probe.b_ins, 0, "precondition: zero at completion too");
    assert!(
        matches!(
            run.decisions.as_slice(),
            [Decision::Deferred { raw: 0, .. }]
        ),
        "{:?}",
        run.decisions
    );
    let need = run.probe.need.expect("a need");
    let released = need.div_ceil(freed);
    assert!(
        released <= OLDER_BIG,
        "precondition: the older residents cover the need {:?} freed {freed}",
        run.probe
    );
    assert_released_then_inserted(&world, &run, &world.older_keys(released), "zero budget");
}

/// Only strictly older residents may leave: when they cannot cover the need
/// (one older resident, need one byte past it), nothing is released even
/// though the newer resident would cover it, and a refusal files in exactly
/// one bucket.
#[test]
fn r0_tail_never_releases_newer_residents() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, 1);
        let spec = Spec {
            older: 1,
            ..releasing(source)
        };
        let (_, run) = calibrated(source, spec, &probe, freed + 1, |_| Opts::default());
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: run.probe.b_ins,
                resident_measured: true,
                active_measured: true,
            }],
            "{source:?}"
        );
        let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, run.before, "{source:?}");
        assert_eq!(
            (
                phase.copy_refusal_admission_evicted,
                run.counts.copy_refusal_admission_evicted,
                run.counts.insert_entries_evicted,
            ),
            (0, 0, 0),
            "{source:?}"
        );
        assert_eq!(
            run.buckets.len() as u64,
            phase.retention_bound_refused + phase.retention_clone_bound_refused,
            "one bucket per refused pass {source:?}"
        );
    }
}

/// T-R0b-key: the cache is built at the scaled entry budget, so the insert's
/// own entry and key bounds are live. A copy past the copy's entry limit
/// (`entry_bytes − entry_overhead − bound(key)`) by one byte never releases;
/// at the exact edge it releases, and a copy that is inserted is never
/// refused by those bounds (residual (e) cannot follow a release).
#[test]
fn r0_tail_in_the_entry_band_never_releases() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        let overhead =
            crate::transcript_cache::entry_overhead::<sampled_jsonl::CachedJsonlReduction>();
        for (offset, deferred) in [(1, false), (0, true)] {
            // The fixture paths have one length, so one key bound.
            let key_bound = crate::heap_layout_bound::bound(
                &key(&scan_fixture(source, 0, SystemTime::now())),
                usize::MAX,
            )
            .unwrap();
            let entry = probe.clone.unwrap() + overhead + key_bound - offset;
            let spec = Spec {
                cache: Some((sampled_scan::state_bytes(), entry)),
                ..releasing(source)
            };
            let (world, run, _) =
                calibrated_at(source, spec, &probe, freed, entry, |_| Opts::default());
            assert_eq!(
                matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
                deferred,
                "{source:?} offset {offset}: {:?}",
                run.decisions
            );
            let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
            assert_eq!(
                phase.copy_refusal_admission_evicted,
                u64::from(deferred),
                "{source:?} offset {offset}"
            );
            if !deferred {
                assert_eq!(at_retain, run.before, "{source:?}");
                assert_eq!(
                    (
                        run.counts.copy_refusal_admission_evicted,
                        run.counts.insert_entries_evicted
                    ),
                    (0, 0),
                    "{source:?}"
                );
                continue;
            }
            assert_eq!(
                (
                    run.counts.insert_entry_bound_refused,
                    run.counts.insert_key_bound_refused,
                ),
                (0, 0),
                "no (e) after a release {source:?}"
            );
            // Both insert at the edge (Claude's ignored line leaves its
            // finalization charge within `K`).
            assert_eq!(
                (world.inserted(), run.counts.insert_admitted),
                (true, 1),
                "{source:?}"
            );
        }
    }
}

/// A race between the completion measure and the release: the older prefix
/// left (newer twins replaced it), so nothing is evicted and no copy is kept.
#[test]
fn r0_release_race_evicts_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        // Same-shape twins, newer than the incumbent, in a spare cache.
        let spare = Arc::new(sampled_scan::SharedCache::default());
        let base = SystemTime::now() - Duration::from_secs(3_600);
        let twins: Vec<ScanFixture> = (0..OLDER as u64)
            .map(|i| resident(source, &spare, 1, base + Duration::from_secs(3_000 + i)))
            .collect();
        let twin_keys: Vec<String> = twins.iter().map(key).collect();
        let swapped = Rc::new(RefCell::new(None));
        let seen = Rc::clone(&swapped);
        let (world, run) = calibrated(source, releasing(source), &probe, freed, |world| {
            let older_keys = world.older_keys(OLDER);
            let cache = Arc::clone(&world.cache);
            let hook = move || {
                for key in &older_keys {
                    assert!(cache.take(key).is_some());
                }
                for key in &twin_keys {
                    let taken = spare.take(key).expect("twin");
                    assert!(cache
                        .retained()
                        .unwrap()
                        .insert(key.clone(), taken.retained));
                }
                *seen.borrow_mut() = Some(victims(&cache));
            };
            Opts {
                hooks: vec![(Point::BeforeStampGate, Box::new(hook) as Hook)],
                ..Opts::default()
            }
        });
        assert!(
            matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
            "{source:?}"
        );
        let swapped = swapped.borrow_mut().take().expect("the race hook ran");
        let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
        assert_eq!(
            at_retain, swapped,
            "nothing evicted after the race {source:?}"
        );
        assert_eq!(
            (
                phase.copy_refusal_admission_evicted,
                phase.retention_bound_refused,
                phase.retention_produced,
            ),
            (0, 1, 0),
            "{source:?}"
        );
        assert_eq!(run.buckets, vec![Bucket::OverBudget], "{source:?}");
        assert!(!world.inserted(), "{source:?}");
        drop(twins);
    }
}

/// A poisoned retained lock at release time: unmeasurable, nothing evicted.
#[test]
fn r0_release_on_a_poisoned_lock_evicts_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        let (_, run) = calibrated(source, releasing(source), &probe, freed, |world| {
            let cache = Arc::clone(&world.cache);
            let hook = move || cache.poison_retained();
            Opts {
                hooks: vec![(Point::BeforeStampGate, Box::new(hook) as Hook)],
                ..Opts::default()
            }
        });
        let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, run.before, "{source:?}");
        assert_eq!(
            (
                phase.copy_refusal_admission_evicted,
                phase.retention_bound_refused,
                phase.retention_produced,
            ),
            (0, 1, 0),
            "{source:?}"
        );
        assert_eq!(run.buckets, vec![Bucket::Walk], "{source:?}");
        // A later step cannot measure the poisoned cache: base records its
        // clear, which releases nothing through the poisoned lock.
        assert_eq!(
            (
                run.counts.copy_refusal_admission_evicted,
                run.counts.insert_entries_evicted,
                run.counts.clear_entries_released
            ),
            (0, 0, 0),
            "{source:?}"
        );
    }
}

/// T-D2: the retained lock is never relocked on one thread; a debug build
/// panics before it would deadlock.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "retained lock taken while this thread holds it")]
fn r0_retained_relock_panics_in_debug_builds() {
    let cache = sampled_scan::SharedCache::default();
    let _held = cache.retained().unwrap();
    let _ = cache.retained();
}

/// T-D1: R0's completion measure waits for a held retained lock; every other
/// walk reads contention as unbounded.
#[test]
fn r0_blocking_measure_waits_for_the_retained_lock() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let cache = Arc::clone(&cache);
        std::thread::spawn(move || {
            let guard = cache.retained().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            drop(guard);
        })
    };
    held_rx.recv().unwrap();
    assert_eq!(
        crate::heap_layout_bound::bound(&*cache, usize::MAX),
        None,
        "an ordinary walk reads contention as unbounded"
    );
    release_tx.send(()).unwrap();
    let blocking = {
        let _blocking = sampled_scan::BlockingResidentMeasure::enter();
        crate::heap_layout_bound::bound(&*cache, usize::MAX)
    };
    holder.join().unwrap();
    assert!(blocking.is_some());
    assert_eq!(
        blocking,
        crate::heap_layout_bound::bound(&*cache, usize::MAX),
        "the same bound as uncontended"
    );
}

/// T-D3 (β): an insert keeps its own finalization charge on the entry, apart
/// from the cursor reservation, and the next take carries it.
#[test]
fn r0_insert_carries_its_finalization_charge_to_the_next_take() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let fixture = resident(
            source,
            &cache,
            1,
            SystemTime::now() - Duration::from_secs(60),
        );
        let taken = cache.take(&key(&fixture)).expect("resident");
        assert!(
            taken.finalization_charge > 0,
            "a production insert carries its finalization charge {source:?}"
        );
        cache.insert(
            key(&fixture),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: taken.retained.checkpoint,
                reduction: Some(taken.retained.state),
                released: None,
            },
            1_234,
        );
        assert_eq!(
            cache
                .take(&key(&fixture))
                .expect("reinserted")
                .finalization_charge,
            1_234,
            "{source:?}"
        );
    }
}

/// The packet: one bucket per refused pass, from the budget it was admitted
/// against and what refused it; excluded and unsealed passes get no budget.
#[test]
fn packet_refusal_buckets_and_budget_variants() {
    let entry = crate::transcript_cache::entry_bytes();
    let granted = |budget, resident_measured, active_measured| {
        RefusalView::of(&RetainBudget::Granted {
            budget,
            resident_measured,
            active_measured,
        })
    };
    let admission = |charge| Refusal::Admission { charge };
    let cases = [
        (granted(0, false, true), admission(Some(10)), Bucket::Walk),
        (granted(9, true, false), admission(Some(10)), Bucket::Walk),
        (
            granted(0, true, true),
            admission(Some(10)),
            Bucket::BudgetZero,
        ),
        (
            granted(5, true, true),
            admission(Some(10)),
            Bucket::OverBudget,
        ),
        (granted(5, true, true), admission(None), Bucket::Walk),
        (
            granted(2 * entry, true, true),
            admission(Some(entry + 1)),
            Bucket::OverEntry,
        ),
        (
            granted(5, false, false),
            Refusal::Clone { charge: Some(10) },
            Bucket::OverBudget,
        ),
        (
            RefusalView::deferred(100, 50),
            Refusal::Release(ReleaseOutcome::Race),
            Bucket::OverBudget,
        ),
        (
            RefusalView::deferred(100, 50),
            Refusal::Release(ReleaseOutcome::Unmeasurable),
            Bucket::Walk,
        ),
        (
            RefusalView::deferred(0, 50),
            Refusal::Release(ReleaseOutcome::Race),
            Bucket::BudgetZero,
        ),
        (
            RefusalView::deferred(100, 50),
            admission(Some(60)),
            Bucket::OverEntry,
        ),
        (
            RefusalView::deferred(100, 50),
            admission(Some(120)),
            Bucket::OverBudget,
        ),
        (
            RefusalView::of(&RetainBudget::TierOrJoinExcluded { raw: 7 }),
            admission(Some(1)),
            Bucket::BudgetZero,
        ),
    ];
    for (index, (view, refusal, bucket)) in cases.into_iter().enumerate() {
        assert_eq!(classify_refusal(view, refusal), bucket, "case {index}");
    }

    // Only a deferred release that ran moves the finalization limit to
    // `budget_after`; none of these has one, so `released` changes nothing.
    let granted = RetainBudget::granted_unclassified(7);
    assert_eq!(
        (
            granted.raw(),
            granted.admission_budget(),
            granted.finalization().after(false),
            granted.finalization().after(true),
        ),
        (7, 7, 7, 7)
    );
    for budget in [
        RetainBudget::granted_unclassified(7).excluded(),
        RetainBudget::granted_unclassified(7).unsealed(),
    ] {
        assert_eq!(
            (
                budget.raw(),
                budget.admission_budget(),
                budget.finalization().after(false),
                budget.finalization().after(true),
            ),
            (7, 0, 7, 7)
        );
    }
    // H3's no-release conversion leaves a non-deferred budget as it was.
    assert!(matches!(
        RetainBudget::granted_unclassified(7).without_release(),
        RetainBudget::Granted { budget: 7, .. }
    ));
    assert!(matches!(
        RetainBudget::granted_unclassified(7)
            .unsealed()
            .without_release(),
        RetainBudget::Unsealed { raw: 7 }
    ));
}

/// Phase-split at `BeforeRetain` and `AfterRetain`: the step starts evicted
/// nothing, the release evicted exactly `evicted` (`CopyAdmission`) and the
/// copy was produced; after it, the insert evicted nothing more and admitted
/// the copy. The newer resident stays.
fn assert_released_then_inserted(world: &World, run: &Run, evicted: &[String], row: &str) {
    let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
    assert_eq!(at_retain, without(run, evicted), "the exact prefix {row}");
    assert_eq!(
        (
            phase.copy_refusal_admission_evicted,
            phase.insert_entries_evicted,
            phase.retention_produced
        ),
        (evicted.len() as u64, 0, 1),
        "{row}"
    );
    assert_step_start_and_insert_evict_nothing(run, row);
    let counts = &run.counts;
    assert_eq!(
        (
            counts.insert_admitted,
            counts.retention_finalization_bound_refused,
        ),
        (1, 0),
        "{row}"
    );
    assert!(
        resident_keys(&world.cache).contains(&world.newer_key()),
        "{row}"
    );
    assert!(world.inserted(), "the newcomer is resident {row}");
}

/// Refused without a release: zero evictions in both phases, the newer
/// resident intact, the copy refused by its admission, and the next change
/// read `Full(StateMissing)`.
fn assert_refused_without_release(world: &mut World, run: &Run, row: &str) {
    let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
    assert_eq!(at_retain, run.before, "{row}");
    assert_eq!(
        (
            phase.copy_refusal_admission_evicted,
            run.counts.copy_refusal_admission_evicted,
            run.counts.insert_entries_evicted,
            run.counts.retention_bound_refused,
            run.counts.insert_admitted,
        ),
        (0, 0, 0, 1, 0),
        "{row}"
    );
    assert!(
        resident_keys(&world.cache).contains(&world.newer_key()),
        "{row}"
    );
    assert!(!world.inserted(), "{row}");
    assert_eq!(next_change(world), (1, 0), "next change {row}");
}

/// The disclosed residuals after a release (need 1: the oldest resident):
/// the release evicted exactly it and the copy was produced, then the copy
/// was dropped after `finish` (no insert event); the residents beyond the
/// prefix are intact.
fn assert_released_then_dropped(world: &World, run: &Run, row: &str) {
    assert_released_then_dropped_at(world, run, 0, row);
}

/// As `assert_released_then_dropped`, with `finalization_refused`
/// `RetentionFinalizationBoundRefused` events (residual (b)).
fn assert_released_then_dropped_at(world: &World, run: &Run, finalization_refused: u64, row: &str) {
    let evicted = world.older_keys(1);
    let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
    assert_eq!(at_retain, without(run, &evicted), "{row}");
    assert_eq!(
        (
            phase.copy_refusal_admission_evicted,
            phase.retention_produced
        ),
        (1, 1),
        "{row}"
    );
    assert_step_start_and_insert_evict_nothing(run, row);
    assert_eq!(
        (
            run.counts.insert_admitted,
            run.counts.retention_finalization_bound_refused,
        ),
        (0, finalization_refused),
        "no insert event {row}"
    );
    assert_eq!(victims(&world.cache), without(run, &evicted), "{row}");
    assert!(!world.inserted(), "{row}");
}

/// Why T-R0b-ins, -ins-band, -node and -node-band set `ins_extra` through
/// the test seam: each needs `ins_extra > A`, and on a supported layout even
/// a minimal Tail (a confirmed-empty file plus one ignored line) holds more
/// active state than the insert's own slot adds.
#[test]
fn r0_insert_term_is_below_the_active_charge_on_supported_layouts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let spec = Spec {
            older: 1,
            rows: 0,
            change: append_ignored,
            ..SPEC
        };
        let mut world = World::build(source, spec);
        let probe = run(&mut world, Opts::default()).probe;
        assert!(
            probe.ins_extra > 0 && probe.a > probe.ins_extra,
            "{source:?}: {probe:?}"
        );
    }
}

/// T-R0b-ins (R2-B1, R2-M2), substitute: `ins_extra = A + f` by the test
/// seam, the cache built at the calibrated state budget. Rev 8's need is
/// `2f`; rev 6's (`2K + A − remaining`) is `f`. Phase-split: the release
/// evicts exactly the two oldest residents, then the insert evicts nothing;
/// the newer resident stays and the copy is resident. On rev 6's need the
/// victim set is the oldest resident alone, so the prefix assertion fails.
/// Codex, whose `K` is `C`.
#[test]
fn r0_tail_releases_for_its_insert_term() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let (probe, freed) = probe_world(source, OLDER);
    let ins_extra = probe.a + freed;
    let expected = Probe { ins_extra, ..probe };
    let spec = Spec {
        scaled_cache: true,
        ins_extra: Some(ins_extra),
        ..SPEC
    };
    let (world, run) = calibrated(source, spec, &expected, 2 * freed, |_| Opts::default());
    let k = probe.k.unwrap();
    assert_eq!(
        2 * k + probe.a - run.probe.remaining,
        freed,
        "rev 6's need is one resident"
    );
    assert_eq!(
        run.decisions,
        vec![Decision::Deferred {
            raw: run.probe.b_ins,
            budget_after: k,
        }]
    );
    assert_released_then_inserted(&world, &run, &world.older_keys(2), "T-R0b-ins");
}

/// T-R0b-ins-band (R2-M2), substitute: one older resident frees rev 6's need
/// (`f`) but not rev 8's (`f + 1`, `ins_extra = A + 1`). Infeasible: granted
/// `b_ins < K`, zero evictions in both phases, the newer resident intact,
/// the copy refused (`RetentionBoundRefused`), the next change
/// `Full(StateMissing)`. On rev 6 the release is feasible and evicts the
/// older resident, so the zero-eviction assertion fails.
#[test]
fn r0_tail_insert_term_band_refuses_without_release() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let (probe, freed) = probe_world(source, 1);
    let ins_extra = probe.a + 1;
    let expected = Probe { ins_extra, ..probe };
    let spec = Spec {
        older: 1,
        scaled_cache: true,
        ins_extra: Some(ins_extra),
        ..SPEC
    };
    let (mut world, run) = calibrated(source, spec, &expected, freed + 1, |_| Opts::default());
    let k = probe.k.unwrap();
    assert_eq!(
        2 * k + probe.a - run.probe.remaining,
        freed,
        "rev 6's need is one resident"
    );
    assert!(run.probe.b_ins < k);
    assert_eq!(
        run.decisions,
        vec![Decision::Granted {
            budget: run.probe.b_ins,
            resident_measured: true,
            active_measured: true,
        }]
    );
    assert_refused_without_release(&mut world, &run, "T-R0b-ins-band");
}

/// T-R0b-node (R1-B1.3, R1-M1), substitute: `remaining = 2K + A`, so
/// `(remaining − A)/2 = K` and rev 7's shortcut grants without a release;
/// `ins_extra = A + f` by the test seam makes rev 8's need `f`. Deferred;
/// phase-split: exactly the oldest resident, then zero insert-phase
/// evictions; the newer resident intact.
#[test]
fn r0_tail_with_room_beside_its_active_still_releases_for_its_slot() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let (probe, freed) = probe_world(source, OLDER);
    let ins_extra = probe.a + freed;
    let expected = Probe { ins_extra, ..probe };
    let spec = Spec {
        scaled_cache: true,
        ins_extra: Some(ins_extra),
        ..SPEC
    };
    let (world, run) = calibrated(source, spec, &expected, freed, |_| Opts::default());
    let k = probe.k.unwrap();
    assert_eq!(
        (run.probe.remaining - probe.a) / 2,
        k,
        "rev 7's shortcut grants"
    );
    assert_eq!(
        run.decisions,
        vec![Decision::Deferred {
            raw: run.probe.b_ins,
            budget_after: k,
        }]
    );
    assert_released_then_inserted(&world, &run, &world.older_keys(1), "T-R0b-node");
}

/// T-R0b-node-band (R1-M1), substitute: as T-R0b-node, but the one older
/// resident cannot cover rev 8's need (`ins_extra = A + f + 1`). Granted
/// `b_ins < K`: the copy refused, zero evictions in both phases, the newer
/// resident intact. Rev 7's shortcut would grant `K` and admit the copy.
#[test]
fn r0_tail_node_band_refuses_without_release() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let (probe, freed) = probe_world(source, 1);
    let ins_extra = probe.a + freed + 1;
    let expected = Probe { ins_extra, ..probe };
    let spec = Spec {
        older: 1,
        scaled_cache: true,
        ins_extra: Some(ins_extra),
        ..SPEC
    };
    let (mut world, run) = calibrated(source, spec, &expected, freed + 1, |_| Opts::default());
    let k = probe.k.unwrap();
    assert_eq!(
        (run.probe.remaining - probe.a) / 2,
        k,
        "rev 7's shortcut grants"
    );
    assert!(run.probe.b_ins < k);
    assert_eq!(
        run.decisions,
        vec![Decision::Granted {
            budget: run.probe.b_ins,
            resident_measured: true,
            active_measured: true,
        }]
    );
    assert_refused_without_release(&mut world, &run, "T-R0b-node-band");
}

/// T-R0b′: even every older resident cannot cover the need (three older
/// residents, need one byte past them): nothing is evicted, the copy is
/// refused, and the next change reads `Full(StateMissing)`.
#[test]
fn r0_tail_infeasible_release_refuses_and_reads_full_next() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        let (mut world, run) =
            calibrated(source, releasing(source), &probe, OLDER * freed + 1, |_| {
                Opts::default()
            });
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: run.probe.b_ins,
                resident_measured: true,
                active_measured: true,
            }],
            "{source:?}"
        );
        let (at_retain, _) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, run.before, "{source:?}");
        assert_eq!(
            (
                run.counts.copy_refusal_admission_evicted,
                run.counts.insert_entries_evicted
            ),
            (0, 0),
            "{source:?}"
        );
        // Codex's `b_ins` is below its clone; Claude's admits the clone, and
        // its finalization charge (`F_prev`, unchanged by the ignored line)
        // exceeds the pre-release `b_ins` it is now limited by: refused.
        assert_eq!(
            (
                run.counts.retention_bound_refused,
                run.counts.retention_finalization_bound_refused,
                run.counts.insert_admitted,
            ),
            match source {
                SnapshotSource::ClaudeCode => (0, 1, 0),
                _ => (1, 0, 0),
            },
            "{source:?}"
        );
        assert!(!world.inserted(), "{source:?}");
        assert_eq!(next_change(&mut world), (1, 0), "{source:?}");
    }
}

/// T-R0b″ (β), and Q-PR15's control: `K = F_prev` covers a finalization
/// charge the change does not grow. Claude (`F_prev > C`), one ignored line:
/// `F_prev > C` alone does not trip the conservative guard (no usage was
/// added), so it is deferred with `budget_after = F_prev`, released, then the
/// copy is inserted with no finalization refusal. The guard is no blanket
/// Claude refusal.
#[test]
fn r0_finalization_charge_rides_in_k() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let spec = Spec {
        change: append_ignored,
        ..SPEC
    };
    let (probe, freed) = probe_spec(source, spec);
    assert!(
        probe.finalization_prev > probe.clone.unwrap(),
        "precondition: K = F_prev {probe:?}"
    );
    let (world, run) = calibrated(source, spec, &probe, freed, |_| Opts::default());
    assert!(!run.probe.finalization_guard, "Q-PR15 control");
    assert_eq!(
        run.decisions,
        vec![Decision::Deferred {
            raw: run.probe.b_ins,
            budget_after: probe.finalization_prev,
        }]
    );
    assert_released_then_inserted(&world, &run, &world.older_keys(1), "T-R0b″");
}

/// T-R0b‴(1)-(5a): a feasible release (need 1, the oldest resident) whose
/// copy a non-budget gate refuses evicts nothing: every resident stays with
/// its bound. (1) an append between revalidation and retention: the commit
/// fails (`UnreadableCause::Reduction`); (2) an unterminated final line
/// (`RetentionUnsealedEof`); (3) a line that is not JSON
/// (`RetentionIncompleteOrLossy`); (4) the file replaced at its path while
/// it is read: revalidation (`UnreadableCause::ScopeObject`); (5a) an append
/// at `BeforeStampGate` (`RetentionUnsealedEof` from the stamp gate).
#[test]
fn r0_tail_non_budget_gates_evict_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    /// The gated run: nothing evicted, every resident intact, no copy.
    fn gate(source: SnapshotSource, spec: Spec, opts: impl FnOnce(&World) -> Opts) -> Run {
        let (probe, _) = probe_spec(source, spec);
        let (world, run) = calibrated(source, spec, &probe, 1, opts);
        assert_eq!(victims(&world.cache), run.before, "{source:?}");
        assert_eq!(
            (
                run.counts.copy_refusal_admission_evicted,
                run.counts.copy_refusal_entries_evicted,
                run.counts.insert_entries_evicted,
                run.counts.retention_produced,
                run.counts.insert_admitted,
            ),
            (0, 0, 0, 0, 0),
            "a refusal before `execute` evicts nothing {source:?}"
        );
        assert!(!world.inserted(), "{source:?}");
        run
    }
    let deferred = |run: &Run| matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]);
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let spec = releasing(source);
        let run = gate(source, spec, |world| Opts {
            hooks: vec![(Point::BeforeRetain, appender(world))],
            ..Opts::default()
        });
        assert!(deferred(&run), "(1) {source:?}");
        assert_eq!(run.unreadable, vec![REDUCTION], "(1) {source:?}");

        // A Claude usage row would trip Q-PR15's guard before the gate.
        let run = gate(
            source,
            Spec {
                change: match source {
                    SnapshotSource::ClaudeCode => append_unterminated_ignored,
                    _ => append_unterminated,
                },
                ..SPEC
            },
            |_| Opts::default(),
        );
        assert!(deferred(&run), "(2) {source:?}");
        assert_eq!(run.counts.retention_unsealed_eof, 1, "(2) {source:?}");

        let run = gate(
            source,
            Spec {
                change: append_malformed,
                ..SPEC
            },
            |_| Opts::default(),
        );
        assert!(deferred(&run), "(3) {source:?}");
        assert_eq!(
            run.counts.retention_incomplete_or_lossy, 1,
            "(3) {source:?}"
        );

        let run = gate(source, spec, |world| {
            let path = world.incumbent.file.0.clone();
            Opts {
                on_active: Some(Box::new(move |_: &OwnedSourceScan| {
                    let replacement = path.with_extension("replacement");
                    fs::copy(&path, &replacement).unwrap();
                    fs::rename(&replacement, &path).unwrap();
                }) as OnActive),
                ..Opts::default()
            }
        });
        assert!(run.decisions.is_empty(), "(4) {source:?}");
        assert_eq!(run.unreadable, vec![SCOPE_OBJECT], "(4) {source:?}");

        let run = gate(source, spec, |world| Opts {
            hooks: vec![(Point::BeforeStampGate, appender(world))],
            ..Opts::default()
        });
        assert!(deferred(&run), "(5a) {source:?}");
        assert_eq!(run.counts.retention_unsealed_eof, 1, "(5a) {source:?}");
    }
}

/// T-R0b‴(5b), the disclosed (d): an append after retention returned. The
/// release evicted the oldest resident and the copy was produced, then
/// `finish` saw the object change (`UnreadableCause::Reduction`): no insert.
/// The retry latch then holds the file unread until its deadline, its first
/// re-read is `Full(StateMissing)`, and that read re-retains it
/// (`assert_retry_latch_then_full_then_retained`).
#[test]
fn r0_tail_append_after_retention_is_disclosed_d() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, _) = probe_world(source, OLDER);
        let (mut world, run) = calibrated(source, releasing(source), &probe, 1, |world| Opts {
            hooks: vec![(Point::AfterRetain, appender(world))],
            ..Opts::default()
        });
        assert_released_then_dropped(&world, &run, "(5b)");
        assert_eq!(run.unreadable, vec![REDUCTION], "{source:?}");
        assert!(
            matches!(run.finish_errors.as_slice(), [error] if error.contains("changed while it was parsed")),
            "{source:?}: {:?}",
            run.finish_errors
        );
        assert_retry_latch_then_full_then_retained(&mut world, "(5b)");
    }
}

/// After a `finish` failure (`UnreadableCause::Reduction`) the generation is
/// terminal-unhealthy, so the unhealthy-retry latch (60 s, doubling, at most
/// an hour) holds the re-walk: the next scan at the same clock does not read
/// the file at all, even after a change. The first scan past the deadline
/// re-reads it with no copy, `Full(StateMissing)` (`(1, 0)`), and admits its
/// copy again (`InsertAdmitted`); the next change after it continues that copy
/// as a Tail.
fn assert_retry_latch_then_full_then_retained(world: &mut World, row: &str) {
    let source = world.source;
    let deadline = world
        .index
        .traversal
        .as_ref()
        .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds);
    assert!(
        deadline.is_some(),
        "the retry latch is set {row} {source:?}"
    );
    let held = next_read_at(world, NOW, true);
    assert_eq!(
        (
            held.reads,
            held.counts.take_hit,
            held.counts.insert_admitted
        ),
        (0, 0, 0),
        "the latch holds the file unread {row} {source:?}"
    );
    let due = next_read_at(world, PAST_RETRY, false);
    assert_eq!(
        (due.state_missing, due.tails),
        (1, 0),
        "past the deadline: Full(StateMissing) {row} {source:?}"
    );
    assert_eq!(
        due.counts.insert_admitted, 1,
        "re-retained {row} {source:?}"
    );
    assert!(world.inserted(), "{row} {source:?}");
    let stable = next_read_at(world, PAST_RETRY, true);
    assert_eq!(
        (stable.state_missing, stable.tails),
        (0, 1),
        "the re-retained copy continues {row} {source:?}"
    );
}

/// T-R0b‴(6), the disclosed (g1), on a scan with an attribution context (a
/// launch root and a launch event for the Codex session, as
/// `launch_demand_tests`): the launch lookup expires after retention, so
/// `finish` fails its launch `ensure!` after the release
/// (`UnreadableCause::Reduction`, no insert; the retry latch, then
/// `Full(StateMissing)` and re-retention past its deadline). The control
/// run, unexpired, inserts.
#[test]
fn r0_tail_launch_lookup_expiry_is_disclosed_g1() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let spec = Spec {
        attribution: true,
        ..SPEC
    };
    let (probe, _) = probe_spec(source, spec);

    let (world, control) = calibrated(source, spec, &probe, 1, |_| Opts::default());
    assert!(
        control.finish_errors.is_empty(),
        "{:?}",
        control.finish_errors
    );
    assert_released_then_inserted(&world, &control, &world.older_keys(1), "(6) control");

    let (mut world, run) = calibrated(source, spec, &probe, 1, |world| {
        let (context, _) = world.attribution.as_ref().unwrap();
        let context = Rc::clone(context);
        Opts {
            hooks: vec![(
                Point::AfterRetain,
                Box::new(move || context.expire_launch_lookup_for_test()) as Hook,
            )],
            ..Opts::default()
        }
    });
    assert_released_then_dropped(&world, &run, "(6)");
    assert_eq!(run.unreadable, vec![REDUCTION]);
    assert!(
        matches!(run.finish_errors.as_slice(), [error] if error.contains("launch evidence lookup incomplete")),
        "{:?}",
        run.finish_errors
    );
    assert_retry_latch_then_full_then_retained(&mut world, "(6)");
}

/// The incumbent's file reason in a run's pending finalization.
fn file_reason(world: &World, run: &Run) -> FileReason {
    let key = key(&world.incumbent);
    run.result
        .pending_finalization
        .iter()
        .find(|pending| pending.index_key == key)
        .expect("the incumbent finished")
        .diagnostic_reason
}

/// T-R0b‴(7), the disclosed (h1), Codex: a retained confirmed-empty file
/// appends positive usage evidence in an envelope the parser does not read.
/// Released and produced, then the zero-snapshot rule drops the copy:
/// `RecognizedUsageDropped`, census `zero_snapshot_usage_evidence_count`.
#[test]
fn r0_codex_zero_snapshot_evidence_is_disclosed_h1() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let spec = Spec {
        rows: 0,
        change: append_unknown_evidence,
        ..SPEC
    };
    let (probe, _) = probe_spec(source, spec);
    let (world, run) = calibrated(source, spec, &probe, 1, |_| Opts::default());
    assert_released_then_dropped(&world, &run, "(7)");
    assert!(run.finish_errors.is_empty() && run.unreadable.is_empty());
    assert_eq!(
        (
            run.result.zero_snapshot_usage_evidence_count,
            run.result.recognized_usage_drop_count,
        ),
        (1, 1)
    );
    assert_eq!(
        file_reason(&world, &run),
        FileReason::RecognizedUsageDropped
    );
}

/// T-R0b‴(8), the disclosed (h2), Claude: one assistant record whose
/// timestamp does not parse. It adds a response record, so Q-PR15's guard
/// refuses the release (`K = F_prev > C` and the usage witness grew): no
/// resident is evicted. The clone fits `b_ins`; CI measured that the dropped
/// record grows the finalization charge past it
/// (`RetentionFinalizationBoundRefused`), before (h2) could drop the copy
/// (`RecognizedUsageDropped`, census `dropped_usage_record_count`). No insert
/// and no eviction.
#[test]
fn r0_claude_response_finalization_drop_is_disclosed_h2() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let spec = Spec {
        change: append_malformed_timestamp,
        ..SPEC
    };
    let (probe, _) = probe_spec(source, spec);
    let (world, run) = calibrated(source, spec, &probe, 1, |_| Opts::default());
    assert!(run.probe.finalization_guard, "(8)");
    assert!(
        matches!(run.decisions.as_slice(), [Decision::Granted { .. }]),
        "(8) {:?}",
        run.decisions
    );
    let (at_retain, _) = run.at_retain.clone().expect("retention ran");
    assert_eq!(at_retain, run.before, "(8)");
    assert_step_start_and_insert_evict_nothing(&run, "(8)");
    assert_eq!(
        (
            run.counts.copy_refusal_admission_evicted,
            run.counts.retention_produced,
            run.counts.retention_finalization_bound_refused,
            run.counts.insert_admitted,
        ),
        (0, 1, 1, 0),
        "(8)"
    );
    assert_eq!(victims(&world.cache), run.before, "(8)");
    assert!(run.finish_errors.is_empty() && run.unreadable.is_empty());
    assert_eq!(
        (
            run.result.dropped_usage_record_count,
            run.result.recognized_usage_drop_count,
        ),
        (1, 1)
    );
    assert_eq!(
        file_reason(&world, &run),
        FileReason::RecognizedUsageDropped
    );
}

/// T-R0b-cursor, the disclosed (f), substitute by fixture cost (the
/// production site is reachable): cursor state that grows between retention
/// and the insert. The production growth sites (the `witness_parent` calls in
/// the completion) need a Codex child/parent ledger pair mid-completion; the
/// row calls the same `witness_parent` at `AfterRetain` instead, with a
/// witness one and a half residents past the room the release left. Its
/// admission evicts the next oldest resident
/// (`CursorReservationEntriesEvicted`), oldest first. The cache is scaled to
/// the calibrated state budget (`scaled_cache`), so its insert enforces the
/// production limit: beside the grown cursor state its loop evicts in victim
/// order the last older resident, the copy and the newer resident
/// (`InsertEntriesEvicted` 3), then refuses with no victim left
/// (`InsertNoVictimRefused`; the cursor state alone leaves no room), and no
/// later step evicts (`CopyRefusalEntriesEvicted` unchanged). The whole global
/// victim order leaves, in order (CI receipt `R0_F_INSERT_PHASE scaled
/// gone=4 inserted=false newer_resident=false`). On an unscaled cache (the
/// previous form of this row)
/// the insert admitted against `STATE_BYTES` and the next step's M1
/// evict-to-fit removed the same entries instead: a fixture artifact.
#[test]
fn r0_cursor_growth_after_release_is_disclosed_f() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let (probe, freed) = probe_world(source, OLDER);
    let remaining = state_for_need(&probe, freed) - (sampled_scan::state_bytes() - probe.remaining);
    let witnessed = Rc::new(RefCell::new(None));
    let seen = Rc::clone(&witnessed);
    let spec = Spec {
        scaled_cache: true,
        ..SPEC
    };
    let (world, run) = calibrated(source, spec, &probe, freed, |world| {
        let cache = Arc::clone(&world.cache);
        let identity = "w".repeat(remaining + freed + freed / 2);
        let hook = move || {
            let admitted = cache.witness_parent(
                &Scope("r0-witness".into()),
                "r0-witness-scope",
                "r0-witness-parent",
                sampled_scan::codex_cursor::ParentWitness {
                    cause: CodexParentUnresolvable::NoLedger,
                    identity: Some(identity.clone()),
                    waits_on: None,
                },
            );
            *seen.borrow_mut() = Some((admitted, victims(&cache), observed().unwrap()));
        };
        Opts {
            hooks: vec![(Point::AfterRetain, Box::new(hook) as Hook)],
            ..Opts::default()
        }
    });
    let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
    assert_eq!(at_retain, without(&run, &world.older_keys(1)));
    let (admitted, after, counts) = witnessed.borrow_mut().take().expect("the witness ran");
    assert!(admitted, "the witness is admitted");
    assert_eq!(
        after,
        without(&run, &world.older_keys(2)),
        "(f): the next oldest resident leaves first"
    );
    assert_eq!(
        counts.cursor_reservation_entries_evicted - phase.cursor_reservation_entries_evicted,
        1
    );
    // The insert phase, after the witness: on the scaled cache the insert
    // itself enforces the state budget.
    let end = &run.counts;
    let final_residents: Victims = victims(&world.cache)
        .into_iter()
        .filter(|(k, _, _)| *k != key(&world.incumbent))
        .collect();
    let gone = run.before.len() - final_residents.len();
    eprintln!(
        "R0_F_INSERT_PHASE scaled gone={gone} inserted={} newer_resident={} counts={end:?}",
        world.inserted(),
        resident_keys(&world.cache).contains(&world.newer_key())
    );
    // Global victim order: the older residents, then the copy, then the
    // newer resident. All of it leaves, in that order.
    let mut order = world.older_keys(OLDER);
    order.push(world.newer_key());
    assert_eq!(gone, OLDER + 1, "(f) insert phase: every resident leaves");
    assert_eq!(
        final_residents,
        run.before
            .iter()
            .filter(|(k, _, _)| !order.contains(k))
            .cloned()
            .collect::<Victims>(),
        "(f) insert phase: the victim order only"
    );
    assert_eq!(
        (
            end.insert_admitted,
            end.insert_self_evicted,
            end.insert_no_victim_refused,
            end.insert_entries_evicted,
            end.copy_refusal_admission_evicted,
            end.copy_refusal_entries_evicted - counts.copy_refusal_entries_evicted,
            world.inserted(),
        ),
        (0, 0, 1, 3, phase.copy_refusal_admission_evicted, 0, false),
        "(f) {end:?}"
    );
}

/// Two appenders: A admitted first, B next, then A's own Tail re-admitted A
/// at `a_secs` past the base (newer than B's taken hint). B then changes
/// as `releasing` changes it and is stamped `b_at` (the base plus 2,500 s by
/// default). B continues; A is resident.
fn interleaved_at(source: SnapshotSource, a_secs: u64, b_at: Option<SystemTime>) -> World {
    let base = SystemTime::now() - Duration::from_secs(3_600);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let scan = |fixture: &ScanFixture, index| {
        production_scan(fixture, source, index, Some(cache.clone()), "mixed-files").0
    };
    let a = scan_fixture(source, INCUMBENT_ROWS, base + Duration::from_secs(1_000));
    let a_index = scan(&a, ScanIndex::default());
    let b = scan_fixture(source, INCUMBENT_ROWS, base + Duration::from_secs(1_500));
    let index = scan(&b, ScanIndex::default());
    append_row(&a, source);
    set_modified(&a, base + Duration::from_secs(a_secs));
    scan(&a, a_index);
    let hint = |fixture: &ScanFixture| {
        victims(&cache)
            .into_iter()
            .find(|(k, _, _)| *k == key(fixture))
            .unwrap_or_else(|| panic!("precondition: resident {source:?}"))
            .1
    };
    let incumbent_hint = hint(&b);
    assert!(
        hint(&a) > incumbent_hint,
        "precondition: A re-admitted after B {source:?}"
    );
    (releasing(source).change)(&b, source);
    set_modified(&b, b_at.unwrap_or(base + Duration::from_secs(2_500)));
    World {
        source,
        spec: Spec {
            older: 0,
            ..releasing(source)
        },
        base,
        cache,
        older: Vec::new(),
        newer: Some(a),
        incumbent: b,
        incumbent_hint,
        index,
        first: Vec::new(),
        attribution: None,
        appended: 0,
    }
}

/// `interleaved_at` continued at the state budget that gives B a need of
/// 64 KiB (well past the 1-byte edge: at need 1 CI measured Codex's copy
/// admitted), calibrated against a probe of the same world.
fn interleaved_run(
    source: SnapshotSource,
    a_secs: u64,
    b_at: Option<SystemTime>,
    opts: impl FnOnce(&World) -> Opts,
) -> (World, Run) {
    const NEED: usize = 64 * 1024;
    let probe = run_probe(&mut interleaved_at(source, a_secs, b_at));
    let state = state_for_need(&probe, NEED);
    let mut world = interleaved_at(source, a_secs, b_at);
    let opts = Opts {
        budgets: Some((state, crate::transcript_cache::entry_bytes())),
        ..opts(&world)
    };
    let run = run(&mut world, opts);
    assert_calibrated(source, &probe, &run, state, NEED);
    (world, run)
}

/// A resident's admitted hint in `victims`.
fn hint_in(victims: &[(String, (i64, i64), usize)], key: &str) -> Option<(i64, i64)> {
    victims
        .iter()
        .find(|(k, _, _)| k == key)
        .map(|(_, hint, _)| *hint)
}

/// A fixture's mtime as an admission hint (`(secs, nanos)`).
fn mtime_hint(fixture: &ScanFixture) -> (i64, i64) {
    let since = fs::metadata(&fixture.file.0)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (since.as_secs() as i64, i64::from(since.subsec_nanos()))
}

fn clock_hint() -> (i64, i64) {
    let now = crate::transcript_cache::admission_now();
    (now.as_secs() as i64, i64::from(now.subsec_nanos()))
}

/// T-R0b-hint (i), unchanged by the rank amendment: a resident with a future
/// mtime is admitted with its hint clipped to admission time; an incumbent
/// written and admitted after it ranks above that hint, so the resident is a
/// candidate and its release covers the need. By raw mtime it would not be
/// older.
#[test]
fn r0_release_candidates_rank_by_clipped_admission_hints() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let spec = Spec {
            older: 1,
            fresh: true,
            ..releasing(source)
        };
        let (probe, freed) = probe_spec(source, spec);
        let (world, fresh) = calibrated(source, spec, &probe, freed, |_| Opts::default());
        let older = world.older_keys(1);
        let resident_hint = hint_in(&fresh.before, &older[0]).expect("the future resident");
        let mtime = mtime_hint(&world.older[0]);
        assert!(resident_hint < mtime, "(i) clipped {source:?}");
        assert!(
            mtime > world.incumbent_hint,
            "(i) by mtime the resident is not older {source:?}"
        );
        let rank = fresh.probe.rank.expect("(i) ranked");
        assert!(resident_hint < rank, "(i) {source:?}");
        assert_eq!(
            fresh.active_hint,
            Some(Some(world.incumbent_hint)),
            "(i) {source:?}"
        );
        assert!(
            matches!(fresh.decisions.as_slice(), [Decision::Deferred { .. }]),
            "(i) {source:?}"
        );
        let (at_retain, phase) = fresh.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, without(&fresh, &older), "(i) {source:?}");
        assert_eq!(phase.copy_refusal_admission_evicted, 1, "(i) {source:?}");
    }
}

/// Q-PR14 amendment (parent ruling 1): the release ranks by the completed
/// copy's re-admission rank, not its taken hint. Two interleaved appenders:
/// A was re-admitted after B's taken hint, but below B's current mtime, the
/// rank B's copy is re-admitted at. A is a candidate: B releases exactly A
/// (`CopyRefusalAdmissionEvicted` 1) and is admitted; its admitted hint is
/// exactly the rank the release ranked against (rank agreement). Under the
/// taken-hint rule (8ccf0d2f) A was protected and B's copy refused. Claude's
/// change is an ignored line (Q-PR15's guard is unchanged and would refuse a
/// usage append first).
#[test]
fn r0_release_ranks_by_the_copys_re_admission_rank() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (world, run) = interleaved_run(source, 2_000, None, |_| Opts::default());
        let a = world.newer_key();
        let a_hint = hint_in(&run.before, &a).expect("A is resident");
        let rank = run.probe.rank.expect("ranked");
        assert!(
            world.incumbent_hint < a_hint && a_hint < rank,
            "precondition: A sits between B's taken hint and its rank {source:?}"
        );
        assert_eq!(
            rank,
            mtime_hint(&world.incumbent),
            "a past mtime is its own rank {source:?}"
        );
        assert!(
            matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
            "{source:?} {:?}",
            run.decisions
        );
        let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, without(&run, &[a]), "{source:?}");
        assert_eq!(
            (
                phase.copy_refusal_admission_evicted,
                phase.retention_produced
            ),
            (1, 1),
            "{source:?}"
        );
        assert_step_start_and_insert_evict_nothing(&run, "rank");
        assert_eq!(run.counts.insert_admitted, 1, "{source:?}");
        assert_eq!(
            hint_in(&victims(&world.cache), &key(&world.incumbent)),
            Some(rank),
            "rank agreement: the copy is admitted at the release's rank {source:?}"
        );
    }
}

/// Equal ranks are protected: A re-admitted at exactly B's current mtime
/// ranks equal to B's re-admission rank, so it is not a candidate. Nothing is
/// released, A is intact, and B's copy, which cannot fit beside A, is not
/// admitted.
#[test]
fn r0_release_rank_protects_an_equal_rank() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (world, run) = interleaved_run(source, 2_500, None, |_| Opts::default());
        let a = world.newer_key();
        let rank = run.probe.rank.expect("ranked");
        assert_eq!(
            hint_in(&run.before, &a),
            Some(rank),
            "precondition: A ranks equal to B's re-admission rank {source:?}"
        );
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: run.probe.b_ins,
                resident_measured: true,
                active_measured: true,
            }],
            "{source:?}"
        );
        assert_eq!(victims(&world.cache), run.before, "{source:?}");
        assert_eq!(
            (
                run.counts.copy_refusal_admission_evicted,
                run.counts.copy_refusal_entries_evicted,
                run.counts.insert_entries_evicted,
            ),
            (0, 0, 0),
            "{source:?}"
        );
        assert!(!world.inserted(), "{source:?}");
    }
}

/// A future mtime is clipped once, at the completion's decision: B stamped a
/// day ahead ranks at the clock read then (between the clocks before and
/// after the run, below its mtime). A ranks below it and is released, and B's
/// copy is admitted at exactly that rank, not at its mtime and not at the
/// insert's later clock.
#[test]
fn r0_release_rank_clips_a_future_mtime_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let future = SystemTime::now() + Duration::from_secs(86_400);
        let before = clock_hint();
        let (world, run) = interleaved_run(source, 2_000, Some(future), |_| Opts::default());
        let after = clock_hint();
        let mtime = mtime_hint(&world.incumbent);
        let rank = run.probe.rank.expect("ranked");
        assert!(
            before <= rank && rank <= after && rank < mtime,
            "clipped to the decision's clock {source:?}: {before:?} {rank:?} {after:?} {mtime:?}"
        );
        assert!(
            matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
            "{source:?} {:?}",
            run.decisions
        );
        let a = world.newer_key();
        let (at_retain, _) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, without(&run, &[a]), "{source:?}");
        assert_eq!(run.counts.insert_admitted, 1, "{source:?}");
        assert_eq!(
            hint_in(&victims(&world.cache), &key(&world.incumbent)),
            Some(rank),
            "rank agreement {source:?}"
        );
    }
}

/// A failed gate mutates nothing, for a resident only the re-admission rank
/// makes a candidate: B's release of A is deferred, then an append before the
/// stamp gate fails it (`RetentionUnsealedEof`); A is intact, nothing is
/// evicted and no copy is admitted.
#[test]
fn r0_release_rank_failed_gate_evicts_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (world, run) = interleaved_run(source, 2_000, None, |world| Opts {
            hooks: vec![(Point::BeforeStampGate, appender(world))],
            ..Opts::default()
        });
        let a = world.newer_key();
        assert!(
            hint_in(&run.before, &a).expect("A is resident") < run.probe.rank.expect("ranked"),
            "precondition: A is a candidate {source:?}"
        );
        assert!(
            matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
            "{source:?}"
        );
        assert_eq!(victims(&world.cache), run.before, "{source:?}");
        assert_eq!(
            (
                run.counts.copy_refusal_admission_evicted,
                run.counts.copy_refusal_entries_evicted,
                run.counts.insert_entries_evicted,
                run.counts.retention_produced,
                run.counts.insert_admitted,
                run.counts.retention_unsealed_eof,
            ),
            (0, 0, 0, 0, 0, 1),
            "{source:?}"
        );
        assert!(!world.inserted(), "{source:?}");
    }
}

fn run_probe(world: &mut World) -> Probe {
    run(world, Opts::default()).probe
}

/// T-R0c: a Claude Tail whose active state passes the walk's 4096 visits.
/// No step-start clear; the completion is granted 0 with the active
/// unmeasured (bucket `Walk`), and nothing is released.
#[test]
fn r0_tail_past_the_visit_limit_is_granted_without_release() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let mut world = World::build(
        source,
        Spec {
            change: append_many,
            ..SPEC
        },
    );
    let run = run(&mut world, Opts::default());
    assert_eq!(
        run.decisions,
        vec![Decision::Granted {
            budget: 0,
            resident_measured: true,
            active_measured: false,
        }]
    );
    assert_eq!(run.buckets, vec![Bucket::Walk]);
    let counts = run.counts;
    assert_eq!(
        (
            counts.clear_other_active,
            counts.clear_no_active,
            counts.clear_full_resident_bound_unknown,
            counts.clear_metadata_unsupported,
            counts.clear_entries_released,
            counts.insert_entries_evicted,
            counts.copy_refusal_admission_evicted,
            counts.copy_refusal_entries_evicted,
            counts.retention_bound_refused,
        ),
        (0, 0, 0, 0, 0, 0, 0, 0, 1)
    );
    assert_eq!(victims(&world.cache), run.before);
}

/// T-R0d: every borrowed-state conjunct keeps a Tail off shape F, so its
/// step-start refusal keeps `ClearOtherActive`, and its completion never
/// reaches `tail_completion_budget` (the only source of `Deferred`, called
/// only behind `borrows_only_retained_reduction`). Aliases and receipts are
/// in the guard matrix; the cursor and group conjuncts are in
/// `codex_cursor_tests` and `group_job_tests`.
#[test]
fn r0_non_f_shapes_keep_clear_other_active() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut world = World::new(source);
        let index = std::mem::take(&mut world.index);
        let mut scan = step_until(
            cached_scan(&world.incumbent, source, index, &world.cache, |_| {}),
            |scan| scan.active_file.is_some(),
        );
        let release = |scan: &mut OwnedSourceScan| {
            let (_, measured) = scan.sampled_copy_parts();
            assert!(measured.is_some(), "precondition: measured {source:?}");
            observe(|| {
                sampled_scan::release_cache_for_copy_refusal(
                    scan.sampling.as_ref(),
                    scan.active_file.as_deref(),
                    measured,
                )
            })
            .1
        };
        let shape_f = |scan: &OwnedSourceScan| {
            sampled_scan::borrows_only_retained_reduction(scan.active_file.as_deref().unwrap())
        };
        assert!(shape_f(&scan), "precondition: shape F {source:?}");
        assert_eq!(release(&mut scan), Counts::default(), "{source:?}");

        let active = scan.active_file.as_deref_mut().unwrap();
        active.comparison_target = true;
        assert!(!shape_f(&scan), "comparison target {source:?}");
        assert_eq!(release(&mut scan).clear_other_active, 1, "{source:?}");
        scan.active_file.as_deref_mut().unwrap().comparison_target = false;

        let active = scan.active_file.as_deref_mut().unwrap();
        let plan = active.parser.reader.acquisition.take();
        assert!(!shape_f(&scan), "no acquisition {source:?}");
        assert_eq!(release(&mut scan).clear_other_active, 1, "{source:?}");
        scan.active_file
            .as_deref_mut()
            .unwrap()
            .parser
            .reader
            .acquisition = plan;

        let active = scan.active_file.as_deref_mut().unwrap();
        let sampling = active.sampling.as_mut().unwrap();
        let mode = sampling.mode;
        sampling.mode = ReadMode::Unchanged;
        assert!(shape_f(&scan), "Unchanged is shape F {source:?}");
        let active = scan.active_file.as_deref_mut().unwrap();
        active.sampling.as_mut().unwrap().mode = mode;

        if source == SnapshotSource::Codex {
            let active = scan.active_file.as_deref_mut().unwrap();
            let replay = active.parser.accumulator.codex_tier_replay.take();
            let mut joined = replay
                .clone()
                .unwrap_or_else(|| codex_file_join::TierReplay::new(None, false, String::new()));
            joined.join = Some(Box::new(codex_file_join::StreamProof::new(
                String::new(),
                false,
                vec![codex_file_join::MemberPlan::default()],
            )));
            active.parser.accumulator.codex_tier_replay = Some(joined);
            assert!(!shape_f(&scan), "join");
            assert_eq!(release(&mut scan).clear_other_active, 1, "join");
            scan.active_file
                .as_deref_mut()
                .unwrap()
                .parser
                .accumulator
                .codex_tier_replay = replay;
        }
        assert!(shape_f(&scan), "restored {source:?}");
    }
}

/// Runs `release` inside `observe` while another thread holds the retained
/// lock; that thread lets go once it sees a new
/// `ClearFullResidentBoundUnknown`, or after 5 s.
fn contended<T>(
    cache: &Arc<sampled_scan::SharedCache>,
    release: impl FnOnce() -> T,
) -> (T, Counts) {
    use crate::local_resource_diagnostics::cache_lifecycle::snapshot;
    let seen = snapshot().clear_full_resident_bound_unknown;
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let holder = {
        let cache = Arc::clone(cache);
        std::thread::spawn(move || {
            let guard = cache.retained().unwrap();
            held_tx.send(()).unwrap();
            let start = std::time::Instant::now();
            while snapshot().clear_full_resident_bound_unknown == seen
                && start.elapsed() < Duration::from_secs(5)
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(guard);
        })
    };
    held_rx.recv().unwrap();
    let observed = observe(release);
    holder.join().unwrap();
    observed
}

/// T-R0e: branches A (a sampled Full read) and D (an unsampled native read)
/// release as at base. Measured and uncontended, neither clears; contended
/// (another thread holds the retained lock), each records
/// `ClearFullResidentBoundUnknown` and releases every resident once the lock
/// is free, never `ClearOtherActive`.
#[test]
fn r0_branches_a_and_d_release_as_base_under_contention() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clears = |counts: &Counts| {
        (
            counts.clear_full_resident_bound_unknown,
            counts.clear_entries_released,
            counts.clear_other_active,
            counts.clear_no_active,
        )
    };
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        // A: a new file read Full beside one resident.
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let base = SystemTime::now() - Duration::from_secs(3_600);
        let other = resident(source, &cache, 1, base);
        let full = scan_fixture(source, INCUMBENT_ROWS, base + Duration::from_secs(1_000));
        let scan = step_until(
            cached_scan(&full, source, ScanIndex::default(), &cache, |_| {}),
            |scan| scan.active_file.is_some(),
        );
        assert!(
            matches!(
                scan.active_file
                    .as_deref()
                    .and_then(|active| active.sampling.as_ref())
                    .map(|sampling| sampling.mode),
                Some(ReadMode::Full(_))
            ),
            "precondition: branch A {source:?}"
        );
        let release = || {
            sampled_scan::release_cache_for_copy_refusal(
                scan.sampling.as_ref(),
                scan.active_file.as_deref(),
                None,
            )
        };
        let ((), counts) = observe(release);
        assert_eq!(clears(&counts), (0, 0, 0, 0), "A {source:?}");
        assert!(resident_keys(&cache).contains(&key(&other)), "{source:?}");
        let ((), counts) = contended(&cache, release);
        assert_eq!(clears(&counts), (1, 1, 0, 0), "contended A {source:?}");
        assert!(resident_keys(&cache).is_empty(), "{source:?}");
        drop(scan);

        // D: an unsampled native read beside one resident.
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let other = resident(source, &cache, 1, base);
        let large = ScanFixture::new(source);
        append_unretainable_rows(&large, source);
        let mut scan = step_until(
            cached_scan(
                &large,
                source,
                ScanIndex::default(),
                &cache,
                incomplete_sidecar_census,
            ),
            |scan| scan.active_file.is_some(),
        );
        assert!(
            scan.active_file
                .as_deref()
                .is_some_and(|active| active.sampling.is_none()),
            "precondition: branch D {source:?}"
        );
        let (measured, counts) = contended(&cache, || {
            let (_, measured) = scan.sampled_copy_parts();
            sampled_scan::release_cache_for_copy_refusal(
                scan.sampling.as_ref(),
                scan.active_file.as_deref(),
                measured,
            );
            measured
        });
        assert_eq!(measured, None, "contention reads unmeasured {source:?}");
        assert_eq!(clears(&counts), (1, 1, 0, 0), "contended D {source:?}");
        assert!(!resident_keys(&cache).contains(&key(&other)), "{source:?}");
    }
}

/// T-R0f: an unknown resident bound (a poisoned retained lock while a Tail
/// is active). Shape F evicts nothing at step start or completion, and its
/// own copy is refused (granted 0, residents unmeasured: bucket `Walk`; the
/// step measure still walks the active, so it reads measured).
/// An unsupported layout is not reachable here: every R0 test returns early
/// without it, and a supported CI build always has it.
#[test]
fn r0_unknown_resident_evicts_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut world = World::new(source);
        let cache = Arc::clone(&world.cache);
        let run = run(
            &mut world,
            Opts {
                on_active: Some(
                    Box::new(move |_: &OwnedSourceScan| cache.poison_retained()) as OnActive
                ),
                ..Opts::default()
            },
        );
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: 0,
                resident_measured: false,
                active_measured: true,
            }],
            "{source:?}"
        );
        assert_eq!(run.buckets, vec![Bucket::Walk], "{source:?}");
        assert_eq!(
            (
                run.counts.insert_entries_evicted,
                run.counts.copy_refusal_admission_evicted,
                run.counts.copy_refusal_entries_evicted,
                run.counts.clear_entries_released,
                run.counts.retention_produced,
                run.counts.insert_admitted,
            ),
            (0, 0, 0, 0, 0, 0),
            "{source:?}"
        );
        assert_eq!(victims(&world.cache), run.before, "{source:?}");
    }
}
