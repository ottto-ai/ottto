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

/// T-R0c (Claude): one usage-bearing assistant record with 2,500 browser
/// `tool_use` blocks, every block with its own id. Since #667 the response
/// book keeps a per-record summary (`owned_heap`), so many small records no
/// longer reach the walk's 4,096 visits; one record whose `tool_uses` (two
/// strings per call) pass them leaves its summary, and so the active,
/// unmeasured. Usage rows alone do not: the parser's walk is constant in its
/// row count (pinned by
/// `sampled_native_large_history_has_constant_step_charge_and_conservative_clones`).
fn append_many(fixture: &ScanFixture, source: SnapshotSource) {
    assert_eq!(source, SnapshotSource::ClaudeCode);
    let blocks = (0..2_500_usize)
        .map(|block| {
            json!({"type":"tool_use", "id":format!("toolu_r0_{block:04}"),
                "name":"mcp__claude-in-chrome__navigate", "input":{}})
        })
        .collect::<Vec<_>>();
    fixture.file.append(
        &json!({"type":"assistant", "sessionId":"native-tail-fixture",
        "requestId":"req_r0_many", "timestamp":"2026-10-07T11:00:00Z",
        "message":{"id":"response-r0-many", "role":"assistant", "model":"fixture-model-tail",
            "usage":{"input_tokens":1,"output_tokens":1}, "content":blocks}}),
    );
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
    ins_extra: None,
    attribution: false,
    fresh: false,
};

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
    cache: Arc<sampled_scan::SharedCache>,
    older: Vec<ScanFixture>,
    newer: Option<ScanFixture>,
    incumbent: ScanFixture,
    index: ScanIndex,
    /// What the incumbent's first (Full) completion was granted (Q-PR13b).
    first: Vec<Decision>,
    attribution: Option<(Rc<SessionAttributionContext>, LaunchHome)>,
}
impl World {
    fn new(source: SnapshotSource) -> Self {
        Self::build(source, SPEC)
    }
    fn build(source: SnapshotSource, spec: Spec) -> Self {
        let base = SystemTime::now() - Duration::from_secs(3_600);
        let cache = Arc::new(sampled_scan::SharedCache::default());
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
        assert!(
            victims(&cache)
                .iter()
                .any(|(k, _, _)| *k == key(&incumbent)),
            "precondition: the incumbent is resident {source:?}"
        );
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
            cache,
            older,
            newer,
            incumbent,
            index,
            first,
            attribution,
        }
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
    /// Census unreadable causes, by ordinal.
    unreadable: Vec<usize>,
    /// Failed `finish` error chains.
    finish_errors: Vec<String>,
}

/// How a continued scan runs.
#[derive(Default)]
struct Opts {
    hooks: Vec<(Point, Hook)>,
    /// Called once, between the steps, when the active file first exists.
    on_active: Option<OnActive>,
}

/// Steps `scan` to completion and returns its index.
fn complete(
    mut scan: OwnedSourceScan,
    context: Option<&SessionAttributionContext>,
    mut on_active: Option<OnActive>,
) -> ScanIndex {
    for _ in 0..10_000 {
        if scan.active_file.is_some() {
            if let Some(on_active) = on_active.take() {
                on_active(&scan);
            }
        }
        match scan.step(context) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, .. } => return index,
        }
    }
    panic!("the scan did not complete");
}

/// Continues the incumbent as `opts` says. Hooks run in order after the
/// recorder of `at_retain`.
fn run(world: &mut World, opts: Opts) -> Run {
    let Opts { hooks, on_active } = opts;
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
        )
    };
    let (index, counts) = observe(scan);
    world.index = index;
    let run = Run {
        probe: test_hooks::last_probe(),
        decisions: test_hooks::decisions(),
        buckets: test_hooks::buckets(),
        before,
        before_retain: before_retain.borrow_mut().take(),
        at_retain: at_retain.borrow_mut().take(),
        counts,
        unreadable: test_hooks::unreadable(),
        finish_errors: test_hooks::finish_errors(),
    };
    test_hooks::clear();
    eprintln!(
        "R0 {:?}: probe {:?}, decisions {:?}, buckets {:?}",
        world.source, run.probe, run.decisions, run.buckets
    );
    run
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
        // #667: a granted copy is admitted against main's peak-reserved
        // budget, `b_ins` less the decode peak (none for Codex).
        let peak = probe.granted_peak.expect("granted peak");
        if source == SnapshotSource::Codex {
            assert_eq!(peak, 0);
        }
        assert_eq!(
            run.decisions,
            vec![Decision::Granted {
                budget: probe.b_ins - peak,
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
        // Nothing released before or at retention; no unreadable cause and
        // no failed finish.
        assert_eq!(
            run.before_retain
                .map(|counts| counts.copy_refusal_admission_evicted),
            Some(0),
            "{source:?}"
        );
        assert_eq!(
            run.at_retain
                .as_ref()
                .map(|(_, counts)| counts.copy_refusal_admission_evicted),
            Some(0),
            "{source:?}"
        );
        assert!(run.unreadable.is_empty(), "{source:?}");
        assert!(run.finish_errors.is_empty(), "{source:?}");
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
                durable: Default::default(),
                checkpoint: taken.retained.checkpoint,
                reduction: Some(taken.retained.state),
                released: None,
                unsealed: false,
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
    let entry = crate::transcript_cache::ENTRY_BYTES;
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

    // Only a deferred release carries a released finalization limit
    // (`released_budget`); reserving #667's peak re-grants a granted budget
    // at main's peak-reserved figure and leaves excluded and unsealed ones.
    let granted = RetainBudget::granted_unclassified(7);
    assert_eq!(
        (
            granted.raw(),
            granted.admission_budget(),
            granted.released_budget()
        ),
        (7, 7, None)
    );
    assert!(matches!(
        RetainBudget::granted_unclassified(7).reserve_peak(5, |_| None),
        RetainBudget::Granted { budget: 5, .. }
    ));
    for budget in [
        RetainBudget::granted_unclassified(7).excluded(),
        RetainBudget::granted_unclassified(7).unsealed(),
    ] {
        assert_eq!(
            (
                budget.raw(),
                budget.admission_budget(),
                budget.released_budget()
            ),
            (7, 0, None)
        );
    }
    assert!(matches!(
        RetainBudget::granted_unclassified(7)
            .excluded()
            .reserve_peak(5, |_| None),
        RetainBudget::TierOrJoinExcluded { raw: 7 }
    ));
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

/// Why T-R0b-ins, -ins-band, -node and -node-band set `ins_extra` through
/// the test seam: each needs `ins_extra` against `A` at a chosen size. On a
/// minimal Tail (a confirmed-empty file plus one ignored line) the natural
/// relation moved with #660/#667: CI 39897160806 measured `ins_extra > A`
/// for both sources (Codex by under 1 KiB). It is recorded, not pinned.
#[test]
fn r0_insert_term_against_the_active_charge_on_supported_layouts() {
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
        eprintln!(
            "R0_INSERT_TERM source={source:?} a={} ins_extra={}",
            probe.a, probe.ins_extra
        );
        assert!(probe.ins_extra > 0 && probe.a > 0, "{source:?}: {probe:?}");
    }
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

/// X_out coverage witness (hunk map §3; c22 ACK): every field of the finished
/// `ParsedJsonlFile` and its `SnapshotItem` is named here with its X_out
/// family, so a new field fails compile until it is classified. Families:
/// I inline, R per Claude response, D derived from the accumulator at
/// `into_items`, M moved unchanged, K capped constant, U observed inputs
/// measured at the proof site (c22 amendment 2; unmeasurable refuses).
/// Compile-only: the closures never run.
#[test]
fn x_out_coverage_witness_names_every_finished_field() {
    let _parsed = |file: ParsedJsonlFile| {
        let ParsedJsonlFile {
            snapshots: _,                               // I (Vec slot) + per-item fields below
            report: _,                                  // M
            recognized_usage_drop_count: _,             // I
            cause: _,                                   // I (local Codex diagnostic)
            ownership_incomplete_file_count: _,         // I
            zero_snapshot_usage_evidence: _,            // I
            dropped_usage_record_count: _,              // I
            claude_compaction_unlinked_parent_count: _, // I
            terminal_line_loss_count: _,                // I
            state_only_blocked_session_ids: _,          // M (Codex only; empty on Claude)
            codex_parent_session_ref: _,                // M (Codex only)
            codex_parent_ledger_identity_used: _,       // M (Codex only)
            codex_parent_resolution_pending: _,         // I
            codex_parent_ownership_ledger: _,           // M (Codex only)
            codex_parent_unresolvable: _,               // I
            codex_parent_ledger_unusable: _,            // I
            codex_parent_ledger_consulted: _,           // I
            codex_parent_prefix_decided: _,             // I
            codex_parent_proof_used: _,                 // M (Codex only)
            codex_parent_proof_refusal: _,              // M (Codex only)
        } = file;
    };
    let _item = |item: SnapshotItem| {
        let SnapshotItem {
            session_account_evidence: _,                    // U (title metadata)
            source_session_id: _,                           // D
            snapshot_fingerprint: _,                        // K (empty)
            status: _,                                      // K ("final")
            input_tokens: _,                                // I
            output_tokens: _,                               // I
            cache_read_tokens: _,                           // I
            cache_creation_5m_tokens: _,                    // I
            cache_creation_1h_tokens: _,                    // I
            reasoning_output_tokens: _,                     // I
            unattributed_total_tokens: _,                   // I
            request_count: _,                               // I
            removed_request_count: _,                       // inline optional wire counters
            removed_usage: _,                               // inline optional wire counters
            telemetry_owned_complete: _,                    // inline optional authority marker
            resolver_conflict_count: _,                     // inline optional wire counter
            claude_money: _, // E aggregate is covered by finish output reserve
            usage_accounting_contract: _, // K (literal)
            claude_usage_request_ids: _, // R
            claude_usage_occurrences: _, // R
            cache_observations: _, // K (None on Claude)
            cache_observations_state: _, // K (None at into_items)
            cache_base_head_etag: _, // K (None at into_items)
            cache_requests: _, // R
            cache_requests_complete: _, // I
            avg_duration_ms: _, // I
            avg_time_to_first_token_ms: _, // I
            max_duration_ms: _, // I
            max_time_to_first_token_ms: _, // I
            peak_context_fill_tokens: _, // I
            first_turn_context_tokens: _, // I
            last_turn_context_tokens: _, // I
            first_turn_context_window_tokens: _, // I (Codex only; D1)
            peak_context_fill_window_tokens: _, // I (Codex only; D1)
            last_turn_context_window_tokens: _, // I (Codex only; D1)
            compaction_count: _, // I
            compaction_timestamps: _, // D
            compaction_events: _, // K (empty on Claude)
            local_context_points: _, // K (empty on Claude)
            first_own_request_at: _, // K (None at finish; #698)
            compaction_total_pre_tokens: _, // I
            compaction_total_post_tokens: _, // I
            compaction_total_cumulative_dropped_tokens: _, // I
            compaction_total_duration_ms: _, // I
            context_curve: _, // K (unavailable_context_curve)
            claude_context_curve_boundaries: _, // M
            claude_context_curve_identity_complete: _, // I
            claude_context_curve_request_index_complete: _, // I
            claude_context_curve_owned_start_proven: _, // I
            claude_file_birth: _, // M
            claude_file_birth_verdict: _, // I (inline enum; None at finish)
            activity_summary: _, // D
            tool_usage: _,   // D (from R's tool names)
            tool_usage_truncated: _, // I
            session_start: _, // U
            model_usage: _,  // D (rows from R)
            usage_buckets: _, // D (rows from R)
            cost: _,         // I
            session_display_name: _, // D / U (title metadata)
            session_display_name_source: _, // D / U (title metadata)
            source_started_at: _, // D
            source_ended_at: _, // D
            source_last_activity_at: _, // D
            collected_at: _, // K (RFC 3339)
            workspace_hash: _, // D
            workspace_display_label: _, // K (None)
            workspace_label_source: _, // K (None)
            repository_hash: _, // U (repository identity)
            repository_label: _, // U
            repository_label_source: _, // U
            repository_identity_source: _, // U
            workspace_kind: _, // U
            source_file_fingerprint: _, // K
            session_artifacts: _, // D
            provenance: _,   // K
            origin: _,       // D
            originator: _,   // D
            attribution_facts: _, // K (enforce_fact_limits caps)
            request_evidence: _, // K (empty at finish; filled post-scan, snapshot_sync)
            request_identity_refusals: _, // I
            claude_org_markers: _, // M
            claude_account_withheld_reason: _, // I (&'static str)
            claude_account_display: _, // K (None at finish; set post-scan, contract-5 tagging)
        } = item;
    };
}

fn u3_identity(tag: &str) -> crate::context_footprint::RepositoryIdentity {
    crate::context_footprint::RepositoryIdentity {
        repository_hash: Some(format!("hash-{tag}")),
        repository_label: Some(format!("label-{tag}")),
        repository_label_source: Some("git_remote".to_string()),
        repository_identity_source: Some("git".to_string()),
        workspace_kind: Some("git_repo".to_string()),
    }
}

/// X_out family U3 control (c22 amendment 2): a cold or expired cache entry
/// is `None` (the proof releases nothing), and peeking neither inserts nor
/// refreshes. Each workspace path is unique to this test: the cache is global.
#[test]
fn u3_repository_identity_peek_is_read_only_and_refuses_a_miss() {
    let cold = Path::new("/u3-peek-test/cold-workspace");
    assert_eq!(peek_repository_identity(cold), None);
    assert_eq!(
        peek_repository_identity(cold),
        None,
        "a miss is not inserted"
    );
    assert!(!repository_identity_cache()
        .lock()
        .expect("cache")
        .contains_key(cold));

    let warm = Path::new("/u3-peek-test/warm-workspace");
    let expired = Path::new("/u3-peek-test/expired-workspace");
    let stale_at =
        SystemTime::now() - Duration::from_secs(REPOSITORY_IDENTITY_CACHE_TTL_SECONDS + 60);
    {
        let mut cache = repository_identity_cache().lock().expect("cache");
        cache.insert(warm.to_path_buf(), (SystemTime::now(), u3_identity("warm")));
        cache.insert(expired.to_path_buf(), (stale_at, u3_identity("expired")));
    }
    assert_eq!(peek_repository_identity(warm), Some(u3_identity("warm")));
    assert_eq!(peek_repository_identity(expired), None);
    let cache = repository_identity_cache().lock().expect("cache");
    assert_eq!(
        cache.get(expired).map(|(at, _)| *at),
        Some(stale_at),
        "peek never extends the TTL"
    );
}

/// X_out family U3 (c22 amendment 2): the identity the proof measured is the
/// one the finished item carries; `into_items` resolves nothing (no IO, no
/// cache insert) when it is supplied.
/// [behaviour] Finalization preserves the measured repository identity without new IO.
#[test]
fn u3_measured_repository_identity_is_the_finished_value() {
    let workspace = "/u3-threading-test/workspace";
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    apply_claude_code_line(
        &serde_json::json!({"type":"assistant","sessionId":"u3-session","cwd":workspace,"requestId":"req_u3","timestamp":"2026-10-23T10:00:00Z","message":{"id":"msg_u3","model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":2}}}),
        &mut accumulator,
    );
    accumulator.finalize_claude_responses();
    let items = accumulator.into_items_with_repository_identity(
        Path::new("u3-session.jsonl"),
        "2026-10-23T10:00:01Z",
        "f".repeat(64),
        None,
        Some(u3_identity("measured")),
        false,
    );
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].repository_hash.as_deref(), Some("hash-measured"));
    assert_eq!(items[0].repository_label.as_deref(), Some("label-measured"));
    assert!(!repository_identity_cache()
        .lock()
        .expect("cache")
        .contains_key(Path::new(workspace)));
}

/// X_out family U1 (c22 amendment 2): a subagent transcript names itself from
/// agent metadata on disk, so its title bound is `None` (zero victims); a
/// top-level transcript's bound charges the desktop title it would take.
#[test]
fn u1_title_metadata_bound_refuses_subagents_and_charges_the_title() {
    let accumulator = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let mut metadata = ClaudeTitleMetadata::default();
    metadata.titles.insert(
        "u1-session".to_string(),
        ClaudeTitleCandidate {
            title: "  a   desktop  title  ".to_string(),
            user_set: true,
        },
    );
    assert_eq!(
        accumulator.claude_title_metadata_bound(
            Path::new("/p/u1-parent/subagents/agent-u1.jsonl"),
            &metadata
        ),
        None
    );
    let bound = accumulator
        .claude_title_metadata_bound(Path::new("/p/u1-session.jsonl"), &metadata)
        .expect("top-level bound");
    assert_eq!(bound.per_usage_row, 0);
    // r36 `desktop_title_bound(22)`: input and join (2 * 22), 11 one-byte
    // words in 16 slots plus the 8 beside them (24 * 16), the collect
    // (3 * 22), `is_safe_display_title`'s copies (2 * 22) and the item's
    // clone (22).
    assert_eq!(
        bound.fixed,
        2 * 22 + 24 * 16 + 3 * 22 + 2 * 22 + 22 + 2 * "desktop_title".len()
    );
}
