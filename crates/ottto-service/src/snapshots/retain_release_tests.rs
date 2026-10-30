//! P1-RETAIN R0: a sampled Tail/Unchanged singleton's completion-time release
//! of residents ranked below its copy's re-admission rank (shape F), and the
//! diagnostic packet's
//! refusal buckets. Its own block, apart from the shared appends above.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{observe, Counts};
use crate::session_attribution::SessionAttributionContext;
use sampled_jsonl::Bucket;
use sampled_scan::test_hooks::{self, Decision, Point, Probe};
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
