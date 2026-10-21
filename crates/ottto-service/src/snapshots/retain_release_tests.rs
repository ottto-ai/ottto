//! P1-RETAIN R0: a sampled Tail/Unchanged singleton's completion-time release
//! of strictly older-hint residents (shape F), and the diagnostic packet's
//! refusal buckets. Its own block, apart from the shared appends above.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{observe, observed, Counts};
use sampled_jsonl::{classify_refusal, Bucket, Refusal, RefusalView};
use sampled_scan::test_hooks::{self, Decision, Point, Probe};
use sampled_scan::{ReleaseOutcome, RetainBudget};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

type Victims = Vec<(String, (i64, i64), usize)>;

static SEQ: AtomicU64 = AtomicU64::new(0);

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
            json!({"type":"session_meta","payload":{"id":"019fa111-2222-7333-8444-555555555555"}}),
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

const OLDER: usize = 3;
/// The incumbent's rows: enough state that `2K + max(A, ins_extra)` covers
/// its own resident copy plus one older resident, so the calibrated budget
/// never refuses a step without an active file (base `ClearNoActive`).
const INCUMBENT_ROWS: usize = 48;

/// Strictly older residents (three by default), one newer one, and an
/// incumbent whose retained copy the next scan continues as a Tail. Every
/// resident has the same shape, so each frees the same bytes.
struct World {
    source: SnapshotSource,
    base: SystemTime,
    cache: Arc<sampled_scan::SharedCache>,
    older: Vec<ScanFixture>,
    newer: ScanFixture,
    incumbent: ScanFixture,
    index: ScanIndex,
    /// What the incumbent's first (Full) completion was granted (Q-PR13b).
    first: Vec<Decision>,
}
impl World {
    fn new(source: SnapshotSource) -> Self {
        Self::with_older(source, OLDER)
    }
    fn with_older(source: SnapshotSource, count: usize) -> Self {
        let base = SystemTime::now() - Duration::from_secs(3_600);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let older = (0..count as u64)
            .map(|i| resident(source, &cache, base + Duration::from_secs(i)))
            .collect();
        let newer = resident(source, &cache, base + Duration::from_secs(2_000));
        let incumbent = scan_fixture(source, INCUMBENT_ROWS, base + Duration::from_secs(1_000));
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
            cache.retained_checkpoint(&key(&incumbent)).is_some(),
            "precondition: the incumbent is resident {source:?}"
        );
        incumbent.file.append(&usage(
            source,
            100 + 10 * INCUMBENT_ROWS as u64,
            1_000,
            "fixture-model-tail",
        ));
        set_modified(&incumbent, base + Duration::from_secs(1_001));
        Self {
            source,
            base,
            cache,
            older,
            newer,
            incumbent,
            index,
            first,
        }
    }
    fn older_keys(&self, count: usize) -> Vec<String> {
        assert!(count <= self.older.len());
        self.older.iter().take(count).map(key).collect()
    }
}

fn resident(
    source: SnapshotSource,
    cache: &Arc<sampled_scan::SharedCache>,
    modified: SystemTime,
) -> ScanFixture {
    let fixture = scan_fixture(source, 1, modified);
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
    /// Residents and counts when retention returned, before `finish`.
    at_retain: Option<(Victims, Counts)>,
    counts: Counts,
}

fn complete(mut scan: OwnedSourceScan) {
    for _ in 0..10_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { .. } => return,
        }
    }
    panic!("the scan did not complete");
}

/// Continues the incumbent, at `budgets` (state, entry) when given, with
/// `before_stamp_gate` run at that point of a deferred retention.
fn run(
    world: &mut World,
    budgets: Option<(usize, usize)>,
    before_stamp_gate: Option<Box<dyn FnMut()>>,
) -> Run {
    test_hooks::clear();
    let at_retain = Rc::new(RefCell::new(None));
    let cache = Arc::clone(&world.cache);
    let seen = Rc::clone(&at_retain);
    test_hooks::set(Point::AfterRetain, move || {
        *seen.borrow_mut() = Some((victims(&cache), observed().unwrap()));
    });
    if let Some(hook) = before_stamp_gate {
        test_hooks::set(Point::BeforeStampGate, hook);
    }
    // The scan takes the incumbent's own copy first: it is never a victim.
    let incumbent = key(&world.incumbent);
    let before = victims(&world.cache)
        .into_iter()
        .filter(|(key, _, _)| *key != incumbent)
        .collect();
    let index = std::mem::take(&mut world.index);
    let scan = || {
        complete(cached_scan(
            &world.incumbent,
            world.source,
            index,
            &world.cache,
            |_| {},
        ))
    };
    let ((), counts) = observe(|| match budgets {
        Some((state, entry)) => sampled_scan::with_test_budgets(state, entry, scan),
        None => scan(),
    });
    let run = Run {
        probe: test_hooks::last_probe(),
        decisions: test_hooks::decisions(),
        buckets: test_hooks::buckets(),
        before,
        at_retain: at_retain.borrow_mut().take(),
        counts,
    };
    test_hooks::clear();
    eprintln!(
        "R0 {:?}: probe {:?}, decisions {:?}, buckets {:?}",
        world.source, run.probe, run.decisions, run.buckets
    );
    run
}

/// An uncalibrated world's measure (`count` older residents), and the bytes
/// one older resident frees.
fn probe_world(source: SnapshotSource, count: usize) -> (Probe, usize) {
    let mut world = World::with_older(source, count);
    let run = run(&mut world, None, None);
    let older_keys = world.older_keys(count);
    let older: Vec<usize> = run
        .before
        .iter()
        .filter(|(key, _, _)| older_keys.contains(key))
        .map(|(_, _, freed)| *freed)
        .collect();
    assert_eq!(
        older.len(),
        count,
        "precondition: older residents {source:?}"
    );
    assert!(
        older.iter().all(|freed| *freed == older[0] && *freed > 0),
        "precondition: same-shape residents free the same bytes {older:?}"
    );
    eprintln!("R0 {source:?}: one older resident frees {}", older[0]);
    (run.probe, older[0])
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
    // Up to retention's return; a later step may see a poisoned lock.
    let (_, phase) = run.at_retain.as_ref().expect("retention ran");
    assert_eq!(
        (
            phase.clear_no_active,
            phase.clear_full_resident_bound_unknown,
            phase.clear_entries_released,
        ),
        (0, 0, 0),
        "precondition: no base clear at the calibrated budget {source:?} state {state} need {need}"
    );
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
        let run = run(&mut world, None, None);
        let probe = run.probe;
        assert_eq!(probe.need, None, "{source:?}");
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
        let after = victims(&world.cache);
        for resident in world.older.iter().chain([&world.newer, &world.incumbent]) {
            assert!(
                after.iter().any(|(k, _, _)| *k == key(resident)),
                "{source:?}"
            );
        }
        assert!(run.buckets.is_empty(), "{source:?}");
    }
}

/// T-R0b: under pressure, the completion releases exactly the shortest
/// strictly-older-hint prefix that covers its need (k = 1, then k = 2), only
/// after retention's non-budget gates, and nothing at step start or insert.
#[test]
fn r0_tail_under_pressure_releases_the_exact_older_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let entry = crate::transcript_cache::entry_bytes();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        for (need, released) in [(freed, 1), (freed + 1, 2)] {
            let state = state_for_need(&probe, need);
            let mut world = World::new(source);
            let run = run(&mut world, Some((state, entry)), None);
            assert_calibrated(source, &probe, &run, state, need);
            assert_eq!(
                run.decisions,
                vec![Decision::Deferred {
                    raw: run.probe.b_ins,
                    budget_after: probe.k.unwrap(),
                }],
                "{source:?} k={released}"
            );
            let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
            let evicted = world.older_keys(released);
            let expected: Victims = run
                .before
                .iter()
                .filter(|(key, _, _)| !evicted.contains(key))
                .cloned()
                .collect();
            assert_eq!(
                at_retain, expected,
                "the exact prefix {source:?} k={released}"
            );
            assert!(
                at_retain.iter().any(|(k, _, _)| *k == key(&world.newer)),
                "a newer resident never leaves {source:?}"
            );
            assert_eq!(
                (
                    phase.insert_entries_evicted,
                    phase.retention_produced,
                    phase.retention_bound_refused,
                    phase.retention_unsealed_eof,
                    phase.clear_other_active,
                    phase.clear_full_resident_bound_unknown,
                    phase.clear_entries_released,
                ),
                (released as u64, 1, 0, 0, 0, 0, 0),
                "{source:?} k={released}"
            );
            // After retention: no further eviction. The copy is inserted, or
            // its finalization charge exceeds `K` (residual, disclosed).
            let counts = run.counts;
            assert_eq!(
                counts.insert_entries_evicted, phase.insert_entries_evicted,
                "{source:?} k={released}"
            );
            let inserted = victims(&world.cache)
                .iter()
                .any(|(k, _, _)| *k == key(&world.incumbent));
            eprintln!(
                "R0 {source:?} k={released}: inserted {inserted}, finalization refused {}",
                counts.retention_finalization_bound_refused
            );
            assert_eq!(
                (inserted, counts.insert_admitted),
                if counts.retention_finalization_bound_refused == 0 {
                    (true, 1)
                } else {
                    (false, 0)
                },
                "{source:?} k={released}"
            );
            assert!(run.buckets.is_empty(), "{source:?}");
        }
    }
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
    let entry = crate::transcript_cache::entry_bytes();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, 1);
        let need = freed + 1;
        let state = state_for_need(&probe, need);
        let mut world = World::with_older(source, 1);
        let run = run(&mut world, Some((state, entry)), None);
        assert_calibrated(source, &probe, &run, state, need);
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
        assert_eq!(phase.insert_entries_evicted, 0, "{source:?}");
        assert_eq!(
            run.buckets.len() as u64,
            phase.retention_bound_refused + phase.retention_clone_bound_refused,
            "one bucket per refused pass {source:?}"
        );
    }
}

/// The entry band: a copy the insert's entry and key bounds would refuse never
/// releases; at the exact edge it does.
#[test]
fn r0_tail_in_the_entry_band_never_releases() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        let state = state_for_need(&probe, freed);
        let overhead =
            crate::transcript_cache::entry_overhead::<sampled_jsonl::CachedJsonlReduction>();
        for (offset, deferred) in [(1, false), (0, true)] {
            let mut world = World::new(source);
            let key_bound =
                crate::heap_layout_bound::bound(&key(&world.incumbent), usize::MAX).unwrap();
            let entry = probe.clone.unwrap() + overhead + key_bound - offset;
            let run = run(&mut world, Some((state, entry)), None);
            assert_calibrated(source, &probe, &run, state, freed);
            assert_eq!(
                matches!(run.decisions.as_slice(), [Decision::Deferred { .. }]),
                deferred,
                "{source:?} offset {offset}: {:?}",
                run.decisions
            );
            let (_, phase) = run.at_retain.clone().expect("retention ran");
            assert_eq!(
                phase.insert_entries_evicted,
                u64::from(deferred),
                "{source:?} offset {offset}"
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
    let entry = crate::transcript_cache::entry_bytes();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        let state = state_for_need(&probe, freed);
        let mut world = World::new(source);
        // Same-shape twins, newer than the incumbent, in a spare cache.
        let spare = Arc::new(sampled_scan::SharedCache::default());
        let twins: Vec<ScanFixture> = (0..OLDER as u64)
            .map(|i| resident(source, &spare, world.base + Duration::from_secs(3_000 + i)))
            .collect();
        let twin_keys: Vec<String> = twins.iter().map(key).collect();
        let older_keys = world.older_keys(OLDER);
        let cache = Arc::clone(&world.cache);
        let swapped = Rc::new(RefCell::new(None));
        let seen = Rc::clone(&swapped);
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
        let run = run(&mut world, Some((state, entry)), Some(Box::new(hook)));
        assert_calibrated(source, &probe, &run, state, freed);
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
                phase.insert_entries_evicted,
                phase.retention_bound_refused,
                phase.retention_produced,
            ),
            (0, 1, 0),
            "{source:?}"
        );
        assert_eq!(run.buckets, vec![Bucket::OverBudget], "{source:?}");
        assert!(
            !victims(&world.cache)
                .iter()
                .any(|(k, _, _)| *k == key(&world.incumbent)),
            "{source:?}"
        );
        drop(twins);
    }
}

/// A poisoned retained lock at release time: unmeasurable, nothing evicted.
#[test]
fn r0_release_on_a_poisoned_lock_evicts_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let entry = crate::transcript_cache::entry_bytes();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let (probe, freed) = probe_world(source, OLDER);
        let state = state_for_need(&probe, freed);
        let mut world = World::new(source);
        let cache = Arc::clone(&world.cache);
        let hook = move || cache.poison_retained();
        let run = run(&mut world, Some((state, entry)), Some(Box::new(hook)));
        assert_calibrated(source, &probe, &run, state, freed);
        let (at_retain, phase) = run.at_retain.clone().expect("retention ran");
        assert_eq!(at_retain, run.before, "{source:?}");
        assert_eq!(
            (
                phase.insert_entries_evicted,
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
                run.counts.insert_entries_evicted,
                run.counts.clear_entries_released
            ),
            (0, 0),
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

/// T-R0h: the base wrapper is the measure at the base limit.
#[test]
fn r0_copy_budget_parts_is_the_remaining_limit_measure() {
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
        assert!(
            sampled_scan::borrows_only_retained_reduction(scan.active_file.as_deref().unwrap()),
            "precondition: shape F {source:?}"
        );
        let measure = sampled_scan::copy_budget_measure(
            scan.sampling.as_ref(),
            scan.active_file.as_deref_mut(),
            false,
            sampled_scan::ActiveLimit::Remaining,
        );
        let parts = sampled_scan::copy_budget_parts(
            scan.sampling.as_ref(),
            scan.active_file.as_deref_mut(),
            false,
        );
        assert_eq!((measure.budget, measure.resident), parts, "{source:?}");
        let state = sampled_scan::copy_budget_measure(
            scan.sampling.as_ref(),
            scan.active_file.as_deref_mut(),
            true,
            sampled_scan::ActiveLimit::State,
        );
        assert_eq!(state.resident, measure.resident, "{source:?}");
        assert_eq!(state.remaining, measure.remaining, "{source:?}");
        assert!(state.active.is_some(), "{source:?}");
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

    let granted = RetainBudget::granted_unclassified(7);
    assert_eq!(
        (
            granted.raw(),
            granted.admission_budget(),
            granted.finalization_budget()
        ),
        (7, 7, 7)
    );
    for budget in [
        RetainBudget::granted_unclassified(7).excluded(),
        RetainBudget::granted_unclassified(7).unsealed(),
    ] {
        assert_eq!(
            (
                budget.raw(),
                budget.admission_budget(),
                budget.finalization_budget()
            ),
            (7, 0, 7)
        );
    }
}
