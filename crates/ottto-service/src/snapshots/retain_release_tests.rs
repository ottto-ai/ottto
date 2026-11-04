//! A sampled Tail/Unchanged singleton's completion-time release
//! of residents ranked below its copy's re-admission rank (shape F), and the
//! diagnostic packet's
//! refusal buckets. Its own block, apart from the shared appends above.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{observe, Counts};
use crate::snapshots::cache_policy_tests::u3_identity;
use sampled_jsonl::{classify_refusal, Bucket, Refusal, RefusalView};
use sampled_scan::{ReleaseOutcome, RetainBudget};
use std::time::Duration;

type Victims = Vec<(String, (i64, i64), usize)>;

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
        SnapshotSource::Pi => dir.join("home/.pi/agent/sessions"),
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
        SnapshotSource::Pi => (
            "native-tail-fixture.jsonl",
            json!({"type":"session", "version":3, "id":"native-tail-fixture",
                "timestamp":"2026-10-07T10:00:00Z", "cwd":"/synthetic/pi"}),
        ),
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

const INCUMBENT_ROWS: usize = 48;

/// Real routed Tail state beside explicitly admitted native cache fixtures.
/// No source scan retains a RAM reduction now that every source has a codec.
struct World {
    cache: Arc<sampled_scan::SharedCache>,
    incumbent: ScanFixture,
    index: ScanIndex,
    _residents: Vec<ScanFixture>,
}
impl World {
    fn new(source: SnapshotSource) -> Self {
        let base = SystemTime::now() - Duration::from_secs(3_600);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let residents = (0..4)
            .map(|i| resident(source, &cache, 1, base + Duration::from_secs(i)))
            .collect();
        let incumbent = scan_fixture(source, INCUMBENT_ROWS, base + Duration::from_secs(1_000));
        let (index, _, _) = production_scan(
            &incumbent,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "mixed-files",
        );
        let index =
            crate::snapshots::e2_pipeline_scan_fixture::route_for_test(source, Some(&cache), index);
        assert_eq!(
            crate::snapshots::tail_source::committed_sealed_offset(
                source,
                &index,
                &key(&incumbent)
            ),
            Some(fs::metadata(&incumbent.file.0).unwrap().len()),
        );
        assert!(cache.retained_checkpoint(&key(&incumbent)).is_none());
        append_row(&incumbent, source);
        set_modified(&incumbent, base + Duration::from_secs(1_001));
        Self {
            cache,
            incumbent,
            index,
            _residents: residents,
        }
    }
}

/// Route the real scanner; explicitly seeded peers exercise the cache engine.
fn cached_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    setup: impl FnOnce(&mut OwnedSourceScan),
) -> OwnedSourceScan {
    let index =
        crate::snapshots::e2_pipeline_scan_fixture::route_for_test(source, Some(cache), index);
    super::cached_scan(fixture, source, index, cache, setup)
}

fn resident(
    source: SnapshotSource,
    cache: &Arc<sampled_scan::SharedCache>,
    rows: usize,
    modified: SystemTime,
) -> ScanFixture {
    let fixture = scan_fixture(source, rows, modified);
    let scope = Scope(format!("synthetic-native-{source:?}"));
    let (retained, mode, _, items) = acquire_items_with(
        &fixture.file,
        source,
        &CodexTitleMetadata::default(),
        &scope,
        None,
        sampled_scan::now_seconds(),
        true,
    );
    assert!(matches!(mode, ReadMode::Full(_)));
    let retained = retained.expect("a native cache fixture fits");
    let finished = serde_json::to_vec(&items).unwrap();
    let finalization = crate::heap_layout_bound::bound(
        &finished,
        crate::snapshots::cache_policy_tests::POLICY_STATE_BYTES,
    )
    .expect("bounded finished fixture bytes");
    assert!(finalization > 0);
    assert!(cache.insert_admitted(
        key(&fixture),
        sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: retained.checkpoint,
            reduction: Some(retained.state),
            released: None,
            unsealed: false,
        },
        finalization,
    ));
    assert!(
        cache.retained_checkpoint(&key(&fixture)).is_some(),
        "precondition: resident {source:?}"
    );
    fixture
}

/// The retained lock is never relocked on one thread; a debug build
/// panics before it would deadlock.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "retained lock taken while this thread holds it")]
fn r0_retained_relock_panics_in_debug_builds() {
    let cache = sampled_scan::SharedCache::default();
    let _held = cache.retained().unwrap();
    let _ = cache.retained();
}

/// The completion measure waits for a held retained lock; every other
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

/// An insert keeps its own finalization charge on the entry, apart
/// from the cursor reservation, and the next take carries it.
#[test]
fn r0_insert_carries_its_finalization_charge_to_the_next_take() {
    // Cache fixtures are admitted explicitly; real scans continue from heads.
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    {
        let source = SnapshotSource::Pi;
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
            "a fixture insert carries its measured finished-byte charge {source:?}"
        );
        cache.insert(
            key(&fixture),
            sampled_jsonl::CompletedNativeAcquisition {
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

/// T-R0d: every borrowed-state conjunct keeps a Tail off shape F, so its
/// step-start refusal keeps `ClearOtherActive`, and its completion never
/// reaches `tail_completion_budget` (the only source of `Deferred`, called
/// only behind `releases_at_completion`). Aliases and receipts are
/// in the guard matrix; the cursor and group conjuncts are in
/// `codex_cursor_tests` and `group_job_tests`. Codex's tier-join conjunct
/// left with Codex's RAM reduction copy (a codec source keeps none).
#[test]
fn r0_non_f_shapes_keep_clear_other_active() {
    // Cache fixtures are admitted explicitly; real scans continue from heads.
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    {
        let source = SnapshotSource::Pi;
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
    // Cache fixtures are admitted explicitly; real scans continue from heads.
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
    {
        let source = SnapshotSource::Pi;
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
            state_only_blocked_session_ids: _,          // M (Codex only; empty on Claude)
            source_session_id_seen: _,                  // I (source session presence)
            codex_parent_session_ref: _,                // M (Codex only)
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
            copy_unproven_counts: _,                        // inline optional money disclosure
            resolver_conflict_count: _,                     // inline optional wire counter
            claude_money: _, // E aggregate is covered by finish output reserve
            usage_accounting_contract: _, // K (literal)
            claude_usage_request_ids: _, // R
            claude_usage_occurrences: _, // R
            cache_observations: _, // K (None on Claude)
            cache_observations_state: _, // K (None at into_items)
            cache_base_head_etag: _, // K (None at into_items)
            cache_conflict_answer: _, // K (None at into_items)
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
            context_curve: _, // K (None; no curves are built)
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
