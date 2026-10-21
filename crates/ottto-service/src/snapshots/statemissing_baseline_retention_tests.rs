//! StateMissing characterization baseline T3: one shared transcript cache, a
//! retained Claude reduction, and a Codex page whose incomplete state census
//! makes it parse unsampled. Asserts TODAY's behavior, which is the defect,
//! so it passes on main; the assertions a fix flips are marked `FLIPS`. Every
//! other assertion is a precondition or an invariant. Fixtures reuse the
//! scanner fixtures and helpers of `transcript_acquisition_tests` unchanged.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{observe, Counts};
use crate::transcript_acquisition::FullReason;

/// The retained-state budget `sampled_scan` derives (its `STATE_BYTES`):
/// the cache bytes, less the overlap budget and the 1 MiB scratch reserve.
const STATEMISSING_STATE_BYTES: usize =
    crate::transcript_cache::CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - 1024 * 1024;
/// Four real retained Claude reductions of 1,400 responses each (about
/// 6.9 MB apiece, under the 8 MiB entry bound) fill the cache to within a
/// few MB of that budget without any eviction.
const STATEMISSING_FILLERS: usize = 4;
const STATEMISSING_FILLER_RECORDS: usize = 1400;
/// One Codex record this long leaves the unsampled parser's line buffer at
/// least this capacity at its next step start: more than the room the
/// filled cache leaves, so the copy budget beside it is zero.
const STATEMISSING_CODEX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// One production scan, driven exactly as `production_scan_at_with_setup`
/// drives it, that also records each step start's active file and the
/// full-read reasons of the sampled context.
struct ObservedScan {
    index: ScanIndex,
    result: SourceScanResult,
    modes: (usize, usize, usize),
    full_reasons: [usize; 11],
    /// Step starts whose active file has no sampled acquisition, no cursor
    /// job and no group job: a plain native parse borrowing no retained state.
    unsampled_active_steps: usize,
    /// Those step starts whose copy budget beside the active file is zero.
    unsampled_zero_budget_steps: usize,
}

fn observed_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    namespace: &str,
    state_census_incomplete: bool,
) -> ObservedScan {
    let mut scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(&fixture.root),
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(cache.clone(), Scope(namespace.into()));
    if state_census_incomplete {
        scan.state_census_complete = false;
    }
    let mut unsampled_active_steps = 0;
    let mut unsampled_zero_budget_steps = 0;
    loop {
        let context = scan
            .sampling
            .as_ref()
            .expect("the scan keeps its sampled shared-cache context");
        let modes = (
            context.full_files,
            context.tail_files,
            context.unchanged_files,
        );
        let full_reasons = context.full_reasons;
        let unsampled = scan.active_file.as_deref().is_some_and(|active| {
            active.sampling.is_none() && active.cursor.is_none() && active.group.is_none()
        });
        if unsampled {
            unsampled_active_steps += 1;
            if scan.sampled_copy_budget() == 0 {
                unsampled_zero_budget_steps += 1;
            }
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index,
                scan: result,
                ..
            } => {
                let mut projected = result.clone();
                apply_upload_policy(
                    source,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(source, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return ObservedScan {
                    index,
                    result,
                    modes,
                    full_reasons,
                    unsampled_active_steps,
                    unsampled_zero_budget_steps,
                };
            }
        }
    }
}

/// The scenario's outcome up to and including the Claude append read.
struct CrossSourceRun {
    resident_after_fill: usize,
    codex: Option<(ObservedScan, Counts)>,
    claude_retained_before_append: bool,
    append: ObservedScan,
    append_counts: Counts,
}

/// Retain one Claude file (a full read, then a small append read as a tail),
/// fill the shared cache near its budget with real retained reductions under
/// unrelated keys, optionally run one Codex page whose setup forces
/// `state_census_complete = false`, then read one more Claude append.
fn statemissing_cross_source_run(codex_page: bool) -> Option<CrossSourceRun> {
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!(
            "STATEMISSING_BASELINE test=T3_cross_source_wipe codex_page={codex_page} supported_positive=UNEXECUTED"
        );
        return None;
    }
    let source = SnapshotSource::ClaudeCode;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let claude = ScanFixture::new(source);
    claude.file.append(&usage(source, 100, 0, "fixture-model"));
    let key = local_index_key(&claude.file.0);
    let full = observed_scan(
        &claude,
        source,
        ScanIndex::default(),
        &cache,
        "statemissing-claude",
        false,
    );
    assert_eq!(full.modes, (1, 0, 0));
    assert_eq!(full.full_reasons[FullReason::StateMissing.slot()], 1);
    claude.file.append(&usage(source, 140, 1, "fixture-model"));
    let tail = observed_scan(
        &claude,
        source,
        full.index,
        &cache,
        "statemissing-claude",
        false,
    );
    assert_eq!(
        tail.modes,
        (0, 1, 0),
        "precondition: the retained Claude reduction resumes as a tail"
    );
    assert!(
        cache.retained_checkpoint(&key).is_some(),
        "precondition: the tail read is retained again"
    );

    let filler = Fixture::new(source);
    for id in 0..STATEMISSING_FILLER_RECORDS {
        filler.append(&usage(source, 100 + id as u64, id, "fixture-model"));
    }
    let (_, fill_counts) = observe(|| {
        for number in 0..STATEMISSING_FILLERS {
            let (retained, _, _, _) = acquire(&filler, source, None, 100);
            let retained = retained.expect("precondition: a filler reduction fits one cache entry");
            assert!(
                cache
                    .retained()
                    .expect("retained cache lock")
                    .insert(format!("statemissing-filler-{number}"), retained),
                "precondition: filler {number} is admitted"
            );
        }
    });
    assert_eq!(fill_counts.insert_admitted, STATEMISSING_FILLERS as u64);
    assert_eq!(
        fill_counts.insert_entries_evicted, 0,
        "precondition: the fill evicts nothing"
    );
    let resident_after_fill = cache
        .retained()
        .expect("retained cache lock")
        .resident_bound()
        .expect("bounded resident state");
    assert!(resident_after_fill <= STATEMISSING_STATE_BYTES);
    assert!(
        cache.retained_checkpoint(&key).is_some(),
        "precondition: the fill keeps the retained Claude entry"
    );

    let codex = codex_page.then(|| {
        let source = SnapshotSource::Codex;
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        fixture.file.append(&json!({
            "type": "synthetic-padding",
            "text": "x".repeat(STATEMISSING_CODEX_LINE_BYTES),
        }));
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        observe(|| {
            observed_scan(
                &fixture,
                source,
                ScanIndex::default(),
                &cache,
                "statemissing-codex",
                true,
            )
        })
    });
    let claude_retained_before_append = cache.retained_checkpoint(&key).is_some();

    claude.file.append(&usage(source, 180, 2, "fixture-model"));
    let (append, append_counts) = observe(|| {
        observed_scan(
            &claude,
            source,
            tail.index,
            &cache,
            "statemissing-claude",
            false,
        )
    });
    Some(CrossSourceRun {
        resident_after_fill,
        codex,
        claude_retained_before_append,
        append,
        append_counts,
    })
}

/// Defect (cross-source wipe, `sampled_scan::release_cache_for_copy_refusal`):
/// a Codex page whose state census is incomplete parses its file with no
/// sampled acquisition. That truly unsampled native active borrows no retained
/// state, yet when the copy budget beside it is zero it is not the #641
/// native-full baseline (`sampling == None`), so the release records
/// `ClearOtherActive` and clears every retained reduction in the shared
/// cache, Claude's included. The next small Claude append then reads
/// `Full(StateMissing)` instead of a tail.
///
/// Expected after the fix (OWNER-PLAN slice A1): a zero copy budget beside an
/// unsampled native active forbids optional copies but keeps independently
/// bounded residents, so `clear_other_active` stays 0, the Claude entry
/// survives, and the append reads `Tail` as in the control
/// `statemissing_baseline_retained_claude_append_reads_tail_without_codex_page`.
#[test]
fn statemissing_baseline_unsampled_codex_page_wipes_retained_claude_state() {
    let Some(run) = statemissing_cross_source_run(true) else {
        return;
    };
    let (codex, counts) = run.codex.expect("the Codex page ran");
    // Preconditions: the sampled shared-cache context is present, the Codex
    // census is incomplete, and its one file is parsed by a truly unsampled
    // native active that took no retained state.
    assert!(!codex.result.state_census_complete);
    assert_eq!(codex.result.scanned_file_count, 1);
    assert_eq!(codex.modes, (0, 0, 0), "no Codex read is sampled");
    assert!(codex.unsampled_active_steps > 0);
    assert_eq!(
        counts.take_hit, 0,
        "the Codex active borrows no retained state"
    );
    assert_eq!(
        codex.unsampled_zero_budget_steps, 1,
        "one step start meets a zero copy budget beside the unsampled active"
    );
    assert_eq!(counts.clear_metadata_unsupported, 0);
    assert_eq!(counts.clear_full_resident_bound_unknown, 0);
    assert_eq!(counts.clear_no_active, 0);
    // FLIPS: that zero budget wipes the whole shared cache, Claude included.
    assert_eq!(counts.clear_other_active, 1);
    assert_eq!(
        counts.clear_entries_released,
        STATEMISSING_FILLERS as u64 + 1
    );
    assert!(!run.claude_retained_before_append);
    // FLIPS: the next Claude append is a full read for missing state.
    assert_eq!(run.append.modes, (1, 0, 0));
    assert_eq!(run.append.full_reasons[FullReason::StateMissing.slot()], 1);
    assert_eq!(run.append_counts.take_hit, 0);
    assert_eq!(run.append_counts.take_absent, 1);
    eprintln!(
        "STATEMISSING_BASELINE test=T3_cross_source_wipe arm=codex_page state_bytes={STATEMISSING_STATE_BYTES} resident_after_fill={} codex_unsampled_active_steps={} codex_zero_budget_steps={} clear_other_active={} clear_entries_released={} claude_append_modes={:?} claude_append_state_missing={}",
        run.resident_after_fill,
        codex.unsampled_active_steps,
        codex.unsampled_zero_budget_steps,
        counts.clear_other_active,
        counts.clear_entries_released,
        run.append.modes,
        run.append.full_reasons[FullReason::StateMissing.slot()]
    );
}

/// Control for the cross-source wipe baseline: the same retained Claude file
/// and the same filled cache, without the Codex page, keeps the Claude entry
/// and reads the append as a tail. This holds today and after the fix.
#[test]
fn statemissing_baseline_retained_claude_append_reads_tail_without_codex_page() {
    let Some(run) = statemissing_cross_source_run(false) else {
        return;
    };
    assert!(run.codex.is_none());
    assert!(run.claude_retained_before_append);
    assert_eq!(run.append.modes, (0, 1, 0));
    assert_eq!(run.append.full_reasons, [0; 11]);
    assert_eq!(run.append_counts.take_hit, 1);
    assert_eq!(run.append_counts.clear_other_active, 0);
    assert_eq!(run.append_counts.clear_entries_released, 0);
    eprintln!(
        "STATEMISSING_BASELINE test=T3_cross_source_wipe arm=control state_bytes={STATEMISSING_STATE_BYTES} resident_after_fill={} claude_append_modes={:?}",
        run.resident_after_fill, run.append.modes
    );
}
