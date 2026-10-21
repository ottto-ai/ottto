//! Red-first cache-policy regression tests for Slice M1 (design report §2
//! L1-L4 and §6 row M1): a copy refusal evicts only what is needed instead of
//! wiping the resume cache. M1 (i) and G3 come from the M0 harness (#661);
//! G1, G2 and M2 belong to later slices and are not here. Each test drives
//! the real production scan step loop against one shared transcript cache, or
//! calls the step-start release with injected measurements, and asserts the
//! DESIRED retention policy, so it fails on main for the reason its doc
//! comment names. Preconditions are asserted first, so a setup failure cannot
//! pass as the defect. Fixtures are synthetic. The helpers are copied from
//! `transcript_acquisition_tests` and the #653 retention baseline, so this
//! module registers on its own.
//!
//! The shared cache is `SharedCache::default()`: its retained cache is
//! `TranscriptCache::with_byte_limit(STATE_BYTES)`, and the copy budget is
//! measured against that same constant, so transcript sizes, not a smaller
//! test limit, decide how many entries fit.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::{observe, Counts};
use crate::transcript_acquisition::{FullReason, ReadMode, Scope};
use crate::transcript_cache::Retained;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const NOW: &str = "2026-10-07T12:00:00Z";
const NAMESPACE: &str = "cache-policy";
const MODEL: &str = "fixture-model";
/// The retained-state budget `sampled_scan` derives (its `STATE_BYTES`).
const POLICY_STATE_BYTES: usize =
    crate::transcript_cache::CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - 1024 * 1024;
/// Four 1,400-response reductions (#653 T3: 27,664,691 B) fill the state
/// budget to within a few MB without any eviction.
const FILLERS: usize = 4;
const FILLER_RECORDS: usize = 1400;
/// One appended record this long leaves the tail parser's line buffer at
/// least this capacity at its next step start: more than the room the
/// filled cache leaves, so the copy budget beside the tail is zero.
const TAIL_PADDING_BYTES: usize = 8 * 1024 * 1024;
/// About 4.96 KB charged per response (measured in CI): this many appended
/// responses grow a tail's borrowed state past the room the fillers leave
/// (about 4.8 MB), yet below one filler's charge (`FILLER_RECORDS`).
const TAIL_GROWTH_RECORDS: usize = 1300;
/// Two days: outside the one-hour audit horizon, so a file this old is cold.
const OLD_SECONDS: u64 = 2 * 24 * 3600;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// One synthetic transcript under its own scan root, removed on drop.
struct ScanFixture {
    dir: PathBuf,
    root: PathBuf,
    path: PathBuf,
}
impl ScanFixture {
    fn new(source: SnapshotSource) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ottto-cache-policy-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let (root, name, first) = match source {
            SnapshotSource::Codex => (
                dir.join("home/.codex/sessions"),
                "rollout-2026-10-07T10-00-00-019fa111-2222-7333-8444-555555555555.jsonl",
                json!({"type":"session_meta","payload":{"id":"019fa111-2222-7333-8444-555555555555"}}),
            ),
            SnapshotSource::ClaudeCode => (
                dir.join("home/.claude/projects"),
                "native-tail-fixture.jsonl",
                json!({"type":"user","sessionId":"native-tail-fixture", "timestamp":"2026-10-07T10:00:00Z", "message":{"role":"user","content":"Synthetic test"}}),
            ),
            _ => unreachable!(),
        };
        fs::create_dir_all(&root).unwrap();
        let fixture = Self {
            path: root.join(name),
            dir,
            root,
        };
        fixture.append(&first);
        fixture
    }
    fn append(&self, value: &Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        serde_json::to_writer(&mut file, value).unwrap();
        file.write_all(b"\n").unwrap();
    }
    fn append_usage(&self, source: SnapshotSource, ids: std::ops::Range<usize>) {
        for id in ids {
            self.append(&usage(source, 100 + id as u64, id, MODEL));
        }
    }
    fn set_modified(&self, unix_seconds: u64) {
        OpenOptions::new()
            .write(true)
            .open(&self.path)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(unix_seconds)),
            )
            .unwrap();
    }
    fn key(&self) -> String {
        local_index_key(&self.path)
    }
}
impl Drop for ScanFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn usage(source: SnapshotSource, n: u64, id: usize, model: &str) -> Value {
    let timestamp = format!("2026-10-07T{:02}:00:00Z", 10 + id % 3);
    match source {
        SnapshotSource::Codex => json!({"type":"event_msg", "timestamp":timestamp,
            "payload":{"type":"token_count", "info":{"model":model,
            "total_token_usage":{"input_tokens":n,"cached_input_tokens":n/2,"output_tokens":n/10},
            "last_token_usage":{"input_tokens":n,"cached_input_tokens":n/2,"output_tokens":n/10}}}}),
        SnapshotSource::ClaudeCode => {
            json!({"type":"assistant", "sessionId":"native-tail-fixture", "timestamp":timestamp,
            "requestId":format!("req-{id}"), "message":{"id":format!("response-{id}"), "model":model,
            "usage":{"input_tokens":n,"cache_read_input_tokens":n/2,"output_tokens":n/10}}})
        }
        _ => unreachable!(),
    }
}

/// A real retained Claude reduction of `fixture`, built by the native parser
/// as `transcript_acquisition_tests::acquire` builds one. Its checkpoint
/// carries the file's current mtime as its eviction rank.
fn retained_reduction(fixture: &ScanFixture) -> Retained<sampled_jsonl::CachedJsonlReduction> {
    let source = SnapshotSource::ClaudeCode;
    let mut file = File::open(&fixture.path).unwrap();
    opened_object_identity(source, &mut file).unwrap();
    let metadata = CodexTitleMetadata::default();
    let mut parser = OwnedJsonlParser::new(
        file,
        &fixture.path,
        source,
        apply_claude_code_line,
        Some(&metadata),
        None,
        None,
        false,
        true,
    )
    .unwrap();
    let scope = Scope("cache-policy-filler".into());
    let now = sampled_scan::now_seconds();
    let mode = parser.prepare_acquisition(None, &scope, None, now).unwrap();
    assert_eq!(mode, ReadMode::Full(FullReason::StateMissing));
    while !parser.step().unwrap() {}
    let acquisition = parser
        .retain_reduction(&scope, now, crate::transcript_cache::ENTRY_BYTES)
        .unwrap()
        .unwrap();
    Retained {
        checkpoint: acquisition.checkpoint,
        state: acquisition
            .reduction
            .expect("precondition: a filler reduction fits one cache entry"),
    }
}

/// One production scan, driven as `production_scan_at_with_setup` drives
/// it, that also records the sampled modes and the zero copy budgets met at
/// step starts.
struct Observed {
    index: ScanIndex,
    modes: (usize, usize, usize),
    full_reasons: [usize; 11],
    /// Step starts whose active file is a sampled tail (it holds borrowed
    /// retained state) and whose copy budget is zero.
    tail_zero_budget_steps: usize,
}
impl Observed {
    fn state_missing(&self) -> usize {
        self.full_reasons[FullReason::StateMissing.slot()]
    }
}

/// A production scan of `fixture` sharing `cache`, not yet stepped.
fn cached_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> OwnedSourceScan {
    OwnedSourceScan::new(
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
    .with_sampled_acquisition(cache.clone(), Scope(NAMESPACE.into()))
}

fn observed_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> Observed {
    let mut scan = cached_scan(fixture, source, index, cache);
    let mut modes = (0, 0, 0);
    let mut full_reasons = [0; 11];
    let mut tail_zero_budget_steps = 0;
    loop {
        if let Some(context) = scan.sampling.as_ref() {
            modes = (
                context.full_files,
                context.tail_files,
                context.unchanged_files,
            );
            full_reasons = context.full_reasons;
        }
        let tail = scan.active_file.as_deref().is_some_and(|active| {
            active.cursor.is_none()
                && active.group.is_none()
                && active
                    .sampling
                    .as_ref()
                    .is_some_and(|sampling| sampling.mode == ReadMode::Tail)
        });
        if tail && scan.sampled_copy_budget() == 0 {
            tail_zero_budget_steps += 1;
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index,
                scan: result,
                ..
            } => {
                let mut projected = result;
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
                return Observed {
                    index,
                    modes,
                    full_reasons,
                    tail_zero_budget_steps,
                };
            }
        }
    }
}

/// Wipe-all releases: every `clear()` path of the copy refusal.
fn wipe_clears(counts: &Counts) -> u64 {
    counts.clear_other_active
        + counts.clear_no_active
        + counts.clear_full_resident_bound_unknown
        + counts.clear_metadata_unsupported
}

/// The whole shared cache's charge: retained entries plus cursor state (R + P).
fn optional_resident(cache: &Arc<sampled_scan::SharedCache>) -> usize {
    crate::heap_layout_bound::bound(&**cache, usize::MAX).expect("bounded shared cache")
}

fn unix_now() -> u64 {
    sampled_scan::now_seconds()
}

fn unexecuted(test: &str) -> bool {
    if crate::heap_layout_bound::layout_supported() {
        return false;
    }
    eprintln!("CACHE_POLICY test={test} supported_positive=UNEXECUTED");
    true
}

fn filler_key(number: usize) -> String {
    format!("cache-policy-filler-{number}")
}

/// Insert `FILLERS` real retained reductions of one `FILLER_RECORDS` file
/// under unrelated keys, as #653 T3 does. `modified` pins the fillers' rank.
fn insert_fillers(cache: &Arc<sampled_scan::SharedCache>, modified: Option<u64>) {
    let source = SnapshotSource::ClaudeCode;
    let filler = ScanFixture::new(source);
    filler.append_usage(source, 0..FILLER_RECORDS);
    if let Some(modified) = modified {
        filler.set_modified(modified);
    }
    let (_, counts) = observe(|| {
        for number in 0..FILLERS {
            let retained = retained_reduction(&filler);
            assert!(
                cache
                    .retained()
                    .expect("retained cache lock")
                    .insert(filler_key(number), retained),
                "precondition: filler {number} is admitted"
            );
        }
    });
    assert_eq!(counts.insert_admitted, FILLERS as u64);
    assert_eq!(
        counts.insert_entries_evicted, 0,
        "precondition: the fill evicts nothing"
    );
}

fn fillers_resident(cache: &sampled_scan::SharedCache) -> usize {
    (0..FILLERS)
        .filter(|number| cache.retained_checkpoint(&filler_key(*number)).is_some())
        .count()
}

/// One small Claude file retained in a shared cache that `FILLERS` real
/// reductions then fill within the state budget, without any eviction.
struct FullCache {
    cache: Arc<sampled_scan::SharedCache>,
    tailed: ScanFixture,
    index: ScanIndex,
    /// The whole shared cache's charge after the fill (R + P).
    resident_before: usize,
    /// The charge one filler added to the shared cache.
    filler_charge: usize,
}

/// `older_tail` pins the tailed file's mtime two days back, below every
/// filler's rank.
fn full_cache_with_retained_file(older_tail: bool) -> FullCache {
    let source = SnapshotSource::ClaudeCode;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let tailed = ScanFixture::new(source);
    tailed.append(&usage(source, 100, 0, MODEL));
    if older_tail {
        tailed.set_modified(unix_now() - OLD_SECONDS);
    }
    let full = observed_scan(&tailed, source, ScanIndex::default(), &cache);
    assert_eq!(full.modes, (1, 0, 0));
    assert_eq!(full.state_missing(), 1);
    assert!(
        cache.retained_checkpoint(&tailed.key()).is_some(),
        "precondition: the first read is retained"
    );
    let before_fill = optional_resident(&cache);
    insert_fillers(&cache, None);
    assert!(
        cache.retained_checkpoint(&tailed.key()).is_some(),
        "precondition: the fill keeps the tailed entry"
    );
    let resident_before = optional_resident(&cache);
    assert!(
        resident_before <= POLICY_STATE_BYTES,
        "precondition: the cache plus the tailed entry fit the state budget"
    );
    if older_tail {
        let tailed_rank = cache
            .retained_checkpoint(&tailed.key())
            .unwrap()
            .modified_hint();
        let filler_rank = cache
            .retained_checkpoint(&filler_key(0))
            .unwrap()
            .modified_hint();
        assert!(
            tailed_rank < filler_rank,
            "precondition: the tailed entry ranks below every filler"
        );
    }
    FullCache {
        cache,
        tailed,
        index: full.index,
        resident_before,
        filler_charge: (resident_before - before_fill) / FILLERS,
    }
}

/// Outcome of a sampled tail read at a zero copy budget beside a full cache.
struct TailBesideFullCache {
    resident_before: usize,
    filler_charge: usize,
    tail: Observed,
    counts: Counts,
    fillers_after: usize,
    tail_retained_after: bool,
}

/// The tailed file's append for `tail_beside_full_cache`: one long record,
/// then one usage record. The long record's line buffer meets a zero copy
/// budget at the next step start; the borrowed state itself stays tiny and
/// fits beside the fillers.
fn append_padded_usage(tailed: &ScanFixture) {
    tailed.append(&json!({
        "type": "synthetic-padding",
        "text": "x".repeat(TAIL_PADDING_BYTES),
    }));
    tailed.append(&usage(SnapshotSource::ClaudeCode, 140, 1, MODEL));
}

/// `full_cache_with_retained_file`, then `append` to the file and read the
/// append as a tail that meets a zero copy budget at a step start.
fn tail_beside_full_cache(older_tail: bool, append: fn(&ScanFixture)) -> TailBesideFullCache {
    let source = SnapshotSource::ClaudeCode;
    let FullCache {
        cache,
        tailed,
        index,
        resident_before,
        filler_charge,
    } = full_cache_with_retained_file(older_tail);
    append(&tailed);
    if older_tail {
        tailed.set_modified(unix_now() - OLD_SECONDS + 1);
    }
    let (tail, counts) = observe(|| observed_scan(&tailed, source, index, &cache));
    assert_eq!(
        tail.modes,
        (0, 1, 0),
        "precondition: the append reads as a tail"
    );
    assert_eq!(
        counts.take_hit, 1,
        "precondition: the tail borrows its entry"
    );
    assert!(
        tail.tail_zero_budget_steps >= 1,
        "precondition: a step start meets a zero copy budget beside the tail"
    );
    TailBesideFullCache {
        resident_before,
        filler_charge,
        fillers_after: fillers_resident(&cache),
        tail_retained_after: cache.retained_checkpoint(&tailed.key()).is_some(),
        tail,
        counts,
    }
}

/// G3, priority (design §5c G3; §3a rank; §2 L1).
///
/// A Claude entry ranked older than everything else in the cache (mtime two
/// days back) is read as a tail beside four newer filler entries that fill
/// the cache. Its appended long record meets a zero copy budget. That
/// overflow is the tail's native line buffer; its borrowed state already fit
/// beside the fillers. Desired: the older candidate evicts no newer entry,
/// neither at the zero-budget step nor at its re-admission. All four fillers
/// stay resident and nothing is wiped.
///
/// Red on main: the zero budget beside a tail active records
/// `ClearOtherActive` and clears the cache: `clear_entries_released=4`,
/// fillers resident 0.
#[test]
fn cache_policy_g3_older_candidate_never_evicts_newer_entries() {
    if unexecuted("G3_priority") {
        return;
    }
    let run = tail_beside_full_cache(true, append_padded_usage);
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} insert_entries_evicted={} fillers_after={} tail_retained_after={}",
        run.resident_before,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.counts.insert_entries_evicted,
        run.fillers_after,
        run.tail_retained_after,
    );
    eprintln!("CACHE_POLICY test=G3_priority {receipt}");
    assert_eq!(
        wipe_clears(&run.counts),
        0,
        "G3: the older candidate's step wiped newer entries; {receipt}"
    );
    assert_eq!(
        run.fillers_after, FILLERS,
        "G3: an older-mtime candidate evicted a newer entry; {receipt}"
    );
}

/// M1 test (i), no wipe-all (design §6 row M1; §2 L1).
///
/// A full but not overflowing cache: one retained Claude entry plus four
/// fillers within the state budget. The Claude file's append (one long record,
/// then a usage record) reads as a tail and meets a zero copy budget at a step
/// start. Desired: the zero budget forbids an optional copy but releases no
/// resident entry (`clear_*` 0, `clear_entries_released` 0). At most one
/// filler may later yield to this newer file's own re-admission.
///
/// Red on main: `ClearOtherActive` 1 and `clear_entries_released` 4, so every
/// filler is gone.
#[test]
fn cache_policy_m1_full_cache_tail_at_zero_budget_releases_nothing() {
    if unexecuted("M1_no_wipe") {
        return;
    }
    let run = tail_beside_full_cache(false, append_padded_usage);
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} fillers_after={} tail_retained_after={}",
        run.resident_before,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.fillers_after,
        run.tail_retained_after,
    );
    eprintln!("CACHE_POLICY test=M1_no_wipe {receipt}");
    assert_eq!(
        run.counts.clear_other_active, 0,
        "M1: a tail at a zero copy budget wiped the cache; {receipt}"
    );
    assert_eq!(
        run.counts.clear_entries_released, 0,
        "M1: released entries beside a cache that was not overflowing; {receipt}"
    );
    assert!(
        run.fillers_after + 1 >= FILLERS,
        "M1: more than one filler lost; {receipt}"
    );
}

/// The tailed file's append for M1 (ii): `TAIL_GROWTH_RECORDS` ordinary
/// responses, so the borrowed tail state itself grows.
fn append_growth(tailed: &ScanFixture) {
    tailed.append_usage(SnapshotSource::ClaudeCode, 1..1 + TAIL_GROWTH_RECORDS);
}

/// M1 test (ii), evict only the overflow (design §6 row M1; §2 L1).
///
/// The same full cache, but the tailed file's append is
/// `TAIL_GROWTH_RECORDS` ordinary responses. The borrowed tail state grows
/// past the room the fillers leave: a real overflow of the state budget, not
/// a merely full cache. Desired: no wipe-all clear. The zero-budget step
/// starts evict in victim order only until the tail fits. The grown state
/// stays below one filler's charge, so the overflow is less than one entry
/// and "at most the overflow plus one entry" allows exactly one filler.
///
/// Red on main: the zero budget beside the tail records `ClearOtherActive`
/// and releases every filler.
#[test]
fn cache_policy_m1_tail_growth_releases_at_most_overflow_plus_one_entry() {
    if unexecuted("M1_tail_growth") {
        return;
    }
    let run = tail_beside_full_cache(false, append_growth);
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} filler_charge={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} cursor_reservation_entries_evicted={} insert_entries_evicted={} fillers_after={} tail_retained_after={}",
        run.resident_before,
        run.filler_charge,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.counts.cursor_reservation_entries_evicted,
        run.counts.insert_entries_evicted,
        run.fillers_after,
        run.tail_retained_after,
    );
    eprintln!("CACHE_POLICY test=M1_tail_growth {receipt}");
    assert_eq!(
        wipe_clears(&run.counts),
        0,
        "M1: a growing tail wiped the cache; {receipt}"
    );
    assert_eq!(
        run.counts.clear_entries_released, 0,
        "M1: a growing tail cleared entries; {receipt}"
    );
    assert_eq!(
        run.fillers_after,
        FILLERS - 1,
        "M1: the overflow did not release exactly one entry; {receipt}"
    );
    assert_eq!(
        run.counts.cursor_reservation_entries_evicted, 0,
        "M1: a copy refusal eviction was counted as a cursor reservation; {receipt}"
    );
}

/// A cached scan of the full cache's file, stepped until its append is the
/// active sampled tail (holding its borrowed entry).
fn tail_active(full: &FullCache) -> OwnedSourceScan {
    let source = SnapshotSource::ClaudeCode;
    full.tailed.append(&usage(source, 140, 1, MODEL));
    let mut scan = cached_scan(&full.tailed, source, full.index.clone(), &full.cache);
    for _ in 0..10_000 {
        let tail = scan.active_file.as_deref().is_some_and(|active| {
            active
                .sampling
                .as_ref()
                .is_some_and(|sampling| sampling.mode == ReadMode::Tail)
        });
        if tail {
            return scan;
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { .. } => panic!("precondition: a tail active"),
        }
    }
    panic!("precondition: the tail never became active");
}

/// M1 test (iii), the refusal decision matrix (design §6 row M1; §2 L1-L3).
///
/// A sampled tail is active beside four fillers that fill the cache. The
/// step-start release is called directly with injected step measurements:
/// - (a) the residents fit beside the active's optional charge (a merely full
///   cache): nothing is released;
/// - (b) no active file and a full cache (`ClearNoActive` today): nothing is
///   released;
/// - (c) lock contention, an unknown resident: a blocking re-measure finds the
///   residents bounded and releases nothing;
/// - (d) a real overflow of one byte evicts exactly one entry, the minimum;
/// - (e) an overflow of one entry and one byte evicts exactly two;
/// - (f) an active charge that cannot fit beside even an empty cache, and
///   (g) an unknown active charge, keep the conservative clear, counted as
///   `ClearOtherActive`.
///
/// No case counts an eviction as a cursor reservation (review F7).
///
/// Red on main: main ignores the active's charge, so case (a) already
/// records `ClearOtherActive` and wipes every filler.
#[test]
fn cache_policy_m1_refusal_decision_matrix_evicts_the_minimum() {
    if unexecuted("M1_decision_matrix") {
        return;
    }
    use sampled_scan::StepMeasure;
    let full = full_cache_with_retained_file(false);
    let scan = tail_active(&full);
    let cache = &full.cache;
    let measured = || {
        crate::heap_layout_bound::bound(scan.sampling.as_ref().unwrap(), POLICY_STATE_BYTES)
            .expect("precondition: bounded residents")
    };
    let release = |active: bool, step: StepMeasure| {
        observe(|| {
            sampled_scan::release_cache_to_fit(
                scan.sampling.as_ref(),
                scan.active_file.as_deref().filter(|_| active),
                step,
            )
        })
        .1
    };
    // Wipe-all releases and evictions counted as a cursor reservation.
    let wiped = |counts: &Counts| {
        wipe_clears(counts)
            + counts.clear_entries_released
            + counts.cursor_reservation_entries_evicted
    };
    assert_eq!(
        fillers_resident(cache),
        FILLERS,
        "precondition: the fillers"
    );

    let resident = measured();
    let room = POLICY_STATE_BYTES - resident;
    let counts = release(
        true,
        StepMeasure {
            resident: Some(resident),
            active: Some(room),
        },
    );
    assert_eq!(
        wiped(&counts),
        0,
        "(a) a merely full cache released; {counts:?}"
    );
    assert_eq!(fillers_resident(cache), FILLERS, "(a)");

    let counts = release(
        false,
        StepMeasure {
            resident: Some(resident),
            active: None,
        },
    );
    assert_eq!(wiped(&counts), 0, "(b) no active released; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS, "(b)");

    let counts = release(
        true,
        StepMeasure {
            resident: None,
            active: Some(room / 2),
        },
    );
    assert_eq!(wiped(&counts), 0, "(c) contention released; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS, "(c)");

    let counts = release(
        true,
        StepMeasure {
            resident: Some(resident),
            active: Some(room + 1),
        },
    );
    assert_eq!(wiped(&counts), 0, "(d) an overflow wiped; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS - 1, "(d) not the minimum");

    let resident = measured();
    let room = POLICY_STATE_BYTES - resident;
    let counts = release(
        true,
        StepMeasure {
            resident: Some(resident),
            active: Some(room + full.filler_charge + 1),
        },
    );
    assert_eq!(wiped(&counts), 0, "(e) an overflow wiped; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS - 3, "(e) not the minimum");

    let counts = release(
        true,
        StepMeasure {
            resident: Some(measured()),
            active: Some(POLICY_STATE_BYTES),
        },
    );
    assert_eq!(counts.clear_other_active, 1, "(f) {counts:?}");
    assert_eq!(counts.clear_entries_released, 1, "(f) {counts:?}");
    assert_eq!(fillers_resident(cache), 0, "(f)");

    let counts = release(
        true,
        StepMeasure {
            resident: Some(measured()),
            active: None,
        },
    );
    assert_eq!(counts.clear_other_active, 1, "(g) {counts:?}");
    assert_eq!(
        counts.cursor_reservation_entries_evicted, 0,
        "(g) {counts:?}"
    );
}
