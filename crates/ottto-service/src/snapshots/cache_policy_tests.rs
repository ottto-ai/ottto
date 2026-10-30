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
//! Round 2 (review of #666): M1 (i) and (ii) are restated for Path A, the
//! owner-accepted admission bridge: a zero-budget tail makes room for its
//! own copy from entries older than the tailed file only. Added: the hot-file
//! model (no Full read of an actively tailed file), the visit-limited active
//! (F1) and the exempt re-measure on the production path (F4). The decision
//! matrix and counter tests use a tail ranked older than every filler, so
//! Path A evicts nothing there and they pin evict-to-fit alone. F2 (a group
//! job's overflow) is in `group_job_tests`, which reuses these fillers.
//!
//! P1-RETAIN R0 (Q-PR14, with the parent's B1 ruling 1): every tail here is
//! a sampled Claude Tail singleton that borrows only its retained reduction
//! (shape F, `borrows_only_retained_reduction`). Its step start gets neither
//! evict-to-fit nor Path A; its only release is at completion, of residents
//! ranked strictly below its copy's re-admission rank (its source mtime
//! clipped to now once, the rank its copy is admitted at), not its taken
//! hint. M1 (i), (ii) and the hot-file model are main's rows, unchanged
//! (ruling 2): they are the acceptance controls. Their
//! `cache_policy_r0_diagnostic_m1_*` twins and the regime-B rows
//! (`cache_policy_r0_regime_b_*`, fillers ranked two days back) are
//! diagnostics, not acceptance: they print R0's probe and decision. A Claude
//! tail proves its release with its measured X_out (M-a, without Q-PR15's
//! guard); a Codex tail keeps `F_prev` and the guard (ruling 5). G3 is
//! unchanged. The decision matrix, the counters and
//! the visit-limited active pin evict-to-fit on a non-F tail (a comparison
//! target), each with a shape-F control that releases nothing;
//! `cache_policy_m1_path_a_admits_a_non_f_tail_from_older_entries_only` pins
//! Path A itself on a non-F tail.
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
pub(super) const POLICY_STATE_BYTES: usize =
    crate::transcript_cache::CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - 1024 * 1024;
/// Four filler reductions fill the state budget to within a few MB without
/// any eviction.
pub(super) const FILLERS: usize = 4;
/// One filler's charge, in thousandths of the state budget: four fill about
/// 84% of it, as four 1,400-response reductions did before compact Claude
/// records (#653 T3: 27,664,691 B, 6,887,051 B each), leaving about 4.8 MB.
/// `filler_records` sizes the filler file from measured charges, so a change
/// to the per-response charge cannot leave the zero-budget steps unreached.
// Keep M-a's 256 KiB prefix margin with E2's itemized finish term, main's
// stored ctime/birth fields, and the longer Linux CI paths. This calibrates
// fixture fill only; zero-budget and exact two-victim assertions stay intact.
const FILLER_STATE_PERMILLE: usize = 210;
/// The two probe files that measure a filler's charge per response.
const FILLER_PROBE_RECORDS: [usize; 2] = [700, 1400];
/// One appended record this long leaves the tail parser's line buffer at
/// least this capacity at its next step start: more than the room the
/// filled cache leaves, so the copy budget beside the tail is zero.
const TAIL_PADDING_BYTES: usize = 8 * 1024 * 1024;
/// Two days: outside the one-hour audit horizon, so a file this old is cold.
const OLD_SECONDS: u64 = 2 * 24 * 3600;
/// Passes of the hot-file model, each one append read as a tail.
const HOT_PASSES: usize = 3;
/// Owned strings that take a tail's per-step walk past the 4,096-visit cap
/// while their bytes stay within the room the fillers leave (about 2.7 MB).
const VISIT_PADDING: usize = 4200;
/// Further strings of about 1 KB each: the visit-limited tail's bytes then
/// overflow the state budget by less than one filler's charge.
const OVERFLOW_PADDING: usize = 3000;

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
        .retain_reduction(
            &scope,
            now,
            sampled_scan::RetainBudget::granted_unclassified(crate::transcript_cache::ENTRY_BYTES),
        )
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
    /// The scan's finished items, before the upload policy.
    snapshots: Vec<SnapshotItem>,
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
        std::slice::from_ref(&fixture.path),
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
                let snapshots = result.snapshots.clone();
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
                    snapshots,
                };
            }
        }
    }
}

/// Wipe-all releases: every `clear()` path of the copy refusal.
pub(super) fn wipe_clears(counts: &Counts) -> u64 {
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

/// The charge one retained reduction of a `records`-response file adds to an
/// empty shared cache. Its lifecycle events are kept out of any caller's.
fn filler_charge_for(records: usize) -> usize {
    let source = SnapshotSource::ClaudeCode;
    let filler = ScanFixture::new(source);
    filler.append_usage(source, 0..records);
    observe(|| {
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let empty = optional_resident(&cache);
        let retained = retained_reduction(&filler);
        assert!(
            cache
                .retained()
                .expect("retained cache lock")
                .insert(filler_key(0), retained),
            "precondition: a {records}-response filler is admitted"
        );
        optional_resident(&cache) - empty
    })
    .0
}

/// The response count whose filler charges `FILLER_STATE_PERMILLE` of the
/// state budget, within 1%: a linear estimate from two probe files, then
/// corrected on the measured charge (vector growth is not linear). Measured
/// once per process.
fn filler_records() -> usize {
    static RECORDS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *RECORDS.get_or_init(|| {
        let target = POLICY_STATE_BYTES / 1000 * FILLER_STATE_PERMILLE;
        let [low, high] = FILLER_PROBE_RECORDS;
        let high_charge = filler_charge_for(high);
        let slope = high_charge.saturating_sub(filler_charge_for(low)) / (high - low);
        assert!(slope > 0, "precondition: a filler's charge grows per response");
        let step = |records: usize, charge: usize| {
            (records as isize + (target as isize - charge as isize) / slope as isize).max(1)
                as usize
        };
        let mut records = step(high, high_charge);
        let mut charge = filler_charge_for(records);
        for _ in 0..4 {
            if charge.abs_diff(target) <= target / 200 {
                break;
            }
            records = step(records, charge);
            charge = filler_charge_for(records);
        }
        eprintln!("CACHE_POLICY filler records={records} charge={charge} target={target} slope={slope}");
        assert!(
            charge.abs_diff(target) <= target / 100,
            "precondition: a {records}-response filler charges {charge} B, not within 1% of {target} B"
        );
        records
    })
}

/// Insert `FILLERS` real retained reductions of one `filler_records` file
/// under unrelated keys, as #653 T3 does. `modified` pins the fillers' rank.
fn insert_fillers(cache: &Arc<sampled_scan::SharedCache>, modified: Option<u64>) {
    let source = SnapshotSource::ClaudeCode;
    let filler = ScanFixture::new(source);
    filler.append_usage(source, 0..filler_records());
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

pub(super) fn fillers_resident(cache: &sampled_scan::SharedCache) -> usize {
    (0..FILLERS)
        .filter(|number| cache.retained_checkpoint(&filler_key(*number)).is_some())
        .count()
}

/// A shared cache holding only the `FILLERS` fillers, and one filler's
/// charge to it.
pub(super) fn filled_cache() -> (Arc<sampled_scan::SharedCache>, usize) {
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let empty = optional_resident(&cache);
    insert_fillers(&cache, None);
    let charge = (optional_resident(&cache) - empty) / FILLERS;
    (cache, charge)
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
    full_cache_in(SnapshotSource::ClaudeCode, older_tail, None)
}

/// `full_cache_with_retained_file` for a `source` file, with the fillers'
/// rank pinned at `fillers_modified` (regime B: older than the tailed file's
/// taken hint and its re-admission rank).
fn full_cache_in(
    source: SnapshotSource,
    older_tail: bool,
    fillers_modified: Option<u64>,
) -> FullCache {
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
    insert_fillers(&cache, fillers_modified);
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
    /// What R0's completion measured and decided (`test_hooks`).
    r0: String,
}

/// The tailed file's append for `tail_beside_full_cache`: one long record,
/// then one usage record. The long record's line buffer meets a zero copy
/// budget at the next step start; the borrowed state itself stays tiny and
/// fits beside the fillers.
fn append_padded_usage(tailed: &ScanFixture) {
    append_padded_usage_at(tailed, 1);
}

/// `append_padded_usage` with response `id`.
fn append_padded_usage_at(tailed: &ScanFixture, id: usize) {
    tailed.append(&json!({
        "type": "synthetic-padding",
        "text": "x".repeat(TAIL_PADDING_BYTES),
    }));
    tailed.append(&usage(
        SnapshotSource::ClaudeCode,
        140 + id as u64,
        id,
        MODEL,
    ));
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
    sampled_scan::test_hooks::clear();
    let (tail, counts) = observe(|| observed_scan(&tailed, source, index, &cache));
    let r0 = format!(
        "probe={:?} decisions={:?}",
        sampled_scan::test_hooks::last_probe(),
        sampled_scan::test_hooks::decisions()
    );
    sampled_scan::test_hooks::clear();
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
        r0,
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
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    eprintln!("CACHE_POLICY test=G3_priority {receipt} {}", run.r0);
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

/// M1 test (i), no wipe-all (design §6 row M1; §2 L1), restated for Path A.
///
/// A full but not overflowing cache: one retained Claude entry plus four
/// fillers within the state budget. The Claude file's append (one long record,
/// then a usage record) reads as a tail and meets a zero copy budget at a step
/// start. That overflow is the tail's line buffer (16 MiB after the 8 MiB
/// record), not optional memory. Desired: no wipe-all clear and no
/// evict-to-fit eviction (`clear_*` 0, `clear_entries_released` 0,
/// `copy_refusal_entries_evicted` 0).
///
/// Path A, the intended behavior (owner-accepted; review §3c): every filler is
/// older than the tailed file, so that zero-budget step evicts the oldest, in
/// victim order, until the tail's own copy fits its next step's budget beside
/// that line buffer. The buffer leaves room for two of the four fillers, so
/// at most two yield, and the tail is re-retained as main's wipe re-retained
/// it. Round 1 asserted at most one filler lost; it never re-retained the
/// tail.
///
/// Red on main: `ClearOtherActive` 1 and `clear_entries_released` 4, so every
/// filler is gone.
#[test]
fn cache_policy_m1_full_cache_tail_at_zero_budget_releases_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_no_wipe") {
        return;
    }
    let run = tail_beside_full_cache(false, append_padded_usage);
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} copy_refusal_entries_evicted={} copy_refusal_admission_evicted={} fillers_after={} tail_retained_after={}",
        run.resident_before,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.counts.copy_refusal_entries_evicted,
        run.counts.copy_refusal_admission_evicted,
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
    assert_eq!(
        run.counts.copy_refusal_entries_evicted, 0,
        "M1: evicted to fit a cache that was not overflowing; {receipt}"
    );
    assert!(
        run.fillers_after + 2 >= FILLERS,
        "Path A: more than two older fillers lost; {receipt}"
    );
    assert!(
        run.tail_retained_after,
        "Path A: the older fillers did not make room for the tail's copy; {receipt}"
    );
}

/// Diagnostic, not acceptance (parent ruling 2): M1 (i)'s scenario, with R0's
/// completion probe and decision in its receipt. The acceptance row is main's
/// `cache_policy_m1_full_cache_tail_at_zero_budget_releases_nothing`,
/// unchanged. Asserts only that nothing is wiped.
#[test]
fn cache_policy_r0_diagnostic_m1_full_cache_tail() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("R0_diag_M1_no_wipe") {
        return;
    }
    let run = tail_beside_full_cache(false, append_padded_usage);
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} filler_charge={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} copy_refusal_entries_evicted={} copy_refusal_admission_evicted={} insert_entries_evicted={} fillers_after={} tail_retained_after={}",
        run.resident_before,
        run.filler_charge,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.counts.copy_refusal_entries_evicted,
        run.counts.copy_refusal_admission_evicted,
        run.counts.insert_entries_evicted,
        run.fillers_after,
        run.tail_retained_after,
    );
    eprintln!("CACHE_POLICY test=R0_diag_M1_no_wipe {receipt} {}", run.r0);
    assert_eq!(wipe_clears(&run.counts), 0, "a wipe-all clear; {receipt}");
}

/// Responses appended for M1 (ii): 13/14 of a filler's, as 1,300 beside
/// 1,400 before compact Claude records. A tail's state is the same Claude
/// reduction, charged per response as a filler is, so the borrowed state grows
/// past the room the fillers leave (about 4.8 MB), yet below one filler's
/// charge.
fn tail_growth_records() -> usize {
    filler_records() * 13 / 14
}

/// The tailed file's append for M1 (ii): `tail_growth_records` ordinary
/// responses, so the borrowed tail state itself grows.
fn append_growth(tailed: &ScanFixture) {
    tailed.append_usage(SnapshotSource::ClaudeCode, 1..1 + tail_growth_records());
}

/// M1 test (ii), corrected (joint M1 (ii) disposition, Oct 22; StateMissing
/// sign-off closed).
///
/// The same full cache, but the tailed file's append is
/// `tail_growth_records` ordinary responses: the borrowed tail state grows
/// past the room the fillers leave, a real overflow of the state budget.
/// Main refused this copy at `retain_reduction`; R0 before M-a released
/// fillers and then refused at finalization, an eviction without benefit.
///
/// Desired: an optional-copy refusal with zero eviction. No copy is
/// retained, all `FILLERS` fillers stay, and the refusal is counted. A
/// release runs only where an owned bound proves the clone, the finished
/// output and the decode peak fit (M-a), and this growth never does.
///
/// Was `cache_policy_m1_tail_growth_releases_at_most_overflow_plus_one_entry`,
/// which pinned two evictions: a release without benefit.
#[test]
fn cache_policy_m1_tail_growth_refuses_its_copy_without_eviction() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_tail_growth_refusal") {
        return;
    }
    let run = tail_beside_full_cache(false, append_growth);
    let refusals = run.counts.retention_bound_refused
        + run.counts.retention_clone_bound_refused
        + run.counts.retention_finalization_bound_refused
        + run.counts.insert_live_reservation_refused
        + run.counts.insert_entry_bound_refused
        + run.counts.insert_frozen_charge_refused
        + run.counts.insert_no_victim_refused;
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} filler_charge={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} cursor_reservation_entries_evicted={} copy_refusal_entries_evicted={} copy_refusal_admission_evicted={} insert_entries_evicted={} refusals={refusals} fillers_after={} tail_retained_after={} {}",
        run.resident_before,
        run.filler_charge,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.counts.cursor_reservation_entries_evicted,
        run.counts.copy_refusal_entries_evicted,
        run.counts.copy_refusal_admission_evicted,
        run.counts.insert_entries_evicted,
        run.fillers_after,
        run.tail_retained_after,
        run.r0,
    );
    eprintln!("CACHE_POLICY test=M1_tail_growth_refusal {receipt}");
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
        run.counts.copy_refusal_entries_evicted
            + run.counts.copy_refusal_admission_evicted
            + run.counts.cursor_reservation_entries_evicted
            + run.counts.insert_entries_evicted,
        0,
        "M1: a refused copy evicted residents; {receipt}"
    );
    assert_eq!(
        run.fillers_after, FILLERS,
        "M1: a refused copy did not keep every filler; {receipt}"
    );
    assert!(
        !run.tail_retained_after,
        "precondition: the grown tail's copy does not fit; {receipt}"
    );
    assert!(refusals >= 1, "M1: the refusal was not counted; {receipt}");
}

/// Diagnostic, not acceptance (parent ruling 2): M1 (ii)'s scenario, with
/// R0's completion probe and decision in its receipt. The acceptance row is
/// `cache_policy_m1_tail_growth_refuses_its_copy_without_eviction`. Asserts
/// only that nothing is wiped.
#[test]
fn cache_policy_r0_diagnostic_m1_tail_growth() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("R0_diag_M1_tail_growth") {
        return;
    }
    let run = tail_beside_full_cache(false, append_growth);
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={} filler_charge={} tail_zero_budget_steps={} clear_other_active={} clear_entries_released={} cursor_reservation_entries_evicted={} copy_refusal_entries_evicted={} copy_refusal_admission_evicted={} insert_entries_evicted={} fillers_after={} tail_retained_after={}",
        run.resident_before,
        run.filler_charge,
        run.tail.tail_zero_budget_steps,
        run.counts.clear_other_active,
        run.counts.clear_entries_released,
        run.counts.cursor_reservation_entries_evicted,
        run.counts.copy_refusal_entries_evicted,
        run.counts.copy_refusal_admission_evicted,
        run.counts.insert_entries_evicted,
        run.fillers_after,
        run.tail_retained_after,
    );
    eprintln!(
        "CACHE_POLICY test=R0_diag_M1_tail_growth {receipt} {}",
        run.r0
    );
    assert_eq!(wipe_clears(&run.counts), 0, "a wipe-all clear; {receipt}");
}

/// A cached scan of the full cache's file, stepped until its append is the
/// active sampled tail (holding its borrowed entry). `older_tail` keeps the
/// file's mtime two days back after the append, below every filler's rank,
/// so Path A has no older entry to evict.
fn tail_active(full: &FullCache, older_tail: bool) -> OwnedSourceScan {
    tail_active_at(full, older_tail.then(|| unix_now() - OLD_SECONDS + 1))
}

/// `tail_active`, with the tailed file's mtime set to `modified` after the
/// append.
fn tail_active_at(full: &FullCache, modified: Option<u64>) -> OwnedSourceScan {
    let source = SnapshotSource::ClaudeCode;
    full.tailed.append(&usage(source, 140, 1, MODEL));
    if let Some(modified) = modified {
        full.tailed.set_modified(modified);
    }
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

/// Make the scan's shape-F tail a non-F one (a comparison target), so its
/// step start keeps evict-to-fit and Path A (Q-PR14 exempts shape F only).
fn make_non_f(scan: &mut OwnedSourceScan) {
    let active = scan.active_file.as_deref_mut().expect("the tail active");
    assert!(
        sampled_scan::borrows_only_retained_reduction(active),
        "precondition: shape F"
    );
    active.comparison_target = true;
    assert!(!sampled_scan::borrows_only_retained_reduction(active));
}

/// Restore the shape-F tail `make_non_f` changed.
fn make_shape_f(scan: &mut OwnedSourceScan) {
    let active = scan.active_file.as_deref_mut().expect("the tail active");
    active.comparison_target = false;
    assert!(sampled_scan::borrows_only_retained_reduction(active));
}

/// An injected step measure: an active charge with its budget charge.
fn measure(resident: Option<usize>, active: Option<usize>) -> sampled_scan::StepMeasure {
    sampled_scan::StepMeasure {
        resident,
        active,
        used: active,
    }
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
/// No case counts an eviction as a cursor reservation (review F7). The tail
/// ranks below every filler, so Path A adds no eviction to any case.
///
/// Red on main: main ignores the active's charge, so case (a) already
/// records `ClearOtherActive` and wipes every filler.
#[test]
fn cache_policy_m1_refusal_decision_matrix_evicts_the_minimum() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_decision_matrix") {
        return;
    }
    let full = full_cache_with_retained_file(true);
    let mut scan = tail_active(&full, true);
    let cache = &full.cache;
    // Q-PR14 control: the same overflowing measures beside the shape-F tail
    // release nothing and clear nothing.
    {
        let resident =
            crate::heap_layout_bound::bound(scan.sampling.as_ref().unwrap(), POLICY_STATE_BYTES)
                .expect("precondition: bounded residents");
        let room = POLICY_STATE_BYTES - resident;
        for step in [
            measure(Some(resident), Some(room + 1)),
            measure(Some(resident), Some(room + full.filler_charge + 1)),
            measure(Some(resident), Some(POLICY_STATE_BYTES)),
            measure(Some(resident), None),
            measure(None, Some(room + 1)),
        ] {
            let (_, counts) = observe(|| {
                sampled_scan::release_cache_to_fit(
                    scan.sampling.as_ref(),
                    scan.active_file.as_deref(),
                    step,
                )
            });
            assert_eq!(counts, Counts::default(), "shape F {step:?}");
            assert_eq!(fillers_resident(cache), FILLERS, "shape F {step:?}");
        }
    }
    make_non_f(&mut scan);
    let measured = || {
        crate::heap_layout_bound::bound(scan.sampling.as_ref().unwrap(), POLICY_STATE_BYTES)
            .expect("precondition: bounded residents")
    };
    let release = |active: bool, step: sampled_scan::StepMeasure| {
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
    let counts = release(true, measure(Some(resident), Some(room)));
    assert_eq!(
        wiped(&counts),
        0,
        "(a) a merely full cache released; {counts:?}"
    );
    assert_eq!(fillers_resident(cache), FILLERS, "(a)");

    let counts = release(false, measure(Some(resident), None));
    assert_eq!(wiped(&counts), 0, "(b) no active released; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS, "(b)");

    let counts = release(true, measure(None, Some(room / 2)));
    assert_eq!(wiped(&counts), 0, "(c) contention released; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS, "(c)");

    let counts = release(true, measure(Some(resident), Some(room + 1)));
    assert_eq!(wiped(&counts), 0, "(d) an overflow wiped; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS - 1, "(d) not the minimum");

    let resident = measured();
    let room = POLICY_STATE_BYTES - resident;
    let counts = release(
        true,
        measure(Some(resident), Some(room + full.filler_charge + 1)),
    );
    assert_eq!(wiped(&counts), 0, "(e) an overflow wiped; {counts:?}");
    assert_eq!(fillers_resident(cache), FILLERS - 3, "(e) not the minimum");

    let counts = release(true, measure(Some(measured()), Some(POLICY_STATE_BYTES)));
    assert_eq!(counts.clear_other_active, 1, "(f) {counts:?}");
    assert_eq!(counts.clear_entries_released, 1, "(f) {counts:?}");
    assert_eq!(fillers_resident(cache), 0, "(f)");

    let counts = release(true, measure(Some(measured()), None));
    assert_eq!(counts.clear_other_active, 1, "(g) {counts:?}");
    assert_eq!(
        counts.cursor_reservation_entries_evicted, 0,
        "(g) {counts:?}"
    );
}

/// M1 counters (review F7) and the overhead bound the release fits against.
/// A merely full cache and a blocking re-measure are counted. An overflow's
/// evictions and charged bytes are counted under the copy refusal, never as a
/// cursor reservation. `context_overhead` never undercounts `bound(context)`.
/// Lands with the fix: the counters do not exist on main.
#[test]
fn cache_policy_m1_counts_copy_refusal_releases_by_cause() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_counters") {
        return;
    }
    let full = full_cache_with_retained_file(true);
    let mut scan = tail_active(&full, true);
    make_non_f(&mut scan);
    let context = scan.sampling.as_ref().unwrap();
    assert!(
        sampled_scan::context_overhead_covers(context),
        "the context overhead undercounts the context"
    );
    let release = |step: sampled_scan::StepMeasure| {
        observe(|| {
            sampled_scan::release_cache_to_fit(Some(context), scan.active_file.as_deref(), step)
        })
        .1
    };
    let resident = crate::heap_layout_bound::bound(context, POLICY_STATE_BYTES)
        .expect("precondition: bounded residents");
    let room = POLICY_STATE_BYTES - resident;

    let counts = release(measure(Some(resident), Some(room)));
    assert_eq!(
        (
            counts.copy_refusal_kept,
            counts.copy_refusal_remeasured,
            counts.copy_refusal_entries_evicted,
            counts.copy_refusal_bytes_released,
        ),
        (1, 0, 0, 0),
        "a merely full cache"
    );

    let counts = release(measure(None, Some(room / 2)));
    assert_eq!(
        (
            counts.copy_refusal_kept,
            counts.copy_refusal_remeasured,
            counts.copy_refusal_entries_evicted,
        ),
        (0, 1, 0),
        "a blocking re-measure"
    );

    let before = optional_resident(&full.cache);
    let counts = release(measure(Some(resident), Some(room + 1)));
    let freed = before - optional_resident(&full.cache);
    assert_eq!(counts.copy_refusal_entries_evicted, 1, "{counts:?}");
    assert_eq!(counts.cursor_reservation_entries_evicted, 0, "{counts:?}");
    assert_eq!(wipe_clears(&counts), 0, "{counts:?}");
    assert!(
        counts.copy_refusal_bytes_released > 0
            && counts.copy_refusal_bytes_released <= freed as u64,
        "released bytes {} of {freed} freed",
        counts.copy_refusal_bytes_released
    );
}

/// M1 Path A, the hot file (review §3b model, regime B).
///
/// One actively tailing session beside `FILLERS` idle entries that fill the
/// cache and are older than it. On each of `HOT_PASSES` passes it gains an
/// append whose long record leaves a line buffer that meets a zero copy
/// budget. Desired: the hot file is read as a tail on every pass and never
/// `Full`: 0 Full reads, as main's wipe gave. Evict-to-fit alone (round 1)
/// refused its copy at the first pass and read it `Full` on every later one.
/// No wipe-all clear; only older entries yield, at most two.
#[test]
fn cache_policy_m1_hot_tail_beside_idle_entries_never_reads_full() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_hot_tail") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let FullCache {
        cache,
        tailed,
        index,
        resident_before,
        ..
    } = full_cache_with_retained_file(false);
    let ((full_reads, tails, zero_budget_steps), counts) = observe(|| {
        let mut index = index;
        let (mut full_reads, mut tails, mut zero_budget_steps) = (0, 0, 0);
        for pass in 0..HOT_PASSES {
            append_padded_usage_at(&tailed, 1 + pass);
            let run = observed_scan(&tailed, source, index, &cache);
            full_reads += run.modes.0;
            tails += run.modes.1;
            zero_budget_steps += run.tail_zero_budget_steps;
            index = run.index;
        }
        (full_reads, tails, zero_budget_steps)
    });
    let fillers_after = fillers_resident(&cache);
    let retained_after = cache.retained_checkpoint(&tailed.key()).is_some();
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={resident_before} passes={HOT_PASSES} full_reads={full_reads} tails={tails} tail_zero_budget_steps={zero_budget_steps} clear_other_active={} copy_refusal_entries_evicted={} copy_refusal_admission_evicted={} fillers_after={fillers_after} tail_retained_after={retained_after}",
        counts.clear_other_active,
        counts.copy_refusal_entries_evicted,
        counts.copy_refusal_admission_evicted,
    );
    eprintln!("CACHE_POLICY test=M1_hot_tail {receipt}");
    assert!(
        zero_budget_steps >= 1,
        "precondition: a tail step meets a zero copy budget; {receipt}"
    );
    assert_eq!(
        full_reads, 0,
        "Path A: the hot file was read Full; {receipt}"
    );
    assert_eq!(tails, HOT_PASSES, "every pass reads a tail; {receipt}");
    assert_eq!(wipe_clears(&counts), 0, "a wipe-all clear; {receipt}");
    assert!(
        fillers_after + 2 >= FILLERS,
        "Path A: more than two older fillers lost; {receipt}"
    );
    assert!(retained_after, "the hot file is not retained; {receipt}");
}

/// Diagnostic, not acceptance (parent ruling 2): the hot-file model's
/// passes, each with R0's completion probe and decision. The acceptance row
/// is main's `cache_policy_m1_hot_tail_beside_idle_entries_never_reads_full`,
/// unchanged. Asserts only that nothing is wiped.
#[test]
fn cache_policy_r0_diagnostic_m1_hot_tail() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("R0_diag_M1_hot_tail") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let FullCache {
        cache,
        tailed,
        index,
        resident_before,
        ..
    } = full_cache_with_retained_file(false);
    let ((full_reads, tails, zero_budget_steps), counts) = observe(|| {
        let mut index = index;
        let (mut full_reads, mut tails, mut zero_budget_steps) = (0, 0, 0);
        for pass in 0..HOT_PASSES {
            append_padded_usage_at(&tailed, 1 + pass);
            sampled_scan::test_hooks::clear();
            let run = observed_scan(&tailed, source, index, &cache);
            eprintln!(
                "CACHE_POLICY test=R0_diag_M1_hot_tail pass={pass} modes={:?} fillers_after={} probe={:?} decisions={:?}",
                run.modes,
                fillers_resident(&cache),
                sampled_scan::test_hooks::last_probe(),
                sampled_scan::test_hooks::decisions()
            );
            sampled_scan::test_hooks::clear();
            full_reads += run.modes.0;
            tails += run.modes.1;
            zero_budget_steps += run.tail_zero_budget_steps;
            index = run.index;
        }
        (full_reads, tails, zero_budget_steps)
    });
    let fillers_after = fillers_resident(&cache);
    let retained_after = cache.retained_checkpoint(&tailed.key()).is_some();
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_before={resident_before} passes={HOT_PASSES} full_reads={full_reads} tails={tails} tail_zero_budget_steps={zero_budget_steps} clear_other_active={} copy_refusal_entries_evicted={} copy_refusal_admission_evicted={} insert_entries_evicted={} fillers_after={fillers_after} tail_retained_after={retained_after}",
        counts.clear_other_active,
        counts.copy_refusal_entries_evicted,
        counts.copy_refusal_admission_evicted,
        counts.insert_entries_evicted,
    );
    eprintln!("CACHE_POLICY test=R0_diag_M1_hot_tail {receipt}");
    assert_eq!(wipe_clears(&counts), 0, "a wipe-all clear; {receipt}");
}

/// M1 F1, the visit cap (brief addendum; review §2).
///
/// A sampled tail, ranked below four fillers that fill the cache, whose
/// per-step walk exceeds the heap walk's 4,096-visit cap: thousands of small
/// owned strings, as a long Codex tail's usage hours grow. That walk is
/// refused, so the byte walk (`completed_bound`) supplies the refusal's
/// charge while the copy budget stays zero; each such step counts
/// `copy_refusal_walk_visit_limit`. Desired: never a wipe-all clear. Where
/// the bytes fit, nothing is evicted. Where they overflow by less than one
/// entry, exactly one entry is evicted and the others survive.
///
/// Red at round 1 (66e5315c): the unknown charge recorded `ClearOtherActive`
/// and cleared every filler.
#[test]
fn cache_policy_m1_visit_limited_active_evicts_at_most_what_it_needs() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_visit_limit") {
        return;
    }
    let full = full_cache_with_retained_file(true);
    let mut scan = tail_active(&full, true);
    make_non_f(&mut scan);
    let cache = &full.cache;
    let pad = |scan: &mut OwnedSourceScan, range: std::ops::Range<usize>, bytes: usize| {
        let active = scan.active_file.as_deref_mut().expect("the tail active");
        active
            .parser
            .accumulator
            .provider_skills
            .extend(range.map(|n| format!("visit-{n:05}-{}", "x".repeat(bytes))));
    };
    // The production step start: this step's walk, then its release.
    let step_release = |scan: &mut OwnedSourceScan| {
        let (budget, step) = scan.sampled_copy_step();
        let counts = observe(|| {
            sampled_scan::release_cache_to_fit(
                scan.sampling.as_ref(),
                scan.active_file.as_deref(),
                step,
            )
        })
        .1;
        (budget, step, counts)
    };
    assert_eq!(
        fillers_resident(cache),
        FILLERS,
        "precondition: the fillers"
    );

    pad(&mut scan, 0..VISIT_PADDING, 0);
    assert!(
        crate::heap_layout_bound::bound(scan.active_file.as_deref().unwrap(), usize::MAX).is_none(),
        "precondition: the per-step walk exceeds the visit cap"
    );
    let (budget, step, counts) = step_release(&mut scan);
    let receipt = format!("budget={budget} step={step:?} counts={counts:?}");
    eprintln!("CACHE_POLICY test=M1_visit_limit fits {receipt}");
    assert_eq!(budget, 0, "precondition: a zero copy budget; {receipt}");
    assert!(
        step.active.is_some() && step.used.is_none(),
        "F1: the byte walk's charge, no budget charge; {receipt}"
    );
    assert!(
        step.resident
            .zip(step.active)
            .is_some_and(|(resident, active)| resident + active <= POLICY_STATE_BYTES),
        "precondition: the bytes fit; {receipt}"
    );
    assert_eq!(counts.copy_refusal_walk_visit_limit, 1, "{receipt}");
    assert_eq!(wipe_clears(&counts), 0, "F1: a wipe-all clear; {receipt}");
    assert_eq!(counts.copy_refusal_entries_evicted, 0, "{receipt}");
    assert_eq!(fillers_resident(cache), FILLERS, "F1: {receipt}");

    pad(
        &mut scan,
        VISIT_PADDING..VISIT_PADDING + OVERFLOW_PADDING,
        1000,
    );
    let (budget, step, counts) = step_release(&mut scan);
    let receipt = format!(
        "budget={budget} step={step:?} filler_charge={} counts={counts:?}",
        full.filler_charge
    );
    eprintln!("CACHE_POLICY test=M1_visit_limit overflow {receipt}");
    let overflow = step
        .resident
        .zip(step.active)
        .map(|(resident, active)| (resident + active).saturating_sub(POLICY_STATE_BYTES));
    assert!(
        step.used.is_none()
            && overflow.is_some_and(|overflow| overflow > 0 && overflow < full.filler_charge),
        "precondition: a visit-limited overflow below one entry; {receipt}"
    );
    assert_eq!(counts.copy_refusal_walk_visit_limit, 1, "{receipt}");
    assert_eq!(wipe_clears(&counts), 0, "F1: a wipe-all clear; {receipt}");
    assert_eq!(counts.copy_refusal_entries_evicted, 1, "{receipt}");
    assert_eq!(fillers_resident(cache), FILLERS - 1, "F1: {receipt}");

    // Q-PR14 control: the same visit-limited overflow beside a shape-F tail
    // counts the visit limit and releases nothing.
    make_shape_f(&mut scan);
    let (_, step, counts) = step_release(&mut scan);
    let receipt = format!("step={step:?} counts={counts:?}");
    assert_eq!(counts.copy_refusal_walk_visit_limit, 1, "shape F {receipt}");
    assert_eq!(wipe_clears(&counts), 0, "shape F {receipt}");
    assert_eq!(
        (
            counts.copy_refusal_entries_evicted,
            counts.copy_refusal_admission_evicted,
            counts.clear_entries_released,
        ),
        (0, 0, 0),
        "shape F {receipt}"
    );
    assert_eq!(fillers_resident(cache), FILLERS - 1, "shape F {receipt}");
}

/// M1 F4, the #654 exemption on the production path.
///
/// An unsampled native read (sidecar census incomplete) owns no optimization
/// state. Its step-start release runs on this step's real measure, with the
/// resident bound withheld as a contended walk leaves it. Desired: a
/// blocking re-measure finds the residents bounded and releases nothing; the
/// exemption never clears for want of a measurement.
#[test]
fn cache_policy_m1_exempt_unsampled_read_remeasures_an_unknown_resident() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_exempt_remeasure") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let (cache, _) = filled_cache();
    let fixture = ScanFixture::new(source);
    fixture.append_usage(source, 0..150);
    let mut scan = cached_scan(&fixture, source, ScanIndex::default(), &cache);
    scan.sidecar_census_complete = false;
    for _ in 0..10_000 {
        if scan.active_file.is_some() {
            break;
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { .. } => panic!("precondition: the file opens"),
        }
    }
    let active = scan
        .active_file
        .as_deref()
        .expect("precondition: the file opens");
    assert!(
        active.sampling.is_none()
            && active.cursor.is_none()
            && active.group.is_none()
            && active.aliases.is_empty()
            && active.applied_receipts.is_empty()
            && active.parser.reader.acquisition.is_none(),
        "precondition: an unsampled native read"
    );
    let (_, step) = scan.sampled_copy_step();
    assert!(
        step.resident.is_some(),
        "precondition: this step measured the residents"
    );
    let step = sampled_scan::StepMeasure {
        resident: None,
        ..step
    };
    let (_, counts) = observe(|| {
        sampled_scan::release_cache_to_fit(
            scan.sampling.as_ref(),
            scan.active_file.as_deref(),
            step,
        )
    });
    assert_eq!(counts.copy_refusal_remeasured, 1, "{counts:?}");
    assert_eq!(
        wipe_clears(&counts),
        0,
        "F4: the exemption cleared; {counts:?}"
    );
    assert_eq!(counts.clear_entries_released, 0, "{counts:?}");
    assert_eq!(counts.copy_refusal_entries_evicted, 0, "{counts:?}");
    assert_eq!(fillers_resident(&cache), FILLERS);
}

/// R2-B2, M1 Path A's positive pin on a non-F tail (a comparison target), at
/// unit level on the decision-matrix fixture. Four fillers ranked older than
/// the tailed file's current mtime fill the cache; one small entry ranks
/// above it. One step measure whose residents fit beside the active's
/// optional charge (`CopyRefusalKept`) but not beside the next step's copy
/// room (`overhead + used + 2·charge`):
/// - shape F (the Q-PR14 control), the same measure: nothing evicted;
/// - non-F, the tailed file ranked below every filler: no older entry can
///   make the room, so nothing is evicted (fit-or-nothing);
/// - non-F, ranked between the fillers and the newer entry: Path A evicts
///   exactly one filler (`CopyRefusalAdmissionEvicted` 1), never the newer
///   entry, and no evict-to-fit (`CopyRefusalEntriesEvicted` 0).
#[test]
fn cache_policy_m1_path_a_admits_a_non_f_tail_from_older_entries_only() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M1_path_a") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let now = unix_now();
    let full = full_cache_in(source, false, Some(now - 600));
    let cache = &full.cache;
    let newer = ScanFixture::new(source);
    newer.append(&usage(source, 100, 0, MODEL));
    newer.set_modified(now - 100);
    let newer_key = "cache-policy-newer".to_string();
    let (admitted, counts) = observe(|| {
        cache
            .retained()
            .expect("retained cache lock")
            .insert(newer_key.clone(), retained_reduction(&newer))
    });
    assert!(admitted, "precondition: the newer entry is admitted");
    assert_eq!(
        counts.insert_entries_evicted, 0,
        "precondition: no eviction"
    );
    let mut scan = tail_active_at(&full, None);
    let resident =
        crate::heap_layout_bound::bound(scan.sampling.as_ref().unwrap(), POLICY_STATE_BYTES)
            .expect("precondition: bounded residents");
    let room = POLICY_STATE_BYTES - resident;
    let charge = 1024;
    assert!(charge <= room, "precondition: the residents fit the charge");
    // The residents fit beside `charge`, but the next step's copy room needs
    // half a filler more than the room left.
    let step = sampled_scan::StepMeasure {
        resident: Some(resident),
        active: Some(charge),
        used: Some(room + full.filler_charge / 2),
    };
    let release = |scan: &OwnedSourceScan| {
        observe(|| {
            sampled_scan::release_cache_to_fit(
                scan.sampling.as_ref(),
                scan.active_file.as_deref(),
                step,
            )
        })
        .1
    };
    let newer_resident = || cache.retained_checkpoint(&newer_key).is_some();
    let counts = release(&scan);
    assert_eq!(counts, Counts::default(), "shape F control");
    assert_eq!(fillers_resident(cache), FILLERS, "shape F control");

    make_non_f(&mut scan);
    let set_rank = |scan: &mut OwnedSourceScan, seconds: u64| {
        let active = scan.active_file.as_deref_mut().expect("the tail active");
        active.candidate.modified_unix_nanos = seconds * 1_000_000_000;
    };
    set_rank(&mut scan, now - 900);
    let counts = release(&scan);
    assert_eq!(
        (
            counts.copy_refusal_kept,
            counts.copy_refusal_admission_evicted,
            counts.copy_refusal_entries_evicted,
            wipe_clears(&counts),
        ),
        (1, 0, 0, 0),
        "no older entry: fit-or-nothing {counts:?}"
    );
    assert_eq!(fillers_resident(cache), FILLERS, "fit-or-nothing");

    set_rank(&mut scan, now - 300);
    let counts = release(&scan);
    eprintln!("CACHE_POLICY test=M1_path_a resident={resident} room={room} counts={counts:?}");
    assert_eq!(
        (
            counts.copy_refusal_kept,
            counts.copy_refusal_admission_evicted,
            counts.copy_refusal_entries_evicted,
            counts.cursor_reservation_entries_evicted,
            wipe_clears(&counts),
        ),
        (1, 1, 0, 0, 0),
        "Path A {counts:?}"
    );
    assert_eq!(fillers_resident(cache), FILLERS - 1, "Path A: one filler");
    assert!(
        newer_resident(),
        "Path A: a newer-ranked entry never leaves"
    );
}

/// The tailed file's long ignored record: its line buffer meets a zero copy
/// budget beside the fillers, and no parser reads it as usage.
fn append_padding(tailed: &ScanFixture) {
    tailed.append(&json!({
        "type": "synthetic-padding",
        "text": "x".repeat(TAIL_PADDING_BYTES),
    }));
}

/// One regime-B pass's append: the padding, then a usage record (`usage`)
/// or nothing more.
fn hot_append(source: SnapshotSource, tailed: &ScanFixture, id: usize, usage_row: bool) {
    append_padding(tailed);
    if usage_row {
        tailed.append(&usage(source, 140 + id as u64, id, MODEL));
    }
}

/// One regime-B pass: its modes, step-start zero budgets, counts, and what
/// R0's completion measured and decided.
struct RegimePass {
    modes: (usize, usize, usize),
    zero_budget_steps: usize,
    counts: Counts,
    probe: sampled_scan::test_hooks::Probe,
    decisions: Vec<sampled_scan::test_hooks::Decision>,
    fillers_after: usize,
    retained_after: bool,
}

/// The hot-file model in regime B (review §3b): `FILLERS` idle entries
/// ranked two days back, below the tailed file's taken hint, fill the
/// cache; the tailed `source` file gains `HOT_PASSES` appends, each read as
/// one scan. Every pass is printed (`CACHE_POLICY test=R0_regime_b`).
fn regime_b_hot(source: SnapshotSource, usage_row: bool, label: &str) -> Vec<RegimePass> {
    let FullCache {
        cache,
        tailed,
        index,
        resident_before,
        filler_charge,
    } = full_cache_in(source, false, Some(unix_now() - OLD_SECONDS));
    let filler_rank = cache
        .retained_checkpoint(&filler_key(0))
        .unwrap()
        .modified_hint();
    let tailed_rank = cache
        .retained_checkpoint(&tailed.key())
        .unwrap()
        .modified_hint();
    assert!(
        filler_rank < tailed_rank,
        "precondition: regime B, every filler ranks below the tailed file's taken hint"
    );
    let mut index = index;
    let mut passes = Vec::new();
    for pass in 0..HOT_PASSES {
        hot_append(source, &tailed, 1 + pass, usage_row);
        sampled_scan::test_hooks::clear();
        let (run, counts) = observe(|| observed_scan(&tailed, source, index, &cache));
        index = run.index;
        let record = RegimePass {
            modes: run.modes,
            zero_budget_steps: run.tail_zero_budget_steps,
            counts,
            probe: sampled_scan::test_hooks::last_probe(),
            decisions: sampled_scan::test_hooks::decisions(),
            fillers_after: fillers_resident(&cache),
            retained_after: cache.retained_checkpoint(&tailed.key()).is_some(),
        };
        sampled_scan::test_hooks::clear();
        eprintln!(
            "CACHE_POLICY test=R0_regime_b_{label} state_bytes={POLICY_STATE_BYTES} resident_before={resident_before} filler_charge={filler_charge} pass={pass} modes={:?} tail_zero_budget_steps={} copy_refusal_admission_evicted={} copy_refusal_entries_evicted={} cursor_reservation_entries_evicted={} insert_entries_evicted={} retention_finalization_bound_refused={} clears={} fillers_after={} tail_retained_after={} probe={:?} decisions={:?}",
            record.modes,
            record.zero_budget_steps,
            counts.copy_refusal_admission_evicted,
            counts.copy_refusal_entries_evicted,
            counts.cursor_reservation_entries_evicted,
            counts.insert_entries_evicted,
            counts.retention_finalization_bound_refused,
            wipe_clears(&counts) + counts.clear_entries_released,
            record.fillers_after,
            record.retained_after,
            record.probe,
            record.decisions,
        );
        passes.push(record);
    }
    passes
}

/// What every regime-B pass must keep, whatever its outcome: one read of the
/// file, no wipe, no step-start evict-to-fit or cursor reservation, nothing
/// evicted by the insert, and fillers leaving only by R0's completion
/// release.
fn assert_regime_b_invariants(passes: &[RegimePass], label: &str) {
    let mut fillers = FILLERS;
    for (pass, record) in passes.iter().enumerate() {
        let counts = &record.counts;
        assert_eq!(
            record.modes.0 + record.modes.1,
            1,
            "{label} pass {pass}: one read"
        );
        assert_eq!(
            (
                wipe_clears(counts),
                counts.clear_entries_released,
                counts.copy_refusal_entries_evicted,
                counts.cursor_reservation_entries_evicted,
                counts.insert_entries_evicted,
            ),
            (0, 0, 0, 0, 0),
            "{label} pass {pass}"
        );
        assert_eq!(
            fillers - record.fillers_after,
            counts.copy_refusal_admission_evicted as usize,
            "{label} pass {pass}: fillers leave only by R0's release"
        );
        fillers = record.fillers_after;
    }
    assert!(
        passes[0].zero_budget_steps >= 1,
        "precondition: {label}: the first tail meets a zero copy budget"
    );
}

/// Diagnostic, not acceptance (parent ruling 2). Regime B, Claude, usage
/// appends: the hot-file model with idle fillers ranked below the tailed
/// file's taken hint, each pass appending a usage record. The outcome is a
/// receipt only (`CACHE_POLICY test=R0_regime_b_claude_usage`): M-a proves
/// the release with the tail's measured X_out, so the copy is kept when
/// `|P*| <= |P_C|` or `b_ins ≥ C`.
#[test]
fn cache_policy_r0_regime_b_claude_usage_tail_receipt() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("R0_regime_b_claude_usage") {
        return;
    }
    let passes = regime_b_hot(SnapshotSource::ClaudeCode, true, "claude_usage");
    assert_regime_b_invariants(&passes, "claude usage");
}

/// Diagnostic, not acceptance (parent ruling 2). Regime B, Claude,
/// ignored-line appends: R0's completion release replaces Path A. Every pass
/// reads a tail (0 Full), only fillers ranked below the copy's re-admission
/// rank leave, each by R0's release, and the copy is retained after every
/// pass.
#[test]
fn cache_policy_r0_regime_b_claude_ignored_tail_is_retained() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("R0_regime_b_claude_ignored") {
        return;
    }
    let passes = regime_b_hot(SnapshotSource::ClaudeCode, false, "claude_ignored");
    assert_regime_b_invariants(&passes, "claude ignored");
    assert_regime_b_retained(&passes, "claude ignored");
}

/// Diagnostic, not acceptance (parent ruling 2). Regime B, Codex, usage
/// appends: R0's completion release replaces Path A, as for the Claude
/// ignored-line tail.
#[test]
fn cache_policy_r0_regime_b_codex_tail_is_retained() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("R0_regime_b_codex") {
        return;
    }
    let passes = regime_b_hot(SnapshotSource::Codex, true, "codex_usage");
    assert_regime_b_invariants(&passes, "codex usage");
    assert_regime_b_retained(&passes, "codex usage");
}

/// 0 Full reads, a copy kept after every pass, and at least one filler
/// released by R0 (the room Path A made on main).
fn assert_regime_b_retained(passes: &[RegimePass], label: &str) {
    for (pass, record) in passes.iter().enumerate() {
        assert_eq!(record.modes, (0, 1, 0), "{label} pass {pass}: a tail");
        assert!(record.retained_after, "{label} pass {pass}: retained");
    }
    assert!(
        matches!(
            passes[0].decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Deferred { .. }]
        ),
        "{label}: the first pass defers a release {:?}",
        passes[0].decisions
    );
    assert!(
        passes[0].counts.copy_refusal_admission_evicted >= 1,
        "{label}: R0 released older fillers"
    );
}

/// Resident entries in victim order: key, admitted rank, stored bytes.
type Residents = Vec<(String, (i64, i64), usize)>;

fn residents(cache: &sampled_scan::SharedCache) -> Residents {
    cache.retained().expect("retained cache lock").victims()
}

/// One M-a control: what a single tail completion proved and released.
struct MaRun {
    modes: (usize, usize, usize),
    counts: Counts,
    probe: sampled_scan::test_hooks::Probe,
    decisions: Vec<sampled_scan::test_hooks::Decision>,
    before: Residents,
    after: Residents,
    tail_key: String,
    /// The tail's finished items.
    snapshots: Vec<SnapshotItem>,
    /// The shared cache's charge besides its retained entries (cursor state
    /// and side ledger), before and after the tail's scan.
    cursor_before: usize,
    cursor_after: usize,
}
impl MaRun {
    fn receipt(&self) -> String {
        format!(
            "modes={:?} probe={:?} decisions={:?} admission_evicted={} before={:?} after={:?}",
            self.modes,
            self.probe,
            self.decisions,
            self.counts.copy_refusal_admission_evicted,
            self.before,
            self.after
        )
    }
    fn resident(&self, key: &str) -> Option<(i64, i64)> {
        self.after
            .iter()
            .find(|(resident, _, _)| resident == key)
            .map(|(_, rank, _)| *rank)
    }
}

/// M-a controls at real scale (SS-3 (c)): main's full cache with the
/// fillers pinned at `fillers_modified` (regime B when older than the
/// tail), `extra` small Claude entries `(key, mtime)` beside them, then the
/// tailed file's padded append (a zero copy budget at its step starts),
/// stamped `tail_modified`, read as one tail with `x_out` in place of the
/// measured Claude bound (`x_out_for`). `touch_at_gate` restamps the file
/// after the proof, just before the deferred path's stamp gate.
fn m_a_tail(
    source: SnapshotSource,
    fillers_modified: u64,
    tail_modified: u64,
    extra: &[(&str, u64)],
    x_out: sampled_scan::XOut,
    touch_at_gate: Option<u64>,
) -> MaRun {
    m_a_tail_with(
        source,
        fillers_modified,
        tail_modified,
        extra,
        MaOpts {
            x_out: Some(x_out),
            touch_at_gate,
            ..MaOpts::default()
        },
    )
}

/// What an M-a control varies besides its ranks (review r32).
#[derive(Default)]
struct MaOpts {
    /// In place of the measured Claude X_out (`set_x_out`); `None` proves
    /// with the bound `x_out_for` measures, as production does.
    x_out: Option<sampled_scan::XOut>,
    touch_at_gate: Option<u64>,
    /// Re-admits the tailed file's entry reserving this finalization charge
    /// (`F_prev` at the next take).
    finalization_prev: Option<usize>,
    /// A Codex tail's append carries a usage record too (Claude's always
    /// does).
    codex_usage: bool,
    /// The appended usage record's `cwd`: the tail's workspace, first seen
    /// in this read (the full read before it has none).
    workspace: Option<String>,
    /// Runs after `retain_reduction`, before `finish`.
    after_retain: Option<Box<dyn FnMut()>>,
}

/// The shared cache's charge besides its retained entries.
fn cursor_charge(cache: &Arc<sampled_scan::SharedCache>) -> usize {
    let retained = crate::heap_layout_bound::bound(
        &*cache.retained().expect("retained cache lock"),
        usize::MAX,
    )
    .expect("bounded retained cache");
    optional_resident(cache) - retained
}

/// `m_a_tail` with `opts`.
fn m_a_tail_with(
    source: SnapshotSource,
    fillers_modified: u64,
    tail_modified: u64,
    extra: &[(&str, u64)],
    opts: MaOpts,
) -> MaRun {
    let MaOpts {
        x_out,
        touch_at_gate,
        finalization_prev,
        codex_usage,
        workspace,
        after_retain,
    } = opts;
    let FullCache {
        cache,
        tailed,
        index,
        ..
    } = full_cache_in(source, false, Some(fillers_modified));
    for (key, modified) in extra {
        let entry = ScanFixture::new(SnapshotSource::ClaudeCode);
        entry.append(&usage(SnapshotSource::ClaudeCode, 100, 0, MODEL));
        entry.set_modified(*modified);
        let retained = retained_reduction(&entry);
        assert!(
            cache
                .retained()
                .expect("retained cache lock")
                .insert((*key).to_string(), retained),
            "precondition: {key} is admitted"
        );
    }
    if let Some(charge) = finalization_prev {
        let mut retained = cache.retained().expect("retained cache lock");
        let taken = retained.take(&tailed.key()).expect("the tailed entry");
        assert!(
            retained.insert_reserving(tailed.key(), taken.retained, 0, charge),
            "precondition: the tailed entry is re-admitted"
        );
    }
    append_padding(&tailed);
    if source == SnapshotSource::ClaudeCode || codex_usage {
        let mut row = usage(source, 141, 1, MODEL);
        if let Some(workspace) = &workspace {
            row["cwd"] = json!(workspace);
        }
        tailed.append(&row);
    }
    tailed.set_modified(tail_modified);
    // The scan takes the tailed file's own entry first: never a victim.
    let tail_key = tailed.key();
    let before: Residents = residents(&cache)
        .into_iter()
        .filter(|(key, _, _)| *key != tail_key)
        .collect();
    sampled_scan::test_hooks::clear();
    sampled_scan::test_hooks::set_x_out(x_out);
    if let Some(hook) = after_retain {
        sampled_scan::test_hooks::set(sampled_scan::test_hooks::Point::AfterRetain, hook);
    }
    if let Some(modified) = touch_at_gate {
        let path = tailed.path.clone();
        sampled_scan::test_hooks::set(
            sampled_scan::test_hooks::Point::BeforeStampGate,
            move || {
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_times(
                        fs::FileTimes::new()
                            .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(modified)),
                    )
                    .unwrap();
            },
        );
    }
    let cursor_before = cursor_charge(&cache);
    let (tail, counts) = observe(|| observed_scan(&tailed, source, index, &cache));
    let run = MaRun {
        modes: tail.modes,
        counts,
        probe: sampled_scan::test_hooks::last_probe(),
        decisions: sampled_scan::test_hooks::decisions(),
        before,
        after: residents(&cache),
        tail_key,
        snapshots: tail.snapshots,
        cursor_before,
        cursor_after: cursor_charge(&cache),
    };
    sampled_scan::test_hooks::clear();
    eprintln!("CACHE_POLICY M-a {source:?} {}", run.receipt());
    assert_eq!(
        run.modes,
        (0, 1, 0),
        "precondition: a tail; {}",
        run.receipt()
    );
    run
}

/// No mutation besides the tail's own copy: every entry resident before is
/// resident after, at its rank.
fn assert_no_victims(run: &MaRun, label: &str) {
    let receipt = run.receipt();
    assert_eq!(
        (
            run.counts.copy_refusal_admission_evicted,
            run.counts.copy_refusal_entries_evicted,
            run.counts.cursor_reservation_entries_evicted,
            run.counts.insert_entries_evicted,
            run.counts.clear_entries_released,
            wipe_clears(&run.counts),
        ),
        (0, 0, 0, 0, 0, 0),
        "{label}: zero victims; {receipt}"
    );
    for (key, rank, _) in &run.before {
        assert_eq!(
            run.resident(key),
            Some(*rank),
            "{label}: {key} stays; {receipt}"
        );
    }
}

/// M-a T2: a Claude completion without an owned X_out (`Refused`), or with
/// one whose checked arithmetic overflows, releases nothing: the copy is
/// refused at its pre-release budget and every resident stays.
#[test]
fn cache_policy_m_a_unknown_or_overflowing_x_out_releases_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T2") {
        return;
    }
    let now = unix_now();
    for x_out in [
        sampled_scan::XOut::Refused,
        sampled_scan::XOut::Bound(usize::MAX),
    ] {
        let run = m_a_tail(
            SnapshotSource::ClaudeCode,
            now - OLD_SECONDS,
            now - 600,
            &[],
            x_out,
            None,
        );
        assert_no_victims(&run, &format!("{x_out:?}"));
        assert!(
            matches!(
                run.decisions.as_slice(),
                [sampled_scan::test_hooks::Decision::Granted { .. }]
            ),
            "{x_out:?}: no release is deferred; {}",
            run.receipt()
        );
        assert!(
            run.resident(&run.tail_key).is_none(),
            "{x_out:?}: the tail's copy does not fit without a release; {}",
            run.receipt()
        );
    }
}

/// Every copy-refusal count (the corrected M1 (ii) row's sum).
fn refusals(counts: &Counts) -> u64 {
    counts.retention_bound_refused
        + counts.retention_clone_bound_refused
        + counts.retention_finalization_bound_refused
        + counts.insert_live_reservation_refused
        + counts.insert_entry_bound_refused
        + counts.insert_frozen_charge_refused
        + counts.insert_no_victim_refused
}

/// The keys a proven release must evict, derived from the fixture's stored
/// charges alone (fresh-r2 R2-3): the shortest victim-order prefix of the
/// entries ranked strictly below the copy's rank whose freed bytes cover
/// `need'`. `need'` must sit at least `MARGIN` from either end of that
/// prefix's last entry (a non-boundary target), so the execute room's few
/// hundred bytes (N5 (a)) cannot move the count.
fn expected_victims(run: &MaRun) -> Vec<String> {
    // At 99f72169 the measured companion's need' (13,428,400) sits 370,784 B
    // below the two-filler prefix's 13,799,184: 108,640 B of need' beyond
    // this margin, so about 54 KB of X_out headroom (need' grows by twice
    // X_out). K/U growth past that trips this precondition loudly; then
    // recalibrate the filler sizes, not the margin.
    const MARGIN: usize = 256 * 1024;
    let receipt = run.receipt();
    let rank = run.probe.rank.expect("the copy's rank");
    let need = run.probe.need_prime.expect("need' was measured");
    let mut freed = 0usize;
    let mut keys = Vec::new();
    for (key, _, bytes) in run.before.iter().filter(|(_, hint, _)| *hint < rank) {
        if freed >= need {
            break;
        }
        assert!(
            freed + MARGIN <= need,
            "precondition: need' is not at a prefix boundary; {receipt}"
        );
        freed += bytes;
        keys.push(key.clone());
    }
    assert!(
        freed >= need + MARGIN,
        "precondition: the older entries cover need' with margin; {receipt}"
    );
    keys
}

/// T8's release: `|P*| = |P_C|`, and exactly the derived prefix leaves, by
/// the release only; the copy is retained at its proof's rank, and the
/// entries at and above that rank stay.
fn assert_exact_prefix_release(run: &MaRun, label: &str) {
    let receipt = run.receipt();
    let (victims, copy_only) = run.probe.prefixes.expect("the prefixes were measured");
    let expected = expected_victims(run);
    let left: Vec<String> = run
        .before
        .iter()
        .filter(|(key, _, _)| run.resident(key).is_none())
        .map(|(key, _, _)| key.clone())
        .collect();
    eprintln!(
        "CACHE_POLICY test=M_a_T8 case={label} x_out={:?} C={:?} peak={:?} need_prime={:?} need_c={:?} prefixes={:?} expected_victims={expected:?} left={left:?}",
        run.probe.x_out,
        run.probe.clone,
        run.probe.peak,
        run.probe.need_prime,
        run.probe.need_c,
        run.probe.prefixes,
    );
    assert_eq!(victims, copy_only, "{label}: |P*| = |P_C|; {receipt}");
    assert_eq!(
        expected.len(),
        copy_only,
        "{label}: the derived prefix is P_C; {receipt}"
    );
    assert_eq!(
        left, expected,
        "{label}: exactly that prefix leaves; {receipt}"
    );
    assert_eq!(
        run.counts.copy_refusal_admission_evicted as usize,
        expected.len(),
        "{label}: by the release only; {receipt}"
    );
    let rank = run.probe.rank.expect("the copy's rank");
    assert!(run.resident("cache-policy-equal").is_some(), "{receipt}");
    assert!(run.resident("cache-policy-newer").is_some(), "{receipt}");
    assert_eq!(
        run.resident(&run.tail_key),
        Some(rank),
        "{label}: the copy is retained at its proof's rank; {receipt}"
    );
    assert_eq!(
        (
            run.counts.copy_refusal_entries_evicted,
            run.counts.insert_entries_evicted,
            wipe_clears(&run.counts),
        ),
        (0, 0, 0),
        "{label}: {receipt}"
    );
}

/// The T8 fixture: two entries at and above the copy's rank beside the
/// fillers.
fn m_a_t8(x_out: Option<sampled_scan::XOut>) -> MaRun {
    let now = unix_now();
    let tail_modified = now - 600;
    m_a_tail_with(
        SnapshotSource::ClaudeCode,
        now - OLD_SECONDS,
        tail_modified,
        &[
            ("cache-policy-equal", tail_modified),
            ("cache-policy-newer", tail_modified + 300),
        ],
        MaOpts {
            x_out,
            ..MaOpts::default()
        },
    )
}

/// M-a T8, the positive provable-fit control, at the policy seam: an X_out
/// within the clone's bound (`Bound(0)`, so `K' = C`) proves
/// `|P*| = |P_C|`, so exactly the copy-only prefix of strictly older
/// fillers leaves (its keys derived from the stored charges, R2-3) and the
/// copy is retained. An entry at the copy's rank and a newer one stay.
#[test]
fn cache_policy_m_a_provable_fit_releases_exactly_the_copy_only_prefix() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T8") {
        return;
    }
    let run = m_a_t8(Some(sampled_scan::XOut::Bound(0)));
    assert_eq!(run.probe.x_out, Some(0), "{}", run.receipt());
    assert_exact_prefix_release(&run, "bound-0");
}

/// T8's measured companion (R2-3): the same fixture proving with the X_out
/// `x_out_for` measures (no `set_x_out`), as production does. Its X_out
/// headroom against `expected_victims`' `MARGIN` is about 54 KB (see there).
#[test]
fn cache_policy_m_a_measured_x_out_releases_exactly_the_copy_only_prefix() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T8_measured") {
        return;
    }
    let run = m_a_t8(None);
    let x_out = run.probe.x_out.expect("a measured X_out");
    assert!(x_out > 0, "{}", run.receipt());
    assert_exact_prefix_release(&run, "measured");
}

/// R2-1's finite X_out: past the clone's bound by enough that `need'`
/// needs one filler more than `need_C` (about 17.1 MB against 12.2 MB, with
/// fillers of about 6.9 MB, in CI's receipts).
const CHURN_X_OUT: usize = 2_500_000;

/// M-a churn negative control (fresh-r2 R2-1) at real scale: a finite,
/// owned X_out whose `need'` takes more victims than the copy alone needs
/// (`|P*| > |P_C|`, asserted first) releases nothing. No release is
/// deferred, nothing leaves, no copy is retained, every resident keeps its
/// rank, the cache's cursor charge is unchanged (this Claude fixture holds
/// no suspended Codex proof), and the refusal is counted.
#[test]
fn cache_policy_m_a_churn_bound_refuses_a_finite_x_out() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_churn") {
        return;
    }
    let now = unix_now();
    let run = m_a_tail_with(
        SnapshotSource::ClaudeCode,
        now - OLD_SECONDS,
        now - 600,
        &[],
        MaOpts {
            x_out: Some(sampled_scan::XOut::Bound(CHURN_X_OUT)),
            ..MaOpts::default()
        },
    );
    let receipt = run.receipt();
    let probe = run.probe;
    eprintln!(
        "CACHE_POLICY test=M_a_churn x_out={CHURN_X_OUT} C={:?} peak={:?} A={} remaining={} need_c={:?} need_prime={:?} prefixes={:?} refusals={} cursor_before={} cursor_after={}",
        probe.clone,
        probe.peak,
        probe.a,
        probe.remaining,
        probe.need_c,
        probe.need_prime,
        probe.prefixes,
        refusals(&run.counts),
        run.cursor_before,
        run.cursor_after,
    );
    let (victims, copy_only) = probe.prefixes.expect("the prefixes were measured");
    assert!(victims > copy_only, "precondition: |P*| > |P_C|; {receipt}");
    assert_eq!(probe.x_out, Some(CHURN_X_OUT), "{receipt}");
    assert!(
        matches!(
            run.decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Granted { .. }]
        ),
        "no release is deferred; {receipt}"
    );
    assert_no_victims(&run, "churn");
    assert!(
        run.resident(&run.tail_key).is_none(),
        "no copy is retained; {receipt}"
    );
    assert_eq!(run.cursor_after, run.cursor_before, "{receipt}");
    assert!(
        refusals(&run.counts) >= 1,
        "the refusal is counted; {receipt}"
    );
}

/// M-a T9 (parent ruling 1), equal rank: fillers stamped at the copy's own
/// rank are never victims, so a provable X_out still releases nothing.
#[test]
fn cache_policy_m_a_equal_rank_is_never_a_victim() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T9_equal") {
        return;
    }
    let tail_modified = unix_now() - 600;
    let run = m_a_tail(
        SnapshotSource::ClaudeCode,
        tail_modified,
        tail_modified,
        &[],
        sampled_scan::XOut::Bound(0),
        None,
    );
    assert_eq!(run.probe.rank, Some((tail_modified as i64, 0)));
    assert_no_victims(&run, "equal rank");
}

/// M-a T9, a future mtime is clipped once, and the rank agrees across
/// proof, release and insert: the copy is admitted at exactly the clipped
/// rank its release ranked residents against.
#[test]
fn cache_policy_m_a_future_mtime_is_clipped_once_and_ranks_agree() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T9_future") {
        return;
    }
    let now = unix_now();
    let run = m_a_tail(
        SnapshotSource::ClaudeCode,
        now - OLD_SECONDS,
        now + 3600,
        &[],
        sampled_scan::XOut::Bound(0),
        None,
    );
    let receipt = run.receipt();
    let rank = run.probe.rank.expect("the copy's rank");
    assert!(
        rank.0 >= now as i64 && rank < ((now + 3600) as i64, 0),
        "clipped to the admission clock; {receipt}"
    );
    assert!(
        run.counts.copy_refusal_admission_evicted >= 1,
        "the release ran; {receipt}"
    );
    assert_eq!(
        run.resident(&run.tail_key),
        Some(rank),
        "admitted at the proof's rank, not a later clock; {receipt}"
    );
    assert!(
        run.before
            .iter()
            .filter(|(key, _, _)| run.resident(key).is_none())
            .all(|(_, hint, _)| *hint < rank),
        "{receipt}"
    );
}

/// M-a T9, a failed gate mutates nothing: the file changes after the proof,
/// so the stamp gate declines and the deferred release never runs.
#[test]
fn cache_policy_m_a_failed_gate_releases_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T9_gate") {
        return;
    }
    let now = unix_now();
    let tail_modified = now - 600;
    let run = m_a_tail(
        SnapshotSource::ClaudeCode,
        now - OLD_SECONDS,
        tail_modified,
        &[],
        sampled_scan::XOut::Bound(0),
        Some(tail_modified + 7),
    );
    assert!(
        matches!(
            run.decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Deferred { .. }]
        ),
        "precondition: the proof deferred a release; {}",
        run.receipt()
    );
    assert_no_victims(&run, "failed stamp gate");
}

/// M-a T10, Codex's explicit residual (ruling 5): a Codex completion keeps
/// `K = max(C, F_prev)` and the Q-PR15 guard whatever X_out says; M-a's
/// proof never runs for it.
#[test]
fn cache_policy_m_a_codex_keeps_the_legacy_release() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T10") {
        return;
    }
    let now = unix_now();
    let run = m_a_tail(
        SnapshotSource::Codex,
        now - OLD_SECONDS,
        now - 600,
        &[],
        sampled_scan::XOut::Refused,
        None,
    );
    let receipt = run.receipt();
    assert_eq!(run.probe.x_out, None, "no M-a proof; {receipt}");
    assert!(
        matches!(
            run.decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Deferred { .. }]
        ),
        "the legacy release is deferred; {receipt}"
    );
    assert!(
        run.counts.copy_refusal_admission_evicted >= 1,
        "and runs; {receipt}"
    );
}

/// A workspace path no other test uses: the repository-identity cache is
/// process-global.
fn unique_workspace(tag: &str) -> String {
    format!(
        "/cache-policy-u3/{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, AtomicOrdering::Relaxed)
    )
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

/// X_out U3 through the scan (fresh-r2 R2-2, fresh-r1 N2), cold: the tail's
/// append first names its workspace (`cwd`), whose repository identity is
/// not in the cache, so `x_out_for` measures no X_out (no `set_x_out`) and
/// the release proof refuses: zero victims, no copy retained, every filler
/// at its rank, the refusal counted.
#[test]
fn cache_policy_m_a_cold_repository_identity_releases_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_U3_cold") {
        return;
    }
    let now = unix_now();
    let workspace = unique_workspace("cold");
    assert_eq!(
        peek_repository_identity(Path::new(&workspace)),
        None,
        "precondition: cold"
    );
    let run = m_a_tail_with(
        SnapshotSource::ClaudeCode,
        now - OLD_SECONDS,
        now - 600,
        &[],
        MaOpts {
            workspace: Some(workspace),
            ..MaOpts::default()
        },
    );
    let receipt = run.receipt();
    eprintln!(
        "CACHE_POLICY test=M_a_U3_cold refusals={} items={} {receipt}",
        refusals(&run.counts),
        run.snapshots.len()
    );
    let [item] = run.snapshots.as_slice() else {
        panic!("precondition: one finished item; {receipt}");
    };
    assert!(
        item.workspace_hash.is_some(),
        "precondition: the tail read its workspace; {receipt}"
    );
    assert!(
        run.probe.rank.is_some(),
        "precondition: a release proof reached X_out; {receipt}"
    );
    assert_eq!(
        run.probe.x_out, None,
        "a cold identity has no X_out; {receipt}"
    );
    assert!(
        matches!(
            run.decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Granted { .. }]
        ),
        "no release is deferred; {receipt}"
    );
    assert_no_victims(&run, "cold U3");
    assert!(
        run.resident(&run.tail_key).is_none(),
        "no copy is retained; {receipt}"
    );
    assert!(
        refusals(&run.counts) >= 1,
        "the refusal is counted; {receipt}"
    );
}

/// X_out U3 through the scan, warm: the identity peeked for X_out is the one
/// the finished item carries. The release runs on the measured X_out; the
/// cache entry is then replaced between the proof and `finish`
/// (`Point::AfterRetain`), and the item still carries the peeked identity,
/// not a re-resolved or re-read one.
#[test]
fn cache_policy_m_a_warm_repository_identity_is_the_finished_one() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_U3_warm") {
        return;
    }
    let now = unix_now();
    let workspace = unique_workspace("warm");
    let path = PathBuf::from(&workspace);
    repository_identity_cache()
        .lock()
        .unwrap()
        .insert(path.clone(), (SystemTime::now(), u3_identity("warm")));
    let replace = path.clone();
    let run = m_a_tail_with(
        SnapshotSource::ClaudeCode,
        now - OLD_SECONDS,
        now - 600,
        &[],
        MaOpts {
            workspace: Some(workspace),
            after_retain: Some(Box::new(move || {
                repository_identity_cache().lock().unwrap().insert(
                    replace.clone(),
                    (SystemTime::now(), u3_identity("replaced")),
                );
            })),
            ..MaOpts::default()
        },
    );
    let receipt = run.receipt();
    let [item] = run.snapshots.as_slice() else {
        panic!("precondition: one finished item; {receipt}");
    };
    eprintln!(
        "CACHE_POLICY test=M_a_U3_warm repository_hash={:?} cache_after={:?} {receipt}",
        item.repository_hash,
        peek_repository_identity(&path).and_then(|identity| identity.repository_hash),
    );
    assert!(
        run.probe.x_out.is_some(),
        "a warm identity proves with a measured X_out; {receipt}"
    );
    assert!(
        matches!(
            run.decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Deferred { .. }]
        ),
        "the release is deferred; {receipt}"
    );
    assert!(
        run.counts.copy_refusal_admission_evicted >= 1,
        "and runs; {receipt}"
    );
    assert_eq!(
        run.resident(&run.tail_key),
        run.probe.rank,
        "the copy is retained; {receipt}"
    );
    assert_eq!(
        peek_repository_identity(&path),
        Some(u3_identity("replaced")),
        "precondition: the entry was replaced between proof and finish"
    );
    assert_eq!(
        (
            item.repository_hash.as_deref(),
            item.repository_label.as_deref()
        ),
        (Some("hash-warm"), Some("label-warm")),
        "the item carries the peeked identity; {receipt}"
    );
}

/// M-a T10's refusal arm (fresh-r2 R2-4): a Codex completion whose
/// `F_prev` exceeds its clone's bound and whose read added usage meets
/// Q-PR15's guard under release pressure: zero victims and no deferred
/// release. T10 keeps the positive row (`F_prev < C`).
#[test]
fn cache_policy_m_a_codex_finalization_guard_releases_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if unexecuted("M_a_T10_guard") {
        return;
    }
    const F_PREV: usize = 1_000_000;
    let now = unix_now();
    let run = m_a_tail_with(
        SnapshotSource::Codex,
        now - OLD_SECONDS,
        now - 600,
        &[],
        MaOpts {
            x_out: Some(sampled_scan::XOut::Refused),
            finalization_prev: Some(F_PREV),
            codex_usage: true,
            ..MaOpts::default()
        },
    );
    let receipt = run.receipt();
    let probe = run.probe;
    assert_eq!(probe.finalization_prev, F_PREV, "precondition: {receipt}");
    assert!(
        probe.clone.is_some_and(|clone| clone < F_PREV),
        "precondition: F_prev > C; {receipt}"
    );
    assert!(
        probe.need.is_some_and(|need| need > 0),
        "precondition: release pressure; {receipt}"
    );
    assert_eq!(probe.x_out, None, "no M-a proof; {receipt}");
    assert!(
        probe.finalization_guard,
        "the guard branch was reached; {receipt}"
    );
    assert!(
        matches!(
            run.decisions.as_slice(),
            [sampled_scan::test_hooks::Decision::Granted { .. }]
        ),
        "no release is deferred; {receipt}"
    );
    assert_no_victims(&run, "codex guard");
}
