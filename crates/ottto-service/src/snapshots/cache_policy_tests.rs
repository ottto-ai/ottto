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
/// 85% of it, as four 1,400-response reductions did before compact Claude
/// records (#653 T3: 27,664,691 B, 6,887,051 B each), leaving about 4.8 MB.
/// `filler_records` sizes the filler file from measured charges, so a change
/// to the per-response charge cannot leave the zero-budget steps unreached.
const FILLER_STATE_PERMILLE: usize = 212;
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

/// M1 test (ii), evict only the overflow (design §6 row M1; §2 L1).
///
/// The same full cache, but the tailed file's append is
/// `tail_growth_records` ordinary responses. The borrowed tail state grows
/// past the room the fillers leave: a real overflow of the state budget, not
/// a merely full cache. Desired: no wipe-all clear. The zero-budget step
/// start evicts in victim order until the tail fits; the grown state stays
/// below one filler's charge, so that is at most one filler.
///
/// Restated for Path A, the intended behavior (owner-accepted; review §3c):
/// the fillers are older than the tailed file, so the same step then evicts
/// older fillers until the tail's own copy would fit its next step's budget
/// at that step's charge (its walk plus twice its charge, about three times
/// the room one filler leaves): two fillers in all, "at most the overflow
/// plus the copy's admission room". Round 1 expected exactly one. The tail
/// keeps growing after that step, so its copy may still be refused at
/// completion; this test pins the eviction bound only.
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
        FILLERS - 2,
        "M1: the overflow and the copy's room did not release exactly two entries; {receipt}"
    );
    assert_eq!(
        run.counts.cursor_reservation_entries_evicted, 0,
        "M1: a copy refusal eviction was counted as a cursor reservation; {receipt}"
    );
}

/// A cached scan of the full cache's file, stepped until its append is the
/// active sampled tail (holding its borrowed entry). `older_tail` keeps the
/// file's mtime two days back after the append, below every filler's rank,
/// so Path A has no older entry to evict.
fn tail_active(full: &FullCache, older_tail: bool) -> OwnedSourceScan {
    let source = SnapshotSource::ClaudeCode;
    full.tailed.append(&usage(source, 140, 1, MODEL));
    if older_tail {
        full.tailed.set_modified(unix_now() - OLD_SECONDS + 1);
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
    if unexecuted("M1_decision_matrix") {
        return;
    }
    let full = full_cache_with_retained_file(true);
    let scan = tail_active(&full, true);
    let cache = &full.cache;
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
    if unexecuted("M1_counters") {
        return;
    }
    let full = full_cache_with_retained_file(true);
    let scan = tail_active(&full, true);
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
    if unexecuted("M1_visit_limit") {
        return;
    }
    let full = full_cache_with_retained_file(true);
    let mut scan = tail_active(&full, true);
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
