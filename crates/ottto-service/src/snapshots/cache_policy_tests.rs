//! Red-first cache-policy regression harness (Slice M design report §5c and
//! §6, slice M0). Each test drives the real production scan step loop against
//! one shared transcript cache and asserts the DESIRED retention policy, so it
//! fails on main for the reason its doc comment names. Preconditions are
//! asserted first, so a setup failure cannot pass as the defect. Fixtures are
//! synthetic. The helpers are copied from `transcript_acquisition_tests` and
//! the #653 retention baseline, so this module registers on its own.
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
/// About 3.5 MB charged per retained reduction (about 4.96 KB per response,
/// measured in CI), so five or six entries cycle through the cache. That
/// fill leaves less room than one 16 MiB JSONL line, so the Codex page below
/// can meet a zero copy budget.
const GROWING_RECORDS: usize = 700;
const GROWING_FILES: usize = 12;
const ROUNDS: usize = 3;
/// Four 1,400-response reductions (#653 T3: 27,664,691 B) fill the state
/// budget to within a few MB without any eviction.
const FILLERS: usize = 4;
const FILLER_RECORDS: usize = 1400;
/// One appended record this long leaves the tail parser's line buffer at
/// least this capacity at its next step start: more than the room the
/// filled cache leaves, so the copy budget beside the tail is zero.
const TAIL_PADDING_BYTES: usize = 8 * 1024 * 1024;
const WARM_RECORDS: usize = 600;
const WARM_FILES: usize = 4;
const COLD_RECORDS: usize = 200;
const COLD_FILES: usize = 50;
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
    result: SourceScanResult,
    modes: (usize, usize, usize),
    full_reasons: [usize; 11],
    /// Step starts whose active file is a plain native parse (no sampled
    /// acquisition, cursor or group job) and whose copy budget is zero.
    unsampled_zero_budget_steps: usize,
    /// Step starts whose active file is a sampled tail (it holds borrowed
    /// retained state) and whose copy budget is zero.
    tail_zero_budget_steps: usize,
}
impl Observed {
    fn state_missing(&self) -> usize {
        self.full_reasons[FullReason::StateMissing.slot()]
    }
}

fn observed_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: Option<&Arc<sampled_scan::SharedCache>>,
    state_census_incomplete: bool,
) -> Observed {
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
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache.clone(), Scope(NAMESPACE.into()));
    }
    if state_census_incomplete {
        scan.state_census_complete = false;
    }
    let mut modes = (0, 0, 0);
    let mut full_reasons = [0; 11];
    let mut unsampled_zero_budget_steps = 0;
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
        // Some(true): a sampled tail; Some(false): a plain native parse.
        let watched = scan.active_file.as_deref().and_then(|active| {
            if active.cursor.is_some() || active.group.is_some() {
                return None;
            }
            match active.sampling.as_ref() {
                None => Some(false),
                Some(sampling) => (sampling.mode == ReadMode::Tail).then_some(true),
            }
        });
        if let Some(tail) = watched.filter(|_| scan.sampling.is_some()) {
            if scan.sampled_copy_budget() == 0 {
                if tail {
                    tail_zero_budget_steps += 1;
                } else {
                    unsampled_zero_budget_steps += 1;
                }
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
                return Observed {
                    index,
                    result,
                    modes,
                    full_reasons,
                    unsampled_zero_budget_steps,
                    tail_zero_budget_steps,
                };
            }
        }
    }
}

fn production_body(source: SnapshotSource, mut scan: SourceScanResult) -> Value {
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    serde_json::to_value(scan.snapshots).unwrap()
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

/// Outcome of a sampled tail read at a zero copy budget beside a full cache.
struct TailBesideFullCache {
    resident_before: usize,
    tail: Observed,
    counts: Counts,
    fillers_after: usize,
    tail_retained_after: bool,
}

/// Retain one small Claude file, fill the shared cache with `FILLERS` real
/// reductions, then append a long record and one usage record to the file and
/// read the append as a tail. The long record's line buffer meets a zero copy
/// budget at the next step start; the borrowed state itself is tiny and
/// fitted beside the fillers. `older_tail` pins the tailed file's mtime two
/// days back, below every filler's rank.
fn tail_beside_full_cache(older_tail: bool) -> TailBesideFullCache {
    let source = SnapshotSource::ClaudeCode;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let old = unix_now() - OLD_SECONDS;
    let tailed = ScanFixture::new(source);
    tailed.append(&usage(source, 100, 0, MODEL));
    if older_tail {
        tailed.set_modified(old);
    }
    let full = observed_scan(&tailed, source, ScanIndex::default(), Some(&cache), false);
    assert_eq!(full.modes, (1, 0, 0));
    assert_eq!(full.state_missing(), 1);
    assert!(
        cache.retained_checkpoint(&tailed.key()).is_some(),
        "precondition: the first read is retained"
    );
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
    tailed.append(&json!({
        "type": "synthetic-padding",
        "text": "x".repeat(TAIL_PADDING_BYTES),
    }));
    tailed.append(&usage(source, 140, 1, MODEL));
    if older_tail {
        tailed.set_modified(old + 1);
    }
    let (tail, counts) =
        observe(|| observed_scan(&tailed, source, full.index, Some(&cache), false));
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
        fillers_after: fillers_resident(&cache),
        tail_retained_after: cache.retained_checkpoint(&tailed.key()).is_some(),
        tail,
        counts,
    }
}

/// G1, degrade gracefully (design §5c G1; §2 L1 and L5; §6 rows M0, M1, M2).
///
/// Twelve growing Claude sessions of 700 responses each, sized so five or six
/// cycle through the 31 MiB state budget (design §4a). Round 0 reads every
/// file for the first time in creation order, so the first-seen sessions fill
/// the cache. `capacity` is the count that round admits, which is the most an
/// empty cache admits beside one active read of this size. Then three rounds of "append to
/// every file (oldest first), then scan each (newest first)", with a
/// census-incomplete Codex page before each round. Its unsampled active meets
/// a zero copy budget (since #654 it must not wipe). Desired:
/// - no wipe-all clear;
/// - after every round the `capacity - 1` or more most recently appended
///   files are the resident ones;
/// - at least `capacity - 1` tails in rounds 2 and 3 (round 1 hands the cache
///   over from the first-seen files to the newest ones);
/// - the whole optional cache within the state budget at every page end;
/// - output byte-equal to a cacheless control.
///
/// Red on main: fill-and-freeze (L5). Admission never evicts, so the
/// first-seen files `0..capacity` stay resident in every round. The most recently
/// appended files are refused (`retention_bound_refused`) and reread
/// `Full(StateMissing)` every round.
#[test]
fn cache_policy_g1_growing_sessions_over_capacity_degrade_gracefully() {
    if unexecuted("G1_degrade_gracefully") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let files = (0..GROWING_FILES)
        .map(|_| ScanFixture::new(source))
        .collect::<Vec<_>>();
    let keys = files.iter().map(ScanFixture::key).collect::<Vec<_>>();
    // Warm, strictly ordered mtimes: file i of round r at base + 100r + i.
    let base = unix_now() - 1800;
    for (number, file) in files.iter().enumerate() {
        file.append_usage(source, 0..GROWING_RECORDS);
        file.set_modified(base + number as u64);
    }
    let mut indexes = files
        .iter()
        .map(|_| ScanIndex::default())
        .collect::<Vec<_>>();
    let resident_keys = |cache: &Arc<sampled_scan::SharedCache>| {
        keys.iter()
            .enumerate()
            .filter(|(_, key)| cache.retained_checkpoint(key).is_some())
            .map(|(number, _)| number)
            .collect::<Vec<_>>()
    };
    let mut max_resident = 0;
    let scan_round = |indexes: &mut [ScanIndex], max_resident: &mut usize, newest_first: bool| {
        let mut results = files.iter().map(|_| None).collect::<Vec<_>>();
        let mut order = (0..GROWING_FILES).collect::<Vec<_>>();
        if newest_first {
            order.reverse();
        }
        for number in order {
            let mut observed = observed_scan(
                &files[number],
                source,
                std::mem::take(&mut indexes[number]),
                Some(&cache),
                false,
            );
            *max_resident = (*max_resident).max(optional_resident(&cache));
            indexes[number] = std::mem::take(&mut observed.index);
            results[number] = Some(observed);
        }
        results.into_iter().map(Option::unwrap).collect::<Vec<_>>()
    };

    // Round 0: every file's first read, in creation order.
    let (first, first_counts) = observe(|| scan_round(&mut indexes[..], &mut max_resident, false));
    for observed in &first {
        assert_eq!(observed.modes, (1, 0, 0), "precondition: first reads");
        assert_eq!(observed.state_missing(), 1);
    }
    assert_eq!(
        wipe_clears(&first_counts),
        0,
        "precondition: no first-read wipe"
    );
    let first_resident = resident_keys(&cache);
    assert!(
        !first_resident.is_empty(),
        "precondition: the first reads retain some files"
    );
    let entry_bytes = cache
        .retained()
        .expect("retained cache lock")
        .resident_bound()
        .expect("bounded resident state")
        / first_resident.len();
    let capacity = first_resident.len();
    assert!(
        (3..=6).contains(&capacity),
        "precondition: a handful of entries cycle (entry_bytes={entry_bytes} capacity={capacity})"
    );

    let mut receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} entry_bytes={entry_bytes} capacity={capacity} round0_resident={first_resident:?}"
    );
    let mut wipes = 0;
    let mut round_tails = Vec::new();
    let mut round_resident = Vec::new();
    let mut last = Vec::new();
    for round in 1..=ROUNDS {
        // The Codex page's one long record must exceed the room the cache
        // leaves now, within the 16 MiB JSONL line bound.
        let padding = POLICY_STATE_BYTES.saturating_sub(optional_resident(&cache)) + 1024 * 1024;
        assert!(
            padding < MAX_JSONL_LINE_BYTES - 64 * 1024,
            "precondition: the Codex padding fits one JSONL line (padding={padding}); {receipt}"
        );
        let codex = ScanFixture::new(SnapshotSource::Codex);
        codex.append(&usage(SnapshotSource::Codex, 100, 0, MODEL));
        codex.append(&json!({"type": "synthetic-padding", "text": "x".repeat(padding)}));
        codex.append(&usage(SnapshotSource::Codex, 140, 1, MODEL));
        let (page, page_counts) = observe(|| {
            observed_scan(
                &codex,
                SnapshotSource::Codex,
                ScanIndex::default(),
                Some(&cache),
                true,
            )
        });
        assert!(!page.result.state_census_complete);
        assert_eq!(
            page.modes,
            (0, 0, 0),
            "precondition: no Codex read is sampled"
        );
        assert_eq!(page_counts.take_hit, 0, "precondition: no borrowed state");
        assert!(
            page.unsampled_zero_budget_steps >= 1,
            "precondition: the Codex page meets a zero copy budget"
        );
        max_resident = max_resident.max(optional_resident(&cache));
        for (number, file) in files.iter().enumerate() {
            let id = GROWING_RECORDS + round;
            file.append(&usage(source, 100 + id as u64, id, MODEL));
            file.set_modified(base + 100 * round as u64 + number as u64);
        }
        let (scans, counts) = observe(|| scan_round(&mut indexes[..], &mut max_resident, true));
        for observed in &scans {
            assert_eq!(observed.modes.2, 0, "precondition: no unchanged reads");
            assert_eq!(observed.modes.0 + observed.modes.1, 1);
        }
        let tails = scans.iter().map(|observed| observed.modes.1).sum::<usize>();
        let resident = resident_keys(&cache);
        let round_wipes = wipe_clears(&page_counts) + wipe_clears(&counts);
        wipes += round_wipes;
        receipt.push_str(&format!(
            " round{round}:codex_padding={padding} codex_clear_other_active={} codex_clear_entries_released={} wipes={round_wipes} tails={tails} state_missing={} resident={resident:?}",
            page_counts.clear_other_active,
            page_counts.clear_entries_released,
            scans.iter().map(Observed::state_missing).sum::<usize>(),
        ));
        round_tails.push(tails);
        round_resident.push(resident);
        last = scans;
    }
    receipt.push_str(&format!(" max_optional_resident={max_resident}"));
    eprintln!("CACHE_POLICY test=G1_degrade_gracefully {receipt}");

    assert_eq!(
        wipes, 0,
        "G1: no wipe-all clear while the cache is merely full; {receipt}"
    );
    for (round, resident) in round_resident.iter().enumerate() {
        let newest = (GROWING_FILES - resident.len()..GROWING_FILES).collect::<Vec<_>>();
        assert!(
            resident.len() + 1 >= capacity && *resident == newest,
            "G1: round {} resident files are not the {} or more most recently appended; {receipt}",
            round + 1,
            capacity - 1
        );
    }
    for (round, tails) in round_tails.iter().enumerate().skip(1) {
        assert!(
            *tails + 1 >= capacity,
            "G1: round {} tails {tails} < capacity - 1; {receipt}",
            round + 1
        );
    }
    assert!(
        max_resident <= POLICY_STATE_BYTES,
        "G1: optional cache over the state budget at a page end; {receipt}"
    );
    for (number, observed) in last.into_iter().enumerate() {
        let control = observed_scan(&files[number], source, ScanIndex::default(), None, false);
        assert_eq!(
            production_body(source, observed.result),
            production_body(source, control.result),
            "G1: file {number} output differs from the cacheless control"
        );
    }
}

/// G2, cold flood (design §5c G2; §3a warm/cold gate; §6 rows M2, M3).
///
/// Four warm sessions (600 responses, current mtime) are retained through the
/// real pipeline. Then 50 cold sessions (200 responses, mtime two days back)
/// are read once each. Desired:
/// - no warm entry is lost, during the flood or at the warm sessions' next
///   append;
/// - cold files may take free room but never evict;
/// - clones do not exceed free-room admissions.
///
/// Red on main, twice:
/// - Clone churn: every cold read clones its reduction (50), but only the
///   first cold files are admitted. The rest are cloned and then dropped,
///   for example by the finalization bound (L7). The flood evicts nothing and
///   keeps every warm entry, so those assertions pass.
/// - Fill-and-freeze (L5): the admitted cold entries keep the free room. A
///   warm session's next tail then refuses its own re-admission
///   (`retention_bound_refused`), so it is no longer resident afterwards.
#[test]
fn cache_policy_g2_cold_flood_never_costs_warm_sessions() {
    if unexecuted("G2_cold_flood") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let warm = (0..WARM_FILES)
        .map(|_| ScanFixture::new(source))
        .collect::<Vec<_>>();
    let mut indexes = Vec::new();
    for file in &warm {
        file.append_usage(source, 0..WARM_RECORDS);
        let observed = observed_scan(file, source, ScanIndex::default(), Some(&cache), false);
        assert_eq!(observed.modes, (1, 0, 0));
        indexes.push(observed.index);
    }
    let warm_resident = |cache: &Arc<sampled_scan::SharedCache>| {
        warm.iter()
            .filter(|file| cache.retained_checkpoint(&file.key()).is_some())
            .count()
    };
    assert_eq!(
        warm_resident(&cache),
        WARM_FILES,
        "precondition: every warm session is retained"
    );
    let resident_after_warm = optional_resident(&cache);

    let old = unix_now() - OLD_SECONDS;
    let (_, flood) = observe(|| {
        for number in 0..COLD_FILES {
            let cold = ScanFixture::new(source);
            cold.append_usage(source, 0..COLD_RECORDS);
            cold.set_modified(old - number as u64);
            let observed = observed_scan(&cold, source, ScanIndex::default(), Some(&cache), false);
            assert_eq!(observed.modes, (1, 0, 0), "precondition: one cold read");
        }
    });
    let warm_after_flood = warm_resident(&cache);
    let resident_after_flood = optional_resident(&cache);
    assert!(
        flood.insert_admitted > 0,
        "precondition: cold files took free room"
    );

    let mut tail_modes = Vec::new();
    let mut tail_counts = Vec::new();
    let mut kept = Vec::new();
    for (number, (file, index)) in warm.iter().zip(indexes).enumerate() {
        let id = WARM_RECORDS + number;
        file.append(&usage(source, 100 + id as u64, id, MODEL));
        let (observed, counts) =
            observe(|| observed_scan(file, source, index, Some(&cache), false));
        tail_modes.push(observed.modes);
        tail_counts.push((counts.retention_bound_refused, counts.insert_admitted));
        kept.push(cache.retained_checkpoint(&file.key()).is_some());
    }
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_after_warm={resident_after_warm} flood_insert_admitted={} flood_retention_produced={} flood_retention_bound_refused={} flood_insert_entries_evicted={} flood_insert_self_evicted={} flood_retention_finalization_bound_refused={} flood_retention_clone_bound_refused={} flood_insert_live_reservation_refused={} flood_wipes={} warm_after_flood={warm_after_flood} resident_after_flood={resident_after_flood} warm_tail_modes={tail_modes:?} warm_tail_(bound_refused,admitted)={tail_counts:?} warm_kept_after_tail={kept:?}",
        flood.insert_admitted,
        flood.retention_produced,
        flood.retention_bound_refused,
        flood.insert_entries_evicted,
        flood.insert_self_evicted,
        flood.retention_finalization_bound_refused,
        flood.retention_clone_bound_refused,
        flood.insert_live_reservation_refused,
        wipe_clears(&flood),
    );
    eprintln!("CACHE_POLICY test=G2_cold_flood {receipt}");

    assert_eq!(wipe_clears(&flood), 0, "G2: the flood wipes; {receipt}");
    assert_eq!(
        warm_after_flood, WARM_FILES,
        "G2: the cold flood evicted a warm entry; {receipt}"
    );
    assert_eq!(
        flood.insert_entries_evicted + flood.insert_self_evicted,
        0,
        "G2: a cold candidate evicted; {receipt}"
    );
    assert!(
        flood.retention_produced <= flood.insert_admitted,
        "G2: clones exceed free-room admissions; {receipt}"
    );
    assert!(
        tail_modes.iter().all(|modes| *modes == (0, 1, 0)),
        "G2: a warm session's next append is not a tail; {receipt}"
    );
    assert!(
        kept.iter().all(|kept| *kept),
        "G2: a warm session lost its entry to cold residents after its tail; {receipt}"
    );
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
    let run = tail_beside_full_cache(true);
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
    let run = tail_beside_full_cache(false);
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

/// M2 fill-and-freeze (design §6 row M2; §2 L5; §3a evicting admission).
///
/// Four old-mtime fillers (two days back) fill the cache within the state
/// budget. Then a recent 600-response Claude session completes a first full
/// read. Desired: it displaces old fillers, is retained, and its next append
/// reads as a tail.
///
/// Red on main: the copy budget already subtracts the whole resident cache,
/// so retention is refused (`retention_bound_refused=1`) and nothing is
/// evicted (`insert_entries_evicted=0`). The session is not retained, and its
/// next append reads `Full(StateMissing)`.
#[test]
fn cache_policy_m2_recent_full_read_displaces_old_fillers() {
    if unexecuted("M2_fill_and_freeze") {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    insert_fillers(&cache, Some(unix_now() - OLD_SECONDS));
    let resident_after_fill = optional_resident(&cache);
    assert!(resident_after_fill <= POLICY_STATE_BYTES);
    let recent = ScanFixture::new(source);
    recent.append_usage(source, 0..WARM_RECORDS);
    let (full, full_counts) =
        observe(|| observed_scan(&recent, source, ScanIndex::default(), Some(&cache), false));
    assert_eq!(full.modes, (1, 0, 0), "precondition: a first full read");
    assert_eq!(full.state_missing(), 1);
    assert_eq!(wipe_clears(&full_counts), 0, "precondition: no wipe");
    let retained_after_full = cache.retained_checkpoint(&recent.key()).is_some();
    let fillers_after_full = fillers_resident(&cache);
    recent.append(&usage(source, 2000, WARM_RECORDS, MODEL));
    let (append, append_counts) =
        observe(|| observed_scan(&recent, source, full.index, Some(&cache), false));
    let receipt = format!(
        "state_bytes={POLICY_STATE_BYTES} resident_after_fill={resident_after_fill} full_retention_bound_refused={} full_retention_produced={} full_insert_entries_evicted={} retained_after_full={retained_after_full} fillers_after_full={fillers_after_full} append_modes={:?} append_state_missing={} append_take_hit={}",
        full_counts.retention_bound_refused,
        full_counts.retention_produced,
        full_counts.insert_entries_evicted,
        append.modes,
        append.state_missing(),
        append_counts.take_hit,
    );
    eprintln!("CACHE_POLICY test=M2_fill_and_freeze {receipt}");
    assert!(
        retained_after_full,
        "M2: the recent full read was not retained over old fillers; {receipt}"
    );
    assert_eq!(
        append.modes,
        (0, 1, 0),
        "M2: the next append is not a tail; {receipt}"
    );
}
