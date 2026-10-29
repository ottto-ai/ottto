//! Shared Stage2-pre fixture harness for the Claude frozen-extent extension.
//! Codex Stage2-pre RED rows remain in their independent draft PR.
//!
//! Every test asserts the behavior the ACKed seam (H1 reader-relative extent
//! limit, H2 in-page E1, H3 grown-Tail sealed-prefix commit) must produce.
//! Tests marked RED fail on main today, for the reason in their doc comment;
//! tests marked PARITY assert main's behavior, which the seam must keep, and
//! pass on main. Production code is unchanged here.
//!
//! Injection points:
//! - after the open step (prepare, and H1 once it lands) and before the first
//!   reader step: `OwnedSourceScan::step` returns `Pending` right after the
//!   open step, so `page_injecting` changes the file between two steps;
//! - after the reader reports EOF and before completion: the same step
//!   continues into completion, so `with_eof_hook` uses the one
//!   `#[cfg(test)]` seam, `snapshots::with_after_reader_eof`.
//!
//! Disclosed residuals (not mutation detection):
//! - `sp5_residual_...`: a rewrite of already-read tail bytes that preserves
//!   both sample windows, followed by growth, is accepted (append-only
//!   sampled-prefix semantics, as the cursor).
//! - SP-10: Unchanged-mode growth keeps dropping the copy.
//! - SP-12 (Codex 2 GiB crossing) is not added: it needs #656 on main.
//! - The N2 `sealed_fragment_withheld` counter is cursor-only (`finish_job`) and
//!   private to `codex_cursor`; the unmodified `codex_cursor_tests` pin it.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle::observe;
use crate::transcript_acquisition::{AuditDebt, FullReason};
use std::cell::Cell;
use std::io::Write;
use std::ops::Range;
use std::rc::Rc;

const NAMESPACE: &str = "stage2pre";
/// `UnreadableCauses` slots, in `UnreadableBreakdown` order.
const OPEN_READ: usize = 2;
const SCOPE_OBJECT: usize = 3;
const STATE_MISSING: usize = 0;
const AUDIT_DUE: usize = 1;

/// One page's sampled-acquisition counters and unreadable census, taken
/// before its last step.
#[derive(Clone, Debug, Default)]
struct Seen {
    modes: (usize, usize, usize),
    full_reasons: [usize; 13],
    unreadable: usize,
    causes: [u64; 8],
}

/// An in-page acquisition's plan and reader position.
#[derive(Clone, Copy, Debug)]
struct InPage {
    mode: ReadMode,
    start: u64,
    frozen: u64,
    consumed: u64,
    cursor: bool,
    extent_limit: Option<u64>,
    debt: Option<AuditDebt>,
}

fn in_page(active: &OwnedActiveFile) -> Option<InPage> {
    let mode = active.sampling.as_ref()?.mode;
    let plan = active.parser.reader.acquisition.as_ref()?;
    Some(InPage {
        mode,
        start: plan.start_offset(),
        frozen: plan.frozen_length(),
        consumed: active.parser.reader.consumed_bytes(),
        cursor: active.cursor.is_some(),
        extent_limit: active.parser.reader.extent_limit,
        debt: plan.audit_obligation(),
    })
}

/// The active in-page read right after its open step, before any reader step.
fn opened(scan: &OwnedSourceScan) -> Option<InPage> {
    let active = scan.active_file.as_deref()?;
    let read = in_page(active)?;
    (read.consumed == 0 && !read.cursor && !active.parser.reader.finished).then_some(read)
}

fn causes(census: &ScanCensus) -> [u64; 8] {
    let value = serde_json::to_value(census.unreadable_causes.projection(0)).unwrap();
    let mut counts = [0; 8];
    for (slot, count) in counts
        .iter_mut()
        .zip(value["counts"].as_array().expect("fixed cause counts"))
    {
        *slot = count.as_u64().unwrap();
    }
    counts
}

/// One production page; `before_step` runs before every step.
fn page(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    mut before_step: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Seen) {
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
    .with_sampled_acquisition(Arc::clone(cache), Scope(NAMESPACE.into()));
    let mut seen = Seen::default();
    loop {
        if let Some(context) = scan.sampling.as_ref() {
            seen.modes = (
                context.full_files,
                context.tail_files,
                context.unchanged_files,
            );
            seen.full_reasons = context.full_reasons;
        }
        seen.unreadable = scan.census.unreadable_path_count;
        seen.causes = causes(&scan.census);
        before_step(&mut scan);
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                // As `production_scan_at_with_setup`: existing post-policy
                // finalization and acceptance.
                let mut projected = scan.clone();
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
                return (index, scan, seen);
            }
        }
    }
}

fn plain(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> (ScanIndex, SourceScanResult, Seen) {
    page(fixture, source, index, cache, |_| {})
}

/// A page that runs `inject` once, between the open step of the first
/// in-page read whose mode satisfies `want` and its first reader step.
fn page_injecting(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    want: fn(ReadMode) -> bool,
    inject: impl FnOnce(&InPage),
) -> (ScanIndex, SourceScanResult, Seen, InPage) {
    let mut inject = Some(inject);
    let mut opened_read = None;
    let (index, result, seen) = page(fixture, source, index, cache, |scan| {
        if opened_read.is_some() {
            return;
        }
        if let Some(read) = opened(scan).filter(|read| want(read.mode)) {
            if let Some(inject) = inject.take() {
                inject(&read);
            }
            opened_read = Some(read);
        }
    });
    let read = opened_read.expect("precondition: the page opened the in-page read");
    (index, result, seen, read)
}

fn is_tail(mode: ReadMode) -> bool {
    mode == ReadMode::Tail
}

fn is_full(mode: ReadMode) -> bool {
    matches!(mode, ReadMode::Full(_))
}

/// Runs `run` with `at_eof` called once, when `path`'s reader reports EOF and
/// before its completion. Returns what the reader looked like then.
fn with_eof_hook<T>(
    path: &Path,
    at_eof: impl FnOnce(&InPage) + 'static,
    run: impl FnOnce() -> T,
) -> (T, Option<InPage>) {
    let seen = Rc::new(Cell::new(None));
    let record = Rc::clone(&seen);
    let name = path.file_name().map(|name| name.to_os_string());
    let mut at_eof = Some(at_eof);
    let value = with_after_reader_eof(
        move |active| {
            if active.candidate.path.file_name() != name.as_deref() {
                return;
            }
            let Some(read) = in_page(active) else {
                return;
            };
            if let Some(at_eof) = at_eof.take() {
                record.set(Some(read));
                at_eof(&read);
            }
        },
        run,
    );
    (value, seen.get())
}

fn row(source: SnapshotSource, id: usize) -> Value {
    usage(source, 100 + 30 * id as u64, id, "fixture-model")
}

fn row_bytes(source: SnapshotSource, ids: Range<usize>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for id in ids {
        serde_json::to_writer(&mut bytes, &row(source, id)).unwrap();
        bytes.push(b'\n');
    }
    bytes
}

fn append_raw(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn truncate(path: &Path, length: u64) {
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(length)
        .unwrap();
}

/// Rename a new object (`bytes`) over `path`; an open FD keeps the old one.
fn replace(path: &Path, bytes: &[u8]) {
    let staged = path.with_extension("replacement");
    fs::write(&staged, bytes).unwrap();
    fs::rename(staged, path).unwrap();
}

fn bytes_of(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

fn overwrite(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}

fn len(path: &Path) -> u64 {
    fs::metadata(path).unwrap().len()
}

/// The unsampled native body of the fixture's current bytes.
fn full_body(fixture: &ScanFixture, source: SnapshotSource) -> Value {
    let (_, full, _) = production_scan(
        fixture,
        source,
        ScanIndex::default(),
        None,
        "stage2pre-oracle",
    );
    production_body(source, full)
}

/// A fixture after a first sampled Full that retained a copy at `sealed`,
/// with `pre` more rows appended so the next ordinary page Tails from it.
struct Baseline {
    fixture: ScanFixture,
    cache: Arc<sampled_scan::SharedCache>,
    index: ScanIndex,
    key: String,
    path: PathBuf,
    sealed: u64,
}

fn baseline(source: SnapshotSource, rows: usize, pre: usize) -> Baseline {
    let fixture = ScanFixture::new(source);
    fixture.file.append(&row(source, 0));
    append_raw(&fixture.file.0, &row_bytes(source, 1..rows));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, seen) = plain(&fixture, source, ScanIndex::default(), &cache);
    assert_eq!(
        seen.modes,
        (1, 0, 0),
        "precondition: the first page is Full"
    );
    let path = fixture.file.0.clone();
    let key = local_index_key(&path);
    let checkpoint = cache
        .retained_checkpoint(&key)
        .expect("precondition: the first Full retains a copy");
    let sealed = checkpoint.sealed_offset();
    assert_eq!(sealed, len(&path), "precondition: the whole file is sealed");
    append_raw(&path, &row_bytes(source, rows..rows + pre));
    Baseline {
        fixture,
        cache,
        index,
        key,
        path,
        sealed,
    }
}

/// Main's failed attempt or the seam's refusal: one unreadable of `cause`,
/// no retained copy, nothing published.
fn assert_refused(
    cache: &sampled_scan::SharedCache,
    key: &str,
    result: &SourceScanResult,
    seen: &Seen,
    cause: usize,
    id: &str,
) {
    assert_eq!(
        (seen.unreadable, seen.causes[cause]),
        (1, 1),
        "{id}: one unreadable of cause slot {cause}; causes={:?}",
        seen.causes
    );
    assert!(
        cache.retained_checkpoint(key).is_none(),
        "{id}: no checkpoint or copy"
    );
    assert!(result.snapshots.is_empty(), "{id}: nothing published");
}

/// SP-11, updated for FE: Claude's in-page Tail with an append publishes
/// its sealed prefix uncertified and drops the copy. Codex Stage2-pre is
/// independent; FE changes the formerly pinned Claude D1 failure.
#[test]
fn sp11_claude_in_page_tail_with_append_publishes_uncertified_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let appended = row_bytes(source, 6..8);
    let (_, tail, seen, _) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(seen.unreadable, 0, "SP-11 FE: causes={:?}", seen.causes);
    assert!(!tail.snapshots.is_empty(), "SP-11 FE: prefix published");
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "SP-11 FE: no copy"
    );
}

mod fe_claude_in_page_read_tests;
