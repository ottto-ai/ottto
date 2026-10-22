//! Stage2-pre red-first fixtures: Codex appends while an in-page sampled
//! `Tail` reads (C10). Controls SP-1..SP-11 of the reviewed Stage2-pre seam.
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
const REDUCTION: usize = 4;
const STATE_MISSING: usize = 0;
const AUDIT_DUE: usize = 1;

/// One page's sampled-acquisition counters and unreadable census, taken
/// before its last step.
#[derive(Clone, Debug, Default)]
struct Seen {
    modes: (usize, usize, usize),
    native_bytes: u64,
    sample_bytes: u64,
    full_reasons: [usize; 11],
    priority_replays: usize,
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
            seen.native_bytes = context.native_bytes;
            seen.sample_bytes = context.sample_bytes;
            seen.full_reasons = context.full_reasons;
            seen.priority_replays = context.priority_replays;
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

/// The same bytes with the first row's session id changed: equal length,
/// different head sample.
fn changed_head(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let changed = text.replacen("8444-555555555555", "8444-555555555556", 1);
    assert_ne!(changed, text, "precondition: the head row names the id");
    changed.into_bytes()
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
    verified: u64,
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
        verified: checkpoint.last_full_verified(),
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

/// SP-1 (RED): a retained Codex file, `s` > 0; complete rows are appended
/// after the open step of its in-page Tail. The Tail commits `[0, frozen)`
/// with the copy retained, and the ordinary next page (directory discovery,
/// no `release_path`, no watcher hint) selects the file and Tails exactly the
/// appended bytes.
///
/// Red on main: the reader reads the appended rows past the frozen length;
/// `observe_record_fragment` fails "acquisition exceeds stable source" (D1),
/// the page records one `OpenRead` unreadable and drops the taken copy, so
/// the next read is `Full(StateMissing)`.
#[test]
fn sp1_append_during_in_page_tail_keeps_copy_and_next_page_tails_append() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let frozen_body = full_body(&base.fixture, source);
    let appended = row_bytes(source, 6..9);
    let path = base.path.clone();
    let (index, tail, seen, read) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(read.start, base.sealed, "precondition: Tail from s");
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(
        seen.unreadable, 0,
        "SP-1: no D1 failure; causes={:?}",
        seen.causes
    );
    let checkpoint = base
        .cache
        .retained_checkpoint(&base.key)
        .expect("SP-1: the Tail's copy is retained");
    assert_eq!(checkpoint.sealed_offset(), read.frozen);
    assert_eq!(checkpoint.last_full_verified(), base.verified);
    assert_eq!(checkpoint.audit_debt(), read.debt, "debt == pre-read");
    assert_eq!(
        base.cache.retained_sealed_offset(&base.key),
        Some(read.frozen)
    );
    assert_eq!(
        production_body(source, tail),
        frozen_body,
        "SP-1: body == Full parse of [0, frozen)"
    );

    let (_, next, seen) = plain(&base.fixture, source, index, &base.cache);
    assert_eq!(seen.modes, (0, 1, 0), "SP-1: the next page Tails");
    assert_eq!(seen.full_reasons[STATE_MISSING], 0);
    assert_eq!(seen.unreadable, 0);
    assert_eq!(seen.native_bytes, appended.len() as u64, "exactly A");
    assert_eq!(seen.sample_bytes, 2 * read.frozen.min(4096));
    assert_eq!(
        base.cache.retained_sealed_offset(&base.key),
        Some(len(&base.path))
    );
    assert_eq!(
        production_body(source, next),
        full_body(&base.fixture, source),
        "SP-1: next body == Full parse of [0, frozen + A)"
    );
}

/// SP-2a (RED): half a row at open, completed (plus more rows) after the
/// open step. The Tail seals at the row's start `s'` < frozen, publishes
/// `[0, s')` without the row and retains the copy; the next page Tails from
/// `s'` with Full-parse parity.
///
/// Red on main: the row's newline lies past the frozen length, so the reader
/// fails D1 ("acquisition exceeds stable source", one `OpenRead`).
#[test]
fn sp2a_partial_row_at_frozen_grown_seals_last_newline() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let row_start = len(&base.path);
    let sealed_body = full_body(&base.fixture, source);
    let split = row_bytes(source, 6..7);
    let (head, rest) = split.split_at(split.len() / 2);
    append_raw(&base.path, head);
    let mut completion = rest.to_vec();
    completion.extend(row_bytes(source, 7..9));
    let path = base.path.clone();
    let (index, tail, seen, read) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &completion),
    );
    assert_eq!(read.frozen, row_start + head.len() as u64);
    assert_eq!(
        seen.unreadable, 0,
        "SP-2a: no D1 failure; causes={:?}",
        seen.causes
    );
    let checkpoint = base
        .cache
        .retained_checkpoint(&base.key)
        .expect("SP-2a: copy retained");
    assert_eq!(checkpoint.sealed_offset(), row_start, "s' = last newline");
    assert_eq!(
        production_body(source, tail),
        sealed_body,
        "SP-2a: the unfinished row is not applied"
    );

    let mut next_start = None;
    let (_, next, seen) = page(&base.fixture, source, index, &base.cache, |scan| {
        if next_start.is_none() {
            next_start = opened(scan).map(|read| read.start);
        }
    });
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(next_start, Some(row_start), "SP-2a: next Tail starts at s'");
    assert_eq!(
        production_body(source, next),
        full_body(&base.fixture, source)
    );
}

/// SP-2b (PARITY): a quiescent unterminated last row, not grown. Main's
/// trailing-line rule applies it (H2 must keep this byte-identical): body ==
/// Full parse, `RetentionUnsealedEof`, no copy, nothing unreadable.
#[test]
fn sp2b_partial_row_not_grown_keeps_main_trailing_line_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let last = row_bytes(source, 6..7);
    append_raw(&base.path, &last[..last.len() - 1]);
    let ((_, tail, seen), counts) =
        observe(|| plain(&base.fixture, source, base.index, &base.cache));
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(counts.retention_unsealed_eof, 1);
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "no copy"
    );
    assert_eq!(
        production_body(source, tail),
        full_body(&base.fixture, source)
    );
}

/// SP-2c (RED): setter units with `s` >= 64 KiB. The reader stops at frozen
/// with a reader-relative limit `frozen - start`.
///
/// Red on main: no in-page limit is set; the reader passes frozen and fails
/// D1 (one `OpenRead`), so the EOF hook never sees this read.
#[test]
fn sp2c_large_prefix_tail_stops_at_frozen_with_relative_limit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 300, 2);
    assert!(base.sealed >= 64 * 1024, "precondition: s >= 64 KiB");
    let path = base.path.clone();
    let appended = row_bytes(source, 302..305);
    let ((_, _, seen, read), at_eof) = with_eof_hook(
        &base.path,
        |_| {},
        || {
            page_injecting(
                &base.fixture,
                source,
                base.index,
                &base.cache,
                is_tail,
                |_| append_raw(&path, &appended),
            )
        },
    );
    assert_eq!(
        seen.unreadable, 0,
        "SP-2c: no D1 failure; causes={:?}",
        seen.causes
    );
    let at_eof = at_eof.expect("SP-2c: the reader reached EOF");
    assert_eq!(
        at_eof.extent_limit,
        Some(read.frozen - read.start),
        "SP-2c: reader-relative limit"
    );
    assert_eq!(at_eof.start + at_eof.consumed, read.frozen);
    assert_eq!(
        base.cache.retained_sealed_offset(&base.key),
        Some(read.frozen)
    );
}

/// SP-2c negative control (PARITY): the reader counts from the plan start,
/// so an absolute `frozen` limit on a Tail with `s` >= 64 KiB over-reads
/// into the append and reproduces D1, while `frozen - start` stops exactly
/// at frozen.
#[test]
fn sp2c_absolute_frozen_limit_reproduces_d1_relative_limit_stops() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let fixture = Fixture::new(source);
    for id in 0..300 {
        fixture.append(&row(source, id));
    }
    let tail_plan = |old| {
        fixture.append(&row(source, 1000));
        let (mut parser, _, scope) = native_parser(&fixture, source);
        assert_eq!(
            parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
            ReadMode::Tail
        );
        let plan = parser.reader.acquisition.as_ref().unwrap();
        let (start, frozen) = (plan.start_offset(), plan.frozen_length());
        assert!(start >= 64 * 1024, "precondition: s >= 64 KiB");
        fixture.append(&row(source, 1001));
        (parser, start, frozen)
    };

    let (old, _, _, _) = acquire(&fixture, source, None, 100);
    let (mut parser, _, frozen) = tail_plan(Some(old.expect("retained")));
    parser.reader.set_extent_limit(frozen);
    let error = loop {
        match parser.step() {
            Ok(true) => panic!("an absolute limit must over-read past frozen"),
            Ok(false) => {}
            Err(error) => break error,
        }
    };
    assert!(
        format!("{error:#}").contains("acquisition exceeds stable source"),
        "{error:#}"
    );

    let (old, _, _, _) = acquire(&fixture, source, None, 100);
    let (mut parser, start, frozen) = tail_plan(Some(old.expect("retained")));
    parser.reader.set_extent_limit(frozen - start);
    while !parser.step().unwrap() {}
    assert_eq!(start + parser.reader.consumed_bytes(), frozen);
}

/// SP-3a (PARITY): a new object renamed over the path during the Tail; the
/// held FD is not grown. Main's revalidation refuses as `ScopeObject`: no
/// checkpoint, copy or publication.
#[test]
fn sp3a_replace_during_tail_not_grown_is_scope_object() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let bytes = bytes_of(&base.path);
    let (_, tail, seen, _) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| replace(&path, &bytes),
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-3a");
}

/// SP-3b (RED): the held object grows and a new object is renamed over the
/// path during the Tail. H3's path check refuses (`Invalidated(Replaced)`)
/// as `ScopeObject`: no grant, no publication; the next read is
/// `Full(StateMissing)`.
///
/// Red on main: the reader reads the held object's append past frozen and
/// fails D1, recorded as `OpenRead`, not `ScopeObject`.
#[test]
fn sp3b_replace_during_tail_with_held_growth_is_scope_object() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let mut bytes = bytes_of(&base.path);
    bytes.extend(row_bytes(source, 6..7));
    let appended = row_bytes(source, 6..8);
    let (index, tail, seen, _) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| {
            append_raw(&path, &appended);
            replace(&path, &bytes);
        },
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-3b");
    append_raw(&base.path, &row_bytes(source, 9..10));
    let (_, _, seen) = plain(&base.fixture, source, index, &base.cache);
    assert_eq!(seen.full_reasons[STATE_MISSING], 1, "next read is a Full");
}

/// SP-4 (PARITY): truncated below frozen during the Tail, no regrow. Not
/// grown, so main's path: revalidation refuses as `ScopeObject`; no
/// checkpoint, copy or publication.
#[test]
fn sp4_truncate_during_tail_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let (path, sealed) = (base.path.clone(), base.sealed);
    let (_, tail, seen, _) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| truncate(&path, sealed),
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-4");
}

/// SP-5a (PARITY): truncated at the open step, so the reader reaches a short
/// EOF (`start + consumed < frozen`), then regrown past frozen before
/// completion. H3's traversal check fails, so main's path: `ScopeObject`.
#[test]
fn sp5a_truncate_then_regrow_after_short_eof_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let (path, sealed) = (base.path.clone(), base.sealed);
    let mut regrown = bytes_of(&base.path)[sealed as usize..].to_vec();
    regrown.extend(row_bytes(source, 6..8));
    let regrow_path = base.path.clone();
    let ((_, tail, seen, read), at_eof) = with_eof_hook(
        &base.path,
        move |_| append_raw(&regrow_path, &regrown),
        || {
            page_injecting(
                &base.fixture,
                source,
                base.index,
                &base.cache,
                is_tail,
                |_| truncate(&path, sealed),
            )
        },
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert!(
        at_eof.start + at_eof.consumed < read.frozen,
        "precondition: a short EOF"
    );
    assert!(len(&base.path) > read.frozen, "precondition: regrown");
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-5a");
}

/// SP-5a' (RED): truncated and regrown past frozen at the open step, with a
/// different head. A pre-boundary regrow does not imply a short read: the
/// reader traverses exactly to frozen, and H3's head sample refuses
/// (`HeadChanged`) as `ScopeObject`; nothing published.
///
/// Red on main: the reader passes frozen into the regrown bytes and fails D1
/// (`OpenRead`), so the EOF hook never sees this read.
#[test]
fn sp5a_prime_regrow_before_first_step_reads_to_frozen_and_refuses_head() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let mut regrown = changed_head(&bytes_of(&base.path));
    regrown.extend(row_bytes(source, 6..8));
    let ((_, tail, seen, read), at_eof) = with_eof_hook(
        &base.path,
        |_| {},
        || {
            page_injecting(
                &base.fixture,
                source,
                base.index,
                &base.cache,
                is_tail,
                |_| overwrite(&path, &regrown),
            )
        },
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-5a'");
    let at_eof = at_eof.expect("SP-5a': the reader reached EOF");
    assert_eq!(at_eof.start + at_eof.consumed, read.frozen);
}

/// SP-5b (PARITY): after the reader passes frozen, the file is truncated and
/// regrown past frozen with a different head. Main's revalidation and H3's
/// head sample both refuse as `ScopeObject`; nothing published.
#[test]
fn sp5b_regrow_after_reader_passes_frozen_with_new_head_refuses() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let mut regrown = changed_head(&bytes_of(&base.path));
    regrown.extend(row_bytes(source, 6..8));
    let ((_, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| overwrite(&path, &regrown),
        || plain(&base.fixture, source, base.index, &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(at_eof.start + at_eof.consumed, at_eof.frozen);
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-5b");
}

/// SP-5c (PARITY): after the reader passes frozen, the file is rewritten to
/// exactly frozen with a different head. Not grown, so main's revalidation
/// (identity: ctime and samples) refuses as `ScopeObject`.
#[test]
fn sp5c_regrow_to_exactly_frozen_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let rewritten = changed_head(&bytes_of(&base.path));
    let ((_, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| overwrite(&path, &rewritten),
        || plain(&base.fixture, source, base.index, &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(len(&base.path), at_eof.frozen, "precondition: not grown");
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-5c");
}

/// SP-5 residual (RED; EXPECTED RESIDUAL, disclosed, not mutation
/// detection): after the reader passed them, already-read tail bytes outside
/// both 4 KiB sample windows are truncated and regrown with a different row
/// of the same length, plus growth. H3 accepts it like the cursor does
/// (append-only sampled-prefix semantics, `commit_sealed_prefix`): the page publishes the
/// bytes it read and retains `[0, frozen)`; only a later Full sees the edit.
///
/// Red on main: main's revalidation sees the grown identity and refuses the
/// page as `ScopeObject`; it publishes nothing.
#[test]
fn sp5_residual_sample_preserving_rewrite_after_read_is_accepted() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 20, 25);
    let frozen = len(&base.path);
    assert!(
        base.sealed > 4096,
        "precondition: head window inside [0, s)"
    );
    let original = bytes_of(&base.path);
    let edited_row = base.sealed as usize;
    let row_len = row_bytes(source, 20..21).len();
    assert!(
        edited_row + row_len < frozen as usize - 4096,
        "precondition: the edit is outside the boundary window"
    );
    let text = String::from_utf8(original[edited_row..edited_row + row_len].to_vec()).unwrap();
    let edited = text.replacen("fixture-model", "fixture-modem", 1);
    assert_ne!(edited, text);
    let mut regrown = original[edited_row..].to_vec();
    regrown[..row_len].copy_from_slice(edited.as_bytes());
    regrown.extend(row_bytes(source, 45..47));
    let frozen_body = full_body(&base.fixture, source);
    let path = base.path.clone();
    let ((_, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| {
            truncate(&path, edited_row as u64);
            append_raw(&path, &regrown);
        },
        || plain(&base.fixture, source, base.index, &base.cache),
    );
    assert!(at_eof.is_some(), "precondition: the reader reached EOF");
    assert_eq!(
        seen.unreadable, 0,
        "SP-5 residual: accepted; causes={:?}",
        seen.causes
    );
    assert_eq!(base.cache.retained_sealed_offset(&base.key), Some(frozen));
    assert_eq!(
        production_body(source, tail),
        frozen_body,
        "SP-5 residual: the bytes read before the edit are published"
    );
}

/// SP-6a (RED): the first protected tier is only in bytes appended after the
/// open step (past frozen). This Tail commits without a replay; the next
/// Tail reads the priority row, hits the tier gate and replays Full with
/// body parity.
///
/// Red on main: the reader fails D1 on the appended rows (`OpenRead`).
#[test]
fn sp6a_priority_only_past_frozen_commits_then_next_tail_replays() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let mut priority = row(source, 6);
    priority["payload"]["service_tier"] = json!("priority");
    let mut appended = serde_json::to_vec(&priority).unwrap();
    appended.push(b'\n');
    appended.extend(row_bytes(source, 7..8));
    let path = base.path.clone();
    let (index, _, seen, read) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(
        seen.unreadable, 0,
        "SP-6a: no D1 failure; causes={:?}",
        seen.causes
    );
    assert_eq!(seen.priority_replays, 0, "SP-6a: no replay this page");
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(
        base.cache.retained_sealed_offset(&base.key),
        Some(read.frozen)
    );

    let (_, next, seen) = plain(&base.fixture, source, index, &base.cache);
    assert_eq!(seen.priority_replays, 1, "SP-6a: the next Tail replays");
    assert_eq!(seen.modes, (1, 1, 0));
    assert_eq!(
        production_body(source, next),
        full_body(&base.fixture, source)
    );
}

/// SP-6b (RED): a protected tier inside `[s, frozen)` and an append after
/// the open step. The reader stops at frozen, the tier gate replays Full
/// exactly as main (no extent on the replay), with body parity.
///
/// Red on main: the reader fails D1 on the appended rows before the gate
/// (`OpenRead`).
#[test]
fn sp6b_priority_inside_tail_with_append_replays_full() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 0);
    let mut priority = row(source, 4);
    priority["payload"]["service_tier"] = json!("priority");
    base.fixture.file.append(&priority);
    append_raw(&base.path, &row_bytes(source, 5..6));
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
    assert_eq!(
        seen.unreadable, 0,
        "SP-6b: no D1 failure; causes={:?}",
        seen.causes
    );
    assert_eq!(seen.priority_replays, 1, "SP-6b: the gate replays");
    assert_eq!(seen.modes, (1, 1, 0));
    assert_eq!(
        production_body(source, tail),
        full_body(&base.fixture, source)
    );
}

/// The baseline plus a malformed row inside `[s, frozen)`.
fn lossy_baseline(source: SnapshotSource) -> Baseline {
    let base = baseline(source, 4, 1);
    append_raw(&base.path, b"{\"type\":\"event_msg\",\"payload\":\n");
    append_raw(&base.path, &row_bytes(source, 5..6));
    base
}

/// SP-7a (PARITY): a lossy row in the Tail, not grown. Main: the retention
/// refuses (`RetentionIncompleteOrLossy`), no copy, nothing unreadable.
#[test]
fn sp7a_lossy_tail_not_grown_keeps_main_uncertified_path() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = lossy_baseline(source);
    let ((_, _, seen), counts) = observe(|| plain(&base.fixture, source, base.index, &base.cache));
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(counts.retention_incomplete_or_lossy, 1);
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "no copy"
    );
}

/// SP-7b (RED): a lossy row in `[s, frozen)` and an append after the open
/// step. Lossy reads are excluded from H3, so main's revalidation refuses the
/// grown object as `ScopeObject`; no checkpoint, copy or grant; the next
/// read is `Full(StateMissing)`.
///
/// Red on main: the reader fails D1 first, recorded as `OpenRead`.
#[test]
fn sp7b_lossy_tail_grown_is_excluded_from_sealed_commit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = lossy_baseline(source);
    let path = base.path.clone();
    let appended = row_bytes(source, 6..8);
    let (index, tail, seen, _) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-7b");
    append_raw(&base.path, &row_bytes(source, 8..9));
    let (_, _, seen) = plain(&base.fixture, source, index, &base.cache);
    assert_eq!(seen.full_reasons[STATE_MISSING], 1, "next read is a Full");
}

/// SP-8a (RED): growth earns no audit credit. The grown Tail's checkpoint
/// keeps the pre-read verification time and debt, and a seal minted from it
/// now is not outlived.
///
/// Red on main: D1 (`OpenRead`), no checkpoint.
#[test]
fn sp8a_grown_tail_keeps_verification_and_debt() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    let path = base.path.clone();
    let appended = row_bytes(source, 6..8);
    let (_, _, seen, read) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(
        seen.unreadable, 0,
        "SP-8a: no D1 failure; causes={:?}",
        seen.causes
    );
    let checkpoint = base
        .cache
        .retained_checkpoint(&base.key)
        .expect("SP-8a: a checkpoint");
    assert_eq!(checkpoint.last_full_verified(), base.verified, "no credit");
    assert!(read.debt.is_some(), "precondition: a Tail owes its audit");
    assert_eq!(checkpoint.audit_debt(), read.debt, "debt unchanged");
    assert!(!checkpoint.seal(sampled_scan::now_seconds()).outlived());
}

/// SP-8b (RED): a grown Tail whose debt falls due before commit refuses
/// (`AuditDue`) as `Reduction`: no checkpoint or copy; the next read is
/// `Full(AuditDue)`.
///
/// Red on main: D1 first, recorded as `OpenRead`, not `Reduction`.
#[test]
fn sp8b_grown_tail_with_debt_due_at_commit_refuses() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let mut base = baseline(source, 4, 2);
    base.index
        .files
        .get_mut(&base.key)
        .unwrap()
        .set_unverified_deadline(sampled_scan::now_seconds() + 2);
    let path = base.path.clone();
    let appended = row_bytes(source, 6..8);
    let index = std::mem::take(&mut base.index);
    let (index, tail, seen, read) =
        page_injecting(&base.fixture, source, index, &base.cache, is_tail, |_| {
            append_raw(&path, &appended);
            std::thread::sleep(std::time::Duration::from_secs(3));
        });
    assert!(
        read.debt
            .is_some_and(|debt| debt.due_unix_seconds <= sampled_scan::now_seconds()),
        "precondition: the debt is due at commit"
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, REDUCTION, "SP-8b");
    append_raw(&base.path, &row_bytes(source, 8..9));
    let (_, _, seen) = plain(&base.fixture, source, index, &base.cache);
    assert_eq!(
        seen.full_reasons[AUDIT_DUE], 1,
        "next read is Full(AuditDue)"
    );
}

/// SP-8c (PARITY): a grown in-page Full keeps main's D1 failure (no extent,
/// no sealed-prefix credit): one `OpenRead`, no checkpoint.
#[test]
fn sp8c_grown_in_page_full_keeps_d1_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    base.cache.clear();
    let path = base.path.clone();
    let appended = row_bytes(source, 6..8);
    let (_, tail, seen, read) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_full,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(read.mode, ReadMode::Full(FullReason::StateMissing));
    assert_refused(&base.cache, &base.key, &tail, &seen, OPEN_READ, "SP-8c");
}

/// SP-8d (PARITY): an unchanged in-page Full verifies at commit through
/// `commit_after_native_completion`, with no debt.
#[test]
fn sp8d_unchanged_in_page_full_verifies_at_commit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    base.cache.clear();
    let started = sampled_scan::now_seconds();
    let (_, _, seen) = plain(&base.fixture, source, base.index, &base.cache);
    assert_eq!(seen.full_reasons[STATE_MISSING], 1);
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    let checkpoint = base
        .cache
        .retained_checkpoint(&base.key)
        .expect("a checkpoint");
    assert!(checkpoint.last_full_verified() >= started);
    assert_eq!(checkpoint.audit_debt(), None);
}

/// SP-9 (PARITY): a Tail larger than the singleton budget is a cursor job,
/// whose own extent limit (set by `cursor_start`) stays `frozen - start`. Busy, N1 and
/// group rows are the existing `codex_cursor_tests`, unmodified.
#[test]
fn sp9_cursor_tail_keeps_its_own_extent_limit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    sampled_scan::codex_cursor::with_test_limits(2048, 1024, 64, || {
        let base = baseline(source, 1, 6);
        assert!(
            len(&base.path) - base.sealed > 1024,
            "precondition: the Tail exceeds the singleton budget"
        );
        let mut job = None;
        let _ = page(&base.fixture, source, base.index, &base.cache, |scan| {
            if job.is_none() {
                job = scan
                    .active_file
                    .as_deref()
                    .and_then(in_page)
                    .filter(|read| read.cursor);
            }
        });
        let job = job.expect("precondition: the Tail started a cursor job");
        assert_eq!(job.mode, ReadMode::Tail);
        assert_eq!(job.start, base.sealed);
        assert_eq!(job.extent_limit, Some(job.frozen - job.start));
    });
}

/// SP-10 (PARITY, residual): growth after an `Unchanged` prepare keeps
/// main's behavior. The reader opens finished and reads nothing, and the
/// full-stamp commit refuses the grown object, whether the growth lands
/// before or after the reader's only step. Either way the copy that moved
/// into the parser is gone.
#[test]
fn sp10_unchanged_mode_growth_keeps_dropping_the_copy() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let fixture = Fixture::new(source);
    for id in 0..3 {
        fixture.append(&row(source, id));
    }
    let unchanged = |fixture: &Fixture| {
        let (old, _, _, _) = acquire(fixture, source, None, 100);
        let (mut parser, _, scope) = native_parser(fixture, source);
        assert_eq!(
            parser
                .prepare_acquisition(Some(old.expect("retained")), &scope, None, 101)
                .unwrap(),
            ReadMode::Unchanged
        );
        (parser, scope)
    };

    let (mut parser, scope) = unchanged(&fixture);
    fixture.append(&row(source, 3));
    assert!(parser.step().unwrap(), "an Unchanged reader opens finished");
    assert_eq!(parser.reader.consumed_bytes(), 0, "no byte is read");
    assert!(parser
        .retain_reduction(&scope, 101, crate::transcript_cache::ENTRY_BYTES)
        .is_err());

    let (mut parser, scope) = unchanged(&fixture);
    while !parser.step().unwrap() {}
    fixture.append(&row(source, 4));
    assert!(parser
        .retain_reduction(&scope, 101, crate::transcript_cache::ENTRY_BYTES)
        .is_err());
}

/// SP-11 (PARITY): Claude is out of scope. Its in-page Tail with an append
/// after the open step keeps main's D1 failure (`OpenRead`) and drops the
/// copy; nothing is published.
#[test]
fn sp11_claude_in_page_tail_with_append_keeps_main_failure() {
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
    assert_refused(&base.cache, &base.key, &tail, &seen, OPEN_READ, "SP-11");
}

mod fe_claude_in_page_read_tests;
