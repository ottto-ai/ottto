//! FE red-first fixtures: Claude appends while an in-page sampled `Full` or
//! `Tail` reads. The extension is the Claude twin of Codex in-page reads: a reader-relative extent
//! limit, an in-page genuine-EOF apply for a quiescent unterminated row, and a
//! grown-read route that publishes the sealed prefix `[0, s)` as a
//! certificate only: no checkpoint, copy, cache insert or Full credit, the
//! entry tagged as a sealed prefix, and the index left at the opened stamp.
//!
//! Tests marked RED assert FE's behavior and fail on main for the reason in
//! their doc comment (the "acquisition exceeds stable source" failure,
//! recorded as `OpenRead`, or `ScopeObject` at revalidation). Tests marked
//! GREEN assert main's behavior, which FE must keep, and pass on main.
//! Uses the EOF fixture seam; production FE lives in snapshots.rs.
//!
//! Conditions for an in-page read:
//! - publish only when `s` is at least the last committed size;
//! - a prefix never backs proof, v1, a family witness, or a verified
//!   request-census record;
//! - The sample-preserving-rewrite residual is accepted.
//!
//! This suite leaves out the Codex parent side-record reads. The
//! former `sp11_claude_in_page_tail_with_append_keeps_main_failure`
//! case now asserts the FE prefix publication.
use super::*;
use crate::claude_local_otel::{ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport};
use crate::snapshots::claude_request_census::claude_request_hash;

const CLAUDE: SnapshotSource = SnapshotSource::ClaudeCode;
/// The fixture's session id, its path stem, and so its family root.
const SESSION: &str = "native-tail-fixture";
const V1: &str = "session_exclusive_reported_usage:v1";

/// A body without the revision fields a stat-bound fingerprint sets, so a
/// prefix publication compares with the parse of a copy cut at `s`.
fn content(mut body: Value) -> Value {
    for item in body.as_array_mut().into_iter().flatten() {
        if let Some(item) = item.as_object_mut() {
            item.remove("source_file_fingerprint");
            item.remove("snapshot_fingerprint");
        }
    }
    body
}

/// The unsampled native body of the fixture's first `length` bytes: the file
/// is cut to `length`, parsed, and restored.
fn body_at(fixture: &ScanFixture, length: u64) -> Value {
    let path = &fixture.file.0;
    let bytes = bytes_of(path);
    overwrite(path, &bytes[..length as usize]);
    let body = full_body(fixture, CLAUDE);
    overwrite(path, &bytes);
    body
}

/// A later mtime at the same length, so the ordinary page re-selects the file.
fn touch(path: &Path) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    let modified = file.metadata().unwrap().modified().unwrap();
    file.set_modified(modified + std::time::Duration::from_secs(10))
        .unwrap();
}

/// The same bytes with the header row's text changed: equal length,
/// different head sample.
fn claude_changed_head(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let changed = text.replacen("Synthetic test", "Synthetic best", 1);
    assert_ne!(changed, text, "precondition: the header row names the text");
    changed.into_bytes()
}

fn requests(ids: Range<usize>) -> impl Iterator<Item = String> {
    ids.map(|id| format!("req-{id}"))
}

/// A request-census record holds sorted 8-byte prefixes.
fn census_hashes(ids: Range<usize>) -> Vec<u64> {
    let mut hashes = requests(ids)
        .map(|request| claude_request_hash(&request))
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes
}

/// Complete API and trace evidence for `ids`, matching `row(CLAUDE, id)`.
fn reports(ids: Range<usize>) -> (ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport) {
    let mut api = Vec::new();
    let mut trace = Vec::new();
    for id in ids {
        let request = format!("req-{id}");
        let n = 100 + 30 * id as u64;
        let mut row = crate::snapshots::tests::complete_api_row(
            SESSION,
            &request,
            id as u64 + 1,
            n,
            n / 10,
            0,
        );
        row.cache_read_tokens = n / 2;
        row.model = "fixture-model".into();
        row.fingerprint.clear();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&row).unwrap())
        );
        api.push(row);
        trace.push(crate::snapshots::tests::complete_trace_row(
            SESSION, &request, "",
        ));
    }
    (
        ClaudeLocalOtelLoadReport {
            evidence: BTreeMap::from([(SESSION.to_string(), api)]),
            health: Default::default(),
        },
        ClaudeTraceOwnershipLoadReport {
            evidence: BTreeMap::from([(SESSION.to_string(), trace)]),
            ..Default::default()
        },
    )
}

/// Runs the scan-level authority fold with complete evidence for `ids`.
/// Returns whether any item was rebuilt under the v1 contract.
fn mints_v1(index: &mut ScanIndex, result: &SourceScanResult, ids: Range<usize>) -> bool {
    let mut scan = result.clone();
    let (api, trace) = reports(ids);
    let _ = apply_claude_reported_usage_to_scan_with_identity(&mut scan, &api, &trace, index, None);
    scan.snapshots
        .iter()
        .any(|item| item.usage_accounting_contract.as_deref() == Some(V1))
}

/// FE's grown-route publication: nothing unreadable, no checkpoint or cache
/// insert, the index entry keeps the opened stamp, and the body is the native
/// parse of a copy cut at `s`.
fn assert_prefix_published(
    id: &str,
    base: &Baseline,
    index: &ScanIndex,
    result: SourceScanResult,
    seen: &Seen,
    read: &InPage,
    s: u64,
) {
    assert_eq!(
        seen.unreadable, 0,
        "{id}: no unreadable; causes={:?}",
        seen.causes
    );
    assert!(len(&base.path) > read.frozen, "precondition: grown");
    assert_eq!(
        index.files[&base.key].size_bytes, read.frozen,
        "{id}: the index keeps the opened stamp"
    );
    assert_eq!(
        content(production_body(CLAUDE, result)),
        content(body_at(&base.fixture, s)),
        "{id}: body == Full parse of a copy cut at s"
    );
}

/// The ordinary next page with no stored continuation: the growth is owed, not
/// lost. The state database paces a growth Full (main's `growth_read_admitted`,
/// one per `GROWTH_FULL_INTERVAL`), so the file waits with nothing unreadable,
/// then reads `Full(reason)` and matches the Full parse.
fn next_full(
    id: &str,
    base: &Baseline,
    index: ScanIndex,
    reason: usize,
) -> (ScanIndex, SourceScanResult) {
    let at = sampled_scan::now_seconds();
    let (index, paced, seen) = plain(&base.fixture, CLAUDE, index, &base.cache);
    assert_eq!(seen.modes, (0, 0, 0), "{id}: the paced page starts no read");
    assert_eq!(seen.unreadable, 0, "{id}: causes={:?}", seen.causes);
    assert!(
        paced.snapshots.is_empty(),
        "{id}: nothing new published yet"
    );
    sampled_scan::set_test_now(Some(at + sampled_audit::GROWTH_FULL_INTERVAL));
    let next = next_read(id, base, index, (1, 0, 0), Some(reason));
    sampled_scan::set_test_now(None);
    next
}

/// The ordinary next page from a committed head: the grown file continues as
/// a Tail, and matches the Full parse.
fn next_tail(id: &str, base: &Baseline, index: ScanIndex) -> (ScanIndex, SourceScanResult) {
    next_read(id, base, index, (0, 1, 0), None)
}

fn next_read(
    id: &str,
    base: &Baseline,
    index: ScanIndex,
    modes: (usize, usize, usize),
    reason: Option<usize>,
) -> (ScanIndex, SourceScanResult) {
    let oracle_index = ScanIndex {
        claude_reemission_exclusions: index.claude_reemission_exclusions.clone(),
        ..ScanIndex::default()
    };
    let (index, next, seen) = plain(&base.fixture, CLAUDE, index, &base.cache);
    assert_eq!(seen.modes, modes, "{id}: the next page's read");
    if let Some(reason) = reason {
        assert_eq!(seen.full_reasons[reason], 1, "{id}: next Full reason");
    }
    assert_eq!(seen.unreadable, 0, "{id}: causes={:?}", seen.causes);
    assert_eq!(
        content(production_body(CLAUDE, next.clone())),
        content({
            let (_, full, _) = production_scan(
                &base.fixture,
                CLAUDE,
                oracle_index,
                None,
                "stage2pre-full-oracle",
            );
            production_body(CLAUDE, full)
        }),
        "{id}: next body == Full parse"
    );
    (index, next)
}

/// A Claude file with rows 0..6 and no copy, read `Full(StateMissing)` while
/// rows 6..9 are appended after the open step.
struct Grown {
    base: Baseline,
    index: ScanIndex,
    result: SourceScanResult,
    seen: Seen,
}

fn grown_full() -> Grown {
    let mut base = baseline(CLAUDE, 4, 2);
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
        &base.cache,
        &base.index,
    );
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let index =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(std::mem::take(&mut base.index));
    let (index, result, seen, read) =
        page_injecting(&base.fixture, CLAUDE, index, &base.cache, is_full, |_| {
            append_raw(&path, &appended)
        });
    assert_eq!(
        read.mode,
        ReadMode::Full(FullReason::StateMissing),
        "precondition: an in-page Full"
    );
    Grown {
        base,
        index,
        result,
        seen,
    }
}

/// (RED): a Claude file with no copy; complete rows are appended after the
/// open step of its in-page `Full`. FE publishes `[0, s)` (here `s` = frozen)
/// with no checkpoint or cache insert and tags the entry as a sealed prefix;
/// the index keeps the opened stamp; the next page re-selects the grown file
/// and reads `Full` with body parity.
///
/// Growth stops at the frozen extent; it is never an `OpenRead` failure.
#[test]
fn fe_claude_append_during_full_read_publishes_sealed_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
        &base.cache,
        &base.index,
    );
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let index = std::mem::take(&mut base.index);
    let (index, full, seen, read) =
        page_injecting(&base.fixture, CLAUDE, index, &base.cache, is_full, |_| {
            append_raw(&path, &appended)
        });
    assert_eq!(read.mode, ReadMode::Full(FullReason::StateMissing));
    assert_eq!(seen.modes, (1, 0, 0));
    assert_prefix_published("SP-1c", &base, &index, full, &seen, &read, read.frozen);
    assert!(
        index.files[&base.key].has_prefix_provenance(),
        "SP-1c: the entry is tagged as a sealed prefix"
    );
    next_full("SP-1c", &base, index, STATE_MISSING);
}

/// (RED): the same during a Claude in-page `Tail` from `s` of a
/// committed head. FE publishes `[0, frozen)`, keeps no copy (no checkpoint
/// or cache insert), and tags the entry as a sealed prefix; the next page
/// continues from the head as a Tail with body parity.
///
/// Red on main: the stable-source failure (one `OpenRead`), and the taken copy is dropped.
#[test]
fn fe_claude_prime_append_during_tail_read_publishes_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let (index, tail, seen, read) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index.clone(),
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(read.start, base.sealed, "precondition: Tail from s");
    assert_eq!(seen.modes, (0, 1, 0));
    assert_prefix_published("SP-1c'", &base, &index, tail, &seen, &read, read.frozen);
    assert!(
        index.files[&base.key].has_prefix_provenance(),
        "SP-1c': the entry is tagged as a sealed prefix"
    );
    next_tail("SP-1c'", &base, index);
}

/// (RED): half a row at open, completed (plus more rows) after the
/// open step of a Claude `Tail`. FE seals at the row's start `s'` < frozen:
/// the row is absent now and present on the next read.
///
/// Red on main: the row's newline lies past the frozen length, so the reader
/// fails the stable-source check (one `OpenRead`).
#[test]
fn fe_claude_partial_row_at_frozen_grown_is_absent_now_present_next() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let row_start = len(&base.path);
    let split = row_bytes(CLAUDE, 6..7);
    let (head, rest) = split.split_at(split.len() / 2);
    append_raw(&base.path, head);
    let mut completion = rest.to_vec();
    completion.extend(row_bytes(CLAUDE, 7..9));
    let path = base.path.clone();
    let (index, tail, seen, read) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index.clone(),
        &base.cache,
        is_tail,
        |_| append_raw(&path, &completion),
    );
    assert_eq!(read.frozen, row_start + head.len() as u64);
    let prefix = content(production_body(CLAUDE, tail.clone()));
    assert_prefix_published("SP-2a-c", &base, &index, tail, &seen, &read, row_start);
    let (_, next) = next_tail("SP-2a-c", &base, index);
    assert_ne!(
        content(production_body(CLAUDE, next)),
        prefix,
        "SP-2a-c: the completed row is present on the next read"
    );
}

/// (GREEN): a quiescent unterminated last row in a Claude `Tail`,
/// not grown. Main's trailing-line rule applies it; the in-page EOF handling must keep this
/// byte-identical: body == Full parse, unsealed, no copy,
/// nothing unreadable.
#[test]
fn fe_claude_quiescent_unterminated_tail_keeps_main_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let last = row_bytes(CLAUDE, 6..7);
    append_raw(&base.path, &last[..last.len() - 1]);
    let (_, tail, seen) = plain(&base.fixture, CLAUDE, base.index, &base.cache);
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(
        production_body(CLAUDE, tail),
        full_body(&base.fixture, CLAUDE)
    );
}

/// Full (GREEN): the same unterminated last row read by a Claude
/// in-page `Full` keeps main's output: nothing unreadable, body == Full parse.
#[test]
fn fe_claude_quiescent_unterminated_full_keeps_main_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
        &base.cache,
        &base.index,
    );
    let last = row_bytes(CLAUDE, 6..7);
    append_raw(&base.path, &last[..last.len() - 1]);
    let (_, full, seen) = plain(&base.fixture, CLAUDE, base.index, &base.cache);
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(
        production_body(CLAUDE, full),
        full_body(&base.fixture, CLAUDE)
    );
}

/// (RED): setter units with `s` >= 64 KiB. The Claude `Tail` reader
/// stops at frozen with a reader-relative limit `frozen - start`.
///
/// Red on main: no in-page limit is set; the reader passes frozen and fails
/// the stable-source check (one `OpenRead`), so the EOF hook never sees this read.
#[test]
fn fe_claude_large_prefix_tail_stops_at_frozen_with_relative_limit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 320, 2);
    assert!(base.sealed >= 64 * 1024, "precondition: s >= 64 KiB");
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 322..325);
    let ((_, _, seen, read), at_eof) = with_eof_hook(
        &base.path,
        |_| {},
        || {
            page_injecting(
                &base.fixture,
                CLAUDE,
                base.index.clone(),
                &base.cache,
                is_tail,
                |_| append_raw(&path, &appended),
            )
        },
    );
    assert_eq!(
        seen.unreadable, 0,
        "SP-2c-c: no D1 failure; causes={:?}",
        seen.causes
    );
    let at_eof = at_eof.expect("SP-2c-c: the reader reached EOF");
    assert_eq!(
        at_eof.extent_limit,
        Some(read.frozen - read.start),
        "SP-2c-c: reader-relative limit"
    );
    assert_eq!(at_eof.start + at_eof.consumed, read.frozen);
}

/// SP-D2c (RED): a Claude `Full` reader reaches EOF exactly at frozen, then
/// rows are appended before revalidation reopens the path. FE takes the grown
/// route: nothing unreadable, `[0, frozen)` published as a certificate only.
///
/// Red on main: revalidation sees the grown identity (length, ctime, last
/// 4 KiB) and refuses the page as one `ScopeObject`.
#[test]
fn fe_claude_append_after_full_reader_eof_takes_grown_route() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
        &base.cache,
        &base.index,
    );
    let frozen = len(&base.path);
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let ((index, full, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| append_raw(&path, &appended),
        || plain(&base.fixture, CLAUDE, base.index.clone(), &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(at_eof.mode, ReadMode::Full(FullReason::StateMissing));
    assert_eq!(at_eof.start + at_eof.consumed, frozen);
    assert_prefix_published("SP-D2c", &base, &index, full, &seen, &at_eof, frozen);
    next_full("SP-D2c", &base, index, STATE_MISSING);
}

/// SP-D2c, Tail (RED): the same after a Claude `Tail` reader reaches EOF.
///
/// Red on main: one `ScopeObject` at revalidation.
#[test]
fn fe_claude_append_after_tail_reader_eof_takes_grown_route() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let frozen = len(&base.path);
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let ((index, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| append_raw(&path, &appended),
        || plain(&base.fixture, CLAUDE, base.index.clone(), &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(at_eof.mode, ReadMode::Tail);
    assert_eq!(at_eof.start + at_eof.consumed, frozen);
    assert_prefix_published("SP-D2c Tail", &base, &index, tail, &seen, &at_eof, frozen);
    next_tail("SP-D2c Tail", &base, index);
}

/// The strict reopen's first refusal in a walk: nothing unreadable, published
/// or retained, and the file requeued on its one same-walk retry.
fn assert_retried(
    index: &ScanIndex,
    result: &SourceScanResult,
    seen: &Seen,
    base: &Baseline,
    id: &str,
) {
    assert_eq!(
        (seen.unreadable, seen.causes),
        (0, [0; 8]),
        "{id}: retried, not refused"
    );
    assert!(result.snapshots.is_empty(), "{id}: nothing published");
    assert!(result.census_status.pending_work, "{id}: the file is owed");
    let walk = index
        .traversal
        .as_ref()
        .unwrap_or_else(|| panic!("{id}: the same walk owes the file"));
    assert_eq!(
        walk.residue.growth_retries.get(&base.key),
        Some(&false),
        "{id}: the walk's one retry is spent"
    );
    assert!(
        walk.pending_candidates.iter().any(|p| p.path == base.path),
        "{id}: requeued"
    );
}

/// A page that renames a same-bytes object over the path once an in-page
/// read whose mode satisfies `want` opens. `rereading`: the file is selected
/// as a watcher-hinted re-read that does not hold the census, in a walk that
/// has counted only its pending members as discovered (the tight bound).
/// Returns the page's walk window and the file's selection flags.
fn replaced_page(
    id: &str,
    source: SnapshotSource,
    base: &Baseline,
    index: ScanIndex,
    want: fn(ReadMode) -> bool,
    rereading: bool,
) -> (ScanIndex, SourceScanResult, Seen, (String, (bool, bool))) {
    let mut selected = None;
    let mut opened_mode = None;
    let (index, result, seen) = page(&base.fixture, source, index, &base.cache, |scan| {
        if selected.is_none()
            && let Some(read) = opened(scan)
        {
            opened_mode = Some(read.mode);
            if !want(read.mode) {
                return;
            }
            if rereading {
                scan.selected_flags.insert(base.key.clone(), (false, true));
                let members = scan.index.skipped_census_member_count();
                scan.discovered_file_count = members;
                let walk = scan.index.traversal.as_mut().unwrap();
                walk.counts.discovered_file_count = members;
            }
            selected = Some((
                scan.census_window_end.clone(),
                scan.selected_flags[&base.key],
            ));
            replace(&base.path, &bytes_of(&base.path));
        }
    });
    let selected = selected.unwrap_or_else(|| {
        panic!("{id}: expected in-page read did not open, got {opened_mode:?}; {seen:?}")
    });
    (index, result, seen, selected)
}

/// A new object renamed over the path during a `Tail`; the held FD
/// is not grown, so the strict reopen refuses. The first refusal keeps
/// nothing and requeues the file with its selection flags, also across a
/// restart. A re-read that did not hold the census is requeued as a census
/// member, so the walk cannot retire before the retry. A stable retry
/// publishes the cold-read body once; a second refusal in the walk is main's
/// `ScopeObject` and keeps the census red.
#[test]
fn fe_claude_replace_during_tail_not_grown_is_scope_object() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for (source, rereading) in [
        (CLAUDE, false),
        (CLAUDE, true),
        (SnapshotSource::Codex, false),
        (SnapshotSource::Codex, true),
        (SnapshotSource::Pi, false),
    ] {
        for refused_again in [false, true] {
            let id =
                format!("SP-3a-c {source:?} rereading={rereading} refused_again={refused_again}");
            let base = baseline(source, 4, 2);
            let first_id = format!("{id} first replacement");
            let (mut index, first, seen, (window, flags)) = replaced_page(
                &first_id,
                source,
                &base,
                base.index.clone(),
                is_tail,
                rereading,
            );
            assert_retried(&index, &first, &seen, &base, &first_id);
            let walk = index.traversal.as_ref().unwrap();
            assert_eq!(walk.census_window_end, window, "{id}: same walk");
            let pending = walk
                .pending_candidates
                .iter()
                .find(|p| p.path == base.path)
                .unwrap();
            assert_eq!(
                (pending.census_member, pending.watcher_hint),
                (true, flags.1),
                "{id}: the retry holds the census"
            );
            if rereading {
                assert_eq!(flags, (false, true), "precondition: {id}");
                assert!(!first.census_complete, "{id}: the walk waits");
                // Skipped == discovered before the promotion; the promoted
                // retry is counted in both, so the status stays valid.
                assert_eq!(
                    (
                        first.skipped_file_count_due_to_limit,
                        first.discovered_file_count,
                        walk.counts.discovered_file_count,
                    ),
                    (1, 1, 1),
                    "{id}: the promoted file is the sole skipped and discovered member"
                );
            } else {
                assert!(flags.0, "precondition: {id}");
            }
            // A restart resumes the saved walk with its spent allowance.
            let resumed: ScanTraversalCheckpoint =
                serde_json::from_value(serde_json::to_value(walk).unwrap()).unwrap();
            assert_eq!(resumed.residue, walk.residue, "{id}");
            index.traversal = Some(resumed);
            // A re-read's retry runs without moving the growth clock.
            if !rereading {
                sampled_scan::set_test_now(Some(
                    sampled_scan::now_seconds() + sampled_audit::GROWTH_FULL_INTERVAL,
                ));
            }
            if refused_again {
                let retry_id = format!("{id} second replacement");
                let (_, refused, seen, _) =
                    replaced_page(&retry_id, source, &base, index, is_full, false);
                sampled_scan::set_test_now(None);
                assert_refused(&refused, &seen, SCOPE_OBJECT, &retry_id);
                assert!(
                    refused.census_status.retryable_problem,
                    "{retry_id}: census red"
                );
            } else {
                let (_, retried, seen) = plain(&base.fixture, source, index, &base.cache);
                sampled_scan::set_test_now(None);
                assert_eq!(seen.unreadable, 0, "{id}: causes={:?}", seen.causes);
                assert_eq!(seen.modes, (1, 0, 0), "{id}: stable retry reads Full");
                assert_eq!(
                    content(production_body(source, retried)),
                    content(full_body(&base.fixture, source)),
                    "{id}: the retry publishes the cold-read body"
                );
            }
        }
    }
    paced_reopen_refuses_without_retry();
}

/// A Claude growth Full that spent its six-hour claim: a retry could only be
/// paced, unread, so the strict refusal records main's `ScopeObject` at once.
/// The clock does not move.
fn paced_reopen_refuses_without_retry() {
    let id = "SP-3a-c paced growth Full";
    let base = baseline(CLAUDE, 4, 2);
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
        &base.cache,
        &base.index,
    );
    let (index, refused, seen, _) =
        replaced_page(id, CLAUDE, &base, base.index.clone(), is_full, false);
    assert!(
        sampled_audit::growth_full_paced(&index, &base.key, sampled_scan::now_seconds()),
        "precondition: {id}: a retry would be paced"
    );
    assert_refused(&refused, &seen, SCOPE_OBJECT, id);
    assert!(refused.census_status.retryable_problem, "{id}: census red");
    assert!(
        index
            .traversal
            .as_ref()
            .is_none_or(|walk| !walk.residue.growth_retries.contains_key(&base.key)),
        "{id}: no retry spent"
    );
}

/// (GREEN): truncated below frozen during a Claude `Tail`, no regrow.
/// Not grown, so main's strict reopen refuses; nothing published, and the
/// file takes its one same-walk retry.
#[test]
fn fe_claude_truncate_during_tail_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let (path, sealed) = (base.path.clone(), base.sealed);
    let (index, tail, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index.clone(),
        &base.cache,
        is_tail,
        |_| truncate(&path, sealed),
    );
    assert_retried(&index, &tail, &seen, &base, "SP-4-c");
}

/// (GREEN): truncated at the open step (a short EOF), then regrown
/// past frozen before completion. The grown-prefix traversal check fails, so main's
/// strict reopen refuses and the file takes its one same-walk retry.
#[test]
fn fe_claude_truncate_then_regrow_after_short_eof_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let (path, sealed) = (base.path.clone(), base.sealed);
    let mut regrown = bytes_of(&base.path)[sealed as usize..].to_vec();
    regrown.extend(row_bytes(CLAUDE, 6..8));
    let regrow_path = base.path.clone();
    let ((index, tail, seen, read), at_eof) = with_eof_hook(
        &base.path,
        move |_| append_raw(&regrow_path, &regrown),
        || {
            page_injecting(
                &base.fixture,
                CLAUDE,
                base.index.clone(),
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
    assert_retried(&index, &tail, &seen, &base, "SP-5a-c");
}

/// (GREEN): after the Claude reader passes frozen, the file is
/// rewritten past frozen with a different head. Main's revalidation and the grown-prefix
/// head sample both refuse as `ScopeObject`; nothing published.
#[test]
fn fe_claude_regrow_after_reader_passes_frozen_with_new_head_refuses() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let mut regrown = claude_changed_head(&bytes_of(&base.path));
    regrown.extend(row_bytes(CLAUDE, 6..8));
    let ((_, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| overwrite(&path, &regrown),
        || plain(&base.fixture, CLAUDE, base.index, &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(at_eof.start + at_eof.consumed, at_eof.frozen);
    assert_refused(&tail, &seen, SCOPE_OBJECT, "SP-5b-c");
}

/// (GREEN): after the Claude reader passes frozen, the file is
/// rewritten to exactly frozen with a different head. Not grown, so main's
/// strict reopen refuses and the file takes its one same-walk retry.
#[test]
fn fe_claude_rewrite_to_exactly_frozen_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let rewritten = claude_changed_head(&bytes_of(&base.path));
    let ((index, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| overwrite(&path, &rewritten),
        || plain(&base.fixture, CLAUDE, base.index.clone(), &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(len(&base.path), at_eof.frozen, "precondition: not grown");
    assert_retried(&index, &tail, &seen, &base, "SP-5c-c");
}

/// Residual, Claude (RED; EXPECTED RESIDUAL, not mutation
/// detection): after the reader passed them, already-read tail bytes outside
/// both 4 KiB sample windows are truncated and regrown with a different row
/// of the same length, plus growth. The grown-prefix check accepts it as the cursor does: the
/// page publishes the bytes it read and tags the entry as a sealed prefix;
/// only a later Full sees the edit.
///
/// Red on main: revalidation sees the grown identity and refuses the page as
/// one `ScopeObject`.
#[test]
fn fe_claude_residual_sample_preserving_rewrite_after_read_is_accepted() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 30, 30);
    let frozen = len(&base.path);
    assert!(
        base.sealed > 4096,
        "precondition: head window inside [0, s)"
    );
    let original = bytes_of(&base.path);
    let edited_row = base.sealed as usize;
    let row_len = row_bytes(CLAUDE, 30..31).len();
    assert!(
        edited_row + row_len < frozen as usize - 4096,
        "precondition: the edit is outside the boundary window"
    );
    let text = String::from_utf8(original[edited_row..edited_row + row_len].to_vec()).unwrap();
    let edited = text.replacen("fixture-model", "fixture-modem", 1);
    assert_ne!(edited, text);
    let mut regrown = original[edited_row..].to_vec();
    regrown[..row_len].copy_from_slice(edited.as_bytes());
    regrown.extend(row_bytes(CLAUDE, 60..62));
    let frozen_body = full_body(&base.fixture, CLAUDE);
    let path = base.path.clone();
    let ((index, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| {
            truncate(&path, edited_row as u64);
            append_raw(&path, &regrown);
        },
        || plain(&base.fixture, CLAUDE, base.index, &base.cache),
    );
    assert!(at_eof.is_some(), "precondition: the reader reached EOF");
    assert_eq!(
        seen.unreadable, 0,
        "SP-5 residual (Claude): accepted; causes={:?}",
        seen.causes
    );
    assert_eq!(
        content(production_body(CLAUDE, tail)),
        content(frozen_body),
        "SP-5 residual (Claude): the bytes read before the edit are published"
    );
    // FE2: the grown publication is tagged as a sealed prefix. A later Full
    // of a file with no stored continuation sees the interior rewrite.
    assert!(index.files[&base.key].has_prefix_provenance());
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(&base.cache, &index);
    sampled_scan::set_test_now(Some(
        sampled_scan::now_seconds() + sampled_audit::GROWTH_FULL_INTERVAL,
    ));
    let (_, next, full) = plain(&base.fixture, CLAUDE, index, &base.cache);
    sampled_scan::set_test_now(None);
    assert_eq!(
        full.full_reasons[STATE_MISSING], 1,
        "FE2: prefix has no checkpoint, so Full is StateMissing"
    );
    assert_eq!(full.unreadable, 0, "FE2: the Full completes");
    assert_eq!(
        content(production_body(CLAUDE, next)),
        content(full_body(&base.fixture, CLAUDE)),
        "FE2: the Full repairs the body"
    );
}

/// The Claude baseline plus a malformed row inside `[s, frozen)`.
fn claude_lossy_baseline() -> Baseline {
    let base = baseline(CLAUDE, 4, 1);
    append_raw(&base.path, b"{\"type\":\"assistant\",\"message\":\n");
    append_raw(&base.path, &row_bytes(CLAUDE, 5..6));
    base
}

/// Bad physical rows no longer block a quiescent Tail's valid siblings.
#[test]
fn fe_claude_bad_record_tail_keeps_valid_siblings() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = claude_lossy_baseline();
    let (index, result, seen) = plain(&base.fixture, CLAUDE, base.index.clone(), &base.cache);
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(result.malformed_json_line_count, 1);
    let continuation = crate::snapshots::e2_pipeline_scan_fixture::continuation_for_test(
        CLAUDE,
        &base.cache,
        &index,
        &base.key,
    )
    .unwrap();
    assert_eq!(continuation.sealed_offset(), len(&base.path));
    assert_eq!(
        content(production_body(CLAUDE, result)),
        content(full_body(&base.fixture, CLAUDE))
    );
    append_raw(&base.path, &row_bytes(CLAUDE, 6..7));
    let (_, next, modes) = production_scan_hinted(
        &base.fixture,
        CLAUDE,
        index,
        Some(base.cache.clone()),
        NAMESPACE,
        std::slice::from_ref(&base.path),
    );
    // Deliver the real watcher's exact hint; listing time alone does not
    // promise a changed member will be selected from an unchanged directory.
    assert_eq!(modes, (0, 1, 0));
    assert_eq!(
        content(production_body(CLAUDE, next)),
        content(full_body(&base.fixture, CLAUDE))
    );
}

/// A grown Tail publishes the same sealed prefix with a bad physical row;
/// the post-open append stays owed, with no retained copy or Full credit.
#[test]
fn fe_claude_bad_record_grown_tail_keeps_valid_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = claude_lossy_baseline();
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..8);
    let (index, tail, seen, read) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index.clone(),
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(tail.malformed_json_line_count, 1);
    assert_prefix_published("SP-7b-c", &base, &index, tail, &seen, &read, read.frozen);
}

/// An older build's complete tag whose deadline has passed still Tails the
/// append: no `AuditDue` Full, and the tag is gone afterwards.
#[test]
fn fe_claude_past_due_complete_tag_tails_and_is_stripped() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    let due = sampled_scan::now_seconds() - 1;
    base.index
        .files
        .get_mut(&base.key)
        .unwrap()
        .scan_identity_version = Some(format!(
        "{LOCAL_SCAN_INDEX_IDENTITY_VERSION}+sampled_unverified:v2:{due}:c"
    ));
    let index = std::mem::take(&mut base.index);
    let (index, result, seen) = plain(&base.fixture, CLAUDE, index, &base.cache);
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.full_reasons[AUDIT_DUE], 0);
    assert_eq!(seen.unreadable, 0);
    assert_eq!(
        index.files[&base.key].scan_identity_version.as_deref(),
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    );
    assert_eq!(
        content(production_body(CLAUDE, result)),
        content(full_body(&base.fixture, CLAUDE))
    );
}

/// Claude, Codex and Pi share frozen extents for ordinary Full and Tail reads.
/// Their next pass includes the append, with cold-read body parity.
#[test]
fn fe_claude_codex_in_page_full_with_append_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [CLAUDE, SnapshotSource::Codex, SnapshotSource::Pi] {
        for full in [true, false] {
            for partial in [false, true] {
                let base = baseline(source, 4, 2);
                // No continuation: the committed head on its route is retired.
                if full {
                    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
                        &base.cache,
                        &base.index,
                    );
                }
                let path = base.path.clone();
                let sealed = len(&path);
                let appended = if partial {
                    let last = row_bytes(source, 6..7);
                    append_raw(&path, &last[..last.len() - 1]);
                    let mut completion = b"\n".to_vec();
                    completion.extend(row_bytes(source, 7..8));
                    completion
                } else {
                    row_bytes(source, 6..8)
                };
                let (index, prefix, seen, read) = page_injecting(
                    &base.fixture,
                    source,
                    base.index.clone(),
                    &base.cache,
                    if full { is_full } else { is_tail },
                    |_| append_raw(&path, &appended),
                );
                assert_eq!(seen.unreadable, 0, "{source:?}: {:?}", seen.causes);
                assert_eq!(read.extent_limit, Some(read.frozen - read.start));
                assert_eq!(index.files[&base.key].size_bytes, read.frozen);
                assert!(index.files[&base.key].has_prefix_provenance());
                let grown = bytes_of(&path);
                if partial && !full {
                    assert_eq!(
                        tail_source::committed_sealed_offset(source, &index, &base.key),
                        Some(base.sealed),
                        "the withheld fragment cannot advance the saved Tail pointer"
                    );
                }
                overwrite(&path, &grown[..sealed as usize]);
                let expected = content(full_body(&base.fixture, source));
                overwrite(&path, &grown);
                assert_eq!(content(production_body(source, prefix)), expected);
                if full {
                    sampled_scan::set_test_now(Some(
                        sampled_scan::now_seconds() + sampled_audit::GROWTH_FULL_INTERVAL,
                    ));
                }
                let (_, next, seen) = plain(&base.fixture, source, index, &base.cache);
                sampled_scan::set_test_now(None);
                assert_eq!(seen.unreadable, 0, "{source:?}: {:?}", seen.causes);
                assert_eq!(
                    content(production_body(source, next)),
                    content(full_body(&base.fixture, source))
                );
            }
        }
    }
    stable_extent_does_not_hide_io_failure();
}

/// A real failed OS read keeps OpenRead, even with growth beside it.
fn stable_extent_does_not_hide_io_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [CLAUDE, SnapshotSource::Codex, SnapshotSource::Pi] {
        let base = baseline(source, 4, 2);
        let mut injected = false;
        let (_, result, seen) = page(&base.fixture, source, base.index, &base.cache, |scan| {
            if !injected && opened(scan).is_some() {
                append_raw(&base.path, &row_bytes(source, 6..8));
                // Same file identity, but read(2) on a write-only FD fails
                // with EBADF. No reader error or census cause is mocked.
                *scan
                    .active_file
                    .as_mut()
                    .unwrap()
                    .parser
                    .reader
                    .reader
                    .get_mut() = OpenOptions::new().write(true).open(&base.path).unwrap();
                injected = true;
            }
        });
        assert!(injected);
        assert_refused(&result, &seen, OPEN_READ, "OS read failure");
    }
}

/// With s below the last committed size: the last page committed
/// a file ending in a complete but unterminated row (size C, main's
/// trailing-line rule). The file is re-selected at size C and, during its
/// in-page `Full`, the row's newline and more rows are appended. The last newline at or below frozen (= C) is the row's start,
/// below C, so defer only this file and publish no weaker body: no
/// copy, and the committed entry stands.
#[test]
fn fe_claude_source_s_below_last_committed_size_publishes_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanFixture::new(CLAUDE);
    let path = fixture.file.0.clone();
    append_raw(&path, &row_bytes(CLAUDE, 0..4));
    let last = row_bytes(CLAUDE, 4..5);
    append_raw(&path, &last[..last.len() - 1]);
    let committed = len(&path);
    let key = local_index_key(&path);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, seen) = plain(&fixture, CLAUDE, ScanIndex::default(), &cache);
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(
        index.files[&key].size_bytes, committed,
        "precondition: the last committed size includes the unterminated row"
    );
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(&cache, &index);
    touch(&path);
    let mut completion = b"\n".to_vec();
    completion.extend(row_bytes(CLAUDE, 5..7));
    let append_path = path.clone();
    let mut read = None;
    let mut selected = None;
    let (index, full, seen) = page(&fixture, CLAUDE, index, &cache, |scan| {
        if read.is_none() {
            if let Some(opened) = opened(scan) {
                assert!(is_full(opened.mode));
                selected = Some((scan.census_window_end.clone(), scan.selected_flags[&key]));
                append_raw(&append_path, &completion);
                read = Some(opened);
            }
        }
    });
    let read = read.expect("weaker-body read opened");
    assert_eq!(read.frozen, committed, "precondition: frozen = C");
    assert_eq!(
        seen.unreadable, 0,
        "SOURCE: file-only deferral; causes={:?}",
        seen.causes
    );
    assert!(full.snapshots.is_empty(), "SOURCE: never a weaker body");
    assert_eq!(
        index.files[&key].size_bytes, committed,
        "the committed entry stands"
    );
    let (window, flags) = selected.unwrap();
    let walk = index.traversal.as_ref().expect("same walk still owes file");
    assert_eq!(walk.census_window_end, window);
    assert_eq!(walk.residue.growth_retries.get(&key), Some(&false));
    let pending = walk
        .pending_candidates
        .iter()
        .find(|p| p.path == path)
        .unwrap();
    assert_eq!((pending.census_member, pending.watcher_hint), flags);
    assert!(full.census_status.pending_work);
    sampled_scan::set_test_now(Some(
        sampled_scan::now_seconds() + sampled_audit::GROWTH_FULL_INTERVAL,
    ));
    let (index, recovered, seen) = plain(&fixture, CLAUDE, index, &cache);
    sampled_scan::set_test_now(None);
    assert_eq!(seen.unreadable, 0, "weaker-body blocker cleared");
    assert_eq!(index.files[&key].size_bytes, len(&path));
    assert_eq!(
        content(production_body(CLAUDE, recovered)),
        content(full_body(&fixture, CLAUDE)),
    );
}

/// Census-record control (GREEN): in this fixture a quiescent sampled `Full` writes a
/// source-verified request-census record of its requests, and a quiescent `Tail` (which
/// verifies no source) writes an unverified one.
#[test]
fn fe_claude_control_quiescent_full_verified_tail_unverified() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 0);
    let record = base
        .index
        .claude_request_census_for_test()
        .get(&base.key)
        .expect("control: the Full writes a D1 record");
    assert!(!record.unverified_for_test(), "control: Full is verified");
    assert_eq!(
        record.request_hashes_for_test(),
        census_hashes(0..4).as_slice()
    );
    append_raw(&base.path, &row_bytes(CLAUDE, 4..6));
    let (index, _, seen) = plain(&base.fixture, CLAUDE, base.index.clone(), &base.cache);
    assert_eq!(seen.modes, (0, 1, 0));
    let record = index
        .claude_request_census_for_test()
        .get(&base.key)
        .expect("control: the Tail writes a D1 record");
    assert!(
        record.unverified_for_test(),
        "control: Tail is not source-verified"
    );
    assert_eq!(
        record.request_hashes_for_test(),
        census_hashes(0..6).as_slice()
    );
}

/// Census record (RED): FE's prefix parse writes a request-census record of the prefix's
/// requests that is never source-verified, and the next read replaces it
/// with the grown file's requests.
///
/// Red on main: the stable-source failure (one `OpenRead`); main invalidates the record.
#[test]
fn fe_claude_source_prefix_record_is_unverified_and_replaced_next_read() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let grown = grown_full();
    assert_eq!(
        grown.seen.unreadable, 0,
        "SOURCE D1: no unreadable; causes={:?}",
        grown.seen.causes
    );
    let record = grown
        .index
        .claude_request_census_for_test()
        .get(&grown.base.key)
        .expect("SOURCE D1: the prefix parse writes a record")
        .clone();
    assert!(
        record.unverified_for_test(),
        "SOURCE D1: a prefix record is never source-verified"
    );
    assert_eq!(
        record.request_hashes_for_test(),
        census_hashes(0..6).as_slice(),
        "SOURCE D1: the record describes the prefix"
    );
    let (index, _) = next_full("SOURCE D1", &grown.base, grown.index, STATE_MISSING);
    let next = index
        .claude_request_census_for_test()
        .get(&grown.base.key)
        .expect("SOURCE D1: the next read writes a record");
    assert_eq!(
        next.request_hashes_for_test(),
        census_hashes(0..9).as_slice(),
        "SOURCE D1: replaced by the next read"
    );
}

/// Real FE prefix provenance, rather than ordinary census-record debt,
/// excludes API rows beyond the published native prefix.
#[test]
fn fe_claude_unverified_source_api_rows_beyond_prefix_cannot_mint_v1() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    assert_eq!(grown.seen.unreadable, 0);
    assert!(!grown.result.snapshots.is_empty());
    let (positive, counts) = observe(|| mints_v1(&mut grown.index, &grown.result, 0..9));
    assert!(!positive);
    assert_eq!(
        counts.prefix_excluded_bodies,
        grown.result.snapshots.len() as u64
    );
    assert!(!grown
        .index
        .claude_usage_family_witnesses
        .contains_key(SESSION));
}

/// Both explicit owned-start and file-birth posture admission stay closed
/// for a prefix. Usage remains present on the ordinary unproven path.
#[test]
fn fe_claude_prefix_cannot_admit_explicit_or_file_birth_posture() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for explicit in [false, true] {
        let mut grown = grown_full();
        assert_eq!(grown.seen.unreadable, 0);
        for item in &mut grown.result.snapshots {
            item.claude_context_curve_owned_start_proven = explicit;
            item.peak_context_fill_tokens = Some(1234);
        }
        assert!(!mints_v1(&mut grown.index, &grown.result, 0..9));
        let (api, trace) = reports(0..9);
        let disposition = apply_claude_reported_usage_to_scan_with_identity(
            &mut grown.result,
            &api,
            &trace,
            &mut grown.index,
            None,
        );
        assert!(!grown.result.snapshots.is_empty());
        assert!(grown.result.snapshots.iter().all(|item| {
            item.usage_accounting_contract.is_none() && item.peak_context_fill_tokens.is_none()
        }));
        assert!(disposition.posture_admission(SESSION).is_none());
    }
}

/// Growth after the genuine-EOF apply must not certify the row it
/// applied outside the last newline. No new reader/acquisition state needed.
#[test]
fn fe_claude_growth_after_applied_fragment_keeps_strict_identity() {
    let fixture = Fixture::new(CLAUDE);
    let mut bytes = row_bytes(CLAUDE, 0..2);
    assert_eq!(bytes.pop(), Some(b'\n'));
    append_raw(&fixture.0, &bytes);
    let (mut parser, _, scope) = native_parser(&fixture, CLAUDE);
    parser
        .prepare_acquisition(None, &scope, sampled_scan::now_seconds())
        .unwrap();
    let frozen = parser.reader.acquisition.as_ref().unwrap().frozen_length();
    parser.reader.set_extent_limit(frozen);
    while !parser.step().unwrap() {}
    assert!(parser.reader.sealed_fragment());
    assert!(parser.apply_sealed_fragment());
    assert!(parser.reader.last_complete_line_end() < parser.reader.consumed_bytes());
    append_raw(&fixture.0, b"\n");
    append_raw(&fixture.0, &row_bytes(CLAUDE, 2..3));
    assert!(
        parser.commit_grown_prefix(&fixture.0, &scope, 0).is_none(),
        "E1-applied bytes beyond the seal cannot get a grown grant"
    );
}

/// Source loss discovered during response finalization excludes that response
/// while a grown prefix preserves every healthy response without Full credit.
#[test]
fn fe_claude_finalizer_response_loss_keeps_valid_grown_prefix() {
    // Resolver conflict as drop residue is gate-off only; gate on it is a disclosed `e2` conflict.

    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
        &base.cache,
        &base.index,
    );
    let mut conflict = row(CLAUDE, 5);
    conflict["message"]["usage"]["input_tokens"] = json!(999);
    conflict["message"]["usage"]["output_tokens"] = json!(0);
    let mut reducer = SnapshotAccumulator::new(CLAUDE);
    apply_claude_code_line(&row(CLAUDE, 5), &mut reducer);
    apply_claude_code_line(&conflict, &mut reducer);
    assert_eq!(
        reducer.dropped_usage_record_count, 0,
        "no loss before finalization"
    );
    reducer.finalize_claude_responses();
    assert_eq!(
        reducer.dropped_usage_record_count, 0,
        "unlisted E2 retains the disclosed resolver conflict"
    );
    let mut bytes = serde_json::to_vec(&conflict).unwrap();
    bytes.push(b'\n');
    append_raw(&base.path, &bytes);
    let path = base.path.clone();
    let (index, result, seen, read) = page_injecting(
        &base.fixture,
        CLAUDE,
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(base.index.clone()),
        &base.cache,
        is_full,
        |_| append_raw(&path, &row_bytes(CLAUDE, 6..9)),
    );
    assert_eq!(seen.unreadable, 0);
    assert_eq!(result.dropped_usage_record_count, 1);
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(
        (
            result.snapshots[0].input_tokens,
            result.snapshots[0].output_tokens,
            result.snapshots[0].request_count
        ),
        (800, 80, 5)
    );
    assert_eq!(index.files[&base.key].size_bytes, read.frozen);
}

/// An ineligible Full still has a ReadPlan, but the extent limit never froze its reader.
/// Growth after its native EOF must not enter the optional prefix route.
#[test]
fn fe_claude_full_without_admission_keeps_strict_completion() {
    let fixture = Fixture::new(CLAUDE);
    append_raw(&fixture.0, &row_bytes(CLAUDE, 0..2));
    let (mut parser, _, scope) = native_parser(&fixture, CLAUDE);
    parser
        .prepare_acquisition(None, &scope, sampled_scan::now_seconds())
        .unwrap();
    while !parser.step().unwrap() {}
    assert_eq!(parser.reader.extent_limit, None);
    append_raw(&fixture.0, &row_bytes(CLAUDE, 2..3));
    assert!(parser.commit_grown_prefix(&fixture.0, &scope, 0).is_none());
}

/// Persistence must preserve the exclusion even without a census record and after key drift.
#[test]
fn fe_claude_prefix_provenance_round_trips_without_a_census_record() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    let tag = grown.index.files[&grown.base.key]
        .scan_identity_version
        .clone();
    grown
        .index
        .claude_request_census_mut_for_test()
        .invalidate_keeping_birth_for_test(&grown.base.key);
    let moved = local_index_key(&grown.base.path.with_file_name("physical-other.jsonl"));
    let entry = grown.index.files.remove(&grown.base.key).unwrap();
    grown.index.files.insert_shared(moved.clone(), entry);
    let path = grown.base.fixture.root.join("prefix-index.json");
    crate::snapshots::e2_pipeline_scan_fixture::save_for_test(&mut grown.index, &path);
    let mut loaded =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::load(&path).unwrap());
    assert_eq!(loaded.files[&moved].scan_identity_version, tag);
    assert!(!mints_v1(&mut loaded, &grown.result, 0..9));
}

/// The recovery Tail starts from a retained COMPLETE pre-prefix reduction,
/// replays all later rows and revalidates EOF. No FE prefix is cached.
#[test]
fn fe_claude_prefix_then_complete_tail_at_eof_clears_the_prefix_tag() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // The prefix comes from a grown Tail; the committed head is the complete
    // baseline the next read replays.
    let mut base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let (index, result, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(std::mem::take(&mut base.index)),
        &base.cache,
        is_tail,
        |_| append_raw(&path, &row_bytes(CLAUDE, 6..9)),
    );
    assert_eq!(seen.unreadable, 0);
    base.index = index;
    // Assess exclusion without carrying the separate same-window member-
    // change invalidation into this provenance-recovery regression.
    let mut prefix_observation = base.index.clone();
    assert!(!mints_v1(&mut prefix_observation, &result, 0..9));
    let ((index, _, seen), counts) =
        observe(|| plain(&base.fixture, CLAUDE, base.index, &base.cache));
    assert_eq!(counts.prefix_tag_clears, 1);
    assert_eq!(
        seen.modes,
        (0, 1, 0),
        "complete baseline reduction is replayed"
    );
    assert_eq!(seen.unreadable, 0);
    assert!(
        !index.files[&base.key].has_sampled_tag(),
        "the complete Tail clears the tag"
    );
    assert!(index
        .claude_request_census_for_test()
        .get(&base.key)
        .unwrap()
        .unverified_or_twin());
}

/// A later grown Tail publication still owes the prefix exclusion, even if
/// its retained baseline was complete. Appending to a prefix is not clearing.
#[test]
fn fe_claude_prefix_then_grown_tail_does_not_clear_provenance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let (index, _, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        std::mem::take(&mut base.index),
        &base.cache,
        is_tail,
        |_| append_raw(&path, &row_bytes(CLAUDE, 6..9)),
    );
    assert_eq!(seen.unreadable, 0);
    assert!(index.files[&base.key].has_prefix_provenance());
    let ((mut index, result, seen, _), counts) = observe(|| {
        page_injecting(
            &base.fixture,
            CLAUDE,
            index,
            &base.cache,
            |mode| mode == ReadMode::Tail,
            |_| append_raw(&path, &row_bytes(CLAUDE, 9..10)),
        )
    });
    assert_eq!(seen.unreadable, 0);
    assert_eq!(counts.prefix_tag_clears, 0);
    assert!(index.files[&base.key].has_prefix_provenance());
    assert!(!mints_v1(&mut index, &result, 0..10));
}

/// Control: the frozen-extent route marks its grown prefix after `record` in the same
/// completion, so a prefix still ends `p` from a clean, replay-reset or
/// legacy prior entry, and stays excluded.
#[test]
fn fe_grown_prefix_still_marks_prefix_after_ordinary_record() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for reset in [
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
        None,
        Some("semantic_sync:v1"),
    ] {
        let mut base = baseline(CLAUDE, 4, 2);
        crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
            &base.cache,
            &base.index,
        );
        let path = base.path.clone();
        let mut index = std::mem::take(&mut base.index);
        index
            .files
            .get_mut(&base.key)
            .unwrap()
            .scan_identity_version = reset.map(Into::into);
        let (mut index, result, seen, read) =
            page_injecting(&base.fixture, CLAUDE, index, &base.cache, is_full, |_| {
                append_raw(&path, &row_bytes(CLAUDE, 6..9))
            });
        assert!(
            is_full(read.mode),
            "{reset:?}: precondition: an in-page Full"
        );
        assert_eq!(seen.unreadable, 0, "{reset:?}: causes={:?}", seen.causes);
        let entry = &index.files[&base.key];
        assert!(entry.has_prefix_provenance(), "{reset:?}");
        assert!(
            entry
                .scan_identity_version
                .as_deref()
                .unwrap()
                .ends_with(":p"),
            "{reset:?}"
        );
        assert!(!mints_v1(&mut index, &result, 0..9), "{reset:?}");
    }
}

/// Only loss-free, identity-complete request-census shapes may bind a
/// recomposed body. An identity-incomplete record keeps its root excluded
/// until a Full read verifies it.
#[test]
fn fe_identity_incomplete_record_cannot_bind_recomposed_body() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusRecord, ClaudeRequestCensusShape as Shape,
    };
    let fingerprint = "a".repeat(64);
    for (shape, hashes, binds) in [
        (Shape::Exact, vec![1], true),
        (Shape::Empty, vec![], true),
        (Shape::IdentityIncomplete, vec![1], false),
        (Shape::Lossy, vec![1], false),
        (Shape::OverBudget, vec![], false),
    ] {
        let record = ClaudeRequestCensusRecord::synthetic_for_test(&fingerprint, 1, shape, hashes)
            .with_unverified_for_test(true);
        assert!(record.unverified_or_twin(), "{shape:?}");
        assert_eq!(record.can_bind_recomposed_body(), binds, "{shape:?}");
    }
}

/// Historical replay keeps a Claude FE prefix entry: its sealed-prefix tag is
/// file-owned recovery evidence, so a replay reset neither drops it nor turns
/// it into `None` or a clean identity.
#[test]
fn fe_prefix_entry_survives_replay_reset_without_positive_verdict() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    let key = grown.base.key.clone();
    assert!(grown.index.files[&key].has_prefix_provenance());
    grown
        .index
        .prepare_historical_replay("fe-prefix-replay".into());
    let entry = grown
        .index
        .files
        .get(&key)
        .expect("replay retains a prefix entry");
    assert!(entry.has_prefix_provenance());
    assert!(entry
        .scan_identity_version
        .as_deref()
        .unwrap()
        .ends_with(":p"));
    assert!(!mints_v1(&mut grown.index, &grown.result, 0..9));
}
