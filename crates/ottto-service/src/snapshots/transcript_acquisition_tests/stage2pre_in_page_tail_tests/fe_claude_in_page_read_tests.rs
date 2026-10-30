//! FE red-first fixtures: Claude appends while an in-page sampled `Full` or
//! `Tail` reads. FE is the Claude twin of Stage2-pre: a reader-relative extent
//! limit (H1c), an in-page E1 for a quiescent unterminated row (H2c), and a
//! grown-read route (H3c) that publishes the sealed prefix `[0, s)` as a
//! certificate only: no checkpoint, copy, cache insert or audit credit, the
//! prepared debt re-staged, and the index left at the opened stamp.
//!
//! Tests marked RED assert FE's behavior and fail on main for the reason in
//! their doc comment (the D1 "acquisition exceeds stable source" failure,
//! recorded as `OpenRead`, or `ScopeObject` at revalidation). Tests marked
//! GREEN assert main's behavior, which FE must keep, and pass on main.
//! Uses the EOF fixture seam from #670; production FE lives in snapshots.rs.
//!
//! SOURCE conditions pinned here (qualified YES, d680b524):
//! - publish only when `s` is at least the last committed size;
//! - a prefix never backs proof, v1, a family witness, or a verified D1
//!   record;
//! - FE2: the sample-preserving-rewrite residual is accepted (SP-5 residual).
//!
//! Not added: #660 side reads (SP-11; #660 is not on main). Stage2-pre's
//! former `sp11_claude_in_page_tail_with_append_keeps_main_failure` now
//! asserts the FE prefix publication.
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

/// Pending keys request ids by their full SHA-256 hex.
fn pending_hashes(ids: Range<usize>) -> BTreeSet<String> {
    requests(ids)
        .map(|request| format!("{:x}", Sha256::digest(request.as_bytes())))
        .collect()
}

/// A D1 record holds sorted 8-byte prefixes.
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
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "{id}: no checkpoint or cache insert"
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

/// The ordinary next page: the grown file re-selects (SourceChanged), reads
/// `Full(reason)` without a copy, and matches the Full parse.
fn next_full(
    id: &str,
    base: &Baseline,
    index: ScanIndex,
    reason: usize,
) -> (ScanIndex, SourceScanResult) {
    let (index, next, seen) = plain(&base.fixture, CLAUDE, index, &base.cache);
    assert_eq!(seen.modes, (1, 0, 0), "{id}: the next page reads Full");
    assert_eq!(seen.full_reasons[reason], 1, "{id}: next Full reason");
    assert_eq!(seen.unreadable, 0, "{id}: causes={:?}", seen.causes);
    assert_eq!(
        content(production_body(CLAUDE, next.clone())),
        content(full_body(&base.fixture, CLAUDE)),
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
    base.cache.clear();
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let index = std::mem::take(&mut base.index);
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

/// A fresh Claude fixture with rows 0..6, read once (sampled, `Full`).
fn quiescent() -> (ScanFixture, ScanIndex, SourceScanResult) {
    let fixture = ScanFixture::new(CLAUDE);
    append_raw(&fixture.file.0, &row_bytes(CLAUDE, 0..6));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, result, seen) = plain(&fixture, CLAUDE, ScanIndex::default(), &cache);
    assert_eq!(seen.modes, (1, 0, 0), "precondition: one Full read");
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert!(result.census_complete, "precondition: a healthy terminal");
    (fixture, index, result)
}

/// SP-1c (RED): a Claude file with no copy and a prepared (not yet due)
/// audit debt; complete rows are appended after the open step of its in-page
/// `Full`. FE publishes `[0, s)` (here `s` = frozen) with no checkpoint or
/// cache insert and no `complete_full_audit` (the debt stays staged at its
/// deadline); the index keeps the opened stamp; the next page re-selects the
/// grown file and reads `Full` with body parity.
///
/// Red on main: the reader passes the frozen length and fails D1
/// ("acquisition exceeds stable source"), recorded as one `OpenRead`.
#[test]
fn fe_claude_sp1c_append_during_full_read_publishes_sealed_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    base.cache.clear();
    let due = sampled_scan::now_seconds() + 1800;
    base.index
        .files
        .get_mut(&base.key)
        .unwrap()
        .set_unverified_deadline(due);
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let index = std::mem::take(&mut base.index);
    let (index, full, seen, read) =
        page_injecting(&base.fixture, CLAUDE, index, &base.cache, is_full, |_| {
            append_raw(&path, &appended)
        });
    assert_eq!(read.mode, ReadMode::Full(FullReason::StateMissing));
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(
        read.debt.map(|debt| debt.due_unix_seconds),
        Some(due),
        "precondition: the Full owes the prepared audit"
    );
    assert_prefix_published("SP-1c", &base, &index, full, &seen, &read, read.frozen);
    assert_eq!(
        index.files[&base.key].unverified_deadline(),
        Some(due),
        "SP-1c: no complete_full_audit; the prepared debt stays staged"
    );
    next_full("SP-1c", &base, index, STATE_MISSING);
}

/// SP-1c' (RED): the same during a Claude in-page `Tail` from `s` of a
/// retained copy. FE publishes `[0, frozen)`, discards the taken copy (no
/// checkpoint or cache insert), and re-stages the Tail's prepared debt
/// unchanged; the next page reads `Full(StateMissing)` with body parity.
///
/// Red on main: D1 (one `OpenRead`), and the taken copy is dropped.
#[test]
fn fe_claude_sp1c_prime_append_during_tail_read_publishes_prefix_and_restages_debt() {
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
    assert!(read.debt.is_some(), "precondition: a Tail owes its audit");
    assert_prefix_published("SP-1c'", &base, &index, tail, &seen, &read, read.frozen);
    assert_eq!(
        index.files[&base.key].unverified_deadline(),
        read.debt.map(|debt| debt.due_unix_seconds),
        "SP-1c': the prepared debt is re-staged unchanged"
    );
    next_full("SP-1c'", &base, index, STATE_MISSING);
}

/// SP-2a-c (RED): half a row at open, completed (plus more rows) after the
/// open step of a Claude `Tail`. FE seals at the row's start `s'` < frozen:
/// the row is absent now and present on the next read.
///
/// Red on main: the row's newline lies past the frozen length, so the reader
/// fails D1 (one `OpenRead`).
#[test]
fn fe_claude_sp2a_partial_row_at_frozen_grown_is_absent_now_present_next() {
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
    let (_, next) = next_full("SP-2a-c", &base, index, STATE_MISSING);
    assert_ne!(
        content(production_body(CLAUDE, next)),
        prefix,
        "SP-2a-c: the completed row is present on the next read"
    );
}

/// SP-2b-c (GREEN): a quiescent unterminated last row in a Claude `Tail`,
/// not grown. Main's trailing-line rule applies it; H2c must keep this
/// byte-identical: body == Full parse, `RetentionUnsealedEof`, no copy,
/// nothing unreadable.
#[test]
fn fe_claude_sp2b_quiescent_unterminated_tail_keeps_main_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let last = row_bytes(CLAUDE, 6..7);
    append_raw(&base.path, &last[..last.len() - 1]);
    let ((_, tail, seen), counts) =
        observe(|| plain(&base.fixture, CLAUDE, base.index, &base.cache));
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(counts.retention_unsealed_eof, 1);
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "no copy"
    );
    assert_eq!(
        production_body(CLAUDE, tail),
        full_body(&base.fixture, CLAUDE)
    );
}

/// SP-2b-c, Full (GREEN): the same unterminated last row read by a Claude
/// in-page `Full` keeps main's output: nothing unreadable, body == Full parse.
#[test]
fn fe_claude_sp2b_quiescent_unterminated_full_keeps_main_output() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    base.cache.clear();
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

/// SP-2c-c (RED): setter units with `s` >= 64 KiB. The Claude `Tail` reader
/// stops at frozen with a reader-relative limit `frozen - start`.
///
/// Red on main: no in-page limit is set; the reader passes frozen and fails
/// D1 (one `OpenRead`), so the EOF hook never sees this read.
#[test]
fn fe_claude_sp2c_large_prefix_tail_stops_at_frozen_with_relative_limit() {
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
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "SP-2c-c: no copy"
    );
}

/// SP-D2c (RED): a Claude `Full` reader reaches EOF exactly at frozen, then
/// rows are appended before revalidation reopens the path. FE takes the grown
/// route: nothing unreadable, `[0, frozen)` published as a certificate only.
///
/// Red on main: revalidation sees the grown identity (length, ctime, last
/// 4 KiB) and refuses the page as one `ScopeObject`.
#[test]
fn fe_claude_spd2c_append_after_full_reader_eof_takes_grown_route() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    base.cache.clear();
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
fn fe_claude_spd2c_append_after_tail_reader_eof_takes_grown_route() {
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
    next_full("SP-D2c Tail", &base, index, STATE_MISSING);
}

/// SP-3a-c (GREEN): a new object renamed over the path during a Claude
/// `Tail`; the held FD is not grown. Main's revalidation refuses as
/// `ScopeObject`: no checkpoint, copy or publication.
#[test]
fn fe_claude_sp3a_replace_during_tail_not_grown_is_scope_object() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let bytes = bytes_of(&base.path);
    let (_, tail, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index,
        &base.cache,
        is_tail,
        |_| replace(&path, &bytes),
    );
    assert_refused(
        &base.cache,
        &base.key,
        &tail,
        &seen,
        SCOPE_OBJECT,
        "SP-3a-c",
    );
}

/// SP-4-c (GREEN): truncated below frozen during a Claude `Tail`, no regrow.
/// Not grown, so main's path: `ScopeObject`; nothing published.
#[test]
fn fe_claude_sp4_truncate_during_tail_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let (path, sealed) = (base.path.clone(), base.sealed);
    let (_, tail, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index,
        &base.cache,
        is_tail,
        |_| truncate(&path, sealed),
    );
    assert_refused(&base.cache, &base.key, &tail, &seen, SCOPE_OBJECT, "SP-4-c");
}

/// SP-5a-c (GREEN): truncated at the open step (a short EOF), then regrown
/// past frozen before completion. H3c's traversal check fails, so main's
/// path: `ScopeObject`.
#[test]
fn fe_claude_sp5a_truncate_then_regrow_after_short_eof_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let (path, sealed) = (base.path.clone(), base.sealed);
    let mut regrown = bytes_of(&base.path)[sealed as usize..].to_vec();
    regrown.extend(row_bytes(CLAUDE, 6..8));
    let regrow_path = base.path.clone();
    let ((_, tail, seen, read), at_eof) = with_eof_hook(
        &base.path,
        move |_| append_raw(&regrow_path, &regrown),
        || {
            page_injecting(
                &base.fixture,
                CLAUDE,
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
    assert_refused(
        &base.cache,
        &base.key,
        &tail,
        &seen,
        SCOPE_OBJECT,
        "SP-5a-c",
    );
}

/// SP-5b-c (GREEN): after the Claude reader passes frozen, the file is
/// rewritten past frozen with a different head. Main's revalidation and H3c's
/// head sample both refuse as `ScopeObject`; nothing published.
#[test]
fn fe_claude_sp5b_regrow_after_reader_passes_frozen_with_new_head_refuses() {
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
    assert_refused(
        &base.cache,
        &base.key,
        &tail,
        &seen,
        SCOPE_OBJECT,
        "SP-5b-c",
    );
}

/// SP-5c-c (GREEN): after the Claude reader passes frozen, the file is
/// rewritten to exactly frozen with a different head. Not grown, so main's
/// revalidation refuses as `ScopeObject`.
#[test]
fn fe_claude_sp5c_rewrite_to_exactly_frozen_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let path = base.path.clone();
    let rewritten = claude_changed_head(&bytes_of(&base.path));
    let ((_, tail, seen), at_eof) = with_eof_hook(
        &base.path,
        move |_| overwrite(&path, &rewritten),
        || plain(&base.fixture, CLAUDE, base.index, &base.cache),
    );
    let at_eof = at_eof.expect("precondition: the reader reached EOF");
    assert_eq!(len(&base.path), at_eof.frozen, "precondition: not grown");
    assert_refused(
        &base.cache,
        &base.key,
        &tail,
        &seen,
        SCOPE_OBJECT,
        "SP-5c-c",
    );
}

/// SP-5 residual, Claude (RED; EXPECTED RESIDUAL per SOURCE FE2, not mutation
/// detection): after the reader passed them, already-read tail bytes outside
/// both 4 KiB sample windows are truncated and regrown with a different row
/// of the same length, plus growth. H3c accepts it as the cursor does: the
/// page publishes the bytes it read; only a later Full (the quiet audit) sees
/// the edit.
///
/// Red on main: revalidation sees the grown identity and refuses the page as
/// one `ScopeObject`.
#[test]
fn fe_claude_sp5_residual_sample_preserving_rewrite_after_read_is_accepted() {
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
    let ((mut index, tail, seen), at_eof) = with_eof_hook(
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
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "no copy"
    );
    assert_eq!(
        content(production_body(CLAUDE, tail)),
        content(frozen_body),
        "SP-5 residual (Claude): the bytes read before the edit are published"
    );
    // FE2: even a grown Full that had no previous debt must retain a
    // deadline. The quiet audit sees the interior rewrite and counts it.
    assert!(index.files[&base.key].unverified_deadline().is_some());
    index
        .files
        .get_mut(&base.key)
        .unwrap()
        .set_unverified_deadline(0);
    let ((_, next, audit), diagnostics) = crate::local_resource_diagnostics::capture(|| {
        plain(&base.fixture, CLAUDE, index, &base.cache)
    });
    assert_eq!(audit.full_reasons[AUDIT_DUE], 1, "FE2: quiet Full audit");
    assert_eq!(audit.unreadable, 0, "FE2: audit completes");
    assert_eq!(
        content(production_body(CLAUDE, next)),
        content(full_body(&base.fixture, CLAUDE)),
        "FE2: audit repairs the body"
    );
    assert!(
        diagnostics
            .iter()
            .any(|row| row["stage"] == "sampled_audit_comparison"
                && row["counts"]["semantic_comparison_available"] == true
                && row["counts"]["semantic_changed"] == true),
        "FE2: audit mismatch counted"
    );
}

/// The Claude baseline plus a malformed row inside `[s, frozen)`.
fn claude_lossy_baseline() -> Baseline {
    let base = baseline(CLAUDE, 4, 1);
    append_raw(&base.path, b"{\"type\":\"assistant\",\"message\":\n");
    append_raw(&base.path, &row_bytes(CLAUDE, 5..6));
    base
}

/// SP-7a-c (GREEN): a lossy row in a Claude `Tail`, not grown. Main: the
/// retention refuses (`RetentionIncompleteOrLossy`), no copy, nothing
/// unreadable.
#[test]
fn fe_claude_sp7a_lossy_tail_not_grown_keeps_main_uncertified_path() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = claude_lossy_baseline();
    let ((_, _, seen), counts) = observe(|| plain(&base.fixture, CLAUDE, base.index, &base.cache));
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert_eq!(counts.retention_incomplete_or_lossy, 1);
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "no copy"
    );
}

/// SP-7b-c (GREEN): a lossy row in `[s, frozen)` and an append after the
/// open step. Lossy reads are excluded from H3c and follow main: one
/// unreadable (main's `OpenRead`; with H1c, `ScopeObject` at revalidation),
/// no checkpoint, copy or publication.
#[test]
fn fe_claude_sp7b_lossy_grown_tail_is_excluded_and_refused() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = claude_lossy_baseline();
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..8);
    let (_, tail, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index,
        &base.cache,
        is_tail,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(
        (
            seen.unreadable,
            seen.causes[OPEN_READ] + seen.causes[SCOPE_OBJECT]
        ),
        (1, 1),
        "SP-7b-c: one refusal; causes={:?}",
        seen.causes
    );
    assert!(
        base.cache.retained_checkpoint(&base.key).is_none(),
        "SP-7b-c: no checkpoint or copy"
    );
    assert!(tail.snapshots.is_empty(), "SP-7b-c: nothing published");
}

/// SP-8c-c (RED): a grown Claude `Full(AuditDue)` earns no audit credit: FE
/// publishes the prefix, the due debt stays staged at its deadline, and the
/// next page is `Full(AuditDue)` again.
///
/// Red on main: D1 (one `OpenRead`).
#[test]
fn fe_claude_sp8c_grown_full_audit_due_keeps_debt_staged() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    let due = sampled_scan::now_seconds() - 1;
    base.index
        .files
        .get_mut(&base.key)
        .unwrap()
        .set_unverified_deadline(due);
    let path = base.path.clone();
    let appended = row_bytes(CLAUDE, 6..9);
    let index = std::mem::take(&mut base.index);
    let (index, full, seen, read) =
        page_injecting(&base.fixture, CLAUDE, index, &base.cache, is_full, |_| {
            append_raw(&path, &appended)
        });
    assert_eq!(read.mode, ReadMode::Full(FullReason::AuditDue));
    assert_eq!(seen.full_reasons[AUDIT_DUE], 1);
    assert_prefix_published("SP-8c-c", &base, &index, full, &seen, &read, read.frozen);
    assert_eq!(
        index.files[&base.key].unverified_deadline(),
        Some(due),
        "SP-8c-c: no audit credit; the debt stays staged"
    );
    next_full("SP-8c-c", &base, index, AUDIT_DUE);
}

/// SP-11-c, Codex (GREEN): FE is Claude-only. A Codex in-page `Full` with an
/// append after the open step keeps main's D1 failure (`OpenRead`).
#[test]
fn fe_claude_sp11_codex_in_page_full_with_append_keeps_main_failure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let base = baseline(source, 4, 2);
    base.cache.clear();
    let path = base.path.clone();
    let appended = row_bytes(source, 6..8);
    let (_, full, seen, read) = page_injecting(
        &base.fixture,
        source,
        base.index,
        &base.cache,
        is_full,
        |_| append_raw(&path, &appended),
    );
    assert_eq!(read.mode, ReadMode::Full(FullReason::StateMissing));
    assert_refused(
        &base.cache,
        &base.key,
        &full,
        &seen,
        OPEN_READ,
        "SP-11-c Codex",
    );
}

/// SP-11-c, Pi (GREEN): Pi has no sampled acquisition, so no in-page read
/// for H1c-H3c to change.
#[test]
fn fe_claude_sp11_pi_has_no_in_page_sampled_read() {
    let root = std::env::temp_dir();
    let scan = OwnedSourceScan::new(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(
        Arc::new(sampled_scan::SharedCache::default()),
        Scope(NAMESPACE.into()),
    );
    assert!(scan.sampling.is_none(), "Pi reads stay unsampled");
}

/// SOURCE, s below the last committed size (GREEN): the last page committed
/// a file ending in a complete but unterminated row (size C, main's
/// trailing-line rule). The file is re-selected at size C and, during its
/// in-page `Full`, the row's newline and more rows are appended. The last newline at or below frozen (= C) is the row's start,
/// below C, so FE must publish nothing (never a weaker body): one refusal, no
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
    cache.clear();
    touch(&path);
    let mut completion = b"\n".to_vec();
    completion.extend(row_bytes(CLAUDE, 5..7));
    let append_path = path.clone();
    let (index, full, seen, read) =
        page_injecting(&fixture, CLAUDE, index, &cache, is_full, |_| {
            append_raw(&append_path, &completion)
        });
    assert_eq!(read.frozen, committed, "precondition: frozen = C");
    assert_eq!(
        seen.unreadable, 1,
        "SOURCE: refused; causes={:?}",
        seen.causes
    );
    assert!(full.snapshots.is_empty(), "SOURCE: never a weaker body");
    assert!(cache.retained_checkpoint(&key).is_none(), "no copy");
    assert_eq!(
        index.files[&key].size_bytes, committed,
        "the committed entry stands"
    );
}

/// D1 control (GREEN): in this fixture a quiescent sampled `Full` writes a
/// source-verified D1 record of its requests, and a quiescent `Tail` (which
/// owes its audit) writes an unverified one.
#[test]
fn fe_claude_d1_control_quiescent_full_verified_tail_unverified() {
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
    assert!(record.unverified_for_test(), "control: Tail owes its audit");
    assert_eq!(
        record.request_hashes_for_test(),
        census_hashes(0..6).as_slice()
    );
}

/// SOURCE, D1 (RED): FE's prefix parse writes a D1 record of the prefix's
/// requests that is never source-verified, and the next read replaces it
/// with the grown file's requests.
///
/// Red on main: D1 (one `OpenRead`); main invalidates the record.
#[test]
fn fe_claude_source_prefix_d1_record_is_unverified_and_replaced_next_read() {
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

/// Proof control (GREEN): in this fixture a quiescent read with exactly
/// matching API and trace evidence mints v1 at a healthy terminal.
#[test]
fn fe_claude_census_control_exact_api_rows_mint_v1() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (_fixture, mut index, result) = quiescent();
    assert!(
        mints_v1(&mut index, &result, 0..6),
        "control: exact rows mint v1"
    );
    assert!(index.claude_usage_family_witnesses.contains_key(SESSION));
}

/// Proof diagnostic (GREEN, main's behavior, not a requirement): the fold
/// accepts trace-owned API rows the transcript does not carry as auxiliary
/// calls (`transcript ⊆ assigned`), so a body missing requests the API
/// reports still mints v1. FE's "proof fails closed" therefore cannot rest
/// on unequal request sets; the SOURCE rows below need an explicit guard.
#[test]
fn fe_claude_census_diag_main_folds_extra_api_rows_as_auxiliary() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (_fixture, mut index, result) = quiescent();
    assert!(
        mints_v1(&mut index, &result, 0..9),
        "diagnostic: main folds the three extra rows and mints v1"
    );
}

/// SOURCE, proof (RED): a prefix body never mints v1 or a family witness,
/// even when the API evidence matches the prefix exactly.
///
/// Red on main: D1 (one `OpenRead`), so no prefix is published.
#[test]
fn fe_claude_source_prefix_never_mints_v1_or_witness() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    assert_eq!(
        grown.seen.unreadable, 0,
        "SOURCE proof: no unreadable; causes={:?}",
        grown.seen.causes
    );
    assert!(
        !grown.result.snapshots.is_empty(),
        "the prefix is published"
    );
    assert!(
        !mints_v1(&mut grown.index, &grown.result, 0..6),
        "SOURCE proof: no v1 from a prefix"
    );
    assert!(
        !grown
            .index
            .claude_usage_family_witnesses
            .contains_key(SESSION),
        "SOURCE proof: no family witness from a prefix"
    );
}

/// Census (RED): the published prefix enters pending as any read does: the
/// member's request set is the prefix's, and the family stays valid.
///
/// Red on main: D1 (one `OpenRead`), so nothing reaches pending.
#[test]
fn fe_claude_census_prefix_enters_pending() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    assert_eq!(
        grown.seen.unreadable, 0,
        "census pending: no unreadable; causes={:?}",
        grown.seen.causes
    );
    let _ = record_claude_native_observations(&grown.result, &mut grown.index);
    let pending = &grown.index.claude_usage_family_pending[SESSION];
    assert!(!pending.invalid, "census pending: the family is valid");
    assert_eq!(
        pending
            .membership()
            .get(SESSION)
            .map(|hashes| hashes.iter().cloned().collect::<BTreeSet<_>>()),
        Some(pending_hashes(0..6)),
        "census pending: the prefix's requests"
    );
}

/// Census (RED): a second read of the grown file in the same census window
/// carries more requests, so pending counts `member_changed` and invalidates
/// the family.
///
/// Red on main: D1 (one `OpenRead`) on the first read.
#[test]
fn fe_claude_census_reread_in_window_gives_member_changed() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    assert_eq!(
        grown.seen.unreadable, 0,
        "census member_changed: no unreadable; causes={:?}",
        grown.seen.causes
    );
    let _ = record_claude_native_observations(&grown.result, &mut grown.index);
    let (mut index, next) = next_full(
        "census member_changed",
        &grown.base,
        grown.index,
        STATE_MISSING,
    );
    assert_eq!(
        next.census_window_end, grown.result.census_window_end,
        "precondition: one census window"
    );
    let observed = record_claude_native_observations(&next, &mut index);
    assert_eq!(
        observed.counts.page_invalidated_member_changed_count, 1,
        "census member_changed: counted once"
    );
    assert!(
        index.claude_usage_family_pending[SESSION].invalid,
        "census member_changed: the family is invalid"
    );
}

/// Census (RED): proof fails closed while the API evidence reports requests
/// beyond the published prefix (rows 6..9 were appended during the read).
///
/// Red on main: D1 (one `OpenRead`), so no prefix is published.
#[test]
fn fe_claude_census_proof_fails_closed_while_api_rows_exceed_prefix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    assert_eq!(
        grown.seen.unreadable, 0,
        "census proof: no unreadable; causes={:?}",
        grown.seen.causes
    );
    assert!(
        !grown.result.snapshots.is_empty(),
        "the prefix is published"
    );
    assert!(
        !mints_v1(&mut grown.index, &grown.result, 0..9),
        "census proof: fails closed while API rows exceed the prefix"
    );
    assert!(
        !grown
            .index
            .claude_usage_family_witnesses
            .contains_key(SESSION),
        "census proof: no family witness"
    );
}

/// SOURCE (B): real FE prefix provenance, rather than ordinary D1 debt,
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

/// Restart/record-budget fallback: the durable prepared audit marker fences
/// proof even when no D1 source record is available for the prefix.
#[test]
fn fe_claude_prefix_without_d1_record_still_cannot_mint_v1() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    assert_eq!(grown.seen.unreadable, 0);
    assert!(grown.index.files[&grown.base.key].has_unverified_source());
    grown
        .index
        .claude_request_census_mut_for_test()
        .invalidate_keeping_birth_for_test(&grown.base.key);
    assert!(!mints_v1(&mut grown.index, &grown.result, 0..9));
    assert!(!grown
        .index
        .claude_usage_family_witnesses
        .contains_key(SESSION));
}

/// A saved family cannot reconstruct v1 from an actual FE prefix on an
/// incomplete page, even with unchanged API/trace evidence.
#[test]
fn fe_claude_unverified_source_cannot_reconstruct_a_saved_family_witness() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (_fixture, mut verified, result) = quiescent();
    assert!(mints_v1(&mut verified, &result, 0..9));
    let previous_witness = verified.claude_usage_family_witnesses[SESSION].clone();
    let mut grown = grown_full();
    grown.index.claude_usage_family_witnesses = verified.claude_usage_family_witnesses;
    grown.result.census_complete = false;
    assert!(!mints_v1(&mut grown.index, &grown.result, 0..9));
    assert_eq!(
        grown.index.claude_usage_family_witnesses.get(SESSION),
        Some(&previous_witness),
        "historical witness remains for hold accounting, never prefix authority"
    );
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

/// Review F1: growth after genuine-EOF E1 must not certify the row E1
/// applied outside the last newline. No new reader/acquisition state needed.
#[test]
fn fe_claude_growth_after_e1_applied_fragment_keeps_strict_identity() {
    let fixture = Fixture::new(CLAUDE);
    let mut bytes = row_bytes(CLAUDE, 0..2);
    assert_eq!(bytes.pop(), Some(b'\n'));
    append_raw(&fixture.0, &bytes);
    let (mut parser, _, scope) = native_parser(&fixture, CLAUDE);
    parser
        .prepare_acquisition(None, &scope, None, sampled_scan::now_seconds())
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
        parser
            .commit_claude_grown_prefix(&fixture.0, &scope, 0)
            .is_none(),
        "E1-applied bytes beyond the seal cannot get a grown grant"
    );
}

/// Review F2: exhausted/unsupported audit metadata retains strict Full
/// behavior, creates no new marker and cannot disable reuse source-wide.
#[test]
fn fe_claude_full_without_audit_capacity_keeps_main_failure_and_marker_count() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for supported in [false, true] {
        let base = baseline(CLAUDE, 4, 2);
        base.cache.clear();
        let mut read = None;
        let (index, result, seen) = page(&base.fixture, CLAUDE, base.index, &base.cache, |scan| {
            if let Some(context) = scan.sampling.as_mut() {
                context.audit_metadata_supported = supported;
                context.audit_slots = 0;
            }
            if read.is_none() {
                if let Some(opened) = opened(scan) {
                    assert!(is_full(opened.mode));
                    assert_eq!(
                        opened.extent_limit, None,
                        "no optional frozen read without capacity"
                    );
                    append_raw(&base.path, &row_bytes(CLAUDE, 6..9));
                    read = Some(opened);
                }
            }
        });
        assert!(read.is_some());
        assert_refused(
            &base.cache,
            &base.key,
            &result,
            &seen,
            OPEN_READ,
            "FE capacity",
        );
        assert!(!index
            .files
            .values()
            .any(ScanIndexEntry::has_unverified_source));
    }
}

/// Source loss may be discovered by response resolution only at finish,
/// after H3c's reader/report check. Refuse the grown body rather than publish
/// without an indexed audit marker (even if the D1 record cannot be stored).
#[test]
fn fe_claude_finalizer_only_response_loss_refuses_the_grown_prefix() {
    // Resolver conflict as drop residue is gate-off only; gate on it is a disclosed E2 conflict.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    base.cache.clear();
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
    assert!(
        reducer.dropped_usage_record_count > 0,
        "incomparable usage loses at finalization"
    );
    let mut bytes = serde_json::to_vec(&conflict).unwrap();
    bytes.push(b'\n');
    append_raw(&base.path, &bytes);
    let path = base.path.clone();
    let (_, result, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        base.index,
        &base.cache,
        is_full,
        |_| append_raw(&path, &row_bytes(CLAUDE, 6..9)),
    );
    assert_refused(
        &base.cache,
        &base.key,
        &result,
        &seen,
        SCOPE_OBJECT,
        "FE finalizer loss",
    );
}

/// An ineligible Full still has a ReadPlan, but H1c never froze its reader.
/// Growth after its native EOF must not enter the optional prefix route.
#[test]
fn fe_claude_full_without_h1c_admission_keeps_strict_completion() {
    let fixture = Fixture::new(CLAUDE);
    append_raw(&fixture.0, &row_bytes(CLAUDE, 0..2));
    let (mut parser, _, scope) = native_parser(&fixture, CLAUDE);
    parser
        .prepare_acquisition(None, &scope, None, sampled_scan::now_seconds())
        .unwrap();
    while !parser.step().unwrap() {}
    assert_eq!(parser.reader.extent_limit, None);
    append_raw(&fixture.0, &row_bytes(CLAUDE, 2..3));
    assert!(parser
        .commit_claude_grown_prefix(&fixture.0, &scope, 0)
        .is_none());
}

/// SOURCE exclusion binds the body revision, not just a physical path's
/// family name. Missing D1 plus a moved physical key cannot let a saved
/// logical-family witness reconstruct v1 from the same prefix.
#[test]
fn fe_claude_prefix_with_different_physical_key_cannot_reconstruct_v1() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (_verified_fixture, mut verified, verified_result) = quiescent();
    assert!(mints_v1(&mut verified, &verified_result, 0..9));
    let mut grown = grown_full();
    assert_eq!(grown.seen.unreadable, 0);
    grown.index.claude_usage_family_witnesses = verified.claude_usage_family_witnesses;
    let moved_key = local_index_key(&grown.base.path.with_file_name("physical-other.jsonl"));
    let entry = grown.index.files.remove(&grown.base.key).unwrap();
    assert!(entry.has_unverified_source());
    assert_eq!(
        grown.result.snapshots[0].source_file_fingerprint.as_deref(),
        Some(entry.source_file_fingerprint.as_str())
    );
    grown.index.files.insert(moved_key, entry);
    grown
        .index
        .claude_request_census_mut_for_test()
        .invalidate_keeping_birth_for_test(&grown.base.key);
    grown.result.census_complete = false;
    assert!(
        !mints_v1(&mut grown.index, &grown.result, 0..9),
        "SOURCE: physical-key drift cannot bypass prefix exclusion"
    );
}

/// Ordinary EOF-recomposed Tail retains positive behavior despite unverified D1.
#[test]
fn fe_claude_ordinary_tail_d1_debt_does_not_exclude_recomposed_body() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 2);
    let (mut index, result, seen) = plain(&base.fixture, CLAUDE, base.index, &base.cache);
    assert_eq!(seen.modes, (0, 1, 0));
    assert_eq!(seen.unreadable, 0);
    assert!(index
        .claude_request_census_for_test()
        .get(&base.key)
        .unwrap()
        .unverified_or_twin());
    assert!(
        index.files[&base.key].has_unverified_source(),
        "audit debt remains"
    );
    assert!(mints_v1(&mut index, &result, 0..9));
}

/// Old, unknown and malformed tags cannot assert a complete native reduction.
#[test]
fn fe_claude_old_unknown_and_malformed_provenance_exclude() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for tag in [
        "semantic_sync:v2+sampled_unverified:v1:9999999999",
        "semantic_sync:v2+sampled_unverified:v99:9999999999:c",
        "semantic_sync:v2+sampled_unverified:v2:9999999999:unknown",
        "semantic_sync:v2+sampled_unverified:v2:bad:c",
    ] {
        let (fixture, mut index, result) = quiescent();
        let key = local_index_key(&fixture.file.0);
        index.files.get_mut(&key).unwrap().scan_identity_version = Some(tag.into());
        assert!(!mints_v1(&mut index, &result, 0..9), "tag {tag}");
    }
}

/// Persistence must preserve the exclusion even without D1 and after key drift.
#[test]
fn fe_claude_prefix_provenance_round_trips_without_d1() {
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
    grown.index.files.insert(moved.clone(), entry);
    let path = grown.base.fixture.root.join("prefix-index.json");
    grown.index.save(&path).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(loaded.files[&moved].scan_identity_version, tag);
    assert!(!mints_v1(&mut loaded, &grown.result, 0..9));
}

/// The recovery Tail starts from a retained COMPLETE pre-prefix reduction,
/// replays all later rows and revalidates EOF. No FE prefix is cached.
#[test]
fn fe_claude_prefix_then_complete_tail_at_eof_is_positive_again() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    let complete = base.cache.take(&base.key).unwrap();
    let path = base.path.clone();
    let (index, result, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        std::mem::take(&mut base.index),
        &base.cache,
        is_full,
        |_| append_raw(&path, &row_bytes(CLAUDE, 6..9)),
    );
    assert_eq!(seen.unreadable, 0);
    base.index = index;
    // Assess exclusion without carrying the separate same-window member-
    // change invalidation into this provenance-recovery regression.
    let mut prefix_observation = base.index.clone();
    assert!(!mints_v1(&mut prefix_observation, &result, 0..9));
    assert!(base.cache.retained_checkpoint(&base.key).is_none());
    assert!(base
        .cache
        .retained()
        .unwrap()
        .insert(base.key.clone(), complete.retained));
    let ((mut index, result, seen), counts) =
        observe(|| plain(&base.fixture, CLAUDE, base.index, &base.cache));
    assert_eq!(counts.prefix_tag_clears, 1);
    assert_eq!(
        seen.modes,
        (0, 1, 0),
        "complete baseline reduction is replayed"
    );
    assert_eq!(seen.unreadable, 0);
    assert!(
        index.files[&base.key].has_unverified_source(),
        "Tail still owes audit"
    );
    assert!(index
        .claude_request_census_for_test()
        .get(&base.key)
        .unwrap()
        .unverified_or_twin());
    assert!(mints_v1(&mut index, &result, 0..9));
}

/// A later grown Tail publication still owes the prefix exclusion, even if
/// its retained baseline was complete. Appending to a prefix is not clearing.
#[test]
fn fe_claude_prefix_then_grown_tail_does_not_clear_provenance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut base = baseline(CLAUDE, 4, 2);
    let complete = base.cache.take(&base.key).unwrap();
    let path = base.path.clone();
    let (index, _, seen, _) = page_injecting(
        &base.fixture,
        CLAUDE,
        std::mem::take(&mut base.index),
        &base.cache,
        is_full,
        |_| append_raw(&path, &row_bytes(CLAUDE, 6..9)),
    );
    assert_eq!(seen.unreadable, 0);
    assert!(index.files[&base.key].has_prefix_provenance());
    assert!(base
        .cache
        .retained()
        .unwrap()
        .insert(base.key.clone(), complete.retained));
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

/// Review: terminal line loss can settle a page, but cannot use its matching
/// unverified D1 record to grant proof merely by inheriting a clean old tag.
#[test]
fn fe_claude_lossy_tail_cannot_inherit_complete_provenance_for_d1_proof() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let base = baseline(CLAUDE, 4, 1);
    base.fixture
        .file
        .append(&json!({"type":"ignored", "padding":"x".repeat(MAX_JSONL_LINE_BYTES + 1024)}));
    append_raw(&base.path, &row_bytes(CLAUDE, 5..6));
    let (mut index, result, seen) = plain(&base.fixture, CLAUDE, base.index, &base.cache);
    assert_eq!(seen.modes, (0, 1, 0));
    assert!(!result.snapshots.is_empty());
    assert!(base.cache.retained_checkpoint(&base.key).is_none());
    assert!(index
        .claude_request_census_for_test()
        .get(&base.key)
        .unwrap()
        .unverified_or_twin());
    assert!(!mints_v1(&mut index, &result, 0..9));
    assert!(!index.claude_usage_family_witnesses.contains_key(SESSION));
}

/// c22 G1 (control): an ordinary unsampled parse that is not verified (a
/// terminal oversized line) and stages no obligation re-records a
/// replay-reset (`None`) or legacy non-stem entry as the clean identity. It
/// mints no `p` tag, no deadline-0 audit debt, and counts no tag clear.
#[test]
fn fe_g1_ordinary_unverified_rerecord_never_mints_prefix_provenance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for (source, reset) in [
        (CLAUDE, None),
        (CLAUDE, Some("semantic_sync:v1")),
        (SnapshotSource::Codex, None),
    ] {
        let id = format!("{source:?}/{reset:?}");
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let (mut index, _, _) = production_scan(&fixture, source, ScanIndex::default(), None, "g1");
        let key = local_index_key(&fixture.file.0);
        index.files.get_mut(&key).unwrap().scan_identity_version = reset.map(Into::into);
        assert!(
            !index.files[&key].has_prefix_provenance(),
            "{id}: SOURCE Option 1: a non-stem identity is not a prefix"
        );
        fixture
            .file
            .append(&json!({"type":"ignored", "padding":"x".repeat(MAX_JSONL_LINE_BYTES + 1024)}));
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let ((index, result, _), counts) =
            observe(|| production_scan(&fixture, source, index, None, "g1"));
        assert!(
            result.over_line_cap_count > 0,
            "{id}: precondition: not loss-free, so not source-verified"
        );
        let entry = &index.files[&key];
        assert_eq!(
            entry.scan_identity_version.as_deref(),
            Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
            "{id}"
        );
        assert!(!entry.has_prefix_provenance(), "{id}");
        assert!(!entry.has_unverified_source(), "{id}: no audit debt");
        assert!(entry.audit_obligation(0).is_none(), "{id}");
        assert_eq!(counts.prefix_tag_clears, 0, "{id}");
    }
}

/// c22 G1 (control): FE marks its grown prefix after `record` in the same
/// completion, so a prefix still ends `p` from a clean, replay-reset or
/// legacy prior entry, and stays excluded.
#[test]
fn fe_g1_grown_prefix_still_marks_prefix_after_ordinary_record() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for reset in [
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
        None,
        Some("semantic_sync:v1"),
    ] {
        let mut base = baseline(CLAUDE, 4, 2);
        base.cache.clear();
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
        assert!(entry.has_unverified_source(), "{reset:?}");
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

/// c22 N1 (narrower): only loss-free, identity-complete D1 shapes may bind a
/// recomposed body. An identity-incomplete record keeps its root excluded
/// until a Full audit verifies it.
#[test]
fn fe_n1_identity_incomplete_record_cannot_bind_recomposed_body() {
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

/// SOURCE N1, marker-preserving versions: an actual identity-incomplete Tail
/// cannot reconstruct a saved witness until its persisted hourly Full audit.
/// Neither a reload nor loss of the optional retained copy cancels the read.
#[test]
fn fe_n1_held_tail_save_reload_reaches_due_full_and_reproves() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::claude_request_census::{
        identity_incomplete_hold_totals, ClaudeRequestCensusShape as Shape,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    struct Clock;
    impl Drop for Clock {
        fn drop(&mut self) {
            sampled_scan::set_test_now(None);
        }
    }
    let _clock = Clock;
    // The scanner's candidate clock remains real. Put the initial verified
    // read one interval back, then complete the Tail just before its due
    // time; after reload both clocks agree the saved deadline has arrived.
    let due = sampled_scan::now_seconds();
    sampled_scan::set_test_now(Some(
        due - crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
    ));
    let fixture = ScanFixture::new(CLAUDE);
    append_raw(&fixture.file.0, &row_bytes(CLAUDE, 0..6));
    let key = local_index_key(&fixture.file.0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut index, first, seen) = plain(&fixture, CLAUDE, ScanIndex::default(), &cache);
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(seen.unreadable, 0);
    assert!(cache.retained_checkpoint(&key).is_some());
    let mut proven = index.clone();
    assert!(mints_v1(&mut proven, &first, 0..6));
    index.claude_usage_family_witnesses = proven.claude_usage_family_witnesses;
    let witness = index.claude_usage_family_witnesses[SESSION].clone();
    let before = identity_incomplete_hold_totals();

    // Keep the six keyed occurrences unchanged and add a real id-less
    // response. Native finish marks the census IdentityIncomplete; only the
    // saved witness, not a fresh identity-complete transcript proof, can bind.
    let mut idless = row(CLAUDE, 6);
    idless.as_object_mut().unwrap().remove("requestId");
    fixture.file.append(&idless);
    sampled_scan::set_test_now(Some(due - 1));
    let (mut index, tail, seen) = plain(&fixture, CLAUDE, index, &cache);
    assert_eq!(seen.modes, (0, 1, 0), "real continued Tail");
    assert_eq!(seen.unreadable, 0);
    let record = index.claude_request_census_for_test().get(&key).unwrap();
    assert_eq!(record.shape_for_test(), Shape::IdentityIncomplete);
    assert!(record.unverified_or_twin());
    assert!(!record.can_bind_recomposed_body(), "Exact|Empty refusal");
    assert_eq!(index.files[&key].unverified_deadline(), Some(due));
    assert!(!index.files[&key].audit_requires_full(due - 1));
    // Isolate the binding decision from the fold's separate retry/rearm
    // bookkeeping; save the native scan's actual D1 and audit marker below.
    assert!(!mints_v1(&mut index.clone(), &tail, 0..6));
    let mut verified_control = index.clone();
    let record = verified_control
        .claude_request_census_for_test()
        .get(&key)
        .unwrap()
        .clone()
        .with_unverified_for_test(false);
    verified_control
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record);
    assert!(
        mints_v1(&mut verified_control, &tail, 0..6),
        "the identical body can reconstruct once N1 verification holds"
    );
    assert_eq!(identity_incomplete_hold_totals(), (before.0 + 1, before.1));

    let path = fixture.dir.join("n1-index.json");
    index.save(&path).unwrap();
    drop(index);
    cache.clear();
    let loaded = ScanIndex::load(&path).unwrap();
    assert!(cache.retained_checkpoint(&key).is_none());
    assert_eq!(loaded.files[&key].unverified_deadline(), Some(due));
    let record = loaded.claude_request_census_for_test().get(&key).unwrap();
    assert_eq!(record.shape_for_test(), Shape::IdentityIncomplete);
    assert!(record.unverified_or_twin());
    assert!(!record.can_bind_recomposed_body());
    assert!(!mints_v1(&mut loaded.clone(), &tail, 0..6));
    assert_eq!(identity_incomplete_hold_totals(), (before.0 + 1, before.1));

    sampled_scan::set_test_now(Some(due));
    assert!(loaded.files[&key].audit_requires_full(due));
    let (mut audited, result, seen, read) = page_injecting(
        &fixture,
        CLAUDE,
        loaded,
        &cache,
        |mode| mode == ReadMode::Full(FullReason::AuditDue),
        |_| {},
    );
    assert_eq!(read.mode, ReadMode::Full(FullReason::AuditDue));
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(seen.full_reasons[AUDIT_DUE], 1);
    assert_eq!(seen.unreadable, 0);
    assert!(!audited.files[&key].has_unverified_source());
    let record = audited.claude_request_census_for_test().get(&key).unwrap();
    assert_eq!(record.shape_for_test(), Shape::IdentityIncomplete);
    assert!(!record.unverified_or_twin(), "Full verifies the source");
    assert!(
        !record.can_bind_recomposed_body(),
        "shape gate stays narrow"
    );
    assert_eq!(audited.claude_usage_family_witnesses[SESSION], witness);
    assert!(
        mints_v1(&mut audited, &result, 0..6),
        "audit releases N1 hold"
    );
    assert_eq!(
        identity_incomplete_hold_totals(),
        (before.0 + 1, before.1 + 1)
    );
}

/// Resets the thread-local sampled scan clock, panic-safe.
struct TestClock;
impl Drop for TestClock {
    fn drop(&mut self) {
        sampled_scan::set_test_now(None);
    }
}

/// A held N1 Tail built as `fe_n1_held_tail_save_reload_reaches_due_full_and_reproves`
/// builds it (Full one interval before `due`, id-less Tail just before), then
/// a marker-erasing downgrade: 0.1.189's parse-free migrate rewrites the
/// entry to plain v2, the index is saved, the retained copy lost and the
/// index reloaded.
struct ErasedHold {
    fixture: ScanFixture,
    key: String,
    cache: Arc<sampled_scan::SharedCache>,
    /// The saved index file `index` was loaded from (save is CAS-bound to it).
    index_path: PathBuf,
    index: ScanIndex,
    witness: ClaudeUsageFamilyWitness,
}

fn erased_hold(due: u64) -> ErasedHold {
    use crate::snapshots::claude_request_census::ClaudeRequestCensusShape as Shape;
    sampled_scan::set_test_now(Some(
        due - crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
    ));
    let fixture = ScanFixture::new(CLAUDE);
    append_raw(&fixture.file.0, &row_bytes(CLAUDE, 0..6));
    let key = local_index_key(&fixture.file.0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut index, first, seen) = plain(&fixture, CLAUDE, ScanIndex::default(), &cache);
    assert_eq!(seen.modes, (1, 0, 0));
    let mut proven = index.clone();
    assert!(mints_v1(&mut proven, &first, 0..6));
    index.claude_usage_family_witnesses = proven.claude_usage_family_witnesses;
    let witness = index.claude_usage_family_witnesses[SESSION].clone();
    let mut idless = row(CLAUDE, 6);
    idless.as_object_mut().unwrap().remove("requestId");
    fixture.file.append(&idless);
    sampled_scan::set_test_now(Some(due - 1));
    let (mut index, tail, seen) = plain(&fixture, CLAUDE, index, &cache);
    assert_eq!(seen.modes, (0, 1, 0), "real continued Tail");
    assert_eq!(seen.unreadable, 0);
    assert_eq!(index.files[&key].unverified_deadline(), Some(due));
    let record = index.claude_request_census_for_test().get(&key).unwrap();
    assert_eq!(record.shape_for_test(), Shape::IdentityIncomplete);
    assert!(record.identity_incomplete_hold());

    let entry = index.files.get_mut(&key).unwrap();
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
    assert!(!entry.has_unverified_source());
    assert_eq!(entry.audit_obligation(due), None, "the deadline is lost");
    let path = fixture.dir.join("erased-index.json");
    index.save(&path).unwrap();
    drop(index);
    cache.clear();
    let index = ScanIndex::load(&path).unwrap();
    assert!(cache.retained_checkpoint(&key).is_none());
    assert_eq!(
        index.files[&key].scan_identity_version.as_deref(),
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    );
    let record = index.claude_request_census_for_test().get(&key).unwrap();
    assert!(record.identity_incomplete_hold(), "the hold survives");
    assert!(!mints_v1(&mut index.clone(), &tail, 0..6));
    ErasedHold {
        fixture,
        key,
        cache,
        index_path: path,
        index,
        witness,
    }
}

/// The restoration a sampled scan's setup runs, dated one interval before
/// `due`: the candidate clock stays real, so only an earlier restoration can
/// come due within a test. Real-clock pages prove the scan seam.
fn restore_dated(index: &mut ScanIndex, due: u64) -> usize {
    sampled_audit::restore_held_audit_deadlines(
        index,
        due - crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
    )
}

/// Option B (SOURCE rule 3): after a marker-erasing downgrade, nothing reads
/// the unchanged held file again. A sampled scan re-derives its deadline from
/// the persisted hold without reading, one interval out and once. The
/// restored deadline survives save/reload, comes due as Full(AuditDue), and
/// the verified source lets the saved witness re-prove.
#[test]
fn fe_n1_option_b_erased_hold_deadline_is_restored_and_audited() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::claude_request_census::{
        identity_incomplete_hold_deadlines_restored_total as restored,
        identity_incomplete_hold_totals, ClaudeRequestCensusShape as Shape,
    };
    use crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS as INTERVAL;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    let before = identity_incomplete_hold_totals();
    let restored_before = restored();
    let hold = erased_hold(due);
    let key = hold.key.clone();
    assert_eq!(identity_incomplete_hold_totals(), (before.0 + 1, before.1));
    assert_eq!(restored(), restored_before, "save/load restores nothing");

    // At the real clock, the restoring page reads nothing: the deadline is
    // one interval out, and a second page neither reads nor restores again.
    sampled_scan::set_test_now(None);
    let start = sampled_scan::now_seconds();
    let (paced, _, seen) = plain(&hold.fixture, CLAUDE, hold.index.clone(), &hold.cache);
    let end = sampled_scan::now_seconds();
    assert_eq!(seen.modes, (0, 0, 0), "restoration is no read");
    assert_eq!(seen.unreadable, 0);
    assert_eq!(restored(), restored_before + 1);
    let entry = &paced.files[&key];
    let deadline = entry.unverified_deadline().expect("deadline restored");
    assert!((start + INTERVAL..=end + INTERVAL).contains(&deadline));
    assert!(entry.has_prefix_provenance(), "fail closed to `p`");
    assert!(!entry.audit_requires_full(end));
    let (paced, _, seen) = plain(&hold.fixture, CLAUDE, paced, &hold.cache);
    assert_eq!(seen.modes, (0, 0, 0));
    assert_eq!(paced.files[&key].unverified_deadline(), Some(deadline));
    assert_eq!(restored(), restored_before + 1, "restored once");

    // Restore the saved downgraded index one interval before `due`, save
    // and reload: the deadline persists and is not restored again.
    let mut restored_index = hold.index.clone();
    assert_eq!(restore_dated(&mut restored_index, due), 1);
    assert_eq!(restored(), restored_before + 2);
    assert_eq!(restored_index.files[&key].unverified_deadline(), Some(due));
    restored_index.save(&hold.index_path).unwrap();
    drop(restored_index);
    let mut loaded = ScanIndex::load(&hold.index_path).unwrap();
    assert_eq!(loaded.files[&key].unverified_deadline(), Some(due));
    assert_eq!(restore_dated(&mut loaded, due), 0);
    assert_eq!(loaded.files[&key].unverified_deadline(), Some(due));
    assert_eq!(restored(), restored_before + 2, "a restored marker is kept");
    assert_eq!(identity_incomplete_hold_totals(), (before.0 + 1, before.1));

    sampled_scan::set_test_now(Some(due));
    assert!(loaded.files[&key].audit_requires_full(due));
    let (mut audited, result, seen, read) = page_injecting(
        &hold.fixture,
        CLAUDE,
        loaded,
        &hold.cache,
        |mode| mode == ReadMode::Full(FullReason::AuditDue),
        |_| {},
    );
    assert_eq!(read.mode, ReadMode::Full(FullReason::AuditDue));
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(seen.full_reasons[AUDIT_DUE], 1);
    assert_eq!(seen.unreadable, 0);
    assert!(!audited.files[&key].has_unverified_source());
    let record = audited.claude_request_census_for_test().get(&key).unwrap();
    assert_eq!(record.shape_for_test(), Shape::IdentityIncomplete);
    assert!(!record.unverified_or_twin(), "Full verifies the source");
    assert!(
        !record.can_bind_recomposed_body(),
        "shape gate stays narrow"
    );
    assert_eq!(audited.claude_usage_family_witnesses[SESSION], hold.witness);
    assert!(
        mints_v1(&mut audited, &result, 0..6),
        "the audit releases the hold"
    );
    assert_eq!(
        identity_incomplete_hold_totals(),
        (before.0 + 1, before.1 + 1)
    );
    assert_eq!(restored(), restored_before + 2);
}

/// Option B keeps the age-window rescue: an erased hold whose file aged out
/// of the backfill window leaves discovery. While the audit-slot budget
/// defers its restoration, reconciliation keeps the unobserved entry and its
/// hold; a later scan restores it without reading, and the restored marker
/// brings it back for its one due Full.
#[test]
fn fe_n1_option_b_aged_out_erased_hold_is_kept_then_rescued_for_due_full() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::snapshots::claude_request_census::identity_incomplete_hold_deadlines_restored_total as restored;
    use crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS as INTERVAL;
    use std::time::{Duration, UNIX_EPOCH};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    let restored_before = restored();
    let hold = erased_hold(due);
    let key = hold.key.clone();
    OpenOptions::new()
        .write(true)
        .open(&hold.fixture.file.0)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))
        .unwrap();
    assert!(
        !sampled_audit::path_requires_verification(&hold.index.files, &hold.fixture.file.0),
        "the erased marker lost the age-window rescue"
    );
    let held = |index: &ScanIndex| {
        index
            .claude_request_census_for_test()
            .get(&key)
            .is_some_and(|record| record.identity_incomplete_hold())
    };

    // Other pending audits leave only the slot restoration never takes.
    let mut crowded = hold.index.clone();
    // Synthetic keys outside the scan root, never walked or opened.
    let pending = (0..crate::transcript_cache::CACHE_ENTRIES - 1)
        .map(|slot| format!("/option-b-pending/{slot}"))
        .collect::<Vec<_>>();
    for pending_key in &pending {
        let mut entry = crowded.files[&key].clone();
        entry.set_unverified_deadline(due);
        crowded.files.insert(pending_key.clone(), entry);
    }
    sampled_scan::set_test_now(None);
    let (crowded, _, seen) = plain(&hold.fixture, CLAUDE, crowded, &hold.cache);
    assert_eq!(seen.modes, (0, 0, 0));
    assert_eq!(restored(), restored_before, "no free slot to restore into");
    assert_eq!(
        crowded.files[&key].scan_identity_version.as_deref(),
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
        "the deferred aged entry is kept"
    );
    assert!(held(&crowded), "and so is its hold");

    // A freed slot: the next scan restores it, reading nothing.
    let mut freed = crowded;
    freed.files.remove(&pending[0]);
    let start = sampled_scan::now_seconds();
    let (freed, _, seen) = plain(&hold.fixture, CLAUDE, freed, &hold.cache);
    let end = sampled_scan::now_seconds();
    assert_eq!(seen.modes, (0, 0, 0), "restoration is no read");
    assert_eq!(restored(), restored_before + 1);
    let deadline = freed.files[&key].unverified_deadline().unwrap();
    assert!((start + INTERVAL..=end + INTERVAL).contains(&deadline));
    assert!(sampled_audit::path_requires_verification(
        &freed.files,
        &hold.fixture.file.0
    ));
    assert!(held(&freed));

    // Dated one interval before `due` (the candidate clock stays real):
    // save, reload, and the due audit reaches the aged file.
    let mut restored_index = hold.index.clone();
    assert_eq!(restore_dated(&mut restored_index, due), 1);
    assert_eq!(restored(), restored_before + 2);
    assert_eq!(restored_index.files[&key].unverified_deadline(), Some(due));
    restored_index.save(&hold.index_path).unwrap();
    drop(restored_index);
    let loaded = ScanIndex::load(&hold.index_path).unwrap();

    sampled_scan::set_test_now(Some(due));
    let (audited, result, seen, read) = page_injecting(
        &hold.fixture,
        CLAUDE,
        loaded,
        &hold.cache,
        |mode| mode == ReadMode::Full(FullReason::AuditDue),
        |_| {},
    );
    assert_eq!(read.mode, ReadMode::Full(FullReason::AuditDue));
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(seen.unreadable, 0);
    assert!(
        !result.snapshots.is_empty(),
        "every age gate admits the audit"
    );
    assert!(!audited.files[&key].has_unverified_source());
    assert!(!held(&audited));
    assert_eq!(restored(), restored_before + 2);
}

/// A retained member can become old at candidate conversion or after its
/// stat but before open. Both age rejections settle as ordinary removals,
/// never as explicit vanished-file retirement.
#[test]
fn fe_n1_option_b_age_rejections_keep_deferred_hold_through_settlement_and_reload() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use std::time::{Duration, UNIX_EPOCH};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    for at_open in [false, true] {
        let hold = erased_hold(due);
        let key = hold.key.clone();
        let pending = || ScanTraversalPath {
            scan_root: hold.fixture.root.clone(),
            path: hold.fixture.file.0.clone(),
            census_member: true,
            watcher_hint: false,
        };
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            CLAUDE,
            pending(),
            &mut census,
            Some(due),
            BACKFILL_WINDOW_DAYS,
            &hold.index.files,
            None,
        )
        .expect("retained while recent");
        File::open(&hold.fixture.file.0)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))
            .unwrap();
        if at_open {
            assert!(open_and_identify_scan_candidate(
                CLAUDE,
                candidate,
                &mut census,
                Some(due),
                BACKFILL_WINDOW_DAYS,
                &hold.index.files,
                None,
            )
            .is_none());
        } else {
            assert!(candidate_from_traversal_path(
                CLAUDE,
                pending(),
                &mut census,
                Some(due),
                BACKFILL_WINDOW_DAYS,
                &hold.index.files,
                None
            )
            .is_none());
        }
        assert!(census.removed_index_keys.contains(&key));
        assert!(!census.claude_vanished_index_keys.contains(&key));
        let mut index = hold.index;
        // This earlier hold takes the one restoration, deferring the real
        // retained member. No deletion or manual freeing of an audit slot.
        index
            .files
            .insert("!earlier-held".into(), index.files[&key].clone());
        let record = index
            .claude_request_census_for_test()
            .get(&key)
            .unwrap()
            .clone();
        index
            .claude_request_census_mut_for_test()
            .insert_for_test("!earlier-held", record);
        sampled_scan::set_test_now(None);
        let removed = census.removed_index_keys.clone();
        let (mut index, _, seen) = page(&hold.fixture, CLAUDE, index, &hold.cache, |scan| {
            scan.census
                .removed_index_keys
                .extend(removed.iter().cloned());
        });
        assert_eq!(seen.modes, (0, 0, 0));
        assert!(sampled_audit::awaits_hold_deadline_restoration(
            &index, &key
        ));
        index.save(&hold.index_path).unwrap();
        let index = ScanIndex::load(&hold.index_path).unwrap();
        assert!(sampled_audit::awaits_hold_deadline_restoration(
            &index, &key
        ));
        let (mut index, _, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
        assert_eq!(seen.modes, (0, 0, 0));
        assert!(index.files[&key].has_prefix_provenance());
        // Date this already-restored deadline so the real candidate clock
        // and deterministic acquisition clock agree, then persist it again.
        index
            .files
            .get_mut(&key)
            .unwrap()
            .set_unverified_deadline(due);
        index.save(&hold.index_path).unwrap();
        let index = ScanIndex::load(&hold.index_path).unwrap();
        sampled_scan::set_test_now(Some(due));
        let (mut index, result, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
        assert_eq!(seen.modes, (1, 0, 0));
        assert_eq!(seen.full_reasons[AUDIT_DUE], 1);
        assert_eq!(seen.unreadable, 0);
        assert!(!index
            .claude_request_census_for_test()
            .get(&key)
            .unwrap()
            .unverified_or_twin());
        assert_eq!(index.claude_usage_family_witnesses[SESSION], hold.witness);
        assert!(mints_v1(&mut index, &result, 0..6));
    }
}

/// Saturate the marker pool with debts that cannot drain, then cross the
/// 255 boundary with readable old downgraded holds. Real pages, saved and
/// reloaded on every turn, must give every readable member its due Full.
/// The test never deletes a pending slot. Failed progress turns rotate too.
#[test]
fn fe_n1_option_b_saturated_non_draining_debts_do_not_starve_many_readable_holds() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS as INTERVAL;
    use crate::transcript_cache::CACHE_ENTRIES;
    use std::time::{Duration, UNIX_EPOCH};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let population = CACHE_ENTRIES + 1;
    let now = sampled_scan::now_seconds();
    let start = now - (population as u64 * 2 + 8) * INTERVAL;
    let hold = erased_hold(start);
    let template = hold.index.files[&hold.key].clone();
    let record = hold
        .index
        .claude_request_census_for_test()
        .get(&hold.key)
        .unwrap()
        .clone();
    let bytes = String::from_utf8(bytes_of(&hold.fixture.file.0)).unwrap();
    let mut index = hold.index;
    let mut readable = BTreeSet::from([hold.key.clone()]);
    let age = |path: &Path| {
        File::open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))
            .unwrap()
    };
    age(&hold.fixture.file.0);
    for n in 0..population {
        let session = format!("held-{n:04}");
        let path = hold.fixture.root.join(format!("{session}.jsonl"));
        fs::write(&path, bytes.replace(SESSION, &session)).unwrap();
        age(&path);
        let key = local_index_key(&path);
        index.files.insert(key.clone(), template.clone());
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(&key, record.clone());
        readable.insert(key);
    }
    // Both missing ancestors and files beyond the cap are non-draining.
    let oversized = hold.fixture.root.join("oversized.jsonl");
    File::create(&oversized)
        .unwrap()
        .set_len(max_jsonl_file_bytes(CLAUDE) + 1)
        .unwrap();
    let mut debts = BTreeSet::new();
    for n in 0..CACHE_ENTRIES - 1 {
        let key = if n == 0 {
            local_index_key(&oversized)
        } else {
            format!("/unavailable-option-b-root/{n}/session.jsonl")
        };
        let mut pending = template.clone();
        pending.set_unverified_deadline(start);
        index.files.insert(key.clone(), pending);
        debts.insert(key);
    }
    // An unavailable *hold* selected before the readable set must also
    // rotate out, without erasing its hold or any ordinary audit marker.
    let unavailable = hold.fixture.root.join("000-unavailable/held.jsonl");
    let unavailable_key = local_index_key(&unavailable);
    index.files.insert(unavailable_key.clone(), template);
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&unavailable_key, record);
    // A prior configured root disappeared while its slot was waiting.
    // Reloaded scheduling state must rotate to the current roots.
    let old_root_key = "/previous-option-b-root/held.jsonl";
    index
        .files
        .insert(old_root_key.into(), index.files[&hold.key].clone());
    let old_root_record = index
        .claude_request_census_for_test()
        .get(&hold.key)
        .unwrap()
        .clone();
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(old_root_key, old_root_record);
    index.held_audit_progress = Some(sampled_audit::HeldAuditProgress {
        key: old_root_key.into(),
        due: start + INTERVAL,
        attempted: false,
    });
    index.save(&hold.index_path).unwrap();
    index = ScanIndex::load(&hold.index_path).unwrap();
    let mut completed = BTreeSet::new();
    let mut fulls = 0;
    for turn in 0..(readable.len() * 2 + 4) {
        sampled_scan::set_test_now(Some(start + turn as u64 * INTERVAL));
        let (next, _, seen) = page(&hold.fixture, CLAUDE, index, &hold.cache, |scan| {
            let context = scan.sampling.as_ref().unwrap();
            assert!(context.audit_metadata_supported);
            assert_eq!(context.audit_slots, 1, "last sampled slot stays free");
        });
        index = next;
        assert!(seen.modes.0 <= 1, "one recovery Full per page");
        assert_eq!(seen.modes.0, seen.full_reasons[AUDIT_DUE]);
        fulls += seen.modes.0;
        for key in &readable {
            if index
                .claude_request_census_for_test()
                .get(key)
                .is_some_and(|record| !record.unverified_or_twin())
            {
                completed.insert(key.clone());
            }
        }
        for key in &debts {
            assert_eq!(index.files[key].unverified_deadline(), Some(start));
        }
        assert!(sampled_audit::awaits_hold_deadline_restoration(
            &index,
            &unavailable_key
        ));
        index.save(&hold.index_path).unwrap();
        index = ScanIndex::load(&hold.index_path).unwrap();
        if completed == readable {
            break;
        }
    }
    assert_eq!(completed, readable, "every readable hold got its Full");
    assert_eq!(fulls, readable.len(), "exactly one Full per readable hold");
    assert_eq!(
        index
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count(),
        CACHE_ENTRIES - 1
    );
}

/// Failed native revalidation and disclosed terminal loss must retain the
/// virtual recovery obligation across partial settlement/save/reload, and
/// must never turn it into a sampled marker taking the reserved last slot.
#[test]
fn fe_n1_option_b_failed_virtual_audits_keep_hold_and_reserved_slot_then_reprove() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    use crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS as INTERVAL;
    use crate::transcript_cache::CACHE_ENTRIES;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    for failure in 0..3 {
        let hold = erased_hold(due - 4 * INTERVAL);
        let key = hold.key.clone();
        let mut index = hold.index;
        for n in 0..CACHE_ENTRIES - 1 {
            let mut pending = index.files[&key].clone();
            pending.set_unverified_deadline(due);
            index
                .files
                .insert(format!("/non-draining-retry/{n}"), pending);
        }
        let path = hold.fixture.file.0.clone();
        let bytes = bytes_of(&path);
        if failure == 1 {
            hold.fixture.file.append(&json!({
                "type":"ignored", "padding":"x".repeat(MAX_JSONL_LINE_BYTES + 1024)
            }));
        }
        if failure == 2 {
            // As the existing finalizer-only response-loss fixture: neither
            // row loses at read time; their usages conflict only at finish.
            let mut conflict = row(CLAUDE, 5);
            conflict["message"]["usage"]["input_tokens"] = json!(999);
            conflict["message"]["usage"]["output_tokens"] = json!(0);
            hold.fixture.file.append(&conflict);
        }
        File::open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        sampled_scan::set_test_now(Some(due - 4 * INTERVAL));
        let (mut index, _, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
        assert_eq!(seen.modes, (0, 0, 0), "scheduling is zero reads");
        index.save(&hold.index_path).unwrap();
        let index = ScanIndex::load(&hold.index_path).unwrap();
        sampled_scan::set_test_now(Some(due - 3 * INTERVAL));
        let mut index = if failure != 0 {
            let (index, result, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
            assert_eq!(seen.full_reasons[AUDIT_DUE], 1);
            if failure == 1 {
                assert!(result.over_line_cap_count > 0);
            } else {
                assert!(
                    result.dropped_usage_record_count > 0,
                    "loss found by finalization"
                );
            }
            assert!(!mints_v1(&mut index.clone(), &result, 0..6));
            index
        } else {
            let parked = path.with_extension("parked");
            let (index, _, seen, read) = page_injecting(
                &hold.fixture,
                CLAUDE,
                index,
                &hold.cache,
                |mode| mode == ReadMode::Full(FullReason::AuditDue),
                |_| {
                    fs::rename(&path, &parked).unwrap();
                    std::os::unix::fs::symlink("missing-target", &path).unwrap();
                },
            );
            assert_eq!(read.mode, ReadMode::Full(FullReason::AuditDue));
            assert!(seen.unreadable > 0, "completion re-open must fail");
            fs::remove_file(&path).unwrap();
            fs::rename(&parked, &path).unwrap();
            index
        };
        assert!(sampled_audit::awaits_hold_deadline_restoration(
            &index, &key
        ));
        assert_eq!(
            index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            CACHE_ENTRIES - 1
        );
        index.save(&hold.index_path).unwrap();
        let index = ScanIndex::load(&hold.index_path).unwrap();
        assert!(sampled_audit::awaits_hold_deadline_restoration(
            &index, &key
        ));
        // Repair the source after the failed attempt; no audit slot is freed.
        fs::write(&path, &bytes).unwrap();
        File::open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        hold.cache.clear();
        sampled_scan::set_test_now(Some(due - 2 * INTERVAL));
        let (mut index, _, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
        assert_eq!(seen.modes, (0, 0, 0), "retry waits a fresh interval");
        index.save(&hold.index_path).unwrap();
        let index = ScanIndex::load(&hold.index_path).unwrap();
        sampled_scan::set_test_now(Some(due - INTERVAL));
        let (mut index, result, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
        assert_eq!(seen.full_reasons[AUDIT_DUE], 1);
        assert_eq!(seen.unreadable, 0);
        assert!(!index
            .claude_request_census_for_test()
            .get(&key)
            .unwrap()
            .unverified_or_twin());
        assert!(mints_v1(&mut index, &result, 0..6));
        assert_eq!(
            index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            CACHE_ENTRIES - 1
        );
    }
}

/// Option B reads nothing extra: a plain-v2 entry without an N1 hold (a
/// verified Full) gets no deadline and no read, and counts no restoration.
#[test]
fn fe_n1_option_b_unheld_plain_entry_gets_no_deadline() {
    use crate::snapshots::claude_request_census::identity_incomplete_hold_deadlines_restored_total as restored;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let restored_before = restored();
    let fixture = ScanFixture::new(CLAUDE);
    append_raw(&fixture.file.0, &row_bytes(CLAUDE, 0..6));
    let key = local_index_key(&fixture.file.0);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, seen) = plain(&fixture, CLAUDE, ScanIndex::default(), &cache);
    assert_eq!(seen.modes, (1, 0, 0));
    assert_eq!(
        index.files[&key].scan_identity_version.as_deref(),
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    );
    let record = index.claude_request_census_for_test().get(&key).unwrap();
    assert!(!record.identity_incomplete_hold());
    cache.clear();
    let (index, _, seen) = plain(&fixture, CLAUDE, index, &cache);
    assert_eq!(seen.modes, (0, 0, 0), "no extra read");
    assert_eq!(
        index.files[&key].scan_identity_version.as_deref(),
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    );
    assert_eq!(restored(), restored_before);
}

/// SOURCE Option 1 condition: historical replay keeps every stem entry and
/// re-sets its deadline with the prefix flag preserved, so a replay reset
/// cannot turn an FE prefix into `None` or a clean identity. Before the next
/// re-record, the replayed prefix still mints no positive verdict.
#[test]
fn fe_prefix_entry_survives_replay_reset_without_positive_verdict() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut grown = grown_full();
    let key = grown.base.key.clone();
    let before = grown.index.files[&key].unverified_deadline();
    assert!(grown.index.files[&key].has_prefix_provenance());
    grown
        .index
        .prepare_historical_replay("fe-prefix-replay".into());
    let entry = grown
        .index
        .files
        .get(&key)
        .expect("replay retains a stem entry");
    assert!(entry.has_unverified_source());
    assert!(entry.has_prefix_provenance());
    assert!(entry
        .scan_identity_version
        .as_deref()
        .unwrap()
        .ends_with(":p"));
    assert_eq!(entry.unverified_deadline(), before);
    assert!(!mints_v1(&mut grown.index, &grown.result, 0..9));
}

/// N4 (fe-seam-ack §5, #660 second-lander parity): only a completion that
/// retains a copy retires a suspended Codex proof beside it. An ordinary
/// retaining Claude Full still passes its copy budget to the retire
/// (unchanged); an H3c grown Claude read retains nothing, so it passes none
/// (`retaining && !h3c_route`) and the suspended proof is kept.
#[test]
fn fe_n4_h3c_grown_read_never_retires_a_suspended_proof() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe as observe_side;
    use crate::snapshots::sampled_scan::codex_cursor::{ProofJob, ProofLease};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let suspend = |cache: &Arc<sampled_scan::SharedCache>| {
        let job = Box::new(ProofJob {
            namespace: "n4-proof".to_owned(),
            index_path: PathBuf::from("/n4/index.json"),
            incarnation: "n4".to_owned(),
            entries: vec![("k".repeat(1 << 20), 1)],
            next_row_end: 0,
            touched_page: 0,
            readers: None,
        });
        assert!(
            ProofLease::new(cache, job).suspend(),
            "precondition: suspended"
        );
        assert!(cache.proof_suspended_for_test().is_some());
        sampled_scan::copy_retire_probe();
    };

    // Ordinary retaining path (unchanged): a quiescent first Full keeps its
    // copy and calls the retire with its copy budget.
    let fixture = ScanFixture::new(CLAUDE);
    append_raw(&fixture.file.0, &row_bytes(CLAUDE, 0..6));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    suspend(&cache);
    let (_, _, seen) = plain(&fixture, CLAUDE, ScanIndex::default(), &cache);
    assert_eq!(seen.modes, (1, 0, 0), "precondition: one Full read");
    assert!(cache
        .retained_checkpoint(&local_index_key(&fixture.file.0))
        .is_some());
    let probe = sampled_scan::copy_retire_probe().expect("a retaining completion retires beside");
    assert!(probe.budget > 0, "{probe:?}");
    assert!(probe.fits(), "{probe:?}");

    // H3c: the grown in-page Full publishes its sealed prefix and passes no
    // copy budget, so no budgeted retire runs and the proof is kept.
    let mut base = baseline(CLAUDE, 4, 2);
    base.cache.clear();
    suspend(&base.cache);
    let path = base.path.clone();
    let index = std::mem::take(&mut base.index);
    let ((index, _, seen, read), counts) = observe_side(|| {
        page_injecting(&base.fixture, CLAUDE, index, &base.cache, is_full, |_| {
            append_raw(&path, &row_bytes(CLAUDE, 6..9))
        })
    });
    assert!(is_full(read.mode), "precondition: an in-page Full");
    assert_eq!(seen.unreadable, 0, "causes={:?}", seen.causes);
    assert!(
        index.files[&base.key].has_prefix_provenance(),
        "precondition: H3c published a prefix"
    );
    assert!(base.cache.retained_checkpoint(&base.key).is_none());
    assert!(
        sampled_scan::copy_retire_probe().is_none(),
        "no budgeted retire on the H3c route"
    );
    assert!(
        base.cache.proof_suspended_for_test().is_some(),
        "proof kept"
    );
    assert_eq!(counts.side_proof_drops, 0);
}

/// #665/#702 second-lander control. The same continued Tail is short of
/// copy room in both worlds. Without growth it proves and executes a release;
/// H3c growth keeps every resident and the suspended proof, with no copy,
/// X_out proof, reserved retention peak or deferred release. Pressure uses
/// R0's existing test-only insert-term seam; all ranks and releases are real.
#[test]
fn fe_second_lander_h3c_release_pressure_keeps_victims_and_suspended_proof() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe as observe_side;
    use crate::snapshots::sampled_scan::codex_cursor::{bound_for_main, ProofJob, ProofLease};
    use sampled_scan::test_hooks::{self, Decision};

    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let state_bytes = crate::snapshots::cache_policy_tests::POLICY_STATE_BYTES;
    for grow in [false, true] {
        let mut base = baseline(CLAUDE, 4, 2);
        let older = (0..2)
            .map(|_| {
                let fixture = ScanFixture::new(CLAUDE);
                // One victim must cover the real X_out + decode peak as
                // well as the copy. Two 512-row residents can leave that
                // proof infeasible or exceed its copy-only victim count.
                append_raw(&fixture.file.0, &row_bytes(CLAUDE, 0..4096));
                OpenOptions::new()
                    .write(true)
                    .open(&fixture.file.0)
                    .unwrap()
                    .set_modified(SystemTime::now() - std::time::Duration::from_secs(7200))
                    .unwrap();
                // Seed a real native reduction through ordinary cache
                // admission, as cache_policy_tests seeds its fillers. A
                // whole-page Full also reserves its finished output; that
                // unrelated finalization bound can discard this large copy.
                let (mut parser, _, scope) = native_parser(&fixture.file, CLAUDE);
                let now = sampled_scan::now_seconds();
                assert!(is_full(
                    parser.prepare_acquisition(None, &scope, None, now).unwrap()
                ));
                while !parser.step().unwrap() {}
                let completed = parser
                    .retain_reduction(
                        &scope,
                        now,
                        sampled_scan::RetainBudget::granted_unclassified(
                            crate::transcript_cache::ENTRY_BYTES,
                        ),
                    )
                    .unwrap()
                    .unwrap();
                assert!(!completed.unsealed, "precondition: a complete victim");
                let retained = Retained {
                    checkpoint: completed.checkpoint,
                    state: completed.reduction.expect("victim fits one cache entry"),
                };
                drop(parser);
                assert!(base
                    .cache
                    .retained()
                    .unwrap()
                    .insert(local_index_key(&fixture.file.0), retained));
                assert!(base
                    .cache
                    .retained_checkpoint(&local_index_key(&fixture.file.0))
                    .is_some());
                fixture
            })
            .collect::<Vec<_>>();
        let before = base
            .cache
            .retained()
            .unwrap()
            .victims()
            .into_iter()
            .filter(|(key, _, _)| key != &base.key)
            .collect::<Vec<_>>();
        assert_eq!(before.len(), older.len(), "precondition: older residents");
        assert!(
            base.cache.retained_checkpoint(&base.key).is_some(),
            "precondition: the complete baseline survived resident setup"
        );
        let job = Box::new(ProofJob {
            namespace: "fe-second-lander-proof".to_owned(),
            index_path: PathBuf::from("/fe-second-lander/index.json"),
            incarnation: "fe-second-lander".to_owned(),
            entries: vec![("k".repeat(1 << 20), 1)],
            next_row_end: 0,
            touched_page: 0,
            readers: None,
        });
        assert!(ProofLease::new(&base.cache, job).suspend());
        let proof = base.cache.proof_suspended_for_test();
        assert!(proof.is_some(), "precondition: suspended proof");
        sampled_scan::copy_retire_probe();
        test_hooks::clear();
        let mut read = None;
        let index = std::mem::take(&mut base.index);
        let (((index, result, seen), counts), side_counts) = observe_side(|| {
            observe(|| {
                page(&base.fixture, CLAUDE, index, &base.cache, |scan| {
                    if read.is_some() {
                        return;
                    }
                    if let Some(opened) = opened(scan) {
                        assert!(is_tail(opened.mode), "precondition: continued Tail");
                        let resident = bound_for_main(scan.sampling.as_ref().unwrap(), state_bytes)
                            .expect("precondition: measured residents");
                        // Give the insert term exactly the remaining room:
                        // b_ins = 0. Only a completion-time release can fund
                        // retention; this never changes the production limit.
                        test_hooks::set_ins_extra(Some(state_bytes - resident));
                        if grow {
                            append_raw(&base.path, &row_bytes(CLAUDE, 6..9));
                        }
                        read = Some(opened);
                    }
                })
            })
        });
        let read = read.expect("precondition: opened read");
        let probe = test_hooks::last_probe();
        assert_eq!(seen.unreadable, 0, "grow={grow}: {:?}", seen.causes);
        assert_eq!(probe.b_ins, 0, "precondition: no copy room; {probe:?}");
        assert!(probe.clone.is_some_and(|clone| clone > probe.b_ins));
        assert!(probe.rank.is_some(), "precondition: release-eligible Tail");
        if grow {
            assert_prefix_published(
                "second-lander",
                &base,
                &index,
                result,
                &seen,
                &read,
                read.frozen,
            );
            assert!(index.files[&base.key].has_prefix_provenance());
            assert_eq!(base.cache.retained().unwrap().victims(), before);
            assert_eq!(base.cache.proof_suspended_for_test(), proof, "proof kept");
            assert_eq!(side_counts.side_proof_drops, 0);
            assert!(sampled_scan::copy_retire_probe().is_none());
            assert!(
                test_hooks::decisions().is_empty(),
                "no retention or deferred release"
            );
            assert_eq!(probe.granted_peak, None, "no reserved retention peak");
            assert_eq!(probe.x_out, None, "no X_out proof");
            assert_eq!(probe.need_prime, None, "no deferred release proof");
            assert_eq!(
                (
                    counts.copy_refusal_admission_evicted,
                    counts.copy_refusal_entries_evicted,
                    counts.clear_entries_released,
                    counts.insert_entries_evicted,
                    counts.retention_produced,
                    counts.insert_admitted,
                ),
                (0, 0, 0, 0, 0, 0),
                "zero victims and no copy: {counts:?}"
            );
        } else {
            let (victims, copy_only) = probe
                .prefixes
                .expect("precondition: residents fund the real X_out release proof");
            assert!(victims > 0, "precondition: nonempty release; {probe:?}");
            assert_eq!(
                victims, copy_only,
                "precondition: X_out stays within the copy-only victim cap; {probe:?}"
            );
            let need = probe
                .need_prime
                .expect("precondition: measured release need");
            assert!(
                before[0].2 >= need + 256 * 1024,
                "precondition: one victim funds X_out and peak with margin; {probe:?}"
            );
            eprintln!(
                "FE second-lander grow={grow} probe={probe:?} counts={counts:?} side={side_counts:?}"
            );
            assert!(!index.files[&base.key].has_prefix_provenance());
            assert!(base.cache.retained_checkpoint(&base.key).is_some());
            assert!(matches!(
                test_hooks::decisions().as_slice(),
                [Decision::Deferred { .. }]
            ));
            assert!(
                counts.copy_refusal_admission_evicted > 0,
                "release-pressure control: {probe:?} {counts:?}"
            );
        }
        test_hooks::clear();
    }
}

mod held_audit_due_carry_tests;
