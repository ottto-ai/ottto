//! Offline cursor-job, page-budget, S5 reader and singleton-memo tests.
//! Every fixture is synthetic; no provider account content.
use super::*;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES;
use crate::transcript_cache::ENTRY_BYTES;

fn plain_path() -> &'static Path {
    Path::new("fixture.jsonl")
}

const NOW: &str = "2026-10-07T12:00:00Z";
const SESSION: &str = "019fa111-2222-7333-8444-555555555555";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-codex-cursor-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }
    fn append(&self, bytes: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(&self.0).unwrap();
        file.write_all(bytes).unwrap();
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(&self.0);
    }
}

fn limits(cursor: u64, singleton: u64, skip_chunk: usize) -> Limits {
    Limits {
        cursor,
        singleton,
        skip_chunk,
    }
}

#[test]
fn page_budget_plans_cursor_singleton_and_deferral() {
    let limits = limits(100, 50, 8);
    let mut page = PageBudget::default();
    assert_eq!(page.plan(limits, 40, true, true), StartPlan::Singleton);
    assert_eq!(page.plan(limits, 60, true, true), StartPlan::Cursor);
    // One slot: a second large file waits for the next page. There is no
    // unpaged fallback on a supported build.
    assert_eq!(page.plan(limits, 60, false, true), StartPlan::Defer);
    // C4: without layout support the cursor is off as a whole and a large
    // file reads in its page as before; small reads keep their budget.
    assert_eq!(page.plan(limits, 60, true, false), StartPlan::Unpaged);
    assert_eq!(page.plan(limits, 60, false, false), StartPlan::Unpaged);
    assert_eq!(page.plan(limits, 40, true, false), StartPlan::Singleton);
    page.charge(false, 30);
    assert_eq!(page.plan(limits, 20, true, true), StartPlan::Singleton);
    assert_eq!(page.plan(limits, 21, true, true), StartPlan::Defer);
    assert_eq!(page.plan(limits, 21, true, false), StartPlan::Defer);
    page.charge(false, 40);
    // An unchanged file costs nothing and is never deferred.
    assert_eq!(page.plan(limits, 0, true, true), StartPlan::Singleton);
    assert!(!page.cursor_exhausted(limits));
    page.charge(true, 100);
    assert!(page.cursor_exhausted(limits));
    assert_eq!(page.plan(limits, 60, true, true), StartPlan::Defer);
    // The disabled cursor is disclosed once per scan object.
    let cache = SharedCache::default();
    page.disclose_disabled(&cache);
    page.disclose_disabled(&cache);
    let disclosed = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| cursor.counters.cursor_disabled_unsupported_layout)
            .unwrap()
    };
    assert_eq!(disclosed(&cache), 1);
    PageBudget::default().disclose_disabled(&cache);
    assert_eq!(disclosed(&cache), 2);
}

#[test]
fn repeated_invalidations_end_as_member_changed_and_parked_files_wake_on_object_change() {
    let mut state = CursorState::default();
    for _ in 1..MEMBER_CHANGED_AFTER {
        assert!(!invalidated(&mut state, "key"));
    }
    assert!(invalidated(&mut state, "key"));
    assert_eq!(
        state.counters.jobs_invalidated,
        u64::from(MEMBER_CHANGED_AFTER)
    );
    assert_eq!(state.counters.jobs_member_changed, 1);
    // The count restarts after the disclosure.
    assert!(!invalidated(&mut state, "key"));
    let temp = Temp::new("parked", b"{\"a\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let parked = |dependencies: Option<&str>| Parked {
        stamp: OpenStamp::capture(&file).unwrap(),
        dependencies: dependencies.map(str::to_owned),
        disclosure: strict(DebtReason::JoinStateBound),
        used: 0,
        exact: false,
    };
    let cache = SharedCache::default();
    cache.with_cursor(|cursor| park(cursor, "key".into(), parked(Some("dependencies"))));
    // Unchanged object and inputs: the strict debt is disclosed again and
    // nothing is read.
    let hit = cache.cursor_parked("key", &file, Some("dependencies"));
    assert_eq!(
        hit.map(|disclosure| (disclosure.reason, disclosure.state_only_blocked_session_ids)),
        Some((DebtReason::JoinStateBound, vec![SESSION.to_owned()]))
    );
    // Growth cannot cure a prefix that only grows: still parked (R2-B3).
    temp.append(b"{\"b\":2}\n");
    assert!(cache
        .cursor_parked("key", &file, Some("dependencies"))
        .is_some());
    // A copy-refusal release keeps parked records (K6).
    cache.clear();
    assert!(cache
        .cursor_parked("key", &file, Some("dependencies"))
        .is_some());
    // A changed dependency wakes it: the record is gone and the file retries.
    assert!(cache.cursor_parked("key", &file, Some("other")).is_none());
    assert!(cache
        .cursor_parked("key", &file, Some("dependencies"))
        .is_none());
    // So does a shrink or in-place rewrite of the held object.
    cache.with_cursor(|cursor| park(cursor, "key".into(), parked(None)));
    fs::write(&temp.0, b"{}\n").unwrap();
    assert!(cache.cursor_parked("key", &file, None).is_none());
    cache.with_cursor(|cursor| {
        for index in 0..=PARKED_KEYS {
            let used = cursor.tick();
            park(
                cursor,
                format!("key-{index:03}"),
                Parked {
                    used,
                    ..parked(None)
                },
            );
        }
        assert_eq!(cursor.parked.len(), PARKED_KEYS);
        // The least recently used record goes first (L1).
        assert!(!cursor.parked.contains_key("key-000"));
        assert!(cursor.parked.contains_key(&format!("key-{PARKED_KEYS:03}")));
        assert_eq!(cursor.counters.parked_hits, 3);
    });
}

#[test]
fn open_stamp_accepts_growth_and_refuses_shrink_or_replacement() {
    let temp = Temp::new("stamp", b"{\"a\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let open = OpenStamp::capture(&file).unwrap();
    assert!(open.append_compatible(&open.clone()));
    temp.append(b"{\"b\":2}\n");
    let grown = OpenStamp::capture(&file).unwrap();
    assert!(grown.extent > open.extent);
    assert!(open.append_compatible(&grown));
    fs::write(&temp.0, b"{}\n").unwrap();
    assert!(!open.append_compatible(&OpenStamp::capture(&file).unwrap()));
    let other = Temp::new("stamp-replacement", b"{\"a\":1}\n");
    fs::rename(&other.0, &temp.0).unwrap();
    let replaced = OpenStamp::capture(&File::open(&temp.0).unwrap()).unwrap();
    assert!(!open.append_compatible(&replaced));
}

fn reader_input() -> (Vec<u8>, u64, u64) {
    let mut input = b"{\"n\":1}\n".to_vec();
    input.extend_from_slice(format!("{{\"big\":\"{}\"}}\n", "x".repeat(200)).as_bytes());
    let second = input.len() as u64;
    input.extend_from_slice(b"{\"n\":2}\n");
    let frozen = input.len() as u64;
    input.extend_from_slice(b"{\"n\":3,\"after\":true}\n");
    (input, second, frozen)
}

#[test]
fn cursor_reader_chunks_overlong_skip_and_freezes_extent() {
    let (input, second, frozen) = reader_input();
    let mut reader =
        BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 64, false);
    reader.set_chunked_skip(32);
    // The frozen extent cuts the fourth record five bytes in.
    reader.set_extent_limit(frozen + 5);
    let mut seen = Vec::new();
    assert_eq!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Line
    );
    assert_eq!(reader.last_complete_line_end(), 8);
    assert!(!reader.lossy_prefix());
    let mut partials = 0;
    loop {
        match reader.step(|value| seen.push(value.clone())).unwrap() {
            JsonlReaderStep::Partial => {
                partials += 1;
                // A paused skip delivers and counts nothing.
                assert_eq!(reader.report.physical_line_count, 1);
                assert!(reader.buf.len() <= 64);
                // E4: the paused skip holds no prefix byte.
                assert!(reader.buf.is_empty());
                if partials == 1 {
                    // Pause-time shrink (parent ACK): a grown buffer is cut
                    // back to `max(len, 64 KiB)` with every live byte and the
                    // skip state kept; the slot charge walks the actual
                    // capacity, which the rest of this read then reuses.
                    reader.buf.reserve(1 << 20);
                    let live = reader.buf.clone();
                    shrink_paused_buffer(&mut reader.buf);
                    assert_eq!(reader.buf, live);
                    assert!(reader.skipping.is_some());
                    assert!(reader.buf.capacity() >= live.len().max(PAUSED_BUFFER_BYTES));
                    assert!(reader.buf.capacity() < 1 << 20);
                }
            }
            JsonlReaderStep::Line => break,
            JsonlReaderStep::Complete(_) => panic!("overlong line must finish"),
        }
    }
    assert!(partials > 0, "the skip paused at least once");
    assert_eq!(reader.last_complete_line_end(), second);
    assert_eq!(reader.report.over_line_cap_count, 1);
    assert!(reader.lossy_prefix());
    assert_eq!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Line
    );
    assert!(matches!(
        reader.step(|value| seen.push(value.clone())).unwrap(),
        JsonlReaderStep::Complete(_)
    ));
    assert!(reader.sealed_fragment());
    assert_eq!(reader.consumed_bytes(), frozen + 5);
    assert_eq!(reader.last_complete_line_end(), frozen);
    assert_eq!(reader.report.physical_line_count, 3);
    assert_eq!(seen, vec![json!({"n":1}), json!({"n":2})]);
}

/// Parent S5 "Critical" (R1-B4): at sealed cursor completion a final record
/// without its newline at or before the frozen extent is never parsed,
/// counted or certified, even when no byte beyond the extent is visible.
/// A read without an extent keeps today's trailing-line behavior.
#[test]
fn sealed_completion_withholds_unterminated_record_even_at_end_of_file() {
    let mut input = b"{\"n\":1}\n{\"n\":2}\n".to_vec();
    let sealed = input.len() as u64;
    input.extend_from_slice(b"{\"n\":3}");
    let read = |extent: Option<u64>| {
        let mut reader =
            BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 64, false);
        if let Some(extent) = extent {
            reader.set_extent_limit(extent);
        }
        let mut seen = Vec::new();
        loop {
            match reader.step(|value| seen.push(value.clone())).unwrap() {
                JsonlReaderStep::Line | JsonlReaderStep::Partial => {}
                JsonlReaderStep::Complete(report) => return (seen, report, reader),
            }
        }
    };
    // The file ends exactly at the extent: nothing beyond it is visible.
    let (seen, report, reader) = read(Some(input.len() as u64));
    assert_eq!(seen, vec![json!({"n":1}), json!({"n":2})]);
    assert!(reader.sealed_fragment());
    assert_eq!(report.physical_line_count, 2);
    assert_eq!(report.parsed_json_line_count, 2);
    assert_eq!(reader.last_complete_line_end(), sealed);
    assert!(reader.consumed_bytes() > reader.last_complete_line_end());
    // Unchanged non-cursor trailing-line behavior: the last line is parsed.
    let (seen, report, reader) = read(None);
    assert_eq!(seen, vec![json!({"n":1}), json!({"n":2}), json!({"n":3})]);
    assert!(!reader.sealed_fragment());
    assert_eq!(report.physical_line_count, 3);
    assert_eq!(report.parsed_json_line_count, 3);
}

/// S12 (R1-B5): `finish` honours a grown object only for the identity the
/// passed certificate proved, and only while the held FD is still that
/// object and no shorter than the frozen extent.
#[test]
fn sealed_prefix_grant_holds_only_for_the_certified_object() {
    let temp = Temp::new("prefix-grant", b"{\"a\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let open = OpenStamp::capture(&file).unwrap();
    let grant = SealedPrefix {
        dev: open.dev,
        ino: open.ino,
        extent: open.extent,
    };
    assert!(grant.holds(&file));
    temp.append(b"{\"b\":2}\n");
    assert!(grant.holds(&file), "growth past the frozen extent");
    assert!(!SealedPrefix {
        extent: open.extent + 1_000,
        ..grant
    }
    .holds(&file));
    let other = Temp::new("prefix-grant-other", b"{\"a\":1}\n{\"b\":2}\n");
    assert!(!grant.holds(&File::open(&other.0).unwrap()));
}

/// Parent ruling 2: the lossy same-object grant revalidates in `finish`
/// against the held FD and the selected path: growth holds; a replaced path
/// (the held FD unchanged) or a shrunk object does not.
#[test]
fn lossy_identity_grant_revalidates_held_object_and_selected_path() {
    let lines = b"{\"a\":1}\n{\"b\":2}\n";
    for edit in ["grow", "replace", "shrink"] {
        let temp = Temp::new("lossy-grant", lines);
        let mut file = OpenOptions::new().read(true).open(&temp.0).unwrap();
        let scope = Scope("lossy-grant".into());
        let mut plan =
            crate::transcript_acquisition::ReadPlan::prepare(&mut file, None, &scope, None, 100)
                .unwrap();
        let frozen = plan.frozen_length();
        plan.observe_complete_records(lines).unwrap();
        let (refusal, identity) = plan.commit_sealed_prefix_or_lossy_identity(
            &mut file, true, &scope, 100, 200, true, frozen,
        );
        assert_eq!(refusal.unwrap_err(), PrefixRefusal::Lossy);
        let grant = FinishGrant::LossySameObject(identity.expect("lossy-only refusal"));
        assert!(grant.holds(&mut file, &temp.0), "{edit}: unchanged");
        match edit {
            "grow" => {
                temp.append(b"{\"c\":3}\n");
                assert!(grant.holds(&mut file, &temp.0), "growth holds");
            }
            "replace" => {
                let replacement = temp.0.with_extension("replacement");
                fs::copy(&temp.0, &replacement).unwrap();
                fs::rename(&replacement, &temp.0).unwrap();
                temp.append(b"{\"c\":3}\n");
                assert!(!grant.holds(&mut file, &temp.0), "replaced path");
            }
            _ => {
                OpenOptions::new()
                    .write(true)
                    .open(&temp.0)
                    .unwrap()
                    .set_len(4)
                    .unwrap();
                assert!(!grant.holds(&mut file, &temp.0), "shrunk");
            }
        }
    }
}

#[test]
fn chunked_reader_matches_unchunked_reader_without_extent() {
    let (input, _, _) = reader_input();
    let read = |chunked: bool| {
        let mut reader =
            BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 64, true);
        if chunked {
            reader.set_chunked_skip(32);
        }
        let mut seen = Vec::new();
        loop {
            match reader.step(|value| seen.push(value.clone())).unwrap() {
                JsonlReaderStep::Line | JsonlReaderStep::Partial => {}
                JsonlReaderStep::Complete(report) => {
                    assert!(!reader.sealed_fragment());
                    return (seen, report, reader.consumed_bytes());
                }
            }
        }
    };
    let chunked = read(true);
    assert_eq!(chunked, read(false));
    assert_eq!(chunked.2, input.len() as u64);
    assert_eq!(chunked.1.physical_line_count, 4);
}

/// An overlong Codex row whose capped prefix carries the salvage envelope.
fn overlong_envelope_row() -> Vec<u8> {
    format!(
        "{{\"timestamp\":\"2026-10-07T10:30:00Z\",\"ordinal\":7,\"type\":\"response_item\",\"payload\":\"{}\"}}",
        "x".repeat(400)
    )
    .into_bytes()
}

/// E1 + E4: a withheld final record applied at a genuine EOF matches a
/// read without an extent applying its trailing line, for a valid, a
/// malformed and an overlong record (whose salvage E4 took early).
#[test]
fn withheld_record_applied_at_eof_matches_trailing_line_rule() {
    for last in [
        br#"{"n":3}"#.to_vec(),
        br#"{"n":"#.to_vec(),
        overlong_envelope_row(),
    ] {
        let mut input = b"{\"n\":1}\n{\"n\":2}\n".to_vec();
        input.extend_from_slice(&last);
        let read = |cursor: bool| {
            let mut reader =
                BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 96, true);
            if cursor {
                reader.set_chunked_skip(32);
                reader.set_extent_limit(input.len() as u64);
            }
            let mut seen = Vec::new();
            while !matches!(
                reader.step(|value| seen.push(value.clone())).unwrap(),
                JsonlReaderStep::Complete(_)
            ) {}
            if cursor {
                assert!(reader.sealed_fragment());
                assert!(reader.apply_sealed_fragment(|value| seen.push(value.clone())));
                assert!(!reader.sealed_fragment());
                assert!(reader.buf.is_empty());
                assert!(!reader.apply_sealed_fragment(|_| panic!("applied once")));
            }
            (seen, reader.report)
        };
        assert_eq!(read(true), read(false));
    }
}

/// E4 (R2-H2): a paused cursor skip holds no prefix byte, so a pause never
/// charges the salvage prefix, and its salvage (taken from the capped
/// prefix when the skip first paused) is the envelope an unchunked read
/// takes at the newline, value for value.
#[test]
fn paused_overlong_skip_salvages_early_with_identical_output() {
    let mut input = codex_line(json!({"n": 1}));
    input.extend(overlong_envelope_row());
    input.push(b'\n');
    input.extend(codex_line(json!({"n": 2})));
    let read = |chunked: bool| {
        let mut reader =
            BoundedJsonlReader::new(BufReader::with_capacity(16, input.as_slice()), 96, true);
        if chunked {
            reader.set_chunked_skip(32);
        }
        let mut seen = Vec::new();
        let mut partials = 0;
        loop {
            match reader.step(|value| seen.push(value.clone())).unwrap() {
                JsonlReaderStep::Partial => {
                    partials += 1;
                    assert!(reader.skipping.is_some());
                    assert!(reader.buf.is_empty(), "no prefix byte is held");
                }
                JsonlReaderStep::Line => {}
                JsonlReaderStep::Complete(report) => return (seen, report, partials),
            }
        }
    };
    let (chunked, chunked_report, partials) = read(true);
    let (unchunked, unchunked_report, unchunked_partials) = read(false);
    assert!(partials > 0, "the skip paused");
    assert_eq!(unchunked_partials, 0);
    assert_eq!(chunked, unchunked);
    assert_eq!(chunked_report, unchunked_report);
    assert_eq!(chunked_report.over_line_cap_count, 1);
    assert_eq!(
        chunked,
        vec![
            json!({"n": 1}),
            json!({"timestamp": "2026-10-07T10:30:00Z",
                "type": "oversized_payload_skipped", "ordinal": 7}),
            json!({"n": 2}),
        ]
    );
}

fn disclosure() -> Disclosure {
    Disclosure {
        reason: DebtReason::HeldTerminal,
        cause: ownership::PARSER,
        ownership_incomplete_file_count: 1,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: vec![SESSION.into()],
        diagnostic_reason: FileReason::OwnershipIncomplete,
        parsed_snapshot_count: 0,
        held: HeldCounts::default(),
        parent_ref: None,
        parent_unresolvable: None,
    }
}

fn strict(reason: DebtReason) -> Disclosure {
    Disclosure {
        reason,
        cause: ownership::GROUP,
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: vec![SESSION.into()],
        diagnostic_reason: FileReason::NotParsedThisCycle,
        parsed_snapshot_count: 0,
        held: HeldCounts::default(),
        parent_ref: None,
        parent_unresolvable: None,
    }
}

/// K2 (R1-B2, parent H-3): `JoinStateBound` and `MemberChanged` keep the
/// strict census gate (a retryable unreadable file, never residue) with the
/// owner blocked and the prior body kept; only a held terminal refusal is
/// settleable residue. One writer classifies fresh, memo and parked debt.
#[test]
fn strict_debt_is_never_settleable_residue_and_held_debt_is() {
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/sessions"),
        path: PathBuf::from(format!(
            "/synthetic/sessions/rollout-2026-10-07T10-00-00-{SESSION}.jsonl"
        )),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "revision".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    let disclose = |disclosure: &Disclosure| {
        let mut index = ScanIndex::default();
        let mut census = ScanCensus::default();
        let mut residue = BTreeSet::new();
        let mut residue_blocked = BTreeSet::new();
        let mut blocked = BTreeSet::new();
        let mut pending = Vec::new();
        disclose_terminal_codex_debt(
            disclosure,
            &candidate,
            (Some("prior".into()), None),
            &mut index,
            DisclosureTargets {
                census: &mut census,
                residue_index_keys: &mut residue,
                residue_blocked_session_ids: &mut residue_blocked,
                codex_state_only_blocked_session_ids: &mut blocked,
                pending_finalization: &mut pending,
            },
        );
        (census, residue, residue_blocked, blocked, pending, index)
    };
    for reason in [
        DebtReason::JoinStateBound,
        DebtReason::MemberChanged,
        DebtReason::ProbeBudgetOrder,
    ] {
        assert!(!reason.settleable());
        let (census, residue, residue_blocked, blocked, pending, index) = disclose(&strict(reason));
        assert!(residue.is_empty() && residue_blocked.is_empty());
        assert_eq!(census.ownership_incomplete_file_count, 0);
        assert_eq!(census.unreadable_path_count, 1);
        assert!(blocked.contains(SESSION));
        assert!(index.codex_state_only_blocked_session_ids.contains(SESSION));
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].parse_complete);
        assert_eq!(pending[0].diagnostic_reason, FileReason::NotParsedThisCycle);
        assert_eq!(
            pending[0].previous_snapshot_fingerprint.as_deref(),
            Some("prior")
        );
    }
    assert!(DebtReason::HeldTerminal.settleable());
    let (census, residue, residue_blocked, blocked, pending, _) = disclose(&disclosure());
    assert_eq!(residue.len(), 1);
    assert!(residue_blocked.contains(SESSION) && blocked.contains(SESSION));
    assert_eq!(census.ownership_incomplete_file_count, 1);
    assert_eq!(census.unreadable_path_count, 0);
    assert_eq!(
        pending[0].diagnostic_reason,
        FileReason::OwnershipIncomplete
    );
}

/// C2: no time-based expiry. A memo entry wakes on cheap changed evidence
/// only: an object change, shrink or same-length stamp change of the held
/// file, a head or boundary sample mismatch at the refused offset, or a
/// changed digest dependency or parent ledger.
///
/// Premise (disclosed): an in-place interior edit outside the samples that
/// also appends is not detected until the entry is lost (restart, LRU
/// eviction) or a dependency changes. A miss is never treated as proof of
/// uniqueness; it only costs a re-read.
#[test]
fn memo_entry_matches_growth_but_not_prefix_or_parent_change() {
    let temp = Temp::new("memo", b"{\"n\":1}\n{\"n\":2}\n");
    let file = File::open(&temp.0).unwrap();
    assert!(LiveWitness::read(plain_path(), &file, 0).is_none());
    assert!(LiveWitness::read(plain_path(), &file, 10_000).is_none());
    let live = LiveWitness::read(plain_path(), &file, 8).unwrap();
    let stamp = OpenStamp::capture(&file).unwrap();
    let parent = Some(ParentDep {
        id: "parent".into(),
        ledger: Some("ledger-1".into()),
        current: Some("p-1".into()),
        witnessed: None,
    });
    let now = |ledger: &str, current: &str| ParentNow {
        ledger: Some(ledger.into()),
        current: Some(current.into()),
        witnessed: None,
    };
    let now_1 = now("ledger-1", "p-1");
    let entry = MemoEntry::new("digest".into(), live, stamp, parent, None, disclosure());
    assert_eq!(entry.parent_ref(), Some("parent"));
    assert!(entry
        .matches(plain_path(), "digest", &file, Some(&now_1), "")
        .is_some());
    assert!(entry
        .matches(plain_path(), "other", &file, Some(&now_1), "")
        .is_none());
    // PR-1 L4: a changed ledger and, separately, a changed parent object
    // each miss.
    assert!(entry
        .matches(
            plain_path(),
            "digest",
            &file,
            Some(&now("ledger-2", "p-1")),
            ""
        )
        .is_none());
    assert!(entry
        .matches(
            plain_path(),
            "digest",
            &file,
            Some(&now("ledger-1", "p-2")),
            ""
        )
        .is_none());
    assert!(entry
        .matches(
            plain_path(),
            "digest",
            &file,
            Some(&ParentNow {
                ledger: Some("ledger-1".into()),
                current: None,
                witnessed: None,
            }),
            ""
        )
        .is_none());
    assert!(entry
        .matches(plain_path(), "digest", &file, None, "")
        .is_none());
    // Growth past the refused offset cannot cure the hold: still a hit, and
    // the hit returns the grown stamp for the entry to keep.
    temp.append(b"{\"n\":3}\n");
    let grown = entry
        .matches(plain_path(), "digest", &file, Some(&now_1), "")
        .expect("growth is a hit");
    assert!(grown.extent > entry.stamp.extent);
    let mut refreshed = entry.clone();
    refreshed.stamp = grown;
    // No timer: an entry whose evidence is unchanged keeps matching.
    assert!(refreshed
        .matches(plain_path(), "digest", &file, Some(&now_1), "")
        .is_some());
    // A same-length stamp change (an in-place write elsewhere) wakes it.
    OpenOptions::new()
        .write(true)
        .open(&temp.0)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();
    assert!(refreshed
        .matches(plain_path(), "digest", &file, Some(&now_1), "")
        .is_none());
    // A rewritten prefix is a miss (re-read).
    fs::write(&temp.0, b"{\"n\":9}\n{\"n\":2}\n{\"n\":3}\n").unwrap();
    assert!(entry
        .matches(plain_path(), "digest", &file, Some(&now_1), "")
        .is_none());
}

fn codex_line(value: Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(&value).unwrap();
    line.push(b'\n');
    line
}

fn token_line(n: u64) -> Vec<u8> {
    codex_line(
        json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
        "payload": {"type": "token_count", "info": {"model": "fixture-model",
        "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
            "output_tokens": n * 10},
        "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
            "output_tokens": 10}}}}),
    )
}

/// `2026-09-24T00:00:00Z` plus `hour` hours and `minute` minutes (RFC 3339).
fn hour_stamp(hour: u64, minute: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp((1_790_208_000 + hour * 3600 + minute * 60) as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

const SESSION_B: &str = "019fa111-2222-7333-8444-666666666666";

struct ScanRoot {
    _dir: Temp,
    root: PathBuf,
}
impl ScanRoot {
    fn new(lines: usize) -> Self {
        Self::with_sessions(&[(SESSION, lines)])
    }
    fn with_sessions(sessions: &[(&str, usize)]) -> Self {
        let dir = Temp::new("scan", b"");
        fs::remove_file(&dir.0).unwrap();
        let root = dir.0.join("home/.codex/sessions");
        fs::create_dir_all(&root).unwrap();
        let fixture = Self { _dir: dir, root };
        for (session, lines) in sessions {
            let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
                "type": "session_meta", "payload": {"id": session}}));
            for n in 1..=*lines as u64 {
                body.extend(token_line(n));
            }
            fs::write(fixture.file(session), body).unwrap();
        }
        fixture
    }
    fn file(&self, session: &str) -> PathBuf {
        self.root
            .join(format!("rollout-2026-10-07T10-00-00-{session}.jsonl"))
    }
    fn append(&self, session: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.file(session))
            .unwrap();
        file.write_all(bytes).unwrap();
    }
    fn len(&self, session: &str) -> u64 {
        fs::metadata(self.file(session)).unwrap().len()
    }
}

thread_local! {
    static CARRIED: std::cell::RefCell<BTreeMap<PathBuf, crate::snapshots::CodexContinuationEvidence>> = Default::default();
    pub(in crate::snapshots) static NATIVE_RANGES: std::cell::RefCell<Option<Vec<std::ops::Range<u64>>>> = const { std::cell::RefCell::new(None) };
    pub(super) static TIER_REPLAYS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(in crate::snapshots) static EOF_APPLIED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(in crate::snapshots) static GROUP_EOF_APPLIED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAIL_EOF_PARK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
// Build certified fixture evidence through the same constructor and header
// steps as an ordinary scan, without retaining evidence from a completed scan.
impl crate::snapshots::CodexContinuationEvidence {
    pub(crate) fn certified_for_test(roots: &[PathBuf], paths: &BTreeSet<String>) -> Self {
        let codex = CodexTitleMetadata::load_from_roots(roots);
        let mut directories = codex_file_join::DirectoryCensus::new();
        for root in roots {
            directories.observe(root, &fs::symlink_metadata(root).unwrap());
        }
        let mut inventory = codex_file_join::HeaderInventory::new(roots, paths, Some(&directories));
        while !inventory.step(&codex) {}
        assert!(inventory.content_unchanged(), "certified fixture inventory");
        Self {
            inventory,
            ledgers: None,
            codex,
            traces: None,
        }
    }
}
pub(in crate::snapshots) fn constrain_eof_park(job: &mut OwnedActiveFile) {
    if FAIL_EOF_PARK.with(std::cell::Cell::get) {
        shrink_paused_buffer(&mut job.parser.reader.buf);
        let inputs = job.parser.take_live_reduction_inputs();
        let charge = paused_charge(job).expect("bounded EOF job");
        job.parser.restore_live_reduction_inputs(inputs);
        TEST_STATE_BUDGET.with(|limit| limit.set(Some(charge - 1)));
    }
}
fn carry(root: &Path, scan: &mut SourceScanResult) {
    if let Some(evidence) = scan.take_continuation_evidence() {
        CARRIED.with(|v| {
            v.borrow_mut().insert(root.to_path_buf(), evidence);
        });
    }
}
fn carried(root: &Path) -> Option<crate::snapshots::CodexContinuationEvidence> {
    CARRIED.with(|v| v.borrow_mut().remove(root))
}
fn parked_eof(cache: &SharedCache) -> bool {
    cache
        .with_cursor(
            |cursor| matches!(&cursor.slot, Slot::Paused(job) if job.parser.reader.finished),
        )
        .unwrap_or(false)
}

/// One page: one `OwnedSourceScan` stepped to completion, then the same
/// post-policy finalization the production collector applies.
fn page(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
) -> (ScanIndex, SourceScanResult) {
    let (index, scan, _) = page_in(fixture, index, cache, "cursor-fixture");
    (index, scan)
}

/// Read modes selected in one page: (full, tail).
type Modes = (usize, usize);

fn page_in(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    namespace: &str,
) -> (ScanIndex, SourceScanResult, Modes) {
    page_at(fixture, index, cache, namespace, NOW)
}

/// A page collected at `collected_at`: a census generation that starts on a
/// later page gets its own window, hence its own fence token (K7).
fn page_at(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    namespace: &str,
    collected_at: &str,
) -> (ScanIndex, SourceScanResult, Modes) {
    page_with(fixture, index, cache, namespace, collected_at, |_| {})
}

/// `page_at` with `tweak` applied to the fresh scan object (census flags).
fn page_with(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    namespace: &str,
    collected_at: &str,
    tweak: impl Fn(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Modes) {
    page_steps(
        fixture,
        index,
        cache,
        namespace,
        collected_at,
        tweak,
        usize::MAX,
    )
}

/// `page_with` that fails once the page takes more than `max_steps` steps
/// (E2: one scan object never spins).
fn page_steps(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    namespace: &str,
    collected_at: &str,
    tweak: impl Fn(&mut OwnedSourceScan),
    max_steps: usize,
) -> (ScanIndex, SourceScanResult, Modes) {
    let (index, scan, selections) = page_selections(
        fixture,
        index,
        cache,
        namespace,
        collected_at,
        tweak,
        max_steps,
    );
    (index, scan, selections.modes)
}

/// Every read-mode selection one page made: `Modes`, acquisition
/// `Unchanged` selections, and full reads by reason (`FullReason::slot`).
/// A file the scheduler skips is in none of them.
#[derive(Clone, Copy, Debug, Default)]
struct Selections {
    modes: Modes,
    unchanged: usize,
    full_reasons: [usize; 11],
}

/// `page_steps` that also reports `Selections`.
fn page_selections(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    namespace: &str,
    collected_at: &str,
    tweak: impl Fn(&mut OwnedSourceScan),
    max_steps: usize,
) -> (ScanIndex, SourceScanResult, Selections) {
    let mut scan = codex_scan(fixture, index, collected_at);
    tweak(&mut scan);
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache, Scope(namespace.into()));
    }
    let mut selections = Selections::default();
    for _ in 0..max_steps {
        if let Some(context) = scan.sampling.as_ref() {
            selections = Selections {
                modes: (context.full_files, context.tail_files),
                unchanged: context.unchanged_files,
                full_reasons: context.full_reasons,
            };
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                carry(&fixture.root, &mut scan);
                return (index, scan, selections);
            }
        }
    }
    panic!("the page did not finish within {max_steps} steps");
}

fn codex_scan(fixture: &ScanRoot, index: ScanIndex, collected_at: &str) -> OwnedSourceScan {
    OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
    )
}

/// `NOW` plus one second per page.
fn collected_at(page: u64) -> String {
    let seconds = 12 * 3600 + page;
    format!(
        "2026-10-07T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn fingerprints(scan: &SourceScanResult) -> Vec<String> {
    scan.snapshots
        .iter()
        .map(|snapshot| snapshot.snapshot_fingerprint.clone())
        .collect()
}

#[test]
fn paged_singleton_matches_unpaged_read_across_scan_objects() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
    assert!(!unpaged.snapshots.is_empty());
    let cache = Arc::new(SharedCache::default());
    let paged = with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            let completed = cache
                .with_cursor(|cursor| cursor.counters.jobs_certified)
                .unwrap();
            if completed > 0 {
                // The attempt consumed the path that held the census.
                assert!(index
                    .traversal
                    .as_ref()
                    .map_or(true, |traversal| traversal.pending_candidates.is_empty()));
                return scan;
            }
            assert!(
                scan.snapshots.is_empty(),
                "a paused job publishes nothing for its file"
            );
        }
        panic!(
            "cursor job did not complete within 64 pages: {}",
            counters(&cache)
        );
    });
    let counters = cache.with_cursor(|cursor| {
        (
            cursor.counters.jobs_started,
            cursor.counters.jobs_paused,
            cursor.counters.jobs_resumed,
            cursor.counters.jobs_certified,
            cursor.counters.jobs_invalidated,
            cursor.counters.jobs_lost,
        )
    });
    eprintln!("CODEX_CURSOR_PARITY counters={counters:?}");
    let (started, paused, resumed, completed, invalidated, lost) = counters.unwrap();
    assert_eq!((started, completed, invalidated, lost), (1, 1, 0, 0));
    assert!(paused > 0 && resumed == paused);
    assert!(cache.cursor_slot_free());
    assert_eq!(cache.cursor_charge(), 0);
    assert_eq!(cache.cursor_reserved(), 0);
    assert_eq!(fingerprints(&paged), fingerprints(&unpaged));
}

/// D1: a paged (paused and resumed) read pairs each context watermark with
/// the same Codex window an unpaged read does, across page boundaries where
/// the window changes, ties at the peak and goes missing.
#[test]
fn paged_singleton_carries_context_windows_like_unpaged_read() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(0);
    let mut total = 0;
    for n in 1..=80_u64 {
        let context = if n == 40 || n == 60 { 9_000 } else { 100 + n };
        let window = match n {
            1..=20 => Some(258_400),
            60 => Some(475_000),
            80 => None,
            _ => Some(400_000),
        };
        total += context;
        let mut line = json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
            "payload": {"type": "token_count", "info": {"model": "fixture-model",
            "total_token_usage": {"input_tokens": total, "cached_input_tokens": total / 2,
                "output_tokens": n * 10},
            "last_token_usage": {"input_tokens": context, "cached_input_tokens": context / 2,
                "output_tokens": 10}}}});
        if let Some(window) = window {
            line["payload"]["info"]["model_context_window"] = json!(window);
        }
        fixture.append(SESSION, &codex_line(line));
    }
    let windows = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .map(|item| {
                (
                    item.first_turn_context_window_tokens,
                    item.peak_context_fill_window_tokens,
                    item.last_turn_context_window_tokens,
                )
            })
            .collect::<Vec<_>>()
    };
    let (recorded, unpaged) = page(&fixture, ScanIndex::default(), None);
    // First turn under the first window; the peak (tied at records 40 and
    // 60) keeps record 40's window; the last record carried none.
    assert_eq!(
        windows(&unpaged),
        vec![(Some(258_400), Some(400_000), None)]
    );
    // Unchanged-file control: the file the windows came from is not selected
    // again while its bytes are unchanged (the parser version is not part of
    // the scan fingerprint).
    assert_eq!(
        recorded.candidate_decision(&unchanged_candidate(&fixture, &recorded)),
        CandidateDecision::Skip
    );
    let cache = Arc::new(SharedCache::default());
    let paged = with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if cache
                .with_cursor(|cursor| cursor.counters.jobs_certified)
                .unwrap()
                > 0
            {
                return scan;
            }
            assert!(scan.snapshots.is_empty());
        }
        panic!("cursor job did not complete within 64 pages");
    });
    let (_, paused, resumed, _, _, _) = cache
        .with_cursor(|cursor| {
            (
                cursor.counters.jobs_started,
                cursor.counters.jobs_paused,
                cursor.counters.jobs_resumed,
                cursor.counters.jobs_certified,
                cursor.counters.jobs_invalidated,
                cursor.counters.jobs_lost,
            )
        })
        .unwrap();
    assert!(paused > 0 && resumed == paused, "the read really paged");
    assert_eq!(windows(&paged), windows(&unpaged));
    assert_eq!(fingerprints(&paged), fingerprints(&unpaged));
}

#[test]
fn uncached_scan_never_pages() {
    let fixture = ScanRoot::new(40);
    let (_, full) = page(&fixture, ScanIndex::default(), None);
    let scaled = with_test_limits(256, 128, 16, || {
        page(&fixture, ScanIndex::default(), None).1
    });
    assert_eq!(fingerprints(&scaled), fingerprints(&full));
}

/// P1-RETAIN-3 reaches cursor sealed-prefix retention too: a Codex fork whose
/// ownership boundary is in-file (`Ordinal`) keeps its certified prefix, then
/// tails from it with the output of an unpaged full read.
#[test]
fn lifted_ordinal_fork_retains_sealed_prefix_then_tails_with_full_parity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let ordinal_token = |ordinal: u64| {
        codex_line(
            json!({"timestamp": "2026-10-07T10:30:00Z", "ordinal": ordinal, "type": "event_msg",
            "payload": {"type": "token_count", "info": {"model": "fixture-model",
            "total_token_usage": {"input_tokens": ordinal * 100, "cached_input_tokens": ordinal * 50,
                "output_tokens": ordinal * 10},
            "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
                "output_tokens": 10}}}}),
        )
    };
    let fixture = ScanRoot::new(0);
    // Ordinal 1 is inherited context; 2..=80 are the fork's own records.
    let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z", "ordinal": 0,
        "type": "session_meta", "payload": {"id": SESSION,
        "forked_from_id": "019fa111-2222-7333-8444-0000000000d1",
        "thread_source": "subagent", "subagent_history_start_ordinal": 2}}));
    for ordinal in 1..=80 {
        body.extend(ordinal_token(ordinal));
    }
    fs::write(fixture.file(SESSION), body).unwrap();
    let key = local_index_key(&fixture.file(SESSION));
    let cache = Arc::new(SharedCache::default());
    let tail = with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        let mut certified = false;
        for _ in 0..64 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                assert!(!scan.snapshots.is_empty(), "the certified read publishes");
                certified = true;
                break;
            }
            assert!(scan.snapshots.is_empty(), "a paused job publishes nothing");
        }
        assert!(
            certified,
            "cursor job did not complete: {}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
        let prefix = cache.retained_checkpoint(&key).unwrap_or_else(|| {
            panic!("the fork's sealed prefix is retained: {}", counters(&cache))
        });
        assert!(prefix.sealed_offset() <= fixture.len(SESSION));
        fixture.append(SESSION, &ordinal_token(81));
        let (_, tail, modes) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
        assert_eq!(modes, (0, 1), "the append tails from the sealed prefix");
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
        let tailed = cache.retained_checkpoint(&key).expect("tail retained");
        assert_eq!(tailed.sealed_offset(), fixture.len(SESSION));
        tail
    });
    let (_, full) = page(&fixture, ScanIndex::default(), None);
    assert!(!full.snapshots.is_empty());
    assert_eq!(fingerprints(&tail), fingerprints(&full));
}

fn counter(cache: &SharedCache, read: fn(&Counters) -> u64) -> u64 {
    cache.with_cursor(|cursor| read(&cursor.counters)).unwrap()
}

fn counters(cache: &SharedCache) -> String {
    cache
        .with_cursor(|cursor| format!("{:?}", cursor.counters))
        .unwrap_or_default()
}

fn pending_hint(index: &ScanIndex, path: &Path) -> Option<bool> {
    index
        .traversal
        .as_ref()?
        .pending_candidates
        .iter()
        .find(|pending| pending.path == path)
        .map(|pending| pending.watcher_hint)
}

/// Restores the real scan clock when a test ends or panics.
struct TestClock;
impl TestClock {
    fn set(&self, now: u64) {
        super::super::set_test_now(Some(now));
    }
}
impl Drop for TestClock {
    fn drop(&mut self) {
        super::super::set_test_now(None);
    }
}

/// R2-M6 #1 with the §e.2 essential-acceptance assertions (i)–(iii): an
/// active singleton larger than B, appended every page.
#[test]
fn active_member_larger_than_budget_appended_every_page_audit_semantics() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    // Ordinary checkpoint admission/completion ignores age, while debt
    // and the original verification time remain owed across later Tails.
    const B: u64 = 2048;
    with_test_limits(B, 8192, 64, || {
        // (i) and (ii): a short page interval, well inside the deadline.
        let fixture = ScanRoot::new(80);
        let path = fixture.file(SESSION);
        let key = local_index_key(&path);
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut now = 1_900_000_000_u64;
        let mut next_line = 81;
        let mut opened = None;
        for _ in 0..64 {
            clock.set(now);
            let started = counter(&cache, |c| c.jobs_started);
            let open_length = fixture.len(SESSION);
            let (next, scan, _) =
                page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_started) > started {
                opened = Some((now, open_length));
            }
            if counter(&cache, |c| c.jobs_certified) == 1 {
                assert!(!scan.snapshots.is_empty(), "the certified read publishes");
                break;
            }
            assert!(scan.snapshots.is_empty(), "a paused job publishes nothing");
            fixture.append(SESSION, &token_line(next_line));
            next_line += 1;
            now += 10;
        }
        let (t_start, open_length) = opened.expect("a cursor job opened");
        let certified = cache
            .retained_checkpoint(&key)
            .unwrap_or_else(|| panic!("certified prefix retained: {}", counters(&cache)));
        // (i) `[0, s)` with `s <= L0`, verified at the read's start.
        assert_eq!(counter(&cache, |c| c.jobs_certified), 1);
        assert_eq!(counter(&cache, |c| c.jobs_invalidated), 0);
        assert!(certified.sealed_offset() <= open_length);
        assert!(certified.sealed_offset() < fixture.len(SESSION));
        assert_eq!(certified.last_full_verified(), t_start);
        assert_eq!(certified.audit_debt(), None);
        // Appends during the job were never marked read: the path stays
        // pending as a watcher hint (C7) and the next page tails from `s`.
        assert_eq!(pending_hint(&index, &path), Some(true));
        fixture.append(SESSION, &token_line(next_line));
        next_line += 1;
        now += 10;
        clock.set(now);
        let (_, scan, modes) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
        // (ii) a tail from `s` while the deadline permits.
        assert_eq!(modes, (0, 1));
        assert!(!scan.snapshots.is_empty());
        let tailed = cache.retained_checkpoint(&key).expect("tail retained");
        assert_eq!(tailed.sealed_offset(), fixture.len(SESSION));
        assert_eq!(tailed.last_full_verified(), t_start);
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);

        // (iii) scaled `L > L_max` for two large files, both appended every
        // page, pages 600 s apart so each read of `ceil(L/B)` pages outlives
        // the interval. Rotation, not a monopoly (K7): the files alternate,
        // each initial Full certifies, then both progress through overdue
        // ordinary Tails without requiring a new census generation or audit.
        let fixture = ScanRoot::with_sessions(&[(SESSION, 80), (SESSION_B, 80)]);
        let sessions = [SESSION, SESSION_B];
        let keys = sessions.map(|session| local_index_key(&fixture.file(session)));
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut opened = BTreeMap::new();
        let mut completions = Vec::new();
        let mut tails = 0;
        let mut overdue_tail_progress = BTreeMap::new();
        for page_number in 0..192_u64 {
            clock.set(now);
            let started = counter(&cache, |c| c.jobs_started);
            let certified = counter(&cache, |c| c.jobs_certified);
            let paused = cache.cursor_job_key();
            let lengths = sessions.map(|session| fixture.len(session));
            let retained = keys.clone().map(|key| cache.retained_checkpoint(&key));
            let (next, scan, modes) = page_at(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                &collected_at(page_number),
            );
            index = next;
            if modes.1 > 0 {
                tails += modes.1;
                for (key, prior) in keys.iter().zip(&retained) {
                    let Some(prior) = prior else { continue };
                    let Some(next) = cache.retained_checkpoint(key) else {
                        continue;
                    };
                    if next.sealed_offset() > prior.sealed_offset() {
                        assert!(!scan.snapshots.is_empty(), "completed Tail publishes");
                        assert_eq!(next.last_full_verified(), prior.last_full_verified());
                        assert_eq!(next.audit_debt(), prior.audit_debt(), "no audit credit");
                        if now >= prior.last_full_verified() + interval {
                            overdue_tail_progress.insert(key.clone(), (now, next.sealed_offset()));
                        }
                    }
                }
            }
            assert_eq!(counter(&cache, |c| c.jobs_audit_restarted), 0);
            if counter(&cache, |c| c.jobs_started) > started {
                let key = cache.cursor_job_key().expect("the new job paused");
                let file = keys.iter().position(|known| *known == key).unwrap();
                opened.insert(key, (now, lengths[file]));
            }
            if counter(&cache, |c| c.jobs_certified) > certified {
                // A job spans pages, so the completed one was paused before.
                let key = paused.expect("a paused job completed");
                let (t_start, open_length) = opened[&key];
                let checkpoint = cache.retained_checkpoint(&key).expect("certificate");
                assert!(
                    !scan.snapshots.is_empty(),
                    "each audit completion publishes"
                );
                assert!(checkpoint.sealed_offset() <= open_length);
                // No deadline reset: verified at read start, still due.
                assert_eq!(checkpoint.last_full_verified(), t_start);
                assert_eq!(
                    checkpoint.audit_debt().map(|debt| debt.due_unix_seconds),
                    Some(t_start + interval)
                );
                let due = index.files[&key]
                    .audit_obligation(now)
                    .map(|debt| debt.due_unix_seconds);
                assert!(due.is_some_and(|due| due <= t_start + interval && due <= now));
                completions.push((key, now, checkpoint.sealed_offset()));
            } else if modes.1 == 0 {
                assert!(scan.snapshots.is_empty(), "paused job publishes nothing");
            }
            if completions.len() == 2 && overdue_tail_progress.len() == 2 {
                break;
            }
            for (session, line) in sessions.iter().zip([next_line, next_line + 1]) {
                fixture.append(session, &token_line(line));
            }
            next_line += 2;
            now += 600;
        }
        assert_eq!(
            completions.len(),
            2,
            "two initial cursors: {}",
            counters(&cache)
        );
        assert_ne!(completions[0].0, completions[1].0, "both files served");
        assert!(tails > 0, "overdue appends keep tailing");
        assert_eq!(overdue_tail_progress.len(), 2, "neither file starves");
        for (key, completed_at, certified_offset) in completions {
            let (tailed_at, tailed_offset) = overdue_tail_progress[&key];
            assert!(
                tailed_at > completed_at,
                "Tail follows initial certification"
            );
            assert!(
                tailed_offset > certified_offset,
                "each file consumes its append"
            );
        }
        assert!(counter(&cache, |c| c.deferred_next_generation) > 0);
        assert_eq!(counter(&cache, |c| c.audit_overdue), 2);
        assert!(counter(&cache, |c| c.audit_overdue_max_age_seconds) > 0);
    });
}

/// C1 at scan level: an in-place edit of already-parsed bytes inside the
/// head sample, made while the paused job's file also grew, invalidates the
/// attempt. Nothing publishes, nothing commits, and the path stays pending;
/// the next attempt certifies the stable file.
#[test]
fn grown_member_with_in_place_head_edit_restarts_and_publishes_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let (mut index, scan) = page(&fixture, ScanIndex::default(), Some(Arc::clone(&cache)));
        assert!(scan.snapshots.is_empty());
        assert!(
            !cache.cursor_slot_free(),
            "the job paused: {}",
            counters(&cache)
        );
        // Same length, inside `[0, 4 KiB)`: `10:00:00` becomes `10:00:01`.
        let bytes = fs::read(&path).unwrap();
        let at = bytes
            .windows(8)
            .position(|window| window == b"10:00:00")
            .unwrap()
            + 7;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all_at(b"1", at as u64)
            .unwrap();
        fixture.append(SESSION, &token_line(41));
        for _ in 0..32 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_invalidated) == 1 {
                assert!(
                    scan.snapshots.is_empty(),
                    "an invalidated attempt publishes nothing"
                );
                assert_eq!(counter(&cache, |c| c.jobs_certified), 0);
                assert!(cache.retained_checkpoint(&key).is_none());
                assert!(
                    pending_hint(&index, &path).is_some(),
                    "the path stays pending"
                );
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_invalidated),
            1,
            "{}",
            counters(&cache)
        );
        for _ in 0..32 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 2);
        assert_eq!(counter(&cache, |c| c.jobs_member_changed), 0);
    });
}

/// C7: a singleton deferred by the aggregate page budget goes back to
/// `pending_candidates` with its selection flags, watcher hint included.
#[test]
fn singleton_aggregate_page_budget_defers_via_pending_keeps_hint() {
    let fixture = ScanRoot::with_sessions(&[(SESSION, 8), (SESSION_B, 8)]);
    let size = fixture.len(SESSION).max(fixture.len(SESSION_B));
    let mut index = ScanIndex::default();
    // The traversal checkpoint fixture: this generation's census with both
    // files pending as watcher hints.
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    let traversal = index.traversal.as_mut().unwrap();

    for pending in &mut traversal.pending_candidates {
        pending.watcher_hint = true;
    }
    let paths = [fixture.file(SESSION), fixture.file(SESSION_B)];
    assert!(paths
        .iter()
        .all(|path| traversal.pending_candidates.iter().any(|p| &p.path == path)));
    let cache = Arc::new(SharedCache::default());
    let (index, scan) = with_test_limits(1 << 20, size + size / 2, 64, || {
        page(&fixture, index, Some(Arc::clone(&cache)))
    });
    assert_eq!(counter(&cache, |c| c.deferred), 1);
    assert_eq!(counter(&cache, |c| c.jobs_started), 0);
    let deferred: Vec<_> = paths
        .iter()
        .filter(|path| pending_hint(&index, path).is_some())
        .collect();
    assert_eq!(
        deferred.len(),
        1,
        "exactly one file waits for the next page"
    );
    assert_eq!(pending_hint(&index, deferred[0]), Some(true));
    assert!(!scan.snapshots.is_empty(), "the first file was read");
    let (index, scan) = with_test_limits(1 << 20, size + size / 2, 64, || {
        page(&fixture, index, Some(Arc::clone(&cache)))
    });
    assert!(!scan.snapshots.is_empty(), "the deferred file is read next");
    assert!(paths
        .iter()
        .all(|path| pending_hint(&index, path).is_none()));
}

/// K10 (R1-H3): a live paused job of another namespace is never evicted by a
/// concurrent scan (no ping-pong); its own namespace keeps resuming it. Only
/// a stale job, untouched for `NAMESPACE_STALE_PAGES` cursor pages because
/// its namespace stopped scanning, is evicted, and its file restarts there.
#[test]
fn concurrent_namespace_leaves_live_job_and_evicts_only_stale_one() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    let paused_namespace = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| match &cursor.slot {
                Slot::Paused(job) => job.cursor.as_ref().map(|meta| meta.namespace.clone()),
                Slot::Empty | Slot::ActiveElsewhere { .. } => None,
            })
            .flatten()
    };
    with_test_limits(2048, 4096, 64, || {
        let (index_a, _, _) = page_in(
            &fixture,
            ScanIndex::default(),
            Some(Arc::clone(&cache)),
            "ns-a",
        );
        assert_eq!(
            paused_namespace(&cache).as_deref(),
            Some("ns-a"),
            "{}",
            counters(&cache)
        );
        assert!(cache.cursor_charge() > 0);
        assert_eq!(cache.cursor_reserved(), 0);
        let (mut index_b, scan, _) = page_in(
            &fixture,
            ScanIndex::default(),
            Some(Arc::clone(&cache)),
            "ns-b",
        );
        assert!(scan.snapshots.is_empty());
        assert_eq!(counter(&cache, |c| c.jobs_lost), 0);
        assert!(counter(&cache, |c| c.namespace_busy) > 0);
        assert_eq!(paused_namespace(&cache).as_deref(), Some("ns-a"));
        // Its own namespace resumes it.
        let resumed = counter(&cache, |c| c.jobs_resumed);
        page_in(&fixture, index_a, Some(Arc::clone(&cache)), "ns-a");
        assert!(counter(&cache, |c| c.jobs_resumed) > resumed);
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
        // Only ns-b keeps scanning: the job goes stale and ns-b takes over.
        let mut pages = 0_u64;
        while counter(&cache, |c| c.jobs_lost) == 0 {
            pages += 1;
            assert!(pages <= NAMESPACE_STALE_PAGES + 1, "{}", counters(&cache));
            let (next, _, _) = page_in(&fixture, index_b, Some(Arc::clone(&cache)), "ns-b");
            index_b = next;
        }
        assert!(
            pages + 1 >= NAMESPACE_STALE_PAGES,
            "evicted after {pages} pages"
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 2);
        assert_eq!(paused_namespace(&cache).as_deref(), Some("ns-b"));
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// K1 (R1-B1 = R2-B3): a session larger than B with more than 256 distinct
/// usage-bearing turns (UUID-shaped turn ids in `task_started`,
/// `turn_context`, `token_count`, `task_complete` shapes) keeps every exact
/// witness in its byte-charged slot, pages to a certificate, publishes once
/// and matches the unpaged read.
#[test]
fn turn_heavy_session_pages_past_the_witness_cap_and_publishes_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const TURNS: u64 = 400;
    let fixture = ScanRoot::new(0);
    let mut body = Vec::new();
    for turn in 1..=TURNS {
        let turn_id = format!("01a03e98-5000-7000-8000-{turn:012}");
        body.extend(codex_line(
            json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
            "payload": {"type": "task_started", "turn_id": turn_id}}),
        ));
        body.extend(codex_line(
            json!({"timestamp": "2026-10-07T10:30:00Z", "type": "turn_context",
            "payload": {"turn_id": turn_id, "model": "fixture-model"}}),
        ));
        body.extend(token_line(turn));
        body.extend(codex_line(
            json!({"timestamp": "2026-10-07T10:30:01Z", "type": "event_msg",
            "payload": {"type": "task_complete", "turn_id": turn_id}}),
        ));
    }
    fixture.append(SESSION, &body);
    let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
    assert!(!unpaged.snapshots.is_empty());
    let cache = Arc::new(SharedCache::default());
    let mut widest = 0;
    let mut publishing_pages = 0;
    let paged = with_test_limits(16 * 1024, 8 * 1024, 1024, || {
        let mut index = ScanIndex::default();
        let mut published = None;
        for _ in 0..128 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            let held = cache.with_cursor(|cursor| match &cursor.slot {
                Slot::Paused(job) => job
                    .parser
                    .accumulator
                    .codex_observed_priority_turns
                    .as_ref()
                    .map_or(0, BTreeMap::len),
                Slot::Empty | Slot::ActiveElsewhere { .. } => 0,
            });
            widest = widest.max(held.unwrap_or(0));
            if !scan.snapshots.is_empty() {
                publishing_pages += 1;
                published = Some(scan);
            }
            if counter(&cache, |c| c.jobs_certified) == 1 {
                let (_, again) = page(&fixture, index, Some(Arc::clone(&cache)));
                assert!(again.snapshots.is_empty(), "published once");
                return published.expect("the certified read publishes");
            }
        }
        panic!("turn-heavy job did not certify: {}", counters(&cache));
    });
    assert!(
        widest > sampled_jsonl::MAX_PRIORITY_WITNESSES,
        "a pause held {widest} exact witnesses"
    );
    assert_eq!(publishing_pages, 1);
    assert_eq!(counter(&cache, |c| c.jobs_state_bound), 0);
    assert_eq!(counter(&cache, |c| c.jobs_started), 1);
    assert_eq!(cache.cursor_reserved(), 0);
    assert_eq!(fingerprints(&paged), fingerprints(&unpaged));
}

/// K6 (R2-B1): a copy-refusal release by a Claude scan sharing the process
/// cache evicts retained copies only. The paused Codex job keeps its charge
/// and resumes to a certificate without restarting.
#[test]
fn claude_copy_refusal_keeps_paused_codex_job_resumable() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let (mut index, scan) = page(&fixture, ScanIndex::default(), Some(Arc::clone(&cache)));
        assert!(scan.snapshots.is_empty());
        let charge = cache.cursor_charge();
        assert!(charge > 0, "the job paused: {}", counters(&cache));
        assert_eq!(cache.cursor_reserved(), 0);
        let claude_root = Temp::new("claude-root", b"");
        fs::remove_file(&claude_root.0).unwrap();
        fs::create_dir_all(claude_root.0.join("projects")).unwrap();
        let support = claude_root.0.join("support");
        fs::create_dir_all(&support).unwrap();
        let claude = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            &[claude_root.0.join("projects")],
            ScanIndex::default(),
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            Some(&support),
            &[],
            false,
        )
        .with_sampled_acquisition(Arc::clone(&cache), Scope("claude-fixture".into()));
        // No active file: the release takes its conservative full path.
        let (_, lifecycle) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            claude.release_sampled_cache_for_copy_refusal();
        });
        assert_eq!(lifecycle.clear_no_active, 1);
        assert_eq!(lifecycle.clear_metadata_unsupported, 0);
        assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
        drop(claude);
        assert_eq!(cache.cursor_charge(), charge, "the paused job survives");
        assert_eq!(cache.cursor_reserved(), 0);
        assert_eq!(counter(&cache, |c| c.jobs_lost), 0);
        for _ in 0..32 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
        assert!(counter(&cache, |c| c.jobs_resumed) > 0);
    });
}

/// L-A1: an unsampled Claude read (sidecar census incomplete) beside a
/// paused Codex job. A measured copy refusal keeps every resident and the
/// job's charge; the conservative no-argument release still clears retained
/// copies only (K6).
#[test]
fn unsampled_claude_refusal_keeps_residents_and_paused_job_charge() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::local_resource_diagnostics::cache_lifecycle::observe;
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let (_, scan) = page(&fixture, ScanIndex::default(), Some(Arc::clone(&cache)));
        assert!(scan.snapshots.is_empty());
        let charge = cache.cursor_charge();
        assert!(
            charge > 0,
            "precondition: the job paused: {}",
            counters(&cache)
        );
        assert_eq!(cache.cursor_reserved(), 0);
        let claude_root = Temp::new("claude-root", b"");
        fs::remove_file(&claude_root.0).unwrap();
        let projects = claude_root.0.join("projects");
        fs::create_dir_all(&projects).unwrap();
        let support = claude_root.0.join("support");
        fs::create_dir_all(&support).unwrap();
        let mut transcript = Vec::new();
        for line in [
            json!({"type":"user", "sessionId":"native-tail-fixture",
                "timestamp":"2026-10-07T10:00:00Z",
                "message":{"role":"user","content":"Synthetic test"}}),
            json!({"type":"assistant", "sessionId":"native-tail-fixture",
                "timestamp":"2026-10-07T10:00:00Z", "requestId":"req-0",
                "message":{"id":"response-0", "model":"fixture-model",
                "usage":{"input_tokens":100,"cache_read_input_tokens":50,"output_tokens":10}}}),
        ] {
            serde_json::to_writer(&mut transcript, &line).unwrap();
            transcript.push(b'\n');
        }
        fs::write(projects.join("native-tail-fixture.jsonl"), transcript).unwrap();
        let mut claude = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&projects),
            ScanIndex::default(),
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            Some(&support),
            &[],
            false,
        )
        .with_sampled_acquisition(Arc::clone(&cache), Scope("claude-fixture".into()));
        claude.sidecar_census_complete = false;
        for _ in 0..10_000 {
            if claude.active_file.is_some() {
                break;
            }
            match claude.step(None) {
                OwnedSourceScanStep::Pending(next) => claude = next,
                OwnedSourceScanStep::Complete { .. } => panic!("the Claude file never opened"),
            }
        }
        let active = claude.active_file.as_deref().unwrap();
        assert!(
            active.sampling.is_none()
                && active.cursor.is_none()
                && active.group.is_none()
                && active.parser.reader.acquisition.is_none(),
            "precondition: an unsampled native read"
        );
        let context = claude.sampling.as_ref().unwrap();
        let measured = crate::heap_layout_bound::bound(context, STATE_BYTES);
        assert!(measured.is_some(), "precondition: residents measured");
        let (_, lifecycle) = observe(|| {
            crate::snapshots::sampled_scan::release_cache_for_copy_refusal(
                Some(context),
                Some(active),
                measured,
            )
        });
        assert_eq!(lifecycle.clear_other_active, 0);
        assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
        assert_eq!(lifecycle.clear_entries_released, 0);
        assert!(crate::heap_layout_bound::bound(context, STATE_BYTES).is_some());
        assert_eq!(cache.cursor_charge(), charge, "the paused job's charge");
        assert_eq!(cache.cursor_reserved(), 0, "no reservation");
        let (_, lifecycle) = observe(|| claude.release_sampled_cache_for_copy_refusal());
        assert_eq!(
            lifecycle.clear_full_resident_bound_unknown, 1,
            "conservative"
        );
        assert_eq!(lifecycle.clear_other_active, 0);
        drop(claude);
        assert_eq!(cache.cursor_charge(), charge, "K6: the paused job survives");
        assert_eq!(cache.cursor_reserved(), 0);
        assert_eq!(counter(&cache, |c| c.jobs_lost), 0);
    });
}

/// L-A1: a live cursor job reads a fresh `Full` acquisition, so the unchanged
/// #641 `Full` branch decides its refusal. The cursor conjunct alone still
/// keeps an otherwise unsampled shape on the conservative release.
#[test]
fn cursor_job_copy_refusal_keeps_conservative_release() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let mut scan = codex_scan(&fixture, ScanIndex::default(), NOW)
            .with_sampled_acquisition(Arc::clone(&cache), Scope("cursor-fixture".into()));
        for _ in 0..10_000 {
            if scan
                .active_file
                .as_ref()
                .is_some_and(|active| active.cursor.is_some())
            {
                break;
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { .. } => panic!("the job never started"),
            }
        }
        assert!(
            scan.active_file
                .as_ref()
                .is_some_and(|active| active.cursor.is_some()),
            "precondition: a live cursor job"
        );
        let release = |scan: &OwnedSourceScan| {
            let measured =
                crate::heap_layout_bound::bound(scan.sampling.as_ref().unwrap(), STATE_BYTES);
            assert!(measured.is_some(), "precondition: residents measured");
            crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
                crate::snapshots::sampled_scan::release_cache_for_copy_refusal(
                    scan.sampling.as_ref(),
                    scan.active_file.as_deref(),
                    measured,
                )
            })
            .1
        };
        let active = scan.active_file.as_deref().unwrap();
        assert!(
            matches!(
                active.sampling.as_ref().map(|sampling| sampling.mode),
                Some(crate::transcript_acquisition::ReadMode::Full(_))
            ),
            "precondition: a cursor job reads a fresh Full acquisition"
        );
        let lifecycle = release(&scan);
        assert_eq!(lifecycle.clear_other_active, 0, "the #641 Full branch");
        assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
        // Isolate the cursor conjunct, then restore the job before its frame
        // returns it to the slot.
        let active = scan.active_file.as_deref_mut().unwrap();
        let sampling = active.sampling.take();
        let acquisition = active.parser.reader.acquisition.take();
        assert!(
            active.cursor.is_some()
                && active.group.is_none()
                && active.aliases.is_empty()
                && active.applied_receipts.is_empty()
                && active
                    .parser
                    .accumulator
                    .codex_tier_replay
                    .as_ref()
                    .map_or(true, |replay| replay.join.is_none()),
            "precondition: only the cursor conjunct owns state"
        );
        let lifecycle = release(&scan);
        assert_eq!(lifecycle.clear_other_active, 1, "the cursor conjunct");
        assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
        let active = scan.active_file.as_deref_mut().unwrap();
        active.sampling = sampling;
        active.parser.reader.acquisition = acquisition;
        // P1-RETAIN R0 (T-R0d): read as a Tail, with its acquisition, the
        // cursor conjunct alone still keeps the job off shape F, so its
        // refusal keeps ClearOtherActive and its completion never reaches
        // R0's release.
        let active = scan.active_file.as_deref_mut().unwrap();
        let sampling = active.sampling.as_mut().unwrap();
        let mode = sampling.mode;
        sampling.mode = crate::transcript_acquisition::ReadMode::Tail;
        assert!(
            active.parser.reader.acquisition.is_some(),
            "precondition: the job's acquisition"
        );
        assert!(!crate::snapshots::sampled_scan::borrows_only_retained_reduction(active));
        let cursor = active.cursor.take();
        assert!(
            crate::snapshots::sampled_scan::borrows_only_retained_reduction(active),
            "precondition: only the cursor conjunct differs from shape F"
        );
        active.cursor = cursor;
        let lifecycle = release(&scan);
        assert_eq!(lifecycle.clear_other_active, 1, "a Tail cursor job");
        assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0);
        let active = scan.active_file.as_deref_mut().unwrap();
        active.sampling.as_mut().unwrap().mode = mode;
    });
}

/// K12 (R2-H3): dropping a scan frame mid-job returns the intact job to the
/// slot; the next page resumes it instead of restarting from byte zero.
#[test]
fn frame_drop_mid_job_returns_job_to_slot() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let mut scan = codex_scan(&fixture, ScanIndex::default(), NOW)
            .with_sampled_acquisition(Arc::clone(&cache), Scope("cursor-fixture".into()));
        for _ in 0..10_000 {
            if scan
                .active_file
                .as_ref()
                .is_some_and(|active| active.cursor.is_some())
            {
                break;
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { .. } => panic!("the job never started"),
            }
        }
        assert!(!cache.cursor_slot_free(), "the frame holds the job");
        drop(scan);
        assert_eq!(counter(&cache, |c| c.jobs_frame_returned), 1);
        assert_eq!(counter(&cache, |c| c.jobs_lost), 0);
        assert!(cache.cursor_charge() > 0);
        assert_eq!(cache.cursor_reserved(), 0);
        let mut index = ScanIndex::default();
        for _ in 0..32 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
        assert!(counter(&cache, |c| c.jobs_resumed) > 0);
    });
}

/// N3 (R2-N-B1): a session larger than B with 320 distinct active usage
/// hours, three models and efforts and two capability surfaces per hour
/// outgrows the ordinary walk's 4,096-visit limit. Its pause charge is the
/// byte-limited completed walk, so it pauses, resumes, certifies and
/// publishes once instead of parking as `JoinStateBound`.
#[test]
fn many_hour_session_pauses_past_the_walk_visit_limit_and_publishes_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const HOURS: u64 = 320;
    let models = ["fixture-model-a", "fixture-model-b", "fixture-model-c"];
    let efforts = ["low", "medium", "high"];
    let surfaces = ["chrome", "iab"];
    let fixture = ScanRoot::new(0);
    let mut body = Vec::new();
    for hour in 0..HOURS {
        let model = models[(hour % 3) as usize];
        let turn_id = format!("01a03e98-5000-7000-8000-{hour:012}");
        body.extend(codex_line(
            json!({"timestamp": hour_stamp(hour, 1), "type": "turn_context",
            "payload": {"turn_id": turn_id, "model": model,
                "effort": efforts[(hour % 3) as usize]}}),
        ));
        for (minute, backend) in surfaces.iter().enumerate() {
            body.extend(codex_line(
                json!({"timestamp": hour_stamp(hour, 2 + minute as u64), "type": "event_msg",
                "payload": {"type": "mcp_tool_call_end",
                    "invocation": {"server": "node_repl", "tool": "js"},
                    "result": {"Ok": {"_meta": {"codex/toolSurface":
                        {"kind": "browserUse", "backend": backend}}}}}}),
            ));
        }
        let n = hour + 1;
        body.extend(codex_line(
            json!({"timestamp": hour_stamp(hour, 10), "type": "event_msg",
            "payload": {"type": "token_count", "info": {"model": model,
            "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
                "output_tokens": n * 10},
            "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
                "output_tokens": 10}}}}),
        ));
    }
    fixture.append(SESSION, &body);
    let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
    assert!(!unpaged.snapshots.is_empty());
    let cache = Arc::new(SharedCache::default());
    let mut widest_hours = 0;
    let mut ordinary_walk_refused = false;
    let mut publishing_pages = 0;
    let paged = with_test_limits(32 * 1024, 16 * 1024, 1024, || {
        let mut index = ScanIndex::default();
        let mut published = None;
        for _ in 0..256 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            let held = cache.with_cursor(|cursor| match &cursor.slot {
                Slot::Paused(job) => (
                    job.parser.accumulator.usage_buckets.len(),
                    crate::heap_layout_bound::bound(&**job, STATE_BYTES).is_none(),
                ),
                Slot::Empty | Slot::ActiveElsewhere { .. } => (0, false),
            });
            let (hours, refused) = held.unwrap_or((0, false));
            widest_hours = widest_hours.max(hours);
            ordinary_walk_refused |= refused;
            if !scan.snapshots.is_empty() {
                publishing_pages += 1;
                published = Some(scan);
            }
            if counter(&cache, |c| c.jobs_certified) == 1 {
                let (_, again) = page(&fixture, index, Some(Arc::clone(&cache)));
                assert!(again.snapshots.is_empty(), "published once");
                return published.expect("the certified read publishes");
            }
        }
        panic!("many-hour job did not certify: {}", counters(&cache));
    });
    assert!(
        widest_hours >= 256,
        "a pause held {widest_hours} usage hours"
    );
    assert!(
        ordinary_walk_refused,
        "the fixture outgrows the ordinary walk's visit limit"
    );
    assert_eq!(publishing_pages, 1);
    assert_eq!(counter(&cache, |c| c.jobs_state_bound), 0);
    assert_eq!(counter(&cache, |c| c.jobs_started), 1);
    assert_eq!(cache.cursor_reserved(), 0);
    assert!(counter(&cache, |c| c.jobs_paused) > 0);
    assert_eq!(
        counter(&cache, |c| c.jobs_resumed),
        counter(&cache, |c| c.jobs_paused)
    );
    assert_eq!(fingerprints(&paged), fingerprints(&unpaged));
}

/// N1 (R1-B1 = R2-N-B2): while the sidecar census is incomplete main still
/// reads and publishes a large file, only unverified. A file larger than the
/// singleton budget pages as a cursor-only job (no retained state), publishes
/// once with main's fingerprints and index verification, keeps no copy, and
/// its path is consumed so the traversal can finish.
#[test]
fn incomplete_sidecar_census_pages_cursor_only_and_publishes_unverified() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let incomplete = |scan: &mut OwnedSourceScan| scan.sidecar_census_complete = false;
    let (main_index, unpaged, _) = page_with(
        &fixture,
        ScanIndex::default(),
        None,
        "cursor-fixture",
        NOW,
        incomplete,
    );
    assert!(!unpaged.snapshots.is_empty());
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        let mut published = Vec::new();
        for _ in 0..64 {
            let (next, scan, _) = page_with(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                NOW,
                incomplete,
            );
            index = next;
            if !scan.snapshots.is_empty() {
                published.push(fingerprints(&scan));
            }
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert!(counter(&cache, |c| c.jobs_paused) > 0, "it paged");
        assert_eq!(counter(&cache, |c| c.jobs_deferred_inputs), 0);
        assert_eq!(published, vec![fingerprints(&unpaged)], "published once");
        assert!(cache.retained_checkpoint(&key).is_none(), "no copy kept");
        let marker = |index: &ScanIndex| {
            index
                .files
                .get(&key)
                .map(|entry| entry.scan_identity_version.clone())
        };
        assert_eq!(marker(&index), marker(&main_index), "main's trust rule");
        assert!(!index
            .files
            .get(&key)
            .is_some_and(ScanIndexEntry::has_unverified_source));
        assert!(index
            .traversal
            .as_ref()
            .map_or(true, |traversal| traversal.pending_candidates.is_empty()));
    });
}

/// [regress] E2 (R2-B1): a resume whose evidence is unavailable is tried at
/// most once per page and ends after `UNAVAILABLE_RESUMES` such pages,
/// freeing the slot. The trigger: an untrusted census plus reduction
/// dependencies that cannot be computed (the existing refusal hook).
/// Before E2 the deferred job was resumed again on the next step of the
/// same scan object, forever; every page here must finish within a bound.
#[test]
fn unavailable_resume_never_spins_and_ends_after_bounded_pages() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const STEPS: usize = 10_000;
    let fixture = ScanRoot::new(40);
    let path = fixture.file(SESSION);
    let cache = Arc::new(SharedCache::default());
    struct ResetDependencies;
    impl Drop for ResetDependencies {
        fn drop(&mut self) {
            super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(false));
        }
    }
    let _reset = ResetDependencies;
    let flipped = |scan: &mut OwnedSourceScan| {
        scan.sidecar_census_complete = false;
        super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(true));
    };
    with_test_limits(2048, 1024, 64, || {
        let (mut index, _, _) = page_steps(
            &fixture,
            ScanIndex::default(),
            Some(Arc::clone(&cache)),
            "cursor-fixture",
            NOW,
            |_| {},
            STEPS,
        );
        assert_eq!(
            counter(&cache, |c| c.jobs_paused),
            1,
            "{}",
            counters(&cache)
        );
        for page in 1..=u64::from(UNAVAILABLE_RESUMES) {
            let (next, _, _) = page_steps(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                NOW,
                flipped,
                STEPS,
            );
            index = next;
            if page < u64::from(UNAVAILABLE_RESUMES) {
                // One resume attempt per page, deferred uncounted (K9).
                assert_eq!(counter(&cache, |c| c.jobs_deferred_inputs), page);
                assert_eq!(counter(&cache, |c| c.jobs_unavailable_ended), 0);
                assert!(!cache.cursor_slot_free());
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_unavailable_ended),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(
            counter(&cache, |c| c.jobs_deferred_inputs),
            u64::from(UNAVAILABLE_RESUMES) - 1
        );
        assert_eq!(
            counter(&cache, |c| c.jobs_invalidated),
            0,
            "not a member change"
        );
        // R2-L4: the ended job freed the slot and its path left the queue.
        assert!(cache.cursor_slot_free(), "{}", counters(&cache));
        assert_eq!(pending_hint(&index, &path), None, "dequeued");
    });
}

/// E1 (R1-B1 = R2-B2): a quiescent file larger than B whose last record has
/// no newline. At a genuine unchanged EOF (held FD stamp equal to the open
/// stamp, reader at that extent) the job applies the buffered record with
/// main's trailing-line rule, reading no byte: a valid record is counted
/// once, on the certified page, and the file is verified like main's full
/// read, so later pages skip it, also past the audit interval. No copy is
/// kept: the applied record lies past the certified prefix `[0, s)`, so
/// every such job is non-retainable and converges through the index alone.
/// A malformed record is reported as a line loss.
#[test]
fn quiescent_unterminated_last_record_is_applied_at_genuine_eof() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    let valid = {
        let mut line = token_line(41);
        line.pop();
        line
    };
    let malformed =
        br#"{"timestamp":"2026-10-07T10:30:00Z","type":"event_msg","payload":"#.to_vec();
    for (case, last) in [("valid", valid), ("malformed", malformed)] {
        let fixture = ScanRoot::new(40);
        fixture.append(SESSION, &last);
        let path = fixture.file(SESSION);
        let key = local_index_key(&path);
        let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
        let cache = Arc::new(SharedCache::default());
        with_test_limits(2048, 4096, 64, || {
            let mut now = 1_900_000_000_u64;
            let mut index = ScanIndex::default();
            let mut completed = None;
            let mut malformed_lines = 0;
            for _ in 0..64 {
                clock.set(now);
                let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
                index = next;
                malformed_lines += scan.malformed_json_line_count;
                // A lossy (malformed) job ends uncertified, like main's
                // lossy full read.
                if counter(&cache, |c| c.jobs_certified + c.jobs_uncertified) == 1 {
                    completed = Some(scan);
                    break;
                }
                assert!(
                    scan.snapshots.is_empty(),
                    "{case}: a paused job publishes nothing"
                );
                now += 10;
            }
            let completed = completed.unwrap_or_else(|| panic!("{case}: {}", counters(&cache)));
            assert_eq!(counter(&cache, |c| c.eof_record_applied), 1, "{case}");
            assert_eq!(counter(&cache, |c| c.sealed_fragment_withheld), 0, "{case}");
            assert!(cache.retained_checkpoint(&key).is_none(), "{case}: no copy");
            if case == "malformed" {
                assert_eq!(counter(&cache, |c| c.jobs_uncertified), 1, "{case}");
                assert!(unpaged.malformed_json_line_count > 0, "main reports it");
                assert!(malformed_lines > 0, "{case}: the loss is reported");
                return;
            }
            assert_eq!(counter(&cache, |c| c.jobs_certified), 1, "{case}");
            assert_eq!(
                fingerprints(&completed),
                fingerprints(&unpaged),
                "{case}: counted once, on the certified page"
            );
            assert!(
                !index
                    .files
                    .get(&key)
                    .is_some_and(ScanIndexEntry::has_unverified_source),
                "{case}: verified like main's full read"
            );
            // No debt was staged, so crossing the audit interval re-reads
            // nothing: the size decision skips the file.
            for _ in 0..3 {
                now += interval + 1;
                clock.set(now);
                let (next, scan, modes) =
                    page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
                index = next;
                assert!(scan.snapshots.is_empty(), "{case}: skipped");
                assert_eq!(modes, (0, 0), "{case}: no read");
            }
            assert_eq!(counter(&cache, |c| c.jobs_started), 1, "{case}: no re-read");
        });
    }
}

/// Pages one cursor job to its certified end, `I/2` apart, from census
/// generation `page_number + 1`. With `append_mid_read`, the file grows
/// after the job's first page. Returns the index, the clock at the job's
/// open and at its commit, and the opening page's full reads by reason.
fn certify_job(
    fixture: &ScanRoot,
    cache: &Arc<SharedCache>,
    mut index: ScanIndex,
    clock: &TestClock,
    now: &mut u64,
    page_number: &mut u64,
    append_mid_read: bool,
) -> (ScanIndex, u64, u64, [usize; 11]) {
    let step = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS / 2;
    let certified = counter(cache, |c| c.jobs_certified);
    let mut opened = None;
    let mut appended = !append_mid_read;
    for _ in 0..64 {
        clock.set(*now);
        *page_number += 1;
        let started = counter(cache, |c| c.jobs_started);
        let (next, scan, selections) = page_selections(
            fixture,
            index,
            Some(Arc::clone(cache)),
            "cursor-fixture",
            &collected_at(*page_number),
            |_| {},
            10_000,
        );
        index = next;
        if counter(cache, |c| c.jobs_started) > started {
            opened = Some((*now, selections.full_reasons));
        }
        if counter(cache, |c| c.jobs_certified) > certified {
            assert!(!scan.snapshots.is_empty(), "the certified read publishes");
            let (opened, reasons) = opened.expect("a cursor job opened");
            return (index, opened, *now, reasons);
        }
        assert!(scan.snapshots.is_empty(), "a paused job publishes nothing");
        if !appended && opened.is_some() {
            fixture.append(SESSION, &token_line(41));
            appended = true;
        }
        *now += step;
    }
    panic!("the cursor job did not certify: {}", counters(cache));
}

/// The candidate an unchanged file presents to the scheduler: its own index
/// entry's facts.
fn unchanged_candidate(fixture: &ScanRoot, index: &ScanIndex) -> CandidateFile {
    let path = fixture.file(SESSION);
    let entry = &index.files[&local_index_key(&path)];
    CandidateFile {
        physical_identity: None,
        scan_root: fixture.root.clone(),
        path,
        size_bytes: entry.size_bytes,
        modified_unix_seconds: entry.modified_unix_seconds,
        modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
        source_file_fingerprint: entry.source_file_fingerprint.clone(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}

/// AD-1 at scan level (AD-T6, AD-T7). A quiescent singleton larger than the
/// page budget is read by a cursor job that outlives the audit interval
/// (`I/2` per page). Its complete read of the unchanged object verifies at
/// commit: no overdue audit, no marker (a seeded past-due one is cleared),
/// and the retained copy is verified at the commit clock. `grown` (AD-T7):
/// an append after the job's first page keeps the grown arm (overdue, due
/// marker); the next generation's audit of the now stable file converges.
///
/// Selection semantics after convergence: in later census generations, past
/// `commit + I`, the scheduler skips the file (`Skip`: same fingerprint, no
/// marker), so no acquisition opens it: neither `Unchanged` nor `AuditDue`
/// is selected. After R2's gate removal, a later append reuses the
/// retained checkpoint as Tail even beyond `commit + I`.
#[test]
fn ad1_quiescent_outlived_cursor_read_verifies_at_commit_and_converges() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    for case in ["unmarked", "due marker", "grown"] {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let mut now = 1_900_000_000_u64;
        clock.set(now);
        let mut index = ScanIndex::default();
        if case == "due marker" {
            // A recorded entry (read in page) that owes an audit already due.
            index = page(
                &fixture,
                ScanIndex::default(),
                Some(Arc::new(SharedCache::default())),
            )
            .0;
            let entry = index.files.get_mut(&key).unwrap();
            entry.set_unverified_deadline(now - 1);
            assert!(entry.audit_requires_full(now));
        }
        let cache = Arc::new(SharedCache::default());
        // The limits under which this fixture's certified cursor read is
        // retained (`tail_eof_record_adding_first_priority_tier_…`).
        with_test_limits(2048, 8192, 64, || {
            let mut page_number = 0;
            let (next, opened, committed, reasons) = certify_job(
                &fixture,
                &cache,
                index,
                &clock,
                &mut now,
                &mut page_number,
                case == "grown",
            );
            index = next;
            let reason = FullReason::StateMissing;
            assert_eq!(reasons[reason.slot()], 1, "{case}: {reasons:?}");
            assert!(
                committed >= opened + interval,
                "{case}: the read outlived I"
            );
            let mut jobs = 1;
            if case == "grown" {
                // AD-T7: the grown arm, as before AD-1.
                assert_eq!(counter(&cache, |c| c.audit_overdue), 1, "{case}");
                let retained = cache.retained_checkpoint(&key).expect("grown prefix");
                assert_eq!(retained.last_full_verified(), opened, "{case}");
                assert_eq!(
                    index.files[&key].unverified_deadline(),
                    Some(opened + interval),
                    "{case}: due marker"
                );
                // Keep AD-1's stable Full-completion control distinct from
                // R2's valid-checkpoint Tail case below. No RAM state survives
                // this explicit eviction; missing state determines the reason.
                cache.clear();
                assert!(cache.retained_checkpoint(&key).is_none());
                let (next, opened, committed, reasons) = certify_job(
                    &fixture,
                    &cache,
                    index,
                    &clock,
                    &mut now,
                    &mut page_number,
                    false,
                );
                index = next;
                // Selection is due, but checkpoint absence is the Full cause.
                assert_eq!(
                    reasons[FullReason::StateMissing.slot()],
                    1,
                    "{case}: {reasons:?}"
                );
                assert!(committed >= opened + interval, "{case}: audit outlived I");
                jobs = 2;
            }
            let committed = now;
            assert_eq!(counter(&cache, |c| c.jobs_certified), jobs, "{case}");
            assert_eq!(counter(&cache, |c| c.jobs_started), jobs, "{case}");
            let overdue = u64::from(case == "grown");
            assert_eq!(counter(&cache, |c| c.audit_overdue), overdue, "{case}");
            assert!(
                !index.files[&key].has_unverified_source(),
                "{case}: verified, no marker"
            );
            let retained = cache.retained_checkpoint(&key).expect("complete copy");
            assert_eq!(retained.last_full_verified(), committed, "{case}");
            assert_eq!(retained.audit_debt(), None, "{case}");
            assert_eq!(retained.sealed_offset(), fixture.len(SESSION), "{case}");
            // Later generations past `commit + I`: the scheduler's `Skip`.
            for _ in 0..3 {
                now += interval + 1;
                clock.set(now);
                page_number += 1;
                let candidate = unchanged_candidate(&fixture, &index);
                assert_eq!(candidate.size_bytes, fixture.len(SESSION));
                assert_eq!(
                    index.candidate_decision_with_reason_at(&candidate, now),
                    (CandidateDecision::Skip, None),
                    "{case}"
                );
                let (next, scan, selections) = page_selections(
                    &fixture,
                    index,
                    Some(Arc::clone(&cache)),
                    "cursor-fixture",
                    &collected_at(page_number),
                    |_| {},
                    10_000,
                );
                index = next;
                assert!(scan.snapshots.is_empty(), "{case}: skipped");
                assert_eq!(selections.modes, (0, 0), "{case}: no read");
                assert_eq!(selections.unchanged, 0, "{case}: not an acquisition");
            }
            assert_eq!(counter(&cache, |c| c.jobs_started), jobs, "{case}");
            // A valid retained checkpoint is not reread for its age: the
            // next append selects Tail even after the old audit horizon.
            assert!(now >= committed + interval);
            let before = fixture.len(SESSION);
            fixture.append(SESSION, &token_line(90));
            let suffix = fixture.len(SESSION) - before;
            assert!(suffix > 0 && suffix <= Limits::current().singleton());
            page_number += 1;
            let (next, scan, selections) = page_selections(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                &collected_at(page_number),
                |_| {},
                10_000,
            );
            assert_eq!(selections.modes, (0, 1), "{case}: a tail read");
            assert_eq!(
                selections.full_reasons[FullReason::AuditDue.slot()],
                0,
                "{case}: {selections:?}"
            );
            assert_eq!(
                counter(&cache, |c| c.jobs_started),
                jobs,
                "{case}: singleton Tail"
            );
            assert_eq!(
                counter(&cache, |c| c.jobs_certified),
                jobs,
                "{case}: no cursor job"
            );
            assert!(
                !scan.snapshots.is_empty(),
                "{case}: Tail publishes the append"
            );
            let tailed = cache.retained_checkpoint(&key).expect("Tail retained");
            assert_eq!(tailed.sealed_offset(), fixture.len(SESSION), "{case}");
            assert!(tailed.sealed_offset() > retained.sealed_offset(), "{case}");
            assert_eq!(
                tailed.last_full_verified(),
                committed,
                "{case}: no audit credit"
            );
            assert_eq!(
                tailed.audit_debt().map(|debt| debt.due_unix_seconds),
                Some(committed + interval),
                "{case}: original verification determines debt, not Tail time"
            );
            assert_eq!(
                next.files[&key].unverified_deadline(),
                Some(committed + interval)
            );
        });
    }
}

/// R1-H1 (#606 final review): a tail-mode cursor job whose genuine-EOF
/// record (E1) introduces the file's first priority tier goes through the
/// protected-tier full replay before anything publishes, as main's trailing
/// line does: a sampled prefix never mints the receipt.
#[test]
fn tail_eof_record_adding_first_priority_tier_replays_before_publishing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let path = fixture.file(SESSION);
        let key = local_index_key(&path);
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert!(
            cache.retained_checkpoint(&key).is_some(),
            "a retained prefix makes the next read a tail: {}",
            counters(&cache)
        );
        // A tail larger than the singleton budget (a cursor job) whose last,
        // unterminated record is the file's first priority usage.
        for n in 41..=80 {
            fixture.append(SESSION, &token_line(n));
        }
        let mut priority = codex_line(
            json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
            "payload": {"type": "token_count", "service_tier": "priority",
            "info": {"model": "fixture-model",
            "total_token_usage": {"input_tokens": 8_100, "cached_input_tokens": 4_050,
                "output_tokens": 810},
            "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
                "output_tokens": 10}}}}),
        );
        priority.pop();
        fixture.append(SESSION, &priority);
        let mut tail_started = false;
        let mut replayed = false;
        let mut published = None;
        // Later census generations: the K7 fence held this file for the
        // generation of its certified read.
        for page_number in 1..=64 {
            let (next, scan, modes) = page_at(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                &collected_at(page_number),
            );
            index = next;
            tail_started |= modes.1 > 0;
            replayed |= tail_started && modes.0 > 0;
            if !scan.snapshots.is_empty() {
                assert!(
                    replayed,
                    "the EOF record's protected tier forced the full replay first"
                );
                // Main's unpaged read of the same object, same collection.
                let (_, unpaged, _) = page_at(
                    &fixture,
                    ScanIndex::default(),
                    None,
                    "cursor-fixture",
                    &collected_at(page_number),
                );
                published = Some((scan, unpaged));
                break;
            }
        }
        let (published, unpaged) = published.unwrap_or_else(|| panic!("{}", counters(&cache)));
        assert!(tail_started, "the read began as a sampled tail");
        assert_eq!(counter(&cache, |c| c.eof_record_applied), 1);
        assert!(index.files[&key].codex_applied_tier_receipt_required);
        assert_eq!(fingerprints(&published), fingerprints(&unpaged));
    });
}

/// E1: a file that grew during the job keeps its unterminated record
/// withheld (the held FD is no longer the opened object); the next page
/// tails it from `s`, so it is counted once, after its newline.
#[test]
fn grown_unterminated_last_record_stays_withheld() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let mut last = token_line(41);
    last.pop();
    fixture.append(SESSION, &last);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 4096, 64, || {
        let mut index = ScanIndex::default();
        let mut appended = false;
        for _ in 0..64 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
            if !appended {
                // Complete the record past the job's frozen extent.
                fixture.append(SESSION, b"\n");
                fixture.append(SESSION, &token_line(42));
                appended = true;
            }
        }
        assert!(appended);
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.eof_record_applied), 0, "withheld");
        let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
        let mut last_published = None;
        for _ in 0..4 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if !scan.snapshots.is_empty() {
                last_published = Some(fingerprints(&scan));
            }
        }
        assert_eq!(
            last_published,
            Some(fingerprints(&unpaged)),
            "the tail counts the record once"
        );
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
    });
}

/// Parent ruling 2 (R1-H1): a lossy cursor job whose file grew past its
/// frozen extent publishes UNCERTIFIED through its same-object identity
/// proof: main's semantic output for the object it read, the original debt
/// and age kept, no checkpoint, copy or verification. Before the grant its
/// `finish` refused (`jobs_finish_failed`). The loss is an overlong line
/// (terminal salvage loss main publishes; a malformed line is retryable and
/// main publishes nothing). Controls: a replaced path or a shrunk file
/// publishes nothing from that attempt.
///
/// `stable` (AD-1's named lossy-stable residual control, design §3.2): the
/// same lossy job on an unchanged file refuses as `Lossy` before AD-1's
/// verify-at-commit arm. It publishes uncertified, keeps its due marker, and
/// is re-read in full every later census generation (one cursor job each,
/// never certified). Disclosed residual: lossy keeps its obligation.
#[test]
fn lossy_grown_job_publishes_uncertified_through_same_object_identity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    let now = 1_900_000_000_u64;
    let due = now + 100;
    let mut overlong = br#"{"timestamp":"2026-10-07T10:30:00Z","type":"event_msg","payload":{"type":"agent_message","message":""#.to_vec();
    overlong.extend(std::iter::repeat_n(b'x', MAX_JSONL_LINE_BYTES + 1));
    overlong.extend_from_slice(b"\"}}\n");
    for case in ["grow", "replace", "shrink", "stable"] {
        clock.set(now);
        let fixture = ScanRoot::new(20);
        fixture.append(SESSION, &overlong);
        for n in 21..=40 {
            fixture.append(SESSION, &token_line(n));
        }
        let path = fixture.file(SESSION);
        let key = local_index_key(&path);
        // A recorded entry that owes `due`; an append then selects the file.
        let (mut seeded, _) = page(
            &fixture,
            ScanIndex::default(),
            Some(Arc::new(SharedCache::default())),
        );
        seeded
            .files
            .get_mut(&key)
            .unwrap()
            .set_unverified_deadline(due);
        fixture.append(SESSION, &token_line(41));
        // Main's sampled lossy read of the same object from the same index.
        let (main_index, main) = page(
            &fixture,
            seeded.clone(),
            Some(Arc::new(SharedCache::default())),
        );
        assert!(!main.snapshots.is_empty(), "main publishes terminal loss");
        let deadline = |index: &ScanIndex| {
            index
                .files
                .get(&key)
                .and_then(ScanIndexEntry::unverified_deadline)
        };
        assert_eq!(deadline(&main_index), Some(due), "main keeps the debt");
        let cache = Arc::new(SharedCache::default());
        with_test_limits(2048, 1024, 64, || {
            let (mut index, first) = page(&fixture, seeded.clone(), Some(Arc::clone(&cache)));
            assert!(first.snapshots.is_empty(), "{case}: paused");
            assert_eq!(
                counter(&cache, |c| c.jobs_paused),
                1,
                "{case}: {}",
                counters(&cache)
            );
            match case {
                "grow" => fixture.append(SESSION, &token_line(42)),
                "stable" => {}
                "replace" => {
                    let replacement = path.with_extension("replacement");
                    fs::copy(&path, &replacement).unwrap();
                    OpenOptions::new()
                        .append(true)
                        .open(&replacement)
                        .unwrap()
                        .write_all(&token_line(42))
                        .unwrap();
                    fs::rename(&replacement, &path).unwrap();
                }
                _ => OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(fixture.len(SESSION) / 2)
                    .unwrap(),
            }
            let ended = |cache: &SharedCache| match case {
                "grow" | "stable" => {
                    counter(cache, |c| c.jobs_uncertified + c.jobs_finish_failed) > 0
                }
                "replace" => counter(cache, |c| c.jobs_unavailable_ended) > 0,
                _ => counter(cache, |c| c.jobs_invalidated) > 0,
            };
            let mut ending = None;
            for _ in 0..64 {
                let (next, scan, _) = page_steps(
                    &fixture,
                    index,
                    Some(Arc::clone(&cache)),
                    "cursor-fixture",
                    NOW,
                    |_| {},
                    10_000,
                );
                index = next;
                if ended(&cache) {
                    ending = Some(scan);
                    break;
                }
                assert!(
                    scan.snapshots.is_empty(),
                    "{case}: a paused job publishes nothing"
                );
            }
            let ending = ending.unwrap_or_else(|| panic!("{case}: {}", counters(&cache)));
            assert_eq!(counter(&cache, |c| c.jobs_finish_failed), 0, "{case}");
            assert_eq!(counter(&cache, |c| c.jobs_certified), 0, "{case}");
            assert!(cache.retained_checkpoint(&key).is_none(), "{case}: no copy");
            if case != "grow" && case != "stable" {
                assert!(ending.snapshots.is_empty(), "{case}: nothing published");
                assert_eq!(counter(&cache, |c| c.jobs_uncertified), 0, "{case}");
                return;
            }
            assert_eq!(counter(&cache, |c| c.jobs_uncertified), 1, "{case}");
            assert_eq!(counter(&cache, |c| c.jobs_invalidated), 0, "{case}");
            assert_eq!(
                fingerprints(&ending),
                fingerprints(&main),
                "{case}: main's semantic output for the object read"
            );
            assert_eq!(
                deadline(&index),
                Some(due),
                "{case}: original debt and age kept"
            );
            if case != "stable" {
                return;
            }
            // Later generations past the due marker: every one re-reads the
            // unchanged file in full and keeps the deadline (no AD-1 clear).
            let mut later = due;
            let mut page_number = 0;
            for generation in 1..=3 {
                later += interval + 1;
                clock.set(later);
                let started = counter(&cache, |c| c.jobs_started);
                let uncertified = counter(&cache, |c| c.jobs_uncertified);
                let mut reread = false;
                for _ in 0..64 {
                    page_number += 1;
                    let (next, _, _) = page_steps(
                        &fixture,
                        index,
                        Some(Arc::clone(&cache)),
                        "cursor-fixture",
                        &collected_at(page_number),
                        |_| {},
                        10_000,
                    );
                    index = next;
                    if counter(&cache, |c| c.jobs_uncertified) > uncertified {
                        reread = true;
                        break;
                    }
                }
                assert!(reread, "generation {generation}: {}", counters(&cache));
                assert_eq!(
                    counter(&cache, |c| c.jobs_started),
                    started + 1,
                    "generation {generation}: one full re-read"
                );
                assert_eq!(counter(&cache, |c| c.jobs_certified), 0);
                assert_eq!(counter(&cache, |c| c.jobs_finish_failed), 0);
                assert!(cache.retained_checkpoint(&key).is_none(), "no copy");
                assert_eq!(
                    deadline(&index),
                    Some(due),
                    "generation {generation}: the deadline never moves"
                );
            }
        });
    }
}

/// G1 (K7 for singletons and re-reads): a Codex watcher hint for a path this
/// generation already processed (observed, no longer pending) re-enters as
/// a non-member and is counted; a pending path is not duplicated; a path the
/// walk has not observed, and every non-Codex hint, stays a census member.
#[test]
fn watcher_hint_for_a_processed_codex_path_is_next_generation_evidence() {
    const SESSION_C: &str = "019fa111-2222-7333-8444-777777777701";
    let fixture = ScanRoot::with_sessions(&[(SESSION, 2), (SESSION_B, 2)]);
    let mut index = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    let walked = index.traversal.as_mut().unwrap();

    let processed = fixture.file(SESSION);
    let pending = fixture.file(SESSION_B);
    let unobserved = fixture.file(SESSION_C);
    assert!(walked
        .observed_index_keys
        .contains(&local_index_key(&processed)));
    // `processed` was selected and read on an earlier page.
    walked
        .pending_candidates
        .retain(|candidate| candidate.path != processed);
    assert!(walked
        .pending_candidates
        .iter()
        .any(|candidate| candidate.path == pending && candidate.census_member));
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        let mut traversal = walked.clone();
        let before = traversal.pending_candidates.len();
        let next_generation = enqueue_watcher_hints(
            source,
            &mut traversal,
            &[processed.clone(), pending.clone(), unobserved.clone()],
            false,
        );
        let flags = |path: &Path| {
            let matches = traversal
                .pending_candidates
                .iter()
                .filter(|candidate| candidate.path == path)
                .map(|candidate| (candidate.census_member, candidate.watcher_hint))
                .collect::<Vec<_>>();
            assert!(matches.len() <= 1, "{source:?}: one entry per path");
            matches.first().copied()
        };
        let codex = source == SnapshotSource::Codex;
        assert_eq!(next_generation, u64::from(codex), "{source:?}");
        assert_eq!(flags(&processed), Some((!codex, true)), "{source:?}");
        assert_eq!(
            flags(&pending),
            Some((true, codex)),
            "{source:?}: the pending census member keeps membership and remembers the hint"
        );
        assert_eq!(flags(&unobserved), Some((true, true)), "{source:?}");
        assert_eq!(traversal.pending_candidates.len(), before + 2);
    }
}

/// One page with `hints` as the cycle's watcher paths (`page_selections`
/// otherwise).
fn hinted_page(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    hints: &[PathBuf],
) -> (ScanIndex, SourceScanResult) {
    hinted_page_limited(fixture, index, cache, collected_at, hints, 10)
}

/// `hinted_page` with a file limit of `limit` per page.
fn hinted_page_limited(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    hints: &[PathBuf],
    limit: usize,
) -> (ScanIndex, SourceScanResult) {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        limit,
        false,
        None,
        hints,
        false,
    )
    .with_sampled_acquisition(Arc::clone(cache), Scope("cursor-fixture".into()));
    loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
}

/// G1/G2 at scan level. Three medium files grow on every page and are
/// hinted, and their retained state is gone each page (as after a restart or
/// a cache eviction), so each growth needs a full re-read; together they
/// exceed the page's singleton budget. A fourth file larger than the budget
/// is read by the cursor, one slice per page, while it also grows.
///
/// Before G1 the re-hinted files re-entered the census on every page and one
/// was always deferred, so the generation never closed. Now the generation
/// closes once the large job ends (within `ceil(L/B)` pages plus a small
/// constant), each page completes a first read ahead of the hints, and the
/// re-reads are counted as next-generation evidence. After growth stops, the
/// follow-up generation re-reads every grown file (G2), and the published
/// totals equal a fresh full read of the final files: no byte lost, none
/// counted twice.
#[test]
fn growing_generation_with_large_file_closes_within_bounded_pages() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const MEDIUM: [&str; 3] = [
        "019fa111-2222-7333-8444-777777777711",
        "019fa111-2222-7333-8444-777777777712",
        "019fa111-2222-7333-8444-777777777713",
    ];
    const LARGE: &str = "019fa111-2222-7333-8444-777777777714";
    const B: u64 = 2048;
    let fixture =
        ScanRoot::with_sessions(&[(MEDIUM[0], 4), (MEDIUM[1], 4), (MEDIUM[2], 4), (LARGE, 60)]);
    let sessions = [MEDIUM[0], MEDIUM[1], MEDIUM[2], LARGE];
    let medium_len = fixture.len(MEDIUM[0]);
    // Two medium full reads fit one page's singleton budget, three never do.
    let singleton = medium_len * 2 + medium_len / 2;
    assert!(fixture.len(LARGE) > singleton);
    let bound = fixture.len(LARGE).div_ceil(B) + 4;
    let cache = Arc::new(SharedCache::default());
    let mut next_line = [5_u64, 5, 5, 61];
    let mut latest = BTreeMap::<String, (u64, u64, u64, u64)>::new();
    let mut record = |scan: &SourceScanResult| {
        for item in &scan.snapshots {
            latest.insert(
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            );
        }
    };
    with_test_limits(B, singleton, 64, || {
        let mut index = ScanIndex::default();
        let mut page_number = 0_u64;
        let mut closed = None;
        let mut closing_token = None;
        while page_number < bound {
            closing_token = census_token(&index);
            let hints = if page_number == 0 {
                Vec::new()
            } else {
                sessions.map(|session| fixture.file(session)).to_vec()
            };
            let (next, scan) =
                hinted_page(&fixture, index, &cache, &collected_at(page_number), &hints);
            index = next;
            record(&scan);
            page_number += 1;
            if scan.census_complete {
                assert_eq!(
                    scan.skipped_file_count_due_to_limit, 0,
                    "census members only"
                );
                closed = Some(page_number);
                break;
            }
            // Steady growth; every retained state is gone by the next page.
            for (session, line) in sessions.iter().zip(next_line.iter_mut()) {
                fixture.append(session, &token_line(*line));
                *line += 1;
            }
            cache.clear();
        }
        let closed = closed.unwrap_or_else(|| {
            panic!(
                "the growing generation did not close within {bound} pages: {}",
                counters(&cache)
            )
        });
        // The closed generation retired. Re-reads still waiting then were
        // carried into the next generation, each as a census member of it.
        if let Some(traversal) = &index.traversal {
            assert_ne!(census_token(&index), closing_token, "a new generation");
            assert!(traversal
                .pending_candidates
                .iter()
                .all(|candidate| candidate.census_member));
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified) + counter(&cache, |c| c.jobs_uncertified),
            1
        );
        assert!(
            counter(&cache, |c| c.deferred_next_generation) > 0,
            "re-reads were counted as next-generation evidence: {}",
            counters(&cache)
        );
        assert!(closed > 1, "the large file really paged");
        // G2: growth stops; the follow-up generation re-reads every grown
        // file, including the growth a closed generation left pending.
        let mut converged = false;
        for _ in 0..bound * 2 {
            let (next, scan) =
                hinted_page(&fixture, index, &cache, &collected_at(page_number), &[]);
            index = next;
            record(&scan);
            page_number += 1;
            let current = sessions.iter().all(|session| {
                index
                    .files
                    .get(&local_index_key(&fixture.file(session)))
                    .is_some_and(|entry| entry.size_bytes == fixture.len(session))
            });
            if scan.census_complete && current {
                converged = true;
                break;
            }
        }
        assert!(
            converged,
            "the follow-up generation re-read every grown file: {}",
            counters(&cache)
        );
    });
    // No byte lost, none counted twice: the last published totals per
    // session equal a fresh full read of the final files.
    let (_, fresh) = page(&fixture, ScanIndex::default(), None);
    let expected = fresh
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(expected.len(), sessions.len());
    assert_eq!(latest, expected);
}

/// An ordinary page that fits must still service both old revalidation and
/// a new hinted session; fresh traffic must not create unnecessary pages.
#[test]
fn freshness_selection_keeps_a_fitting_census_page_together() {
    let fixture = ScanRoot::new(4);
    let (mut index, _) = page(&fixture, ScanIndex::default(), None);
    index
        .files
        .get_mut(&local_index_key(&fixture.file(SESSION)))
        .unwrap()
        .source_file_fingerprint
        .clear();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
        "type": "session_meta", "payload": {"id": SESSION_B}}));
    body.extend(token_line(1));
    fs::write(fixture.file(SESSION_B), body).unwrap();
    let scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[fixture.file(SESSION_B)],
        false,
    );
    assert_eq!(scan.identified_candidates.len(), 2);
    assert!(!scan.index.traversal.as_ref().unwrap().codex_freshness_yield);
}

/// The production-shaped 2,800-member revalidation backlog must not spend
/// the byte budget before a new session or an appended, processed session.
/// A persisted yield then gives the census a whole ordinary page even when
/// fresh data continues to arrive. No upload fingerprints or totals change.
#[test]
fn fresh_sessions_bypass_2800_owed_rereads_within_two_pages() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const NEW: &str = "019fa111-2222-7333-8444-888888888888";
    const NEXT: &str = "019fa111-2222-7333-8444-888888888889";
    let ids = (0..2800)
        .map(|n| format!("019fa111-2222-7333-8444-{n:012}"))
        .collect::<Vec<_>>();
    let mut sessions = ids.iter().map(|id| (id.as_str(), 4)).collect::<Vec<_>>();
    sessions.push((SESSION, 4));
    let fixture = ScanRoot::with_sessions(&sessions);
    let cache = Arc::new(SharedCache::default());
    let (mut index, warm) = published_scan(&fixture, &cache, ScanIndex::default(), NOW, &[]);
    assert_eq!(warm.snapshots.len(), 2801);
    for id in &ids {
        index
            .files
            .get_mut(&local_index_key(&fixture.file(id)))
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    // SESSION already finished its census read; growth must not re-enroll it.
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .retain(|candidate| candidate.path != fixture.file(SESSION));
    let budget = fixture.len(SESSION) * 4;
    cache.clear();
    with_test_limits(2048, budget, 64, || {
        let (next, scan) = published_scan(&fixture, &cache, index, NOW, &[]);
        index = next;
        assert!(scan.snapshots.is_empty(), "unchanged-output revalidation");
        assert!(!scan.census_complete);
        let window = scan.census_window_end.clone();
        let old_pending = index.traversal.as_ref().unwrap().pending_candidates.len();
        assert!(old_pending > 2700);

        let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
            "type": "session_meta", "payload": {"id": NEW}}));
        body.extend(token_line(1));
        fs::write(fixture.file(NEW), body).unwrap();
        fixture.append(SESSION, &token_line(5));
        cache.clear();
        // NEW deliberately has no watcher hint: retained-roster discovery
        // must promote it too, even though refresh runs before hint enqueue.
        let (next, fresh) = published_scan(
            &fixture,
            &cache,
            index,
            &collected_at(1),
            &[fixture.file(SESSION)],
        );
        index = next;
        let published = fresh
            .snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(published, BTreeSet::from([NEW, SESSION]));
        assert_eq!(fresh.census_window_end, window);
        assert!(!fresh.census_complete);
        assert!(index.traversal.as_ref().unwrap().codex_freshness_yield);
        assert_eq!(
            index.traversal.as_ref().unwrap().pending_candidates.len(),
            old_pending
        );

        // Restart preserves the owed ordinary turn. Another real append
        // waits while that page makes census progress with the full budget.
        index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        fixture.append(SESSION, &token_line(6));
        let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:02Z",
            "type": "session_meta", "payload": {"id": NEXT}}));
        body.extend(token_line(1));
        fs::write(fixture.file(NEXT), body).unwrap();
        let (next, ordinary) = published_scan(
            &fixture,
            &cache,
            index,
            &collected_at(2),
            &[fixture.file(SESSION), fixture.file(NEXT)],
        );
        index = next;
        assert!(!ordinary.census_complete);
        assert!(
            ordinary.snapshots.is_empty(),
            "the owed turn is for old census debt"
        );
        assert!(!index.traversal.as_ref().unwrap().codex_freshness_yield);
        assert!(index.traversal.as_ref().unwrap().pending_candidates.len() < old_pending);
        let (_, fresh) = published_scan(&fixture, &cache, index, &collected_at(3), &[]);
        let published = fresh
            .snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(published, BTreeSet::from([NEXT, SESSION]));
    });
}

/// One Codex page stepped to completion, returning the same post-policy
/// upload set the collector would offer.
fn published_scan(
    fixture: &ScanRoot,
    cache: &Arc<SharedCache>,
    index: ScanIndex,
    collected_at: &str,
    hints: &[PathBuf],
) -> (ScanIndex, SourceScanResult) {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        10000,
        false,
        None,
        hints,
        false,
    )
    .with_sampled_acquisition(Arc::clone(cache), Scope("cursor-fixture".into()));
    loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut scan.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                let accepted = scan
                    .snapshots
                    .iter()
                    .map(|item| item.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
}

/// Write a one-turn rollout in a day directory below the fixture root.
fn write_dated_rollout(fixture: &ScanRoot, day: &str, session: &str) -> PathBuf {
    let directory = fixture.root.join(day);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("rollout-2026-10-07T10-00-00-{session}.jsonl"));
    let mut body = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
        "type": "session_meta", "payload": {"id": session}}));
    body.extend(token_line(1));
    fs::write(&path, body).unwrap();
    path
}

/// Only a directory found by retained-roster refresh carries freshness
/// provenance, through its whole subtree. The initial walk of old nested day
/// directories queues cold history unmarked, so it keeps FIFO census order.
#[test]
fn only_roster_discovered_directories_mark_their_sessions_fresh() {
    const OLD: &str = "019fa111-2222-7333-8444-888888888891";
    const NEW: &str = "019fa111-2222-7333-8444-888888888892";
    let fixture = ScanRoot::new(4);
    let old = write_dated_rollout(&fixture, "2026/10/01", OLD);
    let mut index = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    let flags = |index: &ScanIndex, path: &PathBuf| {
        index
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .find(|candidate| candidate.path == *path)
            .map(|candidate| {
                (
                    candidate.census_member,
                    candidate.watcher_hint,
                    codex_fresh_data_pending(candidate, &index.files),
                )
            })
    };
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty());
    assert_eq!(flags(&index, &old), Some((true, false, false)));
    assert_eq!(
        flags(&index, &fixture.file(SESSION)),
        Some((true, false, false))
    );

    // A new month: `2026` moves, and both `11` and `11/01` are new. Wait
    // past coarse directory timestamps so the move is visible everywhere.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let new = write_dated_rollout(&fixture, "2026/11/01", NEW);
    refresh_retained_codex_roster(
        SnapshotSource::Codex,
        index.traversal.as_mut().unwrap(),
        BACKFILL_WINDOW_DAYS,
        discovery_retention!(index),
    );
    assert!(!index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty());
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .is_empty());
    assert_eq!(flags(&index, &new), Some((true, true, true)));
    assert_eq!(flags(&index, &old), Some((true, false, false)));
}

/// A new Codex day is a new date directory. Retained-roster refresh finds it
/// with no watcher hint; its rollout must still reach the post-policy upload
/// set within two ordinary pages instead of waiting behind 2,800 owed old
/// census members.
#[test]
fn new_date_directory_session_bypasses_2800_owed_rereads_within_two_pages() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const NEW: &str = "019fa111-2222-7333-8444-888888888890";
    let ids = (0..2800)
        .map(|n| format!("019fa111-2222-7333-8444-{n:012}"))
        .collect::<Vec<_>>();
    let mut sessions = ids.iter().map(|id| (id.as_str(), 4)).collect::<Vec<_>>();
    sessions.push((SESSION, 4));
    let fixture = ScanRoot::with_sessions(&sessions);
    let cache = Arc::new(SharedCache::default());
    let (mut index, warm) = published_scan(&fixture, &cache, ScanIndex::default(), NOW, &[]);
    assert_eq!(warm.snapshots.len(), 2801);
    for id in &ids {
        index
            .files
            .get_mut(&local_index_key(&fixture.file(id)))
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    let budget = fixture.len(SESSION) * 4;
    cache.clear();
    with_test_limits(2048, budget, 64, || {
        let (next, scan) = published_scan(&fixture, &cache, index, NOW, &[]);
        index = next;
        assert!(scan.snapshots.is_empty(), "unchanged-output revalidation");
        assert!(!scan.census_complete);
        let window = scan.census_window_end.clone();
        assert!(index.traversal.as_ref().unwrap().pending_candidates.len() > 2700);

        std::thread::sleep(std::time::Duration::from_millis(50));
        write_dated_rollout(&fixture, "2026/10/08", NEW);
        cache.clear();
        let mut published = BTreeSet::new();
        for page in 1..=2 {
            let (next, scan) = published_scan(&fixture, &cache, index, &collected_at(page), &[]);
            index = next;
            assert_eq!(scan.census_window_end, window, "same open generation");
            assert!(!scan.census_complete);
            published.extend(
                scan.snapshots
                    .iter()
                    .map(|item| item.source_session_id.clone()),
            );
            if published.contains(NEW) {
                break;
            }
        }
        assert_eq!(published, BTreeSet::from([NEW.to_string()]));
    });
}

/// G1 carry: a census that closes while a re-read is still waiting hands it
/// to the next generation as a member instead of dropping it. Two small
/// files, one full read per page. Page 0 reads one (X) and defers the other
/// (Y). X then grows and is hinted with its retained state gone: a re-read,
/// not a member. Page 1 reads the member Y first, the budget defers X, and the
/// census closes with X waiting. The closed generation never takes X back;
/// the next one holds it as a member and reads it exactly once, and the
/// published totals equal a fresh full read (no byte lost, none twice).
#[test]
fn census_close_carries_a_waiting_reread_into_the_next_generation() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const SESSIONS: [&str; 2] = [
        "019fa111-2222-7333-8444-777777777721",
        "019fa111-2222-7333-8444-777777777722",
    ];
    let fixture = ScanRoot::with_sessions(&[(SESSIONS[0], 4), (SESSIONS[1], 4)]);
    let small = fixture.len(SESSIONS[0]);
    assert_eq!(fixture.len(SESSIONS[1]), small);
    // One full read per page, and a grown file still fits alone.
    let singleton = small + small / 2;
    let cache = Arc::new(SharedCache::default());
    let mut latest = BTreeMap::<String, (u64, u64, u64, u64)>::new();
    let mut record = |scan: &SourceScanResult| {
        for item in &scan.snapshots {
            latest.insert(
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            );
        }
    };
    let waiting = |index: &ScanIndex, path: &Path| {
        index.traversal.as_ref().and_then(|traversal| {
            traversal
                .pending_candidates
                .iter()
                .find(|pending| pending.path == path)
                .map(|pending| (pending.census_member, pending.watcher_hint))
        })
    };
    with_test_limits(2048, singleton, 64, || {
        let (index, scan) = hinted_page(
            &fixture,
            ScanIndex::default(),
            &cache,
            &collected_at(0),
            &[],
        );
        record(&scan);
        assert!(!scan.census_complete, "one file is deferred");
        let [x, y] = if waiting(&index, &fixture.file(SESSIONS[0])).is_some() {
            [SESSIONS[1], SESSIONS[0]]
        } else {
            [SESSIONS[0], SESSIONS[1]]
        };
        let (x_path, y_path) = (fixture.file(x), fixture.file(y));
        assert_eq!(waiting(&index, &y_path), Some((true, false)));
        assert_eq!(waiting(&index, &x_path), None, "X was read");
        let first = census_token(&index).expect("first generation");

        // This test exercises ordinary-page carry. Freshness pages are
        // covered separately; an ordinary page is owed after one of them.
        let mut index = index;
        index.traversal.as_mut().unwrap().codex_freshness_yield = true;
        fixture.append(x, &token_line(5));
        assert!(fixture.len(x) <= singleton);
        cache.clear();
        let (index, scan) = hinted_page(
            &fixture,
            index,
            &cache,
            &collected_at(1),
            std::slice::from_ref(&x_path),
        );
        record(&scan);
        assert!(
            scan.census_complete,
            "the member was read and the census closed: {}",
            counters(&cache)
        );
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != x));
        assert!(counter(&cache, |c| c.deferred_next_generation) >= 1);
        // Carried, not dropped: a member of a new generation, still a hint.
        let second = census_token(&index).expect("the next generation started");
        assert_ne!(second, first);
        assert_eq!(waiting(&index, &x_path), Some((true, true)));
        assert_eq!(waiting(&index, &y_path), None);

        let mut index = index;
        let mut x_reads = 0;
        let mut closed = false;
        for page_number in 2..6 {
            assert_eq!(census_token(&index).as_deref(), Some(second.as_str()));
            let (next, scan) =
                hinted_page(&fixture, index, &cache, &collected_at(page_number), &[]);
            index = next;
            record(&scan);
            x_reads += scan
                .snapshots
                .iter()
                .filter(|item| item.source_session_id == x)
                .count();
            if scan.census_complete {
                closed = true;
                break;
            }
        }
        assert!(closed, "the next generation closed: {}", counters(&cache));
        assert_eq!(x_reads, 1, "read exactly once in the next generation");
        assert_eq!(
            index.files[&local_index_key(&x_path)].size_bytes,
            fixture.len(x)
        );
    });
    let (_, fresh) = page(&fixture, ScanIndex::default(), None);
    let expected = fresh
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(expected.len(), SESSIONS.len());
    assert_eq!(latest, expected);
}

/// Per-session (input, output, cache read, requests) of a fresh, uncached
/// full read of `fixture`.
fn fresh_totals(fixture: &ScanRoot) -> BTreeMap<String, (u64, u64, u64, u64)> {
    let (_, fresh) = page(fixture, ScanIndex::default(), None);
    fresh
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            )
        })
        .collect()
}

/// The (census member, watcher hint) flags of `path` while it is pending.
fn pending_flags(index: &ScanIndex, path: &Path) -> Option<(bool, bool)> {
    index.traversal.as_ref().and_then(|traversal| {
        traversal
            .pending_candidates
            .iter()
            .find(|pending| pending.path == path)
            .map(|pending| (pending.census_member, pending.watcher_hint))
    })
}

/// G1 (review of #751): a re-read cursor job that is not a census member
/// is paused on the page its census closes. `L` was read in the generation
/// as a singleton, then grew past the singleton budget and was hinted with
/// its retained state gone, so its re-read is a non-member cursor job (no
/// K7 fence: no earlier cursor attempt). Page 1 reads the last member and
/// the census closes while that job is paused. The next generation holds
/// `L` as a member; the job resumes there without a restart and publishes
/// exactly once, equal to a fresh full read.
#[test]
fn non_member_job_paused_at_census_close_resumes_in_the_next_generation() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const L: &str = "019fa111-2222-7333-8444-777777777731";
    const M: [&str; 2] = [
        "019fa111-2222-7333-8444-777777777732",
        "019fa111-2222-7333-8444-777777777733",
    ];
    const B: u64 = 2048;
    let fixture = ScanRoot::with_sessions(&[(L, 4), (M[0], 4), (M[1], 4)]);
    let small = fixture.len(L);
    // Two small reads fit one page; the grown `L` never does.
    let singleton = small * 4;
    let l_path = fixture.file(L);
    let l_key = local_index_key(&l_path);
    let cache = Arc::new(SharedCache::default());
    let mut latest = BTreeMap::<String, (u64, u64, u64, u64)>::new();
    let mut record = |scan: &SourceScanResult| {
        let mut l_publications = 0;
        for item in &scan.snapshots {
            l_publications += usize::from(item.source_session_id == L);
            latest.insert(
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            );
        }
        l_publications
    };
    with_test_limits(B, singleton, 64, || {
        // Page 0, two files: `L` and `M0` are read; `M1` waits.
        let (index, scan) = hinted_page_limited(
            &fixture,
            ScanIndex::default(),
            &cache,
            &collected_at(0),
            &[],
            2,
        );
        assert_eq!(record(&scan), 1, "L read as a singleton");
        assert!(!scan.census_complete);
        assert_eq!(
            pending_flags(&index, &fixture.file(M[1])),
            Some((true, false))
        );
        assert_eq!(pending_flags(&index, &l_path), None);
        let first = census_token(&index).expect("first generation");

        for line in 5..65 {
            fixture.append(L, &token_line(line));
        }
        assert!(fixture.len(L) > singleton);
        cache.clear();
        let (index, scan) = hinted_page_limited(
            &fixture,
            index,
            &cache,
            &collected_at(1),
            std::slice::from_ref(&l_path),
            2,
        );
        let mut l_publications = record(&scan);
        assert!(
            scan.census_complete,
            "the last member was read and the census closed: {}",
            counters(&cache)
        );
        assert_eq!(l_publications, 0, "a paused job publishes nothing");
        assert_eq!(counter(&cache, |c| c.jobs_started), 1);
        assert_eq!(
            cache.cursor_job_key().as_deref(),
            Some(l_key.as_str()),
            "the re-read job is paused: {}",
            counters(&cache)
        );
        let second = census_token(&index).expect("the next generation started");
        assert_ne!(second, first);
        assert_eq!(pending_flags(&index, &l_path), Some((true, true)));

        let bound = fixture.len(L).div_ceil(B) + 4;
        let mut index = index;
        let mut page_number = 2;
        while counter(&cache, |c| c.jobs_certified) + counter(&cache, |c| c.jobs_uncertified) == 0
            && page_number < 2 + bound
        {
            let (next, scan) =
                hinted_page_limited(&fixture, index, &cache, &collected_at(page_number), &[], 2);
            index = next;
            l_publications += record(&scan);
            page_number += 1;
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified) + counter(&cache, |c| c.jobs_uncertified),
            1,
            "the job ended within {bound} pages: {}",
            counters(&cache)
        );
        assert_eq!(
            counter(&cache, |c| c.jobs_started),
            1,
            "resumed, never restarted: {}",
            counters(&cache)
        );
        assert_eq!(l_publications, 1, "published exactly once");
        assert_eq!(index.files[&l_key].size_bytes, fixture.len(L));
    });
    assert_eq!(latest, fresh_totals(&fixture));
}

/// G1 (review of #751): a census that closes with a re-read waiting while
/// the sweep is partially settled keeps the old path. Nothing is carried and
/// the unsettled marker stays for the clean follow-up; that walk re-reads the
/// grown file exactly once, and the totals equal a fresh full read.
#[test]
fn unsettled_close_keeps_the_clean_follow_up_and_rereads_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const SESSIONS: [&str; 2] = [
        "019fa111-2222-7333-8444-777777777741",
        "019fa111-2222-7333-8444-777777777742",
    ];
    let fixture = ScanRoot::with_sessions(&[(SESSIONS[0], 4), (SESSIONS[1], 4)]);
    let small = fixture.len(SESSIONS[0]);
    let singleton = small + small / 2;
    let cache = Arc::new(SharedCache::default());
    let mut latest = BTreeMap::<String, (u64, u64, u64, u64)>::new();
    let mut record = |scan: &SourceScanResult, session: &str| {
        let mut publications = 0;
        for item in &scan.snapshots {
            publications += usize::from(item.source_session_id == session);
            latest.insert(
                item.source_session_id.clone(),
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.request_count,
                ),
            );
        }
        publications
    };
    with_test_limits(2048, singleton, 64, || {
        let (index, scan) = hinted_page(
            &fixture,
            ScanIndex::default(),
            &cache,
            &collected_at(0),
            &[],
        );
        assert!(!scan.census_complete, "one file is deferred");
        let [x, y] = if pending_flags(&index, &fixture.file(SESSIONS[0])).is_some() {
            [SESSIONS[1], SESSIONS[0]]
        } else {
            [SESSIONS[0], SESSIONS[1]]
        };
        record(&scan, x);
        let x_path = fixture.file(x);
        assert_eq!(pending_flags(&index, &fixture.file(y)), Some((true, false)));

        // This test exercises ordinary-page carry. Freshness pages are
        // covered separately; an ordinary page is owed after one of them.
        let mut index = index;
        index.traversal.as_mut().unwrap().codex_freshness_yield = true;
        fixture.append(x, &token_line(5));
        assert!(fixture.len(x) <= singleton);
        cache.clear();
        // An earlier page of this sweep settled only partially.
        index.mark_bounded_sweep_unsettled();
        let (index, scan) = hinted_page(
            &fixture,
            index,
            &cache,
            &collected_at(1),
            std::slice::from_ref(&x_path),
        );
        let mut x_publications = record(&scan, x);
        assert!(
            !scan.census_complete,
            "a partially settled sweep owes a clean follow-up"
        );
        assert_eq!(x_publications, 0, "X waited behind the member");
        assert!(counter(&cache, |c| c.deferred_next_generation) >= 1);
        assert!(index.traversal.is_none(), "nothing was carried");
        assert!(index.bounded_sweep_had_unsettled_upload());

        let mut index = index;
        let mut closed = false;
        for page_number in 2..8 {
            let (next, scan) =
                hinted_page(&fixture, index, &cache, &collected_at(page_number), &[]);
            index = next;
            x_publications += record(&scan, x);
            if scan.census_complete {
                closed = true;
                break;
            }
        }
        assert!(closed, "the clean follow-up closed: {}", counters(&cache));
        assert_eq!(x_publications, 1, "the follow-up re-read X once");
        assert!(!index.bounded_sweep_had_unsettled_upload());
        assert_eq!(
            index.files[&local_index_key(&x_path)].size_bytes,
            fixture.len(x)
        );
    });
    assert_eq!(latest, fresh_totals(&fixture));
}

/// §r sizing at the measured event counts. Prints the figures for the PR;
/// asserts only invariants. CI only (heavy; never run on the Mac).
#[test]
fn accumulator_heap_bound_at_measured_event_counts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // (case, token counts or UI events, native items, turns, compactions)
    let cases = [
        (
            "A-3653fb67",
            12_468_usize,
            12_162_usize,
            0_usize,
            109_usize,
            true,
        ),
        ("B-486c5751", 9_990, 6_873, 0, 81, false),
        ("C-af9d28a0", 8_134, 8_174, 0, 53, false),
        ("D-c61fd635", 4_771, 4_783, 1_164, 70, false),
    ];
    // Realistic span (R2-N-B1): events spread over the largest measured
    // session's 265 active usage hours, so usage and activity buckets grow
    // like a long session's instead of sharing one hour.
    const HOURS: usize = 265;
    for (case, first, native, turns, compactions, token_counts) in cases {
        let mut body = codex_line(json!({"timestamp": hour_stamp(0, 0),
            "type": "session_meta", "payload": {"id": SESSION}}));
        let events = first + native + turns + compactions;
        for event in 0..events {
            let stamp = hour_stamp((event * HOURS / events) as u64, 10);
            let line = if event % (events / compactions.max(1)).max(1) == 0
                && event / (events / compactions.max(1)).max(1) < compactions
            {
                codex_line(json!({"timestamp": stamp, "type": "compacted",
                    "payload": {"replacement_history": []}}))
            } else if turns > 0 && event % (events / turns).max(1) == 1 {
                codex_line(json!({"timestamp": stamp, "type": "turn_context",
                    "payload": {"turn_id": format!("turn-{event}"), "model": "fixture-model"}}))
            } else if event % 2 == 0 {
                if token_counts {
                    let n = event as u64 + 1;
                    codex_line(json!({"timestamp": stamp, "type": "event_msg",
                        "payload": {"type": "token_count", "info": {"model": "fixture-model",
                        "total_token_usage": {"input_tokens": n * 100,
                            "cached_input_tokens": n * 50, "output_tokens": n * 10},
                        "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
                            "output_tokens": 10}}}}))
                } else {
                    codex_line(json!({"timestamp": stamp,
                        "type": "event_msg", "payload": {"type": "agent_message",
                        "message": "synthetic"}}))
                }
            } else {
                codex_line(json!({"timestamp": stamp,
                    "type": "response_item", "payload": {"type": "message",
                    "role": "assistant", "content": [{"type": "output_text",
                    "text": "synthetic"}]}}))
            };
            body.extend(line);
        }
        body.extend(codex_line(
            json!({"timestamp": hour_stamp(HOURS as u64, 20),
            "big": "x".repeat(MAX_JSONL_LINE_BYTES + 1)}),
        ));
        let temp = Temp::new("sizing", &body);
        let mut parser = OwnedJsonlParser::new(
            File::open(&temp.0).unwrap(),
            &temp.0,
            SnapshotSource::Codex,
            apply_codex_line,
            Some(&CodexTitleMetadata::default()),
            None,
            None,
            false,
        )
        .unwrap();
        // The pause charge is the completed walk (N3); it must exist.
        let mut peak = None::<usize>;
        let mut first_pause = None::<usize>;
        let mut steps = 0_usize;
        while !parser.step().unwrap() {
            steps += 1;
            if steps % 2_048 == 0 {
                let bound = crate::heap_layout_bound::completed_bound(&parser, usize::MAX);
                assert!(bound.is_some(), "{case}: mid-read completed walk refused");
                first_pause = first_pause.or(bound);
                peak = peak.max(bound);
            }
        }
        let accumulator =
            crate::heap_layout_bound::completed_bound(&parser.accumulator, usize::MAX);
        let walked = crate::heap_layout_bound::completed_bound(&parser, usize::MAX);
        let ordinary = crate::heap_layout_bound::bound(&parser, usize::MAX);
        let buffer = parser.reader.buf.capacity();
        let hours = parser.accumulator.usage_buckets.len();
        eprintln!(
            "CODEX_SIZING case={case} events={events} usage_hours={hours} final_parser={walked:?} \
             ordinary_walk={ordinary:?} peak_parser={peak:?} accumulator={accumulator:?} \
             reader_buffer_capacity={buffer} over_line_cap={}",
            parser.reader.report.over_line_cap_count
        );
        assert_eq!(parser.reader.report.over_line_cap_count, 1);
        let walked = walked.unwrap_or_else(|| panic!("{case}: completed parser walk refused"));
        let accumulator =
            accumulator.unwrap_or_else(|| panic!("{case}: completed accumulator walk refused"));
        // The paused charge walks the reader buffer with the accumulator.
        assert!(walked >= accumulator.saturating_add(buffer));
        assert!(
            walked <= STATE_BYTES,
            "{case}: {walked} exceeds STATE_BYTES"
        );
        let (first, peak) = first_pause.zip(peak).expect("the read paused");
        assert!(peak >= first);
    }
}

/// R1-H1 (#630 review): a hold an append may cure is memoized on the held
/// file's exact stamp only when the job's read reached the file's end.
/// Bytes appended past the frozen extent may already cure it, so the job
/// keeps no hold offset (no memo entry) and its next attempt reads them.
#[test]
fn growth_curable_hold_is_not_anchored_past_unread_bytes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // #635: the created thread held as `AmbiguousFork` too. R2-L3: an
    // ordinary fork (not a created thread) is not growth-curable, so its
    // anchor survives the append.
    for (grow, fork, created) in [
        (false, false, true),
        (true, false, true),
        (false, true, true),
        (true, true, true),
        (true, true, false),
    ] {
        let fixture = ScanRoot::new(40);
        let cache = Arc::new(SharedCache::default());
        let hold = with_test_limits(2048, 4096, 64, || {
            let mut index = ScanIndex::default();
            for _ in 0..64 {
                let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
                index = next;
                if counter(&cache, |c| c.jobs_paused) > 0 {
                    break;
                }
            }
            let mut job = cache
                .with_cursor(
                    |cursor| match std::mem::replace(&mut cursor.slot, Slot::Empty) {
                        Slot::Paused(job) => Some(job),
                        _ => None,
                    },
                )
                .flatten()
                .expect("a paused job");
            while !job.parser.step().unwrap() {}
            // A parentless created thread held for a missing sidecar
            // projection: an append may cure it. The classifier sets
            // `codex_created_thread_native_only` with either boundary (B1).
            let accumulator = &mut job.parser.accumulator;
            accumulator.codex_created_thread_native_only = created;
            accumulator.codex_ownership_boundary = if fork {
                CodexOwnershipBoundary::AmbiguousFork
            } else {
                CodexOwnershipBoundary::NativeCreatedThread
            };
            accumulator.codex_sidecar_created_thread = created;
            accumulator.codex_parent_session_ref = None;
            accumulator.codex_sidecar_projected_next_ordinal = None;
            assert_eq!(growth_may_cure(&job.parser.accumulator), created);
            job.hold_offset = Some(job.parser.reader.last_complete_line_end());
            if grow {
                fixture.append(SESSION, &token_line(41));
            }
            let _ = finish_job(&cache, None, &mut job, None, "legacy", "", true);
            job.hold_offset
        });
        assert_eq!(
            hold.is_some(),
            !grow || !created,
            "grow: {grow}, fork: {fork}, created: {created}"
        );
    }
}

/// R1-L1 / class 7 (NC4, NC5): the sidecar fingerprint and the memo digest
/// carry the set of the path's conflicted candidate ids, not their count. A
/// conflict moving between two candidates at an equal count changes both
/// (NC4); a conflict appearing changes the digest too, so an ordinary fork's
/// entry, which has no sidecar wake, misses (NC5).
#[test]
fn memo_wakes_on_the_conflicted_identity_set() {
    // A timestamp-shaped name has two candidate ids: the whole raw stem
    // (legacy grammar) and the trailing session id (current grammar).
    let path = PathBuf::from(format!(
        "/synthetic/sessions/rollout-2026-10-07T10-00-00-{SESSION}.jsonl"
    ));
    let candidates = codex_session_id_candidates_from_path(&path);
    assert_eq!(candidates.len(), 2, "{candidates:?}");
    let (a, b) = (candidates[0].as_str(), candidates[1].as_str());
    // Both candidates carry identity evidence, so the path resolves to
    // neither and the sidecar facts are the same for {a} and {b}: only the
    // conflicted set tells them apart.
    let evidenced = || {
        let mut codex = CodexTitleMetadata::default();
        for id in [a, b] {
            codex.rollout_extents.insert(
                id.into(),
                CodexRolloutExtent {
                    next_byte_offset: 8,
                    next_ordinal: 1,
                },
            );
        }
        codex
    };
    let with_conflict = |id: &str| {
        let mut codex = evidenced();
        codex.identity_conflicts.insert(id.into());
        codex
    };
    let (on_a, on_b) = (with_conflict(a), with_conflict(b));
    let none = evidenced();
    assert_ne!(
        sidecar_fingerprint(&on_a, &path),
        sidecar_fingerprint(&on_b, &path)
    );
    assert_ne!(
        sidecar_fingerprint(&none, &path),
        sidecar_fingerprint(&on_a, &path)
    );
    let temp = Temp::new("memo-conflict-digest", b"{\"n\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/sessions"),
        path: path.clone(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "revision".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    let digest = |codex: &CodexTitleMetadata| {
        memo_digest(
            &ScanIndex::default(),
            &candidate,
            &file,
            "dependencies",
            codex,
            1,
            "counting",
        )
        .unwrap()
    };
    assert_ne!(digest(&on_a), digest(&on_b));
    assert_ne!(digest(&none), digest(&on_a));
    // NC6 (R1-L1): a path with no rollout id is identity-ambiguous exactly
    // while the state census holds any created thread; both wake inputs
    // carry that bit.
    let orphan = PathBuf::from("/synthetic/sessions/orphan.jsonl");
    assert!(codex_session_id_candidates_from_path(&orphan).is_empty());
    let no_created = CodexTitleMetadata::default();
    let mut created = CodexTitleMetadata::default();
    created.state_created_threads.insert(SESSION.into());
    let orphan_candidate = CandidateFile {
        physical_identity: None,
        path: orphan.clone(),
        ..candidate.clone()
    };
    let orphan_digest = |codex: &CodexTitleMetadata| {
        memo_digest(
            &ScanIndex::default(),
            &orphan_candidate,
            &file,
            "dependencies",
            codex,
            1,
            "counting",
        )
        .unwrap()
    };
    assert_ne!(orphan_digest(&created), orphan_digest(&no_created));
    assert_ne!(
        sidecar_fingerprint(&created, &orphan),
        sidecar_fingerprint(&no_created, &orphan)
    );
    assert_eq!(digest(&on_a), digest(&with_conflict(a)));
}

const CREATED: &str = "01a04e15-49cf-7460-9fd7-f7dbfd2f05e4";
const FORK_SOURCE: &str = "01a02589-5e24-7f10-8a93-a0c1968d8a3a";
const SPAWN_PARENT: &str = "01a0c0de-5e24-7f10-8a93-a0c1968d8a3a";

/// A Codex home with one state-declared created thread (no lineage, its
/// rollout path, created now) and a thread-history projection of the FULL
/// body (`body`, 10 records). The rollout holds `written` records: a
/// projection ahead of the flushed file. The shape is
/// `codex_created_thread_parentless_production_lineage_controls`' admitted
/// thread (Σ last = 200 input over 3 requests); `fork` adds a
/// `forked_from_id` (copied-history evidence that keeps it held).
struct CreatedThreadHome {
    // These lineage controls count Legacy: their owning header predates this epoch.
    _cutover: codex_counting_version::TestCutover,
    fixture: ScanRoot,
    path: PathBuf,
    body: Vec<Vec<u8>>,
    base_ms: i64,
}

impl CreatedThreadHome {
    fn new(written: usize, fork: bool) -> Self {
        Self::with_lineage(written, fork, "agent_created_thread", None)
    }

    /// `new` with the state row's `thread_source` (anything but
    /// `agent_created_thread` leaves the thread declared by its rollout
    /// header only) and an optional `thread_spawn_edges` parent.
    fn with_lineage(
        written: usize,
        fork: bool,
        state_source: &str,
        spawn_parent: Option<&str>,
    ) -> Self {
        let fixture = ScanRoot::with_sessions(&[]);
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let base_ms = now - now % 1_000;
        let at = |offset: i64| bounded_rfc3339_millis(base_ms + offset).unwrap();
        let second = |offset: i64| u64::try_from(base_ms / 1_000 + offset).unwrap();
        let turn = |n: u64| format!("{}-5000-7000-8000-{n:012}", &CREATED[..8]);
        let usage = |(input, cached, output, reasoning): (u64, u64, u64, u64)| {
            json!({"input_tokens": input, "cached_input_tokens": cached,
                "output_tokens": output, "reasoning_output_tokens": reasoning})
        };
        let tokens = |offset: i64, total, last| {
            json!({"timestamp": at(offset), "type": "event_msg", "payload": {
                "type": "token_count", "info": {"total_token_usage": usage(total),
                "last_token_usage": usage(last), "model": "gpt-5.6-sol"}}})
        };
        let mut meta = json!({"id": CREATED, "session_id": CREATED, "timestamp": at(0),
            "history_mode": "paginated", "thread_source": "agent_created_thread",
            "source": "vscode", "originator": "Codex Desktop",
            "creator_user_id": "synthetic-user", "creator_account_id": "synthetic-workspace"});
        if fork {
            meta["forked_from_id"] = json!(FORK_SOURCE);
        }
        let values = [
            json!({"timestamp": at(500), "type": "session_meta", "payload": meta}),
            json!({"timestamp": at(501), "type": "event_msg", "payload": {"type": "task_started",
                "turn_id": turn(1), "started_at": second(0),
                "trace_id": "0123456789abcdef0123456789abcdef"}}),
            json!({"timestamp": at(1_000), "type": "turn_context",
                "payload": {"turn_id": turn(1), "model": "gpt-5.6-sol"}}),
            tokens(2_000, (120, 100, 6, 2), (120, 100, 6, 2)),
            json!({"timestamp": at(3_000), "type": "compacted",
                "payload": {"replacement_history": []}}),
            json!({"timestamp": at(3_500), "type": "event_msg",
                "payload": {"type": "task_complete", "turn_id": turn(1)}}),
            json!({"timestamp": at(4_000), "type": "event_msg", "payload": {"type": "task_started",
                "turn_id": turn(2), "started_at": second(4)}}),
            json!({"timestamp": at(4_100), "type": "turn_context",
                "payload": {"turn_id": turn(2), "model": "gpt-5.6-sol"}}),
            tokens(5_000, (50, 40, 3, 1), (50, 40, 3, 1)),
            tokens(6_000, (80, 60, 5, 1), (30, 20, 2, 0)),
        ];
        let body = values
            .into_iter()
            .zip(0_u64..)
            .map(|(mut value, ordinal)| {
                value["ordinal"] = json!(ordinal);
                codex_line(value)
            })
            .collect::<Vec<_>>();
        let path = fixture.root.join(format!("rollout-{CREATED}.jsonl"));
        fs::write(&path, body[..written].concat()).unwrap();
        let home = Self {
            _cutover: codex_counting_version::TestCutover::set(base_ms + 1),
            fixture,
            path,
            body,
            base_ms,
        };
        let state = rusqlite::Connection::open(home.codex().join("state_5.sqlite")).unwrap();
        state
            .execute_batch(
                "CREATE TABLE threads (\
                    id TEXT NOT NULL, title TEXT, tokens_used INTEGER NOT NULL,\
                    thread_source TEXT, first_user_message TEXT, created_at_ms INTEGER,\
                    rollout_path TEXT\
                );\
                CREATE TABLE thread_spawn_edges (\
                    parent_thread_id TEXT NOT NULL, child_thread_id TEXT NOT NULL\
                );",
            )
            .unwrap();
        state
            .execute(
                "INSERT INTO threads VALUES \
                    (?1, 'Thread', 1, ?4, 'Build the weekly report', ?2, ?3)",
                rusqlite::params![
                    CREATED,
                    home.base_ms,
                    home.path.to_string_lossy().into_owned(),
                    state_source
                ],
            )
            .unwrap();
        if let Some(parent) = spawn_parent {
            state
                .execute(
                    "INSERT INTO thread_spawn_edges VALUES (?1, ?2)",
                    rusqlite::params![parent, CREATED],
                )
                .unwrap();
        }
        let full = home.body.iter().map(Vec::len).sum::<usize>();
        home.project(full, home.body.len());
        home
    }

    /// Bytes of the first `records` body records.
    fn bytes(&self, records: usize) -> usize {
        self.body[..records].iter().map(Vec::len).sum()
    }

    fn codex(&self) -> PathBuf {
        self.fixture.root.parent().unwrap().to_path_buf()
    }

    /// Replace the thread-history projection (the sidecar's rollout extent).
    fn project(&self, bytes: usize, ordinals: usize) {
        let history =
            rusqlite::Connection::open(self.codex().join("thread_history_1.sqlite")).unwrap();
        history
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS thread_history_projection_state (\
                    thread_id TEXT NOT NULL, next_rollout_byte_offset INTEGER NOT NULL,\
                    next_rollout_ordinal INTEGER NOT NULL\
                );\
                DELETE FROM thread_history_projection_state;",
            )
            .unwrap();
        history
            .execute(
                "INSERT INTO thread_history_projection_state VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    CREATED,
                    i64::try_from(bytes).unwrap(),
                    i64::try_from(ordinals).unwrap()
                ],
            )
            .unwrap();
    }

    /// Append records `from..` of the body (the flush catching up).
    fn flush_from(&self, from: usize) {
        let mut file = OpenOptions::new().append(true).open(&self.path).unwrap();
        file.write_all(&self.body[from..].concat()).unwrap();
    }

    /// One page of a new census generation `n` (a later window).
    fn generation(
        &self,
        index: ScanIndex,
        cache: &Arc<SharedCache>,
        n: i64,
    ) -> (ScanIndex, SourceScanResult) {
        let mut index = index;
        index.traversal = None;
        let collected = bounded_rfc3339_millis(self.base_ms + 3_600_000 + n * 1_000).unwrap();
        let (index, scan, _) = page_at(
            &self.fixture,
            index,
            Some(Arc::clone(cache)),
            "cursor-fixture",
            &collected,
        );
        (index, scan)
    }
}

/// The created thread's published usage: (input, requests) per snapshot.
fn created_usage(scan: &SourceScanResult) -> Vec<(u64, u64)> {
    scan.snapshots
        .iter()
        .filter(|snapshot| snapshot.source_session_id == CREATED)
        .map(|snapshot| (snapshot.input_tokens, snapshot.request_count))
        .collect()
}

/// #635 (a), #631 review L1: a projection ahead of the flushed rollout holds
/// the created thread as `AmbiguousFork`. A usage-free prefix (header, first
/// task and turn context, flushed before the first `token_count`) is
/// memoized on its exact stamp.
/// While unchanged it is a memo hit (not re-read); once the append that
/// cures it lands, the next generation reads the appended bytes and admits
/// the thread once, with its full usage. An unchanged generation after
/// that publishes nothing new: no second admission, no resurrected hold.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn projection_ahead_created_thread_memo_misses_on_the_curing_append() {
    let home = CreatedThreadHome::new(3, false);
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    // Unchanged: the exact stamp hits; the file is not read.
    let (index, skipped) = home.generation(index, &cache, 1);
    assert!(created_usage(&skipped).is_empty());
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    // The flush catches up with the projection: no stale hit.
    home.flush_from(3);
    let (index, cured) = home.generation(index, &cache, 2);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_eq!(
        created_usage(&cured),
        vec![(200, 3)],
        "{}",
        counters(&cache)
    );
    assert_admitted_once(&home, &cache, index, &cured, 3);
}

/// Fingerprints of the created thread's published snapshots.
fn created_fingerprints(scan: &SourceScanResult) -> Vec<String> {
    scan.snapshots
        .iter()
        .filter(|snapshot| snapshot.source_session_id == CREATED)
        .map(|snapshot| snapshot.snapshot_fingerprint.clone())
        .collect()
}

/// R1-L2: the admitting generation's `index` no longer blocks the thread,
/// and generation `n` after it, with nothing changed, admits nothing new and
/// re-holds nothing. It publishes nothing, or republishes the same snapshots
/// (same fingerprints, so idempotent); its index still does not block the
/// thread (a re-hold re-inserts it); and the stale hold entry neither hits
/// nor is recorded again.
fn assert_admitted_once(
    home: &CreatedThreadHome,
    cache: &Arc<SharedCache>,
    index: ScanIndex,
    admitted: &SourceScanResult,
    n: i64,
) {
    let (hits, records) = (
        counter(cache, |c| c.memo_hits),
        counter(cache, |c| c.memo_records),
    );
    assert!(
        !index.codex_state_only_blocked_session_ids.contains(CREATED),
        "admitted: {}",
        counters(cache)
    );
    let (index, again) = home.generation(index, cache, n);
    assert!(
        !index.codex_state_only_blocked_session_ids.contains(CREATED),
        "no resurrected hold: {}",
        counters(cache)
    );
    let usage = created_usage(&again);
    assert!(
        usage.is_empty()
            || (usage == created_usage(admitted)
                && created_fingerprints(&again) == created_fingerprints(admitted)),
        "no second admission: {usage:?} {}",
        counters(cache)
    );
    assert_eq!(counter(cache, |c| c.memo_hits), hits, "{}", counters(cache));
    assert_eq!(
        counter(cache, |c| c.memo_records),
        records,
        "{}",
        counters(cache)
    );
}

/// #635 (b): the same hold wakes on its sidecar. A projection change is a
/// memo miss: the file is re-read (still ahead, so held and memoized again)
/// and the new entry hits while unchanged.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn projection_ahead_created_thread_memo_wakes_on_projection_change() {
    let home = CreatedThreadHome::new(3, false);
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    home.project(home.bytes(9), 9);
    let (index, woken) = home.generation(index, &cache, 1);
    assert!(created_usage(&woken).is_empty());
    assert_eq!(counter(&cache, |c| c.memo_hits), 0, "{}", counters(&cache));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        2,
        "re-read: {}",
        counters(&cache)
    );
    let (_, unchanged) = home.generation(index, &cache, 2);
    assert!(created_usage(&unchanged).is_empty());
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
}

/// #635 R2-L2: a lagging projection catches up with an unchanged file. The
/// file is ahead of its projection, so the sidecar binds nothing and the
/// created thread is held as `AmbiguousFork`. It holds usage and is
/// memoized (PR-1's wider gate); the projection change misses it, the
/// change alone cures it, and the thread is admitted once with its full
/// usage.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn lagging_projection_catching_up_cures_an_unchanged_created_thread() {
    let home = CreatedThreadHome::new(10, false);
    home.project(home.bytes(9), 9);
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    home.project(home.bytes(10), 10);
    let (index, cured) = home.generation(index, &cache, 1);
    assert_eq!(
        created_usage(&cured),
        vec![(200, 3)],
        "{}",
        counters(&cache)
    );
    assert_eq!(counter(&cache, |c| c.memo_hits), 0, "{}", counters(&cache));
    assert_admitted_once(&home, &cache, index, &cured, 2);
}

/// #635 (c), negative control: a created thread with copied-history evidence
/// (`forked_from_id`, no trusted parent) is a true fork. Its unchanged stamp
/// hits; growth re-reads it, and once the projection binds the grown file it
/// stays held (no admission), memoized again and hit again while unchanged.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn created_thread_fork_stays_held_after_growth_and_still_memo_hits() {
    let home = CreatedThreadHome::new(2, true);
    home.project(home.bytes(3), 3);
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    let (index, _) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    // The turn context flushes: the file now matches its projection.
    let mut file = OpenOptions::new().append(true).open(&home.path).unwrap();
    file.write_all(&home.body[2]).unwrap();
    let (index, grown) = home.generation(index, &cache, 2);
    assert!(
        created_usage(&grown).is_empty(),
        "still held: {}",
        counters(&cache)
    );
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        1,
        "re-read: {}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        2,
        "{}",
        counters(&cache)
    );
    let (_, unchanged) = home.generation(index, &cache, 3);
    assert!(created_usage(&unchanged).is_empty());
    assert_eq!(counter(&cache, |c| c.memo_hits), 2, "{}", counters(&cache));
}

impl CreatedThreadHome {
    /// The same generation `n` scanned cold (fresh index and cache): what a
    /// full parse of the current files and sidecar publishes and blocks.
    fn oracle(&self, n: i64) -> (ScanIndex, SourceScanResult) {
        self.generation(ScanIndex::default(), &Arc::new(SharedCache::default()), n)
    }

    /// The created thread's memo entry, if any.
    fn memo_entry(&self, cache: &SharedCache) -> Option<MemoEntry> {
        let scope = Scope("cursor-fixture".into());
        [self.path.clone(), fs::canonicalize(&self.path).unwrap()]
            .iter()
            .find_map(|path| cache.memo_lookup(&memo_key(&scope, &local_index_key(path))))
    }
}

/// What a generation discloses about held files: the per-file loss and
/// residue counts the scan result exposes, and the index's full state-only
/// blocked set (R2-M1).
fn census(
    index: &ScanIndex,
    scan: &SourceScanResult,
) -> (Vec<(&'static str, u64)>, BTreeSet<String>) {
    let counts = vec![
        (
            "ownership_incomplete",
            scan.ownership_incomplete_file_count as u64,
        ),
        (
            "terminal_ownership_incomplete",
            scan.terminal_ownership_incomplete_file_count as u64,
        ),
        (
            "zero_snapshot_usage_evidence",
            scan.zero_snapshot_usage_evidence_count as u64,
        ),
        (
            "recognized_usage_drop",
            scan.recognized_usage_drop_count as u64,
        ),
        ("dropped_usage_record", scan.dropped_usage_record_count),
        (
            "residue_index_keys",
            scan.census_residue_index_key_count as u64,
        ),
        (
            "residue_blocked_sessions",
            scan.census_residue_blocked_session_count as u64,
        ),
    ];
    (counts, index.codex_state_only_blocked_session_ids.clone())
}

/// A warm generation, memo hit or miss, discloses exactly what a cold full
/// parse of the same files and sidecar does, and, with `usage`, publishes
/// the same created-thread usage. `usage` is false only where the warm scan
/// legitimately skips an unchanged admitted file that a cold scan publishes.
///
/// `sticky` names sessions the warm index still blocks although a cold parse
/// does not: the index drops a state-only block only when the session
/// publishes a snapshot, so a usage-free cure leaves it (pre-existing index
/// rule, not memo state). Each must be warm-only; every other id matches.
fn assert_oracle(
    home: &CreatedThreadHome,
    cache: &SharedCache,
    index: &ScanIndex,
    scan: &SourceScanResult,
    n: i64,
    usage: bool,
    sticky: &[&str],
) {
    let (oracle_index, oracle) = home.oracle(n);
    let (counts, mut blocked) = census(index, scan);
    let (oracle_counts, oracle_blocked) = census(&oracle_index, &oracle);
    for id in sticky {
        assert!(
            blocked.remove(*id) && !oracle_blocked.contains(*id),
            "generation {n}: {id} sticky: {}",
            counters(cache)
        );
    }
    assert_eq!(
        (counts, blocked),
        (oracle_counts, oracle_blocked),
        "generation {n}: {}",
        counters(cache)
    );
    if usage {
        assert_eq!(
            created_usage(scan),
            created_usage(&oracle),
            "generation {n}: {}",
            counters(cache)
        );
    }
}

/// B1 (N1a, R1's failing case): a thread declared created by its rollout
/// header only (the state row says `user`), with a spawn-edge parent and a
/// projection ahead of the flushed file. The bind refuses the mismatched
/// extent, so no trusted parent binds, the parentless proof needs the state
/// flag, and the header is held as `AmbiguousFork`. The append that brings
/// the file to its extent binds the parent and cures it: the memo must miss
/// (exact stamp), and the thread is admitted once, exactly as a cold parse.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn rollout_declared_created_thread_memo_misses_on_the_curing_append() {
    let home = CreatedThreadHome::with_lineage(3, false, "user", Some(SPAWN_PARENT));
    let cache = Arc::new(SharedCache::default());
    let (mut index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(held.ownership_incomplete_file_count, 1);
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &held, 0, true, &[]);
    // NC1: unchanged, the hold stays quiet: two exact-stamp hits, each
    // disclosing what a cold parse does.
    for n in 1..=2 {
        let (next, quiet) = home.generation(index, &cache, n);
        assert_eq!(
            counter(&cache, |c| c.memo_hits),
            u64::try_from(n).unwrap(),
            "{}",
            counters(&cache)
        );
        assert_oracle(&home, &cache, &next, &quiet, n, true, &[]);
        index = next;
    }
    home.flush_from(3);
    let (index, cured) = home.generation(index, &cache, 3);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        2,
        "no stale hit: {}",
        counters(&cache)
    );
    assert_eq!(
        created_usage(&cured),
        vec![(200, 3)],
        "admitted: {}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &cured, 3, true, &[]);
    assert_admitted_once(&home, &cache, index, &cured, 4);
}

/// B1 (N1b): the same rollout-declared hold on an unchanged file, cured by
/// the projection catching up with it. The entry wakes on its sidecar (a
/// miss), and the re-read binds the spawn parent: the usage-free thread is
/// no longer ownership-incomplete, exactly as a cold parse.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn rollout_declared_created_thread_memo_wakes_on_extent_update() {
    let home = CreatedThreadHome::with_lineage(3, false, "user", Some(SPAWN_PARENT));
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert_eq!(held.ownership_incomplete_file_count, 1);
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &held, 0, true, &[]);
    home.project(home.bytes(3), 3);
    let (index, woken) = home.generation(index, &cache, 1);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        0,
        "no stale hit: {}",
        counters(&cache)
    );
    // The cure, not only the wake: the re-read finds the thread complete
    // (no longer ownership-incomplete) and records no new hold. It stays in
    // the state-only blocked set, as a complete usage-free created thread
    // (a fork) does on a cold parse too; `assert_oracle` compares that set.
    assert_eq!(
        woken.ownership_incomplete_file_count,
        0,
        "{}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "cured, not re-held: {}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &woken, 1, true, &[]);
}

/// B1 second symptom (N1c): a state-declared created thread whose sidecar
/// binds a spawn parent that contradicts its header's `forked_from_id` is
/// held as `AmbiguousFork` with the bound parent as its ref. Growth past the
/// projected extent undoes the bind, so a fresh parse has no parent ref:
/// the entry must miss on growth, and the re-recorded entry carries the
/// fresh parse's ref (none), not the stale bound one. The index's parent
/// refs are insert-only until a reset, so the memo entry, not the index, is
/// where the fresh ref is observable.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn bound_created_thread_fork_memo_misses_on_growth_and_drops_the_bound_parent() {
    let home = CreatedThreadHome::with_lineage(2, true, "agent_created_thread", Some(SPAWN_PARENT));
    home.project(home.bytes(2), 2);
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &held, 0, true, &[]);
    let entry = home.memo_entry(&cache).expect("recorded entry");
    assert_eq!(entry.parent_ref(), Some(SPAWN_PARENT));
    let (index, quiet) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_oracle(&home, &cache, &index, &quiet, 1, true, &[]);
    // The turn context flushes past the projection: the bind no longer
    // matches the file.
    let mut file = OpenOptions::new().append(true).open(&home.path).unwrap();
    file.write_all(&home.body[2]).unwrap();
    let (index, grown) = home.generation(index, &cache, 2);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        1,
        "no stale hit: {}",
        counters(&cache)
    );
    assert!(created_usage(&grown).is_empty(), "{}", counters(&cache));
    assert_oracle(&home, &cache, &index, &grown, 2, true, &[]);
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        2,
        "re-read and re-recorded: {}",
        counters(&cache)
    );
    let entry = home.memo_entry(&cache).expect("re-recorded entry");
    assert_eq!(entry.parent_ref(), None);
    let (index, unchanged) = home.generation(index, &cache, 3);
    assert!(created_usage(&unchanged).is_empty());
    assert_eq!(counter(&cache, |c| c.memo_hits), 2, "{}", counters(&cache));
    assert_oracle(&home, &cache, &index, &unchanged, 3, true, &[]);
}

const ORPHAN: &str = "01a0dead-49cf-7460-9fd7-f7dbfd2f05e4";

/// R1-L1 (NC6): a rollout whose file name carries no rollout id is
/// identity-ambiguous exactly while the state census holds any created
/// thread, so it is held as `AmbiguousFork` and memoized, and its only wake
/// input for that fact is the candidate-less term of the conflicted-id set.
/// Once the last created thread leaves the state census, the entry misses
/// and the ordinary session is admitted, exactly as a cold parse.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn candidate_less_hold_memo_misses_when_the_last_created_thread_goes() {
    // The created thread itself is complete and admitted; until the state
    // census drops it, it records no memo entry, so every memo counter
    // before that is the orphan's.
    let home = CreatedThreadHome::new(10, false);
    let at = |offset: i64| bounded_rfc3339_millis(home.base_ms + offset).unwrap();
    let orphan = [
        json!({"timestamp": at(500), "type": "session_meta", "payload": {
            "id": ORPHAN, "session_id": ORPHAN, "timestamp": at(0),
            "source": "vscode", "originator": "Codex Desktop"}}),
        json!({"timestamp": at(1_000), "type": "turn_context",
            "payload": {"turn_id": "orphan-turn-1", "model": "gpt-5.6-sol"}}),
    ];
    fs::write(
        home.fixture.root.join("orphan.jsonl"),
        orphan
            .into_iter()
            .map(codex_line)
            .collect::<Vec<_>>()
            .concat(),
    )
    .unwrap();
    assert!(
        codex_session_id_candidates_from_path(&home.fixture.root.join("orphan.jsonl")).is_empty()
    );
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert_eq!(created_usage(&held), vec![(200, 3)], "{}", counters(&cache));
    assert_eq!(
        held.ownership_incomplete_file_count,
        1,
        "{}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &held, 0, true, &[]);
    // Unchanged: the orphan hits; the admitted created thread is skipped,
    // which a cold scan republishes, so only the census is compared.
    let (index, quiet) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_oracle(&home, &cache, &index, &quiet, 1, false, &[]);
    // The state census no longer holds any created thread.
    rusqlite::Connection::open(home.codex().join("state_5.sqlite"))
        .unwrap()
        .execute(
            "UPDATE threads SET thread_source = 'user' WHERE id = ?1",
            rusqlite::params![CREATED],
        )
        .unwrap();
    let (index, cured) = home.generation(index, &cache, 2);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        1,
        "no stale hit: {}",
        counters(&cache)
    );
    // Not held again: the miss re-read the orphan as an ordinary session,
    // and its entry is gone. PR-1: the created thread, no longer declared by
    // the state census, is held with usage, which the wider gate memoizes:
    // the one new record is its entry.
    let scope = Scope("cursor-fixture".into());
    let orphan = home.fixture.root.join("orphan.jsonl");
    assert!(
        [orphan.clone(), fs::canonicalize(&orphan).unwrap()]
            .iter()
            .all(|path| cache
                .memo_lookup(&memo_key(&scope, &local_index_key(path)))
                .is_none()),
        "{}",
        counters(&cache)
    );
    assert!(home.memo_entry(&cache).is_some(), "{}", counters(&cache));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        2,
        "{}",
        counters(&cache)
    );
    // SB-T1 (L-SB): its usage-free cure publishes nothing, but the re-read
    // no longer blocks it and no other key holds it, so the warm index
    // releases it, as a cold parse never sets it.
    assert!(!index.codex_state_only_blocked_session_ids.contains(ORPHAN));
    assert_oracle(&home, &cache, &index, &cured, 2, true, &[]);
}

/// Every census count a held file's fresh parse adds and a memo hit replays
/// (C-4), plus `scanned_session_count`.
fn replayed_census(scan: &SourceScanResult) -> Vec<(&'static str, u64)> {
    vec![
        ("over_line_cap", scan.over_line_cap_count as u64),
        (
            "recognized_usage_drop",
            scan.recognized_usage_drop_count as u64,
        ),
        ("dropped_usage_record", scan.dropped_usage_record_count),
        (
            "ownership_incomplete",
            scan.ownership_incomplete_file_count as u64,
        ),
        (
            "zero_snapshot_usage_evidence",
            scan.zero_snapshot_usage_evidence_count as u64,
        ),
        (
            "terminal_over_line_cap",
            scan.terminal_over_line_cap_count as u64,
        ),
        (
            "terminal_recognized_usage_drop",
            scan.terminal_recognized_usage_drop_count as u64,
        ),
        (
            "terminal_dropped_usage_record",
            scan.terminal_dropped_usage_record_count,
        ),
        ("malformed_json_line", scan.malformed_json_line_count as u64),
        ("scanned_session", scan.scanned_session_count as u64),
        (
            "residue_index_keys",
            scan.census_residue_index_key_count as u64,
        ),
        (
            "residue_blocked_sessions",
            scan.census_residue_blocked_session_count as u64,
        ),
    ]
}

/// The memo key the fixture's held file is stored under.
fn stored_memo_key(home: &CreatedThreadHome, cache: &SharedCache) -> String {
    let scope = Scope("cursor-fixture".into());
    [home.path.clone(), fs::canonicalize(&home.path).unwrap()]
        .iter()
        .map(|path| memo_key(&scope, &local_index_key(path)))
        .find(|key| cache.memo_lookup(key).is_some())
        .expect("stored entry")
}

/// PR-1 replay and gate. A usage-bearing held fork (the full body with
/// `forked_from_id` and no trusted parent) is now memoized.
/// - T1/C-T3: an unchanged generation hits at zero transcript bytes and
///   discloses exactly what a cold full parse does: every replayed census
///   count, `scanned_session_count` and the blocked set. The before-parse
///   seam never runs for a hit.
/// - T20 (R1-M1): an entry forced to `own_ledger(true)` for an owed parent
///   is bypassed (counted `memo_miss_other`) and the file is parsed again.
/// - T18: growth with every other input unchanged is counted as an
///   exact-stamp miss with the grown extent, then re-read equal to cold.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn usage_bearing_fork_hold_memo_hit_replays_the_fresh_census() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = CreatedThreadHome::new(10, true);
    let cache = Arc::new(SharedCache::default());
    let parsed = std::rc::Rc::new(std::cell::RefCell::new(Vec::<PathBuf>::new()));
    let hook = {
        let parsed = std::rc::Rc::clone(&parsed);
        move |path: &Path| parsed.borrow_mut().push(path.to_path_buf())
    };
    let (index, held) = crate::snapshots::with_codex_before_parse(hook.clone(), || {
        home.generation(ScanIndex::default(), &cache, 0)
    });
    assert_eq!(parsed.borrow().len(), 1, "{}", counters(&cache));
    assert!(created_usage(&held).is_empty(), "{}", counters(&cache));
    assert!(held.recognized_usage_drop_count > 0, "usage-bearing hold");
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    assert_eq!(replayed_census(&held), replayed_census(&home.oracle(0).1));
    assert_oracle(&home, &cache, &index, &held, 0, true, &[]);

    let ((index, quiet), counts) = codex_memo_lifecycle::observe(|| {
        crate::snapshots::with_codex_before_parse(hook.clone(), || {
            home.generation(index, &cache, 1)
        })
    });
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_eq!(parsed.borrow().len(), 1, "a hit is never parsed");
    assert_eq!(
        counts.memo_hit_estimated_avoided_parser_bytes,
        fs::metadata(&home.path).unwrap().len()
    );
    assert_eq!(replayed_census(&quiet), replayed_census(&home.oracle(1).1));
    assert_oracle(&home, &cache, &index, &quiet, 1, true, &[]);

    // T20: the owed-parent bypass.
    let key = stored_memo_key(&home, &cache);
    let forced = cache.memo_lookup(&key).unwrap().own_ledger(true);
    assert!(forced.has_own_ledger());
    cache.memo_record(key.clone(), forced);
    let mut index = index;
    index.codex_parent_ownership_refs.insert(CREATED.to_owned());
    let records = counter(&cache, |c| c.memo_records);
    let ((mut index, _), counts) = codex_memo_lifecycle::observe(|| {
        crate::snapshots::with_codex_before_parse(hook.clone(), || {
            home.generation(index, &cache, 2)
        })
    });
    assert_eq!(counts.memo_miss_other, 1, "{counts:?}");
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_eq!(parsed.borrow().len(), 2, "bypassed: parsed again");
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        records + 1,
        "{}",
        counters(&cache)
    );
    assert!(!cache.memo_lookup(&key).unwrap().has_own_ledger());
    index.codex_parent_ownership_refs.remove(CREATED);

    // T18: growth alone.
    let extra = codex_line(json!({
        "timestamp": bounded_rfc3339_millis(home.base_ms + 7_000).unwrap(),
        "type": "turn_context",
        "payload": {"turn_id": "grown-turn", "model": "gpt-5.6-sol"},
        "ordinal": 10,
    }));
    OpenOptions::new()
        .append(true)
        .open(&home.path)
        .unwrap()
        .write_all(&extra)
        .unwrap();
    let ((index, grown), counts) =
        codex_memo_lifecycle::observe(|| home.generation(index, &cache, 3));
    assert_eq!(
        (
            counts.memo_miss_exact_stamp,
            counts.memo_miss_exact_stamp_bytes,
            counts.memo_miss_other,
            counts.memo_hit_estimated_avoided_parser_bytes,
        ),
        (1, fs::metadata(&home.path).unwrap().len(), 0, 0),
        "{}",
        counters(&cache)
    );
    assert_eq!(replayed_census(&grown), replayed_census(&home.oracle(3).1));
    assert_oracle(&home, &cache, &index, &grown, 3, true, &[]);
}

/// L-SB site 3 (the one writer): a settleable disclosure replaces the key's
/// attribution and releases what it no longer blocks; a strict one keeps
/// the prior attribution and adds its owner (R1-M2). A replayed disclosure
/// adds the held line and drop totals and re-requests its parent.
#[test]
fn one_writer_attributes_and_replays_held_totals() {
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/sessions"),
        path: PathBuf::from(format!(
            "/synthetic/sessions/rollout-2026-10-07T10-00-00-{SESSION}.jsonl"
        )),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "revision".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    let key = local_index_key(&candidate.path);
    let mut index = ScanIndex::default();
    let mut census = ScanCensus::default();
    let mut disclose = |disclosure: &Disclosure, index: &mut ScanIndex| {
        let mut residue = BTreeSet::new();
        let mut residue_blocked = BTreeSet::new();
        let mut blocked = BTreeSet::new();
        let mut pending = Vec::new();
        disclose_terminal_codex_debt(
            disclosure,
            &candidate,
            (None, None),
            index,
            DisclosureTargets {
                census: &mut census,
                residue_index_keys: &mut residue,
                residue_blocked_session_ids: &mut residue_blocked,
                codex_state_only_blocked_session_ids: &mut blocked,
                pending_finalization: &mut pending,
            },
        );
    };
    let mut held = disclosure();
    held.state_only_blocked_session_ids = vec![SESSION.into(), SESSION_B.into()];
    held.held = HeldCounts {
        over_line_cap: 2,
        recognized_usage_drop: 3,
        dropped_usage_record: 4,
        terminal_line_loss: 2,
    };
    held.parent_ref = Some("019fa111-2222-7333-8444-777777777777".into());
    disclose(&held, &mut index);
    assert_eq!(
        index.codex_state_only_blocked_by_file[&key],
        BTreeSet::from([SESSION.to_owned(), SESSION_B.to_owned()])
    );
    assert!(index
        .codex_parent_ownership_refs
        .contains("019fa111-2222-7333-8444-777777777777"));
    // A strict disclosure keeps the prior attribution and adds.
    let mut owner = strict(DebtReason::JoinStateBound);
    owner.state_only_blocked_session_ids = vec!["019fa111-2222-7333-8444-888888888888".into()];
    disclose(&owner, &mut index);
    assert_eq!(index.codex_state_only_blocked_by_file[&key].len(), 3);
    // A shrinking settleable replay releases what it no longer blocks.
    disclose(&disclosure(), &mut index);
    assert_eq!(
        index.codex_state_only_blocked_by_file[&key],
        BTreeSet::from([SESSION.to_owned()])
    );
    assert!(index.codex_state_only_blocked_session_ids.contains(SESSION));
    assert!(!index
        .codex_state_only_blocked_session_ids
        .contains(SESSION_B));
    // Only the first (settleable, replayed) disclosure added totals.
    assert_eq!(
        (
            census.over_line_cap_count,
            census.recognized_usage_drop_count,
            census.dropped_usage_record_count,
            census.terminal_over_line_cap_count,
            census.terminal_recognized_usage_drop_count,
            census.terminal_dropped_usage_record_count,
        ),
        (2, 3, 4, 2, 2, 2)
    );
}

// PR-1 packet tests (rev 5 §6), adjusted to the L-5 amendment: the page
// borrows the census the index owns, the probe memo is one slot cleared per
// step call, and both after-parse fences re-open the parent.

const PARENT: &str = "019fa111-2222-7333-8444-aaaaaaaaaaaa";
const CHILD: &str = "019fa111-2222-7333-8444-bbbbbbbbbbbb";

fn turn_record(at: &str, turn: &str) -> Value {
    json!({"timestamp": at, "type": "turn_context",
        "payload": {"turn_id": turn, "model": "gpt-5.6-sol"}})
}

fn usage_record(at: &str, total: (u64, u64, u64, u64), last: (u64, u64, u64, u64)) -> Value {
    let usage = |(input, cached, output, reasoning): (u64, u64, u64, u64)| {
        json!({"input_tokens": input, "cached_input_tokens": cached,
            "output_tokens": output, "reasoning_output_tokens": reasoning})
    };
    json!({"timestamp": at, "type": "event_msg", "payload": {"type": "token_count",
        "info": {"total_token_usage": usage(total), "last_token_usage": usage(last),
            "model": "gpt-5.6-sol"}}})
}

fn jsonl(records: &[Value]) -> Vec<u8> {
    records
        .iter()
        .cloned()
        .map(codex_line)
        .collect::<Vec<_>>()
        .concat()
}

/// The memo key `path` is stored under, if any (either path spelling).
fn stored_key(cache: &SharedCache, path: &Path) -> Option<String> {
    let scope = Scope("cursor-fixture".into());
    [
        path.to_path_buf(),
        fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
    ]
    .iter()
    .map(|path| memo_key(&scope, &local_index_key(path)))
    .find(|key| cache.memo_lookup(key).is_some())
}

/// `session`'s published usage: (input, requests) per snapshot.
fn session_usage(scan: &SourceScanResult, session: &str) -> Vec<(u64, u64)> {
    scan.snapshots
        .iter()
        .filter(|snapshot| snapshot.source_session_id == session)
        .map(|snapshot| (snapshot.input_tokens, snapshot.request_count))
        .collect()
}

/// One page stepped to completion, with `between` run before every step
/// call: a deterministic point between two records of the active file. It
/// may change the scan's own index there (fix round 6's proof transition).
fn page_between(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    mut between: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult) {
    let mut scan = codex_scan(fixture, index, collected_at)
        .with_sampled_acquisition(Arc::clone(cache), Scope("cursor-fixture".into()));
    for _ in 0..100_000 {
        between(&mut scan);
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
    panic!("the page did not finish");
}

/// Whether the scan's active file is `path`'s (by file name).
fn active_is(scan: &OwnedSourceScan, path: &Path) -> bool {
    scan.active_file
        .file
        .as_ref()
        .is_some_and(|active| active.candidate.path.file_name() == path.file_name())
}

/// A parent rollout P (two turns with usage: a complete ledger of four
/// signatures) and an ordinary fork C of P (`forked_from_id`, a `user`
/// thread) in one sessions root, with no sidecar.
struct ForkHome {
    fixture: ScanRoot,
}

impl ForkHome {
    fn new(child: &[Value]) -> Self {
        let home = Self {
            fixture: ScanRoot::with_sessions(&[]),
        };
        fs::write(home.fixture.file(PARENT), jsonl(&Self::parent())).unwrap();
        home.write_child(child);
        home
    }

    fn parent() -> Vec<Value> {
        vec![
            json!({"timestamp": "2026-10-07T08:00:00Z", "type": "session_meta",
                "payload": {"id": PARENT, "thread_source": "user"}}),
            turn_record("2026-10-07T08:00:01Z", "parent-turn-1"),
            usage_record("2026-10-07T08:00:02Z", (100, 80, 10, 2), (100, 80, 10, 2)),
            turn_record("2026-10-07T08:30:01Z", "parent-turn-2"),
            usage_record("2026-10-07T08:30:02Z", (160, 125, 18, 4), (60, 45, 8, 2)),
        ]
    }

    /// Kind (iii): C's first signature is its own turn, so its prefix
    /// diverges from P's complete ledger at signature 0 (`AmbiguousFork`,
    /// held), followed by `usage` own `token_count`s.
    fn diverging_child(usage: u64) -> Vec<Value> {
        let mut records = vec![turn_record("2026-10-07T08:20:01Z", "child-turn-1")];
        for n in 1..=usage {
            records.push(usage_record(
                "2026-10-07T08:20:02Z",
                (10 * n, 5 * n, n, 0),
                (10, 5, 1, 0),
            ));
        }
        records
    }

    /// A mid-ledger divergence: P's first turn and usage, then C's own turn
    /// and usage while later parent signatures exist (owned from there).
    fn matching_child() -> Vec<Value> {
        let parent = Self::parent();
        vec![
            parent[1].clone(),
            parent[2].clone(),
            turn_record("2026-10-07T08:20:01Z", "child-turn-1"),
            usage_record("2026-10-07T08:20:02Z", (130, 100, 14, 3), (30, 20, 4, 1)),
        ]
    }

    fn write_child(&self, records: &[Value]) {
        let mut all = vec![
            json!({"timestamp": "2026-10-07T08:20:00Z", "type": "session_meta",
            "payload": {"id": CHILD, "forked_from_id": PARENT, "thread_source": "user"}}),
        ];
        all.extend_from_slice(records);
        fs::write(self.fixture.file(CHILD), jsonl(&all)).unwrap();
    }

    fn generation(
        &self,
        index: ScanIndex,
        cache: &Arc<SharedCache>,
        n: u64,
    ) -> (ScanIndex, SourceScanResult) {
        self.generation_with(index, cache, n, |_| {})
    }

    /// One page of census generation `n`; `tweak` runs once the scan object
    /// is constructed (page start: census frozen, ledgers validated) and
    /// before its first step.
    fn generation_with(
        &self,
        index: ScanIndex,
        cache: &Arc<SharedCache>,
        n: u64,
        tweak: impl Fn(&mut OwnedSourceScan),
    ) -> (ScanIndex, SourceScanResult) {
        let mut index = index;
        index.traversal = None;
        let (index, scan, _) = page_with(
            &self.fixture,
            index,
            Some(Arc::clone(cache)),
            "cursor-fixture",
            &collected_at(n),
            tweak,
        );
        (index, scan)
    }

    /// Generations from `n` until the fork is settled: a generation that
    /// started with P's ledger indexed discloses the same census as the one
    /// before it. Returns the last generation and the next free `n`.
    fn settle(
        &self,
        index: ScanIndex,
        cache: &Arc<SharedCache>,
        n: u64,
    ) -> (ScanIndex, SourceScanResult, u64) {
        let (mut index, mut scan) = self.generation(index, cache, n);
        for next in n + 1..n + 8 {
            let before = census(&index, &scan);
            let ledgered = Self::parent_ledger(&index).is_some();
            let (following, again) = self.generation(index, cache, next);
            let stable = ledgered && census(&following, &again) == before;
            index = following;
            scan = again;
            if stable {
                return (index, scan, next + 1);
            }
        }
        panic!("the fork did not settle: {}", counters(cache));
    }

    /// The cold oracle: a fresh index and cache, settled from generation `n`.
    fn oracle(&self, n: u64) -> (ScanIndex, SourceScanResult) {
        let (index, scan, _) =
            self.settle(ScanIndex::default(), &Arc::new(SharedCache::default()), n);
        (index, scan)
    }

    /// The same generation read again with no memo: a fresh cache over a
    /// copy of the warm index (C-T3's fresh side).
    fn twin(&self, index: &ScanIndex, n: u64) -> (ScanIndex, SourceScanResult) {
        self.generation(index.clone(), &Arc::new(SharedCache::default()), n)
    }

    fn child_entry(&self, cache: &SharedCache) -> Option<MemoEntry> {
        stored_key(cache, &self.fixture.file(CHILD)).and_then(|key| cache.memo_lookup(&key))
    }

    /// P's indexed complete ledger identity.
    fn parent_ledger(index: &ScanIndex) -> Option<String> {
        index
            .codex_parent_ownership_ledgers
            .get(PARENT)
            .filter(|ledger| ledger.scan_complete)
            .map(|ledger| ledger.opened_object_identity.clone())
    }
}

/// P rewritten in place, not appended: a turn with usage inserted after its
/// first turn, every later signature kept (B2-T1's change).
fn rewrite_parent(path: &Path) {
    let parent = ForkHome::parent();
    let mut changed = parent[..3].to_vec();
    changed.push(turn_record("2026-10-07T08:10:01Z", "parent-turn-inserted"));
    changed.push(usage_record(
        "2026-10-07T08:10:02Z",
        (130, 103, 14, 3),
        (30, 23, 4, 1),
    ));
    changed.extend_from_slice(&parent[3..]);
    fs::write(path, jsonl(&changed)).unwrap();
}

/// P appended: one more turn with usage (`n` keeps the turn ids distinct).
fn append_parent_turn(path: &Path, n: u64) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&jsonl(&[
        turn_record("2026-10-07T09:00:01Z", &format!("parent-grown-{n}")),
        usage_record(
            "2026-10-07T09:00:02Z",
            (200 + 10 * n, 150 + 5 * n, 20 + n, 4),
            (10, 5, 1, 0),
        ),
    ]))
    .unwrap();
}

/// T1 (kind (iii)) and C-T3: a fork whose copied prefix diverges from its
/// parent's complete ledger at signature 0 is held with usage and memoized
/// with the ledger it used and the parent's current identity. An unchanged
/// generation hits at zero transcript bytes and discloses exactly what a
/// fresh read of the same generation does (same index, no memo), field by
/// field plus `scanned_session_count`, and what a cold settled scan does.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn kind_iii_fork_hold_hits_and_replays_a_fresh_read_exactly() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (index, settled, n) = home.settle(ScanIndex::default(), &cache, 0);
    let ledger = ForkHome::parent_ledger(&index).expect("indexed parent ledger");
    let entry = home
        .child_entry(&cache)
        .unwrap_or_else(|| panic!("the kind (iii) hold is memoized: {}", counters(&cache)));
    let dep = entry.parent.as_ref().expect("parent dependency");
    assert_eq!(
        (
            dep.id.as_str(),
            dep.ledger.as_deref(),
            dep.current.as_deref()
        ),
        (PARENT, Some(ledger.as_str()), Some(ledger.as_str()))
    );
    assert!(session_usage(&settled, CHILD).is_empty());
    assert_eq!(
        settled.ownership_incomplete_file_count,
        1,
        "{}",
        counters(&cache)
    );
    let hits = counter(&cache, |c| c.memo_hits);
    let (twin_index, twin) = home.twin(&index, n);
    let ((index, hit), counts) =
        codex_memo_lifecycle::observe(|| home.generation(index, &cache, n));
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        hits + 1,
        "{}",
        counters(&cache)
    );
    assert_eq!(
        counts.memo_hit_estimated_avoided_parser_bytes,
        home.fixture.len(CHILD)
    );
    assert!(session_usage(&hit, CHILD).is_empty());
    assert_eq!(replayed_census(&hit), replayed_census(&twin));
    assert_eq!(census(&index, &hit), census(&twin_index, &twin));
    let (oracle_index, oracle) = home.oracle(n + 1);
    assert_eq!(census(&index, &hit), census(&oracle_index, &oracle));
}

/// T14: after a restart (a new `SharedCache`, the index kept) the held fork
/// is read once and recorded, then hits with the same disclosure.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn a_new_shared_cache_rereads_a_held_fork_once_then_hits() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let (index, _, n) = home.settle(ScanIndex::default(), &Arc::new(SharedCache::default()), 0);
    let cache = Arc::new(SharedCache::default());
    let (index, reread) = home.generation(index, &cache, n);
    assert_eq!(
        (
            counter(&cache, |c| c.memo_hits),
            counter(&cache, |c| c.memo_records)
        ),
        (0, 1),
        "{}",
        counters(&cache)
    );
    let (_, hit) = home.generation(index, &cache, n + 1);
    assert_eq!(
        (
            counter(&cache, |c| c.memo_hits),
            counter(&cache, |c| c.memo_records)
        ),
        (1, 1),
        "{}",
        counters(&cache)
    );
    assert_eq!(replayed_census(&hit), replayed_census(&reread));
}

/// SOURCE 1(b), B2's scan-level case (M1 durable warm-cache reuse): restore +
/// Tail beside a non-empty held-fork memo and a non-empty parent ledger. One
/// sessions root holds P (a complete ledger of real signatures), its kind
/// (iii) fork C (held, memoized with P's ledger as its dependency) and a
/// plain singleton S. Process 1 settles, saves and writes S's record under
/// the state-directory lock. S grows (an unchanged file never reaches the
/// read path). Process 2 (a fresh `SharedCache`, the saved index loaded,
/// P's persisted ledger re-validated and re-injected by the scan) restores
/// and Tails S on its first page while C is re-read and memoized again. The
/// RAM copies are then released (`clear`, which keeps the memo, K6) and S
/// grows again: the next page restores S from the same record with the memo
/// non-empty and Tails it while C hits its memo. Each page's body, census,
/// ledgers and #660 maps equal a cold Full (no cache) of the same index and
/// files.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn durable_restore_then_tail_beside_a_held_fork_memo_and_parent_ledger_matches_cold_full() {
    const SINGLE: &str = "019fa111-2222-7333-8444-cccccccccccc";
    let source = SnapshotSource::Codex;
    let namespace = Scope("cursor-fixture".into());
    let capture = true; // Outside a sync cycle every scan captures.
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    fs::write(
        home.fixture.file(SINGLE),
        jsonl(&[
            json!({"timestamp": "2026-10-07T08:40:00Z", "type": "session_meta",
                "payload": {"id": SINGLE, "thread_source": "user"}}),
            turn_record("2026-10-07T08:40:01Z", "single-turn-1"),
            usage_record("2026-10-07T08:40:02Z", (100, 50, 10, 0), (100, 50, 10, 0)),
        ]),
    )
    .unwrap();
    let page = |index: ScanIndex, cache: Option<Arc<SharedCache>>, n: u64| {
        let mut index = index;
        index.traversal = None;
        page_selections(
            &home.fixture,
            index,
            cache,
            "cursor-fixture",
            &collected_at(n),
            |_| {},
            usize::MAX,
        )
    };
    let body = |scan: &SourceScanResult| {
        let mut snapshots = scan.snapshots.clone();
        apply_upload_policy(source, &mut snapshots, SnapshotUploadPolicy::default());
        serde_json::to_value(snapshots).unwrap()
    };
    // P's indexed ledger: complete, with real signatures.
    let ledger_signed = |index: &ScanIndex| {
        let ledger = index
            .codex_parent_ownership_ledgers
            .get(PARENT)
            .expect("indexed parent ledger");
        assert!(
            ledger.scan_complete && !ledger.signatures.is_empty(),
            "a non-empty complete parent ledger"
        );
        ledger.opened_object_identity.clone()
    };
    let parent_records = |index: &ScanIndex| {
        (
            serde_json::to_vec(&index.codex_parent_ownership_ledgers).unwrap(),
            serde_json::to_vec(&index.codex_parent_side).unwrap(),
            serde_json::to_vec(&index.codex_parent_side_requests).unwrap(),
            serde_json::to_vec(&index.codex_parent_prefix_proofs).unwrap(),
        )
    };
    let memo_depends_on = |cache: &SharedCache, identity: &str| {
        let entry = home
            .child_entry(cache)
            .unwrap_or_else(|| panic!("C's hold is memoized: {}", counters(cache)));
        let dep = entry.parent.as_ref().expect("parent dependency");
        assert_eq!(
            (dep.id.as_str(), dep.ledger.as_deref()),
            (PARENT, Some(identity)),
            "the memo used P's ledger"
        );
    };

    // Process 1.
    let state = home.fixture._dir.0.join("state");
    fs::create_dir_all(&state).unwrap();
    let index_path = state.join("index.json");
    let lock = crate::locked_state_dir::test_locks::hold(&state);
    let first = Arc::new(SharedCache::default());
    first.durable_begin_pass(source, &index_path, &namespace, capture);
    let (mut index, settled, n) = home.settle(ScanIndex::default(), &first, 0);
    let identity = ledger_signed(&index);
    memo_depends_on(&first, &identity);
    assert!(session_usage(&settled, CHILD).is_empty(), "C is held");
    // S published on its first generation; the settled page is quiet for it.
    let single_key = local_index_key(&home.fixture.file(SINGLE));
    assert!(
        index
            .files
            .get(&single_key)
            .is_some_and(|entry| entry.last_snapshot_fingerprint.is_some()),
        "S is indexed and published"
    );
    index.save(&index_path).unwrap();
    first.durable_write_after_save(lock, source, &index);
    let records = fs::read_dir(crate::durable_tail_store::store_dir_for_index(&index_path))
        .map_or(0, |entries| entries.count());
    assert!(records >= 1, "S's record is written after the save");
    drop(first);

    // Process 2, first page: S restores and Tails (the restart) while C is
    // re-read and memoized again against P's re-injected ledger.
    let grow = |at: &str, total: (u64, u64, u64, u64)| {
        home.fixture
            .append(SINGLE, &jsonl(&[usage_record(at, total, (30, 20, 3, 0))]));
    };
    grow("2026-10-07T08:40:03Z", (130, 70, 13, 0));
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(ledger_signed(&loaded), identity, "the ledger persisted");
    let second = Arc::new(SharedCache::default());
    assert!(home.child_entry(&second).is_none(), "a restart has no memo");
    second.durable_begin_pass(source, &index_path, &namespace, capture);
    let (index_a, warm_a, selections_a) = page(loaded.clone(), Some(Arc::clone(&second)), n);
    let (counters_a, store_a) = second.durable_counters(source).unwrap();
    eprintln!(
        "held-memo restart page: {}",
        counters_a.summary(source, &store_a)
    );
    assert!(counters_a.restored >= 1, "S restores from its record");
    assert!(selections_a.modes.1 >= 1, "S continues by Tail");
    memo_depends_on(&second, &identity);
    let (cold_index_a, cold_a, _) = page(loaded, None, n);
    assert_eq!(body(&warm_a), body(&cold_a));
    assert_eq!(census(&index_a, &warm_a), census(&cold_index_a, &cold_a));
    assert_eq!(replayed_census(&warm_a), replayed_census(&cold_a));
    assert_eq!(parent_records(&index_a), parent_records(&cold_index_a));

    // Process 2 commits page A and rewrites S's record, which now binds the
    // Tailed entry (a record never outlives its committed entry). Then the
    // RAM copies are released (the memo survives) and S grows: the next page
    // restores S again with the memo non-empty and Tails it; C hits.
    let mut index_a = index_a;
    index_a.save(&index_path).unwrap();
    second.durable_write_after_save(lock, source, &index_a);
    second.clear();
    memo_depends_on(&second, &identity);
    grow("2026-10-07T08:40:04Z", (160, 90, 16, 0));
    assert_eq!(ledger_signed(&index_a), identity, "re-injected unchanged");
    let hits = counter(&second, |c| c.memo_hits);
    second.durable_begin_pass(source, &index_path, &namespace, capture);
    let (warm_index, warm, selections) = page(index_a.clone(), Some(Arc::clone(&second)), n + 1);
    let (counters_b, store_b) = second.durable_counters(source).unwrap();
    eprintln!(
        "held-memo tail page: {}",
        counters_b.summary(source, &store_b)
    );
    assert_eq!(
        counters_b.restored,
        counters_a.restored + 1,
        "S restores beside the memo"
    );
    assert_eq!(selections.modes.1, 1, "S continues by Tail");
    assert_eq!(
        counter(&second, |c| c.memo_hits),
        hits + 1,
        "C hits its memo: {}",
        counters(&second)
    );
    let (cold_index, cold, _) = page(index_a, None, n + 1);
    assert!(session_usage(&warm, CHILD).is_empty(), "C stays held");
    assert!(session_usage(&cold, CHILD).is_empty(), "C stays held cold");
    assert_ne!(
        session_usage(&warm, SINGLE),
        session_usage(&warm_a, SINGLE),
        "S's second growth is published"
    );
    assert_eq!(session_usage(&warm, SINGLE), session_usage(&cold, SINGLE));
    assert_eq!(body(&warm), body(&cold));
    assert_eq!(census(&warm_index, &warm), census(&cold_index, &cold));
    assert_eq!(replayed_census(&warm), replayed_census(&cold));
    assert_eq!(ledger_signed(&warm_index), identity);
    assert_eq!(parent_records(&warm_index), parent_records(&cold_index));
}

/// T15 (PR-P §2.4): a created thread never consults a parent ledger, so it
/// records no parent ref, before or after an index reset; its memo hit
/// re-requests nothing. P-T32 covers an ordinary fork's re-request.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn memo_hit_after_an_index_reset_requests_no_parent_ref() {
    let home = CreatedThreadHome::with_lineage(2, true, "agent_created_thread", Some(SPAWN_PARENT));
    home.project(home.bytes(2), 2);
    let cache = Arc::new(SharedCache::default());
    let (mut index, _) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(!index.codex_parent_ownership_refs.contains(SPAWN_PARENT));
    index.codex_parent_ownership_refs.clear();
    let (index, quiet) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert!(
        !index.codex_parent_ownership_refs.contains(SPAWN_PARENT),
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &quiet, 1, true, &[]);
}

/// T15b: the parent's object is replaced (same bytes, new inode). The
/// child's entry misses once, counted `memo_miss_other`, and the fork
/// settles on the new parent object exactly as a cold scan.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn replaced_parent_object_misses_the_child_and_settles_like_a_cold_scan() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (index, _, n) = home.settle(ScanIndex::default(), &cache, 0);
    let before = ForkHome::parent_ledger(&index).unwrap();
    let hits = counter(&cache, |c| c.memo_hits);
    let parent = home.fixture.file(PARENT);
    let replacement = home
        .fixture
        .root
        .parent()
        .unwrap()
        .join("parent-replacement");
    fs::copy(&parent, &replacement).unwrap();
    fs::rename(&replacement, &parent).unwrap();
    let ((index, replaced), counts) =
        codex_memo_lifecycle::observe(|| home.generation(index, &cache, n));
    assert_eq!(
        (
            counts.memo_hit_estimated_avoided_parser_bytes,
            counts.memo_miss_exact_stamp,
            counts.memo_miss_other
        ),
        (0, 0, 1),
        "{}",
        counters(&cache)
    );
    assert_eq!(counter(&cache, |c| c.memo_hits), hits);
    assert!(session_usage(&replaced, CHILD).is_empty());
    let (index, settled, n) = home.settle(index, &cache, n + 1);
    let after = ForkHome::parent_ledger(&index).unwrap();
    assert_ne!(after, before);
    let entry = home.child_entry(&cache).expect("re-recorded");
    assert_eq!(
        entry.parent.as_ref().and_then(|dep| dep.ledger.as_deref()),
        Some(after.as_str())
    );
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// T15c, rewritten for PR-P in two legs.
/// (a) A held created thread whose trusted spawn parent has a local,
/// complete rollout: the hold never consults a ledger, so the parent gets no
/// ref and no index ledger. From its second generation the unchanged hold
/// hits every generation and discloses what a cold scan does.
/// (b) The live case, an ordinary fork C of P whose first parse precedes P
/// on the page: C is pending (never recorded) until P's ledger arrives at an
/// unchanged P identity, then recorded once, then quiet: nothing is parsed
/// again, and the census equals the cold oracle.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn parent_ledger_arrival_at_an_unchanged_identity_misses_at_most_once() {
    let home = CreatedThreadHome::with_lineage(2, true, "agent_created_thread", Some(SPAWN_PARENT));
    home.project(home.bytes(2), 2);
    let at = |offset: i64| bounded_rfc3339_millis(home.base_ms + offset).unwrap();
    fs::write(
        home.fixture
            .root
            .join(format!("rollout-2026-10-07T08-00-00-{SPAWN_PARENT}.jsonl")),
        jsonl(&[
            json!({"timestamp": at(-60_000), "type": "session_meta",
                "payload": {"id": SPAWN_PARENT, "thread_source": "user"}}),
            turn_record(&at(-59_000), "spawn-parent-turn"),
            usage_record(&at(-58_000), (40, 20, 4, 1), (40, 20, 4, 1)),
        ]),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut hits = Vec::new();
    let mut last = None;
    for n in 0..4 {
        let (next, scan) = home.generation(index, &cache, n);
        assert!(
            !next.codex_parent_ownership_refs.contains(SPAWN_PARENT)
                && !next
                    .codex_parent_ownership_ledgers
                    .contains_key(SPAWN_PARENT),
            "generation {n}: {}",
            counters(&cache)
        );
        assert!(created_usage(&scan).is_empty());
        hits.push(counter(&cache, |c| c.memo_hits));
        index = next;
        last = Some(scan);
    }
    let entry = home.memo_entry(&cache).expect("memoized hold");
    let dep = entry.parent.as_ref().expect("spawn parent dependency");
    assert_eq!(
        (dep.id.as_str(), dep.ledger.as_deref()),
        (SPAWN_PARENT, None)
    );
    // At most one miss after the first record, then a hit per generation.
    assert_eq!(hits[3] - hits[1], 2, "{}", counters(&cache));
    assert!(
        counter(&cache, |c| c.memo_records) <= 2,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &last.unwrap(), 3, true, &[]);

    // (b) C's rollout sorts before P's, so its first parse precedes P.
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let early = home
        .fixture
        .root
        .join(format!("rollout-2026-10-07T09-00-00-{CHILD}.jsonl"));
    fs::rename(home.fixture.file(CHILD), &early).unwrap();
    let cache = Arc::new(SharedCache::default());
    let (index, _, n) = home.settle(ScanIndex::default(), &cache, 0);
    let ledger = ForkHome::parent_ledger(&index).expect("indexed parent ledger");
    let key = stored_key(&cache, &early)
        .unwrap_or_else(|| panic!("C is held and memoized: {}", counters(&cache)));
    let entry = cache.memo_lookup(&key).unwrap();
    let dep = entry.parent.as_ref().expect("parent dependency");
    assert_eq!(
        (dep.ledger.as_deref(), dep.witnessed),
        (Some(ledger.as_str()), None)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "never recorded while pending, once after the ledger: {}",
        counters(&cache)
    );
    let hits = counter(&cache, |c| c.memo_hits);
    let ((index, quiet), parsed) = parses(|| {
        let (index, _) = home.generation(index, &cache, n);
        home.generation(index, &cache, n + 1)
    });
    assert!(parsed.is_empty(), "{parsed:?}: {}", counters(&cache));
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        hits + 2,
        "{}",
        counters(&cache)
    );
    let (oracle_index, oracle) = home.oracle(n + 2);
    assert_eq!(census(&index, &quiet), census(&oracle_index, &oracle));
}

/// Every parse started inside `run`, by file name: the B2-T1 seam fires
/// after a memo miss (or no lookup) and before the parse, never on a hit.
fn parses<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = std::rc::Rc::clone(&seen);
    let value = crate::snapshots::with_codex_before_parse(
        move |path: &Path| {
            sink.borrow_mut().push(
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            );
        },
        run,
    );
    let seen = seen.borrow().clone();
    (value, seen)
}

/// `scan`'s traversal-cumulative held-parent counts, by cause index.
fn parent_causes(scan: &SourceScanResult) -> [u64; PARENT_UNRESOLVABLE_CAUSES] {
    scan.local_codex_diagnostics
        .as_ref()
        .expect("Codex diagnostics")
        .parent_unresolvable
        .counts()
}

/// `count` held children under `cause` and none elsewhere.
fn only(cause: CodexParentUnresolvable, count: u64) -> [u64; PARENT_UNRESOLVABLE_CAUSES] {
    let mut expected = [0; PARENT_UNRESOLVABLE_CAUSES];
    expected[cause.index()] = count;
    expected
}

fn restarts_in_scope(scan: &SourceScanResult) -> Option<u64> {
    scan.local_codex_diagnostics
        .as_ref()
        .expect("Codex diagnostics")
        .parent_restarts_in_scope
}

/// T15d: a child of a growing parent never hits (the parent's identity moves
/// every generation) and its misses are `memo_miss_other`, never an
/// exact-stamp miss; it is never admitted.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn child_of_a_growing_parent_never_hits() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (mut index, _, mut n) = home.settle(ScanIndex::default(), &cache, 0);
    let hits = counter(&cache, |c| c.memo_hits);
    let mut other = 0;
    for grown in 0..3 {
        append_parent_turn(&home.fixture.file(PARENT), grown);
        let ((next, scan), counts) =
            codex_memo_lifecycle::observe(|| home.generation(index, &cache, n));
        assert_eq!(
            (
                counts.memo_hit_estimated_avoided_parser_bytes,
                counts.memo_miss_exact_stamp
            ),
            (0, 0),
            "{counts:?}"
        );
        assert!(session_usage(&scan, CHILD).is_empty());
        other += counts.memo_miss_other;
        index = next;
        n += 1;
    }
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        hits,
        "{}",
        counters(&cache)
    );
    assert!(other >= 1, "{}", counters(&cache));
}

/// T1b/N2 and T3b, with PR-P (P-T1a): a `forked_from_id` fork whose parent
/// is not on disk is pending on its first generation: its parent requested,
/// never recorded. From the next match the parent is witnessed `Absent`, so
/// the fork is held, counted under `Absent` (with the scope's restart
/// count), recorded once and then hits. T7: once the parent arrives the
/// witness drops and the fork settles exactly as a cold scan (here held and
/// memoized: kind (iii)).
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn absent_parent_fork_is_held_then_settles_when_its_parent_arrives() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let parent = home.fixture.file(PARENT);
    let away = home.fixture.root.parent().unwrap().join("parent-away");
    fs::rename(&parent, &away).unwrap();
    let cache = Arc::new(SharedCache::default());
    let (mut index, first) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(session_usage(&first, CHILD).is_empty());
    assert!(
        home.child_entry(&cache).is_none(),
        "a parent-pending fork is never recorded: {}",
        counters(&cache)
    );
    assert!(index.codex_parent_ownership_refs.contains(PARENT));
    let mut hits = counter(&cache, |c| c.memo_hits);
    for n in 1..4 {
        let (next, scan) = home.generation(index, &cache, n);
        assert!(session_usage(&scan, CHILD).is_empty());
        assert_eq!(
            parent_causes(&scan),
            only(CodexParentUnresolvable::Absent, 1),
            "generation {n}: {}",
            counters(&cache)
        );
        assert!(
            restarts_in_scope(&scan).is_some_and(|restarts| restarts <= 1),
            "generation {n}: {:?}",
            restarts_in_scope(&scan)
        );
        assert_eq!(
            counter(&cache, |c| c.memo_records),
            1,
            "generation {n}: {}",
            counters(&cache)
        );
        if n > 1 {
            assert_eq!(
                counter(&cache, |c| c.memo_hits),
                hits + 1,
                "generation {n}: {}",
                counters(&cache)
            );
        }
        hits = counter(&cache, |c| c.memo_hits);
        assert!(next.codex_parent_ownership_refs.contains(PARENT));
        index = next;
    }
    let entry = home.child_entry(&cache).expect("held and recorded");
    assert_eq!(
        entry.parent.as_ref().and_then(|dep| dep.witnessed),
        Some(CodexParentUnresolvable::Absent)
    );
    fs::rename(&away, &parent).unwrap();
    let (index, settled, n) = home.settle(index, &cache, 4);
    assert!(home.child_entry(&cache).is_some(), "{}", counters(&cache));
    assert_eq!(
        parent_causes(&settled),
        only(CodexParentUnresolvable::Absent, 0)
    );
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// T1d (R1-L4 control): a fork that matches its parent's first signatures
/// and diverges while later parent signatures exist is owned from there: it
/// is admitted once with its own usage and never memoized.
#[test]
fn mid_ledger_divergence_is_admitted_and_never_memoized() {
    let home = ForkHome::new(&ForkHome::matching_child());
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut published = Vec::new();
    for n in 0..6 {
        let (next, scan) = home.generation(index, &cache, n);
        published.extend(session_usage(&scan, CHILD));
        assert!(home.child_entry(&cache).is_none(), "{}", counters(&cache));
        index = next;
    }
    assert_eq!(published, vec![(30, 1)], "{}", counters(&cache));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        0,
        "{}",
        counters(&cache)
    );
}

/// B2-T1 (scan-level liveness and safety): the child grows, so its lookup
/// misses (exact stamp) after probing P; the seam then rewrites P before
/// C's parse, which uses the page-start ledger. The fence re-opens P and
/// refuses C (parent-pending: not recorded, nothing published). Later
/// generations settle on the new P exactly as a cold scan.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn parent_rewritten_after_the_child_lookup_refuses_the_child() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (index, _, n) = home.settle(ScanIndex::default(), &cache, 0);
    assert!(home.child_entry(&cache).is_some(), "{}", counters(&cache));
    let before = ForkHome::parent_ledger(&index).unwrap();
    home.fixture.append(
        CHILD,
        &jsonl(&[usage_record(
            "2026-10-07T08:20:03Z",
            (40, 20, 4, 0),
            (10, 5, 1, 0),
        )]),
    );
    let fired = std::rc::Rc::new(std::cell::Cell::new(0));
    let hook = {
        let fired = std::rc::Rc::clone(&fired);
        let (child, parent) = (home.fixture.file(CHILD), home.fixture.file(PARENT));
        move |path: &Path| {
            if path.file_name() == child.file_name() {
                fired.set(fired.get() + 1);
                rewrite_parent(&parent);
            }
        }
    };
    let ((index, refused), counts) = codex_memo_lifecycle::observe(|| {
        crate::snapshots::with_codex_before_parse(hook, || home.generation(index, &cache, n))
    });
    assert_eq!(fired.get(), 1, "{}", counters(&cache));
    assert_eq!(counts.memo_miss_exact_stamp, 1, "{counts:?}");
    assert!(session_usage(&refused, CHILD).is_empty());
    assert!(
        home.child_entry(&cache).is_none(),
        "refused as parent-pending, not re-recorded: {}",
        counters(&cache)
    );
    let (index, settled, n) = home.settle(index, &cache, n + 1);
    let after = ForkHome::parent_ledger(&index).unwrap();
    assert_ne!(after, before);
    let entry = home
        .child_entry(&cache)
        .expect("re-recorded on the new parent");
    assert_eq!(
        entry.parent.as_ref().and_then(|dep| dep.ledger.as_deref()),
        Some(after.as_str())
    );
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// B2-T2 (resume): C's parse spans step calls. After its header classified
/// against P's ledger, P changes between two step calls; when C's parse
/// finishes the fence re-opens P and refuses C. A fresh cache makes C read
/// in full (no memo). Later generations settle exactly as a cold scan.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn parent_changed_between_the_child_step_calls_refuses_it_on_resume() {
    let home = ForkHome::new(&ForkHome::diverging_child(12));
    let (mut index, _, n) = home.settle(ScanIndex::default(), &Arc::new(SharedCache::default()), 0);
    let before = ForkHome::parent_ledger(&index).unwrap();
    let cache = Arc::new(SharedCache::default());
    let (child, parent) = (home.fixture.file(CHILD), home.fixture.file(PARENT));
    let mut rewritten = 0;
    index.traversal = None;
    let (index, refused) = page_between(&home.fixture, index, &cache, &collected_at(n), |scan| {
        let classified = active_is(scan, &child)
            && scan.active_file.file.as_ref().is_some_and(|active| {
                active
                    .parser
                    .accumulator
                    .codex_parent_ledger_identity_used
                    .is_some()
            });
        if classified && rewritten == 0 {
            rewrite_parent(&parent);
            rewritten += 1;
        }
    });
    assert_eq!(rewritten, 1, "{}", counters(&cache));
    assert!(session_usage(&refused, CHILD).is_empty());
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        0,
        "refused as parent-pending, not recorded: {}",
        counters(&cache)
    );
    let (index, settled, n) = home.settle(index, &cache, n + 1);
    assert_ne!(ForkHome::parent_ledger(&index).unwrap(), before);
    assert!(home.child_entry(&cache).is_some(), "{}", counters(&cache));
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// B2-T3 (liveness): P is appended after page start (the census is frozen
/// and its old ledger validated) and before its own parse. The ledger insert
/// re-opens P after that parse, so the new ledger is still inserted.
#[test]
fn parent_appended_after_page_start_still_gets_its_ledger() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (index, _, n) = home.settle(ScanIndex::default(), &cache, 0);
    let before = ForkHome::parent_ledger(&index).unwrap();
    let parent = home.fixture.file(PARENT);
    let (index, _) = home.generation_with(index, &cache, n, |_| append_parent_turn(&parent, 0));
    let ledger = index
        .codex_parent_ownership_ledgers
        .get(PARENT)
        .unwrap_or_else(|| panic!("no ledger: {}", counters(&cache)));
    assert!(ledger.scan_complete);
    assert_ne!(ledger.opened_object_identity, before);
    assert_eq!(ledger.signatures.len(), 6);
    let (index, settled, n) = home.settle(index, &cache, n + 1);
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// L6-T1: a rollout-declared created thread with a spawn parent, flushed to
/// 9 of the 10 records its projection covers. The bind seeds at that length
/// (no bind: held), and the 10th record lands between the parser's open and
/// its read. The hold must not be recorded at a stamp its bind never saw.
/// Generation 1 binds at the full length and admits once, as cold.
#[test]
fn bind_seed_short_of_the_read_extent_is_never_recorded() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = CreatedThreadHome::with_lineage(9, false, "user", Some(SPAWN_PARENT));
    let cache = Arc::new(SharedCache::default());
    let collected = bounded_rfc3339_millis(home.base_ms + 3_600_000).unwrap();
    let mut appended = false;
    let ((index, held), counts) = codex_memo_lifecycle::observe(|| {
        page_between(
            &home.fixture,
            ScanIndex::default(),
            &cache,
            &collected,
            |scan| {
                if !appended && active_is(scan, &home.path) {
                    home.flush_from(9);
                    appended = true;
                }
            },
        )
    });
    assert!(appended, "{}", counters(&cache));
    assert!(
        created_usage(&held).is_empty(),
        "held: {}",
        counters(&cache)
    );
    assert_eq!(
        (
            counter(&cache, |c| c.memo_records),
            counts.memo_hit_estimated_avoided_parser_bytes
        ),
        (0, 0),
        "{}",
        counters(&cache)
    );
    assert!(home.memo_entry(&cache).is_none());
    let (index, admitted) = home.generation(index, &cache, 1);
    assert_eq!(
        created_usage(&admitted),
        vec![(200, 3)],
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &admitted, 1, true, &[]);
}

/// T1c: kind (i) with usage (a rollout-declared created thread whose file
/// is ahead of its projection) hits while unchanged; growth is an
/// exact-stamp miss with the grown extent, re-read and held again as cold.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn kind_i_usage_hold_hits_unchanged_and_misses_grown() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = CreatedThreadHome::with_lineage(10, false, "user", Some(SPAWN_PARENT));
    home.project(home.bytes(9), 9);
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert!(created_usage(&held).is_empty(), "{}", counters(&cache));
    assert!(held.recognized_usage_drop_count > 0, "usage-bearing hold");
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &held, 0, true, &[]);
    let (index, quiet) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_eq!(replayed_census(&quiet), replayed_census(&home.oracle(1).1));
    let extra = codex_line(json!({
        "timestamp": bounded_rfc3339_millis(home.base_ms + 7_000).unwrap(),
        "type": "turn_context",
        "payload": {"turn_id": "grown-turn", "model": "gpt-5.6-sol"},
        "ordinal": 10,
    }));
    OpenOptions::new()
        .append(true)
        .open(&home.path)
        .unwrap()
        .write_all(&extra)
        .unwrap();
    let ((index, grown), counts) =
        codex_memo_lifecycle::observe(|| home.generation(index, &cache, 2));
    assert_eq!(
        (
            counts.memo_miss_exact_stamp,
            counts.memo_miss_exact_stamp_bytes,
            counts.memo_miss_other
        ),
        (1, fs::metadata(&home.path).unwrap().len(), 0),
        "{}",
        counters(&cache)
    );
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        2,
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &grown, 2, true, &[]);
}

/// T2: a held fork with a terminal over-line-cap line (one line past
/// `MAX_JSONL_LINE_BYTES`) is memoized and hits; every replayed count,
/// `over_line_cap` and the terminal trio included, equals a cold read.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn terminal_over_line_cap_hold_hits_with_the_cold_counts() {
    let home = CreatedThreadHome::new(10, true);
    let mut row = format!(
        "{{\"timestamp\":\"{}\",\"type\":\"response_item\",\"payload\":\"",
        bounded_rfc3339_millis(home.base_ms + 7_000).unwrap()
    )
    .into_bytes();
    row.extend(std::iter::repeat_n(b'x', MAX_JSONL_LINE_BYTES + 1));
    row.extend_from_slice(b"\"}\n");
    OpenOptions::new()
        .append(true)
        .open(&home.path)
        .unwrap()
        .write_all(&row)
        .unwrap();
    let cache = Arc::new(SharedCache::default());
    let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
    assert_eq!(held.over_line_cap_count, 1, "{}", counters(&cache));
    assert!(created_usage(&held).is_empty(), "{}", counters(&cache));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    let (index, quiet) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    let cold = home.oracle(1).1;
    assert_eq!(replayed_census(&quiet), replayed_census(&cold));
    assert_eq!(quiet.over_line_cap_count, 1);
    assert_eq!(
        quiet.terminal_over_line_cap_count,
        held.terminal_over_line_cap_count
    );
    assert_oracle(&home, &cache, &index, &quiet, 1, true, &[]);
}

/// T3: a non-monotone hold (`AwaitingLegacyTrigger`: a subagent fork with
/// copied usage and no trigger turn) is memoized at its read end: unchanged
/// it hits exactly; grown, it is an exact-stamp miss and is read again. Its
/// parent is not on disk, so no parent ledger ever arrives (T15c covers
/// that). (An `Undetermined` file, usage before any header, never reaches
/// the memo: its first record is not an owning header, so the header
/// inventory holds the page, as on main.)
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn non_monotone_legacy_trigger_hold_hits_exactly_and_misses_on_growth() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let fixture = ScanRoot::with_sessions(&[]);
    let mut fork = codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
        "type": "session_meta", "payload": {"id": SESSION_B, "forked_from_id": SESSION,
        "thread_source": "subagent"}}));
    fork.extend(token_line(1));
    fork.extend(token_line(2));
    fs::write(fixture.file(SESSION_B), fork).unwrap();
    let cache = Arc::new(SharedCache::default());
    let generation = |index: ScanIndex, n: u64| {
        let mut index = index;
        index.traversal = None;
        let (index, scan, _) = page_at(
            &fixture,
            index,
            Some(Arc::clone(&cache)),
            "cursor-fixture",
            &collected_at(n),
        );
        (index, scan)
    };
    let (index, held) = generation(ScanIndex::default(), 0);
    assert!(
        session_usage(&held, SESSION_B).is_empty(),
        "{}",
        counters(&cache)
    );
    assert_eq!(
        held.ownership_incomplete_file_count,
        1,
        "{}",
        counters(&cache)
    );
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    let (index, quiet) = generation(index, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert_eq!(
        census(&index, &quiet).0,
        census(&index, &held).0,
        "{}",
        counters(&cache)
    );
    fixture.append(SESSION_B, &token_line(3));
    let ((index, grown), counts) = codex_memo_lifecycle::observe(|| generation(index, 2));
    assert_eq!(
        (
            counts.memo_miss_exact_stamp,
            counts.memo_miss_exact_stamp_bytes,
            counts.memo_miss_other
        ),
        (1, fixture.len(SESSION_B), 0),
        "{}",
        counters(&cache)
    );
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    assert!(session_usage(&grown, SESSION_B).is_empty());
    let _ = generation(index, 3);
    assert_eq!(counter(&cache, |c| c.memo_hits), 2, "{}", counters(&cache));
}

/// T3 (second shape): a fork that matches every signature of its parent's
/// ledger and ends there stays `AwaitingParentPrefix` (non-monotone, not
/// parent-pending): memoized, hit while unchanged; growth is an exact-stamp
/// miss and the re-read settles exactly as a cold scan.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn prefix_exhausted_fork_hold_hits_exactly_and_misses_on_growth() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = ForkHome::new(&ForkHome::parent()[1..]);
    let cache = Arc::new(SharedCache::default());
    let (index, settled, n) = home.settle(ScanIndex::default(), &cache, 0);
    assert!(session_usage(&settled, CHILD).is_empty());
    assert!(home.child_entry(&cache).is_some(), "{}", counters(&cache));
    let hits = counter(&cache, |c| c.memo_hits);
    let (index, _) = home.generation(index, &cache, n);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        hits + 1,
        "{}",
        counters(&cache)
    );
    home.fixture.append(
        CHILD,
        &jsonl(&[turn_record("2026-10-07T08:40:01Z", "child-turn-1")]),
    );
    let ((index, _), counts) =
        codex_memo_lifecycle::observe(|| home.generation(index, &cache, n + 1));
    assert_eq!(
        (counts.memo_miss_exact_stamp, counts.memo_miss_other),
        (1, 0),
        "{counts:?}"
    );
    let (index, settled, n) = home.settle(index, &cache, n + 2);
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// T6 and T18 (second half): growth together with a sidecar change is not
/// an exact-stamp miss (a tail could not replay it): it counts
/// `memo_miss_other`, re-reads equal to cold, and the new entry hits.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn growth_with_a_sidecar_change_counts_an_other_miss() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = CreatedThreadHome::new(10, true);
    let cache = Arc::new(SharedCache::default());
    let (index, _) = home.generation(ScanIndex::default(), &cache, 0);
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        1,
        "{}",
        counters(&cache)
    );
    let extra = codex_line(json!({
        "timestamp": bounded_rfc3339_millis(home.base_ms + 7_000).unwrap(),
        "type": "turn_context",
        "payload": {"turn_id": "grown-turn", "model": "gpt-5.6-sol"},
        "ordinal": 10,
    }));
    OpenOptions::new()
        .append(true)
        .open(&home.path)
        .unwrap()
        .write_all(&extra)
        .unwrap();
    home.project(home.bytes(10) + extra.len(), 11);
    let ((index, woken), counts) =
        codex_memo_lifecycle::observe(|| home.generation(index, &cache, 1));
    assert_eq!(
        (
            counts.memo_miss_exact_stamp,
            counts.memo_miss_other,
            counts.memo_hit_estimated_avoided_parser_bytes
        ),
        (0, 1, 0),
        "{}",
        counters(&cache)
    );
    assert_oracle(&home, &cache, &index, &woken, 1, true, &[]);
    let _ = home.generation(index, &cache, 2);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
}

/// T8: the held file's object changes without new records: a same-size
/// touch (mtime and ctime), a replacement (new inode, same bytes) and a
/// shrink each miss once, re-read equal to cold; a shrink is never counted
/// as an exact-stamp (growth) miss.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn touched_replaced_or_shrunk_held_file_misses() {
    use crate::local_resource_diagnostics::codex_memo_lifecycle;
    let home = CreatedThreadHome::new(10, true);
    let cache = Arc::new(SharedCache::default());
    let (mut index, _) = home.generation(ScanIndex::default(), &cache, 0);
    let replacement = home.codex().join("held-replacement");
    let mut n = 1;
    for name in ["touch", "replace", "shrink"] {
        let hits = counter(&cache, |c| c.memo_hits);
        match name {
            "touch" => File::options()
                .write(true)
                .open(&home.path)
                .unwrap()
                .set_modified(SystemTime::now() + std::time::Duration::from_secs(120))
                .unwrap(),
            "replace" => {
                fs::copy(&home.path, &replacement).unwrap();
                fs::rename(&replacement, &home.path).unwrap();
            }
            _ => OpenOptions::new()
                .write(true)
                .open(&home.path)
                .unwrap()
                .set_len(u64::try_from(home.bytes(9)).unwrap())
                .unwrap(),
        }
        let ((next, scan), counts) =
            codex_memo_lifecycle::observe(|| home.generation(index, &cache, n));
        assert_eq!(
            counter(&cache, |c| c.memo_hits),
            hits,
            "{name}: {}",
            counters(&cache)
        );
        assert_eq!(
            counts.memo_miss_other + counts.memo_miss_exact_stamp,
            1,
            "{name}: {counts:?}"
        );
        if name == "shrink" {
            assert_eq!(counts.memo_miss_exact_stamp, 0, "{name}: {counts:?}");
        }
        assert_oracle(&home, &cache, &next, &scan, n, true, &[]);
        index = next;
        n += 1;
    }
    let _ = home.generation(index, &cache, n);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        1,
        "the last re-read is memoized again: {}",
        counters(&cache)
    );
}

/// T19 (R1-L3) and the T9 fences, at the digest: a tier-receipt content
/// change with the same `required` (Some → Some), the upload context, each
/// unscoped-incomplete census flag and the owner member count each change
/// the memo digest; the same inputs give the same digest.
#[test]
fn memo_digest_fences_receipt_contents_context_census_flags_and_members() {
    use crate::snapshots::codex_file_join::AppliedTierReceipt;
    let temp = Temp::new("memo-fence-digest", b"{\"n\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let candidate = CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/sessions"),
        path: PathBuf::from(format!(
            "/synthetic/sessions/rollout-2026-10-07T10-00-00-{SESSION}.jsonl"
        )),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "revision".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    let receipt = |tier: &str| -> AppliedTierReceipt {
        serde_json::from_value(json!({"version": 1, "derivation": "fixture",
            "scope": "fixture", "records": 3, "prefix_digest": "prefix",
            "tiers": {"turn-1": tier}}))
        .unwrap()
    };
    let with_receipt = |receipt: AppliedTierReceipt| {
        let mut index = ScanIndex::default();
        index.files.insert(
            local_index_key(&candidate.path),
            ScanIndexEntry {
                codex_fragment: None,
                size_bytes: 8,
                modified_unix_seconds: 0,
                modified_unix_nanos: None,
                source_file_fingerprint: "revision".into(),
                last_snapshot_fingerprint: None,
                last_upload_body_witness: None,
                effective_upload_body_witness_revision: 0,
                scan_identity_version: Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string()),
                codex_joined_member_set: None,
                codex_captured_joined_member_set: None,
                codex_protected_owner: None,
                codex_applied_tier_receipt: Some(receipt),
                codex_applied_tier_receipt_required: false,
                codex_captured_tier_receipt: None,
                codex_captured_tier_receipt_required: false,
                codex_captured_uncommitted: false,
                codex_counting_v2: false,
                codex_counting_owner: None,
                opened_changed_nanos: 0,
                opened_birth_nanos: 0,
                upload_context_receipt: None,
            },
        );
        index
    };
    let digest = |index: &ScanIndex, codex: &CodexTitleMetadata, members: usize| {
        memo_digest(
            index,
            &candidate,
            &file,
            "dependencies",
            codex,
            members,
            "counting",
        )
        .unwrap()
    };
    let codex = CodexTitleMetadata::default();
    let base = with_receipt(receipt("priority"));
    let reference = digest(&base, &codex, 1);
    assert_eq!(
        reference,
        digest(&with_receipt(receipt("priority")), &codex, 1)
    );
    assert_ne!(
        reference,
        digest(&with_receipt(receipt("flex")), &codex, 1),
        "T19: receipt contents"
    );
    let mut context = with_receipt(receipt("priority"));
    context.active_upload_context_fingerprint = Some("another-upload-context".into());
    assert_ne!(reference, digest(&context, &codex, 1), "upload context");
    let flags: [fn(&mut CodexTitleMetadata); 3] = [
        |codex| {
            codex
                .created_thread_census_failed_homes
                .insert(PathBuf::from("/failed-home"));
        },
        |codex| codex.state_census_unscoped_incomplete = true,
        |codex| codex.sidecar_census_unscoped_incomplete = true,
    ];
    for (n, flag) in flags.iter().enumerate() {
        let mut flipped = CodexTitleMetadata::default();
        flag(&mut flipped);
        assert_ne!(reference, digest(&base, &flipped, 1), "census flag {n}");
    }
    assert_ne!(reference, digest(&base, &codex, 2), "owner members");
}

/// T16: the memo has no clock input. The same unchanged hold collected a
/// week later hits with the same disclosure.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn memo_hit_a_week_later_is_the_same_hit() {
    let home = CreatedThreadHome::new(10, true);
    let cache = Arc::new(SharedCache::default());
    let (index, _) = home.generation(ScanIndex::default(), &cache, 0);
    let (index, day) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    let blocked = index.codex_state_only_blocked_session_ids.clone();
    let (index, week) = home.generation(index, &cache, 7 * 86_400);
    assert_eq!(counter(&cache, |c| c.memo_hits), 2, "{}", counters(&cache));
    assert_eq!(replayed_census(&week), replayed_census(&day));
    assert_eq!(index.codex_state_only_blocked_session_ids, blocked);
    assert!(created_usage(&week).is_empty());
}

const STATE_ONLY: &str = "01a05eed-49cf-7460-9fd7-f7dbfd2f05e4";
const LEGACY_ONLY: &str = "01a01e9a-49cf-7460-9fd7-f7dbfd2f05e4";

impl CreatedThreadHome {
    /// A state row with `tokens` and no rollout: a state-only thread.
    fn state_row(&self, id: &str, tokens: i64) {
        rusqlite::Connection::open(self.codex().join("state_5.sqlite"))
            .unwrap()
            .execute(
                "INSERT INTO threads VALUES (?1, 'Thread', ?2, 'user', 'Summarize', ?3, NULL)",
                rusqlite::params![id, tokens, self.base_ms],
            )
            .unwrap();
    }

    fn set_tokens(&self, id: &str, tokens: i64) {
        rusqlite::Connection::open(self.codex().join("state_5.sqlite"))
            .unwrap()
            .execute(
                "UPDATE threads SET tokens_used = ?2 WHERE id = ?1",
                rusqlite::params![id, tokens],
            )
            .unwrap();
    }

    /// The full body, its header with or without `forked_from_id`.
    fn body_with(&self, fork: bool) -> Vec<u8> {
        let mut header: Value = serde_json::from_slice(&self.body[0]).unwrap();
        let payload = header["payload"].as_object_mut().unwrap();
        if fork {
            payload.insert("forked_from_id".into(), json!(FORK_SOURCE));
        } else {
            payload.remove("forked_from_id");
        }
        let mut bytes = codex_line(header);
        bytes.extend(self.body[1..].concat());
        bytes
    }

    /// Rewrite the created thread's rollout and project it in full.
    fn rewrite(&self, fork: bool) {
        let body = self.body_with(fork);
        fs::write(&self.path, &body).unwrap();
        self.project(body.len(), self.body.len());
    }
}

/// State-only totals published by a generation: id → tokens.
fn state_only(scan: &SourceScanResult) -> BTreeMap<String, u64> {
    scan.snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.request_count == 0
                && snapshot.input_tokens == 0
                && snapshot.unattributed_total_tokens > 0
        })
        .map(|snapshot| {
            (
                snapshot.source_session_id.clone(),
                snapshot.unattributed_total_tokens,
            )
        })
        .collect()
}

/// C-T1/C-T2 after generation `n`, against a cold oracle of the same files:
/// - SB-T18: every attributed id is blocked;
/// - warm ⊇ cold on the blocked set outside the ids a published body covers
///   (cold's set there depends on page order around an acceptance); the
///   excess outside `legacy ∪ unattributed` is only ids attributed to a key
///   no longer on disk (class (e));
/// - warm publishes no state-only total cold does not, and withholds only
///   ids in that excess, `legacy` or `unattributed`.
///
/// Returns the excess and cold's state-only totals.
fn assert_warm_covers_cold(
    home: &CreatedThreadHome,
    cache: &SharedCache,
    index: &ScanIndex,
    scan: &SourceScanResult,
    n: i64,
) -> (BTreeSet<String>, BTreeMap<String, u64>) {
    let (oracle_index, oracle) = home.oracle(n);
    for (key, ids) in &index.codex_state_only_blocked_by_file {
        for id in ids {
            assert!(
                index.codex_state_only_blocked_session_ids.contains(id),
                "generation {n}: SB-T18 {key} attributes unblocked {id}"
            );
        }
    }
    let bodies = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .filter(|snapshot| snapshot.request_count > 0)
            .map(|snapshot| snapshot.source_session_id.clone())
            .collect::<BTreeSet<_>>()
    };
    let mut covered = bodies(scan);
    covered.extend(bodies(&oracle));
    for (key, entry) in &index.files {
        if entry.last_snapshot_fingerprint.is_some() {
            covered.extend(codex_session_id_candidates_from_path(Path::new(key)));
        }
    }
    let cold = oracle_index
        .codex_state_only_blocked_session_ids
        .difference(&covered)
        .cloned()
        .collect::<BTreeSet<_>>();
    let warm = index
        .codex_state_only_blocked_session_ids
        .difference(&covered)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        cold.is_subset(&warm),
        "generation {n}: warm {warm:?} does not cover cold {cold:?}: {}",
        counters(cache)
    );
    let excess = warm
        .difference(&cold)
        .filter(|id| {
            !index.codex_state_only_blocked_legacy.contains(*id)
                && !index.codex_state_only_blocked_unattributed.contains(*id)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    for id in &excess {
        assert!(
            index
                .codex_state_only_blocked_by_file
                .iter()
                .any(|(key, ids)| ids.contains(id) && !Path::new(key).exists()),
            "generation {n}: {id} over-blocked with no deleted holder: {:?}",
            index.codex_state_only_blocked_by_file
        );
    }
    let (warm_state, cold_state) = (state_only(scan), state_only(&oracle));
    for (id, tokens) in &warm_state {
        assert_eq!(
            cold_state.get(id),
            Some(tokens),
            "generation {n}: warm publishes {id} beyond cold"
        );
    }
    for id in cold_state.keys().filter(|id| !warm_state.contains_key(*id)) {
        assert!(
            excess.contains(id)
                || index.codex_state_only_blocked_legacy.contains(id)
                || index.codex_state_only_blocked_unattributed.contains(id),
            "generation {n}: warm withholds {id} outside the disclosed excess: {}",
            counters(cache)
        );
    }
    (excess, cold_state)
}

/// C-T1 (sweep): one home through nine generations; after each, warm covers
/// cold (see `assert_warm_covers_cold`). Generations: a held fork appears;
/// a memo hit; a second file blocks the same id; the first is cured and
/// publishes while the second still claims the id; the second is deleted;
/// the first is a held fork again; a memo hit; the held fork is deleted
/// (warm keeps its block, cold publishes the state total: class (e),
/// asserted); unchanged after that. Not in this sweep: the capture-boundary
/// revert, two-page, historical-replay and strict/park generations
/// (method-level `l_sb_*` tests in `snapshots.rs`).
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn warm_state_only_blocks_cover_cold_across_a_generation_sweep() {
    let home = CreatedThreadHome::new(10, true);
    home.set_tokens(CREATED, 50);
    home.state_row(STATE_ONLY, 70);
    let duplicate = home
        .fixture
        .root
        .join(format!("rollout-2026-10-07T11-00-00-{CREATED}.jsonl"));
    let cache = Arc::new(SharedCache::default());
    let run = |index: ScanIndex, n: i64| {
        let (index, scan) = home.generation(index, &cache, n);
        let (excess, cold_state) = assert_warm_covers_cold(&home, &cache, &index, &scan, n);
        (index, scan, excess, cold_state)
    };
    // (1) a held fork appears.
    let (index, scan, _, cold_state) = run(ScanIndex::default(), 0);
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert_eq!(
        (
            state_only(&scan).get(STATE_ONLY),
            cold_state.get(STATE_ONLY)
        ),
        (Some(&70), Some(&70)),
        "positive control: {}",
        counters(&cache)
    );
    // (2) a memo-hit generation.
    let (index, _, _, _) = run(index, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1, "{}", counters(&cache));
    // (3) a second file blocks the same id.
    fs::write(&duplicate, home.body_with(true)).unwrap();
    let (index, _, _, _) = run(index, 2);
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    // (4) the first file is cured and publishes; the second still claims it.
    home.rewrite(false);
    let (index, _, _, _) = run(index, 3);
    // (5) the second blocker is deleted.
    fs::remove_file(&duplicate).unwrap();
    let (index, _, _, _) = run(index, 4);
    // (6) the first file is a held fork again.
    home.rewrite(true);
    let (index, _, _, _) = run(index, 5);
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    // (7) a memo-hit generation.
    let hits = counter(&cache, |c| c.memo_hits);
    let (index, _, _, _) = run(index, 6);
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        hits + 1,
        "{}",
        counters(&cache)
    );
    // (8) the held fork is deleted: no retirement, so warm keeps its block
    // (class (e)) while cold publishes the state total.
    fs::remove_file(&home.path).unwrap();
    let (index, scan, _, cold_state) = run(index, 7);
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert!(!state_only(&scan).contains_key(CREATED));
    assert_eq!(cold_state.get(CREATED), Some(&50), "{}", counters(&cache));
    // (9) unchanged: still blocked, still never published.
    let (index, scan, _, _) = run(index, 8);
    assert!(index.codex_state_only_blocked_session_ids.contains(CREATED));
    assert!(!state_only(&scan).contains_key(CREATED));
}

/// C-T2 (legacy start): the C-T1 home from a pre-upgrade index (no
/// attribution, plus a legacy-only claim on a thread whose claimant is never
/// re-parsed). Legacy ids are never released by attribution; `legacy` never
/// grows; warm never publishes a state-only total cold does not (cold
/// publishes the legacy-only thread, warm withholds it). Class (h) is not
/// asserted as an equality.
#[test]
fn legacy_blocks_survive_attribution_from_a_pre_upgrade_index() {
    let home = CreatedThreadHome::new(10, true);
    home.set_tokens(CREATED, 50);
    home.state_row(STATE_ONLY, 70);
    home.state_row(LEGACY_ONLY, 30);
    let cache = Arc::new(SharedCache::default());
    let (mut index, _) = home.generation(ScanIndex::default(), &cache, 0);
    index.codex_state_only_blocked_by_file.clear();
    index.codex_state_only_blocked_unattributed.clear();
    index.codex_state_only_blocked_legacy.clear();
    index.codex_state_only_blocked_attributed = false;
    index
        .codex_state_only_blocked_session_ids
        .insert(LEGACY_ONLY.to_owned());
    let mut legacy = usize::MAX;
    for n in 1..=6 {
        match n {
            3 => home.rewrite(false),
            5 => home.rewrite(true),
            _ => {}
        }
        let (next, scan) = home.generation(index, &cache, n);
        let (_, cold_state) = assert_warm_covers_cold(&home, &cache, &next, &scan, n);
        assert!(next.codex_state_only_blocked_attributed);
        assert!(
            next.codex_state_only_blocked_legacy.contains(LEGACY_ONLY)
                && next
                    .codex_state_only_blocked_session_ids
                    .contains(LEGACY_ONLY),
            "generation {n}: {}",
            counters(&cache)
        );
        assert!(!state_only(&scan).contains_key(LEGACY_ONLY));
        assert_eq!(cold_state.get(LEGACY_ONLY), Some(&30), "generation {n}");
        assert!(
            next.codex_state_only_blocked_legacy.len() <= legacy,
            "generation {n}: legacy grew"
        );
        legacy = next.codex_state_only_blocked_legacy.len();
        index = next;
    }
}

// #641 join resource (H1-H9): J-T4c, J-T6..J-T11 and credit settlement.

const JOIN_OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const JOIN_OTHER: &str = "ffffffff-1111-4111-8111-ffffffffffff";

fn join_member(path: PathBuf) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/sessions"),
        path,
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}

fn join_members(names: &[&str]) -> Vec<CandidateFile> {
    names
        .iter()
        .map(|name| join_member(PathBuf::from(format!("/synthetic/sessions/{name}"))))
        .collect()
}

/// The members' exact `local_index_key`s joined by '\0'.
fn joined(members: &[CandidateFile]) -> String {
    members
        .iter()
        .map(|member| local_index_key(&member.path))
        .collect::<Vec<_>>()
        .join("\0")
}

fn join_entry(cache: &SharedCache, owner: &str) -> Option<String> {
    cache
        .with_cursor(|cursor| cursor.join_owners.get(owner).map(|(_, keys)| keys.clone()))
        .flatten()
}

/// The exact accounted size of one new entry (J-T10).
fn join_charge(owner: &str, members: &[CandidateFile]) -> usize {
    crate::heap_layout_bound::tree_node_bytes::<String, JoinProvenance>().unwrap()
        + owner.len()
        + joined(members).len()
}

/// The retained cache's own bound: admission keeps it beside the state.
fn retained_floor(cache: &SharedCache) -> usize {
    crate::heap_layout_bound::bound(&*cache.retained().unwrap(), usize::MAX).unwrap()
}

/// F4b: everything admission keeps beside the state and a charge: the
/// retained cache's own bound and the side ledger's fixed reservation.
fn admission_floor(cache: &SharedCache) -> usize {
    retained_floor(cache) + crate::snapshots::sampled_scan::side_ledger::SIDE_LEDGER_BYTES
}

/// Boundary requests must use the least cursor state admission can reach.
/// Real scan pages also warm optional header facts; those can yield before
/// provenance, witnesses or retained copies, and are not a mandatory floor.
/// Keep `cursor_resident` whole so no-eviction assertions still include them.
fn cursor_without_header_facts(cache: &SharedCache) -> usize {
    let headers = cache
        .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
        .unwrap();
    cache.cursor_resident().checked_sub(headers).unwrap()
}

/// Every release `release_join_owners` reports, with its member keys.
fn released(
    cache: &SharedCache,
    census: &BTreeSet<String>,
    keep: impl Fn(&str) -> bool,
) -> Vec<(String, Vec<String>)> {
    let mut released = Vec::new();
    cache.release_join_owners(census, keep, |owner, members| {
        released.push((owner.to_owned(), members.map(str::to_owned).collect()));
    });
    released
}

/// J-T4 (c): `keep` holds a queued or paused owner; without it the owner is
/// released exactly once with its exact member keys, and only when every
/// member left the census. Another owner's provenance survives.
#[test]
fn join_release_reports_exact_members_once_unless_kept() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let empty = cache.cursor_resident();
    let members = join_members(&["a.jsonl", "b.jsonl"]);
    let others = join_members(&["c.jsonl"]);
    cache.record_join_owner(JOIN_OWNER, &members);
    cache.record_join_owner(JOIN_OTHER, &others);
    let keys = members
        .iter()
        .map(|member| local_index_key(&member.path))
        .collect::<Vec<_>>();
    let census = BTreeSet::from([local_index_key(&others[0].path)]);
    assert!(released(&cache, &census, |owner| owner == JOIN_OWNER).is_empty());
    assert!(join_entry(&cache, JOIN_OWNER).is_some());
    // One member still in the census keeps it.
    let partial = BTreeSet::from([keys[0].clone(), local_index_key(&others[0].path)]);
    assert!(released(&cache, &partial, |_| false).is_empty());
    assert_eq!(
        released(&cache, &census, |_| false),
        vec![(JOIN_OWNER.to_owned(), keys)]
    );
    assert!(released(&cache, &census, |_| false).is_empty());
    assert_eq!(join_entry(&cache, JOIN_OWNER), None);
    assert_eq!(join_entry(&cache, JOIN_OTHER), Some(joined(&others)));
    assert_eq!(
        cache.cursor_resident(),
        empty + join_charge(JOIN_OTHER, &others)
    );
}

/// J-T11: a non-UTF-8 member key is built, measured and matched exactly as
/// `local_index_key`; empty, NUL-bearing and empty-list provenance is
/// refused before anything is reserved, and forgets an older entry.
#[test]
fn join_keys_match_local_index_key_and_malformed_ones_are_refused() {
    use std::os::unix::ffi::OsStrExt;
    let lossy = [
        &b"/synthetic/sessions/rollout-\xff.jsonl"[..],
        &b"/synthetic/sessions/rollout-\xff\xfe-\xe2\x82-x.jsonl"[..],
        &b"/synthetic/sessions/plain.jsonl"[..],
    ]
    .map(|bytes| PathBuf::from(std::ffi::OsStr::from_bytes(bytes)));
    for path in &lossy {
        let key = local_index_key(path);
        let mut built = String::new();
        push_join_key(&mut built, path);
        assert_eq!(built, key);
        assert_eq!(join_key_len(path), Some(key.len()));
        assert!(join_key_eq(&key, path));
        assert!(!join_key_eq(&key[..key.len() - 1], path));
        assert!(!join_key_eq(&format!("{key}x"), path));
    }
    let members = lossy.iter().cloned().map(join_member).collect::<Vec<_>>();
    assert!(same_join_members(&joined(&members), &members));
    assert!(!same_join_members(&joined(&members[..2]), &members));
    assert_eq!(join_keys_len(&members), Some(joined(&members).len()));
    let nul = PathBuf::from(std::ffi::OsStr::from_bytes(
        b"/synthetic/sessions/a\0b.jsonl",
    ));
    assert_eq!(join_key_len(&nul), None);
    assert_eq!(join_key_len(Path::new("")), None);
    assert_eq!(join_keys_len(&[]), None);
    for stored in ["", "a\0", "\0a", "a\0\0b"] {
        assert!(!join_members_well_formed(stored), "{stored:?}");
    }
    assert!(join_members_well_formed("a\0b"));
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let empty = cache.cursor_resident();
    cache.record_join_owner(JOIN_OWNER, &members);
    assert_eq!(join_entry(&cache, JOIN_OWNER), Some(joined(&members)));
    assert_eq!(
        cache.cursor_resident() - empty,
        join_charge(JOIN_OWNER, &members)
    );
    let malformed: [Vec<CandidateFile>; 3] = [
        vec![join_member(nul.clone())],
        vec![members[0].clone(), join_member(PathBuf::new())],
        Vec::new(),
    ];
    for members in &malformed {
        cache.record_join_owner(JOIN_OWNER, &members[..]);
        assert_eq!(join_entry(&cache, JOIN_OWNER), None);
        assert_eq!(cache.cursor_resident(), empty);
    }
    cache.record_join_owner("", &members);
    assert_eq!(join_entry(&cache, ""), None);
    assert_eq!(cache.cursor_resident(), empty);
    assert_eq!(cache.cursor_reserved(), 0);
    // Malformed or partial stored provenance is never released.
    cache.with_cursor(|cursor| {
        for (owner, stored) in [(JOIN_OWNER, ""), (JOIN_OTHER, "a\0")] {
            let used = cursor.tick();
            cursor
                .join_owners
                .insert(owner.to_owned(), (used, stored.to_owned()));
        }
    });
    assert!(released(&cache, &BTreeSet::new(), |_| false).is_empty());
    assert!(join_entry(&cache, JOIN_OWNER).is_some());
    assert!(join_entry(&cache, JOIN_OTHER).is_some());
}

/// J-T7: claim vs claim. An outstanding claim is charged like resident
/// state, so a second claim and optional provenance cannot spend its room;
/// settling and refunding each return it exactly once.
#[test]
fn outstanding_claim_blocks_a_second_claim_and_provenance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let floor = admission_floor(&cache);
    let state = cache.cursor_resident();
    let claim = 4096;
    let members = join_members(&["a.jsonl", "b.jsonl"]);
    with_test_state_budget(state + claim + floor, || {
        let credit = cache.cursor_reserve(claim).expect("the claim fits");
        assert_eq!(credit.bytes(), claim);
        assert_eq!(cache.cursor_reserved(), claim);
        assert_eq!(cache.cursor_resident(), state + claim);
        let second = cache.cursor_reserve(claim);
        assert!(second.is_none(), "the claimed room is spent once");
        assert_eq!(cache.cursor_reserved(), claim);
        cache.record_join_owner(JOIN_OTHER, &members);
        assert_eq!(join_entry(&cache, JOIN_OTHER), None);
        cache.with_cursor(|cursor| credit.settle(cursor)).unwrap();
        assert_eq!(cache.cursor_reserved(), 0);
        let credit = cache
            .cursor_reserve(claim)
            .expect("the settled room is free");
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
        assert_eq!(cache.cursor_resident(), state);
    });
}

/// R2-M1: an admission that cannot fit even after every eviction it may make
/// evicts nothing. A hopeless paused reserve (`JoinStateBound`) keeps both
/// provenance entries and the retained copy; optional provenance inside the
/// empty-retained floor window is refused and keeps the copy too.
#[test]
fn hopeless_admission_evicts_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const JOIN_THIRD: &str = "33333333-cccc-4ccc-8ccc-333333333333";
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        let copy = cache
            .take(&key)
            .unwrap_or_else(|| panic!("a certified copy: {}", counters(&cache)))
            .retained;
        // Measured with no retained copy and no provenance: the least an
        // admission could ever evict down to.
        let floor = admission_floor(&cache);
        let empty = cursor_without_header_facts(&cache);
        cache.insert(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: copy.checkpoint,
                reduction: Some(copy.state),
                released: None,
                unsealed: false,
            },
            0,
        );
        let members = join_members(&["a.jsonl", "b.jsonl"]);
        cache.record_join_owner(JOIN_OWNER, &members);
        cache.record_join_owner(JOIN_OTHER, &members);
        let intact = || {
            assert!(
                cache.retained_checkpoint(&key).is_some(),
                "the copy is kept"
            );
            for owner in [JOIN_OWNER, JOIN_OTHER] {
                assert_eq!(join_entry(&cache, owner), Some(joined(&members)), "{owner}");
            }
            assert_eq!(cache.cursor_reserved(), 0);
        };
        intact();
        let resident = cache.cursor_resident();
        // Fits the state with no provenance, never beside an empty retained
        // cache (before the fix: both entries and the copy were evicted).
        // Then a charge the state alone cannot hold.
        for hopeless in [STATE_BYTES - empty - floor + 1, STATE_BYTES] {
            assert!(cache.cursor_reserve(hopeless).is_none(), "{hopeless}");
            intact();
            assert_eq!(cache.cursor_resident(), resident);
        }
        // Optional twin: room for the claim, not for the claim and the floor.
        let claim = join_charge(JOIN_THIRD, &members);
        with_test_state_budget(
            cursor_without_header_facts(&cache) + claim + floor - 1,
            || {
                cache.record_join_owner(JOIN_THIRD, &members);
            },
        );
        assert_eq!(join_entry(&cache, JOIN_THIRD), None);
        intact();
        assert_eq!(cache.cursor_resident(), resident);
        // Control: a reserve that fits once provenance is forgotten still
        // goes on (baseline progress), now that it is feasible.
        let credit = cache
            .cursor_reserve(STATE_BYTES - empty - floor)
            .expect("feasible after forgetting provenance and copies");
        assert_eq!(join_entry(&cache, JOIN_OWNER), None);
        assert_eq!(join_entry(&cache, JOIN_OTHER), None);
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// J-T8: claim vs retained insert. The insert measures outstanding claims
/// under the retained lock, so a copy that fits only if the claim is
/// ignored is not kept.
#[test]
fn outstanding_claim_is_charged_against_a_retained_insert() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        let copy = cache
            .take(&key)
            .unwrap_or_else(|| panic!("a certified copy: {}", counters(&cache)))
            .retained;
        let completed = |copy: crate::transcript_cache::Retained<_>| {
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: copy.checkpoint,
                reduction: Some(copy.state),
                released: None,
                unsealed: false,
            }
        };
        // Control: without a claim the copy fits.
        cache.insert(key.clone(), completed(copy), 0);
        assert!(cache.retained_checkpoint(&key).is_some());
        // F4b: the side ledger's reservation is part of the floor.
        let with_copy = admission_floor(&cache);
        let state = cursor_without_header_facts(&cache);
        assert!(with_copy + state <= STATE_BYTES);
        let copy = cache.take(&key).expect("retained").retained;
        // F4b exact boundary: a claim that leaves exactly the copy's room
        // beside the side ledger's reservation; the copy is kept.
        let exact = STATE_BYTES - state - with_copy;
        let credit = cache.cursor_reserve(exact).expect("the claim fits alone");
        cache.insert(key.clone(), completed(copy), 0);
        assert!(
            cache.retained_checkpoint(&key).is_some(),
            "kept at the boundary"
        );
        assert_eq!(
            admission_floor(&cache) + cache.cursor_resident(),
            STATE_BYTES
        );
        credit.refund();
        let copy = cache.take(&key).expect("retained").retained;
        // A claim that leaves one byte too few for it.
        let claim = exact + 1;
        let credit = cache.cursor_reserve(claim).expect("the claim fits alone");
        cache.insert(key.clone(), completed(copy), 0);
        assert!(cache.retained_checkpoint(&key).is_none(), "refused");
        assert!(admission_floor(&cache) + cache.cursor_resident() <= STATE_BYTES);
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// J-T9: one lock order (retained, then cursor) and no recursive cursor
/// locking, checked in debug builds before any lock is taken.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "cursor lock taken while this thread holds it")]
fn nested_cursor_lock_is_refused() {
    let cache = SharedCache::default();
    cache.with_cursor(|_| cache.with_cursor(|_| ()));
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "retained lock taken under the cursor lock")]
fn retained_lock_under_the_cursor_lock_is_refused() {
    let cache = SharedCache::default();
    cache.with_cursor(|_| drop(cache.retained()));
}

/// J-T9 control and settlement: `cursor_reserve` takes retained, then
/// cursor; a credit unwound outside the lock refunds itself; one unwound
/// inside a cursor closure does not relock; the held flag resets on every
/// unwind; a poisoned cursor admits nothing and strands nothing.
#[test]
fn credits_settle_once_on_every_path() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let credit = cache.cursor_reserve(64).expect("room");
    assert_eq!(cache.cursor_reserved(), 64);
    credit.refund();
    assert_eq!(cache.cursor_reserved(), 0);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _credit = cache.cursor_reserve(64).expect("room");
        assert_eq!(cache.cursor_reserved(), 64);
        panic!("unwind with an outstanding credit");
    }));
    assert!(unwound.is_err());
    assert!(!cursor_held());
    assert_eq!(
        cache.cursor_reserved(),
        0,
        "dropped while unwinding: refunded"
    );
    let stranded = cache.cursor_reserve(64).expect("room");
    let inside = cache.cursor_reserve(64).expect("room");
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        cache.with_cursor(move |_| {
            let _inside = inside;
            panic!("poison the cursor");
        });
    }));
    assert!(unwound.is_err());
    assert!(!cursor_held(), "reset on unwind");
    // Poisoned: measured as the whole budget; admits and settles nothing.
    assert_eq!(cache.cursor_reserved(), usize::MAX);
    assert_eq!(cache.cursor_resident(), STATE_BYTES);
    assert!(cache.cursor_reserve(1).is_none());
    stranded.refund();
    cache.record_join_owner(JOIN_OWNER, &join_members(&["a.jsonl"]));
    assert!(released(&cache, &BTreeSet::new(), |_| false).is_empty());
}

/// Corrupt credit accounting (a claim that is not outstanding, or one
/// against another state) fails closed: the state measures unbounded.
#[test]
fn corrupt_credit_accounting_fails_closed() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    for wrong_state in [false, true] {
        let cache = Arc::new(SharedCache::default());
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            cache.with_cursor(|cursor| {
                let id = cursor.id + u64::from(wrong_state);
                cursor.reserved = usize::from(wrong_state);
                settle_claim(cursor, id, 1);
            });
        }));
        assert_eq!(unwound.is_err(), cfg!(debug_assertions));
        assert!(!cursor_held());
        assert_eq!(cache.cursor_reserved(), usize::MAX);
        assert_eq!(cache.cursor_resident(), STATE_BYTES);
        assert!(cache.cursor_reserve(1).is_none());
    }
}

// PR-P: parent witnesses, the restart table and held parent causes.

fn absent_witness() -> ParentWitness {
    ParentWitness {
        cause: CodexParentUnresolvable::Absent,
        identity: None,
        waits_on: None,
    }
}

/// The witness keys of `namespace`, read without touching anything.
fn witness_keys(cache: &SharedCache, namespace: &str) -> Vec<String> {
    cache
        .with_cursor(|cursor| {
            cursor
                .parents
                .get(namespace)
                .map(|entry| entry.witnesses.entries.keys().cloned().collect())
                .unwrap_or_default()
        })
        .unwrap()
}

/// A namespace's whole parent entry: scope, match mark and every witness
/// with its stored charge.
type WitnessEntry = (
    String,
    Option<(String, u64)>,
    Vec<(String, ParentWitness, usize)>,
);

/// `namespace`'s whole parent entry, read without touching anything.
fn witness_entry(cache: &SharedCache, namespace: &str) -> Option<WitnessEntry> {
    cache
        .with_cursor(|cursor| {
            cursor.parents.get(namespace).map(|entry| {
                (
                    entry.scope.clone(),
                    entry.matched.clone(),
                    entry
                        .witnesses
                        .entries
                        .iter()
                        .map(|(parent, (witness, charge))| {
                            (parent.clone(), witness.clone(), *charge)
                        })
                        .collect(),
                )
            })
        })
        .unwrap()
}

/// `namespace`'s RAM witness of `parent`, read without touching anything.
fn witness_of(cache: &SharedCache, namespace: &str, parent: &str) -> Option<ParentWitness> {
    cache
        .with_cursor(|cursor| {
            cursor
                .parents
                .get(namespace)
                .and_then(|entry| entry.witnesses.entries.get(parent))
                .map(|(witness, _)| witness.clone())
        })
        .unwrap()
}

/// P-T26 (L4, cache level): the inline table holds `ROTATION_KEYS` pairs.
/// An evicting insert starts spent, and so does an evicted pair that comes
/// back: no restart is ever refilled. `parent_state` never inserts into
/// `parents`, and 20 later pages of another namespace change nothing.
#[test]
fn evicted_restart_slot_reenters_spent() {
    let cache = SharedCache::default();
    let first = Scope("namespace-00".into());
    assert_eq!(cache.parent_state(&first, "scope").restarts, 0);
    assert_eq!(cache.note_parent_restart(&first, "scope"), Some(1));
    for n in 1..ROTATION_KEYS {
        cache.with_cursor(|cursor| cursor.rotation.page += 1);
        let namespace = Scope(format!("namespace-{n:02}"));
        assert_eq!(cache.parent_state(&namespace, "scope").restarts, 0);
    }
    assert_eq!(counter(&cache, |c| c.parent_restart_slot_evicted), 0);
    cache.with_cursor(|cursor| cursor.rotation.page += 1);
    let last = Scope("namespace-64".into());
    assert_eq!(
        cache.parent_state(&last, "scope").restarts,
        PARENT_RESTART_BUDGET,
        "an evicting insert starts spent"
    );
    assert_eq!(counter(&cache, |c| c.parent_restart_slot_evicted), 1);
    cache.with_cursor(|cursor| cursor.rotation.page += 1);
    assert_eq!(
        cache.parent_state(&first, "scope").restarts,
        PARENT_RESTART_BUDGET,
        "the evicted pair re-enters spent"
    );
    assert_eq!(counter(&cache, |c| c.parent_restart_slot_evicted), 2);
    for _ in 0..20 {
        cache.with_cursor(|cursor| cursor.rotation.page += 1);
        assert_eq!(
            cache.parent_state(&last, "scope").restarts,
            PARENT_RESTART_BUDGET
        );
    }
    assert_eq!(
        cache.note_parent_restart(&first, "scope"),
        Some(PARENT_RESTART_BUDGET + 1),
        "counted, never reset"
    );
    assert!(cache
        .with_cursor(|cursor| cursor.parents.is_empty())
        .unwrap());
}

/// P-T17 (R2-L4): 5,000 witnesses across 80 namespaces under the production
/// budget stay inside the state budget (at most `ROTATION_KEYS` namespace
/// entries), and a paused job's mandatory reserve still gets its room by
/// forgetting them.
#[test]
fn many_witnesses_stay_bounded_and_yield_to_a_paused_job() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let floor = admission_floor(&cache);
    let empty = cache.cursor_resident();
    for n in 0..5_000_u64 {
        if n % 64 == 0 {
            cache.with_cursor(|cursor| cursor.rotation.page += 1);
        }
        let namespace = Scope(format!("namespace-{:02}", n % 80));
        cache.witness_parent(
            &namespace,
            "scope",
            &format!("parent-{n:05}"),
            ParentWitness {
                cause: CodexParentUnresolvable::ParentHeld,
                identity: Some(format!("identity-{n}")),
                waits_on: None,
            },
        );
    }
    assert!(cache.cursor_resident() < STATE_BYTES);
    assert!(cache.with_cursor(|cursor| cursor.parents.len()).unwrap() <= ROTATION_KEYS);
    assert!(counter(&cache, |c| c.parent_namespace_refused) > 0);
    let credit = cache
        .cursor_reserve(STATE_BYTES - empty - floor)
        .unwrap_or_else(|| panic!("the paused job's room: {}", counters(&cache)));
    assert!(counter(&cache, |c| c.parent_witness_evicted) > 0);
    assert!(cache
        .with_cursor(|cursor| cursor.parents.is_empty())
        .unwrap());
    credit.refund();
    assert_eq!(cache.cursor_reserved(), 0);
    assert_eq!(cache.cursor_resident(), empty);
}

/// #643 intake ruling (a), N2: an optional witness or match mark for a new
/// 65th namespace is refused before admission and changes nothing retained:
/// the 64 namespaces keep their entries, witnesses and marks, and the
/// newcomer gets no settling witness and no match mark, so step start applies
/// nothing to it and its parent stays owed (re-read, fail-closed). An existing
/// namespace's update and a mandatory admission's eviction are unchanged.
#[test]
fn optional_65th_namespace_is_refused_and_the_retained_64_are_kept() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let floor = admission_floor(&cache);
    let empty = cache.cursor_resident();
    let namespace = |n: usize| Scope(format!("namespace-{n:02}"));
    for n in 0..ROTATION_KEYS {
        cache.with_cursor(|cursor| cursor.rotation.page += 1);
        assert!(cache.witness_parent(&namespace(n), "scope", PARENT, absent_witness()));
        cache.mark_parents_matched(&namespace(n), "scope", "window-end", 0);
    }
    let retained = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| {
                cursor
                    .parents
                    .iter()
                    .map(|(key, entry)| {
                        (
                            key.clone(),
                            entry.scope.clone(),
                            entry.touched,
                            entry.matched.clone(),
                            entry
                                .witnesses
                                .entries
                                .iter()
                                .map(|(parent, (witness, charge))| {
                                    (parent.clone(), witness.clone(), *charge)
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap()
    };
    let before = retained(&cache);
    assert_eq!(before.len(), ROTATION_KEYS);
    let resident = cache.cursor_resident();
    let newcomer = namespace(ROTATION_KEYS);
    cache.with_cursor(|cursor| cursor.rotation.page += 1);
    assert!(!cache.witness_parent(&newcomer, "scope", PARENT, absent_witness()));
    cache.mark_parents_matched(&newcomer, "scope", "window-end", 0);
    assert_eq!(retained(&cache), before, "the retained 64 are unchanged");
    assert_eq!(cache.cursor_resident(), resident);
    assert_eq!(counter(&cache, |c| c.parent_namespace_refused), 2);
    assert_eq!(counter(&cache, |c| c.parent_witness_refused), 1);
    assert_eq!(counter(&cache, |c| c.parent_match_unmarked), 1);
    let state = cache.parent_state(&newcomer, "scope");
    assert!(
        state.witnesses.is_empty() && state.matched.is_none(),
        "the overflow stays owed"
    );
    // An existing namespace still takes an update past the count bound.
    assert!(cache.witness_parent(&namespace(0), "scope", "another-parent", absent_witness()));
    assert_eq!(counter(&cache, |c| c.parent_namespace_refused), 2);
    // A mandatory admission still forgets witnesses for its room.
    let credit = cache
        .cursor_reserve(STATE_BYTES - empty - floor)
        .unwrap_or_else(|| panic!("the paused job's room: {}", counters(&cache)));
    assert!(cache
        .with_cursor(|cursor| cursor.parents.is_empty())
        .unwrap());
    credit.refund();
}

const WITNESS_NAMESPACES: [&str; 2] = ["witness-namespace-1", "witness-namespace-2"];
const WITNESS_KEYS: [&str; 2] = ["parent-a", "parent-b"];

/// #641's `hopeless_admission_evicts_nothing` setup with witnesses: a real
/// certified retained copy, `floor` and `empty` measured with no copy, no
/// provenance and no witnesses, then two provenance entries and two
/// witnesses in each of two namespaces (namespace 1 strictly older).
struct WitnessAdmission {
    _fixture: ScanRoot,
    cache: Arc<SharedCache>,
    key: String,
    members: Vec<CandidateFile>,
    floor: usize,
    empty: usize,
}

fn witness_admission() -> WitnessAdmission {
    let fixture = ScanRoot::new(40);
    let key = local_index_key(&fixture.file(SESSION));
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    for _ in 0..64 {
        let (next, _, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
        index = next;
        if counter(&cache, |c| c.jobs_certified) == 1 {
            break;
        }
    }
    let copy = cache
        .take(&key)
        .unwrap_or_else(|| panic!("a certified copy: {}", counters(&cache)))
        .retained;
    let floor = admission_floor(&cache);
    let empty = cursor_without_header_facts(&cache);
    // A single-session root has no parent refs: no `parents` entry exists.
    assert!(cache
        .with_cursor(|cursor| cursor.parents.is_empty())
        .unwrap());
    cache.insert(
        key.clone(),
        sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: copy.checkpoint,
            reduction: Some(copy.state),
            released: None,
            unsealed: false,
        },
        0,
    );
    let members = join_members(&["a.jsonl", "b.jsonl"]);
    cache.record_join_owner(JOIN_OWNER, &members);
    cache.record_join_owner(JOIN_OTHER, &members);
    for namespace in WITNESS_NAMESPACES {
        for parent in WITNESS_KEYS {
            assert!(cache.witness_parent(
                &Scope(namespace.into()),
                "scope",
                parent,
                absent_witness()
            ));
        }
        cache.with_cursor(|cursor| cursor.rotation.page += 1);
    }
    WitnessAdmission {
        _fixture: fixture,
        cache,
        key,
        members,
        floor,
        empty,
    }
}

/// P-T37 (the witness twin of `hopeless_admission_evicts_nothing`): a
/// hopeless reserve keeps every witness, provenance entry and the retained
/// copy, byte for byte; an optional witness inside the floor window is
/// refused and keeps them too. A reserve that fits once both provenance
/// entries and exactly one witness are forgotten forgets exactly that one:
/// the oldest namespace's first key.
#[test]
fn hopeless_admission_keeps_every_witness() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let setup = witness_admission();
        let cache = &setup.cache;
        // R2-L4: every witness value, charge, scope and match mark, not
        // only the keys.
        let entries = WITNESS_NAMESPACES.map(|namespace| witness_entry(cache, namespace));
        assert!(entries.iter().all(Option::is_some));
        let intact = || {
            assert!(
                cache.retained_checkpoint(&setup.key).is_some(),
                "the copy is kept"
            );
            for owner in [JOIN_OWNER, JOIN_OTHER] {
                assert_eq!(
                    join_entry(cache, owner),
                    Some(joined(&setup.members)),
                    "{owner}"
                );
            }
            for namespace in WITNESS_NAMESPACES {
                assert_eq!(witness_keys(cache, namespace), WITNESS_KEYS, "{namespace}");
            }
            assert_eq!(
                WITNESS_NAMESPACES.map(|namespace| witness_entry(cache, namespace)),
                entries
            );
            assert_eq!(counter(cache, |c| c.parent_witness_evicted), 0);
            assert_eq!(cache.cursor_reserved(), 0);
        };
        intact();
        let resident = cache.cursor_resident();
        for hopeless in [STATE_BYTES - setup.empty - setup.floor + 1, STATE_BYTES] {
            assert!(cache.cursor_reserve(hopeless).is_none(), "{hopeless}");
            intact();
            assert_eq!(cache.cursor_resident(), resident);
        }
        // Optional twin: a third namespace inside the floor window.
        let refused = counter(cache, |c| c.parent_witness_refused);
        with_test_state_budget(cursor_without_header_facts(cache) + setup.floor + 1, || {
            assert!(!cache.witness_parent(
                &Scope("witness-namespace-3".into()),
                "scope",
                "parent-c",
                absent_witness()
            ));
        });
        assert_eq!(counter(cache, |c| c.parent_witness_refused), refused + 1);
        intact();
        assert_eq!(cache.cursor_resident(), resident);
        // Proportional: room once both provenance entries and exactly one
        // witness (its node and key) are forgotten.
        let node =
            crate::heap_layout_bound::tree_node_bytes::<String, (ParentWitness, usize)>().unwrap();
        let after = cursor_without_header_facts(cache)
            - join_charge(JOIN_OWNER, &setup.members)
            - join_charge(JOIN_OTHER, &setup.members)
            - node
            - WITNESS_KEYS[0].len();
        let credit = cache
            .cursor_reserve(STATE_BYTES - setup.floor - after)
            .unwrap_or_else(|| panic!("fits after one witness: {}", counters(cache)));
        assert_eq!(counter(cache, |c| c.parent_witness_evicted), 1);
        assert_eq!(join_entry(cache, JOIN_OWNER), None);
        assert_eq!(join_entry(cache, JOIN_OTHER), None);
        assert_eq!(
            witness_keys(cache, WITNESS_NAMESPACES[0]),
            [WITNESS_KEYS[1]]
        );
        assert_eq!(witness_keys(cache, WITNESS_NAMESPACES[1]), WITNESS_KEYS);
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// P-T37's feasible control (and P-T26b's feasible variant), on a fresh
/// setup: a reserve that fits only once provenance and every witness are
/// forgotten forgets them all and succeeds; both namespace entries go.
#[test]
fn feasible_reserve_forgets_provenance_then_witnesses() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let setup = witness_admission();
        let cache = &setup.cache;
        let credit = cache
            .cursor_reserve(STATE_BYTES - setup.empty - setup.floor)
            .unwrap_or_else(|| panic!("feasible: {}", counters(cache)));
        assert_eq!(join_entry(cache, JOIN_OWNER), None);
        assert_eq!(join_entry(cache, JOIN_OTHER), None);
        assert_eq!(counter(cache, |c| c.parent_witness_evicted), 4);
        assert!(cache
            .with_cursor(|cursor| cursor.parents.is_empty())
            .unwrap());
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// P-T5/P-T33b (D2): with the ref set full, a new fork's ref does not fit,
/// so the fork is held `DeferredRef` (counted, never published) with no
/// restart, and memo-hits from its second generation. Once refs leave the
/// set it resolves as a cold scan does.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn full_ref_set_holds_a_new_fork_deferred_ref_without_restart() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    for n in 0..crate::snapshots::MAX_CODEX_PARENT_LEDGER_REFS {
        index
            .codex_parent_ownership_refs
            .insert(format!("prefilled-{n:03}"));
    }
    let mut hits = Vec::new();
    for n in 0..3 {
        let (next, scan) = home.generation(index, &cache, n);
        assert!(session_usage(&scan, CHILD).is_empty());
        assert!(!next.codex_parent_ownership_refs.contains(PARENT));
        // [behaviour] A refused global parent-ref request is locally visible.
        if n == 0 {
            assert!(scan.cap_counts.parent_ref_refusals > 0);
        }
        assert_eq!(restarts_in_scope(&scan), Some(0), "generation {n}");
        assert_eq!(
            parent_causes(&scan),
            only(CodexParentUnresolvable::DeferredRef, 1),
            "generation {n}: {}",
            counters(&cache)
        );
        hits.push(counter(&cache, |c| c.memo_hits));
        index = next;
    }
    assert_eq!(hits[2] - hits[1], 1, "{}", counters(&cache));
    index
        .codex_parent_ownership_refs
        .retain(|parent| !parent.starts_with("prefilled-"));
    let (index, settled, n) = home.settle(index, &cache, 3);
    assert_eq!(
        parent_causes(&settled),
        only(CodexParentUnresolvable::Absent, 0)
    );
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// Fix round 6 (R1-F1): the proof hook's `Proven` transition for C over P,
/// on the page's own index (census keys): C's proof as the job mints it (m
/// = the leading signatures C shares with P's `parent_records`, the chain
/// over C's s_0..s_m, P at `parent` sealed now under the proof scope), P's
/// settled side record covering it, and C's hold memo forgotten
/// (`forget_proven_hold_memos`). Returns C's key.
fn prove_child(
    scan: &mut OwnedSourceScan,
    cache: &SharedCache,
    parent: &Path,
    parent_records: &[Value],
    child: &Path,
    child_records: &[Value],
) -> String {
    use crate::snapshots::codex_parent_proof_use_tests::seal_of;
    use crate::snapshots::{
        codex_digest_hex, codex_ownership_signature, codex_parent_prefix_chain,
        codex_parent_prefix_seed, codex_parent_proof_scope, codex_parent_side_scope,
        CodexParentPrefixProof, CodexParentProofState, CodexParentSide, SideVerdict,
    };
    let census_key = |path: &Path| {
        let name = file_name(path);
        scan.index
            .traversal
            .as_ref()
            .and_then(|traversal| {
                traversal
                    .codex_rollout_paths
                    .iter()
                    .find(|key| key.ends_with(name.as_str()))
                    .cloned()
            })
            .expect("in the census")
    };
    let (p_key, c_key) = (census_key(parent), census_key(child));
    let signatures = |records: &[Value]| {
        records
            .iter()
            .filter_map(codex_ownership_signature)
            .collect::<Vec<_>>()
    };
    let (theirs, ours) = (signatures(parent_records), signatures(child_records));
    let matched = theirs
        .iter()
        .zip(&ours)
        .take_while(|(parent, child)| parent == child)
        .count();
    let mut digest = codex_parent_prefix_seed();
    for signature in &ours[..=matched] {
        digest = codex_parent_prefix_chain(&digest, signature);
    }
    let file = File::open(parent).unwrap();
    let now = crate::snapshots::sampled_scan::now_seconds();
    scan.index.codex_parent_prefix_proofs.insert(
        c_key.clone(),
        CodexParentProofState::Proven(CodexParentPrefixProof {
            parent: PARENT.into(),
            parent_seal: seal_of(&file, now, &codex_parent_proof_scope().0),
            matched: matched as u64,
            child_digest: codex_digest_hex(&digest),
            owned: matched > 0,
            published: false,
        }),
    );
    scan.index.codex_parent_side.insert(
        p_key,
        CodexParentSide {
            verdict: SideVerdict::Settled,
            seal: seal_of(&file, now, &codex_parent_side_scope().0),
            parsed: OpenStamp::capture(&file).unwrap(),
            pace: None,
            generation: 1,
            referenced_epoch: 0,
        },
    );
    cache.memo_forget(&memo_key(&Scope("cursor-fixture".into()), &c_key));
    c_key
}

/// Fix round 6 (R1-F1, control A): with the ref set full, C's parser is
/// built while C is owed (no install), and C's proof turns `Proven` before
/// C's parse completes (production: a cursor job paused across the hook's
/// page; here: between two step calls of C's parse, so the record site sees
/// the same state). C completes pending, is deferred `DeferredRef` with no
/// step-map witness and held, and that hold is not memoized; the next page
/// parses C, installs the proof and C resolves. Before fix round 6 the hold
/// was memoized and replayed on every later page.
#[test]
fn a_deferred_ref_hold_built_before_its_proof_is_not_memoized() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::CodexParentProofState;
    use CodexParentUnresolvable::DeferredRef;
    let home = ForkHome::new(&ForkHome::matching_child());
    let mut index = ScanIndex::default();
    for n in 0..crate::snapshots::MAX_CODEX_PARENT_LEDGER_REFS {
        index
            .codex_parent_ownership_refs
            .insert(format!("prefilled-{n:03}"));
    }
    let (mut index, owed) = home.generation(index, &Arc::new(SharedCache::default()), 0);
    assert!(session_usage(&owed, CHILD).is_empty());
    assert_eq!(parent_causes(&owed), only(DeferredRef, 1));

    // A fresh cache, so C is parsed (no hold memo).
    let cache = Arc::new(SharedCache::default());
    let (parent, child) = (home.fixture.file(PARENT), home.fixture.file(CHILD));
    let mut key = None;
    index.traversal = None;
    let ((index, held), parsed) = parses(|| {
        page_between(&home.fixture, index, &cache, &collected_at(1), |scan| {
            if key.is_none() && active_is(scan, &child) {
                key = Some(prove_child(
                    scan,
                    &cache,
                    &parent,
                    &ForkHome::parent(),
                    &child,
                    &ForkHome::matching_child(),
                ));
            }
        })
    });
    let key = key.expect("C's parse spans step calls");
    assert!(parsed.contains(&file_name(&child)), "{parsed:?}");
    assert!(session_usage(&held, CHILD).is_empty());
    assert_eq!(
        parent_causes(&held),
        only(DeferredRef, 1),
        "{}",
        counters(&cache)
    );
    assert!(matches!(
        index.codex_parent_prefix_proofs.get(&key),
        Some(CodexParentProofState::Proven(_))
    ));
    assert_eq!(
        counter(&cache, |c| c.memo_records),
        0,
        "the hold is not memoized: {}",
        counters(&cache)
    );
    assert!(home.child_entry(&cache).is_none());

    // The next page parses C, installs the proof, and C resolves.
    let ((_, resolved), parsed) = parses(|| home.generation(index, &cache, 2));
    assert!(parsed.contains(&file_name(&child)), "{parsed:?}");
    assert_eq!(
        session_usage(&resolved, CHILD),
        vec![(30, 1)],
        "{}",
        counters(&cache)
    );
    assert_eq!(parent_causes(&resolved), only(DeferredRef, 0));
}

/// P-T14 (M1): the step-start match runs once per traversal: one census
/// pass per generation here (each generation is one traversal and one
/// page), and the namespace is marked matched for exactly that traversal,
/// so a later page of it re-applies without matching.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn step_start_matches_once_per_traversal() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    fs::rename(
        home.fixture.file(PARENT),
        home.fixture.root.parent().unwrap().join("parent-away"),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let (mut index, _) = home.generation(ScanIndex::default(), &cache, 0);
    for n in 1..4 {
        let before = crate::snapshots::codex_parent_step_start_matches_for_test();
        let (next, _) = home.generation(index, &cache, n);
        assert_eq!(
            crate::snapshots::codex_parent_step_start_matches_for_test() - before,
            1,
            "generation {n}"
        );
        // The completed traversal's census window end is this page's.
        let end = Some(collected_at(n));
        let matched = cache
            .with_cursor(|cursor| {
                cursor
                    .parents
                    .get("cursor-fixture")
                    .and_then(|entry| entry.matched.clone())
            })
            .unwrap();
        assert_eq!(matched.map(|(at, _)| at), end, "generation {n}");
        index = next;
    }
}

/// P-T35 (L3, N3): referenced id A's only rollout is a file named A whose
/// `session_meta` id is B, and a fork of B has no file named B. A is
/// witnessed `NoLedger` at that file's identity and B `Absent`; each child
/// is held under its parent's cause. From then on nothing is parsed. An
/// append to the file drops A's witness and the file is read again.
/// (Rev 5's admitted-B variant is dropped per the lease's N3.)
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn misnamed_parent_rollout_witnesses_no_ledger_and_absent() {
    const A: &str = "019fa111-2222-7333-8444-cccccccccccc";
    const B: &str = "019fa111-2222-7333-8444-dddddddddddd";
    const CHILD_A: &str = "019fa111-2222-7333-8444-eeeeeeeeeeee";
    const CHILD_B: &str = "019fa111-2222-7333-8444-ffffffffffff";
    let fixture = ScanRoot::with_sessions(&[]);
    let mut misnamed = ForkHome::parent();
    misnamed[0] = json!({"timestamp": "2026-10-07T08:00:00Z", "type": "session_meta",
        "payload": {"id": B, "thread_source": "user"}});
    fs::write(fixture.file(A), jsonl(&misnamed)).unwrap();
    for (child, parent) in [(CHILD_A, A), (CHILD_B, B)] {
        let mut records = vec![json!({"timestamp": "2026-10-07T08:20:00Z",
            "type": "session_meta",
            "payload": {"id": child, "forked_from_id": parent, "thread_source": "user"}})];
        records.extend(ForkHome::diverging_child(2));
        fs::write(fixture.file(child), jsonl(&records)).unwrap();
    }
    let cache = Arc::new(SharedCache::default());
    let generation = |index: ScanIndex, n: u64| {
        let mut index = index;
        index.traversal = None;
        let (index, scan, _) = page_with(
            &fixture,
            index,
            Some(Arc::clone(&cache)),
            "cursor-fixture",
            &collected_at(n),
            |_| {},
        );
        (index, scan)
    };
    let mut expected = [0; PARENT_UNRESOLVABLE_CAUSES];
    expected[CodexParentUnresolvable::NoLedger.index()] = 1;
    expected[CodexParentUnresolvable::Absent.index()] = 1;
    let mut index = ScanIndex::default();
    let mut held_at = None;
    for n in 0..4 {
        let (next, scan) = generation(index, n);
        index = next;
        assert!(restarts_in_scope(&scan).is_some_and(|restarts| restarts <= PARENT_RESTART_BUDGET));
        if parent_causes(&scan) == expected {
            held_at = Some(n);
            break;
        }
    }
    let held_at = held_at.unwrap_or_else(|| panic!("both children held: {}", counters(&cache)));
    assert!(held_at <= 2, "{held_at}");
    assert!(!index.codex_parent_ownership_ledgers.contains_key(B));
    assert!(!index
        .codex_parent_ownership_ledgers
        .get(A)
        .is_some_and(|ledger| ledger.scan_complete));
    for n in held_at + 1..held_at + 3 {
        let ((next, scan), parsed) = parses(|| generation(index, n));
        assert!(parsed.is_empty(), "generation {n}: {parsed:?}");
        assert_eq!(parent_causes(&scan), expected, "generation {n}");
        index = next;
    }
    fixture.append(
        A,
        &jsonl(&[turn_record("2026-10-07T09:00:01Z", "appended")]),
    );
    let n = held_at + 3;
    let (_, parsed) = parses(|| generation(index, n));
    let name = fixture
        .file(A)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(parsed.contains(&name), "{parsed:?}");
}

/// One cached generation of `fixture` (a fresh traversal at page `n`).
fn fixture_generation(
    fixture: &ScanRoot,
    cache: &Arc<SharedCache>,
    index: ScanIndex,
    n: u64,
) -> (ScanIndex, SourceScanResult) {
    let mut index = index;
    index.traversal = None;
    let (index, scan, _) = page_with(
        fixture,
        index,
        Some(Arc::clone(cache)),
        "cursor-fixture",
        &collected_at(n),
        |_| {},
    );
    (index, scan)
}

/// A rollout of `id`, optionally a fork of `parent`, with `records` after
/// its `session_meta`.
fn write_rollout(fixture: &ScanRoot, id: &str, parent: Option<&str>, records: &[Value]) {
    let mut payload = json!({"id": id, "thread_source": "user"});
    if let Some(parent) = parent {
        payload["forked_from_id"] = json!(parent);
    }
    let mut all = vec![json!({"timestamp": "2026-10-07T08:00:00Z",
        "type": "session_meta", "payload": payload})];
    all.extend_from_slice(records);
    fs::write(fixture.file(id), jsonl(&all)).unwrap();
}

/// P-T32: a held ordinary fork whose parent is witnessed `Absent` memo-hits
/// after an index reset and re-requests its parent ref, exactly as its
/// fresh parse did.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn witnessed_fork_memo_hit_after_an_index_reset_re_requests_its_parent_ref() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    fs::rename(
        home.fixture.file(PARENT),
        home.fixture.root.parent().unwrap().join("parent-away"),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    for n in 0..3 {
        index = home.generation(index, &cache, n).0;
    }
    assert!(home.child_entry(&cache).is_some(), "{}", counters(&cache));
    index.codex_parent_ownership_refs.clear();
    let hits = counter(&cache, |c| c.memo_hits);
    let ((index, scan), parsed) = parses(|| home.generation(index, &cache, 3));
    assert!(parsed.is_empty(), "{parsed:?}");
    assert_eq!(
        counter(&cache, |c| c.memo_hits),
        hits + 1,
        "{}",
        counters(&cache)
    );
    assert!(index.codex_parent_ownership_refs.contains(PARENT));
    assert_eq!(
        parent_causes(&scan),
        only(CodexParentUnresolvable::Absent, 1)
    );
}

/// P-T18 (witness lifetime): G is absent, P forks G and C forks P. P is held
/// `Absent` and witnessed `ParentHeld`, so C is held `ParentHeld`. When G
/// appears (sorted before P), G and P are read, P is admitted with its own
/// usage, P's RAM witness is gone, and the chain settles as a cold scan.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn admitted_parent_loses_its_witness_and_its_child_resolves() {
    let fixture = chain_fixture(false);
    let away = fixture.root.parent().unwrap().join("grandparent-away");
    fs::rename(fixture.file(GRANDPARENT), &away).unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut expected = [0; PARENT_UNRESOLVABLE_CAUSES];
    expected[CodexParentUnresolvable::Absent.index()] = 1;
    expected[CodexParentUnresolvable::ParentHeld.index()] = 1;
    let mut index = ScanIndex::default();
    let mut held = false;
    for n in 0..4 {
        let (next, scan) = fixture_generation(&fixture, &cache, index, n);
        index = next;
        assert!(session_usage(&scan, PARENT).is_empty());
        if parent_causes(&scan) == expected {
            held = true;
            break;
        }
    }
    assert!(held, "P held Absent, C ParentHeld: {}", counters(&cache));
    assert!(
        witness_keys(&cache, "cursor-fixture").contains(&PARENT.to_owned()),
        "{}",
        counters(&cache)
    );
    fs::rename(&away, fixture.file(GRANDPARENT)).unwrap();
    let mut published = Vec::new();
    let mut settled = None;
    for n in 4..10 {
        let (next, scan) = fixture_generation(&fixture, &cache, index, n);
        published.extend(session_usage(&scan, PARENT));
        let stable = parent_causes(&scan) == [0; PARENT_UNRESOLVABLE_CAUSES]
            && settled
                .as_ref()
                .is_some_and(|(_, before)| census(&next, &scan) == *before);
        settled = Some((n, census(&next, &scan)));
        index = next;
        if stable {
            break;
        }
    }
    assert!(
        !witness_keys(&cache, "cursor-fixture").contains(&PARENT.to_owned()),
        "{}",
        counters(&cache)
    );
    assert_eq!(published, vec![(30, 1)], "{}", counters(&cache));
    let (n, warm) = settled.unwrap();
    let mut oracle_index = ScanIndex::default();
    let oracle_cache = Arc::new(SharedCache::default());
    let mut oracle = None;
    for m in n..n + 6 {
        let (next, scan) = fixture_generation(&fixture, &oracle_cache, oracle_index, m);
        oracle = Some(census(&next, &scan));
        oracle_index = next;
    }
    assert_eq!(warm, oracle.unwrap());
}

/// P-T25 (R1-M2): a parent last modified outside the backfill window is
/// witnessed `OutOfWindow`: its fork is held under that cause and never
/// `DeferredRestart` at two consecutive generations. Touching the parent
/// changes its identity: the witness drops, the parent is read and the
/// fork settles as a cold scan.
#[test]
fn out_of_window_parent_holds_its_fork_until_touched() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let set_modified = |at: std::time::SystemTime| {
        OpenOptions::new()
            .write(true)
            .open(home.fixture.file(PARENT))
            .unwrap()
            .set_modified(at)
            .unwrap();
    };
    set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000));
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut previous_deferred = false;
    let mut held_at = None;
    for n in 0..4 {
        let (next, scan) = home.generation(index, &cache, n);
        let causes = parent_causes(&scan);
        let deferred = causes[CodexParentUnresolvable::DeferredRestart.index()] > 0;
        assert!(!(deferred && previous_deferred), "generation {n}");
        previous_deferred = deferred;
        assert!(session_usage(&scan, CHILD).is_empty());
        if causes == only(CodexParentUnresolvable::OutOfWindow, 1) {
            held_at.get_or_insert(n);
        }
        index = next;
    }
    assert!(
        held_at.is_some_and(|n| n <= 2),
        "{held_at:?}: {}",
        counters(&cache)
    );
    set_modified(std::time::SystemTime::now());
    let (index, settled, n) = home.settle(index, &cache, 4);
    assert_eq!(parent_causes(&settled), [0; PARENT_UNRESOLVABLE_CAUSES]);
    let (oracle_index, oracle) = home.oracle(n);
    assert_eq!(census(&index, &settled), census(&oracle_index, &oracle));
}

/// P-T28 (N3, M4): C forks P and P forks C. With the budget spent, both wait
/// on each other (`DeferredRestart` wait records); the next match finds the
/// cycle and witnesses both `ForkCycle`. From then both are held `ForkCycle`
/// and neither file is read again.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn fork_cycle_is_witnessed_and_then_quiet() {
    let fixture = ScanRoot::with_sessions(&[]);
    write_rollout(&fixture, PARENT, Some(CHILD), &ForkHome::diverging_child(2));
    write_rollout(&fixture, CHILD, Some(PARENT), &ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let namespace = Scope("cursor-fixture".into());
    let scope = group_scope(&ScanIndex::default());
    for _ in 0..PARENT_RESTART_BUDGET {
        cache.note_parent_restart(&namespace, &scope);
    }
    let cycle = only(CodexParentUnresolvable::ForkCycle, 2);
    let mut index = ScanIndex::default();
    let mut held_at = None;
    for n in 0..5 {
        let (next, scan) = fixture_generation(&fixture, &cache, index, n);
        index = next;
        assert_eq!(restarts_in_scope(&scan), Some(PARENT_RESTART_BUDGET));
        if parent_causes(&scan) == cycle {
            held_at = Some(n);
            break;
        }
    }
    let held_at = held_at.unwrap_or_else(|| panic!("cycle never witnessed: {}", counters(&cache)));
    assert!(held_at <= 3, "{held_at}");
    for n in held_at + 1..held_at + 3 {
        let ((next, scan), parsed) = parses(|| fixture_generation(&fixture, &cache, index, n));
        assert!(parsed.is_empty(), "generation {n}: {parsed:?}");
        assert_eq!(parent_causes(&scan), cycle, "generation {n}");
        index = next;
    }
}

const GRANDPARENT: &str = "019fa111-2222-7333-8444-111111111111";

/// G, P forking G (owned from a mid-ledger divergence, so admitted once G's
/// ledger is known) and C forking P (kind (iii) against P). `reversed`
/// names the rollouts so C sorts first and G last.
fn chain_fixture(reversed: bool) -> ScanRoot {
    let fixture = ScanRoot::with_sessions(&[]);
    let grandparent = ForkHome::parent();
    let own = [
        grandparent[1].clone(),
        grandparent[2].clone(),
        turn_record("2026-10-07T08:20:01Z", "parent-own-turn"),
        usage_record("2026-10-07T08:20:02Z", (130, 100, 14, 3), (30, 20, 4, 1)),
    ];
    write_rollout(&fixture, GRANDPARENT, None, &grandparent[1..]);
    write_rollout(&fixture, PARENT, Some(GRANDPARENT), &own);
    write_rollout(&fixture, CHILD, Some(PARENT), &ForkHome::diverging_child(2));
    if reversed {
        for (id, hour) in [(CHILD, "07"), (PARENT, "08"), (GRANDPARENT, "09")] {
            fs::rename(
                fixture.file(id),
                fixture
                    .root
                    .join(format!("rollout-2026-10-07T{hour}-00-00-{id}.jsonl")),
            )
            .unwrap();
        }
    }
    fixture
}

/// P-T26b (M2): a `ParentHeld` witness is never stale-pruned. After 20
/// pages of another namespace (past `NAMESPACE_STALE_PAGES`), the held
/// chain's next generation parses nothing and its holds memo-hit.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn parent_held_witness_survives_another_namespaces_pages() {
    let fixture = chain_fixture(false);
    let away = fixture.root.parent().unwrap().join("grandparent-away");
    fs::rename(fixture.file(GRANDPARENT), &away).unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    for n in 0..4 {
        index = fixture_generation(&fixture, &cache, index, n).0;
    }
    assert!(
        witness_keys(&cache, "cursor-fixture").contains(&PARENT.to_owned()),
        "{}",
        counters(&cache)
    );
    let other = ScanRoot::new(3);
    let mut other_index = ScanIndex::default();
    for _ in 0..20 {
        other_index = page_in(
            &other,
            other_index,
            Some(Arc::clone(&cache)),
            "other-namespace",
        )
        .0;
    }
    let hits = counter(&cache, |c| c.memo_hits);
    let ((_, scan), parsed) = parses(|| fixture_generation(&fixture, &cache, index, 4));
    assert!(parsed.is_empty(), "{parsed:?}: {}", counters(&cache));
    assert!(
        counter(&cache, |c| c.memo_hits) >= hits + 2,
        "{}",
        counters(&cache)
    );
    let mut expected = [0; PARENT_UNRESOLVABLE_CAUSES];
    expected[CodexParentUnresolvable::Absent.index()] = 1;
    expected[CodexParentUnresolvable::ParentHeld.index()] = 1;
    assert_eq!(parent_causes(&scan), expected);
}

/// Generations from 0 until `scan`'s causes equal `expected` (at most
/// `limit`), then two more that must parse nothing and keep them.
fn held_then_quiet(
    fixture: &ScanRoot,
    expected: [u64; PARENT_UNRESOLVABLE_CAUSES],
    limit: u64,
    never: CodexParentUnresolvable,
) {
    let cache = Arc::new(SharedCache::default());
    held_then_quiet_from(
        fixture,
        &cache,
        ScanIndex::default(),
        0,
        expected,
        limit,
        never,
    );
}

/// `held_then_quiet` continuing `cache` and `index` from generation `from`.
fn held_then_quiet_from(
    fixture: &ScanRoot,
    cache: &Arc<SharedCache>,
    index: ScanIndex,
    from: u64,
    expected: [u64; PARENT_UNRESOLVABLE_CAUSES],
    limit: u64,
    never: CodexParentUnresolvable,
) {
    let mut index = index;
    let mut held_at = None;
    let mut history = Vec::new();
    for n in from..=from + limit {
        let ((next, scan), parsed) = parses(|| fixture_generation(fixture, cache, index, n));
        index = next;
        history.push(format!(
            "{n}: causes {:?} restarts {:?} parsed {parsed:?} scanned {} incomplete {} \
             census {} refs {} ledger {:?}",
            parent_causes(&scan),
            restarts_in_scope(&scan),
            scan.scanned_file_count,
            scan.ownership_incomplete_file_count,
            scan.census_complete,
            index.codex_parent_ownership_refs.contains(PARENT),
            index
                .codex_parent_ownership_ledgers
                .get(PARENT)
                .map(|ledger| ledger.scan_complete),
        ));
        assert_eq!(parent_causes(&scan)[never.index()], 0, "{history:#?}");
        if parent_causes(&scan) == expected {
            held_at = Some(n);
            break;
        }
    }
    let held_at =
        held_at.unwrap_or_else(|| panic!("never held: {history:#?}\n{}", counters(cache)));
    for n in held_at + 1..held_at + 3 {
        let ((next, scan), parsed) = parses(|| fixture_generation(fixture, cache, index, n));
        assert!(parsed.is_empty(), "generation {n}: {parsed:?}");
        assert_eq!(parent_causes(&scan), expected, "generation {n}");
        index = next;
    }
}

/// P-T31 (R1-L1): a second rollout claiming P's id makes P `Duplicated`:
/// the fork is held under it, never `ParentLossy`, and nothing is read
/// again.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn duplicated_parent_holds_its_fork_duplicated() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    fs::copy(
        home.fixture.file(PARENT),
        home.fixture
            .root
            .join(format!("rollout-2026-10-07T11-00-00-{PARENT}.jsonl")),
    )
    .unwrap();
    held_then_quiet(
        &home.fixture,
        only(CodexParentUnresolvable::Duplicated, 1),
        3,
        CodexParentUnresolvable::ParentLossy,
    );
}

// PR-P fix round 1: event (c), deferral chains, multi-page folds and the
// wait-record transition.

/// `id`'s rollout at `hour` on 2026-10-07 (`ScanRoot::file` is hour 10).
fn rollout_at(fixture: &ScanRoot, id: &str, hour: &str) -> PathBuf {
    fixture
        .root
        .join(format!("rollout-2026-10-07T{hour}-00-00-{id}.jsonl"))
}

/// The name `parses` records for `path`.
fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// `scan`'s held children under a `parent_debt()` cause.
fn parent_debt(scan: &SourceScanResult) -> u64 {
    let causes = parent_causes(scan);
    causes[CodexParentUnresolvable::ParentHeld.index()]
        + causes[CodexParentUnresolvable::ParentLossy.index()]
}

/// One line past `MAX_JSONL_LINE_BYTES` (an image row) appended to `path`:
/// a terminal over-line-cap loss, so a complete parse of the file records a
/// terminal disposition and publishes no ledger.
fn append_oversized_line(path: &Path) {
    let mut row = b"{\"timestamp\":\"2026-10-07T08:40:01Z\",\"type\":\"response_item\",\
        \"payload\":{\"type\":\"message\",\"content\":[{\"type\":\"input_image\",\
        \"image_url\":\""
        .to_vec();
    row.extend(std::iter::repeat_n(b'x', MAX_JSONL_LINE_BYTES + 1));
    row.extend_from_slice(b"\"}]}}\n");
    OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(&row)
        .unwrap();
}

/// P-T34 (R1-M1, R2-M1): event (c). P's only rollout ends in a terminal
/// over-line-cap line, so its one complete parse records a terminal
/// disposition and no ledger. When C requests P, the unchanged P is skipped
/// and witnessed `ParentLossy` at its probed identity instead of being read
/// again: P is parsed exactly once, C is held `ParentLossy`, and from then on
/// nothing is read.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn lossy_parent_is_read_once_and_witnessed_parent_lossy() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    append_oversized_line(&home.fixture.file(PARENT));
    let parent = file_name(&home.fixture.file(PARENT));
    let lossy = only(CodexParentUnresolvable::ParentLossy, 1);
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut parent_parses = 0;
    let mut held_at = None;
    let mut history = Vec::new();
    for n in 0..6 {
        let ((next, scan), parsed) = parses(|| home.generation(index, &cache, n));
        index = next;
        parent_parses += parsed.iter().filter(|name| **name == parent).count();
        history.push(format!(
            "{n}: causes {:?} restarts {:?} parsed {parsed:?}",
            parent_causes(&scan),
            restarts_in_scope(&scan)
        ));
        assert!(session_usage(&scan, CHILD).is_empty(), "{history:#?}");
        if held_at.is_some() {
            assert!(parsed.is_empty(), "{history:#?}");
            assert_eq!(parent_causes(&scan), lossy, "{history:#?}");
        } else if parent_causes(&scan) == lossy {
            held_at = Some(n);
        }
    }
    let held_at =
        held_at.unwrap_or_else(|| panic!("never held: {history:#?}\n{}", counters(&cache)));
    assert!(held_at <= 2, "{history:#?}");
    assert_eq!(parent_parses, 1, "{history:#?}");
    assert!(index
        .terminal_jsonl_dispositions
        .contains_key(&local_index_key(&home.fixture.file(PARENT))));
    assert!(index.codex_parent_ownership_refs.contains(PARENT));
    assert!(!index
        .codex_parent_ownership_ledgers
        .get(PARENT)
        .is_some_and(|ledger| ledger.scan_complete));
    let witness = witness_of(&cache, "cursor-fixture", PARENT);
    assert!(
        witness.as_ref().is_some_and(|witness| witness.cause
            == CodexParentUnresolvable::ParentLossy
            && witness.identity.is_some()
            && witness.waits_on.is_none()),
        "{witness:?}"
    );
}

/// P-T34's duplicate-copy leg: a lossy P is read once and recorded with a
/// terminal disposition. Then C (sorted first) and a second rollout named
/// with P's id appear together. That rollout's header is another session,
/// so the join inventory (grouped by header id) does not hold P, while the
/// census (by path id) sees P twice: when C requests P, the skipped P
/// reaches event (c), whose probe is `Duplicated`, so P is never witnessed
/// `ParentLossy` (in RAM or in any count). The next match witnesses P
/// `Duplicated`, C is held under it, and nothing is read again. (Identical
/// copies are a join `CandidateCopy` refusal before any parse, so they
/// never reach event (c).)
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn duplicated_lossy_parent_is_never_witnessed_parent_lossy() {
    const OTHER_HEADER: &str = "019fa111-2222-7333-8444-444444444444";
    let fixture = ScanRoot::with_sessions(&[]);
    fs::write(fixture.file(PARENT), jsonl(&ForkHome::parent())).unwrap();
    append_oversized_line(&fixture.file(PARENT));
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    for n in 0..2 {
        index = fixture_generation(&fixture, &cache, index, n).0;
    }
    assert!(
        index
            .terminal_jsonl_dispositions
            .contains_key(&local_index_key(&fixture.file(PARENT))),
        "{}",
        counters(&cache)
    );
    let mut second = ForkHome::parent();
    second[0] = json!({"timestamp": "2026-10-07T08:00:00Z", "type": "session_meta",
        "payload": {"id": OTHER_HEADER, "thread_source": "user"}});
    fs::write(rollout_at(&fixture, PARENT, "11"), jsonl(&second)).unwrap();
    let mut records = vec![json!({"timestamp": "2026-10-07T08:20:00Z",
        "type": "session_meta",
        "payload": {"id": CHILD, "forked_from_id": PARENT, "thread_source": "user"}})];
    records.extend(ForkHome::diverging_child(3));
    fs::write(rollout_at(&fixture, CHILD, "05"), jsonl(&records)).unwrap();
    let duplicated = only(CodexParentUnresolvable::Duplicated, 1);
    let mut held_at = None;
    let mut history = Vec::new();
    for n in 2..8 {
        let ((next, scan), parsed) = parses(|| fixture_generation(&fixture, &cache, index, n));
        index = next;
        let witness = witness_of(&cache, "cursor-fixture", PARENT);
        history.push(format!(
            "{n}: causes {:?} restarts {:?} parsed {parsed:?} witness {witness:?}",
            parent_causes(&scan),
            restarts_in_scope(&scan)
        ));
        assert_eq!(
            parent_causes(&scan)[CodexParentUnresolvable::ParentLossy.index()],
            0,
            "{history:#?}"
        );
        assert!(
            !matches!(
                witness,
                Some(ParentWitness {
                    cause: CodexParentUnresolvable::ParentLossy,
                    ..
                })
            ),
            "{history:#?}"
        );
        if held_at.is_some() {
            assert!(parsed.is_empty(), "{history:#?}");
            assert_eq!(parent_causes(&scan), duplicated, "{history:#?}");
        } else if parent_causes(&scan) == duplicated {
            held_at = Some(n);
        }
    }
    assert!(
        held_at.is_some_and(|n| n <= 4),
        "{history:#?}\n{}",
        counters(&cache)
    );
}

const ABSENT_GRANDPARENT: &str = "019fa111-2222-7333-8444-333333333333";

/// P-T5b (R2-B1): C -> P -> X with X's ref the 257th, so it never fits. P is
/// held `DeferredRef` and witnessed `DeferredRef` (settling), and C is held
/// `DeferredRef` under it: never a `parent_debt()` cause. P is not re-read
/// every generation: from generation 2 nothing is parsed. P before C (P's
/// ref already held from an earlier traversal) runs no restart; C before P
/// runs at most one (C is pending before P's step-map entry exists).
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn deferred_intermediate_parent_is_not_reread_every_generation() {
    for c_first in [false, true] {
        let fixture = ScanRoot::with_sessions(&[]);
        write_rollout(
            &fixture,
            PARENT,
            Some(ABSENT_GRANDPARENT),
            &ForkHome::parent()[1..],
        );
        write_rollout(&fixture, CHILD, Some(PARENT), &ForkHome::diverging_child(2));
        let mut index = ScanIndex::default();
        for n in 0..crate::snapshots::MAX_CODEX_PARENT_LEDGER_REFS - 1 {
            index
                .codex_parent_ownership_refs
                .insert(format!("prefilled-{n:03}"));
        }
        if c_first {
            fs::rename(fixture.file(CHILD), rollout_at(&fixture, CHILD, "09")).unwrap();
        } else {
            index.codex_parent_ownership_refs.insert(PARENT.to_owned());
        }
        let parent = file_name(&fixture.file(PARENT));
        let cache = Arc::new(SharedCache::default());
        let mut parent_parses = 0;
        let mut history = Vec::new();
        for n in 0..6 {
            let ((next, scan), parsed) = parses(|| fixture_generation(&fixture, &cache, index, n));
            index = next;
            parent_parses += parsed.iter().filter(|name| **name == parent).count();
            history.push(format!(
                "{n}: causes {:?} restarts {:?} parsed {parsed:?}",
                parent_causes(&scan),
                restarts_in_scope(&scan)
            ));
            assert_eq!(parent_debt(&scan), 0, "c_first {c_first}: {history:#?}");
            assert!(!index
                .codex_parent_ownership_refs
                .contains(ABSENT_GRANDPARENT));
            let restarts = restarts_in_scope(&scan);
            if c_first {
                assert!(
                    restarts.is_some_and(|restarts| restarts <= 1),
                    "{history:#?}"
                );
            } else {
                assert_eq!(restarts, Some(0), "{history:#?}");
            }
            if n >= 2 {
                assert!(parsed.is_empty(), "c_first {c_first}: {history:#?}");
                assert_eq!(
                    parent_causes(&scan),
                    only(CodexParentUnresolvable::DeferredRef, 2),
                    "c_first {c_first}: {history:#?}"
                );
            }
        }
        if c_first {
            assert!(parent_parses <= 2, "{history:#?}");
        } else {
            assert_eq!(parent_parses, 1, "{history:#?}");
        }
        let witness = witness_of(&cache, "cursor-fixture", PARENT);
        assert!(
            witness
                .as_ref()
                .is_some_and(|witness| witness.cause == CodexParentUnresolvable::DeferredRef),
            "c_first {c_first}: {witness:?}"
        );
    }
}

/// Fix round 6 (control B): C -> P -> X with X's ref never fitting, so C is
/// held `DeferredRef` under P's step-map witness. C's hold memo ends and its
/// proof turns `Proven` once C's parser is built (as in control A: no install,
/// no refusal, the record site sees `Proven`). The witness arm holds C, and
/// that hold is memoized: from the page after, C is not parsed. (An install
/// would change nothing here: the witness arm drops a proof unused, so the
/// record site reads the same no-proof, no-refusal parse.)
#[test]
fn a_witnessed_deferred_ref_hold_stays_memoized_beside_its_proven_entry() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::CodexParentProofState;
    use CodexParentUnresolvable::DeferredRef;
    let fixture = ScanRoot::with_sessions(&[]);
    let parent_records = ForkHome::parent()[1..].to_vec();
    let child_records = ForkHome::diverging_child(2);
    write_rollout(&fixture, PARENT, Some(ABSENT_GRANDPARENT), &parent_records);
    write_rollout(&fixture, CHILD, Some(PARENT), &child_records);
    let mut index = ScanIndex::default();
    for n in 0..crate::snapshots::MAX_CODEX_PARENT_LEDGER_REFS - 1 {
        index
            .codex_parent_ownership_refs
            .insert(format!("prefilled-{n:03}"));
    }
    index.codex_parent_ownership_refs.insert(PARENT.to_owned());
    let cache = Arc::new(SharedCache::default());
    for n in 0..3 {
        index = fixture_generation(&fixture, &cache, index, n).0;
    }
    let (parent, child) = (fixture.file(PARENT), fixture.file(CHILD));
    cache.memo_forget(&stored_key(&cache, &child).expect("C's hold memo"));
    let mut key = None;
    index.traversal = None;
    let ((index, held), parsed) = parses(|| {
        page_between(&fixture, index, &cache, &collected_at(3), |scan| {
            if key.is_none() && active_is(scan, &child) {
                key = Some(prove_child(
                    scan,
                    &cache,
                    &parent,
                    &parent_records,
                    &child,
                    &child_records,
                ));
            }
        })
    });
    let key = key.expect("C's parse spans step calls");
    assert_eq!(parsed, vec![file_name(&child)], "{}", counters(&cache));
    assert_eq!(parent_causes(&held), only(DeferredRef, 2));
    assert!(matches!(
        index.codex_parent_prefix_proofs.get(&key),
        Some(CodexParentProofState::Proven(_))
    ));
    assert!(stored_key(&cache, &child).is_some(), "{}", counters(&cache));
    let hits = counter(&cache, |c| c.memo_hits);
    let ((_, again), parsed) = parses(|| fixture_generation(&fixture, &cache, index, 4));
    assert!(parsed.is_empty(), "{parsed:?}: {}", counters(&cache));
    assert_eq!(parent_causes(&again), only(DeferredRef, 2));
    assert!(
        counter(&cache, |c| c.memo_hits) > hits,
        "{}",
        counters(&cache)
    );
}

const GREAT_GRANDPARENT: &str = "019fa111-2222-7333-8444-222222222222";

/// The settled census of `fixture` from generation `n` on a fresh index and
/// cache (unspent budget): the cold oracle of a chain.
fn cold_census(fixture: &ScanRoot, n: u64) -> (Vec<(&'static str, u64)>, BTreeSet<String>) {
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut last = None;
    for m in n..n + 8 {
        let (next, scan) = fixture_generation(fixture, &cache, index, m);
        last = Some(census(&next, &scan));
        index = next;
    }
    last.unwrap()
}

/// P-T10c (R2-M1, covers P-T10): C -> P -> G -> H in the worst page order (C
/// first, H last) with the scope's restart budget already spent. No restart
/// runs; links wait as `DeferredRestart` while the chain converges, never a
/// `parent_debt()` cause; the chain then settles as a cold scan does.
#[test]
fn spent_budget_chain_never_counts_parent_debt_and_converges() {
    let fixture = ScanRoot::with_sessions(&[]);
    let root = ForkHome::parent();
    let grandparent = [
        root[1].clone(),
        root[2].clone(),
        turn_record("2026-10-07T08:20:01Z", "grandparent-own-turn"),
        usage_record("2026-10-07T08:20:02Z", (130, 100, 14, 3), (30, 20, 4, 1)),
        turn_record("2026-10-07T08:40:01Z", "grandparent-own-turn-2"),
        usage_record("2026-10-07T08:40:02Z", (150, 115, 17, 4), (20, 15, 3, 1)),
    ];
    let mut parent = grandparent[..4].to_vec();
    parent.push(turn_record("2026-10-07T08:30:01Z", "parent-own-turn"));
    parent.push(usage_record(
        "2026-10-07T08:30:02Z",
        (145, 110, 16, 3),
        (15, 10, 2, 0),
    ));
    write_rollout(&fixture, GREAT_GRANDPARENT, None, &root[1..]);
    write_rollout(&fixture, GRANDPARENT, Some(GREAT_GRANDPARENT), &grandparent);
    write_rollout(&fixture, PARENT, Some(GRANDPARENT), &parent);
    write_rollout(&fixture, CHILD, Some(PARENT), &ForkHome::diverging_child(2));
    for (id, hour) in [
        (CHILD, "05"),
        (PARENT, "06"),
        (GRANDPARENT, "07"),
        (GREAT_GRANDPARENT, "08"),
    ] {
        fs::rename(fixture.file(id), rollout_at(&fixture, id, hour)).unwrap();
    }
    let cache = Arc::new(SharedCache::default());
    let namespace = Scope("cursor-fixture".into());
    let scope = group_scope(&ScanIndex::default());
    for _ in 0..PARENT_RESTART_BUDGET {
        cache.note_parent_restart(&namespace, &scope);
    }
    let mut index = ScanIndex::default();
    let mut history = Vec::new();
    let mut previous = None;
    let mut settled = None;
    for n in 0..10 {
        let (next, scan) = fixture_generation(&fixture, &cache, index, n);
        index = next;
        history.push(format!(
            "{n}: causes {:?} restarts {:?}",
            parent_causes(&scan),
            restarts_in_scope(&scan)
        ));
        assert_eq!(parent_debt(&scan), 0, "{history:#?}");
        assert_eq!(
            restarts_in_scope(&scan),
            Some(PARENT_RESTART_BUDGET),
            "{history:#?}"
        );
        let now = census(&index, &scan);
        let quiet = parent_causes(&scan) == [0; PARENT_UNRESOLVABLE_CAUSES];
        if quiet && previous.as_ref() == Some(&now) {
            settled = Some((n, now));
            break;
        }
        previous = quiet.then_some(now);
    }
    let (n, warm) =
        settled.unwrap_or_else(|| panic!("never settled: {history:#?}\n{}", counters(&cache)));
    assert_eq!(warm, cold_census(&fixture, n + 1), "{history:#?}");
}

/// P-T16 (R2-M1): a traversal spanning pages. Twelve changed sessions and C
/// (a fork of absent P, sorted first) are 13 candidates over 10-file pages.
/// On each steady traversal the step-start match runs once, C's `Absent`
/// count appears on its page and every later page of the traversal reports
/// it again (the page-to-traversal fold, traversal-cumulative per page),
/// P's witness survives every page, and restarts stay within budget.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn multi_page_traversal_folds_parent_causes_and_matches_once() {
    let fillers = (0..12)
        .map(|n| format!("019fa111-2222-7333-8444-9000000000{n:02}"))
        .collect::<Vec<_>>();
    let sessions = fillers
        .iter()
        .map(|id| (id.as_str(), 2))
        .collect::<Vec<_>>();
    let fixture = ScanRoot::with_sessions(&sessions);
    write_rollout(&fixture, CHILD, Some(PARENT), &ForkHome::diverging_child(2));
    fs::rename(fixture.file(CHILD), rollout_at(&fixture, CHILD, "05")).unwrap();
    let absent = only(CodexParentUnresolvable::Absent, 1);
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut page = 0;
    for traversal in 0..5 {
        for id in &fillers {
            fixture.append(id, &token_line(3 + traversal));
        }
        let before = crate::snapshots::codex_parent_step_start_matches_for_test();
        let mut pages = Vec::new();
        loop {
            let (next, scan, _) = page_with(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                &collected_at(page),
                |_| {},
            );
            index = next;
            page += 1;
            pages.push((
                parent_causes(&scan),
                restarts_in_scope(&scan),
                witness_of(&cache, "cursor-fixture", PARENT).map(|witness| witness.cause),
            ));
            if index.traversal.is_none() {
                break;
            }
            assert!(pages.len() < 10, "traversal {traversal}: {pages:?}");
        }
        let matches = crate::snapshots::codex_parent_step_start_matches_for_test() - before;
        for (_, restarts, _) in &pages {
            assert!(
                !restarts.is_some_and(|restarts| restarts > PARENT_RESTART_BUDGET),
                "traversal {traversal}: {pages:?}"
            );
        }
        if traversal < 2 {
            continue;
        }
        assert!(pages.len() >= 2, "traversal {traversal}: {pages:?}");
        assert_eq!(matches, 1, "traversal {traversal}: {pages:?}");
        let at = pages
            .iter()
            .position(|(causes, ..)| *causes == absent)
            .unwrap_or_else(|| panic!("traversal {traversal}: {pages:?}"));
        assert!(at + 1 < pages.len(), "traversal {traversal}: {pages:?}");
        for (causes, ..) in &pages[..at] {
            assert_eq!(
                *causes, [0; PARENT_UNRESOLVABLE_CAUSES],
                "traversal {traversal}: {pages:?}"
            );
        }
        for (causes, _, witness) in &pages[at..] {
            assert_eq!(*causes, absent, "traversal {traversal}: {pages:?}");
            assert_eq!(
                *witness,
                Some(CodexParentUnresolvable::Absent),
                "traversal {traversal}: {pages:?}"
            );
        }
    }
}

/// P-T18b (R1-M2): P-T18 with P before G on the page. G absent: P is held
/// `Absent` and witnessed `ParentHeld`, C is held `ParentHeld`. When G
/// appears, P's re-read finds G not yet read, so P's settling witness is
/// replaced by a `DeferredRestart` wait record on G (and unwitnessed in the
/// step map) before P resolves. With P and C both before G, C is never
/// counted `ParentHeld` after G appears. With C first (`chain_fixture(true)`)
/// C may keep the conservative `ParentHeld` label until P's actual
/// dependency-triggered re-read (the general bound; not one traversal by
/// wall clock). In this fixture that re-read runs on the first such
/// generation, so C may count `ParentHeld` then, never later. Both settle as
/// a cold scan.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn pending_parent_replaces_its_parent_held_witness_with_a_wait_record() {
    for c_first in [false, true] {
        let fixture = chain_fixture(c_first);
        let grandparent = if c_first {
            rollout_at(&fixture, GRANDPARENT, "09")
        } else {
            for (id, hour) in [(PARENT, "06"), (CHILD, "07")] {
                fs::rename(fixture.file(id), rollout_at(&fixture, id, hour)).unwrap();
            }
            fixture.file(GRANDPARENT)
        };
        let away = fixture.root.parent().unwrap().join("grandparent-away");
        fs::rename(&grandparent, &away).unwrap();
        let mut held = [0; PARENT_UNRESOLVABLE_CAUSES];
        held[CodexParentUnresolvable::Absent.index()] = 1;
        held[CodexParentUnresolvable::ParentHeld.index()] = 1;
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut history = Vec::new();
        let mut n = 0;
        loop {
            let (next, scan) = fixture_generation(&fixture, &cache, index, n);
            index = next;
            history.push(format!("{n}: causes {:?}", parent_causes(&scan)));
            n += 1;
            if parent_causes(&scan) == held {
                break;
            }
            assert!(n < 6, "c_first {c_first}: {history:#?}");
        }
        let witness = witness_of(&cache, "cursor-fixture", PARENT);
        assert!(
            witness
                .as_ref()
                .is_some_and(|witness| witness.cause == CodexParentUnresolvable::ParentHeld),
            "c_first {c_first}: {witness:?}"
        );
        fs::rename(&away, &grandparent).unwrap();
        let mut published = Vec::new();
        let mut censuses = Vec::new();
        for m in n..n + 6 {
            let (next, scan) = fixture_generation(&fixture, &cache, index, m);
            index = next;
            let witness = witness_of(&cache, "cursor-fixture", PARENT);
            history.push(format!(
                "{m}: causes {:?} restarts {:?} witness {witness:?}",
                parent_causes(&scan),
                restarts_in_scope(&scan)
            ));
            let parent_held = parent_causes(&scan)[CodexParentUnresolvable::ParentHeld.index()];
            assert!(
                parent_held == 0 || (c_first && m == n),
                "c_first {c_first}: {history:#?}"
            );
            if m == n {
                assert!(
                    witness.as_ref().is_some_and(|witness| witness.cause
                        == CodexParentUnresolvable::DeferredRestart
                        && witness.waits_on.as_deref() == Some(GRANDPARENT)),
                    "c_first {c_first}: {history:#?}\n{}",
                    counters(&cache)
                );
            }
            published.extend(session_usage(&scan, PARENT));
            censuses.push(census(&index, &scan));
        }
        assert_eq!(
            witness_of(&cache, "cursor-fixture", PARENT),
            None,
            "c_first {c_first}: {history:#?}"
        );
        assert_eq!(published, vec![(30, 1)], "c_first {c_first}: {history:#?}");
        let warm = censuses.pop().unwrap();
        assert_eq!(Some(&warm), censuses.last(), "c_first {c_first}");
        assert_eq!(warm, cold_census(&fixture, n + 6), "c_first {c_first}");
    }
}

/// P-T23 (R1-M1, R2-M1): P's index ledger is admitted and the fork settled;
/// then a copy of P appears and C changes once. The admitted ledger no
/// longer validates and does not hide P: C is held `Duplicated` (never
/// `ParentLossy`) and then nothing, neither copy of P nor C, is read again.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn duplicate_after_an_admitted_ledger_holds_the_fork_duplicated() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (index, _, n) = home.settle(ScanIndex::default(), &cache, 0);
    assert!(ForkHome::parent_ledger(&index).is_some());
    fs::copy(
        home.fixture.file(PARENT),
        rollout_at(&home.fixture, PARENT, "11"),
    )
    .unwrap();
    home.fixture.append(
        CHILD,
        &jsonl(&[usage_record(
            "2026-10-07T08:20:03Z",
            (40, 20, 4, 0),
            (10, 5, 1, 0),
        )]),
    );
    held_then_quiet_from(
        &home.fixture,
        &cache,
        index,
        n,
        only(CodexParentUnresolvable::Duplicated, 1),
        4,
        CodexParentUnresolvable::ParentLossy,
    );
}

// ---------------------------------------------------------------------------
// U1a-2a cc rows 1–5, 8 and ss-6: the proof holder (dormant until the proof
// hook; driven directly here).

fn proof_job(namespace: &str, path: &str, incarnation: &str, bytes: usize) -> Box<ProofJob> {
    Box::new(ProofJob {
        namespace: namespace.to_owned(),
        index_path: PathBuf::from(path),
        incarnation: incarnation.to_owned(),
        entries: vec![("k".repeat(bytes), 1)],
        next_row_end: 0,
        touched_page: 0,
        readers: None,
    })
}

fn proof_charge(job: &ProofJob) -> usize {
    crate::heap_layout_bound::bound(job, STATE_BYTES).unwrap()
}

/// Suspend `job` through a lease, as the proof hook will.
fn suspend(cache: &Arc<SharedCache>, job: Box<ProofJob>) -> bool {
    ProofLease::new(cache, job).suspend()
}

fn proof_drops(counts: crate::local_resource_diagnostics::codex_side_lifecycle::Counts) -> u64 {
    counts.side_proof_drops
}

fn next_page(cache: &SharedCache) {
    next_page_in(cache, "ns");
}

fn next_page_in(cache: &SharedCache, namespace: &str) {
    PageBudget::default().note_page(cache, &Scope(namespace.into()));
}

/// cc rows 1, 5: the hook's claim. Another index's job is busy until it is
/// `NAMESPACE_STALE_PAGES` cursor pages old, then dropped (counted); this
/// index's job comes out with its pages touched; the same index under a new
/// incarnation drops it (counted); a dropped lease loses its job (counted).
#[test]
fn proof_take_is_mine_busy_stale_or_mismatched() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let ns_a = Scope("ns-a".to_owned());
    let ns_b = Scope("ns-b".to_owned());
    let (a, b) = (Path::new("/idx/a.json"), Path::new("/idx/b.json"));
    let cache = Arc::new(SharedCache::default());
    assert!(matches!(
        cache.proof_take(&ns_a, a, "inc-1"),
        ProofTake::Free
    ));
    assert!(suspend(
        &cache,
        proof_job("ns-a", "/idx/a.json", "inc-1", 8)
    ));
    for _ in 0..NAMESPACE_STALE_PAGES - 1 {
        next_page(&cache);
        assert!(matches!(
            cache.proof_take(&ns_b, b, "inc-9"),
            ProofTake::Busy
        ));
    }
    // The same namespace with another index path is another index.
    assert!(matches!(
        cache.proof_take(&ns_a, b, "inc-1"),
        ProofTake::Busy
    ));
    let ProofTake::Mine(mut lease) = cache.proof_take(&ns_a, a, "inc-1") else {
        panic!("this index's own job");
    };
    assert_eq!(lease.job().touched_page, NAMESPACE_STALE_PAGES - 1);
    assert_eq!(cache.proof_suspended_for_test(), None);
    assert!(lease.suspend());
    for _ in 0..NAMESPACE_STALE_PAGES {
        next_page(&cache);
    }
    let (take, counts) = observe(|| cache.proof_take(&ns_b, b, "inc-9"));
    assert!(matches!(take, ProofTake::Free));
    assert_eq!(proof_drops(counts), 1, "stale");
    assert_eq!(cache.proof_suspended_for_test(), None);
    // A new incarnation of the same index never resumes the old job.
    assert!(suspend(
        &cache,
        proof_job("ns-a", "/idx/a.json", "inc-1", 8)
    ));
    let (take, counts) = observe(|| cache.proof_take(&ns_a, a, "inc-2"));
    assert!(matches!(take, ProofTake::Free));
    assert_eq!(proof_drops(counts), 1, "mismatch");
    assert_eq!(cache.proof_suspended_for_test(), None);
    // A lease dropped holding its job loses it; `finish` does not count.
    assert!(suspend(
        &cache,
        proof_job("ns-a", "/idx/a.json", "inc-1", 8)
    ));
    let ProofTake::Mine(lease) = cache.proof_take(&ns_a, a, "inc-1") else {
        panic!("mine");
    };
    let ((), counts) = observe(|| drop(lease));
    assert_eq!(proof_drops(counts), 1);
    assert!(suspend(
        &cache,
        proof_job("ns-a", "/idx/a.json", "inc-1", 8)
    ));
    let ProofTake::Mine(lease) = cache.proof_take(&ns_a, a, "inc-1") else {
        panic!("mine");
    };
    let ((), counts) = observe(|| lease.finish());
    assert_eq!(proof_drops(counts), 0);
    assert_eq!(cache.proof_suspended_for_test(), None);
}

/// cc row 4: the step needs `PROOF_STEP_HEADROOM_BYTES` beside the context
/// and the job's walked charge.
#[test]
fn proof_room_keeps_the_headroom() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let context = super::super::Context {
        cache: Arc::new(SharedCache::default()),
        namespace: Scope("ns-a".to_owned()),
        audit_metadata_supported: true,
        audit_slots: 0,
        full_files: 0,
        tail_files: 0,
        unchanged_files: 0,
        native_bytes: 0,
        sample_bytes: 0,
        full_reasons: [0; 11],
        priority_replays: 0,
        audits_started: 0,
        audits_completed: 0,
        audit_quiet_retired: 0,
        audit_cap_full: 0,
        audit_cap_delay: 0,
        pace_evicted: 0,
        start_overdue_seconds: 0,
        completion_overdue_seconds: 0,
        admission: Default::default(),
    };
    let resident = crate::heap_layout_bound::bound(&context, STATE_BYTES).unwrap();
    let exact = STATE_BYTES - resident - PROOF_STEP_HEADROOM_BYTES;
    assert_eq!(proof_room(&context), Some(exact));
}

/// ss-6: the retained insert reserves main's cursor term, so its decision is
/// the no-proof one; the proof is retired under the same lock exactly when
/// the kept copy took its room, and the charged state stays within budget.
#[test]
fn a_retained_insert_decides_without_the_proof_and_retires_it_when_needed() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        let completed = |copy: crate::transcript_cache::Retained<_>| {
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: copy.checkpoint,
                reduction: Some(copy.state),
                released: None,
                unsealed: false,
            }
        };
        let copy = cache.take(&key).expect("a certified copy").retained;
        cache.insert(key.clone(), completed(copy), 0);
        let with_copy = admission_floor(&cache);
        let state = cache.cursor_resident();
        let copy = cache.take(&key).expect("retained").retained;
        let job = proof_job("ns-a", "/idx/a.json", "inc-1", 4096);
        let proof = proof_charge(&job);
        // Room for the copy and the proof exactly: both stay.
        let claim = STATE_BYTES - state - with_copy - proof;
        let credit = cache.cursor_reserve(claim).expect("fits alone");
        assert!(suspend(&cache, job));
        let ((), counts) = observe(|| cache.insert(key.clone(), completed(copy), 0));
        assert!(cache.retained_checkpoint(&key).is_some());
        assert!(cache.proof_suspended_for_test().is_some());
        assert_eq!(proof_drops(counts), 0);
        assert_eq!(
            admission_floor(&cache) + cache.cursor_resident(),
            STATE_BYTES
        );
        credit.refund();
        let copy = cache.take(&key).expect("retained").retained;
        assert!(matches!(
            cache.proof_take(&Scope("ns-a".to_owned()), Path::new("/idx/a.json"), "inc-1"),
            ProofTake::Mine(_)
        ));
        // One byte more claimed: the copy still fits beside main's state, so
        // it is kept as with no proof, and the proof is retired.
        let credit = cache.cursor_reserve(claim + 1).expect("fits alone");
        assert!(suspend(
            &cache,
            proof_job("ns-a", "/idx/a.json", "inc-1", 4096)
        ));
        let ((), counts) = observe(|| cache.insert(key.clone(), completed(copy), 0));
        assert!(
            cache.retained_checkpoint(&key).is_some(),
            "the no-proof decision"
        );
        assert_eq!(cache.proof_suspended_for_test(), None);
        assert_eq!(proof_drops(counts), 1);
        assert!(admission_floor(&cache) + cache.cursor_resident() <= STATE_BYTES);
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// R2 optional-header composition uses the existing main copy measure and
/// production allocation callback, including the shape-F measure's view.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn header_facts_never_shrink_the_main_copy_budget_and_yield_before_allocation() {
    let (root, fixture) = codex_file_join::tests::fixture();
    let paths = fixture
        .headers
        .iter()
        .map(|header| local_index_key(&header.candidate.path))
        .collect();
    let cache = Arc::new(SharedCache::default());
    let credit = cache
        .cursor_reserve(
            STATE_BYTES - admission_floor(&cache) - cache.cursor_resident() - 128 * 1024,
        )
        .unwrap();
    let first = codex_file_join::header_cache_tests::page(&root, &paths, &cache);
    assert!(first.complete);
    assert_eq!(first.reuse_misses, 2);
    let bytes = cache
        .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
        .unwrap();
    assert!(bytes > 0);
    cache.retire_headers_over_room(bytes);
    assert_eq!(
        cache
            .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
            .unwrap(),
        bytes
    );
    cache.retire_headers_over_room(bytes - 1);
    assert!(cache
        .with_cursor(|cursor| cursor.headers.is_empty())
        .unwrap());
    let refreshed = codex_file_join::header_cache_tests::page(&root, &paths, &cache);
    assert_eq!((refreshed.reuse_misses, refreshed.reuse_evictions), (2, 2));
    let job = proof_job("header-proof", "/idx/header-proof.json", "inc-1", 4096);
    assert!(suspend(&cache, job));
    cache.retire_headers_over_room(bytes);
    assert!(cache
        .with_cursor(|cursor| cursor.headers.is_empty())
        .unwrap());
    assert!(
        cache.proof_suspended_for_test().is_some(),
        "header pressure must preserve proof authority"
    );
    cache.retire_proof_over_room(0);
    assert!(cache.proof_suspended_for_test().is_none());
    let refreshed = codex_file_join::header_cache_tests::page(&root, &paths, &cache);
    assert_eq!(refreshed.reuse_evictions, 2);
    let context = main_context(&cache);
    let (budget, step) = super::super::copy_budget_step(Some(&context), None, true);
    assert!(budget > 0 && budget < super::super::ENTRY_BYTES);
    let headers = cache
        .with_cursor(|cursor| std::mem::take(&mut cursor.headers))
        .unwrap();
    let (cold_budget, cold_step) = super::super::copy_budget_step(Some(&context), None, true);
    cache
        .with_cursor(|cursor| cursor.headers = headers)
        .unwrap();
    assert_eq!((budget, step), (cold_budget, cold_step));
    assert_eq!(
        cache
            .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
            .unwrap(),
        bytes,
        "measurement alone cannot evict"
    );
    super::super::retire_proof_beside_copy(Some(&context), budget, step);
    assert!(cache
        .with_cursor(|cursor| cursor.headers.is_empty())
        .unwrap());
    assert!(super::super::copy_retire_probe().unwrap().fits());
    let next = codex_file_join::header_cache_tests::page(&root, &paths, &cache);
    assert_eq!(
        (next.reuse_hits, next.reuse_misses, next.reuse_evictions),
        (0, 2, 2)
    );
    credit.refund();
    assert_eq!(cache.cursor_reserved(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn release_paths_reclaim_headers_only_when_the_ranked_fit_is_reachable() {
    for path in 0..3 {
        let (root, fixture) = codex_file_join::tests::fixture();
        let paths = fixture
            .headers
            .iter()
            .map(|header| local_index_key(&header.candidate.path))
            .collect();
        let cache = SharedCache::default();
        let first = codex_file_join::header_cache_tests::page(&root, &paths, &cache);
        assert!(first.complete);
        let before = cache
            .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
            .unwrap();
        assert!(before > 0);
        let release = |pinned| match path {
            0 => cache.release_to_fit(pinned),
            1 => cache.release_older_to_fit(pinned, (1, 0)),
            _ => cache.release_older_prefix_to_fit(pinned, (1, 0), 0),
        };
        assert!(!release(STATE_BYTES), "hopeless claims evict nothing");
        assert_eq!(
            cache
                .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
                .unwrap(),
            before
        );
        let pinned =
            STATE_BYTES - cache.cursor_resident_for_main() + before - retained_floor(&cache);
        assert!(release(pinned));
        assert!(cache
            .with_cursor(|cursor| cursor.headers.is_empty())
            .unwrap());
        let next = codex_file_join::header_cache_tests::page(&root, &paths, &cache);
        assert_eq!((next.reuse_hits, next.reuse_evictions), (0, 2));
        fs::remove_dir_all(root).unwrap();
    }
}

fn main_context(cache: &Arc<SharedCache>) -> super::super::Context {
    super::super::Context {
        cache: Arc::clone(cache),
        namespace: Scope("ns-main".to_owned()),
        audit_metadata_supported: true,
        audit_slots: 0,
        full_files: 0,
        tail_files: 0,
        unchanged_files: 0,
        native_bytes: 0,
        sample_bytes: 0,
        full_reasons: [0; 11],
        priority_replays: 0,
        audits_started: 0,
        audits_completed: 0,
        audit_quiet_retired: 0,
        audit_cap_full: 0,
        audit_cap_delay: 0,
        pace_evicted: 0,
        start_overdue_seconds: 0,
        completion_overdue_seconds: 0,
        admission: Default::default(),
    }
}

/// R2-B3: main's copy budget is measured as if no proof existed. With and
/// without a suspended proof that fits free room, main gets the same copy
/// budget and resident measure (the proof keeps its slot: nothing was
/// spent yet); the insert that needs the proof's room then retires it and
/// keeps the copy (ss-6).
#[test]
fn a_suspended_proof_never_shrinks_mains_copy_budget() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _, _) = page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture");
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        let completed = |copy: crate::transcript_cache::Retained<_>| {
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: copy.checkpoint,
                reduction: Some(copy.state),
                released: None,
                unsealed: false,
            }
        };
        let copy = cache.take(&key).expect("a certified copy").retained;
        cache.insert(key.clone(), completed(copy), 0);
        let with_copy = admission_floor(&cache);
        let state = cache.cursor_resident();
        let copy = cache.take(&key).expect("retained").retained;
        let job = proof_job("ns-a", "/idx/a.json", "inc-1", 4096);
        let proof = proof_charge(&job);
        let context = main_context(&cache);
        let budget = || super::super::copy_budget_step(Some(&context), None, false);
        let (without, measured_without) = budget();
        assert!(without > proof, "precondition: a visible difference");
        assert!(suspend(&cache, job));
        let (with, measured_with) = budget();
        assert_eq!(with, without, "parity");
        assert_eq!(measured_with.resident, measured_without.resident);
        assert!(cache.proof_suspended_for_test().is_some());
        // One byte short of room for both: the copy needs the proof's room.
        let claim = STATE_BYTES - state - with_copy - proof + 1;
        let credit = cache.cursor_reserve(claim).expect("fits beside the proof");
        assert!(cache.proof_suspended_for_test().is_some());
        let ((), counts) = observe(|| cache.insert(key.clone(), completed(copy), 0));
        assert!(
            cache.retained_checkpoint(&key).is_some(),
            "the copy is kept"
        );
        assert_eq!(cache.proof_suspended_for_test(), None);
        assert_eq!(proof_drops(counts), 1);
        assert!(admission_floor(&cache) + cache.cursor_resident() <= STATE_BYTES);
        credit.refund();
    });
}

/// R2-B3, fix round 2 DB1 (c22 ruling (b)), fix round 3 DM3: main's copy
/// budget funds two shares, so where it is allocated against
/// (`retire_proof_beside_copy`) a suspended proof over `room - budget -
/// min(budget, ENTRY_BYTES)` is retired, even one the finish/output share
/// alone leaves room for (`room - budget - 1`); then `bound(context)` +
/// copy + finish/output fit `STATE_BYTES`. `copy_budget_step` itself retires nothing, and nothing is
/// retired where no copy is allocated (budget 0, as an unknown room gives):
/// no drop on unavailable inputs. The retired job keeps only its `seq`s.
#[test]
fn a_proof_is_retired_only_where_both_copy_shares_are_allocated() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let context = main_context(&cache);
    let budget = || super::super::copy_budget_step(Some(&context), None, false);
    let (without, measured) = budget();
    let room = measured.room().expect("a measured room");
    assert_eq!(without, room / 2);
    // Kept by the copy's share alone, over both shares.
    let fixed = proof_charge(&proof_job("ns-a", "/idx/a.json", "inc-1", 4096)) - 4096;
    let job = proof_job("ns-a", "/idx/a.json", "inc-1", room - without - 1 - fixed);
    let charge = proof_charge(&job);
    assert!(
        charge > room - without - without.min(ENTRY_BYTES) && charge < room - without,
        "{charge}"
    );
    assert!(suspend(&cache, job), "fits the free room alone");
    let ((with, step), counts) = observe(budget);
    assert_eq!(with, without, "the budget is unchanged");
    assert_eq!(step.room(), Some(room));
    assert!(
        cache.proof_suspended_for_test().is_some(),
        "no retire at the step"
    );
    assert_eq!(proof_drops(counts), 0);
    // No copy allocated: nothing retired.
    let ((), counts) = observe(|| super::super::retire_proof_beside_copy(Some(&context), 0, step));
    assert!(cache.proof_suspended_for_test().is_some());
    assert_eq!(proof_drops(counts), 0);
    // A busy cache: an unknown room and budget 0; the proof is kept.
    let busy = {
        let _held = cache.retained().unwrap();
        budget()
    };
    assert_eq!((busy.0, busy.1.room()), (0, None));
    let ((), counts) =
        observe(|| super::super::retire_proof_beside_copy(Some(&context), busy.0, busy.1));
    assert!(cache.proof_suspended_for_test().is_some());
    assert_eq!(proof_drops(counts), 0);
    // The allocation: retired first, and both shares fit beside the rest.
    super::super::copy_retire_probe();
    let ((), counts) =
        observe(|| super::super::retire_proof_beside_copy(Some(&context), with, step));
    assert_eq!(cache.proof_suspended_for_test(), None, "retired first");
    assert_eq!(proof_drops(counts), 1);
    let probe = super::super::copy_retire_probe().expect("probed");
    assert_eq!((probe.proof, probe.used, probe.budget), (Some(0), 0, with));
    assert!(probe.fits(), "{probe:?}");
    let scope = Scope("ns-a".to_owned());
    let index = std::path::Path::new("/idx/a.json");
    assert_eq!(cache.take_retired_proof_seqs(&scope, index, "inc-1"), [1]);
    assert!(cache
        .take_retired_proof_seqs(&scope, index, "inc-1")
        .is_empty());
    // Nothing of the retired job stays charged.
    assert_eq!(budget().1.resident, measured.resident);
}

/// Fix round 2 DB1, the completion site: a cursor job's pages that allocate
/// nothing keep a suspended proof of a third of the state budget; the page
/// whose completion retains the certified copy retires it before the clone:
/// the walk's resident + the proof left there (none) + the active + both
/// shares fit `STATE_BYTES`.
#[test]
fn a_completing_cursor_job_retires_the_proof_before_its_clone() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        assert!(suspend(
            &cache,
            proof_job("ns-a", "/idx/a.json", "inc-1", STATE_BYTES / 3)
        ));
        super::super::copy_retire_probe();
        let mut index = ScanIndex::default();
        let mut certified = false;
        for _ in 0..64 {
            let ((next, _, _), counts) =
                observe(|| page_in(&fixture, index, Some(Arc::clone(&cache)), "cursor-fixture"));
            index = next;
            if counter(&cache, |c| c.jobs_certified) == 1 {
                assert_eq!(cache.proof_suspended_for_test(), None);
                assert_eq!(proof_drops(counts), 1);
                certified = true;
                break;
            }
            assert!(
                cache.proof_suspended_for_test().is_some(),
                "a page with no clone keeps the proof"
            );
        }
        assert!(certified, "precondition: the job certified");
        assert!(cache.take(&key).is_some(), "the certified copy is retained");
        let probe = super::super::copy_retire_probe().expect("probed");
        assert!(probe.budget > 0);
        assert_eq!(probe.proof, Some(0), "nothing of the proof at the clone");
        assert!(probe.fits(), "{probe:?}");
    });
}

/// Fix round 3 (DM3(2)): with a room whose budget is over `ENTRY_BYTES`,
/// the copy's share is the 8 MiB cap, so a suspended proof that fits
/// beside both shares (`room - budget - ENTRY_BYTES`) is kept where main
/// allocates, and the whole still fits `STATE_BYTES` at the clone.
#[test]
fn a_proof_beside_a_capped_copy_share_is_kept() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let context = main_context(&cache);
    let (budget, step) = super::super::copy_budget_step(Some(&context), None, false);
    let room = step.room().expect("a measured room");
    assert!(budget > ENTRY_BYTES, "precondition: a large room: {budget}");
    let fixed = proof_charge(&proof_job("ns-a", "/idx/a.json", "inc-1", 4096)) - 4096;
    let job = proof_job(
        "ns-a",
        "/idx/a.json",
        "inc-1",
        room - budget - ENTRY_BYTES - fixed - 4096,
    );
    let charge = proof_charge(&job);
    assert!(charge < room - budget - ENTRY_BYTES, "{charge}");
    assert!(
        charge > room - 2 * budget,
        "fix round 2 retired it: {charge}"
    );
    assert!(suspend(&cache, job));
    super::super::copy_retire_probe();
    let ((), counts) =
        observe(|| super::super::retire_proof_beside_copy(Some(&context), budget, step));
    assert!(cache.proof_suspended_for_test().is_some(), "kept");
    assert_eq!(proof_drops(counts), 0);
    let probe = super::super::copy_retire_probe().expect("probed");
    assert!(
        probe.proof.is_some_and(|proof| proof >= charge),
        "{probe:?}"
    );
    assert!(probe.fits(), "{probe:?}");
}

/// Fix round 3 (DM3, DL3), the completion site of an ordinary (not cursor)
/// singleton read: it retains its copy with a budget over `ENTRY_BYTES`,
/// and retires a suspended proof only over what both shares leave of the
/// room: a third of the state budget is retired before the clone; one that
/// fits beside the finish/output share and the 8 MiB-capped copy is kept.
/// Either way the whole fits `STATE_BYTES` at the clone.
#[test]
fn an_ordinary_completion_retires_only_a_proof_over_both_shares() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let room = {
        let cache = Arc::new(SharedCache::default());
        let context = main_context(&cache);
        let (_, step) = super::super::copy_budget_step(Some(&context), None, false);
        step.room().expect("a measured room")
    };
    let fixed = proof_charge(&proof_job("ns-a", "/idx/a.json", "inc-1", 4096)) - 4096;
    assert!(room / 2 > ENTRY_BYTES + (2 << 20), "precondition: {room}");
    let beside = room / 2 - ENTRY_BYTES - (1 << 20) - fixed;
    for (bytes, retired) in [(STATE_BYTES / 3, true), (beside, false)] {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        assert!(suspend(
            &cache,
            proof_job("ns-a", "/idx/a.json", "inc-1", bytes)
        ));
        super::super::copy_retire_probe();
        let (_, counts) = observe(|| {
            page_in(
                &fixture,
                ScanIndex::default(),
                Some(Arc::clone(&cache)),
                "cursor-fixture",
            )
        });
        assert_eq!(counter(&cache, |c| c.jobs_paused), 0, "not a cursor job");
        assert!(cache.take(&key).is_some(), "the copy is retained");
        let probe = super::super::copy_retire_probe().expect("probed");
        assert!(probe.budget > ENTRY_BYTES, "{probe:?}");
        assert!(probe.fits(), "{probe:?}");
        assert_eq!(cache.proof_suspended_for_test().is_none(), retired);
        assert_eq!(proof_drops(counts), u64::from(retired));
        if retired {
            assert_eq!(probe.proof, Some(0), "nothing of the proof at the clone");
        } else {
            assert!(probe.proof.is_some_and(|proof| proof >= bytes), "{probe:?}");
        }
    }
}

/// Fix round 3 (DM3(1)): a completion that cannot retain a copy (an
/// incomplete sidecar census: the cursor job publishes unverified, with no
/// certificate) passes no copy budget, so a suspended proof of a third of
/// the state budget is kept through every page, its completion included.
#[test]
fn a_completion_that_retains_no_copy_keeps_the_proof() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    clock.set(1_900_000_000);
    let incomplete = |scan: &mut OwnedSourceScan| scan.sidecar_census_complete = false;
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let key = local_index_key(&fixture.file(SESSION));
        let cache = Arc::new(SharedCache::default());
        assert!(suspend(
            &cache,
            proof_job("ns-a", "/idx/a.json", "inc-1", STATE_BYTES / 3)
        ));
        super::super::copy_retire_probe();
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let ((next, _, _), counts) = observe(|| {
                page_with(
                    &fixture,
                    index,
                    Some(Arc::clone(&cache)),
                    "cursor-fixture",
                    NOW,
                    incomplete,
                )
            });
            index = next;
            assert_eq!(proof_drops(counts), 0);
            assert!(cache.proof_suspended_for_test().is_some(), "kept");
            if counter(&cache, |c| c.jobs_certified) == 1 {
                break;
            }
        }
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            1,
            "{}",
            counters(&cache)
        );
        assert!(cache.retained_checkpoint(&key).is_none(), "no copy kept");
        assert!(
            super::super::copy_retire_probe().is_none(),
            "no budgeted retire"
        );
    });
}

// ---------------------------------------------------------------------------
// U1a-2a D6(e): M1's release to fit measures main's cursor state (no
// suspended proof) and retires the proof first, under the same locks.

type SideCounts = crate::local_resource_diagnostics::codex_side_lifecycle::Counts;
type CacheCounts = crate::local_resource_diagnostics::cache_lifecycle::Counts;

/// The `FILLERS` filled shared cache (`cache_policy_tests::filled_cache`),
/// with a suspended proof when `proof`, and its measures.
struct ReleaseScene {
    cache: Arc<SharedCache>,
    /// Main's cursor state (`cursor_resident_for_main`).
    main: usize,
    /// The retained copies' bound.
    resident: usize,
    /// One filler's charge.
    filler: usize,
    /// The proof's charge (suspended only when `proof`).
    proof: usize,
}
impl ReleaseScene {
    fn new(proof: bool) -> Self {
        let (cache, filler) = crate::snapshots::cache_policy_tests::filled_cache();
        let job = proof_job("ns-a", "/idx/a.json", "inc-1", 4096);
        let charge = proof_charge(&job);
        if proof {
            assert!(
                suspend(&cache, job),
                "precondition: the proof fits beside the fillers"
            );
        }
        let main = cache.cursor_resident_for_main();
        assert_eq!(
            cache.cursor_resident(),
            main + if proof { charge } else { 0 }
        );
        Self {
            resident: retained_floor(&cache),
            cache,
            main,
            filler,
            proof: charge,
        }
    }
    /// The `pinned` at which the copies fit exactly beside main's state.
    fn exact(&self) -> usize {
        STATE_BYTES - self.main - self.resident
    }
    /// `pinned` at which even an empty retained cache would not fit.
    fn unreachable(&self) -> usize {
        let floor =
            crate::heap_layout_bound::bound(&super::super::RetainedCache::default(), STATE_BYTES)
                .unwrap();
        STATE_BYTES - self.main - floor + 1
    }
    /// M1's release (`release_to_fit`) or Path A (`release_older_to_fit`)
    /// at `rank`, observing both counter sets.
    fn release(
        &self,
        pinned: usize,
        path_a: Option<(i64, i64)>,
    ) -> (bool, SideCounts, CacheCounts) {
        let ((released, side), counts) =
            crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
                crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| match path_a {
                    Some(rank) => self.cache.release_older_to_fit(pinned, rank),
                    None => self.cache.release_to_fit(pinned),
                })
            });
        (released, side, counts)
    }
    fn fillers(&self) -> usize {
        crate::snapshots::cache_policy_tests::fillers_resident(&self.cache)
    }
    /// What the release charged, all of it: the copies, the whole cursor
    /// state (any proof left included) and `pinned`.
    fn charged(&self, pinned: usize) -> usize {
        retained_floor(&self.cache) + self.cache.cursor_resident() + pinned
    }
}

fn evicted(counts: &CacheCounts) -> (u64, u64, u64) {
    (
        counts.copy_refusal_entries_evicted,
        counts.copy_refusal_admission_evicted,
        counts.copy_refusal_bytes_released,
    )
}

const NONE_OLDER: (i64, i64) = (0, 0);
const ALL_OLDER: (i64, i64) = (i64::MAX, 0);

/// D6(e) (a), (d): over budget only beside a suspended proof. M1's release
/// retires the proof first, counted under its own cause, and evicts no
/// copy; with room for both, the proof stays. One retained lock, then one
/// cursor critical section: the proof's box is freed under them (a
/// `ProofJob` and its readers have no `Drop` that locks), a relock would
/// trip the `retained` and `with_cursor` debug guards, and both locks are
/// free and unpoisoned after.
#[test]
fn release_to_fit_retires_a_suspended_proof_before_any_copy() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::cache_policy_tests::FILLERS;
    let scene = ReleaseScene::new(true);
    let pinned = scene.exact() - scene.proof;
    let (released, side, counts) = scene.release(pinned, None);
    assert!(released);
    assert!(scene.cache.proof_suspended_for_test().is_some());
    assert_eq!(side, SideCounts::default());
    assert_eq!(evicted(&counts), (0, 0, 0));
    assert_eq!(scene.charged(pinned), STATE_BYTES);
    // One byte more: the proof goes, and no copy does.
    let (released, side, counts) = scene.release(pinned + 1, None);
    assert!(released);
    assert_eq!(scene.cache.proof_suspended_for_test(), None);
    assert_eq!(
        (side.side_proof_release_drops, side.side_proof_drops),
        (1, 0)
    );
    assert_eq!(evicted(&counts), (0, 0, 0), "{counts:?}");
    assert_eq!(scene.fillers(), FILLERS);
    assert_eq!(scene.cache.cursor_resident(), scene.main);
    assert!(scene.charged(pinned + 1) <= STATE_BYTES);
    // (d) Nothing is held, locked or poisoned after the drop.
    assert!(!cursor_held());
    assert!(scene.cache.inner.try_lock().is_ok());
    assert!(scene.cache.cursor.try_lock().is_ok());
    assert_eq!(scene.cache.cursor_reserved(), 0);
}

/// D6(e) (b): Path A likewise, with no copy ranked older than the tail: an
/// overflow the proof covers retires the proof and evicts nothing; one past
/// it cannot fit, so nothing goes, the proof included (fit-or-nothing).
#[test]
fn release_older_to_fit_retires_the_proof_only_where_path_a_fits() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::cache_policy_tests::FILLERS;
    let scene = ReleaseScene::new(true);
    let (released, side, counts) = scene.release(scene.exact() + 1, Some(NONE_OLDER));
    assert!(!released);
    assert!(scene.cache.proof_suspended_for_test().is_some());
    assert_eq!(side, SideCounts::default());
    assert_eq!(evicted(&counts), (0, 0, 0));
    let pinned = scene.exact() - scene.proof + 1;
    let (released, side, counts) = scene.release(pinned, Some(NONE_OLDER));
    assert!(released);
    assert_eq!(scene.cache.proof_suspended_for_test(), None);
    assert_eq!(
        (side.side_proof_release_drops, side.side_proof_drops),
        (1, 0)
    );
    assert_eq!(evicted(&counts), (0, 0, 0), "{counts:?}");
    assert_eq!(scene.fillers(), FILLERS);
    assert!(scene.charged(pinned) <= STATE_BYTES);
}

/// D6(e) (c) and no-proof parity: an overflow past the proof retires the
/// proof first, then evicts in victim order only what main's room still
/// needs, exactly what the same release evicts with no proof (one copy),
/// for M1's release and for Path A with every copy ranked older.
#[test]
fn a_proof_smaller_than_the_overflow_goes_first_then_the_minimal_copies() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::cache_policy_tests::FILLERS;
    for path_a in [None, Some(ALL_OLDER)] {
        let mut outcomes = Vec::new();
        for proof in [true, false] {
            let scene = ReleaseScene::new(proof);
            assert!(scene.proof < scene.filler / 2, "precondition");
            let pinned = scene.exact() + scene.filler / 2;
            let (released, side, counts) = scene.release(pinned, path_a);
            assert!(released, "{path_a:?} proof={proof}");
            assert_eq!(scene.cache.proof_suspended_for_test(), None);
            assert_eq!(
                (side.side_proof_release_drops, side.side_proof_drops),
                (u64::from(proof), 0)
            );
            assert!(scene.charged(pinned) <= STATE_BYTES);
            outcomes.push((
                counts.copy_refusal_entries_evicted,
                counts.copy_refusal_admission_evicted,
                scene.fillers(),
            ));
        }
        assert_eq!(outcomes[0], outcomes[1], "the no-proof decision");
        let one = if path_a.is_some() { (0, 1) } else { (1, 0) };
        assert_eq!(outcomes[0], (one.0, one.1, FILLERS - 1), "{path_a:?}");
    }
}

/// D6(e) no-proof parity and the charge bound: with no proof, main's measure
/// is the whole cursor state, so M1's limit is unchanged. `pinned` carries
/// the side ledger's fixed charge once and nothing adds it again: copies
/// fitting exactly beside main's state and `pinned` evict nothing (as the
/// cursor admission floor agrees, F4b), one byte more evicts one copy, an
/// unreachable fit evicts nothing. No proof drop is counted.
#[test]
fn with_no_proof_the_release_is_m1s() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::local_resource_diagnostics::cache_lifecycle::observe;
    use crate::snapshots::cache_policy_tests::FILLERS;
    use crate::snapshots::sampled_scan::side_ledger::SIDE_LEDGER_BYTES;
    let scene = ReleaseScene::new(false);
    assert_eq!(scene.cache.cursor_resident(), scene.main);
    let exact = scene.exact();
    assert!(exact > SIDE_LEDGER_BYTES, "precondition");
    let (credit, counts) = observe(|| scene.cache.cursor_reserve(exact - SIDE_LEDGER_BYTES));
    credit
        .expect("F4b: the cursor admission floor agrees")
        .refund();
    assert_eq!(counts.cursor_reservation_entries_evicted, 0);
    for path_a in [Some(NONE_OLDER), None] {
        for (pinned, fits) in [
            (exact, true),
            (scene.unreachable(), false),
            (usize::MAX, false),
        ] {
            let (released, side, counts) = scene.release(pinned, path_a);
            assert_eq!(released, fits, "{path_a:?} {pinned}");
            assert_eq!(side, SideCounts::default());
            assert_eq!(evicted(&counts), (0, 0, 0));
            assert_eq!(scene.fillers(), FILLERS);
        }
    }
    let (released, side, counts) = scene.release(exact + 1, Some(NONE_OLDER));
    assert!(!released, "nothing older: Path A fits or evicts nothing");
    assert_eq!((side, evicted(&counts)), (SideCounts::default(), (0, 0, 0)));
    let (released, side, counts) = scene.release(exact + 1, None);
    assert!(released);
    assert_eq!(side, SideCounts::default());
    assert_eq!(counts.copy_refusal_entries_evicted, 1);
    assert_eq!(scene.fillers(), FILLERS - 1);
    assert!(scene.charged(exact + 1) <= STATE_BYTES);
}

/// D6(e): a release that cannot measure keeps M1's refusal and drops no
/// proof: an unreachable fit, a `pinned` past the budget, unsupported
/// (overflowing) cursor accounting, a poisoned cursor lock. No copy goes.
#[test]
fn a_release_without_a_measure_drops_no_proof() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::cache_policy_tests::FILLERS;
    let scene = ReleaseScene::new(true);
    let overflow = scene.exact() + scene.filler / 2;
    let refuses = |pinned: usize, label: &str| {
        for path_a in [None, Some(ALL_OLDER)] {
            let (released, side, counts) = scene.release(pinned, path_a);
            assert!(!released, "{label} {path_a:?}");
            assert_eq!(side, SideCounts::default(), "{label}");
            assert_eq!(evicted(&counts), (0, 0, 0), "{label}");
            assert_eq!(scene.fillers(), FILLERS, "{label}");
        }
    };
    refuses(scene.unreachable(), "unreachable");
    refuses(usize::MAX, "past the budget");
    assert!(scene.cache.proof_suspended_for_test().is_some());
    scene
        .cache
        .with_cursor(|cursor| cursor.reserved = usize::MAX);
    refuses(overflow, "unsupported accounting");
    scene.cache.with_cursor(|cursor| cursor.reserved = 0);
    assert!(scene.cache.proof_suspended_for_test().is_some());
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        scene.cache.with_cursor(|_| panic!("poison the cursor"));
    }));
    assert!(unwound.is_err());
    assert!(!cursor_held());
    refuses(overflow, "poisoned cursor");
}

// Continuation fixtures drive the enabled resume-only scan frame directly.

/// Steps `scan` to completion with the collector's post-policy finalization
/// (as `page_selections`).
fn finish_page(mut scan: OwnedSourceScan) -> (ScanIndex, SourceScanResult) {
    let root = scan.roots[0].clone();
    let continuation = scan.codex_page.continuation();
    for _ in 0..100_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                carry(&root, &mut scan);
                if continuation {
                    return (index, scan);
                }
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan);
            }
        }
    }
    panic!("the continuation page did not finish");
}

/// One continuation page of the paused job whose member index keys are
/// `members`, over `root` (`days` as the ordinary pages used),
/// standing for `ordinary` of the ordinary cadence (§6).
#[allow(clippy::too_many_arguments)]
fn continuation_page_in(
    root: &Path,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    namespace: &str,
    collected_at: &str,
    days: u64,
    ordinary: Option<std::time::Duration>,
    tweak: impl Fn(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult) {
    let mut scan = OwnedSourceScan::new_continuation(
        std::slice::from_ref(&root.to_path_buf()),
        index,
        collected_at,
        days,
        10,
        false,
        ordinary,
        carried(root),
    );
    tweak(&mut scan);
    finish_page(scan.with_sampled_acquisition(Arc::clone(cache), Scope(namespace.into())))
}

/// `continuation_page_in` over a `ScanRoot` page's settings, with today's
/// production ordinary equivalent (`None`: unknown, so the resumed attempt
/// loses its acceleration and mints no further ticket).
fn continuation_page(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    tweak: impl Fn(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult) {
    continuation_page_in(
        &fixture.root,
        index,
        cache,
        "cursor-fixture",
        NOW,
        BACKFILL_WINDOW_DAYS,
        None,
        tweak,
    )
}

/// A `ScanRoot` page that leaves SESSION's job paused (scaled budgets), and
/// the job's member keys.
fn paused_singleton(fixture: &ScanRoot, cache: &Arc<SharedCache>) -> (ScanIndex, BTreeSet<String>) {
    let (index, _) = page(fixture, ScanIndex::default(), Some(Arc::clone(cache)));
    assert_eq!(counter(cache, |c| c.jobs_paused), 1, "{}", counters(cache));
    let members = cache.paused_members_for_test().expect("paused job");
    assert_eq!(
        members,
        BTreeSet::from([local_index_key(&fixture.file(SESSION))])
    );
    (index, members)
}

/// §7 D: a continuation page selects only the paused job's pending paths:
/// it resumes the job and leaves every other pending path queued and
/// unread. It never plans or starts an attempt (`jobs_started`,
/// `groups_started` unchanged) and pages the job to its one completion,
/// with the unpaged read's output.
#[test]
fn continuation_selects_only_job_paths_and_never_starts_attempts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::with_sessions(&[(SESSION, 80), (SESSION_B, 2)]);
    let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
    let other = fixture.file(SESSION_B);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let (mut index, _) = paused_singleton(&fixture, &cache);
        // SESSION_B was read as a singleton; queue it again as a fresh
        // census member the next ordinary page would select.
        let template = index
            .traversal
            .as_ref()
            .unwrap()
            .pending_candidates
            .iter()
            .find(|pending| pending.path == fixture.file(SESSION))
            .cloned()
            .expect("the paused job's path stays pending");
        let traversal = index.traversal.as_mut().unwrap();
        if !traversal.pending_candidates.iter().any(|p| p.path == other) {
            let mut queued = template;
            queued.path = other.clone();
            traversal.pending_candidates.push_back(queued);
        }
        let entry = |index: &ScanIndex| {
            serde_json::to_value(index.files.get(&local_index_key(&other))).unwrap()
        };
        let other_entry = entry(&index);
        let started = counter(&cache, |c| c.jobs_started);
        let groups = counter(&cache, |c| c.groups_started);
        let mut published = None;
        for _ in 0..64 {
            let resumed = counter(&cache, |c| c.jobs_resumed);
            let (next, scan) = continuation_page(&fixture, index, &cache, |_| {});
            index = next;
            assert_eq!(counter(&cache, |c| c.jobs_resumed), resumed + 1);
            assert_eq!(counter(&cache, |c| c.jobs_started), started);
            assert_eq!(counter(&cache, |c| c.groups_started), groups);
            assert!(pending_hint(&index, &other).is_some(), "still queued");
            assert_eq!(entry(&index), other_entry, "never read");
            assert!(
                scan.continuation_ticket().is_none(),
                "an unknown ordinary equivalent ends the attempt's acceleration"
            );
            assert!(scan.snapshots.is_empty());
            if parked_eof(&cache) {
                let (_, ordinary) = page(&fixture, index, Some(Arc::clone(&cache)));
                published = Some(ordinary);
                break;
            }
            assert!(scan.snapshots.is_empty(), "a paused job publishes nothing");
        }
        let published = published.unwrap_or_else(|| panic!("{}", counters(&cache)));
        assert!(cache.cursor_slot_free());
        // Only the job's file publishes, as the unpaged read does.
        let unpaged = fingerprints(&unpaged);
        let published = fingerprints(&published);
        assert!(!published.is_empty());
        assert!(published
            .iter()
            .all(|fingerprint| unpaged.contains(fingerprint)));
    });
}

/// §7 D (N3): group preparation on a continuation page. The paused group's
/// job stays parked: continuation refuses it before stepping or applying EOF.
/// `groups_started` stays one until the ordinary pass completes the group.
#[test]
fn continuation_prepares_no_group_attempt() {
    use crate::snapshots::codex_file_join::tests::usage;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const AT: &str = "2026-10-06T23:00:00Z";
    fn chain(prefix: &str, created: &str, start: u64) -> Vec<u8> {
        let mut body = codex_line(json!({"type": "session_meta", "timestamp": created,
            "payload": {"id": OWNER, "timestamp": created}}));
        for i in 0..30_u64 {
            let after = start + 10 * (i + 1);
            body.extend(codex_line(json!({"type": "token_usage_record",
                "timestamp": "2026-10-01T10:01:00Z", "payload": {"thread_id": OWNER,
                "response_id": format!("{prefix}-{i}"), "usage": usage(10),
                "thread_token_usage": usage(after)}})));
            let at = format!(
                "2026-10-01T{:02}:{:02}:{:02}Z",
                10 + after / 3600,
                after / 60 % 60,
                after % 60
            );
            body.extend(codex_line(json!({"type": "event_msg", "timestamp": at,
                "payload": {"type": "token_count", "info": {"last_token_usage": usage(10),
                "total_token_usage": usage(after)}}})));
        }
        body
    }
    let dir = Temp::new("group-continuation", b"");
    fs::remove_file(&dir.0).unwrap();
    let sessions = dir.0.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    fs::write(
        sessions.join("a.jsonl"),
        chain("a", "2026-10-01T10:00:00Z", 0),
    )
    .unwrap();
    fs::write(
        sessions.join("b.jsonl"),
        chain("b", "2026-10-01T10:30:00Z", 300),
    )
    .unwrap();
    let ordinary = |index: ScanIndex, cache: &Arc<SharedCache>| {
        finish_page(
            OwnedSourceScan::new(
                SnapshotSource::Codex,
                std::slice::from_ref(&sessions),
                index,
                AT,
                7,
                10,
                false,
                None,
                &[],
                false,
            )
            .with_sampled_acquisition(Arc::clone(cache), Scope("group-fixture".into())),
        )
    };
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        // Ordinary pages until the group job pauses (a group whose probes
        // outran a page takes a page of its own first).
        let mut index = ScanIndex::default();
        for _ in 0..8 {
            index = ordinary(index, &cache).0;
            if cache.paused_members_for_test().is_some() {
                break;
            }
        }
        let first = cache.counters_for_test();
        assert_eq!(first.groups_started, 1, "{first:?}");
        assert!(first.jobs_paused > 0, "{first:?}");
        let members = cache.paused_members_for_test().expect("paused group");
        assert_eq!(members.len(), 2, "both members belong to the job");
        let started = first.jobs_started;
        // Even a future acceleration regression must not mint a group ticket.
        let (mut job, lease) = cache
            .cursor_resume(&Scope("group-fixture".into()), false)
            .unwrap();
        let mut budget = PageBudget::default();
        budget.charge(true, Limits::current().cursor);
        let (_, ordinary_records) = crate::local_resource_diagnostics::capture(|| {
            assert!(cache
                .continuation_ticket(&job, &PageBudget::default())
                .is_none());
            assert!(cache.continuation_ticket(&job, &budget).is_none());
        });
        assert!(
            ordinary_records.is_empty(),
            "ordinary group pauses are not continuation holds"
        );
        job.cursor.as_mut().unwrap().pace.accelerate = true;
        let (_, refused_records) = crate::local_resource_diagnostics::capture(|| {
            assert!(cache.continuation_ticket(&job, &budget).is_none());
        });
        assert_eq!(refused_records.len(), 1);
        assert_eq!(
            refused_records[0]["counts"]["continuation_held"]["group_job"],
            1
        );
        assert!(matches!(lease.pause(job), PauseEnd::Paused));
        let resumed = counter(&cache, |c| c.jobs_resumed);
        GROUP_EOF_APPLIED.with(|v| v.set(0));
        for _ in 0..3 {
            let before = serde_json::to_value(&index).unwrap();
            let evidence = crate::snapshots::CodexContinuationEvidence::certified_for_test(
                std::slice::from_ref(&sessions),
                &members,
            );
            CARRIED.with(|v| v.borrow_mut().insert(sessions.clone(), evidence));
            let ((next, scan), records) = crate::local_resource_diagnostics::capture(|| {
                continuation_page_in(
                    &sessions,
                    index,
                    &cache,
                    "group-fixture",
                    AT,
                    7,
                    None,
                    |_| {},
                )
            });
            let holds = records
                .iter()
                .filter(|row| row["stage"] == "codex_continuation")
                .collect::<Vec<_>>();
            assert_eq!(holds.len(), 1);
            assert_eq!(holds[0]["counts"]["continuation_held"]["group_job"], 1);
            assert_eq!(holds[0]["counts"]["continuation_pages_run"], 0);
            index = next;
            let now = cache.counters_for_test();
            assert_eq!(now.groups_started, 1, "never restarted: {now:?}");
            assert_eq!(now.jobs_started, started, "{now:?}");
            assert_eq!(
                now.jobs_resumed, resumed,
                "group never resumed by continuation"
            );
            assert_eq!(serde_json::to_value(&index).unwrap(), before);
            assert!(scan.snapshots.is_empty());
            GROUP_EOF_APPLIED.with(|v| assert_eq!(v.get(), 0, "no continuation group EOF"));
        }
        // The unchanged ordinary path owns group completion and EOF application.
        for _ in 0..128 {
            index = ordinary(index, &cache).0;
            let now = cache.counters_for_test();
            assert_eq!(now.groups_started, 1, "ordinary resumes the same group");
            if now.jobs_certified + now.jobs_uncertified > 0 {
                assert!(cache.cursor_slot_free());
                GROUP_EOF_APPLIED.with(|v| assert!(v.get() > 0, "ordinary group EOF observed"));
                return;
            }
        }
        panic!(
            "ordinary group did not complete: {:?}",
            cache.counters_for_test()
        );
    });
}

/// §7 ready: `cursor_continuation_ready` readies the exact paused,
/// accelerated attempt (its members are the job's), and refuses a foreign,
/// stale or restarted ticket and an unaccelerated attempt. A refused ticket
/// names no members. No IO: only the cursor lock.
#[test]
fn ready_refuses_foreign_stale_restarted_or_unaccelerated_job() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        paused_singleton(&fixture, &cache);
        let exact = cache.paused_ticket_for_test().expect("paused job");
        let ready = |ticket: &CodexCursorTicket| cache.cursor_continuation_ready(ticket);
        let port = CodexCursorPort::new(Arc::clone(&cache));
        assert_eq!(ready(&exact), Ok(()));
        let members = cache.paused_members_for_test();
        assert!(members.is_some());
        assert_eq!(cache.continuation_members(&exact), members);
        assert!(port.ready(&exact));
        assert_eq!(port.members(&exact), members);
        let set_accelerate = |accelerate: bool| {
            cache
                .with_cursor(|cursor| {
                    if let Slot::Paused(job) = &mut cursor.slot {
                        job.cursor.as_mut().unwrap().pace.accelerate = accelerate;
                    }
                })
                .unwrap();
        };
        set_accelerate(false);
        assert_eq!(ready(&exact), Err(ReadyRefusal::Unaccelerated));
        assert_eq!(cache.continuation_members(&exact), None);
        assert!(!port.ready(&exact));
        assert_eq!(port.members(&exact), None);
        set_accelerate(true);
        let foreign = CodexCursorTicket {
            namespace: ticket_digest(b"namespace", &[b"other"]),
            ..exact.clone()
        };
        assert_eq!(ready(&foreign), Err(ReadyRefusal::Foreign));
        let other_file = CodexCursorTicket {
            key: ticket_digest(b"rotation_key", &[b"cursor-fixture", b"/other"]),
            ..exact.clone()
        };
        assert_eq!(ready(&other_file), Err(ReadyRefusal::Stale));
        let other_generation = CodexCursorTicket {
            fence: Some(ticket_digest(b"fence", &[b"another generation"])),
            ..exact.clone()
        };
        assert_eq!(ready(&other_generation), Err(ReadyRefusal::Stale));
        let restarted_attempt = CodexCursorTicket {
            started: exact.started + 1,
            ..exact.clone()
        };
        assert_eq!(ready(&restarted_attempt), Err(ReadyRefusal::Restarted));
        let restarted_cache = CodexCursorTicket {
            epoch: exact.epoch.wrapping_add(1),
            ..exact.clone()
        };
        assert_eq!(ready(&restarted_cache), Err(ReadyRefusal::Restarted));
        // A fresh cache (a process restart) never matches, and an empty
        // slot of the same cursor state is stale.
        let fresh = SharedCache::default();
        assert_eq!(
            fresh.cursor_continuation_ready(&exact),
            Err(ReadyRefusal::Restarted)
        );
        let epoch = fresh.with_cursor(|cursor| cursor.id).unwrap();
        assert_eq!(
            fresh.cursor_continuation_ready(&CodexCursorTicket {
                epoch,
                ..exact.clone()
            }),
            Err(ReadyRefusal::Stale)
        );
        // The digests bind full, length-prefixed values.
        assert_ne!(
            ticket_digest(b"rotation_key", &[b"ab", b"c"]),
            ticket_digest(b"rotation_key", &[b"a", b"bc"])
        );
        assert_eq!(
            crate::heap_layout_bound::bound(&exact, usize::MAX),
            Some(std::mem::size_of::<CodexCursorTicket>()),
            "fixed-size, inline"
        );
    });
}

// Stage 1 S1-b (`stage1/c14c15-answer.md` §6, §7 Guard row; conditions 2 and
// 4): the accelerate guard, its pace table and their accounting.

fn rev(ino: u64, extent: u64) -> OpenStamp {
    OpenStamp {
        dev: 1,
        ino,
        extent,
        modified: (1, 0),
        changed: (1, 0),
    }
}

fn secs(n: u64) -> std::time::Duration {
    std::time::Duration::from_secs(n)
}

/// A job's `JobMeta` around `pace` (accrual tests).
fn pace_meta(temp: &Temp, pace: JobPace) -> JobMeta {
    JobMeta {
        key: "key".into(),
        namespace: "namespace".into(),
        stamp_open: OpenStamp::capture(&File::open(&temp.0).unwrap()).unwrap(),
        started: 0,
        dependencies: None,
        owner: None,
        counting: String::new(),
        fence: None,
        census_trusted: true,
        pages: 1,
        unavailable_resumes: 0,
        charge: None,
        eof_applied: false,
        pace,
    }
}

/// `key`'s attempt begun at `t0` on `rev`, whose ordinary equivalent is
/// `equivalent` at its last page `at`, recorded there (a pause or an end).
fn paced(
    table: &mut PaceTable,
    key: [u64; 2],
    rev: &OpenStamp,
    t0: std::time::Instant,
    equivalent: std::time::Duration,
    at: std::time::Instant,
) {
    assert!(table.begin(key, rev, t0));
    let mut pace = JobPace::new(key, t0, true);
    pace.equiv_secs = Some(equivalent);
    pace.last_page_mono = at;
    assert!(table.record(&pace, at));
}

const START_UNACCELERATED: PaceVerdict = PaceVerdict::Start { accelerate: false };

/// §7 Guard, through the scan: an accelerated attempt that took a
/// continuation page standing for ten minutes, then was lost (its
/// equivalent kept), is not restarted on the same revision before that
/// equivalent. The paced deferral leaves the file pending (owed), and is not
/// a waiter (it blocks no other file's turn), a completion, a fence or a
/// loss. Once eligible, the restart is accelerated again.
#[test]
fn paced_defer_is_pending_not_waiter_not_fenced() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let path = fixture.file(SESSION);
    let waiter = rotation_key("cursor-fixture", &local_index_key(&path));
    let cache = Arc::new(SharedCache::default());
    let t0 = std::time::Instant::now();
    with_test_limits(2048, 1024, 64, || {
        let (index, _) = with_pace_clock(Some(t0), false, || paused_singleton(&fixture, &cache));
        let (index, scan) = with_pace_clock(Some(t0 + secs(1)), false, || {
            continuation_page_in(
                &fixture.root,
                index,
                &cache,
                "cursor-fixture",
                NOW,
                BACKFILL_WINDOW_DAYS,
                Some(secs(600)),
                |_| {},
            )
        });
        assert!(
            scan.continuation_ticket().is_some(),
            "a known equivalent keeps the attempt accelerated: {}",
            counters(&cache)
        );
        // The stale job is evicted (lost); its equivalent stays recorded.
        with_pace_clock(Some(t0 + secs(2)), false, || {
            cache
                .with_cursor(|cursor| cursor.rotation.page += NAMESPACE_STALE_PAGES)
                .unwrap();
            assert!(cache.cursor_resume(&Scope("other".into()), false).is_none());
        });
        assert_eq!(counter(&cache, |c| c.jobs_lost), 1);
        cache
            .with_cursor(|cursor| cursor.rotation.wait(&waiter))
            .unwrap();
        let (index, _) = with_pace_clock(Some(t0 + secs(3)), false, || {
            page(&fixture, index, Some(Arc::clone(&cache)))
        });
        let now = cache.counters_for_test();
        assert_eq!(now.deferred_paced, 1, "{now:?}");
        assert_eq!(now.jobs_started, 1, "{now:?}");
        assert_eq!(now.deferred_next_generation, 0, "not fenced: {now:?}");
        assert_eq!(now.jobs_lost, 1, "not a loss: {now:?}");
        assert_eq!(now.jobs_certified + now.jobs_uncertified, 0, "{now:?}");
        assert!(pending_hint(&index, &path).is_some(), "owed: still pending");
        cache
            .with_cursor(|cursor| {
                assert!(
                    !cursor.rotation.waiting.contains_key(&waiter),
                    "not a waiter"
                );
                assert!(cursor.rotation.turn("cursor-fixture\0/another"));
                assert!(
                    !cursor.rotation.attempted.contains_key(&waiter),
                    "not fenced"
                );
                assert!(
                    !cursor.rotation.served.contains_key(&waiter),
                    "not completed"
                );
            })
            .unwrap();
        assert!(cache.cursor_slot_free());
        // Eligible after the recorded equivalent (601 s from the start).
        with_pace_clock(Some(t0 + secs(601)), false, || {
            page(&fixture, index, Some(Arc::clone(&cache)))
        });
        let now = cache.counters_for_test();
        assert_eq!(now.deferred_paced, 1, "{now:?}");
        assert_eq!(now.jobs_started, 2, "{now:?}");
        let accelerated = cache
            .with_cursor(|cursor| match &cursor.slot {
                Slot::Paused(job) => job.cursor.as_ref().map(accelerated),
                Slot::Empty | Slot::ActiveElsewhere { .. } => None,
            })
            .flatten();
        assert_eq!(accelerated, Some(true), "{now:?}");
    });
}

/// §7 Guard, condition 2: a clock failure, an unknown ordinary interval or an
/// overflow is unknown coverage. The attempt loses its acceleration for good
/// (no further ticket); its pause or end forgets its slot and holds
/// `unknown_until` past its deadline and at least an hour ahead, so its next
/// start is today's, unaccelerated. Narrowing never shortens a deadline.
#[test]
fn pace_clock_failure_is_unknown() {
    let temp = Temp::new("pace-clock", b"{}\n");
    let t0 = std::time::Instant::now();
    let key = pace_key("ns", "s", "/a");
    let same = rev(1, 100);
    let mut table = PaceTable::default();
    assert!(table.begin(key, &same, t0));
    let mut meta = pace_meta(&temp, JobPace::new(key, t0, true));
    with_pace_clock(Some(t0 + secs(5)), true, || {
        assert_eq!(accrue_equivalent(&mut meta, true, Some(secs(600))), None);
    });
    assert!(!meta.pace.accelerate);
    assert_eq!(meta.pace.equiv_secs, None);
    with_pace_clock(Some(t0 + secs(6)), false, || {
        assert_eq!(accrue_equivalent(&mut meta, false, None), None, "sticky");
    });
    assert!(!meta.pace.accelerate);
    assert!(!table.record(&meta.pace, t0 + secs(6)));
    assert!(table.position(key).is_none());
    assert_eq!(table.unknown_until, Some(t0 + secs(3_606)));
    assert_eq!(table.verdict(key, &same, t0 + secs(7)), START_UNACCELERATED);
    // A failing elapsed time at the record itself forgets the slot too.
    let other = pace_key("ns", "s", "/b");
    paced(&mut table, other, &rev(2, 1), t0, secs(9_000), t0);
    let pace = JobPace::new(other, t0, true);
    with_pace_clock(None, true, || assert!(!table.record(&pace, t0 + secs(8))));
    assert!(table.position(other).is_none());
    assert_eq!(
        table.unknown_until,
        Some(t0 + secs(9_000)),
        "past its deadline"
    );
    // Production's continuation input today is unknown (`None`).
    let mut continued = pace_meta(&temp, JobPace::new(other, t0, true));
    with_pace_clock(Some(t0 + secs(9)), false, || {
        assert_eq!(accrue_equivalent(&mut continued, true, None), None);
    });
    assert!(!continued.pace.accelerate);
    // Narrowing rounds up and refuses what a u32 offset cannot hold.
    assert_eq!(
        pace_offset(std::time::Duration::from_millis(1_001)),
        Some(2)
    );
    assert_eq!(pace_offset(secs(u64::from(u32::MAX))), Some(u32::MAX));
    assert_eq!(pace_offset(secs(u64::from(u32::MAX) + 1)), None);
    let huge = pace_key("ns", "s", "/huge");
    assert!(table.begin(huge, &rev(3, 1), t0));
    let mut overflow = JobPace::new(huge, t0, true);
    overflow.equiv_secs = Some(secs(u64::from(u32::MAX) + 1));
    overflow.last_page_mono = t0;
    assert!(
        !table.record(&overflow, t0),
        "overflow: unknown, never a shorter deadline"
    );
    assert!(table.position(huge).is_none());
}

/// Every live pace slot of `cache` (64 distinct keys), deadlines ahead.
fn fill_pace(cache: &SharedCache) {
    let t0 = std::time::Instant::now();
    cache
        .with_cursor(|cursor| {
            for i in 0..ROTATION_KEYS {
                let key = pace_key("fill", "s", &i.to_string());
                paced(
                    &mut cursor.pace,
                    key,
                    &rev(i as u64, 1),
                    t0,
                    secs(9_000),
                    t0,
                );
            }
        })
        .unwrap();
}

/// [behaviour] Condition 4 accounting, each site exactly once:
/// - cursor feasibility and reservation (`state_for_main`, `cursor_resident`)
///   carry the table inside `size_of_val(CursorState)` and never walk it;
/// - the whole-cache bound carries it inside `size_of::<SharedCache>()` (the
///   `Arc` payload) and not in the locked parts;
/// - `context_overhead`, which every release (copy refusal, Path A, and
///   #665's X_out/peak `prove_release` through `release_room_for_main`) adds
///   beside `state_for_main`, leaves it out;
/// - a job's pace facts are inside its own walk (`paused_charge`), with no
///   heap, and the table is not reachable from a job.
#[test]
fn pace_table_is_charged_once_in_admission_release_and_whole_cache() {
    use crate::heap_layout_bound::bound;
    use std::mem::{align_of, size_of};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let side = crate::snapshots::sampled_scan::side_ledger::SIDE_LEDGER_BYTES;
    let cache = Arc::new(SharedCache::default());
    let walked = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| {
                let mut c = Counter::new(usize::MAX);
                cursor.heap_bound(&mut c).unwrap();
                c.bytes
            })
            .unwrap()
    };
    let empty_heap = walked(&cache);
    let main_state = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| state_for_main(cursor))
            .flatten()
            .unwrap()
    };
    let empty_state = main_state(&cache);
    fill_pace(&cache);
    let state = main_state(&cache);
    assert_eq!(state, empty_state, "a full table adds no walked bytes");
    assert_eq!(walked(&cache), empty_heap);
    assert_eq!(
        state,
        size_of::<CursorState>() + empty_heap,
        "once, via size_of_val"
    );
    assert_eq!(cache.cursor_resident(), state);
    // Whole cache: once, in the `Arc` payload; the locked parts never carry it.
    let mut whole = Counter::new(usize::MAX);
    cache.heap_bound(&mut whole).unwrap();
    let mut parts = Counter::new(usize::MAX);
    cache.inner.heap_bound(&mut parts).unwrap();
    cache.cursor.heap_bound(&mut parts).unwrap();
    cache.withheld_memo.heap_bound(&mut parts).unwrap();
    assert_eq!(
        whole.bytes,
        size_of::<SharedCache>()
            + align_of::<SharedCache>()
            + 2 * size_of::<usize>()
            + parts.bytes
            + side
    );
    // The release math: `context_overhead` without the table, beside
    // `state_for_main` with it.
    let fixture = ScanRoot::new(4);
    let scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
    )
    .with_sampled_acquisition(Arc::clone(&cache), Scope("ns".into()));
    let context = scan.sampling.as_ref().unwrap();
    let overhead = crate::snapshots::sampled_scan::context_overhead(context).unwrap();
    assert_eq!(
        overhead,
        size_of::<crate::snapshots::sampled_scan::Context>() + size_of::<SharedCache>()
            - size_of::<PaceTable>()
            + align_of::<SharedCache>()
            + 2 * size_of::<usize>()
            + side
            + bound(&context.namespace, STATE_BYTES).unwrap()
            + bound(&context.admission, STATE_BYTES).unwrap()
    );
    assert!(crate::snapshots::sampled_scan::context_overhead_covers(
        context
    ));
    let retained = cache.retained().unwrap();
    let room = cache.release_room_for_main(&retained, overhead, |_| true);
    assert_eq!(room, Some(STATE_BYTES - state - overhead));
    drop(retained);
    // A job: its pace facts walk to nothing beyond its own size.
    let temp = Temp::new("pace-job", b"{}\n");
    let meta = pace_meta(&temp, JobPace::new([1; 2], std::time::Instant::now(), true));
    let mut c = Counter::new(usize::MAX);
    meta.pace.heap_bound(&mut c).unwrap();
    assert_eq!(c.bytes, 0);
}

/// Carried evidence removes the parent sample re-probe. Continuation also
/// keeps the existing G7, side-due, proof-hook and sweep exclusions.
#[test]
fn continuation_parent_evidence_is_carried_and_exclusions_hold() {
    use std::os::unix::fs::MetadataExt;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::with_sessions(&[(SESSION, 80), (SESSION_B, 2)]);
    let parent = fixture.file(SESSION_B);
    let cache = Arc::new(SharedCache::default());
    let index_path = Path::new("/tmp/ottto-s1b-q1-index.json");
    with_test_limits(2048, 1024, 64, || {
        let (mut index, members) = paused_singleton(&fixture, &cache);
        assert!(!members.contains(&local_index_key(&parent)));
        let traversal = index.traversal.as_ref().expect("the job's traversal");
        assert!(crate::snapshots::codex_frozen_census_valid(traversal));
        assert!(
            traversal
                .codex_rollout_paths
                .iter()
                .any(|path| path.ends_with(&format!("{SESSION_B}.jsonl"))),
            "the parent is in the frozen census"
        );
        // A G7/side-due candidate on the owed parent, and a sweep orphan.
        let meta = fs::metadata(&parent).unwrap();
        index.codex_parent_side_requests.insert(
            local_index_key(&parent),
            crate::snapshots::SideRequest {
                dev_ino: (meta.dev(), meta.ino()),
                needed_extent: meta.len() + 1,
                state: crate::snapshots::SideRequestState::Live,
                state_extent: meta.len(),
                state_ctime: (meta.ctime(), meta.ctime_nsec()),
                attempt_extent: 0,
                attempt_ctime: (0, 0),
                attempts: 0,
                not_before_unix_seconds: 0,
                needed_charge: None,
                referenced_epoch: 0,
            },
        );
        let orphan = "/nonexistent/s1b-q1-orphan-rollout.jsonl".to_owned();
        index.codex_parent_side.insert(
            orphan.clone(),
            serde_json::from_value(serde_json::json!({
                "verdict": { "kind": "settled" },
                "seal": {
                    "stamp": {
                        "length": 4096,
                        "device": 1,
                        "inode": 2,
                        "modified": [1_792_540_800, 5],
                        "changed": [1_792_540_800, 5],
                    },
                    "scope": crate::snapshots::codex_parent_side_scope().0,
                    "sample_len": 4096,
                    "head_sha256": "a".repeat(64),
                    "boundary_sha256": "b".repeat(64),
                    "verified_unix_seconds": 1_792_540_800,
                    "sealed_unix_seconds": 1_792_540_800,
                },
                "parsed": {
                    "dev": 1,
                    "ino": 2,
                    "extent": 4096,
                    "modified": [1_792_540_800, 5],
                    "changed": [1_792_540_800, 5],
                },
                "generation": 1,
                "referenced_epoch": 0,
            }))
            .unwrap(),
        );
        for page in 0..64 {
            // The parent stays owed: referenced, with no completed ledger.
            index
                .codex_parent_ownership_refs
                .insert(SESSION_B.to_owned());
            index.codex_parent_ownership_ledgers.remove(SESSION_B);
            let pass = crate::snapshots::begin_codex_continuation_side_pass(
                &cache, index_path, &mut index,
            );
            assert_eq!(pass.kind, crate::snapshots::CodexPageKind::Continuation);
            let ledger = cache.side_ledger().len();
            let requests = serde_json::to_value(&index.codex_parent_side_requests).unwrap();
            let side = serde_json::to_value(&index.codex_parent_side).unwrap();
            let sweep = index.codex_parent_side_cursor.clone();
            let matches = crate::snapshots::codex_parent_step_start_matches_for_test();
            let mut scan = OwnedSourceScan::new_continuation(
                std::slice::from_ref(&fixture.root),
                index,
                NOW,
                BACKFILL_WINDOW_DAYS,
                10,
                false,
                Some(secs(600)),
                carried(&fixture.root),
            )
            .with_sampled_acquisition(Arc::clone(&cache), Scope("cursor-fixture".into()))
            .with_codex_side_pass(Some(pass));
            let mut singleton = 0;
            let mut steps = 0;
            let result = loop {
                assert!(steps < 100_000, "page {page}: the page did not finish");
                steps += 1;
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => {
                        singleton = next.codex_page.singleton_decoded;
                        scan = next;
                    }
                    OwnedSourceScanStep::Complete {
                        index: next, scan, ..
                    } => {
                        index = next;
                        break scan;
                    }
                }
            };
            let matched = crate::snapshots::codex_parent_step_start_matches_for_test() - matches;
            assert_eq!(matched, 0, "carried evidence: no parent re-probe");
            assert_eq!(singleton, 0, "no parent sample reads");
            // The four exclusions, on the same page.
            assert_eq!(cache.side_ledger().len(), ledger, "page {page}: no G7");
            assert_eq!(
                serde_json::to_value(&index.codex_parent_side_requests).unwrap(),
                requests,
                "page {page}: no G7 or side-due write"
            );
            assert_eq!(
                cache.proof_suspended_for_test(),
                None,
                "page {page}: no hook job"
            );
            assert_eq!(
                serde_json::to_value(&index.codex_parent_side).unwrap(),
                side,
                "page {page}: not swept"
            );
            assert!(index.codex_parent_side.contains_key(&orphan));
            assert_eq!(index.codex_parent_side_cursor, sweep, "page {page}");
            let mut result = result;
            carry(&fixture.root, &mut result);
            if parked_eof(&cache) {
                assert!(page > 0, "the job spans continuation pages");
                assert_eq!(counter(&cache, |c| c.jobs_certified), 0);
                assert!(result.snapshots.is_empty());
                return;
            }
        }
        panic!("{}", counters(&cache));
    });
}

// Stage 1 integration (StateMissing, under c22's K5/K6/K7/W9 rulings): the
// leased deadline and capture lines, the no-save continuation contract and a
// worker panic's next ordinary page. New tests only.

/// K6 through the scan: a continuation page past its deadline pauses the
/// job at the next `step()` return, still paused and resumable, and mints no
/// ticket (`PausedContended`); the same page without a deadline keeps the
/// attempt accelerated.
#[test]
fn continuation_page_past_its_deadline_pauses_without_a_ticket() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let cache = Arc::new(SharedCache::default());
    let t0 = std::time::Instant::now();
    with_test_limits(2048, 1024, 64, || {
        let (index, members) =
            with_pace_clock(Some(t0), false, || paused_singleton(&fixture, &cache));
        let paused = counter(&cache, |c| c.jobs_paused);
        let (_, scan) = with_pace_clock(Some(t0 + secs(10)), false, || {
            continuation_page_in(
                &fixture.root,
                index.clone(),
                &cache,
                "cursor-fixture",
                NOW,
                BACKFILL_WINDOW_DAYS,
                Some(secs(600)),
                |scan| scan.codex_page.set_continuation_deadline(t0 + secs(5)),
            )
        });
        assert!(
            scan.continuation_ticket().is_none(),
            "a deadline pause mints no ticket: {}",
            counters(&cache)
        );
        assert!(scan.snapshots.is_empty());
        assert_eq!(counter(&cache, |c| c.jobs_paused), paused + 1);
        assert_eq!(cache.paused_members_for_test(), Some(members.clone()));
        let (_, scan) = with_pace_clock(Some(t0 + secs(11)), false, || {
            continuation_page_in(
                &fixture.root,
                index,
                &cache,
                "cursor-fixture",
                NOW,
                BACKFILL_WINDOW_DAYS,
                Some(secs(600)),
                |_| {},
            )
        });
        assert!(
            scan.continuation_ticket().is_some(),
            "no deadline: the byte budget, as today: {}",
            counters(&cache)
        );
    });
}

/// K7.2 proof: a continuation page whose job's member changed under it is
/// not saved. The ordinary pages that follow, from the index the minting
/// page saved, re-derive the whole debt: they publish exactly the unpaged
/// read of the changed file, nothing older and nothing lost. Pace clock: the
/// changed revision waits the guard's equivalent first (deferred, not lost).
#[test]
fn a_dropped_continuation_end_leaves_its_debt_to_the_ordinary_pass() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let path = fixture.file(SESSION);
    let cache = Arc::new(SharedCache::default());
    let t0 = std::time::Instant::now();
    with_test_limits(2048, 1024, 64, || {
        let (saved, _) = with_pace_clock(Some(t0), false, || paused_singleton(&fixture, &cache));
        // Rewrite one byte of the already-read prefix in place, and grow.
        let bytes = fs::read(&path).unwrap();
        let at = bytes
            .windows(8)
            .position(|window| window == b"10:00:00")
            .unwrap()
            + 7;
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .write_all_at(b"1", at as u64)
            .unwrap();
        fixture.append(SESSION, &token_line(81));
        let (_, dropped) = with_pace_clock(Some(t0 + secs(1)), false, || {
            continuation_page_in(
                &fixture.root,
                saved.clone(),
                &cache,
                "cursor-fixture",
                NOW,
                BACKFILL_WINDOW_DAYS,
                Some(secs(600)),
                |_| {},
            )
        });
        assert!(
            dropped.snapshots.is_empty(),
            "K7.1: no snapshots before EOF"
        );
        assert_eq!(
            counter(&cache, |c| c.jobs_certified),
            0,
            "a changed member never commits"
        );
        drop(dropped);
        let (_, current) = page(&fixture, ScanIndex::default(), None);
        let expected = fingerprints(&current);
        assert!(!expected.is_empty());
        let mut index = saved;
        let mut published = BTreeSet::new();
        for page_number in 0..64u64 {
            let (next, scan) = with_pace_clock(Some(t0 + secs(3_601 + page_number)), false, || {
                page(&fixture, index, Some(Arc::clone(&cache)))
            });
            index = next;
            published.extend(fingerprints(&scan));
            if expected.iter().all(|f| published.contains(f)) {
                assert!(
                    published.iter().all(|f| expected.contains(f)),
                    "nothing older than the changed file: {}",
                    counters(&cache)
                );
                return;
            }
        }
        panic!("the debt was lost: {}", counters(&cache));
    });
}

/// W9: a continuation worker that panicked while holding the cursor, the
/// retained or the side-ledger lock leaves the process running. The next
/// ordinary pages neither panic nor deadlock, and fail closed: they publish
/// nothing the unpaged read would not, and a poisoned cursor admits nothing.
#[test]
fn ordinary_pages_after_a_worker_panic_under_any_lock_fail_closed() {
    use crate::snapshots::sampled_scan::TestLock;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let (_, unpaged) = page(&fixture, ScanIndex::default(), None);
    let unpaged = fingerprints(&unpaged);
    for lock in [TestLock::Cursor, TestLock::Retained, TestLock::Side] {
        let cache = Arc::new(SharedCache::default());
        with_test_limits(2048, 1024, 64, || {
            let (mut index, _) = paused_singleton(&fixture, &cache);
            let worker = std::thread::scope(|scope| {
                std::thread::Builder::new()
                    .name("ottto-codex-continuation".to_string())
                    .spawn_scoped(scope, || cache.panic_under_lock_for_test(lock))
                    .unwrap()
                    .join()
            });
            assert!(worker.is_err(), "{lock:?}: the panic stays on the worker");
            assert!(!cursor_held() && !crate::snapshots::sampled_scan::retained_held());
            for _ in 0..8 {
                let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
                index = next;
                assert!(
                    fingerprints(&scan).iter().all(|f| unpaged.contains(f)),
                    "{lock:?}"
                );
                if lock == TestLock::Cursor {
                    assert!(cache.cursor_reserve(1).is_none(), "admits nothing");
                }
            }
        });
    }
}

/// The cache and held entry are produced by the real sampled pipeline.
fn wake_chmod(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let before = fs::metadata(path).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(before.permissions().mode() ^ 0o004),
    )
    .unwrap();
    let after = fs::metadata(path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    assert_eq!(before.created().unwrap(), after.created().unwrap());
    assert_ne!(
        (before.ctime(), before.ctime_nsec()),
        (after.ctime(), after.ctime_nsec())
    );
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn retained_held_singleton_ignores_ctime_but_wakes_on_content_birth_and_inode() {
    for change in [
        "chmod",
        "append",
        "edit",
        "earlier_birth",
        "later_birth",
        "missing_birth",
        "inode",
    ] {
        let home = CreatedThreadHome::new(10, true);
        let cache = Arc::new(SharedCache::default());
        let (index, held) = home.generation(ScanIndex::default(), &cache, 0);
        assert_eq!(
            counter(&cache, |c| c.memo_records),
            1,
            "{change}: {}",
            counters(&cache)
        );
        let before = counter(&cache, |c| c.memo_hits);
        match change {
            "append" => OpenOptions::new()
                .append(true)
                .open(&home.path)
                .unwrap()
                .write_all(b"{}\n")
                .unwrap(),
            "edit" => {
                let bytes = fs::read(&home.path).unwrap();
                let changed = String::from_utf8(bytes)
                    .unwrap()
                    .replace("grown-turn", "other-turn")
                    .replace("gpt-5.6-sol", "gpt-5.7-sol");
                assert_ne!(changed.as_bytes(), fs::read(&home.path).unwrap());
                fs::write(&home.path, changed).unwrap();
            }
            "inode" => {
                let replacement = home.path.with_extension("replacement");
                fs::copy(&home.path, &replacement).unwrap();
                assert_ne!(
                    fs::metadata(&home.path).unwrap().ino(),
                    fs::metadata(&replacement).unwrap().ino()
                );
                fs::rename(replacement, &home.path).unwrap();
            }
            _ => {
                if change != "chmod" {
                    cache.with_cursor(|cursor| {
                        let hint = &mut cursor
                            .wake
                            .0
                            .get_mut(&local_index_key(&home.path))
                            .expect("retained content evidence")
                            .0;
                        assert_ne!(hint.0[1], 0);
                        hint.0[1] = match change {
                            "earlier_birth" => hint.0[1] - 1,
                            "later_birth" => hint.0[1] + 1,
                            "missing_birth" => 0,
                            _ => unreachable!(),
                        };
                    });
                }
                wake_chmod(&home.path);
            }
        }
        let parsed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let hook = {
            let parsed = std::rc::Rc::clone(&parsed);
            move |path: &Path| parsed.borrow_mut().push(path.to_path_buf())
        };
        let (_, scan) =
            crate::snapshots::with_codex_before_parse(hook, || home.generation(index, &cache, 1));
        if change == "chmod" {
            assert!(
                parsed.borrow().is_empty(),
                "ctime-only must never replay: {}",
                counters(&cache)
            );
            assert_eq!(counter(&cache, |c| c.memo_hits), before + 1);
            assert_eq!(replayed_census(&scan), replayed_census(&held));
        } else {
            assert_eq!(
                parsed.borrow().len(),
                1,
                "{change}: content/object change must wake"
            );
            assert_eq!(counter(&cache, |c| c.memo_hits), before, "{change}");
        }
        let mut count = crate::heap_layout_bound::Counter::new(STATE_BYTES);
        cache
            .heap_bound(&mut count)
            .expect("shared cache remains bounded");
        eprintln!(
            "codex_wake_budget: case={change} bytes={} visits={} state_limit={STATE_BYTES}",
            count.bytes,
            count.visits_for_test()
        );
        assert!(count.visits_for_test() <= 4096);
    }
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn retained_parent_dependency_ignores_ctime_but_wakes_on_parent_append() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let cache = Arc::new(SharedCache::default());
    let (index, settled, n) = home.settle(ScanIndex::default(), &cache, 0);
    assert!(home.child_entry(&cache).is_some());
    let parent = home.fixture.file(PARENT);
    let hits = counter(&cache, |c| c.memo_hits);
    let records = counter(&cache, |c| c.memo_records);
    wake_chmod(&parent);
    let parsed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let hook = {
        let parsed = std::rc::Rc::clone(&parsed);
        move |path: &Path| parsed.borrow_mut().push(path.to_path_buf())
    };
    let (index, quiet) = crate::snapshots::with_codex_before_parse(hook.clone(), || {
        home.generation(index, &cache, n)
    });
    assert!(
        parsed.borrow().is_empty(),
        "metadata-only parent change: {:?}",
        parsed.borrow()
    );
    assert_eq!(counter(&cache, |c| c.memo_hits), hits + 1);
    assert_eq!(counter(&cache, |c| c.memo_records), records);
    assert_eq!(replayed_census(&quiet), replayed_census(&settled));
    append_parent_turn(&parent, 1);
    let _ =
        crate::snapshots::with_codex_before_parse(hook, || home.generation(index, &cache, n + 1));
    assert!(
        parsed.borrow().contains(&parent),
        "parent append must parse"
    );
    assert!(
        parsed.borrow().contains(&home.fixture.file(CHILD)),
        "changed dependency must wake child"
    );
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn retained_parent_witness_survives_ctime_only_change() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    let parent = home.fixture.file(PARENT);
    OpenOptions::new()
        .write(true)
        .open(&parent)
        .unwrap()
        .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000))
        .unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut index = ScanIndex::default();
    let mut last = None;
    for n in 0..4 {
        let (next, scan) = home.generation(index, &cache, n);
        index = next;
        last = Some(scan);
    }
    assert_eq!(
        parent_causes(last.as_ref().unwrap()),
        only(CodexParentUnresolvable::OutOfWindow, 1)
    );
    wake_chmod(&parent);
    let parsed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let hook = {
        let parsed = std::rc::Rc::clone(&parsed);
        move |path: &Path| parsed.borrow_mut().push(path.to_path_buf())
    };
    let (_, scan) =
        crate::snapshots::with_codex_before_parse(hook, || home.generation(index, &cache, 4));
    assert!(
        parsed.borrow().is_empty(),
        "a ctime-only parent witness must not wake: {:?}",
        parsed.borrow()
    );
    assert_eq!(
        parent_causes(&scan),
        only(CodexParentUnresolvable::OutOfWindow, 1)
    );
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn retained_open_samples_cannot_be_reused_after_another_live_ctime_change() {
    let home = CreatedThreadHome::new(10, true);
    let cache = Arc::new(SharedCache::default());
    let (index, _) = home.generation(ScanIndex::default(), &cache, 0);
    assert_eq!(counter(&cache, |c| c.memo_records), 1);
    wake_chmod(&home.path);
    let (_, _) = home.generation(index, &cache, 1);
    assert_eq!(counter(&cache, |c| c.memo_hits), 1);
    let file = File::open(&home.path).unwrap();
    let sampled = OpenStamp::capture(&file).unwrap();
    wake_chmod(&home.path);
    let now = OpenStamp::capture(&file).unwrap();
    assert_ne!(sampled.changed, now.changed);
    assert_eq!(
        cache.retained_stamp(&home.path, now.clone()),
        now,
        "a change after sampling must keep its live stamp"
    );
    let (qualified, _, _) = cache.retained_open(&home.path, &file).unwrap();
    assert_ne!(
        qualified.changed, now.changed,
        "a fresh equal-content sample pass can qualify the stored ctime"
    );
}

/// EOF belongs to the ordinary pass even when earlier pages were accelerated.
/// This observes actual native byte ranges, the EOF application and full bodies.
#[test]
fn continuation_eof_parks_then_ordinary_resumes_without_rereading_and_applies_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let mut trailing: serde_json::Value = serde_json::from_slice(&token_line(81)).unwrap();
    trailing["payload"]["service_tier"] = "priority".into();
    fixture.append(SESSION, &serde_json::to_vec(&trailing).unwrap());
    with_test_limits(2048, 1024, 64, || {
        let baseline = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut expected = Vec::new();
        for _ in 0..64 {
            let (next, scan) = page(&fixture, index, Some(Arc::clone(&baseline)));
            index = next;
            expected.extend(scan.snapshots);
            if counter(&baseline, |c| c.jobs_certified) > 0 {
                break;
            }
        }
        assert!(!expected.is_empty(), "uninterrupted ordinary paged output");
        let expected = serde_json::to_value(expected).unwrap();
        let expected_receipt = serde_json::to_value(
            &index.files[&local_index_key(&fixture.file(SESSION))].codex_applied_tier_receipt,
        )
        .unwrap();
        assert!(!expected_receipt.is_null(), "priority receipt is exercised");
        for schedule in ["before", "after", "interleaved", "restart"] {
            let mut cache = Arc::new(SharedCache::default());
            let (mut index, _) = paused_singleton(&fixture, &cache);
            EOF_APPLIED.with(|v| v.set(0));
            TIER_REPLAYS.with(|v| v.set(0));
            if schedule == "before" {
                let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
                index = next;
                assert!(scan.snapshots.is_empty());
            }
            let mut reached_eof = false;
            let started = counter(&cache, |c| c.jobs_started);
            for turn in 0..64 {
                if schedule == "restart" && turn == 2 {
                    let stale = cache.paused_ticket_for_test().unwrap();
                    let path = fixture._dir.0.join("restart-index.json");
                    index.save(&path).unwrap();
                    drop(cache); // Cursor, reader and continuation inputs are RAM-only.
                    CARRIED.with(|v| {
                        v.borrow_mut().remove(&fixture.root);
                    });
                    index = ScanIndex::load_for_snapshot_source(
                        &path,
                        SnapshotSource::Codex,
                        &fixture._dir.0,
                    )
                    .unwrap();
                    cache = Arc::new(SharedCache::default());
                    assert!(!CodexCursorPort::new(Arc::clone(&cache)).ready(&stale));
                    NATIVE_RANGES.with(|v| *v.borrow_mut() = Some(Vec::new()));
                    let (next, scan, selections) = page_selections(
                        &fixture,
                        index,
                        Some(Arc::clone(&cache)),
                        "cursor-fixture",
                        NOW,
                        |_| {},
                        usize::MAX,
                    );
                    index = next;
                    assert!(scan.snapshots.is_empty());
                    assert_eq!(
                        selections.modes,
                        (1, 0),
                        "one clean Full re-plan after RAM loss"
                    );
                    assert_eq!(selections.full_reasons[FullReason::StateMissing.slot()], 1);
                }
                if schedule == "interleaved" && turn == 2 {
                    let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
                    index = next;
                    assert!(scan.snapshots.is_empty());
                }
                let before = serde_json::to_value(&index).unwrap();
                let context = index.active_upload_context_fingerprint.clone();
                let contract = index.claude_request_identity_contract_changed;
                let (next, scan) = continuation_page_in(
                    &fixture.root,
                    index,
                    &cache,
                    "cursor-fixture",
                    NOW,
                    BACKFILL_WINDOW_DAYS,
                    Some(secs(600)),
                    |_| {},
                );
                index = next;
                assert_eq!(
                    serde_json::to_value(&index).unwrap(),
                    before,
                    "{schedule} page {turn}: no traversal, census or ACK write"
                );
                assert_eq!(index.active_upload_context_fingerprint, context);
                assert_eq!(index.claude_request_identity_contract_changed, contract);
                assert!(scan.snapshots.is_empty());
                assert!(scan.pending_finalization.is_empty());
                assert_eq!(scan.scanned_file_count, 0);
                assert!(!scan.census_complete);
                assert_eq!(counter(&cache, |c| c.jobs_started), started);
                assert_eq!(counter(&cache, |c| c.jobs_certified), 0);
                EOF_APPLIED.with(|v| assert_eq!(v.get(), 0, "continuation never applies EOF"));
                if parked_eof(&cache) {
                    assert!(scan.continuation_ticket().is_none(), "EOF leaves no ticket");
                    reached_eof = true;
                    break;
                }
            }
            assert!(reached_eof, "{schedule}: EOF parked");
            if schedule == "restart" {
                NATIVE_RANGES.with(|v| {
                    let ranges = v.borrow_mut().take().unwrap();
                    let mut end = 0;
                    for range in ranges {
                        assert_eq!(
                            range.start, end,
                            "restart allows one clean Full, no extra re-read"
                        );
                        end = range.end;
                    }
                    assert_eq!(end, fixture.len(SESSION));
                });
            }
            TIER_REPLAYS.with(|v| assert_eq!(v.get(), 0, "no TierReplay restart"));
            let resumed = counter(&cache, |c| c.jobs_resumed);
            NATIVE_RANGES.with(|v| *v.borrow_mut() = Some(Vec::new()));
            let (index, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
            NATIVE_RANGES.with(|v| {
                assert!(
                    v.borrow_mut().take().unwrap().is_empty(),
                    "{schedule}: ordinary EOF must read 0 native bytes"
                )
            });
            assert_eq!(
                counter(&cache, |c| c.jobs_resumed),
                resumed + 1,
                "same cursor slot"
            );
            assert_eq!(
                serde_json::to_value(&scan.snapshots).unwrap(),
                expected,
                "{schedule}: emitted body"
            );
            assert!(!scan.snapshots.is_empty());
            assert_eq!(counter(&cache, |c| c.jobs_certified), 1);
            let key = local_index_key(&fixture.file(SESSION));
            let receipt =
                serde_json::to_value(&index.files[&key].codex_applied_tier_receipt).unwrap();
            assert_eq!(
                receipt, expected_receipt,
                "{schedule}: one receipt application"
            );
            EOF_APPLIED.with(|v| assert_eq!(v.get(), 1));
            let (index, duplicate) = page(&fixture, index, Some(Arc::clone(&cache)));
            assert!(
                duplicate.snapshots.is_empty(),
                "ordinary EOF is not emitted twice"
            );
            EOF_APPLIED.with(|v| assert_eq!(v.get(), 1));
            assert_eq!(
                serde_json::to_value(&index.files[&key].codex_applied_tier_receipt).unwrap(),
                receipt
            );
            TIER_REPLAYS.with(|v| assert_eq!(v.get(), 0));
        }
    });
}

#[test]
fn eof_park_state_bound_keeps_prior_body_and_discloses_without_rereading() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_EOF_PARK.with(|v| v.set(false));
            TEST_STATE_BUDGET.with(|v| v.set(None));
        }
    }
    let _reset = Reset;
    let fixture = ScanRoot::new(80);
    let (mut index, prior) = page(&fixture, ScanIndex::default(), None);
    assert!(!prior.snapshots.is_empty());
    assert!(prior.snapshots.iter().any(|s| s.input_tokens > 0));
    let prior_fingerprints = index.file_snapshot_fingerprints.clone();
    for n in 81..161 {
        fixture.append(SESSION, &token_line(n));
    }
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        (index, _) = page(&fixture, index, Some(Arc::clone(&cache)));
        let started = counter(&cache, |c| c.jobs_started);
        assert_eq!(started, 1);
        FAIL_EOF_PARK.with(|v| v.set(true));
        for _ in 0..128 {
            let before = serde_json::to_value(&index).unwrap();
            let (next, scan) = continuation_page_in(
                &fixture.root,
                index,
                &cache,
                "cursor-fixture",
                NOW,
                BACKFILL_WINDOW_DAYS,
                Some(secs(600)),
                |_| {},
            );
            index = next;
            assert_eq!(serde_json::to_value(&index).unwrap(), before);
            assert!(scan.snapshots.is_empty() && scan.pending_finalization.is_empty());
            if counter(&cache, |c| c.jobs_state_bound) > 0 {
                assert!(scan.continuation_ticket().is_none());
                break;
            }
        }
        assert_eq!(counter(&cache, |c| c.jobs_state_bound), 1);
        assert!(
            cache.cursor_slot_free(),
            "strict parked debt, not a resumable job"
        );
        FAIL_EOF_PARK.with(|v| v.set(false));
        TEST_STATE_BUDGET.with(|v| v.set(None));
        NATIVE_RANGES.with(|v| *v.borrow_mut() = Some(Vec::new()));
        let (next, scan) = page(&fixture, index, Some(Arc::clone(&cache)));
        index = next;
        NATIVE_RANGES
            .with(|v| assert!(v.borrow_mut().take().unwrap().is_empty(), "no Full re-read"));
        assert!(
            scan.snapshots.is_empty(),
            "held prior body, never a zero replacement"
        );
        assert!(scan.unreadable_path_count > 0);
        assert!(!scan.census_complete);
        assert_eq!(index.file_snapshot_fingerprints, prior_fingerprints);
        assert_eq!(counter(&cache, |c| c.jobs_started), started);
    });
}

#[test]
fn compressed_memo_rechecks_refuse_decoded_offsets() {
    let temp = Temp::new("zst-memo", b"{\"n\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let live = LiveWitness::read(plain_path(), &file, 8).unwrap();
    let stamp = OpenStamp::capture(&file).unwrap();
    let entry = MemoEntry::new(
        "digest".into(),
        live,
        stamp.clone(),
        None,
        None,
        disclosure(),
    );
    let path = Path::new("rollout.jsonl.zst");
    codex_zst_refusal_tests::assert_refused(CodexZstCause::PhysicalOffsetUnsupported, || {
        assert!(entry
            .matches_stamp(path, "digest", &file, None, "", stamp)
            .is_none());
    });
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs validated heap layout"
)]
fn decoder_floor_preserves_a_real_primary_tail_and_other_retained_copy() {
    let _lock = crate::snapshots::codex_compressed_input::tests::DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let primary = ScanRoot::new(40);
        let peer = ScanRoot::new(40);
        let cache = Arc::new(SharedCache::default());
        let key = local_index_key(&primary.file(SESSION));
        let peer_key = local_index_key(&peer.file(SESSION));
        let mut index = ScanIndex::default();
        for fixture in [&primary, &peer] {
            let mut warm = ScanIndex::default();
            for _ in 0..64 {
                let (next, _) = page(fixture, warm, Some(Arc::clone(&cache)));
                warm = next;
                if cache
                    .retained_checkpoint(&local_index_key(&fixture.file(SESSION)))
                    .is_some()
                {
                    break;
                }
            }
            if std::ptr::eq(fixture, &primary) {
                index = warm;
            }
        }
        assert!(cache.retained_checkpoint(&key).is_some());
        assert!(cache.retained_checkpoint(&peer_key).is_some());
        let bytes = zstd::stream::encode_all(&b"synthetic archive"[..], 1).unwrap();
        let archive = Temp::new("decoder-floor", &bytes);
        let credit = codex_compressed_input::compressed_input_credit().unwrap();
        let floor = ENTRY_BYTES + super::super::side_ledger::SIDE_LEDGER_BYTES;
        let budget = cache.cursor_resident()
            + retained_floor(&cache)
            + credit
            + floor
            + super::super::side_ledger::SIDE_LEDGER_BYTES;
        with_test_state_budget(budget - 1, || {
            assert!(OpenedInput::funded(File::open(&archive.0).unwrap(), &cache)
                .unwrap()
                .is_none());
            assert_eq!(cache.cursor_reserved(), 0);
        });
        with_test_state_budget(budget, || {
            let mut input = OpenedInput::funded(File::open(&archive.0).unwrap(), &cache)
                .unwrap()
                .unwrap();
            input.read_exact(&mut [0; 1]).unwrap();
            primary.append(SESSION, &token_line(41));
            index.traversal = None;
            let (_, scan, modes) =
                page_in(&primary, index, Some(Arc::clone(&cache)), "cursor-fixture");
            assert_eq!(
                modes,
                (0, 1),
                "a real primary Tail progresses during the decode"
            );
            assert_eq!(scan.snapshots.len(), 1);
            assert!(
                cache.retained_checkpoint(&peer_key).is_some(),
                "decoder causes no extra eviction"
            );
            assert!(cache.retained_checkpoint(&key).is_some());
            assert_eq!(cache.cursor_reserved(), credit);
            input.close();
        });
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

/// Header occupancy is observable, never a decoder eviction or a promise
/// that an unrelated progress admission will run before the next attempt.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs validated heap layout"
)]
fn decoder_header_occupancy_refusal_is_counted_without_reclamation() {
    use crate::local_resource_diagnostics::capture;
    let _lock = crate::snapshots::codex_compressed_input::tests::DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let cache = Arc::new(SharedCache::default());
        let key = local_index_key(&fixture.file(SESSION));
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if cache.retained_checkpoint(&key).is_some() {
                break;
            }
        }
        assert!(cache.retained_checkpoint(&key).is_some());
        let resident = cache.cursor_resident();
        let headers = cache
            .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
            .unwrap();
        assert!(headers > 0, "production inventory warmed header facts");
        let cursor = cursor_without_header_facts(&cache);
        assert_eq!(resident, cursor + headers);
        let retained = retained_floor(&cache);
        let credit = codex_compressed_input::compressed_input_credit().unwrap();
        let side = super::super::side_ledger::SIDE_LEDGER_BYTES;
        // T is the exact free-only decoder boundary WITHOUT optional facts:
        // C + R + D + ENTRY_BYTES + 2*SIDE. With facts it needs T + H.
        let budget = cursor + retained + credit + ENTRY_BYTES + 2 * side;
        let archive = Temp::new(
            "decoder-header-occupancy",
            &zstd::stream::encode_all(&b"synthetic archive"[..], 1).unwrap(),
        );
        let cause = "decoder_refused_header_occupancy";
        let refuse = |limit, expected: usize| {
            let ((), rows) = capture(|| {
                with_test_state_budget(limit, || {
                    assert!(OpenedInput::funded(File::open(&archive.0).unwrap(), &cache)
                        .unwrap()
                        .is_none());
                });
            });
            assert_eq!(
                rows.iter()
                    .filter(|row| row["counts"]["codex_zst_refused"][cause].is_u64())
                    .count(),
                expected
            );
            assert_eq!(rows.len(), expected + 1, "only refusal count records");
            assert!(rows.iter().any(|row| {
                row["counts"]["codex_zst_refused"]["CompressedAdmissionRefused"].is_u64()
            }));
            assert_eq!(cache.cursor_resident(), resident, "no header reclamation");
            assert!(cache.retained_checkpoint(&key).is_some());
            assert_eq!(cache.cursor_reserved(), 0);
        };
        refuse(budget - 1, 0); // Even without facts it cannot fit.
        for _ in 0..2 {
            refuse(budget, 1); // Count each attempt; no bounded retry is claimed.
        }
        let other = Arc::new(SharedCache::default());
        let owner = DecoderOwner::acquire(&other, 1).unwrap();
        refuse(budget, 0); // Singleton busy is not header-occupancy refusal.
        owner.release();

        // An actual decoder fits with the measured H bytes available, and
        // success produces no occupancy refusal or header eviction.
        let ((), rows) = capture(|| {
            with_test_state_budget(budget + headers, || {
                let mut input = OpenedInput::funded(File::open(&archive.0).unwrap(), &cache)
                    .unwrap()
                    .unwrap();
                input.read_exact(&mut [0; 1]).unwrap();
                assert_eq!(cache.cursor_reserved(), credit);
                input.close();
            });
        });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["stage"], "codex_zst_input");
        assert!(
            rows[0]["counts"]["codex_zst_decoded_bytes"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(cache.cursor_resident(), resident);
        assert_eq!(cache.cursor_reserved(), 0);

        // Test-only counterfactual control, not a production reclaim path:
        // release ONLY H, then the same decoder fits the original exact T.
        cache.with_cursor(|cursor| cursor.headers.clear()).unwrap();
        assert_eq!(cache.cursor_resident(), cursor);
        let ((), rows) = capture(|| {
            with_test_state_budget(budget, || {
                let input = OpenedInput::funded(File::open(&archive.0).unwrap(), &cache)
                    .unwrap()
                    .unwrap();
                input.close();
            });
        });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["stage"], "codex_zst_input");
        assert_eq!(rows[0]["counts"]["codex_zst_decoded_bytes"], 0);
        assert!(cache.retained_checkpoint(&key).is_some());
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs validated heap layout"
)]
fn decoder_release_and_unwind_follow_the_production_stores_guard() {
    let _lock = crate::snapshots::codex_compressed_input::tests::DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for unwind in [false, true] {
        let cache = Arc::new(SharedCache::default());
        let f = Temp::new(
            "stores-owner",
            &zstd::stream::encode_all(&b"synthetic"[..], 1).unwrap(),
        );
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            let mut input = OpenedInput::funded(File::open(&f.0).unwrap(), &cache)
                .unwrap()
                .unwrap();
            input.read_exact(&mut [0; 1]).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let stores = cache.durable().unwrap();
                assert!(super::super::durable_tail::stores_held());
                if unwind {
                    panic!("synthetic durable operation failure");
                }
                drop(stores);
            }));
            assert_eq!(result.is_err(), unwind);
            assert!(!super::super::durable_tail::stores_held());
            input.close();
        });
        assert_eq!(cache.cursor_reserved(), 0);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_owner"));
    }
    #[cfg(debug_assertions)]
    {
        let cache = Arc::new(SharedCache::default());
        let guard = cache.durable().unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| DecoderOwner::acquire(
                &cache, 1
            )))
            .is_err()
        );
        drop(guard);
        DecoderOwner::acquire(&cache, 1).unwrap().release();
    }
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs validated heap layout"
)]
fn decoder_fixed_floor_admits_a_warm_cache_without_evicting_it() {
    let _lock = crate::snapshots::codex_compressed_input::tests::DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let clock = TestClock;
    clock.set(1_900_000_000);
    with_test_limits(2048, 8192, 64, || {
        let fixture = ScanRoot::new(40);
        let cache = Arc::new(SharedCache::default());
        let key = local_index_key(&fixture.file(SESSION));
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _) = page(&fixture, index, Some(Arc::clone(&cache)));
            index = next;
            if cache.retained_checkpoint(&key).is_some() {
                break;
            }
        }
        let copy = cache.take(&key).expect("real retained reduction").retained;
        // Two real reductions with large synthetic keys warm > 8 MiB, while
        // each entry remains under ENTRY_BYTES. The graph is measured normally.
        let warm_key = "a".repeat(5 * 1024 * 1024);
        let peer_key = "b".repeat(5 * 1024 * 1024);
        for key in [&warm_key, &peer_key] {
            assert!(cache.retained().unwrap().insert(
                key.clone(),
                crate::transcript_cache::Retained {
                    checkpoint: copy.checkpoint.clone(),
                    state: copy.state.clone(),
                }
            ));
        }
        let warm = retained_floor(&cache);
        assert!(warm > ENTRY_BYTES);
        let credit = codex_compressed_input::compressed_input_credit().unwrap();
        let side = super::super::side_ledger::SIDE_LEDGER_BYTES;
        let budget = cache.cursor_resident() + warm + credit + ENTRY_BYTES + 2 * side;
        // An explicit budget isolates the floor rule from zstd version sizing.
        // The prior retained-sized floor would reject this same warm graph.
        assert!(cache.cursor_resident() + 2 * warm + credit + 2 * side > budget);
        with_test_state_budget(budget, || {
            let owner = DecoderOwner::acquire(&cache, credit).expect("warm cache admits");
            assert!(cache.retained_checkpoint(&warm_key).is_some());
            assert!(cache.retained_checkpoint(&peer_key).is_some());
            owner.release();
        });
        assert_eq!(cache.cursor_reserved(), 0);
    });
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs validated heap layout"
)]
fn decoder_drop_under_cursor_strands_credit_without_relocking() {
    let _lock = crate::snapshots::codex_compressed_input::tests::DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache = Arc::new(SharedCache::default());
    let owner = DecoderOwner::acquire(&cache, 4096).unwrap();
    let ((), rows) = crate::local_resource_diagnostics::capture(|| {
        cache.with_cursor(|_| drop(owner)).unwrap();
    });
    assert_eq!(
        cache.cursor_reserved(),
        4096,
        "stranded, never under-accounted"
    );
    assert!(DECODER_LIVE.load(std::sync::atomic::Ordering::SeqCst));
    assert!(rows.iter().any(|r| r["counts"]["leaked_release"] == 1));
    // Only the test repairs the intentionally stranded impossible-path state.
    cache.with_cursor(|c| settle_claim(c, c.id, 4096)).unwrap();
    DECODER_LIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    DecoderOwner::acquire(&cache, 4096).unwrap().release();
}

#[test]
fn ownership_disclosure_replays_preserve_cause_and_group_strict_uses_group_bucket() {
    let candidate = CandidateFile {
        path: PathBuf::from("/synthetic/ownership-same.jsonl"),
        scan_root: PathBuf::from("/synthetic"),
        physical_identity: None,
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "synthetic".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    for cause in [ownership::CREATED, ownership::PARENT, ownership::PARSER] {
        let mut index = ScanIndex::default();
        let mut census = ScanCensus::default();
        census.causes = census.causes.page(Some(77));
        let mut residue = BTreeSet::new();
        let mut blocked = BTreeSet::new();
        let mut residue_blocked = BTreeSet::new();
        let mut pending = Vec::new();
        let mut debt = disclosure();
        debt.cause = cause;
        for _ in 0..2 {
            disclose_terminal_codex_debt(
                &debt,
                &candidate,
                (None, None),
                &mut index,
                DisclosureTargets {
                    census: &mut census,
                    residue_index_keys: &mut residue,
                    residue_blocked_session_ids: &mut residue_blocked,
                    codex_state_only_blocked_session_ids: &mut blocked,
                    pending_finalization: &mut pending,
                },
            );
        }
        let (c, [unknown, _, _]) = census
            .causes
            .summary(census.ownership_incomplete_file_count);
        assert_eq!(census.ownership_incomplete_file_count, 2);
        assert_eq!(c[cause], 2);
        assert_eq!(c[..6].iter().sum::<usize>() + unknown, 2);
        assert_eq!(residue.len(), 1);
        codex_file_join::disclose_strict(
            "synthetic-owner",
            std::slice::from_ref(&candidate),
            DisclosureTargets {
                census: &mut census,
                residue_index_keys: &mut residue,
                residue_blocked_session_ids: &mut residue_blocked,
                codex_state_only_blocked_session_ids: &mut blocked,
                pending_finalization: &mut pending,
            },
        );
        let (c, [unknown, _, _]) = census
            .causes
            .summary(census.ownership_incomplete_file_count);
        assert_eq!(c[ownership::GROUP], 1);
        assert_eq!(c[..6].iter().sum::<usize>() + unknown, 3);
    }
}

#[test]
fn mcp_version_waits_for_resumed_cursor_eof() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(80);
    let path = fixture.file(SESSION);
    let text = fs::read_to_string(&path).unwrap();
    let (first, rest) = text.split_once('\n').unwrap();
    let mut meta: Value = serde_json::from_str(first).unwrap();
    meta["payload"]["cli_version"] = json!("0.148.9");
    fs::write(&path, meta.to_string() + "\n" + rest).unwrap();
    let home = fixture.root.parent().unwrap().parent().unwrap();
    let projection = Arc::new(crate::snapshots::codex_version::CodexVersionFeed::new(
        Some(home),
    ));
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let mut index = ScanIndex::default();
        for _ in 0..64 {
            let (next, _, _) = page_with(
                &fixture,
                index,
                Some(cache.clone()),
                "mcp-cursor",
                NOW,
                |s| s.codex_versions = Some(projection.clone()),
            );
            index = next;
            let completed = cache.with_cursor(|c| c.counters.jobs_certified).unwrap();
            if completed > 0 {
                assert!(cache.with_cursor(|c| c.counters.jobs_resumed).unwrap() > 0);
                assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
                assert_eq!(projection.snapshot().1, 1, "publish only at completed EOF");
                return;
            }
            assert!(
                projection.snapshot().0.is_none(),
                "paused cursors publish nothing"
            );
        }
        panic!("cursor never completed");
    });
}

/// R1 singleton: a paged cursor job starts while its file is indexed, so it
/// captures no missing-carrier due, then parks; the per-pass index loses the
/// entry. On completion settlement re-probes the record read-only (live
/// context, once-clamped) and stages the marker, counting the miss and the
/// staged transition once each. The job is not invalidated.
#[test]
fn parked_singleton_across_fresh_index_reprobes_record_debt() {
    use crate::durable_tail_store as store;
    use std::io::Read;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let incomplete = |scan: &mut OwnedSourceScan| scan.sidecar_census_complete = false;
    let (mut index, _, _) = page_with(
        &fixture,
        ScanIndex::default(),
        None,
        "cursor-fixture",
        NOW,
        incomplete,
    );
    assert!(index.files.contains_key(&key));
    // A same-context debt record for the indexed file.
    let state = fixture.root.parent().unwrap().to_path_buf();
    let index_path = state.join("index.json");
    let scope = Scope("cursor-fixture".into());
    let now = crate::snapshots::sampled_scan::now_seconds();
    let due = now - 90;
    let mut file = fs::File::open(&path).unwrap();
    let mut plan =
        crate::transcript_acquisition::ReadPlan::prepare(&mut file, None, &scope, None, now)
            .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let mut certificate = plan
        .commit_after_native_completion(&file, &scope, now)
        .unwrap()
        .durable_certificate(0)
        .unwrap();
    certificate.audit_debt_unix_seconds = Some(due);
    let ds = store::DurableSource::Codex;
    let lock = crate::locked_state_dir::test_locks::hold(&state);
    let mut disk = store::DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let pending = store::PendingRecord {
        binding: store::Binding {
            source: ds,
            key: store::key_digest(ds, &key),
            context: store::context_digest(&scope.0, None),
            scope: [0; 32],
            entry: [0; 32],
        },
        certificate,
        body: crate::snapshots::durable_store_fixture_body(SnapshotSource::Codex, 0, 0),
        allowlist: crate::snapshots::sampled_jsonl::durable::allowlist_digest(
            SnapshotSource::Codex,
        ),
    };
    assert_eq!(
        disk.write_after_save(lock, 1, vec![pending])
            .unwrap()
            .written,
        1
    );
    drop(disk);
    fixture.append(SESSION, &token_line(41));
    index.traversal = None;
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(SnapshotSource::Codex, &index_path, &scope, false);
    let index = with_test_limits(2048, 1024, 64, || {
        let mut index = index;
        let mut cleared = false;
        for _ in 0..64 {
            let (next, _, _) = page_with(
                &fixture,
                index,
                Some(Arc::clone(&cache)),
                "cursor-fixture",
                NOW,
                incomplete,
            );
            index = next;
            let done =
                counter(&cache, |c| c.jobs_certified) + counter(&cache, |c| c.jobs_uncertified);
            if done > 0 {
                break;
            }
            if !cleared && counter(&cache, |c| c.jobs_paused) > 0 {
                // Retain the real Legacy ACK before the entry leaves the index.
                assert!(codex_counting_version::tombstone_before_retire(
                    &mut index, &key
                ));
                // The per-pass index loads without the parked file's entry.
                index.files.remove(&key);
                cleared = true;
            }
        }
        assert!(cleared, "the job parked: {}", counters(&cache));
        assert_eq!(
            counter(&cache, |c| c.jobs_invalidated),
            0,
            "{}",
            counters(&cache)
        );
        index
    });
    assert_eq!(
        index.files[&key].unverified_deadline(),
        Some(due),
        "staged from the record at settlement"
    );
    let (durable, _) = cache.durable_counters(SnapshotSource::Codex).unwrap();
    // A start-time restore attempt on the then-indexed entry may count its
    // own carrier miss (A's existing-entry rearm); the re-probe adds one.
    assert!(durable
        .ineligible
        .get("audit_carrier")
        .is_some_and(|n| *n >= 1));
    assert_eq!(
        durable.ineligible.get("audit_carrier_staged_unverified"),
        Some(&1)
    );
    assert_eq!(durable.restored, 0);
}
