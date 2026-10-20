//! Offline cursor-job, page-budget, S5 reader and singleton-memo tests.
//! Every fixture is synthetic; no provider account content.
use super::*;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES;

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

#[test]
fn monotone_holds_are_fork_and_broken_ordinal_streams_only() {
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert!(!held_monotone(&accumulator));
    accumulator.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
    assert!(held_monotone(&accumulator));
    // A parented created thread keeps the ordinal-only rule.
    accumulator.codex_parent_session_ref = Some("parent".into());
    for boundary in [
        CodexOwnershipBoundary::NativeCreatedThread,
        CodexOwnershipBoundary::Ordinal { start: 3 },
    ] {
        accumulator.codex_ownership_boundary = boundary;
        accumulator.codex_ordinal_sequence_valid = true;
        assert!(!held_monotone(&accumulator));
        accumulator.codex_ordinal_sequence_valid = false;
        assert!(held_monotone(&accumulator));
    }
    accumulator.codex_ownership_boundary = CodexOwnershipBoundary::AllLocal;
    assert!(!held_monotone(&accumulator));
    // K8: one reuse predicate for the restored accumulator.
    assert!(counting_reusable(&accumulator, "legacy", "legacy"));
    assert!(!counting_reusable(&accumulator, "legacy", "v2"));
}

/// C6: #597's parentless created-thread hold is memoized only where an
/// append cannot cure it.
#[test]
fn parentless_created_thread_hold_is_monotone_only_when_append_incurable() {
    let proven = || {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        accumulator.codex_ownership_boundary = CodexOwnershipBoundary::NativeCreatedThread;
        accumulator.codex_ordinal_sequence_valid = true;
        accumulator.codex_sidecar_projected_next_ordinal = Some(1);
        accumulator
    };
    // Every set-only conjunct holds; only usage (append-curable) may be
    // missing: never memoized.
    assert!(!held_monotone(&proven()));
    let incurable: [fn(&mut SnapshotAccumulator); 5] = [
        |a| a.codex_ordinal_sequence_valid = false,
        |a| a.codex_native_created_thread_valid = false,
        |a| a.codex_creator_evidence_conflicted = true,
        |a| a.origin.parent_session_ref = Some("parent".into()),
        |a| a.origin.source_subagent = Some(true),
    ];
    for set in incurable {
        let mut accumulator = proven();
        set(&mut accumulator);
        assert!(held_monotone(&accumulator));
    }
    // Missing sidecar projection (no `trace_id`, a disagreeing state row, or
    // a lagging rollout extent): no append cures it, a sidecar change does.
    // It is memoized, and the entry's full sidecar fingerprint wakes it
    // (`held_singleton_memo_woken_by_sidecar_change`).
    let mut accumulator = proven();
    accumulator.codex_sidecar_projected_next_ordinal = None;
    assert!(held_monotone(&accumulator));
    assert!(sidecar_wakes(&accumulator));
    // A parent ref makes it a parented created thread: ordinal rule only.
    accumulator.codex_parent_session_ref = Some("parent".into());
    assert!(!held_monotone(&accumulator));
}

fn disclosure() -> Disclosure {
    Disclosure {
        reason: DebtReason::HeldTerminal,
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

/// K3 (R1-B3): a parentless created thread held for a missing sidecar
/// projection wakes when the sidecar facts that can cure it change, e.g. the
/// rollout extent catching up with the file (`rollout_file_matches`), or an
/// identity conflict appearing. An ambiguous fork records no sidecar wake.
#[test]
fn held_singleton_memo_woken_by_sidecar_change() {
    let temp = Temp::new("memo-sidecar", b"{\"n\":1}\n{\"n\":2}\n");
    let file = File::open(&temp.0).unwrap();
    let path = PathBuf::from(format!(
        "/synthetic/sessions/rollout-2026-10-07T10-00-00-{SESSION}.jsonl"
    ));
    let mut codex = CodexTitleMetadata::default();
    codex.rollout_extents.insert(
        SESSION.into(),
        CodexRolloutExtent {
            next_byte_offset: 8,
            next_ordinal: 1,
        },
    );
    let mut held = SnapshotAccumulator::new(SnapshotSource::Codex);
    held.codex_ownership_boundary = CodexOwnershipBoundary::NativeCreatedThread;
    held.codex_sidecar_projected_next_ordinal = None;
    // `NativeCreatedThread` is set only in the classifier's created-thread
    // branch, which also sets `codex_created_thread_native_only` (B1).
    held.codex_created_thread_native_only = true;
    assert!(held_monotone(&held) && sidecar_wakes(&held));
    let recorded = sidecar_fingerprint(&codex, &path);
    let entry = |sidecar: Option<String>| {
        MemoEntry::new(
            "digest".into(),
            LiveWitness::read(&file, 8).unwrap(),
            OpenStamp::capture(&file).unwrap(),
            None,
            sidecar,
            disclosure(),
        )
    };
    let created = entry(sidecar_wakes(&held).then(|| recorded.clone()));
    assert!(created.matches("digest", &file, None, &recorded).is_some());
    // The sidecar rollout extent catches up with the file: the cure is
    // visible, the entry wakes and the file is re-read.
    codex.rollout_extents.insert(
        SESSION.into(),
        CodexRolloutExtent {
            next_byte_offset: 16,
            next_ordinal: 2,
        },
    );
    let caught_up = sidecar_fingerprint(&codex, &path);
    assert_ne!(caught_up, recorded);
    assert!(created.matches("digest", &file, None, &caught_up).is_none());
    // An identity conflict on the path's session also wakes it.
    let mut conflicted = codex.clone();
    conflicted.identity_conflicts.insert(SESSION.into());
    let conflict = sidecar_fingerprint(&conflicted, &path);
    assert_ne!(conflict, caught_up);
    let caught_up_entry = entry(Some(caught_up.clone()));
    assert!(caught_up_entry
        .matches("digest", &file, None, &conflict)
        .is_none());
    // R1-H1: a missing projection may also mean the sidecar extent is ahead
    // of the flushed file, which an append cures: that entry hits only on
    // its exact stamp, and any growth re-reads it.
    assert!(growth_may_cure(&held));
    let ahead = entry(Some(caught_up.clone())).growth_may_cure(growth_may_cure(&held));
    assert!(ahead.matches("digest", &file, None, &caught_up).is_some());
    temp.append(b"{\"n\":3}\n");
    assert!(ahead.matches("digest", &file, None, &caught_up).is_none());
    assert!(caught_up_entry
        .matches("digest", &file, None, &caught_up)
        .is_some());
    // An ordinary (not created-thread) fork hold is cured by peer parent
    // evidence only.
    held.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
    held.codex_created_thread_native_only = false;
    assert!(!growth_may_cure(&held));
    assert!(!sidecar_wakes(&held));
    let fork = entry(sidecar_wakes(&held).then(|| recorded.clone()));
    assert!(fork.matches("digest", &file, None, &caught_up).is_some());
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
    assert!(LiveWitness::read(&file, 0).is_none());
    assert!(LiveWitness::read(&file, 10_000).is_none());
    let live = LiveWitness::read(&file, 8).unwrap();
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
    assert!(entry.matches("digest", &file, Some(&now_1), "").is_some());
    assert!(entry.matches("other", &file, Some(&now_1), "").is_none());
    // PR-1 L4: a changed ledger and, separately, a changed parent object
    // each miss.
    assert!(entry
        .matches("digest", &file, Some(&now("ledger-2", "p-1")), "")
        .is_none());
    assert!(entry
        .matches("digest", &file, Some(&now("ledger-1", "p-2")), "")
        .is_none());
    assert!(entry
        .matches(
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
    assert!(entry.matches("digest", &file, None, "").is_none());
    // Growth past the refused offset cannot cure the hold: still a hit, and
    // the hit returns the grown stamp for the entry to keep.
    temp.append(b"{\"n\":3}\n");
    let grown = entry
        .matches("digest", &file, Some(&now_1), "")
        .expect("growth is a hit");
    assert!(grown.extent > entry.stamp.extent);
    let mut refreshed = entry.clone();
    refreshed.stamp = grown;
    // No timer: an entry whose evidence is unchanged keeps matching.
    assert!(refreshed
        .matches("digest", &file, Some(&now_1), "")
        .is_some());
    // A same-length stamp change (an in-place write elsewhere) wakes it.
    OpenOptions::new()
        .write(true)
        .open(&temp.0)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();
    assert!(refreshed
        .matches("digest", &file, Some(&now_1), "")
        .is_none());
    // A rewritten prefix is a miss (re-read).
    fs::write(&temp.0, b"{\"n\":9}\n{\"n\":2}\n{\"n\":3}\n").unwrap();
    assert!(entry.matches("digest", &file, Some(&now_1), "").is_none());
}

#[test]
fn singleton_memo_is_bounded_lru_with_frozen_charges() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let temp = Temp::new("memo-lru", b"{\"n\":1}\n");
    let file = File::open(&temp.0).unwrap();
    let entry = MemoEntry::new(
        "digest".into(),
        LiveWitness::read(&file, 8).unwrap(),
        OpenStamp::capture(&file).unwrap(),
        None,
        None,
        disclosure(),
    );
    let mut memo = SingletonMemo::default();
    for index in 0..MEMO_ENTRIES {
        assert!(memo.insert(format!("key-{index}"), entry.clone()));
    }
    memo.touch("key-0");
    assert!(memo.insert("key-new".into(), entry.clone()));
    assert_eq!(memo.entries.len(), MEMO_ENTRIES);
    assert!(memo.entries.contains_key("key-0"));
    assert!(!memo.entries.contains_key("key-1"));
    assert!(memo.entries.values().all(|entry| entry.charge > 0));
    let charged = crate::heap_layout_bound::bound(&memo, usize::MAX).unwrap();
    let frozen: usize = memo.entries.values().map(|entry| entry.charge).sum();
    assert!(charged >= frozen);
    memo.remove("key-0");
    assert!(!memo.entries.contains_key("key-0"));
    // A copy-refusal release keeps every memo entry (K6): they are charged
    // once in `heap_bound` and reserved at insert admission.
    let cache = SharedCache::default();
    cache.memo_record("key".into(), entry);
    assert!(cache.memo_lookup("key").is_some());
    let resident = cache.cursor_resident();
    assert!(resident >= frozen / MEMO_ENTRIES);
    cache.clear();
    assert!(cache.memo_lookup("key").is_some());
    assert_eq!(cache.cursor_resident(), resident);
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
    let mut scan = codex_scan(fixture, index, collected_at);
    tweak(&mut scan);
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache, Scope(namespace.into()));
    }
    let mut modes = (0, 0);
    for _ in 0..max_steps {
        if let Some(context) = scan.sampling.as_ref() {
            modes = (context.full_files, context.tail_files);
        }
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
                return (index, scan, modes);
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
        true,
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

#[test]
fn uncached_scan_never_pages() {
    let fixture = ScanRoot::new(40);
    let (_, full) = page(&fixture, ScanIndex::default(), None);
    let scaled = with_test_limits(256, 128, 16, || {
        page(&fixture, ScanIndex::default(), None).1
    });
    assert_eq!(fingerprints(&scaled), fingerprints(&full));
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
    // Lever (i) is undecided, so P1 runs outcome D (strict `AuditDue`).
    // Under G a tail would also be permitted while an audit is queued; the
    // per-page tail check below holds under both outcomes.
    const LEVER_GRACE: bool = false;
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
        // each certifies once per census generation, and a completed attempt
        // ends that file's census hold, so generations turn over.
        let fixture = ScanRoot::with_sessions(&[(SESSION, 80), (SESSION_B, 80)]);
        let sessions = [SESSION, SESSION_B];
        let keys = sessions.map(|session| local_index_key(&fixture.file(session)));
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut opened = BTreeMap::new();
        let mut completions = Vec::new();
        let mut tails = 0;
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
                // Every tail is permitted by its deadline or by G's grace.
                let permitted = retained
                    .iter()
                    .flatten()
                    .all(|retained| now < retained.last_full_verified() + interval);
                assert!(permitted || LEVER_GRACE, "tail past the audit deadline");
                tails += modes.1;
            }
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
                completions.push((key, census_token(&index)));
                if completions.len() == 4 {
                    break;
                }
            } else {
                assert!(
                    scan.snapshots.is_empty(),
                    "nothing publishes between audits"
                );
            }
            for (session, line) in sessions.iter().zip([next_line, next_line + 1]) {
                fixture.append(session, &token_line(line));
            }
            next_line += 2;
            now += 600;
        }
        assert_eq!(completions.len(), 4, "four audits: {}", counters(&cache));
        // Rotation: each pair of completions serves both files.
        assert_ne!(completions[0].0, completions[1].0, "{}", counters(&cache));
        assert_ne!(completions[2].0, completions[3].0, "{}", counters(&cache));
        // The fence ended each file's hold after its attempt, so the census
        // generation turned over between the two rounds.
        assert_ne!(completions[0].1, completions[2].1);
        assert!(counter(&cache, |c| c.deferred_next_generation) > 0);
        assert_eq!(counter(&cache, |c| c.audit_overdue), 4);
        assert!(counter(&cache, |c| c.audit_overdue_max_age_seconds) > 0);
        if !LEVER_GRACE {
            assert_eq!(tails, 0, "outcome D: no tails above L_max");
        }
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
    let traversal = index.traversal.as_mut().unwrap();
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        traversal,
        BACKFILL_WINDOW_DAYS,
        &index.files,
    );
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
            true,
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

/// E2 (R2-B1): a resume whose evidence is unavailable is tried at most once
/// per page and ends after `UNAVAILABLE_RESUMES` such pages, freeing the
/// slot. The trigger is R1-M1's: an untrusted census plus a changed scope.
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
    let flipped = |scan: &mut OwnedSourceScan| {
        scan.sidecar_census_complete = false;
        scan.context_curve_enabled = !scan.context_curve_enabled;
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

/// E2: a paused job whose path no longer names its held object (replaced
/// here) ends on its next resume: slot freed, nothing published from it,
/// never counted as a member change.
#[test]
fn paused_job_whose_path_was_replaced_ends_on_resume() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = ScanRoot::new(40);
    let path = fixture.file(SESSION);
    let cache = Arc::new(SharedCache::default());
    with_test_limits(2048, 1024, 64, || {
        let (index, _) = page(&fixture, ScanIndex::default(), Some(Arc::clone(&cache)));
        assert_eq!(
            counter(&cache, |c| c.jobs_paused),
            1,
            "{}",
            counters(&cache)
        );
        let replacement = path.with_extension("replacement");
        fs::copy(&path, &replacement).unwrap();
        fs::rename(&replacement, &path).unwrap();
        let (_, _, _) = page_steps(
            &fixture,
            index,
            Some(Arc::clone(&cache)),
            "cursor-fixture",
            NOW,
            |_| {},
            10_000,
        );
        assert_eq!(
            counter(&cache, |c| c.jobs_unavailable_ended),
            1,
            "{}",
            counters(&cache)
        );
        assert_eq!(counter(&cache, |c| c.jobs_resumed), 1, "one attempt");
        assert_eq!(counter(&cache, |c| c.jobs_invalidated), 0);
    });
}

/// E3 (R2-H1): between walks a live job's copy-budget charge is the last
/// walk plus every byte consumed since; a walk is due again only after
/// `CHARGE_REFRESH_BYTES` or a reader restart, never per line.
#[test]
fn live_job_charge_is_estimated_between_bounded_walks() {
    let temp = Temp::new("charge", b"{}\n");
    let mut meta = JobMeta {
        key: "key".into(),
        namespace: "namespace".into(),
        stamp_open: OpenStamp::capture(&File::open(&temp.0).unwrap()).unwrap(),
        started: 0,
        dependencies: None,
        owner: None,
        counting: String::new(),
        fence: None,
        census_trusted: true,
        pages: 0,
        unavailable_resumes: 0,
        charge: None,
        eof_applied: false,
    };
    assert_eq!(meta.charge_estimate(0, 64), None, "the first step walks");
    meta.record_charge(1_000, 10, 64);
    assert_eq!(meta.charge_estimate(10, 64), Some(1_000));
    assert_eq!(
        meta.charge_estimate(510, 64),
        Some(1_500),
        "consumed bytes charged"
    );
    assert_eq!(
        meta.charge_estimate(510, 4_160),
        Some(5_596),
        "reader buffer capacity growth charged (R2-M1)"
    );
    assert_eq!(
        meta.charge_estimate(510, 32),
        Some(1_500),
        "a shrunk buffer never lowers the charge below the walk"
    );
    assert!(meta
        .charge_estimate(10 + CHARGE_REFRESH_BYTES - 1, 64)
        .is_some());
    assert_eq!(
        meta.charge_estimate(10 + CHARGE_REFRESH_BYTES, 64),
        None,
        "walk again"
    );
    assert_eq!(
        meta.charge_estimate(5, 64),
        None,
        "a restarted reader walks again"
    );
    meta.record_charge(usize::MAX, 10, 64);
    assert_eq!(
        meta.charge_estimate(20, 64),
        Some(usize::MAX),
        "a refused walk stays refused"
    );
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
#[test]
fn lossy_grown_job_publishes_uncertified_through_same_object_identity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let clock = TestClock;
    let now = 1_900_000_000_u64;
    let due = now + 100;
    let mut overlong = br#"{"timestamp":"2026-10-07T10:30:00Z","type":"event_msg","payload":{"type":"agent_message","message":""#.to_vec();
    overlong.extend(std::iter::repeat_n(b'x', MAX_JSONL_LINE_BYTES + 1));
    overlong.extend_from_slice(b"\"}}\n");
    for case in ["grow", "replace", "shrink"] {
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
                "grow" => counter(cache, |c| c.jobs_uncertified + c.jobs_finish_failed) > 0,
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
            if case != "grow" {
                assert!(ending.snapshots.is_empty(), "{case}: nothing published");
                assert_eq!(counter(&cache, |c| c.jobs_uncertified), 0, "{case}");
                return;
            }
            assert_eq!(counter(&cache, |c| c.jobs_uncertified), 1);
            assert_eq!(counter(&cache, |c| c.jobs_invalidated), 0);
            assert_eq!(
                fingerprints(&ending),
                fingerprints(&main),
                "main's semantic output for the object read"
            );
            assert_eq!(deadline(&index), Some(due), "original debt and age kept");
        });
    }
}

/// K7 as pure state: oldest waiter first, never-served files ahead of served
/// ones (an overdue audit is aged behind waiting large files), inactive
/// waiters do not block, and one completed attempt per census generation.
#[test]
fn rotation_serves_waiters_in_turn_and_fences_one_attempt_per_generation() {
    let mut rotation = Rotation {
        page: 10,
        ..Rotation::default()
    };
    rotation.wait("a");
    rotation.page = 11;
    rotation.wait("b");
    assert!(rotation.turn("a"));
    assert!(!rotation.turn("b"));
    assert!(
        !rotation.turn("new"),
        "a newcomer waits behind active waiters"
    );
    rotation.complete("a", Some("g1"));
    assert!(rotation.turn("b"));
    assert!(!rotation.turn("a"), "a served file goes behind a waiter");
    assert!(rotation.fenced("a", Some("g1")));
    assert!(!rotation.fenced("a", Some("g2")));
    assert!(!rotation.fenced("a", None));
    rotation.complete("b", Some("g1"));
    // Next generation: both served, `a` longer ago; a never-served file
    // that starts waiting later still goes first.
    rotation.page = 12;
    rotation.wait("b");
    rotation.wait("a");
    rotation.page = 13;
    rotation.wait("c");
    assert!(rotation.turn("c"));
    assert!(!rotation.turn("a") && !rotation.turn("b"));
    rotation.complete("c", Some("g2"));
    assert!(rotation.turn("a"));
    assert!(!rotation.turn("b"));
    // A waiter not seen for `WAITER_ACTIVE_PAGES` pages blocks nobody.
    rotation.page += WAITER_ACTIVE_PAGES;
    rotation.wait("b");
    assert!(rotation.turn("b"));
    // Forgotten after `WAITER_FORGET_PAGES`; every table stays bounded.
    rotation.page += WAITER_FORGET_PAGES;
    rotation.wait("d");
    assert!(!rotation.waiting.contains_key("a"));
    for index in 0..=ROTATION_KEYS {
        let key = format!("key-{index:03}");
        rotation.wait(&key);
        rotation.complete(&key, Some("g3"));
    }
    assert!(rotation.waiting.len() <= ROTATION_KEYS);
    assert_eq!(rotation.served.len(), ROTATION_KEYS);
    assert_eq!(rotation.attempted.len(), ROTATION_KEYS);
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
            true,
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

/// R2-N5: a group's legacy tee takes every consumed byte too, so the E3
/// estimate counts each byte once per accumulator.
#[test]
fn estimate_counts_bytes_once_per_fed_accumulator() {
    assert_eq!(
        estimate_charge(Some((1_000, 10, 64)), 510, 64, 1),
        Some(1_500)
    );
    assert_eq!(
        estimate_charge(Some((1_000, 10, 64)), 510, 64, 2),
        Some(2_000)
    );
}

/// B1 (steady-state rev 2), replacing #635's unbound-only class: every hold
/// from the classifier's created-thread branch or identity-ambiguous return
/// (`codex_created_thread_native_only`) is growth-curable and sidecar-woken,
/// whether the thread is state- or rollout-declared, and whether or not its
/// sidecar bound a parent or projection: the bind itself depends on the file
/// length, so a bound parent can come undone with growth. An ordinary fork
/// (NC2) keeps the fork rule: growth matches, no sidecar wake.
#[test]
fn created_thread_holds_are_exact_and_sidecar_woken() {
    let created = || {
        let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
        accumulator.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
        accumulator.codex_created_thread_native_only = true;
        accumulator
    };
    let mut fork = SnapshotAccumulator::new(SnapshotSource::Codex);
    fork.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
    assert!(held_monotone(&fork) && !growth_may_cure(&fork) && !sidecar_wakes(&fork));
    // The state flag alone no longer decides: a state-declared row on an
    // ordinary fork's accumulator (never produced by the classifier) is not
    // a member; a rollout-declared thread with no state flag is.
    fork.codex_sidecar_created_thread = true;
    assert!(!growth_may_cure(&fork) && !sidecar_wakes(&fork));
    assert!(held_monotone(&created()) && growth_may_cure(&created()) && sidecar_wakes(&created()));
    let variants: [fn(&mut SnapshotAccumulator); 5] = [
        |a| a.codex_sidecar_created_thread = true,
        |a| a.codex_sidecar_projected_next_ordinal = Some(4),
        |a| a.codex_sidecar_parent = Some(("child".into(), "parent".into())),
        |a| a.codex_parent_session_ref = Some("parent".into()),
        // NC3: the identity-ambiguous return, created or not.
        |a| a.codex_sidecar_identity_ambiguous = true,
    ];
    for set in variants {
        let mut accumulator = created();
        set(&mut accumulator);
        assert!(held_monotone(&accumulator));
        assert!(growth_may_cure(&accumulator) && sidecar_wakes(&accumulator));
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
        scan_root: PathBuf::from("/synthetic/sessions"),
        path: path.clone(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "revision".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
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
/// call: a deterministic point between two records of the active file.
fn page_between(
    fixture: &ScanRoot,
    index: ScanIndex,
    cache: &Arc<SharedCache>,
    collected_at: &str,
    mut between: impl FnMut(&OwnedSourceScan),
) -> (ScanIndex, SourceScanResult) {
    let mut scan = codex_scan(fixture, index, collected_at)
        .with_sampled_acquisition(Arc::clone(cache), Scope("cursor-fixture".into()));
    for _ in 0..100_000 {
        between(&scan);
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

/// T15 (PR-P §2.4): a created thread never consults a parent ledger, so it
/// records no parent ref, before or after an index reset; its memo hit
/// re-requests nothing. P-T32 covers an ordinary fork's re-request.
#[test]
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
        |codex| codex.created_thread_census_unscoped_incomplete = true,
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
        scan_root: PathBuf::from("/synthetic/sessions"),
        path,
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
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

/// J-T6 + J-T10: the entry's resident delta is exactly its admitted charge;
/// an unchanged re-record builds and admits nothing; a new member list
/// moves it by the key-length difference; one byte short of the charge is
/// refused and forgets the older entry.
#[test]
fn join_provenance_charge_is_the_exact_accounted_delta() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let floor = retained_floor(&cache);
    let empty = cache.cursor_resident();
    let three = join_members(&["a.jsonl", "bb.jsonl", "rollout-ccc.jsonl"]);
    cache.record_join_owner(JOIN_OWNER, &three);
    assert_eq!(join_entry(&cache, JOIN_OWNER), Some(joined(&three)));
    assert_eq!(
        cache.cursor_resident() - empty,
        join_charge(JOIN_OWNER, &three)
    );
    assert_eq!(cache.cursor_reserved(), 0);
    // Unchanged membership needs no room at all.
    let resident = cache.cursor_resident();
    with_test_state_budget(0, || cache.record_join_owner(JOIN_OWNER, &three));
    assert_eq!(join_entry(&cache, JOIN_OWNER), Some(joined(&three)));
    assert_eq!(cache.cursor_resident(), resident);
    // A new member list: the stored owner key is kept.
    let two = join_members(&["a.jsonl", "b.jsonl"]);
    cache.record_join_owner(JOIN_OWNER, &two);
    assert_eq!(join_entry(&cache, JOIN_OWNER), Some(joined(&two)));
    assert_eq!(
        resident - cache.cursor_resident(),
        joined(&three).len() - joined(&two).len()
    );
    // One byte short: refused, and the older entry is forgotten.
    let state = cache.cursor_resident();
    let charge = join_charge(JOIN_OWNER, &three);
    with_test_state_budget(state + charge + floor - 1, || {
        cache.record_join_owner(JOIN_OWNER, &three);
    });
    assert_eq!(join_entry(&cache, JOIN_OWNER), None);
    assert_eq!(cache.cursor_resident(), empty);
    assert!(released(&cache, &BTreeSet::new(), |_| false).is_empty());
    // Exactly enough: admitted.
    with_test_state_budget(empty + charge + floor, || {
        cache.record_join_owner(JOIN_OWNER, &three);
    });
    assert_eq!(join_entry(&cache, JOIN_OWNER), Some(joined(&three)));
    assert_eq!(cache.cursor_resident(), empty + charge);
    assert_eq!(cache.cursor_reserved(), 0);
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
    let floor = retained_floor(&cache);
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

/// The mandatory paused-job reserve forgets optional join provenance for
/// room; optional provenance never forgets other provenance and never takes
/// a claim's room back (baseline progress keeps its reserve).
#[test]
fn paused_reserve_outranks_join_provenance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = Arc::new(SharedCache::default());
    let floor = retained_floor(&cache);
    let empty = cache.cursor_resident();
    let members = join_members(&["a.jsonl", "b.jsonl"]);
    cache.record_join_owner(JOIN_OWNER, &members);
    let claim = join_charge(JOIN_OWNER, &members);
    with_test_state_budget(empty + claim + floor, || {
        cache.record_join_owner(JOIN_OTHER, &members);
        assert_eq!(join_entry(&cache, JOIN_OTHER), None);
        assert_eq!(join_entry(&cache, JOIN_OWNER), Some(joined(&members)));
        let credit = cache
            .cursor_reserve(claim)
            .expect("baseline progress forgets provenance first");
        assert_eq!(join_entry(&cache, JOIN_OWNER), None);
        assert_eq!(cache.cursor_resident(), empty + claim);
        cache.record_join_owner(JOIN_OWNER, &members);
        assert_eq!(join_entry(&cache, JOIN_OWNER), None);
        credit.refund();
    });
    assert_eq!(cache.cursor_reserved(), 0);
    assert_eq!(cache.cursor_resident(), empty);
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
            .unwrap_or_else(|| panic!("a certified copy: {}", counters(&cache)));
        // Measured with no retained copy and no provenance: the least an
        // admission could ever evict down to.
        let floor = retained_floor(&cache);
        let empty = cache.cursor_resident();
        cache.insert(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: copy.checkpoint,
                reduction: Some(copy.state),
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
        with_test_state_budget(resident + claim + floor - 1, || {
            cache.record_join_owner(JOIN_THIRD, &members);
        });
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
            .unwrap_or_else(|| panic!("a certified copy: {}", counters(&cache)));
        let completed = |copy: crate::transcript_cache::Retained<_>| {
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: copy.checkpoint,
                reduction: Some(copy.state),
            }
        };
        // Control: without a claim the copy fits.
        cache.insert(key.clone(), completed(copy), 0);
        assert!(cache.retained_checkpoint(&key).is_some());
        let with_copy = retained_floor(&cache);
        let state = cache.cursor_resident();
        assert!(with_copy + state <= STATE_BYTES);
        let copy = cache.take(&key).expect("retained");
        // A claim that leaves one byte too few for it.
        let claim = STATE_BYTES - state - with_copy + 1;
        let credit = cache.cursor_reserve(claim).expect("the claim fits alone");
        cache.insert(key.clone(), completed(copy), 0);
        assert!(cache.retained_checkpoint(&key).is_none(), "refused");
        assert!(retained_floor(&cache) + cache.cursor_resident() <= STATE_BYTES);
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

/// H5: a job the slot no longer names is freed, counted lost, and only
/// then is its claim refunded; nothing stays reserved or charged.
#[test]
fn failed_store_drops_the_job_then_refunds_its_claim() {
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
        // The impossible case `store` still handles: the slot moved on.
        cache.with_cursor(|cursor| cursor.slot = Slot::Empty);
        drop(scan);
        assert_eq!(counter(&cache, |c| c.jobs_frame_returned), 0);
        assert_eq!(counter(&cache, |c| c.jobs_lost), 1);
        assert_eq!(cache.cursor_reserved(), 0);
        assert_eq!(cache.cursor_charge(), 0);
    });
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

/// P-T26 (L1): a restart slot is keyed by (namespace, scope). A new scope is
/// a new slot; the old scope's spent budget is never reset; two pairs whose
/// keys collide share one budget (spent sooner, never refilled).
#[test]
fn restart_slots_are_per_scope_and_never_reset() {
    let x = parent_restart_key("namespace", "scope-x");
    let y = parent_restart_key("namespace", "scope-y");
    assert_ne!(x, y);
    // The length prefix keeps the pair unambiguous.
    assert_ne!(parent_restart_key("ab", "c"), parent_restart_key("a", "bc"));
    let mut table = ParentRestarts::default();
    for page in 0..PARENT_RESTART_BUDGET {
        table.touch(x, page).0.restarts += 1;
    }
    assert_eq!(table.touch(y, 10).0.restarts, 0);
    assert_eq!(table.touch(x, 11).0.restarts, PARENT_RESTART_BUDGET);
    for page in 12..32 {
        assert_eq!(table.touch(x, page).0.restarts, PARENT_RESTART_BUDGET);
    }
    // Two pairs forced onto one key share one budget.
    let mut shared = ParentRestarts::default();
    shared.touch(7, 1).0.restarts += 1;
    shared.touch(7, 2).0.restarts += 1;
    assert_eq!(shared.touch(7, 3).0.restarts, PARENT_RESTART_BUDGET);
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
    assert_eq!(cache.note_parent_restart(&first, "scope"), 1);
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
        PARENT_RESTART_BUDGET + 1,
        "counted, never reset"
    );
    assert!(cache
        .with_cursor(|cursor| cursor.parents.is_empty())
        .unwrap());
}

/// P-T19 (unit): a refused witness keeps nothing and is counted; a refused
/// match mark leaves the namespace unmarked (it re-matches next page).
#[test]
fn refused_witness_and_mark_keep_nothing() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let cache = SharedCache::default();
    let namespace = Scope("namespace".into());
    let resident = cache.cursor_resident();
    with_test_state_budget(0, || {
        assert!(!cache.witness_parent(&namespace, "scope", PARENT, absent_witness()));
        cache.mark_parents_matched(&namespace, "scope", "window-end", 0);
    });
    assert_eq!(counter(&cache, |c| c.parent_witness_refused), 1);
    assert_eq!(counter(&cache, |c| c.parent_match_unmarked), 1);
    assert_eq!(cache.cursor_resident(), resident);
    let state = cache.parent_state(&namespace, "scope");
    assert!(state.witnesses.is_empty() && state.matched.is_none());
    // Admitted under the production budget: kept with its exact charge.
    assert!(cache.witness_parent(&namespace, "scope", PARENT, absent_witness()));
    let state = cache.parent_state(&namespace, "scope");
    assert_eq!(state.witnesses, vec![(PARENT.to_owned(), absent_witness())]);
    // A scope change drops the namespace's witnesses (revalidated later).
    assert!(cache
        .parent_state(&namespace, "other-scope")
        .witnesses
        .is_empty());
    assert_eq!(cache.cursor_resident(), resident);
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
    let floor = retained_floor(&cache);
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
    assert!(counter(&cache, |c| c.parent_namespace_evicted) > 0);
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

/// P-T30 (R2-L2): the witness store's walk costs a fixed number of visits
/// per namespace whatever its witness count (stored charges, no per-witness
/// walk), so a full store stays far inside `Counter`'s 4,096-visit limit.
#[test]
fn witness_store_visits_do_not_grow_with_witness_count() {
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let visits = |cache: &SharedCache| {
        cache
            .with_cursor(|cursor| {
                let mut counter = Counter::new(usize::MAX);
                cursor.heap_bound(&mut counter).unwrap();
                counter.visits_for_test()
            })
            .unwrap()
    };
    let cache = SharedCache::default();
    let fill = |per: usize| {
        for namespace in 0..ROTATION_KEYS {
            for parent in 0..per {
                assert!(cache.witness_parent(
                    &Scope(format!("namespace-{namespace:02}")),
                    "scope",
                    &format!("parent-{parent:03}"),
                    absent_witness(),
                ));
            }
        }
    };
    let empty = visits(&cache);
    fill(1);
    let one = visits(&cache);
    fill(50);
    let many = visits(&cache);
    assert_eq!(many, one, "visits grew with the witness count");
    assert!(one - empty <= ROTATION_KEYS * 8 + 8, "{empty} -> {one}");
    assert!(many < 4096, "{many}");
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
        .unwrap_or_else(|| panic!("a certified copy: {}", counters(&cache)));
    let floor = retained_floor(&cache);
    let empty = cache.cursor_resident();
    // A single-session root has no parent refs: no `parents` entry exists.
    assert!(cache
        .with_cursor(|cursor| cursor.parents.is_empty())
        .unwrap());
    cache.insert(
        key.clone(),
        sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: copy.checkpoint,
            reduction: Some(copy.state),
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
        with_test_state_budget(resident + setup.floor + 1, || {
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
        let after = resident
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

/// N1: `parent_restarts_in_scope` is reported only when the page
/// established it: omitted, never a fabricated 0, without a shared cache;
/// present on a cached page whose step-start pass ran.
#[test]
fn parent_restarts_in_scope_is_omitted_unless_established() {
    let fixture = ScanRoot::new(3);
    let (_, uncached) = page(&fixture, ScanIndex::default(), None);
    let diagnostic = uncached.local_codex_diagnostics.expect("Codex diagnostics");
    assert_eq!(diagnostic.parent_restarts_in_scope, None);
    assert!(serde_json::to_value(diagnostic)
        .unwrap()
        .get("parent_restarts_in_scope")
        .is_none());
    let (_, cached) = page(
        &fixture,
        ScanIndex::default(),
        Some(Arc::new(SharedCache::default())),
    );
    assert_eq!(restarts_in_scope(&cached), Some(0));
}

/// P-T21/P-T22: with the scope's budget already spent, a new fork of an
/// absent parent is held `DeferredRestart` on its first generation (no third
/// restart), then `Absent` from the next match: never `DeferredRestart` at
/// two consecutive generations.
#[test]
fn spent_budget_holds_a_new_fork_deferred_once_then_absent() {
    let home = ForkHome::new(&ForkHome::diverging_child(3));
    fs::rename(
        home.fixture.file(PARENT),
        home.fixture.root.parent().unwrap().join("parent-away"),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let namespace = Scope("cursor-fixture".into());
    let scope = group_scope(&ScanIndex::default());
    for _ in 0..PARENT_RESTART_BUDGET {
        cache.note_parent_restart(&namespace, &scope);
    }
    let mut index = ScanIndex::default();
    for n in 0..4 {
        let (next, scan) = home.generation(index, &cache, n);
        assert!(session_usage(&scan, CHILD).is_empty());
        assert_eq!(
            restarts_in_scope(&scan),
            Some(PARENT_RESTART_BUDGET),
            "generation {n}: no third restart"
        );
        let expected = if n == 0 {
            only(CodexParentUnresolvable::DeferredRestart, 1)
        } else {
            only(CodexParentUnresolvable::Absent, 1)
        };
        assert_eq!(
            parent_causes(&scan),
            expected,
            "generation {n}: {}",
            counters(&cache)
        );
        index = next;
    }
}

/// P-T5/P-T33b (D2): with the ref set full, a new fork's ref does not fit,
/// so the fork is held `DeferredRef` (counted, never published) with no
/// restart, and memo-hits from its second generation. Once refs leave the
/// set it resolves as a cold scan does.
#[test]
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

/// P-T14 (M1): the step-start match runs once per traversal: one census
/// pass per generation here (each generation is one traversal and one
/// page), and the namespace is marked matched for exactly that traversal,
/// so a later page of it re-applies without matching.
#[test]
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

/// P-T10b: C -> P -> G with G present and resolvable, in both page orders:
/// no generation ever counts `ParentHeld`, and P is admitted once.
#[test]
fn resolvable_chain_never_counts_parent_held() {
    for reversed in [false, true] {
        let fixture = chain_fixture(reversed);
        let cache = Arc::new(SharedCache::default());
        let mut index = ScanIndex::default();
        let mut published = Vec::new();
        for n in 0..6 {
            let (next, scan) = fixture_generation(&fixture, &cache, index, n);
            assert_eq!(
                parent_causes(&scan)[CodexParentUnresolvable::ParentHeld.index()],
                0,
                "reversed {reversed}, generation {n}: {}",
                counters(&cache)
            );
            assert!(restarts_in_scope(&scan).is_some_and(|restarts| restarts <= 2));
            published.extend(session_usage(&scan, PARENT));
            index = next;
        }
        assert_eq!(published, vec![(30, 1)], "reversed {reversed}");
    }
}

/// P-T26b (M2): a `ParentHeld` witness is never stale-pruned. After 20
/// pages of another namespace (past `NAMESPACE_STALE_PAGES`), the held
/// chain's next generation parses nothing and its holds memo-hit.
#[test]
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
    let mut index = ScanIndex::default();
    let mut held_at = None;
    let mut history = Vec::new();
    for n in 0..=limit {
        let ((next, scan), parsed) = parses(|| fixture_generation(fixture, &cache, index, n));
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
        held_at.unwrap_or_else(|| panic!("never held: {history:#?}\n{}", counters(&cache)));
    for n in held_at + 1..held_at + 3 {
        let ((next, scan), parsed) = parses(|| fixture_generation(fixture, &cache, index, n));
        assert!(parsed.is_empty(), "generation {n}: {parsed:?}");
        assert_eq!(parent_causes(&scan), expected, "generation {n}");
        index = next;
    }
}

/// P-T29 (N2): a referenced parent rollout with no session id is witnessed
/// `NoLedger`; its fork is held under it and nothing is read again.
#[test]
fn parent_without_a_session_id_is_witnessed_no_ledger() {
    let fixture = ScanRoot::with_sessions(&[]);
    let mut parent = ForkHome::parent();
    parent[0] = json!({"timestamp": "2026-10-07T08:00:00Z", "type": "session_meta",
        "payload": {"thread_source": "user"}});
    fs::write(fixture.file(PARENT), jsonl(&parent)).unwrap();
    write_rollout(&fixture, CHILD, Some(PARENT), &ForkHome::diverging_child(3));
    held_then_quiet(
        &fixture,
        only(CodexParentUnresolvable::NoLedger, 1),
        3,
        CodexParentUnresolvable::ParentLossy,
    );
}

/// P-T31 (R1-L1): a second rollout claiming P's id makes P `Duplicated`:
/// the fork is held under it, never `ParentLossy`, and nothing is read
/// again.
#[test]
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
