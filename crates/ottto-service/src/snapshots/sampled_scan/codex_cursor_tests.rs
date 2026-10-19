//! Offline cursor-job, page-budget, S5 reader and singleton-memo tests.
//! Every fixture is synthetic; no provider account content.
use super::*;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

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
    // A fork hold is cured by peer parent evidence only.
    held.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
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
    let parent = Some(("parent".to_owned(), Some("ledger-1".to_owned())));
    let entry = MemoEntry::new("digest".into(), live, stamp, parent, None, disclosure());
    assert_eq!(entry.parent_ref(), Some("parent"));
    assert!(entry
        .matches("digest", &file, Some("ledger-1".into()), "")
        .is_some());
    assert!(entry
        .matches("other", &file, Some("ledger-1".into()), "")
        .is_none());
    assert!(entry
        .matches("digest", &file, Some("ledger-2".into()), "")
        .is_none());
    assert!(entry.matches("digest", &file, None, "").is_none());
    // Growth past the refused offset cannot cure the hold: still a hit, and
    // the hit returns the grown stamp for the entry to keep.
    temp.append(b"{\"n\":3}\n");
    let grown = entry
        .matches("digest", &file, Some("ledger-1".into()), "")
        .expect("growth is a hit");
    assert!(grown.extent > entry.stamp.extent);
    let mut refreshed = entry.clone();
    refreshed.stamp = grown;
    // No timer: an entry whose evidence is unchanged keeps matching.
    assert!(refreshed
        .matches("digest", &file, Some("ledger-1".into()), "")
        .is_some());
    // A same-length stamp change (an in-place write elsewhere) wakes it.
    OpenOptions::new()
        .write(true)
        .open(&temp.0)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();
    assert!(refreshed
        .matches("digest", &file, Some("ledger-1".into()), "")
        .is_none());
    // A rewritten prefix is a miss (re-read).
    fs::write(&temp.0, b"{\"n\":9}\n{\"n\":2}\n{\"n\":3}\n").unwrap();
    assert!(entry
        .matches("digest", &file, Some("ledger-1".into()), "")
        .is_none());
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
        claude.release_sampled_cache_for_copy_refusal();
        drop(claude);
        assert_eq!(cache.cursor_charge(), charge, "the paused job survives");
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
    for grow in [false, true] {
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
            // projection: an append may cure it.
            let accumulator = &mut job.parser.accumulator;
            accumulator.codex_ownership_boundary = CodexOwnershipBoundary::NativeCreatedThread;
            accumulator.codex_parent_session_ref = None;
            accumulator.codex_sidecar_projected_next_ordinal = None;
            assert!(growth_may_cure(&job.parser.accumulator));
            job.hold_offset = Some(job.parser.reader.last_complete_line_end());
            if grow {
                fixture.append(SESSION, &token_line(41));
            }
            let _ = finish_job(&cache, None, &mut job, None, "legacy", "", true);
            job.hold_offset
        });
        assert_eq!(hold.is_some(), !grow, "grow: {grow}");
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
