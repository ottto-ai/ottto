// Design E: Claude Code context scalars from the transcript file itself. A
// root record more than 60 s older than its file's birth was copied in and
// leaves first/peak/last and compactions; usage, cost, identity and account
// handling do not move. Subagent files are exempt; telemetry only vetoes.
// Every fixture is synthetic and content-free. Own records are stamped just
// before the file is written (inside the 60 s slack), copied ones two days
// earlier, so the real file birth of the test file decides.
use super::*;

const ROOT: &str = "a0000000-0000-4000-8000-00000000000a";
const SECOND: &str = "b0000000-0000-4000-8000-00000000000b";
const OTHER_ROOT: &str = "c0000000-0000-4000-8000-00000000000c";
const COPIED: i64 = -2 * 24 * 60 * 60;
const CONTEXT_KEYS: [&str; 9] = [
    "compaction_count",
    "compaction_timestamps",
    "compaction_total_cumulative_dropped_tokens",
    "compaction_total_duration_ms",
    "compaction_total_post_tokens",
    "compaction_total_pre_tokens",
    "first_turn_context_tokens",
    "last_turn_context_tokens",
    "peak_context_fill_tokens",
];

/// RFC 3339 `offset_seconds` from `now`, whole seconds.
fn stamp(now: OffsetDateTime, offset_seconds: i64) -> String {
    (now + time::Duration::seconds(offset_seconds))
        .replace_nanosecond(0)
        .expect("whole second")
        .format(&Rfc3339)
        .expect("format fixture timestamp")
}

fn assistant(session: &str, request: &str, timestamp: &str, input_tokens: u64) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"type\":\"assistant\",\"version\":\"2.1.226\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
    )
}

fn id_less_assistant(session: &str, timestamp: &str, input_tokens: u64) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"message\":{{\"id\":\"msg_id_less\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
    )
}

fn subagent_assistant(session: &str, agent: &str, request: &str, timestamp: &str) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"agentId\":\"{agent}\",\"isSidechain\":true,\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":40,\"output_tokens\":1}}}}}}\n"
    )
}

fn boundary(session: &str, timestamp: &str, pre: u64, post: u64) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"sessionId\":\"{session}\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{{\"trigger\":\"auto\",\"preTokens\":{pre},\"postTokens\":{post},\"cumulativeDroppedTokens\":3,\"durationMs\":9}}}}\n"
    )
}

fn parse(path: &Path, now: OffsetDateTime) -> SnapshotItem {
    parse_claude_code_jsonl_file(path, &stamp(now, 0), "file-birth-fp".to_string())
        .expect("parse transcript fixture")
        .remove(0)
}

/// Write one root transcript (birth = now) and parse its snapshot.
fn root_session(dir: &Path, session_id: &str, lines: &[String]) -> (PathBuf, SnapshotItem) {
    fs::create_dir_all(dir).expect("create project dir");
    let path = dir.join(format!("{session_id}.jsonl"));
    fs::write(&path, lines.concat()).expect("write transcript fixture");
    let item = parse(&path, OffsetDateTime::now_utc());
    assert!(
        item.claude_file_birth.is_root_with_birth_for_test(),
        "the test file system must report file birth"
    );
    (path, item)
}

/// API and trace rows, each request reported under `root` (no agent).
fn reports(
    rows: &[(&str, &str, u64, u64)],
    with_trace: bool,
) -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    let mut api = BTreeMap::<String, Vec<_>>::new();
    let mut trace = BTreeMap::<String, Vec<_>>::new();
    for (root, request, sequence, input_tokens) in rows {
        api.entry(root.to_string())
            .or_default()
            .push(complete_api_row(
                root,
                request,
                *sequence,
                *input_tokens,
                1,
                0,
            ));
        if with_trace {
            trace
                .entry(root.to_string())
                .or_default()
                .push(complete_trace_row(root, request, ""));
        }
    }
    (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: api,
            health: Default::default(),
        },
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: trace,
            ..Default::default()
        },
    )
}

fn no_reports() -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    reports(&[], true)
}

/// Index every path. `fence_closed` models the steady state on real Macs: the
/// global duplicate fence is held, so no item is owned by the strict rule.
fn indexed(paths: &[&Path], fence_closed: bool) -> ScanIndex {
    let mut index = ScanIndex::default();
    for path in paths {
        index
            .files
            .insert(local_index_key(path), manifest_index_entry(None));
    }
    index.claude_duplicate_request_witness_overflowed = fence_closed;
    index
}

fn fold(
    items: &mut [SnapshotItem],
    reports: &(
        crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ),
    index: &mut ScanIndex,
    census_complete: bool,
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_with_index_and_limits(
        items,
        &reports.0,
        &reports.1,
        index,
        census_complete,
        &stamp(OffsetDateTime::now_utc(), 60),
        1_000,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    )
}

fn posture(item: &SnapshotItem) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    (
        item.first_turn_context_tokens,
        item.peak_context_fill_tokens,
        item.last_turn_context_tokens,
        item.compaction_count,
    )
}

fn assert_cleared(item: &SnapshotItem) {
    assert_eq!(posture(item), (None, None, None, None));
    assert!(item.compaction_timestamps.is_empty());
    assert_eq!(item.compaction_total_pre_tokens, None);
    assert_eq!(item.compaction_total_post_tokens, None);
    assert_eq!(item.compaction_total_cumulative_dropped_tokens, None);
    assert_eq!(item.compaction_total_duration_ms, None);
}

fn inherited_start(item: &SnapshotItem) -> Option<SnapshotSessionStart> {
    item.session_start
        .clone()
        .and_then(|start| (*start).inherited())
}

/// Serialized top-level keys whose values differ between two bodies.
fn differing_keys(left: &SnapshotItem, right: &SnapshotItem) -> BTreeSet<String> {
    let left = serde_json::to_value(left).expect("serialize body");
    let right = serde_json::to_value(right).expect("serialize body");
    let (left, right) = (
        left.as_object().expect("body object"),
        right.as_object().expect("body object"),
    );
    left.keys()
        .chain(right.keys())
        .filter(|key| left.get(*key) != right.get(*key))
        .cloned()
        .collect()
}

fn allowed_difference() -> BTreeSet<String> {
    CONTEXT_KEYS
        .iter()
        .chain(&["session_start", "snapshot_fingerprint"])
        .map(|key| key.to_string())
        .collect()
}

#[test]
fn rewind_copy_counts_only_own_records() {
    let dir = temp_dir("claude-file-birth-rewind");
    let now = OffsetDateTime::now_utc();
    let lines = [
        // Copied in by Rewind with the original timestamps.
        assistant(ROOT, "req_c1", &stamp(now, COPIED), 900_000),
        assistant(ROOT, "req_c2", &stamp(now, COPIED + 1), 950_000),
        boundary(ROOT, &stamp(now, COPIED + 2), 950_010, 100_000),
        assistant(ROOT, "req_c3", &stamp(now, COPIED + 3), 120_000),
        // This session's own turns.
        assistant(ROOT, "req_a1", &stamp(now, -30), 100),
        assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        boundary(ROOT, &stamp(now, -28), 310, 50),
        assistant(ROOT, "req_a3", &stamp(now, -27), 200),
        // A second copied block after own turns: dropped by timestamp.
        assistant(ROOT, "req_c4", &stamp(now, COPIED + 10), 990_000),
        boundary(ROOT, &stamp(now, COPIED + 11), 990_010, 100_000),
        assistant(ROOT, "req_a4", &stamp(now, -26), 150),
    ];
    let (path, parsed) = root_session(&dir, ROOT, &lines);
    assert!(
        parsed.peak_context_fill_tokens > Some(300),
        "today's parser value includes the copy"
    );
    assert_eq!(parsed.claude_file_birth.tagged_responses_for_test(), 4);
    let fold_with = |rule_on: bool| {
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], true);
        let disposition = if rule_on {
            fold(&mut items, &no_reports(), &mut index, true)
        } else {
            claude_context_file_birth::with_file_birth_rule_disabled_for_test(|| {
                fold(&mut items, &no_reports(), &mut index, true)
            })
        };
        (disposition, items.remove(0))
    };

    let (disposition, item) = fold_with(true);
    let (_, control) = fold_with(false);

    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(posture(&item), (Some(100), Some(300), Some(150), Some(1)));
    let own_boundary = stamp(now, -28);
    assert_eq!(item.compaction_timestamps, vec![own_boundary]);
    assert_eq!(item.compaction_total_pre_tokens, Some(310));
    assert_eq!(item.compaction_total_post_tokens, Some(50));
    // The opening was copied: the session did not start here.
    assert_eq!(
        item.session_start.as_deref(),
        inherited_start(&parsed).as_ref()
    );
    let counts = &disposition.context_file_birth.total;
    assert_eq!(counts.tagged_record_count, 6, "4 responses + 2 boundaries");
    assert_eq!(counts.file_birth_rule_session_count, 1);
    // Usage, cost, identity and accounts: byte-identical to today's clear.
    assert_cleared(&control);
    let differing = differing_keys(&item, &control);
    assert!(differing.is_subset(&allowed_difference()), "{differing:?}");
    assert!(!differing.contains("session_start"));
    assert_eq!(item.request_count, parsed.request_count);
    assert_eq!(item.input_tokens, parsed.input_tokens);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn fresh_growing_file_has_numbers_on_its_first_upload() {
    let dir = temp_dir("claude-file-birth-growing");
    let now = OffsetDateTime::now_utc();
    let first = assistant(ROOT, "req_a1", &stamp(now, -30), 100);
    let (path, parsed) = root_session(&dir, ROOT, std::slice::from_ref(&first));
    let mut items = vec![parsed.clone()];
    // Incomplete census and a held fence: today this waited for a quiet pass.
    let mut index = indexed(&[&path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, false);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(
        posture(&items[0]),
        (Some(100), Some(100), Some(100), Some(0))
    );
    // R9: no local proven family witness, so this contract-less body may
    // carry its scalars (once per change). Counted locally.
    let counts = &disposition.context_file_birth;
    assert_eq!(counts.contractless_scalars_witness_missing_session_count, 1);
    assert_eq!(counts.contractless_scalars_witness_present_session_count, 0);
    assert_eq!(
        items[0].session_start.as_deref(),
        inherited_start(&parsed).as_ref(),
        "session start stays under its existing gate"
    );

    // The same file keeps its birth while it grows.
    fs::write(
        &path,
        [first, assistant(ROOT, "req_a2", &stamp(now, -29), 300)].concat(),
    )
    .expect("append fixture");
    let grown = parse(&path, now);
    let mut items = vec![grown.clone()];
    let disposition = fold(&mut items, &no_reports(), &mut index, false);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(
        posture(&items[0]),
        (Some(100), Some(300), Some(300), Some(0))
    );
    assert_eq!(
        items[0].session_start.as_deref(),
        inherited_start(&grown).as_ref()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn late_born_subagent_file_is_not_tagged() {
    let dir = temp_dir("claude-file-birth-subagent");
    let now = OffsetDateTime::now_utc();
    let agent = "a4d1585d310070d0f";
    let child_dir = dir.join(ROOT).join("subagents");
    fs::create_dir_all(&child_dir).expect("create subagent dir");
    let path = child_dir.join(format!("agent-{agent}.jsonl"));
    // Written long after its records' timestamps: exempt all the same.
    fs::write(
        &path,
        subagent_assistant(ROOT, agent, "req_s1", &stamp(now, COPIED)),
    )
    .expect("write subagent fixture");
    let parsed = parse(&path, now);
    assert!(parsed.claude_file_birth.is_subagent_for_test());
    assert_eq!(parsed.claude_file_birth.tagged_responses_for_test(), 0);
    let session_id = parsed.source_session_id.clone();
    let mut items = vec![parsed.clone()];
    let mut index = indexed(&[&path], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    assert_eq!(
        disposition.posture_admission(&session_id),
        Some("file_birth_rule")
    );
    assert_eq!(posture(&items[0]), (Some(40), Some(40), Some(40), Some(0)));
    assert_eq!(
        items[0].session_start.as_deref(),
        inherited_start(&parsed).as_ref()
    );
    assert_eq!(disposition.context_file_birth.total.tagged_record_count, 0);
    let _ = fs::remove_dir_all(dir);
}

/// SOURCE condition 2: a subagent file is exempt from the birth rule only.
/// The telemetry tripwire still applies wherever sidecars exist.
#[test]
fn subagent_file_is_not_exempt_from_the_tripwire() {
    let dir = temp_dir("claude-file-birth-subagent-tripwire");
    let now = OffsetDateTime::now_utc();
    let agent = "a4d1585d310070d0f";
    let child_dir = dir.join(ROOT).join("subagents");
    fs::create_dir_all(&child_dir).expect("create subagent dir");
    let path = child_dir.join(format!("agent-{agent}.jsonl"));
    fs::write(
        &path,
        subagent_assistant(ROOT, agent, "req_s1", &stamp(now, -30)),
    )
    .expect("write subagent fixture");
    let parsed = parse(&path, now);
    assert!(parsed.claude_file_birth.is_subagent_for_test());
    let session_id = parsed.source_session_id.clone();
    let mut index = indexed(&[&path], true);
    // Admitted first: a veto is remembered for this file version (F2).
    for (owner, expected) in [(ROOT, "file_birth_rule"), (OTHER_ROOT, "withheld_tripwire")] {
        let mut items = vec![parsed.clone()];
        let evidence = reports(&[(owner, "req_s1", 1, 40)], true);
        let disposition = fold(&mut items, &evidence, &mut index, true);
        assert_eq!(
            disposition.posture_admission(&session_id),
            Some(expected),
            "{owner}"
        );
        if expected == "withheld_tripwire" {
            assert_cleared(&items[0]);
            assert_eq!(
                items[0].session_start.as_deref().cloned(),
                inherited_start(&parsed),
                "a tripwire withhold also withholds the split"
            );
            assert_eq!(
                disposition
                    .context_file_birth
                    .total
                    .withheld_tripwire_session_count,
                1
            );
        } else {
            assert_eq!(posture(&items[0]), (Some(40), Some(40), Some(40), Some(0)));
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// F1 / SESSION Context: the files of one session id are not merged, so
/// neither file ships its own first/peak/last or compaction count as the
/// session's numbers. The whole tuple is withheld and session start keeps the
/// version only; the counter stays.
#[test]
fn same_session_id_in_two_folders_withholds_the_tuple() {
    let dir = temp_dir("claude-file-birth-two-folders");
    let now = OffsetDateTime::now_utc();
    let (path_a, parsed) = root_session(
        &dir.join("project-a"),
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
            boundary(ROOT, &stamp(now, -28), 310, 50),
            assistant(ROOT, "req_a3", &stamp(now, -27), 200),
        ],
    );
    let (path_b, other) = root_session(
        &dir.join("project-b"),
        ROOT,
        &[assistant(ROOT, "req_b1", &stamp(now, -28), 700)],
    );
    // Only one file is on this page; the index still knows the other one.
    let mut items = vec![parsed.clone()];
    let mut index = indexed(&[&path_a, &path_b], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    assert_eq!(
        disposition.posture_admission(ROOT),
        Some("withheld_multi_file")
    );
    assert_cleared(&items[0]);
    assert_eq!(
        items[0].session_start.as_deref(),
        inherited_start(&parsed).as_ref()
    );
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_multi_file_session_count,
        1
    );
    // Both files on one page: the same, for each file.
    let mut items = vec![parsed.clone(), other];
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    for item in &items {
        assert_cleared(item);
    }
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_multi_file_session_count,
        2
    );
    // Once the second file is gone, the remaining file is admitted.
    let mut items = vec![parsed];
    let mut index = indexed(&[&path_a], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(
        posture(&items[0]),
        (Some(100), Some(300), Some(200), Some(1))
    );
    let _ = fs::remove_dir_all(dir);
}

/// SOURCE Amendment 5 (review F7): a restored, synced or slot-moved file that
/// keeps growing is admitted with post-birth numbers only and counted as
/// `partially_pre_birth`. When the original file of the same session id is
/// also present, F1's whole-tuple withhold wins.
#[test]
fn restored_file_that_grows_counts_post_birth_only_unless_the_original_is_present() {
    let dir = temp_dir("claude-file-birth-restored-grows");
    let now = OffsetDateTime::now_utc();
    let (restored_path, restored) = root_session(
        &dir.join("restored"),
        ROOT,
        &[
            // The original session, restored with its timestamps.
            assistant(ROOT, "req_o1", &stamp(now, COPIED), 900_000),
            boundary(ROOT, &stamp(now, COPIED + 1), 950_000, 100_000),
            assistant(ROOT, "req_o2", &stamp(now, COPIED + 2), 950_000),
            // New activity after the restore.
            assistant(ROOT, "req_n1", &stamp(now, -30), 100),
            assistant(ROOT, "req_n2", &stamp(now, -29), 300),
        ],
    );
    let (original_path, _) = root_session(
        &dir.join("original"),
        ROOT,
        &[
            assistant(ROOT, "req_o1", &stamp(now, -31), 900_000),
            assistant(ROOT, "req_o2", &stamp(now, -30), 950_000),
        ],
    );
    let partially = |disposition: &ClaudeUsageAuthorityDisposition| {
        let counts = &disposition.context_file_birth;
        let by_version = counts
            .by_claude_code_version
            .values()
            .map(|row| row.partially_pre_birth_session_count)
            .sum::<usize>();
        (counts.total.partially_pre_birth_session_count, by_version)
    };

    // Only the restored file: admitted, post-birth numbers only. First is
    // the first prompt after the restore; peak never includes copied records.
    let mut items = vec![restored.clone()];
    let mut index = indexed(&[&restored_path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(
        posture(&items[0]),
        (Some(100), Some(300), Some(300), Some(0))
    );
    assert_eq!(partially(&disposition), (1, 1));

    // The original is also present: same session id in two files, the whole
    // tuple is withheld.
    let mut items = vec![restored];
    let mut index = indexed(&[&restored_path, &original_path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    assert_eq!(
        disposition.posture_admission(ROOT),
        Some("withheld_multi_file")
    );
    assert_cleared(&items[0]);
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_multi_file_session_count,
        1
    );
    assert_eq!(partially(&disposition), (1, 1));

    // Controls: a fresh file and a later copied block are not partial.
    let (fresh_path, fresh) = root_session(
        &dir.join("fresh"),
        SECOND,
        &[assistant(SECOND, "req_f1", &stamp(now, -30), 100)],
    );
    let (later_path, later) = root_session(
        &dir.join("later"),
        OTHER_ROOT,
        &[
            assistant(OTHER_ROOT, "req_l1", &stamp(now, -30), 100),
            assistant(OTHER_ROOT, "req_lc", &stamp(now, COPIED), 900_000),
            assistant(OTHER_ROOT, "req_l2", &stamp(now, -29), 300),
        ],
    );
    let mut items = vec![fresh, later];
    let mut index = indexed(&[&fresh_path, &later_path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .file_birth_rule_session_count,
        2
    );
    assert_eq!(partially(&disposition), (0, 0));
    let _ = fs::remove_dir_all(dir);
}

/// F5: a reported birth at or before 2020-01-01T00:00:00Z (0, the epoch, a
/// reset clock) is not evidence, so the file withholds as unknown birth.
#[test]
fn birth_at_or_before_2020_counts_as_unknown() {
    let dir = temp_dir("claude-file-birth-floor");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[assistant(ROOT, "req_a1", &stamp(now, -30), 100)],
    );
    let floor = 1_577_836_800_i128 * 1_000_000_000;
    let second = 1_000_000_000_i128;
    for (birth, expected) in [
        (0, "withheld_unknown_birth"),
        (-second, "withheld_unknown_birth"),
        (floor, "withheld_unknown_birth"),
        (floor - second, "withheld_unknown_birth"),
        // Just past the floor is a real birth: every record is younger, so
        // the file is its own.
        (floor + second, "file_birth_rule"),
    ] {
        let mut item = parsed.clone();
        item.claude_file_birth.set_birth_for_test(birth);
        let mut items = vec![item];
        let mut index = indexed(&[&path], true);
        let disposition = fold(&mut items, &no_reports(), &mut index, true);
        assert_eq!(
            disposition.posture_admission(ROOT),
            Some(expected),
            "{birth}"
        );
        if expected == "withheld_unknown_birth" {
            assert_cleared(&items[0]);
            assert_eq!(
                disposition
                    .context_file_birth
                    .total
                    .withheld_unknown_birth_session_count,
                1
            );
        } else {
            assert_eq!(
                posture(&items[0]),
                (Some(100), Some(100), Some(100), Some(0))
            );
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// F4: a root response or boundary whose timestamp is missing or unusable
/// cannot be classified, so the file withholds (never "owned" by default).
#[test]
fn untimed_or_invalid_record_timestamp_withholds() {
    let dir = temp_dir("claude-file-birth-untimed");
    let now = OffsetDateTime::now_utc();
    let own = assistant(ROOT, "req_a1", &stamp(now, -30), 100);
    // The same response shape without a `timestamp` key.
    let untimed_response = assistant(ROOT, "req_u1", "", 300).replace("\"timestamp\":\"\",", "");
    for (case, tail) in [
        ("missing", untimed_response),
        ("invalid", assistant(ROOT, "req_u1", "not-a-timestamp", 300)),
        (
            "invalid boundary",
            boundary(ROOT, "2026-13-45T99:00:00Z", 310, 50),
        ),
    ] {
        let case_dir = dir.join(case.replace(' ', "-"));
        let (path, parsed) = root_session(&case_dir, ROOT, &[own.clone(), tail]);
        let mut items = vec![parsed];
        let mut index = indexed(&[&path], true);
        let disposition = fold(&mut items, &no_reports(), &mut index, true);
        assert_eq!(
            disposition.posture_admission(ROOT),
            Some("withheld_untimed_record"),
            "{case}"
        );
        assert_cleared(&items[0]);
        assert_eq!(
            disposition
                .context_file_birth
                .total
                .withheld_untimed_record_session_count,
            1,
            "{case}"
        );
    }
    let _ = fs::remove_dir_all(dir);
}

/// F4: the evidence bound is per root. A root over it is withheld; another
/// root on the same page is still admitted.
#[test]
fn evidence_bound_withholds_only_that_root() {
    let dir = temp_dir("claude-file-birth-evidence-bound");
    let now = OffsetDateTime::now_utc();
    let (path_a, large) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
            assistant(ROOT, "req_a3", &stamp(now, -28), 200),
        ],
    );
    let (path_b, small) = root_session(
        &dir,
        SECOND,
        &[assistant(SECOND, "req_b1", &stamp(now, -30), 100)],
    );
    let mut items = vec![large, small];
    let mut index = indexed(&[&path_a, &path_b], true);

    let disposition = apply_claude_reported_usage_with_index_and_limits(
        &mut items,
        &no_reports().0,
        &no_reports().1,
        &mut index,
        true,
        &stamp(OffsetDateTime::now_utc(), 60),
        2,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    );

    assert_eq!(
        disposition.posture_admission(ROOT),
        Some("withheld_evidence_bound")
    );
    assert_cleared(&items[0]);
    assert_eq!(
        disposition.posture_admission(SECOND),
        Some("file_birth_rule")
    );
    assert_eq!(
        posture(&items[1]),
        (Some(100), Some(100), Some(100), Some(0))
    );
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_evidence_bound_session_count,
        1
    );
    let _ = fs::remove_dir_all(dir);
}

const FOURTH: &str = "d0000000-0000-4000-8000-00000000000d";
const FIFTH: &str = "e0000000-0000-4000-8000-00000000000e";

/// Five own requests per root for `roots`, one file each in `dir`.
fn five_request_roots(
    dir: &Path,
    now: OffsetDateTime,
    roots: &[&str],
) -> Vec<(PathBuf, SnapshotItem)> {
    roots
        .iter()
        .map(|root| {
            let lines = (0..5)
                .map(|turn| {
                    assistant(
                        root,
                        &format!("req_{}_{turn}", &root[..1]),
                        &stamp(now, -30 + turn),
                        100 * (turn as u64 + 1),
                    )
                })
                .collect::<Vec<_>>();
            root_session(dir, root, &lines)
        })
        .collect()
}

/// Every request of `roots` reported under its own root, plus `extra`.
fn own_rows<'a>(roots: &[&'a str], extra: &[(&'a str, &'a str)]) -> Vec<(String, String)> {
    roots
        .iter()
        .flat_map(|root| {
            (0..5).map(move |turn| (root.to_string(), format!("req_{}_{turn}", &root[..1])))
        })
        .chain(
            extra
                .iter()
                .map(|(root, request)| (root.to_string(), request.to_string())),
        )
        .collect()
}

fn fold_with_bound(
    items: &mut [SnapshotItem],
    rows: &[(String, String)],
    index: &mut ScanIndex,
    bound: usize,
) -> ClaudeUsageAuthorityDisposition {
    let rows = rows
        .iter()
        .enumerate()
        .map(|(sequence, (root, request))| (root.as_str(), request.as_str(), sequence as u64, 100))
        .collect::<Vec<_>>();
    let (api, trace) = reports(&rows, true);
    apply_claude_reported_usage_with_index_and_limits(
        items,
        &api,
        &trace,
        index,
        true,
        &stamp(OffsetDateTime::now_utc(), 60),
        bound,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
    )
}

/// N1: the bound is per root. Four roots of five requests each fill a page
/// far past a bound of six, with 40+ loaded telemetry rows, so the owners
/// lookup runs in several partitions. Each root is under its own bound, so
/// all are judged: the four are admitted and confirmed, and a fifth root whose
/// kept request telemetry reports under another root is still caught.
#[test]
fn roots_under_their_own_bound_are_all_admitted_on_a_page_over_it() {
    let dir = temp_dir("claude-file-birth-per-root-bound");
    let now = OffsetDateTime::now_utc();
    let roots = [ROOT, SECOND, OTHER_ROOT, FOURTH];
    let mut files = five_request_roots(&dir, now, &roots);
    files.push(root_session(
        &dir,
        FIFTH,
        &[assistant(FIFTH, "req_e1", &stamp(now, -30), 100)],
    ));
    let paths = files
        .iter()
        .map(|(path, _)| path.as_path())
        .collect::<Vec<_>>();
    let mut index = indexed(&paths, true);
    let mut items = files
        .iter()
        .map(|(_, item)| item.clone())
        .collect::<Vec<_>>();
    let rows = own_rows(&roots, &[(ROOT, "req_e1")]);
    assert!(
        rows.len() * 2 > 6 * 6,
        "the loaded rows exceed the bound many times"
    );

    let disposition = fold_with_bound(&mut items, &rows, &mut index, 6);

    for (root, item) in roots.iter().zip(&items) {
        assert_eq!(disposition.posture_admission(root), Some("file_birth_rule"));
        assert_eq!(posture(item), (Some(100), Some(500), Some(500), Some(0)));
    }
    assert_eq!(
        disposition.posture_admission(FIFTH),
        Some("withheld_tripwire")
    );
    assert_cleared(&items[4]);
    let total = disposition.context_file_birth.total;
    assert_eq!(total.withheld_evidence_bound_session_count, 0);
    assert_eq!(total.file_birth_rule_session_count, 4);
    assert_eq!(total.telemetry_confirmed_session_count, 4);
    assert_eq!(total.withheld_tripwire_session_count, 1);
    let _ = fs::remove_dir_all(dir);
}

/// N1: a session admitted on a small page keeps the same body when a later
/// big page (a backfill or a closed-fence re-arm) carries it with many other
/// roots whose total is far over the bound.
#[test]
fn admitted_session_is_not_blanked_by_a_big_page() {
    let dir = temp_dir("claude-file-birth-big-page");
    let now = OffsetDateTime::now_utc();
    let roots = [ROOT, SECOND, OTHER_ROOT, FOURTH, FIFTH];
    let files = five_request_roots(&dir, now, &roots);
    let paths = files
        .iter()
        .map(|(path, _)| path.as_path())
        .collect::<Vec<_>>();

    let mut small = vec![files[0].1.clone()];
    let mut index = indexed(&paths[..1], true);
    let disposition = fold_with_bound(&mut small, &own_rows(&roots[..1], &[]), &mut index, 6);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(
        posture(&small[0]),
        (Some(100), Some(500), Some(500), Some(0))
    );

    let mut big = files
        .iter()
        .map(|(_, item)| item.clone())
        .collect::<Vec<_>>();
    let mut index = indexed(&paths, true);
    let disposition = fold_with_bound(&mut big, &own_rows(&roots, &[]), &mut index, 6);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    let changed = differing_keys(&small[0], &big[0])
        .intersection(&allowed_difference())
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        changed.is_empty(),
        "the big page keeps the context numbers and session start: {changed:?}"
    );
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_evidence_bound_session_count,
        0
    );
    let _ = fs::remove_dir_all(dir);
}

/// review-678c R3: one root whose requests span slices, with the
/// contradiction in a later slice than a confirmed request. The earlier
/// slice's confirmation must not hide the later contradiction.
#[test]
fn contradiction_in_a_later_slice_vetoes_the_root() {
    let dir = temp_dir("claude-file-birth-later-slice");
    let now = OffsetDateTime::now_utc();
    let bound = 6;
    let own = (0..5)
        .map(|turn| format!("req_a_{turn}"))
        .collect::<Vec<_>>();
    let fillers = [SECOND, FOURTH];
    let page_rows = |late: &str| {
        let mut rows = own_rows(&fillers, &[]);
        rows.extend(
            own.iter()
                .map(|request| (ROOT.to_string(), request.clone())),
        );
        // A kept request of ROOT that telemetry reports under another root.
        rows.push((SECOND.to_string(), late.to_string()));
        rows
    };
    let (late, partitions) = (0..256)
        .find_map(|n| {
            let late = format!("req_late_{n}");
            let rows = page_rows(&late);
            // Each request is loaded twice: its API row and its trace row.
            let loaded = rows
                .iter()
                .flat_map(|(_, request)| [request.as_str(), request.as_str()])
                .collect::<Vec<_>>();
            let slice = |request: &str| {
                claude_context_file_birth::telemetry_slice_for_test(&loaded, bound, request)
            };
            let (partitions, late_slice) = slice(late.as_str())?;
            let earliest_own = own
                .iter()
                .filter_map(|request| slice(request.as_str()))
                .min()?
                .1;
            (partitions > 1 && late_slice > earliest_own).then_some((late, partitions))
        })
        .expect("some request id falls in a later slice");
    assert!(partitions > 1);
    let mut lines = own
        .iter()
        .enumerate()
        .map(|(turn, request)| assistant(ROOT, request, &stamp(now, -30 + turn as i64), 100))
        .collect::<Vec<_>>();
    lines.push(assistant(ROOT, &late, &stamp(now, -20), 100));
    let mut files = vec![root_session(&dir, ROOT, &lines)];
    files.extend(five_request_roots(&dir, now, &fillers));
    let paths = files
        .iter()
        .map(|(path, _)| path.as_path())
        .collect::<Vec<_>>();
    let mut index = indexed(&paths, true);
    let mut items = files
        .iter()
        .map(|(_, item)| item.clone())
        .collect::<Vec<_>>();
    assert_eq!(items[0].claude_usage_occurrences.len(), bound);

    let disposition = fold_with_bound(&mut items, &page_rows(&late), &mut index, bound);

    assert_eq!(
        disposition.posture_admission(ROOT),
        Some("withheld_tripwire")
    );
    assert_cleared(&items[0]);
    for root in fillers {
        assert_eq!(disposition.posture_admission(root), Some("file_birth_rule"));
    }
    let total = disposition.context_file_birth.total;
    assert_eq!(total.withheld_evidence_bound_session_count, 0);
    assert_eq!(total.withheld_tripwire_session_count, 1);
    let _ = fs::remove_dir_all(dir);
}

/// SOURCE Amendment 7: with the per-root bound lowered by the test seam, a
/// root the production bound admitted is counted as evidence-bound on every
/// later pass, the accessor reports the resource withhold, and the local
/// alarm fires on the first such pass only.
#[test]
fn evidence_bound_past_the_lowered_seam_is_counted_and_alarms_once() {
    let dir = temp_dir("claude-file-birth-evidence-bound-seam");
    let now = OffsetDateTime::now_utc();
    let files = five_request_roots(&dir, now, &[ROOT]);
    let paths = [files[0].0.as_path()];
    let rows = own_rows(&[ROOT], &[]);
    let is_alarm =
        |record: &serde_json::Value| record["stage"] == "claude_context_resource_withhold";
    let pass = || {
        let mut items = vec![files[0].1.clone()];
        let mut index = indexed(&paths, true);
        let (disposition, records) = crate::local_resource_diagnostics::capture(|| {
            fold_with_bound(
                &mut items,
                &rows,
                &mut index,
                MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            )
        });
        let alarms = records.into_iter().filter(is_alarm).collect::<Vec<_>>();
        (disposition, items.remove(0), alarms)
    };

    let (admitted, item, alarms) = pass();
    assert_eq!(admitted.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(posture(&item), (Some(100), Some(500), Some(500), Some(0)));
    assert!(!admitted.context_file_birth.resource_withheld());
    assert!(alarms.is_empty());

    claude_context_file_birth::with_claude_evidence_bound_for_test(4, || {
        for first in [true, false] {
            let (withheld, item, alarms) = pass();
            assert_eq!(
                withheld.posture_admission(ROOT),
                Some("withheld_evidence_bound")
            );
            assert_cleared(&item);
            let counts = &withheld.context_file_birth;
            assert_eq!(counts.total.withheld_evidence_bound_session_count, 1);
            assert!(!counts.remembered_veto_overflowed);
            assert!(counts.resource_withheld());
            if first {
                assert_eq!(alarms.len(), 1);
                assert_eq!(alarms[0]["source"], "claude_code");
                assert_eq!(
                    alarms[0]["counts"]["withheld_evidence_bound_session_count"],
                    1
                );
                assert_eq!(alarms[0]["counts"]["remembered_veto_overflowed"], false);
            } else {
                assert!(alarms.is_empty(), "the alarm fires once per process");
            }
        }
    });
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unknown_birth_withholds_and_is_counted() {
    let dir = temp_dir("claude-file-birth-unknown");
    let now = OffsetDateTime::now_utc();
    let (path, mut unknown) = root_session(
        &dir,
        ROOT,
        &[assistant(ROOT, "req_a1", &stamp(now, -30), 100)],
    );
    unknown.claude_file_birth.forget_birth_for_test();
    let (second_path, mut unobserved) = root_session(
        &dir,
        SECOND,
        &[assistant(SECOND, "req_b1", &stamp(now, -30), 100)],
    );
    // Not read through the transcript parser: nothing vouches for it.
    unobserved.claude_file_birth = Default::default();
    let mut items = vec![unknown, unobserved];
    let mut index = indexed(&[&path, &second_path], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    for (session, item) in [(ROOT, &items[0]), (SECOND, &items[1])] {
        assert_eq!(
            disposition.posture_admission(session),
            Some("withheld_unknown_birth")
        );
        assert_cleared(item);
    }
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_unknown_birth_session_count,
        2
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn all_copied_file_withholds() {
    let dir = temp_dir("claude-file-birth-all-copied");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_c1", &stamp(now, COPIED), 900_000),
            assistant(ROOT, "req_c2", &stamp(now, COPIED + 1), 950_000),
        ],
    );
    let mut items = vec![parsed];
    let mut index = indexed(&[&path], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    assert_eq!(
        disposition.posture_admission(ROOT),
        Some("withheld_all_copied")
    );
    assert_cleared(&items[0]);
    let counts = &disposition.context_file_birth.total;
    assert_eq!(counts.withheld_all_copied_session_count, 1);
    assert_eq!(counts.tagged_record_count, 2);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn telemetry_contradiction_withholds_and_is_counted() {
    let dir = temp_dir("claude-file-birth-tripwire");
    let now = OffsetDateTime::now_utc();
    // A kept request that another root's telemetry owns.
    let (path_a, kept_foreign) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    // A tagged request that this root's own telemetry owns.
    let (path_b, tagged_own) = root_session(
        &dir,
        SECOND,
        &[
            assistant(SECOND, "req_b0", &stamp(now, COPIED), 900_000),
            assistant(SECOND, "req_b1", &stamp(now, -30), 100),
        ],
    );
    let mut items = vec![kept_foreign, tagged_own];
    let mut index = indexed(&[&path_a, &path_b], true);
    let evidence = reports(
        &[
            (OTHER_ROOT, "req_a1", 1, 100),
            (SECOND, "req_b0", 1, 900_000),
        ],
        true,
    );

    let disposition = fold(&mut items, &evidence, &mut index, true);

    for (session, item) in [(ROOT, &items[0]), (SECOND, &items[1])] {
        assert_eq!(
            disposition.posture_admission(session),
            Some("withheld_tripwire")
        );
        assert_cleared(item);
    }
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_tripwire_session_count,
        2
    );
    let _ = fs::remove_dir_all(dir);
}

/// F2: which telemetry rows a fold loads depends on the page. A veto is
/// remembered for the vetoed file version for the process lifetime, so a
/// later page that did not load the rows cannot admit the same bytes again.
/// Only a changed file (a new fingerprint) is checked afresh.
#[test]
fn telemetry_veto_stays_until_the_file_changes() {
    let dir = temp_dir("claude-file-birth-late-tripwire");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    let grown_as = |fingerprint: &str| {
        let mut grown = parsed.clone();
        grown.source_file_fingerprint = Some(fingerprint.to_string());
        grown
    };
    let (grown, grown_again) = (
        grown_as("file-birth-fp-grown"),
        grown_as("file-birth-fp-grown-2"),
    );
    let mut index = indexed(&[&path], true);
    let contradiction = || reports(&[(OTHER_ROOT, "req_a1", 1, 100)], true);
    // Missing telemetry is not a contradiction. A row arriving later
    // withholds, and the withhold holds on pages without that row until the
    // file changes.
    for (step, item, evidence, expected, remembered) in [
        (1, &parsed, no_reports(), "file_birth_rule", 0),
        (2, &parsed, contradiction(), "withheld_tripwire", 0),
        (3, &parsed, no_reports(), "withheld_tripwire", 1),
        (4, &grown, contradiction(), "withheld_tripwire", 0),
        (5, &grown, no_reports(), "withheld_tripwire", 1),
        (6, &grown_again, no_reports(), "file_birth_rule", 0),
    ] {
        let mut items = vec![item.clone()];
        let disposition = fold(&mut items, &evidence, &mut index, true);
        assert_eq!(
            disposition.posture_admission(ROOT),
            Some(expected),
            "{step}"
        );
        let counts = &disposition.context_file_birth.total;
        assert_eq!(
            counts.withheld_tripwire_remembered_session_count, remembered,
            "{step}"
        );
        if expected == "withheld_tripwire" {
            assert_cleared(&items[0]);
        } else {
            assert_eq!(
                posture(&items[0]),
                (Some(100), Some(300), Some(300), Some(0)),
                "{step}"
            );
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// F2: the veto memory is bounded. Past its capacity it fails closed: every
/// later file withholds until the process restarts.
#[test]
fn remembered_tripwire_fails_closed_when_full() {
    let dir = temp_dir("claude-file-birth-remembered-full");
    let now = OffsetDateTime::now_utc();
    let file = |session: &str| {
        root_session(
            &dir,
            session,
            &[assistant(
                session,
                &format!("req_{session}"),
                &stamp(now, -30),
                100,
            )],
        )
        .1
    };
    let (first, second, third) = (file(ROOT), file(SECOND), file(OTHER_ROOT));
    let mut memory = claude_context_file_birth::ClaudeRememberedTripwire::new(1);
    assert!(!memory.holds(&first));
    memory.remember(&first);
    assert!(memory.holds(&first));
    assert!(!memory.holds(&second));
    let mut changed = first.clone();
    changed.source_file_fingerprint = Some("changed".to_string());
    assert!(
        !memory.holds(&changed),
        "a new file version is checked afresh"
    );
    memory.remember(&second);
    for item in [&first, &second, &third, &changed] {
        assert!(memory.holds(item), "full: fail closed");
    }
    // N3: the full list shows on the local counts line.
    let reports = no_reports();
    let veto_rows = ClaudeVetoApiRows::new();
    let tripwire = claude_context_file_birth::ClaudeTelemetryTripwire::build(
        std::slice::from_ref(&third),
        1_000,
        &reports.0,
        &reports.1,
        &veto_rows,
    );
    let mut counts = ClaudeContextFileBirthCounts::default();
    let mut held = third.clone();
    let verdict = claude_context_file_birth::admit_claude_file_birth_posture(
        &mut held,
        OTHER_ROOT,
        &tripwire,
        &mut memory,
        false,
        &mut counts,
    );
    assert_eq!(verdict, ClaudeFileBirthVerdict::Tripwire);
    assert!(counts.remembered_veto_overflowed);
    assert_eq!(counts.total.withheld_tripwire_remembered_session_count, 1);
    // review-678c R1: a full list is a resource withhold. The accessor
    // reports it and the first one raises the local alarm, once.
    assert!(!ClaudeContextFileBirthCounts::default().resource_withheld());
    assert!(counts.resource_withheld());
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        claude_context_file_birth::alarm_first_resource_withhold(&counts);
        claude_context_file_birth::alarm_first_resource_withhold(&counts);
    });
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0]["stage"], "claude_context_resource_withhold");
    assert_eq!(alarms[0]["source"], "claude_code");
    assert_eq!(alarms[0]["counts"]["remembered_veto_overflowed"], true);
    assert_eq!(
        alarms[0]["counts"]["withheld_evidence_bound_session_count"],
        0
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn same_session_id_never_merges_across_accounts() {
    let dir = temp_dir("claude-file-birth-two-accounts");
    let now = OffsetDateTime::now_utc();
    let (path_a, mut first) = root_session(
        &dir.join("account-a"),
        ROOT,
        &[assistant(ROOT, "req_a1", &stamp(now, -30), 100)],
    );
    let (path_b, mut second) = root_session(
        &dir.join("account-b"),
        ROOT,
        &[assistant(ROOT, "req_b1", &stamp(now, -29), 700)],
    );
    let account = |hash: char| SessionAccountEvidence {
        provider: "anthropic",
        account_identifier_hash: Some(hash.to_string().repeat(64)),
        provider_workspace_hash: None,
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "claude_desktop_original:v1",
        identity_disposition: Some("complete"),
        source_created_at: None,
    };
    first.session_account_evidence = Some(account('a'));
    second.session_account_evidence = Some(account('b'));
    let mut items = vec![first, second];
    let mut index = indexed(&[&path_a, &path_b], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    // Neither file borrows the other's numbers; both withhold the tuple.
    assert_cleared(&items[0]);
    assert_cleared(&items[1]);
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .withheld_multi_file_session_count,
        2
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn root_records_copied_under_a_subagent_path_are_not_exempt() {
    let dir = temp_dir("claude-file-birth-subagent-alias");
    let now = OffsetDateTime::now_utc();
    let child_dir = dir.join(ROOT).join("subagents");
    fs::create_dir_all(&child_dir).expect("create subagent dir");
    let path = child_dir.join("agent-a4d1585d310070d0f.jsonl");
    // An ordinary root transcript (no sidechain marker) placed where a
    // subagent file would live: the path keys it as a child, the records do
    // not, so the exemption does not apply.
    fs::write(
        &path,
        assistant(ROOT, "req_s1", &stamp(now, COPIED), 900_000),
    )
    .expect("write fixture");
    let parsed = parse(&path, now);
    assert!(parsed.claude_file_birth.is_subagent_for_test());
    let session_id = parsed.source_session_id.clone();
    let mut items = vec![parsed];
    let mut index = indexed(&[&path], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    assert_eq!(
        disposition.posture_admission(&session_id),
        Some("withheld_unknown_birth")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

/// The production loader keeps API rows of a root without a trace sidecar for
/// the veto only: a copied request that this root's own API sidecar reports
/// still withholds, through the real scan and local evidence pipeline.
#[test]
fn api_sidecar_without_trace_sidecar_still_vetoes() {
    let dir = temp_dir("claude-file-birth-api-only-pipeline");
    let now = OffsetDateTime::now_utc();
    root_session(
        &dir,
        SECOND,
        &[
            assistant(SECOND, "req_f0", &stamp(now, COPIED), 900_000),
            assistant(SECOND, "req_f1", &stamp(now, -30), 100),
        ],
    );
    let support = temp_dir("claude-file-birth-api-only-support");
    let digest = format!("{:x}", Sha256::digest(SECOND.as_bytes()));
    let path = support
        .join("local-otel")
        .join("claude-code-effort")
        .join(format!("{digest}.jsonl"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let row = complete_api_row(SECOND, "req_f0", 1, 900_000, 1, 0);
    fs::write(&path, serde_json::to_string(&row).unwrap() + "\n").unwrap();
    let transcript = dir.join(format!("{SECOND}.jsonl"));
    let run = |veto_rows: bool| {
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&dir),
            &mut index,
            "2026-08-02T07:10:00Z",
            7,
            100,
            false,
        )
        .unwrap();
        if !veto_rows {
            let _ = fs::remove_file(&path);
        }
        let (_, _, stats) = crate::snapshot_sync::apply_claude_local_evidence_to_scan_with_permit(
            &support, &mut scan, &mut index, None,
        );
        let item = scan
            .snapshots
            .into_iter()
            .find(|item| item.source_session_id == SECOND)
            .expect("fresh root body");
        (item, stats)
    };

    let (vetoed, stats) = run(true);
    assert_cleared(&vetoed);
    assert_eq!(
        stats
            .context_file_birth
            .total
            .withheld_tripwire_session_count,
        1
    );
    // Without the sidecar the same bytes stay withheld (F2: the veto is
    // remembered for this file version, whatever the next page loads).
    let (held, stats) = run(false);
    assert_cleared(&held);
    assert_eq!(
        stats
            .context_file_birth
            .total
            .withheld_tripwire_remembered_session_count,
        1
    );
    // Once the file grows (a new fingerprint), missing telemetry is not a
    // contradiction, so it is admitted.
    let mut grown = fs::read_to_string(&transcript).unwrap();
    grown.push_str(&assistant(SECOND, "req_f2", &stamp(now, -29), 300));
    fs::write(&transcript, grown).unwrap();
    let (admitted, stats) = run(false);
    assert_eq!(
        posture(&admitted),
        (Some(100), Some(300), Some(300), Some(0))
    );
    assert_eq!(
        stats.context_file_birth.total.file_birth_rule_session_count,
        1
    );
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(support);
}

#[test]
fn api_row_without_trace_row_counts_as_owned() {
    let dir = temp_dir("claude-file-birth-api-only");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    let mut items = vec![parsed];
    let mut index = indexed(&[&path], true);
    let evidence = reports(&[(ROOT, "req_a1", 1, 100), (ROOT, "req_a2", 2, 300)], false);

    let disposition = fold(&mut items, &evidence, &mut index, true);

    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(
        posture(&items[0]),
        (Some(100), Some(300), Some(300), Some(0))
    );
    assert_eq!(
        disposition
            .context_file_birth
            .total
            .telemetry_confirmed_session_count,
        1
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn telemetry_proven_session_keeps_todays_numbers() {
    let dir = temp_dir("claude-file-birth-parity");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
            boundary(ROOT, &stamp(now, -28), 310, 50),
            assistant(ROOT, "req_a3", &stamp(now, -27), 200),
        ],
    );
    let evidence = reports(
        &[
            (ROOT, "req_a1", 1, 100),
            (ROOT, "req_a2", 2, 300),
            (ROOT, "req_a3", 3, 200),
        ],
        true,
    );
    let run = |fence_closed: bool| {
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], fence_closed);
        let disposition = fold(&mut items, &evidence, &mut index, true);
        (disposition.posture_admission(ROOT), items.remove(0))
    };

    let (strict_admission, strict) = run(false);
    let (birth_admission, birth) = run(true);

    assert_eq!(strict_admission, Some("strict"));
    assert_eq!(birth_admission, Some("file_birth_rule"));
    assert_eq!(posture(&strict), (Some(100), Some(300), Some(200), Some(1)));
    assert_eq!(posture(&birth), posture(&strict));
    assert_eq!(birth.compaction_timestamps, strict.compaction_timestamps);
    assert_eq!(
        birth.compaction_total_pre_tokens,
        strict.compaction_total_pre_tokens
    );
    assert_eq!(
        birth.session_start.as_deref(),
        inherited_start(&strict).as_ref()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn id_less_responses_share_the_one_scalar_source() {
    let dir = temp_dir("claude-file-birth-id-less");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            id_less_assistant(ROOT, &stamp(now, -30), 500),
            assistant(ROOT, "req_a1", &stamp(now, -29), 100),
        ],
    );
    assert!(!parsed.claude_context_curve_identity_complete);
    let evidence = reports(&[(ROOT, "req_a1", 1, 100)], true);
    for fence_closed in [false, true] {
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], fence_closed);
        fold(&mut items, &evidence, &mut index, true);
        assert_eq!(
            posture(&items[0]),
            (Some(500), Some(500), Some(100), Some(0)),
            "fence_closed={fence_closed}"
        );
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn last_turn_alone_does_not_change_the_upload_fingerprint() {
    let dir = temp_dir("claude-file-birth-fingerprint");
    let now = OffsetDateTime::now_utc();
    let (_, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    let base = snapshot_fingerprint(SnapshotSource::ClaudeCode, &parsed);
    let mut last_moved = parsed.clone();
    last_moved.last_turn_context_tokens = Some(123);
    assert_eq!(
        snapshot_fingerprint(SnapshotSource::ClaudeCode, &last_moved),
        base,
        "a change in last alone does not upload"
    );
    let mut peak_moved = parsed;
    peak_moved.peak_context_fill_tokens = Some(301);
    assert_ne!(
        snapshot_fingerprint(SnapshotSource::ClaudeCode, &peak_moved),
        base
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn context_basis_counts_by_version_stay_bounded() {
    let dir = temp_dir("claude-file-birth-version-bound");
    let now = OffsetDateTime::now_utc();
    let mut items = Vec::new();
    let mut paths = Vec::new();
    for number in 0..20_u32 {
        let session = format!("d0000000-0000-4000-8000-{number:012}");
        let line = assistant(&session, &format!("req_{number}"), &stamp(now, -30), 100);
        let (path, mut item) = root_session(&dir, &session, &[line]);
        item.session_start = Some(Box::new(SnapshotSessionStart {
            client_version: Some(format!("2.1.{number}")),
            ..SnapshotSessionStart::default()
        }));
        paths.push(path);
        items.push(item);
    }
    let mut index = indexed(
        &paths.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
        true,
    );

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    let counts = &disposition.context_file_birth;
    assert_eq!(counts.total.file_birth_rule_session_count, 20);
    assert_eq!(
        counts.by_claude_code_version.len(),
        17,
        "sixteen versions + other"
    );
    assert_eq!(
        counts.by_claude_code_version["other"].file_birth_rule_session_count,
        4
    );
    let serialized = serde_json::to_vec(counts).expect("serialize counts");
    // Fixed fields times seventeen rows: bounded whatever the version mix.
    assert!(serialized.len() < 12_288, "{} bytes", serialized.len());
    let _ = fs::remove_dir_all(dir);
}

/// SI byte-identity check with request identity capture ON: through the real
/// scan and local evidence pipeline, the rule changes context scalars,
/// session start and the derived fingerprint only. Money, usage, identity,
/// contract 5 rows and account tags are byte-identical to the clear.
#[test]
fn capture_on_bodies_match_the_clear_outside_context_scalars() {
    use crate::snapshots::claude_request_identity as identity;
    let (dir, root, api, trace) = h296_root_evidence();
    let support = dir.join("support");
    let digest = format!("{:x}", Sha256::digest(root.source_session_id.as_bytes()));
    for (kind, rows) in [
        (
            "claude-code-effort",
            api.evidence[&root.source_session_id]
                .iter()
                .map(|row| serde_json::to_value(row).unwrap())
                .collect::<Vec<_>>(),
        ),
        (
            "claude-code-trace-ownership",
            trace.evidence[&root.source_session_id]
                .iter()
                .map(|row| serde_json::to_value(row).unwrap())
                .collect::<Vec<_>>(),
        ),
    ] {
        let path = support
            .join("local-otel")
            .join(kind)
            .join(format!("{digest}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            rows.iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    // A fresh root with a copied opening and a subagent, no telemetry: the
    // rule admits both; the clear withholds both.
    let now = OffsetDateTime::now_utc();
    root_session(
        &dir,
        SECOND,
        &[
            assistant(SECOND, "req_f0", &stamp(now, COPIED), 900_000),
            assistant(SECOND, "req_f1", &stamp(now, -30), 100),
            assistant(SECOND, "req_f2", &stamp(now, -29), 300),
        ],
    );
    let child_dir = dir.join(SECOND).join("subagents");
    fs::create_dir_all(&child_dir).unwrap();
    fs::write(
        child_dir.join("agent-b4d1585d310070d0f.jsonl"),
        subagent_assistant(SECOND, "b4d1585d310070d0f", "req_fs1", &stamp(now, -28)),
    )
    .unwrap();
    let claude = SnapshotSource::ClaudeCode;
    let permit = || identity::permit_when(true, claude, Some(identity::COHORT_HINT_TOKEN)).ok();
    assert!(permit().is_some(), "capture ON");
    let run = |rule_on: bool, fence_closed: bool| {
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots_with_test_limit(
            claude,
            std::slice::from_ref(&dir),
            &mut index,
            "2026-08-02T07:10:00Z",
            7,
            100,
            false,
        )
        .unwrap();
        index.claude_duplicate_request_witness_overflowed = fence_closed;
        let apply = |scan: &mut SourceScanResult, index: &mut ScanIndex| {
            crate::snapshot_sync::apply_claude_local_evidence_to_scan_with_permit(
                &support,
                scan,
                index,
                permit(),
            )
        };
        let (_, _, stats) = if rule_on {
            apply(&mut scan, &mut index)
        } else {
            claude_context_file_birth::with_file_birth_rule_disabled_for_test(|| {
                apply(&mut scan, &mut index)
            })
        };
        (scan.snapshots, stats)
    };

    for fence_closed in [false, true] {
        let (bodies, stats) = run(true, fence_closed);
        let (control, _) = run(false, fence_closed);

        assert_eq!(bodies.len(), control.len());
        if !fence_closed {
            let h296 = bodies
                .iter()
                .find(|item| item.source_session_id == root.source_session_id)
                .expect("h296 root body");
            assert_eq!(h296.provenance.collector, identity::COLLECTOR);
        }
        let mut changed = 0;
        for (body, control) in bodies.iter().zip(&control) {
            assert_eq!(body.source_session_id, control.source_session_id);
            let differing = differing_keys(body, control);
            assert!(
                differing.is_subset(&allowed_difference()),
                "fence_closed={fence_closed} {}: {differing:?}",
                body.source_session_id
            );
            changed += usize::from(!differing.is_empty());
        }
        assert!(changed >= 2, "the fresh root and its subagent are admitted");
        assert!(stats.context_file_birth.total.file_birth_rule_session_count >= 2);
        let fresh = bodies
            .iter()
            .find(|item| item.source_session_id == SECOND)
            .expect("fresh root body");
        assert_eq!(posture(fresh), (Some(100), Some(300), Some(300), Some(0)));
    }
    fs::remove_dir_all(dir).unwrap();
}
