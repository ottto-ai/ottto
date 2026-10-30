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
const CONTEXT_KEYS: [&str; 11] = [
    "compaction_count",
    "compaction_events",
    "compaction_timestamps",
    "compaction_total_cumulative_dropped_tokens",
    "compaction_total_duration_ms",
    "compaction_total_post_tokens",
    "compaction_total_pre_tokens",
    "first_own_request_at",
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
    assert!(item.compaction_events.is_empty());
    assert!(item.local_context_points.is_empty());
    assert_eq!(item.first_own_request_at, None);
}

/// Prompt sizes of the item's Mac-local points, oldest first.
fn point_sizes(item: &SnapshotItem) -> Vec<u32> {
    item.local_context_points
        .iter()
        .map(|point| point.prompt_tokens)
        .collect()
}

fn inherited_start(item: &SnapshotItem) -> Option<SnapshotSessionStart> {
    item.session_start
        .clone()
        .and_then(|start| (*start).inherited())
}

/// Serialized top-level keys whose values differ between two bodies.
fn differing_keys(left: &SnapshotItem, right: &SnapshotItem) -> BTreeSet<String> {
    if left.context_curve != right.context_curve {
        // The E-on/control comparison may change only the unavailable reason,
        // never introduce curve evidence alongside the admitted scalars.
        assert_eq!(
            left.claude_file_birth_verdict(),
            Some(ClaudeFileBirthVerdict::Admitted)
        );
        for (item, coverage) in [
            (left, "scalars_file_birth_only"),
            (right, "ownership_unresolved"),
        ] {
            assert_eq!(
                item.context_curve,
                Some(unavailable_context_curve(
                    CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
                    CLAUDE_CONTEXT_CURVE_OWNERSHIP_REVISION,
                    coverage,
                    0,
                    0,
                ))
            );
        }
    }
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
        .chain(&["session_start", "snapshot_fingerprint", "context_curve"])
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
    assert_eq!(item.compaction_timestamps, vec![own_boundary.clone()]);
    assert_eq!(item.compaction_total_pre_tokens, Some(310));
    assert_eq!(item.compaction_total_post_tokens, Some(50));
    // Sizes come from own requests only: the copied boundaries have no
    // event, and the copied request between req_a3 and req_a4 is never a size.
    assert_eq!(
        item.compaction_events,
        vec![SnapshotCompactionEvent {
            at: own_boundary.clone(),
            before: Some(300),
            after: Some(200),
            trigger: Some("auto".to_string()),
        }]
    );
    // Local points: the same own requests as first/peak/last.
    let points = point_sizes(&item);
    assert_eq!(points.first(), Some(&100));
    assert_eq!(points.last(), Some(&150));
    assert!(points.iter().all(|size| *size <= 300), "{points:?}");
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

/// RFC 3339 at `offset_millis` from the file's own birth, so which side of
/// the 60 s copy line a record falls on does not depend on test timing.
fn from_birth(birth: i128, offset_millis: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(birth + i128::from(offset_millis) * 1_000_000)
        .expect("fixture timestamp")
        .format(&Rfc3339)
        .expect("format fixture timestamp")
}

fn uuid_boundary(timestamp: &str, uuid: &str, pre: u64, post: u64) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"uuid\":\"{uuid}\",\"parentUuid\":null,\"sessionId\":\"{ROOT}\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{{\"trigger\":\"auto\",\"preTokens\":{pre},\"postTokens\":{post}}}}}\n"
    )
}

fn compaction_attachment(timestamp: &str, uuid: &str, parent: &str) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"uuid\":\"{uuid}\",\"parentUuid\":\"{parent}\",\"sessionId\":\"{ROOT}\",\"type\":\"attachment\"}}\n"
    )
}

/// A legacy compaction summary; `parent: None` names no `parentUuid`.
fn compaction_summary(timestamp: &str, uuid: &str, parent: Option<&str>) -> String {
    let parent = parent.map_or("null".to_string(), |parent| format!("\"{parent}\""));
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"uuid\":\"{uuid}\",\"parentUuid\":{parent},\"sessionId\":\"{ROOT}\",\"type\":\"user\",\"isCompactSummary\":true,\"isVisibleInTranscriptOnly\":true,\"message\":{{\"role\":\"user\",\"content\":\"summary\"}}}}\n"
    )
}

/// Pair ambiguity on the #676-integrated head: the birth filter drops records
/// one by one, then #676 pairs what is left (by `parentUuid` chain, else by a
/// 2 s window for a summary naming no parent). No compaction counts twice, and
/// a copied half never lends an owned half its metrics or its partner.
#[test]
fn compaction_pairs_across_the_copy_line_count_once() {
    let dir = temp_dir("claude-file-birth-pair-ambiguity");
    let path = dir.join(format!("{ROOT}.jsonl"));
    fs::write(&path, "").expect("create transcript fixture");
    let birth = fs::metadata(&path)
        .ok()
        .and_then(|metadata| metadata.created().ok())
        .and_then(system_time_unix_nanos_i128)
        .expect("the test file system must report file birth");
    let at = |offset_millis| from_birth(birth, offset_millis);
    let lines = [
        assistant(ROOT, "req_c1", &at(-2 * 24 * 60 * 60 * 1_000), 900_000),
        // 1. A linked pair split by the copy line before the first own
        //    request: copied boundary, summary 2 s later on the owned side.
        uuid_boundary(&at(-61_000), "bnd-line", 900_010, 90_000),
        compaction_attachment(&at(-60_900), "att-line", "bnd-line"),
        compaction_summary(&at(-59_000), "sum-line", Some("att-line")),
        assistant(ROOT, "req_a1", &at(-50_000), 100),
        // 2. The same split after own requests: the copied boundary leaves,
        //    the linked owned summary stays as one event without metrics.
        uuid_boundary(&at(-61_500), "bnd-late", 990_000, 99_000),
        compaction_attachment(&at(-61_400), "att-late", "bnd-late"),
        compaction_summary(&at(-58_000), "sum-late", Some("att-late")),
        assistant(ROOT, "req_a2", &at(-40_000), 300),
        // 3. An owned boundary and an owned summary naming no parent, 1 s
        //    apart: the time window pairs them.
        uuid_boundary(&at(-30_000), "bnd-own", 310, 50),
        compaction_summary(&at(-29_000), "sum-own", None),
        // 4. An owned boundary 1.5 s after a copied summary naming no
        //    parent: paired before the filter, the boundary alone after it.
        uuid_boundary(&at(-59_000), "bnd-near", 410, 60),
        compaction_summary(&at(-60_500), "sum-near", None),
        assistant(ROOT, "req_a3", &at(-20_000), 200),
    ];
    // Truncating rewrite of the same file: the birth read above stays.
    fs::write(&path, lines.concat()).expect("write transcript fixture");
    let parsed = parse(&path, OffsetDateTime::now_utc());
    assert!(parsed.claude_file_birth.is_root_with_birth_for_test());
    // Today's parser: two linked pairs plus two time-window pairs.
    assert_eq!(parsed.compaction_count, Some(4));

    let mut items = vec![parsed.clone()];
    let mut index = indexed(&[&path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    let item = items.remove(0);
    let mut control = vec![parsed.clone()];
    let mut control_index = indexed(&[&path], true);
    let _ = claude_context_file_birth::with_file_birth_rule_disabled_for_test(|| {
        fold(&mut control, &no_reports(), &mut control_index, true)
    });

    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(posture(&item), (Some(100), Some(300), Some(200), Some(3)));
    let mut timestamps = item.compaction_timestamps.clone();
    timestamps.sort();
    let mut expected = vec![at(-59_000), at(-58_000), at(-30_000)];
    expected.sort();
    assert_eq!(
        timestamps, expected,
        "bnd-near, sum-late and bnd-own; never a copied record or sum-own"
    );
    assert_eq!(item.compaction_total_pre_tokens, Some(310 + 410));
    assert_eq!(item.compaction_total_post_tokens, Some(50 + 60));
    let counts = &disposition.context_file_birth.total;
    assert_eq!(
        counts.tagged_record_count, 4,
        "1 response + 2 boundaries + 1 summary"
    );
    assert_eq!(counts.partially_pre_birth_session_count, 1);
    assert_cleared(&control[0]);
    let differing = differing_keys(&item, &control[0]);
    assert!(differing.is_subset(&allowed_difference()), "{differing:?}");
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
    assert_eq!(items[0].session_start, parsed.session_start, "full split");

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
    assert_eq!(items[0].session_start, grown.session_start);
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
    assert_eq!(items[0].session_start, parsed.session_start, "own split");
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
        let (_, _, stats) = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
            &support, &mut scan, &mut index,
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
    // Legacy reported-usage body/authority assertions; E2 emits request-owned grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
    assert_eq!(birth.session_start, strict.session_start);
    // Both writers build sizes and points through one helper: same values.
    assert_eq!(
        strict.compaction_events,
        vec![SnapshotCompactionEvent {
            at: stamp(now, -28),
            before: Some(300),
            after: Some(200),
            trigger: Some("auto".to_string()),
        }]
    );
    assert_eq!(birth.compaction_events, strict.compaction_events);
    assert!(!strict.local_context_points.is_empty());
    assert_eq!(birth.local_context_points, strict.local_context_points);
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
/// session start, the unavailable curve reason and the derived fingerprint
/// only. Money, usage, identity,
/// contract 5 rows and account tags are byte-identical to the clear.
#[test]
fn capture_on_bodies_match_the_clear_outside_context_scalars() {
    // Legacy reported-usage body/authority assertions; E2 emits request-owned grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(&support, scan, index)
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

// ---- Session start (addendum 4) -------------------------------------------
// One classification feeds the scalars and the split: the split is kept only
// when the scalar tuple is admitted and nothing copied sits in the opening
// window, and it comes from the same occurrence as first.

/// The request-1 split total, when the split was kept.
fn split_total(item: &SnapshotItem) -> Option<u64> {
    let start = item.session_start.as_deref()?;
    Some(
        start.first_request_uncached_input_tokens?
            + start.first_request_cache_read_tokens.unwrap_or(0)
            + start.first_request_cache_write_5m_tokens.unwrap_or(0)
            + start.first_request_cache_write_1h_tokens.unwrap_or(0),
    )
}

#[test]
fn session_start_split_follows_the_scalar_classification() {
    let dir = temp_dir("claude-file-birth-session-start");
    let now = OffsetDateTime::now_utc();
    let own = |session: &str, request: &str, offset: i64, tokens: u64| {
        assistant(session, request, &stamp(now, offset), tokens)
    };
    let copied =
        |session: &str, request: &str| assistant(session, request, &stamp(now, COPIED), 900_000);
    // (label, session, lines, telemetry owner of the first request, forget
    // birth, verdict, first, full split kept)
    let session = |number: u64| format!("e0000000-0000-4000-8000-{number:012}");
    let cases = [
        (
            "fresh root, fence closed",
            session(1),
            vec![
                own(&session(1), "req_1a", -30, 100),
                own(&session(1), "req_1b", -29, 300),
            ],
            None,
            false,
            "file_birth_rule",
            Some(100),
            true,
        ),
        (
            "copied opening",
            session(2),
            vec![
                copied(&session(2), "req_2c"),
                own(&session(2), "req_2a", -30, 100),
                own(&session(2), "req_2b", -29, 300),
            ],
            None,
            false,
            "file_birth_rule",
            Some(100),
            false,
        ),
        (
            "later copied block keeps the owned opening",
            session(3),
            vec![
                own(&session(3), "req_3a", -30, 100),
                own(&session(3), "req_3b", -29, 200),
                own(&session(3), "req_3c", -28, 300),
                copied(&session(3), "req_3x"),
                own(&session(3), "req_3d", -27, 400),
            ],
            None,
            false,
            "file_birth_rule",
            Some(100),
            true,
        ),
        (
            "id-less first occurrence",
            session(4),
            vec![
                id_less_assistant(&session(4), &stamp(now, -30), 50),
                own(&session(4), "req_4a", -29, 100),
            ],
            None,
            false,
            "file_birth_rule",
            Some(50),
            true,
        ),
        (
            "contradicting telemetry",
            session(5),
            vec![
                own(&session(5), "req_5a", -30, 100),
                own(&session(5), "req_5b", -29, 300),
            ],
            Some((OTHER_ROOT, "req_5a")),
            false,
            "withheld_tripwire",
            None,
            false,
        ),
        (
            "unknown birth",
            session(6),
            vec![own(&session(6), "req_6a", -30, 100)],
            None,
            true,
            "withheld_unknown_birth",
            None,
            false,
        ),
    ];
    for (label, session_id, lines, owner, forget, verdict, first, full_split) in cases {
        let (path, mut parsed) = root_session(&dir, &session_id, &lines);
        if forget {
            parsed.claude_file_birth.forget_birth_for_test();
        }
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], true);
        let evidence = match owner {
            Some((root, request)) => reports(&[(root, request, 1, 100)], true),
            None => no_reports(),
        };
        let disposition = fold(&mut items, &evidence, &mut index, true);
        let item = &items[0];
        assert_eq!(
            disposition.posture_admission(&session_id),
            Some(verdict),
            "{label}"
        );
        assert_eq!(item.first_turn_context_tokens, first, "{label}");
        if full_split {
            assert_eq!(item.session_start, parsed.session_start, "{label}");
            assert_eq!(split_total(item), first, "{label}: split sums to first");
        } else {
            assert_eq!(
                item.session_start.as_deref().cloned(),
                inherited_start(&parsed),
                "{label}: version only"
            );
            assert_eq!(split_total(item), None, "{label}");
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// The per-file start verdict reads the folded item, so it matches the start
/// the snapshot uploads: a fresh root and a subagent file keep a measured
/// start, a copied opening keeps the version only.
#[test]
fn start_verdict_matches_the_folded_session_start() {
    let dir = temp_dir("claude-file-birth-start-verdict");
    let now = OffsetDateTime::now_utc();
    let fresh = "e1000000-0000-4000-8000-000000000001";
    let copied = "e1000000-0000-4000-8000-000000000002";
    let agent = "a4d1585d310070d0e";
    let child_dir = dir.join(ROOT).join("subagents");
    fs::create_dir_all(&child_dir).expect("create subagent dir");
    let child = child_dir.join(format!("agent-{agent}.jsonl"));
    fs::write(
        &child,
        subagent_assistant(ROOT, agent, "req_s1", &stamp(now, -30)),
    )
    .expect("write subagent fixture");
    let (fresh_path, fresh_item) = root_session(
        &dir,
        fresh,
        &[
            assistant(fresh, "req_f1", &stamp(now, -30), 100),
            assistant(fresh, "req_f2", &stamp(now, -29), 300),
        ],
    );
    let (copied_path, copied_item) = root_session(
        &dir,
        copied,
        &[
            assistant(copied, "req_c0", &stamp(now, COPIED), 900_000),
            assistant(copied, "req_c1", &stamp(now, -30), 100),
            assistant(copied, "req_c2", &stamp(now, -29), 300),
        ],
    );
    let cases = [
        ("fresh root", fresh_path, fresh_item, StartVerdict::Measured),
        // Measured before the fold; the fold keeps the version only.
        (
            "copied opening",
            copied_path,
            copied_item,
            StartVerdict::NotMeasured,
        ),
        (
            "subagent",
            child.clone(),
            parse(&child, now),
            StartVerdict::Measured,
        ),
    ];
    for (label, path, parsed, expected) in cases {
        assert_eq!(
            session_start_verdict(&parsed),
            StartVerdict::Measured,
            "{label}: parsed"
        );
        let mut items = vec![parsed];
        let mut index = indexed(&[&path], true);
        fold(&mut items, &no_reports(), &mut index, true);
        assert_eq!(
            session_start::uploaded_start_verdict(&items[0]),
            expected,
            "{label}: uploaded body"
        );
        assert_eq!(session_start_verdict(&items[0]), expected, "{label}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// One native read: reuse `old` when the reader accepts it, retain, finish.
fn native_read(
    path: &Path,
    old: Option<
        crate::transcript_cache::Retained<crate::snapshots::sampled_jsonl::CachedJsonlReduction>,
    >,
    now: u64,
    collected_at: &str,
) -> (
    Option<
        crate::transcript_cache::Retained<crate::snapshots::sampled_jsonl::CachedJsonlReduction>,
    >,
    crate::transcript_acquisition::ReadMode,
    SnapshotItem,
) {
    let scope = crate::transcript_acquisition::Scope("file-birth-tail".into());
    let mut file = fs::File::open(path).expect("open fixture");
    let expected = opened_object_identity(SnapshotSource::ClaudeCode, &mut file).expect("identity");
    let mut parser = OwnedJsonlParser::new(
        file,
        path,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        Some(&CodexTitleMetadata::default()),
        None,
        None,
        false,
        true,
    )
    .expect("parser");
    let debt = old.as_ref().and_then(|old| old.checkpoint.audit_debt());
    let mode = parser
        .prepare_acquisition(old, &scope, debt, now)
        .expect("prepare");
    while !parser.step().expect("step") {}
    let acquisition = parser
        .retain_reduction(&scope, now, sampled_scan::RetainBudget::granted_unclassified(crate::transcript_cache::ENTRY_BYTES))
        .expect("retain")
        .expect("retained");
    let retained = acquisition
        .reduction
        .map(|state| crate::transcript_cache::Retained {
            checkpoint: acquisition.checkpoint,
            state,
        });
    let parsed = parser
        .finish(
            &expected,
            path,
            collected_at,
            "file-birth-fp".into(),
            Some(&CodexTitleMetadata::default()),
            Some(&ClaudeTitleMetadata::default()),
            None,
        )
        .expect("finish");
    let item = parsed.snapshots.into_iter().next().expect("snapshot");
    (retained, mode, item)
}

/// The tail path and a full read select the same first request, so the
/// scalars and the split agree at every append boundary.
#[test]
fn tail_and_full_read_select_the_same_first_request() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = temp_dir("claude-file-birth-tail");
    fs::create_dir_all(&dir).expect("create project dir");
    let now = OffsetDateTime::now_utc();
    let collected_at = stamp(now, 0);
    let rows = [
        id_less_assistant(ROOT, &stamp(now, -10), 50),
        assistant(ROOT, "req_a1", &stamp(now, -9), 100),
        assistant(ROOT, "req_a2", &stamp(now, -8), 300),
        assistant(ROOT, "req_c0", &stamp(now, COPIED), 900_000),
        assistant(ROOT, "req_a3", &stamp(now, -7), 200),
    ];
    let path = dir.join(format!("{ROOT}.jsonl"));
    for split in 1..rows.len() {
        let _ = fs::remove_file(&path);
        fs::write(&path, rows[..split].concat()).expect("write prefix");
        let (retained, _, _) = native_read(&path, None, 100, &collected_at);
        assert!(retained.is_some(), "split {split}: prefix retained");
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        std::io::Write::write_all(&mut file, rows[split..].concat().as_bytes())
            .expect("append rest");
        drop(file);
        let (_, mode, tailed) = native_read(&path, retained, 101, &collected_at);
        assert_eq!(
            mode,
            crate::transcript_acquisition::ReadMode::Tail,
            "split {split}"
        );
        let (_, _, full) = native_read(&path, None, 102, &collected_at);
        assert_eq!(
            tailed.claude_file_birth, full.claude_file_birth,
            "split {split}"
        );
        let mut folded = Vec::new();
        for item in [tailed, full] {
            let mut items = vec![item];
            let mut index = indexed(&[&path], true);
            let disposition = fold(&mut items, &no_reports(), &mut index, true);
            assert_eq!(
                disposition.posture_admission(ROOT),
                Some("file_birth_rule"),
                "split {split}"
            );
            folded.push(items.remove(0));
        }
        assert_eq!(posture(&folded[0]), posture(&folded[1]), "split {split}");
        assert_eq!(
            posture(&folded[0]),
            (Some(50), Some(300), Some(200), Some(0))
        );
        assert_eq!(
            folded[0].session_start, folded[1].session_start,
            "split {split}"
        );
        assert_eq!(split_total(&folded[0]), Some(50), "split {split}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// #677 stop latch (SOURCE Amendments 7 and 10): the first Claude fold that
/// withholds for a resource limit stops the one-time re-read until the daemon
/// restarts; a later clean fold does not resume it. The evidence-bound trigger
/// uses the merged seam; the full remembered-veto table triggers it too.
#[test]
fn claude_backfill_stop_latches_until_restart() {
    let dir = temp_dir("claude-file-birth-backfill-stop");
    let now = OffsetDateTime::now_utc();
    let files = five_request_roots(&dir, now, &[ROOT, SECOND]);
    let paths = [files[0].0.as_path()];
    let rows = own_rows(&[ROOT], &[]);
    let is_stop_alarm = |record: &serde_json::Value| {
        record["stage"]
            .as_str()
            .is_some_and(|stage| stage.starts_with("claude_reemission_stop_latched"))
    };
    let fold_pass = || {
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
        let alarms = records
            .into_iter()
            .filter(is_stop_alarm)
            .collect::<Vec<_>>();
        (disposition, alarms)
    };
    let (home, transcripts, backfill) =
        claude_context_backfill_fixture("claude-file-birth-backfill-stop-history", 1);
    let adoption_page = || {
        let mut index = backfill.clone();
        let scan =
            claude_context_backfill_scan(&transcripts, &mut index, MAX_BACKFILL_FILES_PER_SOURCE);
        assert!(scan.census_complete, "a stop never holds the census");
        scan.scanned_file_count
    };

    let (clean, alarms) = fold_pass();
    assert!(!clean.context_file_birth.resource_withheld());
    assert!(alarms.is_empty());
    assert!(!claude_reemission_stop_latched());
    assert_eq!(adoption_page(), 2, "the root and its subagent adopt");

    // Evidence bound: the seam puts ROOT's five requests over a bound of 4.
    let (withheld, alarms) =
        claude_context_file_birth::with_claude_evidence_bound_for_test(4, fold_pass);
    assert_eq!(
        withheld.posture_admission(ROOT),
        Some("withheld_evidence_bound")
    );
    assert!(withheld.context_file_birth.resource_withheld());
    assert!(claude_reemission_stop_latched());
    assert_eq!(alarms.len(), 1, "one alarm when the latch sets");
    assert_eq!(alarms[0]["stage"], "claude_reemission_stop_latched");
    assert_eq!(alarms[0]["source"], "claude_code");
    let counts = &alarms[0]["counts"];
    assert_eq!(counts["withheld_evidence_bound_session_count"], 1);
    assert_eq!(counts["remembered_veto_overflowed"], false);
    assert_eq!(counts["withheld_folds"], 1);
    assert_eq!(counts["over_bound_root_count"], 1);
    let root_ref = format!("{:x}", Sha256::digest(ROOT.as_bytes()))[..16].to_string();
    assert_eq!(counts["over_bound_root_refs"], json!([root_ref]));
    assert!(!alarms[0].to_string().contains(ROOT), "no raw id");
    assert_eq!(adoption_page(), 0, "budget 0 once latched");

    // A clean fold keeps the stop and does not repeat the alarm.
    let (clean, alarms) = fold_pass();
    assert!(!clean.context_file_birth.resource_withheld());
    assert!(alarms.is_empty(), "no repeat within the hour");
    assert!(claude_reemission_stop_latched());
    assert_eq!(adoption_page(), 0, "a clean fold does not resume");
    assert_eq!(claude_reemission_stop_withheld_folds(), 1);

    // A restart is the only reset.
    restart_claude_reemission_stop_for_test();
    assert!(!claude_reemission_stop_latched());
    assert_eq!(adoption_page(), 2);

    // A full remembered-veto table latches it too: a capacity-1 table that
    // already holds another file overflows on the next veto.
    let item = files[0].1.clone();
    let mut memory = claude_context_file_birth::ClaudeRememberedTripwire::new(1);
    memory.remember(&files[1].1);
    memory.remember(&item);
    let reports = no_reports();
    let veto_rows = ClaudeVetoApiRows::new();
    let tripwire = claude_context_file_birth::ClaudeTelemetryTripwire::build(
        std::slice::from_ref(&item),
        1_000,
        &reports.0,
        &reports.1,
        &veto_rows,
    );
    let mut counts = ClaudeContextFileBirthCounts::default();
    let verdict = claude_context_file_birth::admit_claude_file_birth_posture(
        &mut item.clone(),
        ROOT,
        &tripwire,
        &mut memory,
        false,
        &mut counts,
    );
    assert_eq!(verdict, ClaudeFileBirthVerdict::Tripwire);
    assert!(counts.remembered_veto_overflowed);
    assert_eq!(counts.total.withheld_evidence_bound_session_count, 0);
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        note_claude_reemission_stop(&counts, tripwire.over_bound_roots())
    });
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0]["counts"]["remembered_veto_overflowed"], true);
    assert_eq!(alarms[0]["counts"]["over_bound_root_count"], 0);
    assert!(claude_reemission_stop_latched());
    assert_eq!(adoption_page(), 0, "veto overflow stops adoption");
    note_claude_reemission_stop(&ClaudeContextFileBirthCounts::default(), &BTreeSet::new());
    assert_eq!(adoption_page(), 0);
    let _ = (fs::remove_dir_all(dir), fs::remove_dir_all(home));
}

/// While latched, the alarm repeats at most once an hour, whatever the folds.
#[test]
fn claude_backfill_stop_reminder_is_at_most_hourly() {
    let withheld = ClaudeContextFileBirthCounts {
        remembered_veto_overflowed: true,
        ..Default::default()
    };
    let clean = ClaudeContextFileBirthCounts::default();
    let roots = BTreeSet::new();
    let start = std::time::Instant::now();
    let stages = |counts: &ClaudeContextFileBirthCounts, minutes: u64| {
        let ((), records) = crate::local_resource_diagnostics::capture(|| {
            note_claude_reemission_stop_at(
                counts,
                &roots,
                start + std::time::Duration::from_secs(minutes * 60),
            )
        });
        records
            .iter()
            .map(|record| record["stage"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
    };
    assert!(stages(&clean, 0).is_empty(), "a clean fold never latches");
    assert_eq!(stages(&withheld, 1), ["claude_reemission_stop_latched"]);
    assert!(stages(&withheld, 2).is_empty());
    assert!(stages(&clean, 60).is_empty(), "59 minutes since the alarm");
    assert_eq!(
        stages(&clean, 61),
        ["claude_reemission_stop_latched_reminder"]
    );
    assert!(stages(&withheld, 90).is_empty());
    assert_eq!(
        stages(&clean, 121),
        ["claude_reemission_stop_latched_reminder"]
    );
    assert_eq!(claude_reemission_stop_withheld_folds(), 3);
    assert!(claude_reemission_stop_latched());
    restart_claude_reemission_stop_for_test();
    assert!(!claude_reemission_stop_latched());
    assert_eq!(claude_reemission_stop_withheld_folds(), 0);
}

/// Exercise the daemon's real load boundary, including quarantine, rather
/// than directly setting the stop. NewFile reads still run while adoption of
/// a different destination's existing history is stopped process-wide.
#[test]
fn claude_backfill_index_rebuild_load_latches_until_restart() {
    for kind in ["absent", "corrupt", "empty"] {
        for missing_list in [false, true] {
            restart_claude_reemission_stop_for_test();
            let (home, root, baseline) =
                claude_context_backfill_fixture("claude-index-rebuild-stop", 1);
            let support = home.join("support");
            let list = ReemissionExclusions::path(&support);
            fs::create_dir_all(list.parent().unwrap()).unwrap();
            fs::write(&list, "").unwrap();
            assert_eq!(
                ReemissionExclusions::load(&support).state(),
                ListState::Installed
            );
            if missing_list {
                fs::remove_file(&list).unwrap();
            }
            let path = home.join("rebuild-index.json");
            match kind {
                "corrupt" => fs::write(&path, "{truncated").unwrap(),
                "empty" => {
                    fs::write(&path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap()
                }
                _ => {}
            }
            let (loaded, alarms) = crate::local_resource_diagnostics::capture(|| {
                ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &support)
                    .unwrap()
            });
            let mut loaded = loaded;
            assert!(loaded.files.is_empty());
            assert_eq!(loaded.generation, 0);
            if kind == "corrupt" {
                assert!(!path.exists(), "the corrupt file was quarantined");
                assert!(fs::read_dir(&home).unwrap().flatten().any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("rebuild-index.corrupt.")));
            }
            assert!(claude_reemission_stop_latched());
            assert_eq!(claude_reemission_stop_reason(), "index_rebuild_withheld");
            assert_eq!(alarms.len(), 1);
            assert_eq!(alarms[0]["stage"], "claude_reemission_stop_latched");
            assert_eq!(alarms[0]["counts"]["cause"], "index_rebuild");
            assert_eq!(alarms[0]["counts"]["withheld_folds"], 0);
            assert_eq!(alarms[0]["counts"]["over_bound_root_refs"], json!([]));
            let new_files =
                claude_context_backfill_scan(&root, &mut loaded, MAX_BACKFILL_FILES_PER_SOURCE);
            assert_eq!(new_files.scanned_file_count, 2, "NewFile is unchanged");
            let mut adoption = baseline.clone();
            assert_eq!(
                claude_context_backfill_scan(&root, &mut adoption, MAX_BACKFILL_FILES_PER_SOURCE)
                    .scanned_file_count,
                0,
                "adoption in another destination is stopped"
            );
            let clean = ClaudeContextFileBirthCounts::default();
            let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
                note_claude_reemission_stop(&clean, &BTreeSet::new());
                ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &support)
                    .unwrap();
            });
            assert!(
                alarms.is_empty(),
                "clean folds and loads do not repeat the alarm"
            );
            assert_eq!(claude_reemission_stop_reason(), "index_rebuild_withheld");
            let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
                note_claude_reemission_stop_at(
                    &clean,
                    &BTreeSet::new(),
                    std::time::Instant::now() + CLAUDE_REEMISSION_STOP_REMINDER_INTERVAL,
                );
            });
            assert_eq!(alarms.len(), 1);
            assert_eq!(
                alarms[0]["stage"],
                "claude_reemission_stop_latched_reminder"
            );
            assert_eq!(alarms[0]["counts"]["cause"], "index_rebuild");
            restart_claude_reemission_stop_for_test();
            assert_eq!(claude_reemission_stop_reason(), "none");
            let mut adoption = baseline;
            assert_eq!(
                claude_context_backfill_scan(&root, &mut adoption, MAX_BACKFILL_FILES_PER_SOURCE)
                    .scanned_file_count,
                2,
                "restart resets adoption; a still-empty load will latch again"
            );
            let _ = fs::remove_dir_all(home);
        }
    }
}

#[test]
fn claude_backfill_index_load_without_seen_marker_does_not_latch() {
    let home = temp_dir("claude-index-rebuild-not-active");
    for corrupt in [false, true] {
        let path = home.join("scan-index.json");
        if corrupt {
            fs::write(&path, "{truncated").unwrap();
        }
        ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &home).unwrap();
        assert!(!claude_reemission_stop_latched());
        assert_eq!(claude_reemission_stop_reason(), "none");
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn claude_backfill_index_load_preserves_other_sources_and_existing_indexes() {
    let (home, _, mut baseline) =
        claude_context_backfill_fixture("claude-index-rebuild-source-guard", 1);
    let marker = ReemissionExclusions::seen_marker_path(&home);
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    fs::write(marker, "").unwrap();
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        // Production sources own separate checkpoints and rebuild budgets.
        let path = home.join(format!("other-{}-index.json", source.api_slug()));
        ScanIndex::load_for_snapshot_source(&path, source, &home).unwrap();
        assert!(!claude_reemission_stop_latched());
        fs::write(&path, "{truncated").unwrap();
        ScanIndex::load_for_snapshot_source(&path, source, &home).unwrap();
        assert!(!claude_reemission_stop_latched());
    }
    // Both conditions matter: a populated generation-0 index and an empty
    // saved index with a nonzero generation must not be treated as fresh.
    let path = home.join("existing-index.json");
    baseline.generation = 0;
    fs::write(&path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &home).unwrap();
    assert!(!claude_reemission_stop_latched());
    baseline.files.clear();
    baseline.generation = 1;
    fs::write(&path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &home).unwrap();
    assert!(!claude_reemission_stop_latched());
    let _ = fs::remove_dir_all(home);
}

// ---- Compaction sizes and local points (daemon 5b) --------------------------

#[test]
fn withheld_item_clears_sizes_and_points_with_the_tuple() {
    let dir = temp_dir("claude-file-birth-sizes-withheld");
    let now = OffsetDateTime::now_utc();
    let (path, mut parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            boundary(ROOT, &stamp(now, -29), 110, 50),
            assistant(ROOT, "req_a2", &stamp(now, -28), 200),
        ],
    );
    parsed.claude_file_birth.forget_birth_for_test();
    // Stale values from an earlier pass must not survive a withhold.
    parsed.compaction_events = vec![SnapshotCompactionEvent {
        at: stamp(now, -29),
        before: Some(100),
        after: Some(200),
        trigger: None,
    }];
    parsed.local_context_points = vec![LocalContextPoint {
        at_unix_seconds: 1,
        prompt_tokens: 100,
    }];
    let mut items = vec![parsed];
    let mut index = indexed(&[&path], true);

    let disposition = fold(&mut items, &no_reports(), &mut index, true);

    assert_eq!(
        disposition.posture_admission(ROOT),
        Some("withheld_unknown_birth")
    );
    assert_cleared(&items[0]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn incomplete_identity_ships_sizes_from_the_own_set() {
    let dir = temp_dir("claude-file-birth-sizes-id-less");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            id_less_assistant(ROOT, &stamp(now, -31), 500),
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            boundary(ROOT, &stamp(now, -29), 110, 50),
            assistant(ROOT, "req_a2", &stamp(now, -28), 200),
        ],
    );
    assert!(!parsed.claude_context_curve_identity_complete);
    let evidence = reports(&[(ROOT, "req_a1", 1, 100), (ROOT, "req_a2", 2, 200)], true);
    for fence_closed in [false, true] {
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], fence_closed);
        let disposition = fold(&mut items, &evidence, &mut index, true);
        let item = &items[0];
        // The id-less response is not next to the compaction.
        let counts = &disposition.context_file_birth;
        assert_eq!(counts.id_less_response_before_compaction_count, 0);
        assert_eq!(counts.id_less_response_after_compaction_count, 0);
        // Strict with incomplete identity and file birth both ship the
        // own-only tuple, so both ship own-only sizes and points.
        assert_eq!(
            item.compaction_events,
            vec![SnapshotCompactionEvent {
                at: stamp(now, -29),
                before: Some(100),
                after: Some(200),
                trigger: Some("auto".to_string()),
            }],
            "fence_closed={fence_closed}"
        );
        // An id-less response has no occurrence, so it is never a size or a
        // point (first/peak still read it).
        assert_eq!(
            point_sizes(item),
            vec![100, 200],
            "fence_closed={fence_closed}"
        );
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn id_less_neighbours_of_a_compaction_are_counted_locally() {
    let dir = temp_dir("claude-file-birth-sizes-id-less-neighbours");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            // The responses just before and just after the compaction have no
            // request id: never a size, so before and after skip them.
            id_less_assistant(ROOT, &stamp(now, -29), 150),
            boundary(ROOT, &stamp(now, -28), 160, 50),
            id_less_assistant(ROOT, &stamp(now, -27), 60)
                .replace("msg_id_less", "msg_id_less_after"),
            assistant(ROOT, "req_a2", &stamp(now, -26), 200),
        ],
    );
    assert!(!parsed.claude_context_curve_identity_complete);
    let evidence = reports(&[(ROOT, "req_a1", 1, 100), (ROOT, "req_a2", 2, 200)], true);
    for fence_closed in [false, true] {
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], fence_closed);
        let disposition = fold(&mut items, &evidence, &mut index, true);
        assert_eq!(
            items[0].compaction_events,
            vec![SnapshotCompactionEvent {
                at: stamp(now, -28),
                before: Some(100),
                after: Some(200),
                trigger: Some("auto".to_string()),
            }],
            "fence_closed={fence_closed}"
        );
        // Counted on the local basis-counts line only; the wire is unchanged.
        let counts = &disposition.context_file_birth;
        assert_eq!(
            (
                counts.id_less_response_before_compaction_count,
                counts.id_less_response_after_compaction_count
            ),
            (1, 1),
            "fence_closed={fence_closed}"
        );
        let wire = serde_json::to_value(&items[0]).unwrap();
        assert!(!wire.to_string().contains("id_less"));
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn id_less_neighbours_mark_every_matching_cut_only() {
    let dir = temp_dir("claude-file-birth-id-less-repeated-cuts");
    let now = OffsetDateTime::now_utc();
    let (_, parsed) = root_session(
        &dir,
        ROOT,
        &[
            boundary(ROOT, &stamp(now, -40), 200, 50),
            assistant(ROOT, "req_a1", &stamp(now, -39), 100),
            assistant(ROOT, "req_a2", &stamp(now, -38), 120),
            boundary(ROOT, &stamp(now, -37), 160, 50),
            id_less_assistant(ROOT, &stamp(now, -36), 150),
            boundary(ROOT, &stamp(now, -34), 160, 50),
            // Same cut, out-of-order timestamp: both markers must be marked.
            boundary(ROOT, &stamp(now, -35), 160, 50),
            assistant(ROOT, "req_a3", &stamp(now, -33), 200),
            assistant(ROOT, "req_a4", &stamp(now, -32), 220),
            boundary(ROOT, &stamp(now, -31), 250, 50),
        ],
    );
    let flags = parsed
        .claude_context_curve_boundaries
        .iter()
        .map(|observation| {
            (
                observation.response_count_before,
                observation.id_less_before,
                observation.id_less_after,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        flags,
        vec![
            (0, false, false),
            (2, false, true),
            (3, true, false),
            (3, true, false),
            (5, false, false),
        ]
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn folded_sizes_and_points_leave_every_identity_unchanged() {
    let dir = temp_dir("claude-file-birth-sizes-identity");
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
    let mut items = vec![parsed];
    let mut index = indexed(&[&path], true);
    fold(&mut items, &no_reports(), &mut index, true);
    let item = items.remove(0);
    assert_eq!(item.compaction_events.len(), 1);
    assert!(!item.local_context_points.is_empty());
    let mut bare = item.clone();
    bare.compaction_events.clear();
    bare.local_context_points.clear();
    let claude = SnapshotSource::ClaudeCode;
    let policy = valid_v6_batch_request().upload_policy;
    assert_eq!(
        snapshot_fingerprint(claude, &item),
        snapshot_fingerprint(claude, &bare)
    );
    assert_eq!(
        snapshot_semantic_component_hashes(claude, &item),
        snapshot_semantic_component_hashes(claude, &bare)
    );
    assert_eq!(
        snapshot_semantic_envelope(claude, &item, policy),
        snapshot_semantic_envelope(claude, &bare, policy)
    );
    assert_eq!(
        snapshot_upload_body_witness(&item),
        snapshot_upload_body_witness(&bare)
    );
    assert_eq!(
        snapshot_upload_body_witness_version(&item),
        snapshot_upload_body_witness_version(&bare)
    );
    // Sizes ride the upload; points never do.
    let wire = serde_json::to_value(&item).expect("serialize body");
    assert_eq!(
        wire["compaction_events"],
        serde_json::json!([{"at": stamp(now, -28), "before": 300, "after": 200, "trigger": "auto"}])
    );
    assert!(wire.get("local_context_points").is_none());
    let _ = fs::remove_dir_all(dir);
}

// ---- first_own_request_at (SOURCE ruling, Ron's go) -------------------------

/// Every body that carries `first_own_request_at` also carries this scan
/// identity, so the server takes the start scalars from the same body.
#[test]
fn claude_scan_identity_stays_at_or_above_the_server_posture_minimum() {
    const WHY: &str = "the server pairs start scalars with first_own_request_at only for \
        Claude scan identity >= v28 (session_posture_semantics.\
        CLAUDE_AUTHORITATIVE_POSTURE_SCAN_MIN); lowering it breaks the start-changes rule";
    let version = CLAUDE_CODE_SCAN_IDENTITY_VERSION
        .strip_prefix("claude_code_jsonl:v")
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u32>().ok());
    assert!(
        version.is_some_and(|version| version >= 28),
        "{CLAUDE_CODE_SCAN_IDENTITY_VERSION:?}: {WHY}"
    );
    assert_eq!(
        SnapshotSource::ClaudeCode.scan_identity_version(),
        CLAUDE_CODE_SCAN_IDENTITY_VERSION,
        "{WHY}"
    );
}

/// A measured root file: the first own request's end time, even when copied
/// records with older timestamps (which set `source_started_at`) follow it.
#[test]
fn measured_file_carries_its_first_own_request_time() {
    let dir = temp_dir("claude-file-birth-first-own");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_c1", &stamp(now, COPIED), 900_000),
            boundary(ROOT, &stamp(now, COPIED + 1), 900_010, 100_000),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    assert_eq!(parsed.first_own_request_at, None, "the fold sets it");
    let mut items = vec![parsed.clone()];
    let mut index = indexed(&[&path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    let counts = &disposition.context_file_birth.total;
    assert_eq!(counts.partially_pre_birth_session_count, 0);
    let item = &items[0];
    assert_eq!(item.first_own_request_at, Some(stamp(now, -30)));
    // The earlier copied record never wins, and the field is not started_at.
    assert_eq!(item.source_started_at, Some(stamp(now, COPIED)));
    let wire = serde_json::to_value(item).expect("serialize body");
    assert_eq!(
        wire["first_own_request_at"],
        serde_json::json!(stamp(now, -30))
    );
    let wire = serde_json::to_value(&parsed).expect("serialize body");
    assert!(wire.get("first_own_request_at").is_none());
    let _ = fs::remove_dir_all(dir);
}

/// Absent unless the birth was measured: a file whose first own request
/// follows copied records (partially pre-birth), withheld or unknown birth,
/// a subagent (exempt, not measured) and an id-less first own response. A
/// stale value is cleared, never kept.
#[test]
fn first_own_request_time_is_absent_unless_the_birth_is_measured() {
    let dir = temp_dir("claude-file-birth-first-own-absent");
    let now = OffsetDateTime::now_utc();
    let stale = Some(stamp(now, -3_600));
    let run = |path: &PathBuf, mut item: SnapshotItem| {
        item.first_own_request_at = stale.clone();
        let session = item.source_session_id.clone();
        let mut items = vec![item];
        let mut index = indexed(&[path.as_path()], true);
        let disposition = fold(&mut items, &no_reports(), &mut index, true);
        let admission = disposition.posture_admission(&session);
        let partially = disposition
            .context_file_birth
            .total
            .partially_pre_birth_session_count;
        (admission, partially, items.remove(0))
    };

    let (path, partial) = root_session(
        &dir.join("partial"),
        ROOT,
        &[
            assistant(ROOT, "req_c1", &stamp(now, COPIED), 900_000),
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    let (admission, partially, item) = run(&path, partial);
    assert_eq!(admission, Some("file_birth_rule"));
    assert_eq!(partially, 1);
    assert_eq!(posture(&item), (Some(100), Some(300), Some(300), Some(0)));
    assert_eq!(item.first_own_request_at, None, "partially pre-birth");

    let own = [
        assistant(ROOT, "req_a1", &stamp(now, -30), 100),
        assistant(ROOT, "req_a2", &stamp(now, -29), 300),
    ];
    let (path, mut unknown) = root_session(&dir.join("unknown"), ROOT, &own);
    unknown.claude_file_birth.forget_birth_for_test();
    let (admission, _, item) = run(&path, unknown);
    assert_eq!(admission, Some("withheld_unknown_birth"));
    assert_cleared(&item);

    let (path, copied) = root_session(
        &dir.join("all-copied"),
        ROOT,
        &[assistant(ROOT, "req_c1", &stamp(now, COPIED), 900_000)],
    );
    let (admission, _, item) = run(&path, copied);
    assert_eq!(admission, Some("withheld_all_copied"));
    assert_cleared(&item);

    let (path, id_less) = root_session(
        &dir.join("id-less"),
        ROOT,
        &[
            id_less_assistant(ROOT, &stamp(now, -30), 50),
            assistant(ROOT, "req_a1", &stamp(now, -29), 100),
        ],
    );
    let (admission, _, item) = run(&path, id_less);
    assert_eq!(admission, Some("file_birth_rule"));
    assert_eq!(item.first_own_request_at, None, "no occurrence to read");

    // A stamped partial, then the same response's unstamped final record:
    // the kept timestamp is the partial's, not the request's end.
    let unstamped_end = assistant(ROOT, "req_a1", "", 100)
        .replace("\"timestamp\":\"\",", "")
        .replace("\"output_tokens\":1}", "\"output_tokens\":5}");
    let (path, unstamped) = root_session(
        &dir.join("unstamped-end"),
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            unstamped_end,
        ],
    );
    let (admission, _, item) = run(&path, unstamped);
    assert_eq!(admission, Some("file_birth_rule"));
    assert_eq!(item.first_own_request_at, None, "end time not proven");

    let agent = "a4d1585d310070d0f";
    let child_dir = dir.join("subagent").join(ROOT).join("subagents");
    fs::create_dir_all(&child_dir).expect("create subagent dir");
    let path = child_dir.join(format!("agent-{agent}.jsonl"));
    fs::write(
        &path,
        subagent_assistant(ROOT, agent, "req_s1", &stamp(now, -30)),
    )
    .expect("write subagent fixture");
    let subagent = parse(&path, now);
    assert!(subagent.claude_file_birth.is_subagent_for_test());
    let (admission, _, item) = run(&path, subagent);
    assert_eq!(admission, Some("file_birth_rule"));
    assert_eq!(item.first_own_request_at, None, "exempt is not measured");
    let _ = fs::remove_dir_all(dir);
}

/// The strict rule never carries design E's first own request time, even
/// for the same file the birth rule measures.
#[test]
fn strict_path_has_no_first_own_request_time() {
    // Legacy reported-usage body/authority assertions; E2 emits request-owned grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let dir = temp_dir("claude-file-birth-first-own-strict");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        ],
    );
    let evidence = reports(&[(ROOT, "req_a1", 1, 100), (ROOT, "req_a2", 2, 300)], true);
    let run = |fence_closed: bool| {
        let mut item = parsed.clone();
        item.first_own_request_at = Some(stamp(now, -3_600));
        let mut items = vec![item];
        let mut index = indexed(&[&path], fence_closed);
        let disposition = fold(&mut items, &evidence, &mut index, true);
        (disposition.posture_admission(ROOT), items.remove(0))
    };
    let (strict_admission, strict) = run(false);
    let (birth_admission, birth) = run(true);
    assert_eq!(strict_admission, Some("strict"));
    assert_eq!(birth_admission, Some("file_birth_rule"));
    assert_eq!(posture(&strict), posture(&birth));
    assert_eq!(strict.first_own_request_at, None);
    assert_eq!(birth.first_own_request_at, Some(stamp(now, -30)));
    let _ = fs::remove_dir_all(dir);
}

/// Display-only: the field never moves semantic identity, the content hash,
/// the revision or revision v2 input, the envelope or the body witness.
#[test]
fn first_own_request_time_leaves_every_identity_unchanged() {
    let dir = temp_dir("claude-file-birth-first-own-identity");
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
    fold(&mut items, &no_reports(), &mut index, true);
    let item = items.remove(0);
    assert_eq!(item.first_own_request_at, Some(stamp(now, -30)));
    let mut bare = item.clone();
    bare.first_own_request_at = None;
    let claude = SnapshotSource::ClaudeCode;
    let policy = valid_v6_batch_request().upload_policy;
    let hashes = snapshot_semantic_component_hashes(claude, &item);
    assert_eq!(hashes, snapshot_semantic_component_hashes(claude, &bare));
    assert_eq!(
        snapshot_fingerprint(claude, &item),
        snapshot_fingerprint(claude, &bare)
    );
    assert_eq!(
        snapshot_revision_v2_body(claude, &item, policy, &hashes),
        snapshot_revision_v2_body(claude, &bare, policy, &hashes)
    );
    assert_eq!(
        snapshot_semantic_envelope(claude, &item, policy),
        snapshot_semantic_envelope(claude, &bare, policy)
    );
    assert_eq!(
        snapshot_upload_body_witness(&item),
        snapshot_upload_body_witness(&bare)
    );
    assert_eq!(
        snapshot_upload_body_witness_version(&item),
        snapshot_upload_body_witness_version(&bare)
    );
    assert_eq!(
        differing_keys(&item, &bare),
        BTreeSet::from(["first_own_request_at".to_string()])
    );
    let _ = fs::remove_dir_all(dir);
}

/// The tail path and a full read give the same first own request time at
/// every append boundary.
#[test]
fn tail_and_full_read_give_the_same_first_own_request_time() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = temp_dir("claude-file-birth-first-own-tail");
    fs::create_dir_all(&dir).expect("create project dir");
    let now = OffsetDateTime::now_utc();
    let collected_at = stamp(now, 0);
    let rows = [
        assistant(ROOT, "req_a1", &stamp(now, -9), 100),
        assistant(ROOT, "req_a2", &stamp(now, -8), 300),
        assistant(ROOT, "req_c0", &stamp(now, COPIED), 900_000),
        assistant(ROOT, "req_a3", &stamp(now, -7), 200),
    ];
    let path = dir.join(format!("{ROOT}.jsonl"));
    for split in 1..rows.len() {
        let _ = fs::remove_file(&path);
        fs::write(&path, rows[..split].concat()).expect("write prefix");
        let (retained, _, _) = native_read(&path, None, 100, &collected_at);
        assert!(retained.is_some(), "split {split}: prefix retained");
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        std::io::Write::write_all(&mut file, rows[split..].concat().as_bytes())
            .expect("append rest");
        drop(file);
        let (_, mode, tailed) = native_read(&path, retained, 101, &collected_at);
        assert_eq!(
            mode,
            crate::transcript_acquisition::ReadMode::Tail,
            "split {split}"
        );
        let (_, _, full) = native_read(&path, None, 102, &collected_at);
        let mut folded = Vec::new();
        for item in [tailed, full] {
            let mut items = vec![item];
            let mut index = indexed(&[&path], true);
            let disposition = fold(&mut items, &no_reports(), &mut index, true);
            assert_eq!(
                disposition.posture_admission(ROOT),
                Some("file_birth_rule"),
                "split {split}"
            );
            folded.push(items.remove(0));
        }
        assert_eq!(
            folded[0].first_own_request_at, folded[1].first_own_request_at,
            "split {split}"
        );
        assert_eq!(
            folded[0].first_own_request_at,
            Some(stamp(now, -9)),
            "split {split}"
        );
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn points_work_refusal_preserves_every_other_snapshot_field() {
    use super::local_context_points::{
        LOCAL_CONTEXT_POINT_ORDER_PASSES, LOCAL_CONTEXT_POINT_ORDER_WINDOW,
    };
    let dir = temp_dir("claude-points-work-refusal");
    let now = OffsetDateTime::now_utc();
    let (_, mut item) = root_session(
        &dir,
        ROOT,
        &[
            assistant(ROOT, "req_a1", &stamp(now, -30), 100),
            assistant(ROOT, "req_a2", &stamp(now, -29), 300),
            boundary(ROOT, &stamp(now, -28), 310, 50),
            assistant(ROOT, "req_a3", &stamp(now, -27), 200),
        ],
    );
    let template = item
        .claude_usage_occurrences
        .values()
        .next()
        .unwrap()
        .clone();
    let count = LOCAL_CONTEXT_POINT_ORDER_WINDOW * LOCAL_CONTEXT_POINT_ORDER_PASSES + 1;
    item.claude_usage_occurrences = (0..count)
        .map(|index| {
            let mut occurrence = template.clone();
            occurrence.sequence = index as u64;
            occurrence.timestamp = Some(stamp(now, -30 + index as i64 / 2000));
            (format!("req_{:08}", count - index), occurrence)
        })
        .collect();
    // A stale retained curve must be replaced with empty, never kept on refusal.
    item.local_context_points = vec![LocalContextPoint {
        at_unix_seconds: 1,
        prompt_tokens: 9,
    }];
    item.first_own_request_at = item
        .claude_usage_occurrences
        .values()
        .next()
        .unwrap()
        .timestamp
        .clone();
    let mut expected = item.clone();
    // Every fixture record is owned (within the file-birth slack). Keep the
    // parser's own first/peak/last, including the peak from request a2.
    expected.first_turn_context_tokens = Some(100);
    expected.peak_context_fill_tokens = Some(300);
    expected.last_turn_context_tokens = Some(200);
    let owned = item.claude_context_curve_boundaries.clone();
    let mut ordered = item
        .claude_usage_occurrences
        .values()
        .cloned()
        .collect::<Vec<_>>();
    ordered.sort_by_key(|occurrence| occurrence.sequence);
    // Previous collect/stable-sort algorithm over this all-owned fixture.
    let (id_less, refused) =
        set_claude_compaction_scalars(&mut expected, &owned, ordered.iter(), true, |_| true);
    assert!(!refused);
    assert!(!expected.local_context_points.is_empty());
    assert!(!expected.compaction_events.is_empty());
    let mut counts = ClaudeContextFileBirthCounts::default();
    claude_context_file_birth::apply_own_context_scalars(&mut item, &mut counts);
    assert_eq!(counts.local_context_points_work_refused_session_count, 1);
    assert!(
        !counts.resource_withheld(),
        "LOCAL refusal cannot block upload/backfill"
    );
    assert_eq!(
        counts.id_less_response_before_compaction_count,
        id_less.before
    );
    assert_eq!(
        counts.id_less_response_after_compaction_count,
        id_less.after
    );
    assert!(item.local_context_points.is_empty());
    assert_eq!(
        serde_json::to_value(&item).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    expected.local_context_points.clear();
    // Includes serde-skipped state, money, identities, first-own time and all
    // compaction fields, not merely a selected list of serialized fields.
    assert_eq!(format!("{item:?}"), format!("{expected:?}"));
    clear_claude_context_posture(&mut item);
    assert_cleared(&item);
    let _ = fs::remove_dir_all(dir);
}

/// Advertised curves must distinguish E's admitted scalars from copied or
/// unresolved posture, while the curve itself remains strictly unavailable.
#[test]
fn file_birth_only_curve_coverage_keeps_admitted_scalars_on_batch_wire() {
    let dir = temp_dir("claude-file-birth-curve-coverage");
    let now = OffsetDateTime::now_utc();
    let lines = [
        assistant(ROOT, "req_a1", &stamp(now, -30), 100),
        assistant(ROOT, "req_a2", &stamp(now, -29), 300),
        boundary(ROOT, &stamp(now, -28), 310, 50),
        assistant(ROOT, "req_a3", &stamp(now, -27), 200),
    ];
    let (path, parsed) = root_session(&dir, ROOT, &lines);
    // finish() has no E verdict and must keep the conservative default.
    assert_eq!(parsed.claude_file_birth_verdict(), None);
    assert_eq!(
        parsed.context_curve.as_ref().unwrap().coverage,
        "ownership_unresolved"
    );
    for (advertised, index_complete, expected) in [
        (true, true, Some("scalars_file_birth_only")),
        (true, false, Some("parser_unsupported")),
        (false, true, None),
    ] {
        let mut item = parsed.clone();
        if !advertised {
            item.context_curve = None;
        }
        item.claude_context_curve_request_index_complete = index_complete;
        let mut items = vec![item];
        let mut index = indexed(&[&path], true);
        let disposition = fold(&mut items, &no_reports(), &mut index, false);
        let item = &items[0];
        assert_eq!(
            item.claude_file_birth_verdict(),
            Some(ClaudeFileBirthVerdict::Admitted)
        );
        assert_eq!(posture(item), (Some(100), Some(300), Some(200), Some(1)));
        assert_eq!(
            item.session_start, parsed.session_start,
            "fresh opening keeps full split"
        );
        assert_eq!(item.first_own_request_at, Some(stamp(now, -30)));
        assert_eq!(
            item.context_curve
                .as_ref()
                .map(|curve| curve.coverage.as_str()),
            expected
        );
        assert_eq!(
            disposition
                .context_file_birth
                .curve_scalars_file_birth_only_session_count,
            usize::from(expected == Some("scalars_file_birth_only"))
        );
        assert_eq!(
            disposition
                .context_file_birth
                .curve_ownership_unresolved_session_count,
            0
        );
        if let Some(curve) = &item.context_curve {
            assert_eq!(
                *curve,
                unavailable_context_curve(
                    CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
                    CLAUDE_CONTEXT_CURVE_OWNERSHIP_REVISION,
                    expected.unwrap(),
                    0,
                    0
                )
            );
            validate_context_curve(0, curve).expect("new unavailable coverage is valid locally");
        }
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "claude_code".to_string(),
            machine_id: "machine".to_string(),
            collector_version: None,
            snapshots: items.clone(),
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let wire = serde_json::to_value(&request).expect("serialize real batch wire");
        let body = &wire["snapshots"][0];
        assert_eq!(body["first_turn_context_tokens"], 100);
        assert_eq!(body["peak_context_fill_tokens"], 300);
        assert_eq!(body["last_turn_context_tokens"], 200);
        assert_eq!(body["compaction_count"], 1);
        assert_eq!(body["compaction_timestamps"], json!([stamp(now, -28)]));
        assert_eq!(body["compaction_events"][0]["before"], 300);
        assert_eq!(body["compaction_events"][0]["after"], 200);
        assert_eq!(body["compaction_total_pre_tokens"], 310);
        assert_eq!(body["compaction_total_post_tokens"], 50);
        assert_eq!(body["compaction_total_cumulative_dropped_tokens"], 3);
        assert_eq!(body["compaction_total_duration_ms"], 9);
        assert_eq!(body["first_own_request_at"], stamp(now, -30));
        assert_eq!(
            body["session_start"],
            serde_json::to_value(&parsed.session_start).unwrap()
        );
        assert!(body.get("claude_file_birth_verdict").is_none());
        assert!(body.get("claude_file_birth").is_none());
        assert_eq!(body.get("context_curve").is_some(), advertised);
        if advertised {
            assert_eq!(body["context_curve"]["coverage"], expected.unwrap());
        }
        let mut previous_coverage = item.clone();
        previous_coverage.context_curve = parsed.context_curve.clone();
        assert_eq!(
            snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, item),
            snapshot_semantic_component_hashes(SnapshotSource::ClaudeCode, &previous_coverage),
            "coverage and the local verdict cannot move protected semantic roots"
        );
        assert_eq!(
            snapshot_fingerprint(SnapshotSource::ClaudeCode, item),
            snapshot_fingerprint(SnapshotSource::ClaudeCode, &previous_coverage)
        );
        let mut cleared = item.clone();
        clear_claude_context_posture(&mut cleared);
        assert_eq!(cleared.claude_file_birth_verdict(), None);
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn copied_and_unknown_birth_curves_keep_ownership_unresolved() {
    let dir = temp_dir("claude-file-birth-curve-unresolved");
    let now = OffsetDateTime::now_utc();
    let (path, parsed) = root_session(
        &dir,
        ROOT,
        &[assistant(ROOT, "req_a1", &stamp(now, -30), 100)],
    );
    let (_, copied) = root_session(
        &dir,
        SECOND,
        &[assistant(SECOND, "req_c1", &stamp(now, COPIED), 900_000)],
    );
    let mut unknown = parsed;
    unknown.claude_file_birth.forget_birth_for_test();
    let mut items = vec![unknown, copied];
    let second_path = dir.join(format!("{SECOND}.jsonl"));
    let mut index = indexed(&[&path, &second_path], true);
    let disposition = fold(&mut items, &no_reports(), &mut index, false);
    assert_eq!(
        items[0].claude_file_birth_verdict(),
        Some(ClaudeFileBirthVerdict::UnknownBirth)
    );
    assert_eq!(
        items[1].claude_file_birth_verdict(),
        Some(ClaudeFileBirthVerdict::AllCopied)
    );
    assert_eq!(
        disposition
            .context_file_birth
            .curve_scalars_file_birth_only_session_count,
        0
    );
    assert_eq!(
        disposition
            .context_file_birth
            .curve_ownership_unresolved_session_count,
        2
    );
    for item in &items {
        assert_cleared(item);
        assert_eq!(
            item.context_curve.as_ref().unwrap().coverage,
            "ownership_unresolved"
        );
        validate_context_curve(0, item.context_curve.as_ref().unwrap()).unwrap();
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn scalars_file_birth_only_curve_rejects_nonzero_evidence() {
    let mut curve = unavailable_context_curve(
        CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
        CLAUDE_CONTEXT_CURVE_OWNERSHIP_REVISION,
        "scalars_file_birth_only",
        0,
        0,
    );
    validate_context_curve(0, &curve).unwrap();
    curve.total_owned_request_count = 1;
    assert!(validate_context_curve(0, &curve)
        .unwrap_err()
        .contains("zero evidence"));
}
