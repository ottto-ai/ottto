// Census-verified fresh start (slice 2c): a root Claude Code transcript with
// no telemetry proof keeps first/peak/last context and owned compactions only
// when SOURCE's copy signature passes, a complete accepted census verified its
// exact revision, and no duplicate, telemetry verdict or contradicting row
// refuses it. Default off. All fixtures are synthetic and content-free.
use super::*;

const FRESH: &str = "f0000000-0000-4000-8000-00000000000f";
const PEER: &str = "b0000000-0000-4000-8000-00000000000b";
const OTHER_ROOT: &str = "c0000000-0000-4000-8000-00000000000c";
const V1_ROOT: &str = "d0000000-0000-4000-8000-00000000000d";
const STRADDLER: &str = "e0000000-0000-4000-8000-00000000000e";
const CONTRA: &str = "a0000000-0000-4000-8000-00000000000a";
const WINDOW: &str = "2026-08-20T10:30:00Z";
const LATER_WINDOW: &str = "2026-08-20T11:30:00Z";

/// Switch and birth overrides for this test thread, reset on drop.
struct Fixture;

impl Fixture {
    fn on(births: &[(&str, &str)]) -> Self {
        Self::with(true, births)
    }

    fn with(enabled: bool, births: &[(&str, &str)]) -> Self {
        CLAUDE_FRESH_START_ENABLED_FOR_TEST.with(|switch| switch.set(Some(enabled)));
        CLAUDE_TRANSCRIPT_BIRTH_FOR_TEST.with(|map| {
            *map.borrow_mut() = Some(
                births
                    .iter()
                    .map(|(stem, birth)| (stem.to_string(), ms(birth)))
                    .collect(),
            )
        });
        Fixture
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        CLAUDE_FRESH_START_ENABLED_FOR_TEST.with(|switch| switch.set(None));
        CLAUDE_TRANSCRIPT_BIRTH_FOR_TEST.with(|map| *map.borrow_mut() = None);
    }
}

fn ms(timestamp: &str) -> i64 {
    i64::try_from(rfc3339_unix_nanos(timestamp).expect("RFC 3339 fixture") / 1_000_000)
        .expect("fixture time")
}

fn at(minute: u32, second: u32) -> String {
    format!("2026-08-20T10:{minute:02}:{second:02}Z")
}

fn user(session: &str, uuid: &str, timestamp: &str) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"type\":\"user\",\"uuid\":\"{uuid}\",\"sessionId\":\"{session}\",\"message\":{{\"role\":\"user\",\"content\":\"x\"}}}}\n"
    )
}

fn assistant(session: &str, request: &str, timestamp: &str, input_tokens: u64) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"type\":\"assistant\",\"uuid\":\"u_{request}\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"id\":\"msg_{request}\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":{input_tokens},\"output_tokens\":1}}}}}}\n"
    )
}

fn metadata(session: &str, kind: &str, timestamp: &str) -> String {
    format!("{{\"timestamp\":\"{timestamp}\",\"type\":\"{kind}\",\"sessionId\":\"{session}\"}}\n")
}

fn boundary(session: &str, timestamp: &str, pre: u64) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"sessionId\":\"{session}\",\"type\":\"system\",\"subtype\":\"compact_boundary\",\"compactMetadata\":{{\"trigger\":\"auto\",\"preTokens\":{pre},\"postTokens\":1,\"cumulativeDroppedTokens\":1,\"durationMs\":1}}}}\n"
    )
}

/// A fresh root: a boundary before its first response (not counted), three
/// responses and a boundary after the first one (counted).
fn fresh_lines(session: &str, minute: u32) -> Vec<String> {
    let tag = &session[..1];
    vec![
        user(session, &format!("u_{tag}0"), &at(minute, 0)),
        boundary(session, &at(minute, 1), 10),
        assistant(session, &format!("req_{tag}1"), &at(minute, 2), 100),
        boundary(session, &at(minute, 3), 20),
        assistant(session, &format!("req_{tag}2"), &at(minute, 4), 300),
        assistant(session, &format!("req_{tag}3"), &at(minute, 5), 200),
    ]
}

fn write(dir: &Path, stem: &str, lines: &[String]) -> PathBuf {
    let path = dir.join(format!("{stem}.jsonl"));
    fs::write(&path, lines.concat()).expect("write transcript fixture");
    path
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
    assert_eq!(
        posture(item),
        (None, None, None, None),
        "{}",
        item.source_session_id
    );
    assert!(item.compaction_timestamps.is_empty());
    assert_eq!(item.compaction_total_pre_tokens, None);
}

/// The scalars a verified `fresh_lines` root carries: first, peak, last, and
/// one compaction (the boundary after the first response).
fn assert_fresh_scalars(item: &SnapshotItem) {
    assert_eq!(posture(item), (Some(100), Some(300), Some(200), Some(1)));
    assert_eq!(item.compaction_total_pre_tokens, Some(20));
    assert_eq!(item.compaction_timestamps.len(), 1);
    // Scalars only: no cache observations, no curve, no usage contract.
    assert!(item.cache_observations.is_none());
    assert!(item
        .context_curve
        .as_ref()
        .map_or(true, |curve| curve.coverage != "complete"));
    assert_eq!(item.usage_accounting_contract, None);
}

fn state(index: &ScanIndex, member: &str) -> Option<ClaudeFreshStartState> {
    index
        .claude_fresh_start_census
        .get(member)
        .map(|witness| witness.state)
}

fn item<'a>(items: &'a [SnapshotItem], session: &str) -> &'a SnapshotItem {
    items
        .iter()
        .find(|item| item.source_session_id == session)
        .unwrap_or_else(|| panic!("item {session}"))
}

fn rows(
    api: &[(&str, &str, &str)],
    trace: &[(&str, &str, &str, &str)],
) -> (
    crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
) {
    // Rows carry the token counts `fresh_lines` writes for the same request
    // suffix, so complete rows prove their family.
    let input_tokens = |request: &str| match request.chars().last() {
        Some('1') => 100,
        Some('2') => 300,
        Some('3') => 200,
        _ => 1,
    };
    let mut api_rows = BTreeMap::<String, Vec<_>>::new();
    for (sequence, (root, session, request)) in api.iter().enumerate() {
        let mut row = complete_api_row(
            session,
            request,
            sequence as u64,
            input_tokens(request),
            1,
            0,
        );
        row.session_id = session.to_string();
        api_rows.entry(root.to_string()).or_default().push(row);
    }
    let mut trace_rows = BTreeMap::<String, Vec<_>>::new();
    for (root, session, request, agent) in trace {
        trace_rows
            .entry(root.to_string())
            .or_default()
            .push(complete_trace_row(session, request, agent));
    }
    (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport {
            evidence: api_rows,
            health: Default::default(),
        },
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
            evidence: trace_rows,
            ..Default::default()
        },
    )
}

/// The real scan loop, fold and finalization over one or more scan roots.
struct Machine {
    roots: Vec<PathBuf>,
    index: ScanIndex,
    reports: (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ),
    settled: BTreeSet<String>,
}

impl Machine {
    fn new(roots: Vec<PathBuf>, settled: &[&str]) -> Self {
        Self {
            roots,
            index: ScanIndex::default(),
            reports: rows(&[], &[]),
            settled: settled.iter().map(|root| root.to_string()).collect(),
        }
    }

    fn pass(&mut self, collected_at: &str) -> (Vec<SnapshotItem>, ClaudeUsageAuthorityDisposition) {
        let mut page = scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            &self.roots,
            &mut self.index,
            collected_at,
            BACKFILL_WINDOW_DAYS,
            1_000,
            true,
        )
        .expect("scan page");
        assert!(page.census_complete, "one page covers the fixture corpus");
        let window = page.census_window_end.clone();
        let disposition = apply_claude_reported_usage_with_index_limits_and_current_files(
            &mut page.snapshots,
            &self.reports.0,
            &self.reports.1,
            &mut self.index,
            page.census_complete,
            &window,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
            &BTreeSet::new(),
            None,
            None,
            &self.settled,
        );
        let items = page.snapshots.clone();
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut page, &mut self.index);
        (items, disposition)
    }
}

/// One fold of already parsed items, as a scan page would run it.
#[allow(clippy::too_many_arguments)]
fn fold(
    items: &mut [SnapshotItem],
    reports: &(
        crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ),
    index: &mut ScanIndex,
    census_complete: bool,
    window: &str,
    max_pending_occurrences: usize,
    settled: &[&str],
) -> ClaudeUsageAuthorityDisposition {
    apply_claude_reported_usage_with_index_limits_and_current_files(
        items,
        &reports.0,
        &reports.1,
        index,
        census_complete,
        window,
        max_pending_occurrences,
        MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
        None,
        &BTreeSet::new(),
        None,
        None,
        &settled.iter().map(|root| root.to_string()).collect(),
    )
}

/// Parse one transcript outside the scan loop; its fingerprint is `<stem>-fp`.
fn parsed(dir: &Path, stem: &str, lines: &[String]) -> (PathBuf, SnapshotItem) {
    let path = write(dir, stem, lines);
    let item = parse_claude_code_jsonl_file(&path, WINDOW, format!("{stem}-fp"))
        .expect("parse transcript fixture")
        .remove(0);
    (path, item)
}

/// Index every path under the fingerprint its parsed item carries.
fn indexed(paths: &[&Path]) -> ScanIndex {
    let mut index = ScanIndex::default();
    for path in paths {
        let mut entry = manifest_index_entry(None);
        entry.source_file_fingerprint = format!(
            "{}-fp",
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .expect("stem")
        );
        index.files.insert(local_index_key(path), entry);
    }
    index
}

fn witness(index: &mut ScanIndex, member: &str, state: ClaudeFreshStartState) {
    index.claude_fresh_start_census.insert(
        member.to_string(),
        ClaudeFreshStartCensusWitness {
            candidate_source_file_fingerprint: format!("{member}-fp"),
            derivation_revision: claude_fresh_start_current_revision(),
            state,
        },
    );
}

fn indexed_fingerprint<'a>(index: &'a ScanIndex, path: &Path) -> &'a str {
    &index.files[&local_index_key(path)].source_file_fingerprint
}

fn observation(lines: &[String]) -> ClaudeCopySignatureObservation {
    let mut observation = ClaudeCopySignatureObservation::default();
    let mut first_session_id = None::<String>;
    for line in lines {
        let value = serde_json::from_str::<Value>(line).expect("fixture JSON");
        if first_session_id.is_none() {
            first_session_id = claude_record_session_id(&value).map(str::to_string);
        }
        observation.observe(&value, first_session_id.as_deref());
    }
    observation
}

fn signature(lines: &[String], birth: Option<&str>, stem: &str) -> ClaudeCopySignature {
    let observation = observation(lines);
    let first_session_id = lines
        .iter()
        .filter_map(|line| {
            claude_record_session_id(&serde_json::from_str::<Value>(line).ok()?).map(str::to_string)
        })
        .next();
    claude_copy_signature(
        &observation,
        birth.map(ms),
        stem,
        first_session_id.as_deref(),
        ms(WINDOW),
    )
}

// ---------------------------------------------------------------------------
// Copy signature (pure). SOURCE ruling 2026-10-21 §1 and S2.

#[test]
fn signature_pre_birth_record_fires_only_beyond_sixty_seconds() {
    let lines = fresh_lines(FRESH, 0);
    // Earliest record 10:00:00. Birth 59 s and 60 s later pass; 61 s fires.
    assert_eq!(
        signature(&lines, Some("2026-08-20T10:00:59Z"), FRESH),
        ClaudeCopySignature::Fresh
    );
    assert_eq!(
        signature(&lines, Some("2026-08-20T10:01:00Z"), FRESH),
        ClaudeCopySignature::Fresh
    );
    assert_eq!(
        signature(&lines, Some("2026-08-20T10:01:01Z"), FRESH),
        ClaudeCopySignature::Copy(ClaudeCopyRule::PreBirthRecord)
    );
}

#[test]
fn signature_root_uuid_older_than_first_record_fires_only_beyond_sixty_seconds() {
    // A metadata record without uuid comes first (10:05:00); the
    // conversation root is 59, 60 or 61 s older. Birth precedes both, so (i)
    // is silent.
    for (root, expected) in [
        ("2026-08-20T10:04:01Z", ClaudeCopySignature::Fresh),
        ("2026-08-20T10:04:00Z", ClaudeCopySignature::Fresh),
        (
            "2026-08-20T10:03:59Z",
            ClaudeCopySignature::Copy(ClaudeCopyRule::RootOlderThanFirstRecord),
        ),
    ] {
        let lines = vec![
            metadata(FRESH, "custom-title", &at(5, 0)),
            user(FRESH, "u_root", root),
            assistant(FRESH, "req_f1", &at(5, 10), 100),
        ];
        assert_eq!(
            signature(&lines, Some("2026-08-20T09:00:00Z"), FRESH),
            expected,
            "{root}"
        );
    }
}

#[test]
fn signature_session_id_must_be_the_stem_on_every_record() {
    let lines = fresh_lines(FRESH, 0);
    let birth = Some("2026-08-20T10:00:00Z");
    // First sessionId is another session's (raw copy under a new stem).
    assert_eq!(
        signature(&lines, birth, PEER),
        ClaudeCopySignature::Copy(ClaudeCopyRule::SessionIdNotStem)
    );
    // A later record names another session.
    let mut later = lines.clone();
    later.push(assistant(PEER, "req_p1", &at(0, 9), 50));
    assert_eq!(
        signature(&later, birth, FRESH),
        ClaudeCopySignature::Copy(ClaudeCopyRule::SessionIdNotStem)
    );
    // No sessionId at all.
    let anonymous = vec![
        "{\"timestamp\":\"2026-08-20T10:00:00Z\",\"type\":\"user\",\"uuid\":\"u0\"}\n".to_string(),
    ];
    assert_eq!(
        signature(&anonymous, birth, FRESH),
        ClaudeCopySignature::Copy(ClaudeCopyRule::SessionIdNotStem)
    );
}

#[test]
fn signature_unknown_inputs_fail_closed() {
    let lines = fresh_lines(FRESH, 0);
    let birth = Some("2026-08-20T10:00:00Z");
    assert_eq!(
        signature(&lines, None, FRESH),
        ClaudeCopySignature::Unknown(ClaudeCopyUnknown::NoBirth)
    );
    assert_eq!(
        signature(&lines, Some("2026-08-20T10:31:01Z"), FRESH),
        ClaudeCopySignature::Unknown(ClaudeCopyUnknown::BirthInFuture)
    );
    let mut future = lines.clone();
    future.push(assistant(FRESH, "req_late", "2026-08-20T10:31:01Z", 1));
    assert_eq!(
        signature(&future, birth, FRESH),
        ClaudeCopySignature::Unknown(ClaudeCopyUnknown::RecordInFuture)
    );
    let mut garbled = lines.clone();
    garbled.push(format!(
        "{{\"timestamp\":\"yesterday\",\"type\":\"user\",\"uuid\":\"u9\",\"sessionId\":\"{FRESH}\"}}\n"
    ));
    assert_eq!(
        signature(&garbled, birth, FRESH),
        ClaudeCopySignature::Unknown(ClaudeCopyUnknown::UnparseableTimestamp)
    );
    let untimed = vec![format!(
        "{{\"type\":\"user\",\"uuid\":\"u0\",\"sessionId\":\"{FRESH}\"}}\n"
    )];
    assert_eq!(
        signature(&untimed, birth, FRESH),
        ClaudeCopySignature::Unknown(ClaudeCopyUnknown::NoTimestamp)
    );
    // S2: the root uuid record carries no timestamp.
    let mut root_untimed = vec![format!(
        "{{\"type\":\"user\",\"uuid\":\"u0\",\"sessionId\":\"{FRESH}\"}}\n"
    )];
    root_untimed.extend(lines);
    assert_eq!(
        signature(&root_untimed, birth, FRESH),
        ClaudeCopySignature::Unknown(ClaudeCopyUnknown::RootUuidUntimed)
    );
}

#[test]
fn signature_passes_an_ordinary_fresh_transcript() {
    assert_eq!(
        signature(&fresh_lines(FRESH, 0), Some("2026-08-20T10:00:00Z"), FRESH),
        ClaudeCopySignature::Fresh
    );
}

// ---------------------------------------------------------------------------
// Real scan pipeline.

#[test]
fn fresh_root_without_telemetry_gets_scalars_after_one_corrective_parse() {
    let fixture = Fixture::on(&[(FRESH, "2026-08-20T09:59:30Z")]);
    let dir = temp_dir("claude-2c-fresh");
    let path = write(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut machine = Machine::new(vec![dir.clone()], &[FRESH]);

    // First pass: the signature passes and the complete census verifies the
    // revision, but this body was already built without numbers.
    let (items, disposition) = machine.pass("2026-08-20T10:30:00Z");
    assert_cleared(item(&items, FRESH));
    assert_eq!(
        disposition.posture_admission(FRESH),
        Some("withheld_no_contract")
    );
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Verified)
    );
    assert!(
        indexed_fingerprint(&machine.index, &path).is_empty(),
        "one corrective parse"
    );

    // Corrective parse: scalars with the fresh-start provenance.
    let (items, disposition) = machine.pass("2026-08-20T10:40:00Z");
    assert_eq!(items.len(), 1);
    let fresh = item(&items, FRESH);
    assert_eq!(
        disposition.posture_admission(FRESH),
        Some("census_verified_fresh_start")
    );
    assert_fresh_scalars(fresh);
    assert_eq!(
        fresh.session_start.as_deref(),
        fresh
            .session_start
            .clone()
            .and_then(|start| (*start).inherited())
            .as_ref(),
        "session_start stays inherited-only"
    );
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Emitted)
    );

    // No further re-arm for this revision.
    let (items, _) = machine.pass("2026-08-20T10:50:00Z");
    assert!(items.is_empty());
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn every_measured_copy_shape_is_withheld() {
    // Births per file: a copy is born after the records it copied.
    let source = "50000000-0000-4000-8000-000000000005";
    let fork = "51000000-0000-4000-8000-000000000051";
    let orphan = "52000000-0000-4000-8000-000000000052";
    let twice = "53000000-0000-4000-8000-000000000053";
    let raw = "54000000-0000-4000-8000-000000000054";
    let inherit = "55000000-0000-4000-8000-000000000055";
    let s6_only = "56000000-0000-4000-8000-000000000056";
    let migrated = "77000000-0000-4000-8000-000000000077";
    let unknown = "88000000-0000-4000-8000-000000000088";
    let fixture = Fixture::on(&[
        (source, "2026-08-20T10:00:00Z"),
        (fork, "2026-08-20T11:00:00Z"),
        (orphan, "2026-08-20T11:00:00Z"),
        (twice, "2026-08-20T11:00:00Z"),
        (raw, "2026-08-20T11:00:00Z"),
        (inherit, "2026-08-20T11:00:00Z"),
        (s6_only, "2026-08-20T08:00:00Z"),
        (migrated, "2026-08-22T09:00:00Z"),
    ]);
    let dir = temp_dir("claude-2c-copies");
    write(&dir, source, &fresh_lines(source, 0));
    // T3: new-id Desktop fork, metadata stamped at birth, then the copied
    // chain (original timestamps and request ids), then new turns.
    let copied = |session: &str| {
        vec![
            user(session, "u_50", &at(0, 0)),
            boundary(session, &at(0, 1), 10),
            assistant(session, "req_51", &at(0, 2), 100),
            boundary(session, &at(0, 3), 20),
        ]
    };
    let mut fork_lines = vec![
        metadata(fork, "custom-title", "2026-08-20T11:00:00Z"),
        metadata(fork, "mode", "2026-08-20T11:00:00Z"),
    ];
    fork_lines.extend(copied(fork));
    fork_lines.push(assistant(fork, "req_fork_new", "2026-08-20T11:00:10Z", 900));
    write(&dir, fork, &fork_lines);
    // T4: the same shape whose source is gone.
    let mut orphan_lines = vec![metadata(orphan, "custom-title", "2026-08-20T11:00:00Z")];
    orphan_lines.extend([
        user(orphan, "u_gone", "2026-08-19T10:00:00Z"),
        assistant(orphan, "req_gone", "2026-08-19T10:00:05Z", 700),
        assistant(orphan, "req_orphan_new", "2026-08-20T11:00:10Z", 800),
    ]);
    write(&dir, orphan, &orphan_lines);
    // T5: the copied chain twice.
    let mut twice_lines = vec![metadata(twice, "custom-title", "2026-08-20T11:00:00Z")];
    twice_lines.extend([
        user(twice, "u_t0", "2026-08-19T09:00:00Z"),
        assistant(twice, "req_t1", "2026-08-19T09:00:05Z", 10),
        user(twice, "u_t0b", "2026-08-19T09:00:00Z"),
        assistant(twice, "req_t1b", "2026-08-19T09:00:05Z", 10),
        assistant(twice, "req_twice_new", "2026-08-20T11:00:10Z", 20),
    ]);
    write(&dir, twice, &twice_lines);
    // T6: raw copy keeping another session id under a new stem.
    write(
        &dir,
        raw,
        &[
            user(OTHER_ROOT, "u_r0", "2026-08-20T11:00:00Z"),
            assistant(OTHER_ROOT, "req_r1", "2026-08-20T11:00:05Z", 10),
        ],
    );
    // T8: fork_inherit history suppression ahead of the copied records.
    let mut inherit_lines = vec![format!(
        "{{\"timestamp\":\"2026-08-20T11:00:00Z\",\"type\":\"history-suppression\",\"cause\":\"fork_inherit\",\"sessionId\":\"{inherit}\"}}\n"
    )];
    inherit_lines.extend([
        user(inherit, "u_i0", "2026-08-19T08:00:00Z"),
        assistant(inherit, "req_i1", "2026-08-19T08:00:05Z", 10),
        assistant(inherit, "req_inherit_new", "2026-08-20T11:00:10Z", 20),
    ]);
    write(&dir, inherit, &inherit_lines);
    // T9: birth earlier than every record, but the conversation root is five
    // minutes older than the first timestamped record.
    write(
        &dir,
        s6_only,
        &[
            metadata(s6_only, "custom-title", &at(5, 0)),
            user(s6_only, "u_s6", &at(0, 0)),
            assistant(s6_only, "req_s6", &at(5, 10), 10),
        ],
    );
    // T11: migrated or synced history: new birth, records days old.
    write(&dir, migrated, &fresh_lines(migrated, 0));
    // T10: unknown birth.
    write(&dir, unknown, &fresh_lines(unknown, 0));
    let settled = [
        source, fork, orphan, twice, raw, inherit, s6_only, migrated, unknown,
    ];
    let mut machine = Machine::new(vec![dir.clone()], &settled);

    let mut seen = Vec::new();
    for collected_at in [
        "2026-08-22T10:00:00Z",
        "2026-08-22T10:10:00Z",
        "2026-08-22T10:20:00Z",
    ] {
        let (items, _) = machine.pass(collected_at);
        seen.extend(items);
    }
    for item in &seen {
        assert_cleared(item);
    }
    for copy in [
        fork, orphan, twice, raw, inherit, s6_only, migrated, unknown,
    ] {
        assert_eq!(
            state(&machine.index, copy),
            None,
            "{copy} is never a candidate"
        );
    }
    // The source shares a request with the fork that the census sees.
    assert_eq!(
        state(&machine.index, source),
        Some(ClaudeFreshStartState::Revoked)
    );
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn same_id_slot_copy_under_two_config_roots_is_never_verified() {
    // T7: the same stem under two roots; the copy was born 2 s after its
    // first record, which no signature catches.
    let fixture = Fixture::on(&[(FRESH, "2026-08-20T10:00:02Z")]);
    let first = temp_dir("claude-2c-slot-a");
    let second = temp_dir("claude-2c-slot-b");
    write(&first, FRESH, &fresh_lines(FRESH, 0));
    write(&second, FRESH, &fresh_lines(FRESH, 0));
    let mut machine = Machine::new(vec![first.clone(), second.clone()], &[FRESH]);
    for collected_at in ["2026-08-20T10:30:00Z", "2026-08-20T10:40:00Z"] {
        let (items, _) = machine.pass(collected_at);
        for item in &items {
            assert_cleared(item);
        }
        assert!(!matches!(
            state(&machine.index, FRESH),
            Some(ClaudeFreshStartState::Verified | ClaudeFreshStartState::Emitted)
        ));
    }
    drop(fixture);
    let _ = fs::remove_dir_all(first);
    let _ = fs::remove_dir_all(second);
}

#[test]
fn a_same_id_path_appearing_after_emission_withdraws_the_emitted_numbers() {
    // Review F1: a second path of an emitted root replaces its witness. The
    // emitted path is re-armed once so it uploads without numbers, and the
    // two-path root is revoked.
    let fixture = Fixture::on(&[(FRESH, "2026-08-20T10:00:00Z")]);
    let first = temp_dir("claude-2c-late-slot-a");
    let second = temp_dir("claude-2c-late-slot-b");
    let emitted_path = write(&first, FRESH, &fresh_lines(FRESH, 0));
    let mut machine = Machine::new(vec![first.clone(), second.clone()], &[FRESH]);
    let _ = machine.pass("2026-08-20T10:30:00Z");
    let (admitted, _) = machine.pass("2026-08-20T10:40:00Z");
    assert_fresh_scalars(item(&admitted, FRESH));
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Emitted)
    );
    assert!(!indexed_fingerprint(&machine.index, &emitted_path).is_empty());

    write(&second, FRESH, &fresh_lines(FRESH, 0));
    let mut withheld = Vec::new();
    for collected_at in ["2026-08-20T10:50:00Z", "2026-08-20T10:55:00Z"] {
        let (items, _) = machine.pass(collected_at);
        withheld.extend(items);
    }
    // The new path and the re-armed emitted path were both parsed, and
    // neither carries numbers.
    assert!(
        withheld
            .iter()
            .filter(|item| item.source_session_id == FRESH)
            .count()
            >= 2
    );
    for item in &withheld {
        assert_cleared(item);
    }
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Revoked)
    );
    drop(fixture);
    let _ = fs::remove_dir_all(first);
    let _ = fs::remove_dir_all(second);
}

#[test]
fn first_install_with_mixed_history_admits_only_fresh_roots_without_contradiction() {
    let births = [
        (FRESH, "2026-08-20T10:00:00Z"),
        (V1_ROOT, "2026-08-20T10:00:00Z"),
        (STRADDLER, "2026-08-20T10:00:00Z"),
        (CONTRA, "2026-08-20T10:00:00Z"),
        ("agent-x", "2026-08-20T10:00:00Z"),
    ];
    let fixture = Fixture::on(&births);
    let dir = temp_dir("claude-2c-first-install");
    write(&dir, FRESH, &fresh_lines(FRESH, 0));
    // A subagent of the fresh root: root-only scope keeps it withheld.
    let subagents = dir.join(FRESH).join("subagents");
    fs::create_dir_all(&subagents).expect("subagent dir");
    write(
        &subagents,
        "agent-x",
        &[
            user(FRESH, "u_x0", &at(0, 10)),
            assistant(FRESH, "req_x1", &at(0, 11), 40),
        ],
    );
    write(&dir, V1_ROOT, &fresh_lines(V1_ROOT, 0));
    write(&dir, STRADDLER, &fresh_lines(STRADDLER, 0));
    write(&dir, CONTRA, &fresh_lines(CONTRA, 0));
    let mut machine = Machine::new(vec![dir.clone()], &[FRESH, V1_ROOT, STRADDLER, CONTRA]);
    let v1_requests = ["req_d1", "req_d2", "req_d3"];
    machine.reports = rows(
        &[
            (V1_ROOT, V1_ROOT, v1_requests[0]),
            (V1_ROOT, V1_ROOT, v1_requests[1]),
            (V1_ROOT, V1_ROOT, v1_requests[2]),
            // S1: an agreeing partial row adds no authority and refuses nothing.
            (STRADDLER, STRADDLER, "req_e1"),
            // A row assigning this root's request to another root contradicts it.
            (OTHER_ROOT, OTHER_ROOT, "req_a1"),
        ],
        &[
            (V1_ROOT, V1_ROOT, v1_requests[0], ""),
            (V1_ROOT, V1_ROOT, v1_requests[1], ""),
            (V1_ROOT, V1_ROOT, v1_requests[2], ""),
            (STRADDLER, STRADDLER, "req_e1", ""),
        ],
    );

    let (first, _) = machine.pass("2026-08-20T10:30:00Z");
    for session in [FRESH, STRADDLER, CONTRA] {
        assert_cleared(item(&first, session));
    }
    let (second, disposition) = machine.pass("2026-08-20T10:40:00Z");
    let (third, _) = machine.pass("2026-08-20T10:50:00Z");

    assert_fresh_scalars(item(&second, FRESH));
    assert_fresh_scalars(item(&second, STRADDLER));
    assert_eq!(
        disposition.posture_admission(STRADDLER),
        Some("census_verified_fresh_start")
    );
    assert_cleared(item(&second, CONTRA));
    assert_eq!(
        state(&machine.index, CONTRA),
        Some(ClaudeFreshStartState::Refused)
    );
    // The telemetry-proven root keeps its own path; 2c never re-arms it.
    let v1 = item(&first, V1_ROOT);
    assert_eq!(
        v1.usage_accounting_contract.as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_eq!(
        state(&machine.index, V1_ROOT),
        Some(ClaudeFreshStartState::Refused)
    );
    assert!(second.iter().all(|item| item.source_session_id != V1_ROOT));
    // The subagent never carries numbers (root transcripts only).
    for item in first.iter().chain(&second) {
        if item.source_session_id != FRESH && item.source_session_id.contains(FRESH) {
            assert_cleared(item);
        }
    }
    // Refused and emitted revisions are not re-armed again.
    assert!(third.is_empty(), "no re-arm loop");
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn sessions_without_usable_request_identity_never_carry_numbers() {
    let api_error = "60000000-0000-4000-8000-000000000060";
    let id_less = "61000000-0000-4000-8000-000000000061";
    let fixture = Fixture::on(&[
        (FRESH, "2026-08-20T10:00:00Z"),
        (api_error, "2026-08-20T10:00:00Z"),
        (id_less, "2026-08-20T10:00:00Z"),
    ]);
    let dir = temp_dir("claude-2c-no-identity");
    write(&dir, FRESH, &fresh_lines(FRESH, 0));
    write(
        &dir,
        api_error,
        &[
            user(api_error, "u_e0", &at(0, 0)),
            format!(
                "{{\"timestamp\":\"{}\",\"type\":\"assistant\",\"uuid\":\"u_e1\",\"sessionId\":\"{api_error}\",\"requestId\":\"req_err\",\"isApiErrorMessage\":true,\"message\":{{\"id\":\"msg_err\",\"model\":\"<synthetic>\",\"usage\":{{\"input_tokens\":0,\"output_tokens\":0}}}}}}\n",
                at(0, 1)
            ),
        ],
    );
    write(
        &dir,
        id_less,
        &[
            user(id_less, "u_i0", &at(0, 0)),
            format!(
                "{{\"timestamp\":\"{}\",\"type\":\"assistant\",\"uuid\":\"u_i1\",\"sessionId\":\"{id_less}\",\"message\":{{\"id\":\"msg_idless\",\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":70,\"output_tokens\":1}}}}}}\n",
                at(0, 1)
            ),
        ],
    );
    let mut machine = Machine::new(vec![dir.clone()], &[FRESH, api_error, id_less]);
    let (first, first_disposition) = machine.pass("2026-08-20T10:30:00Z");
    let (second, _) = machine.pass("2026-08-20T10:40:00Z");
    for item in first.iter().chain(&second) {
        if item.source_session_id == api_error || item.source_session_id == id_less {
            assert_cleared(item);
        }
    }
    for member in [api_error, id_less] {
        assert_eq!(state(&machine.index, member), None);
    }
    // Today's census composition: such a member is never covered by family
    // pending, so the window is not accepted and no fresh root verifies on
    // this Mac. StateMissing's `claude_census_disjointness_complete` owns that
    // seam; this pins the fail-closed behavior until it lands.
    assert!(!first_disposition.transcript_ownership_complete);
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Candidate)
    );
    for item in first.iter().chain(&second) {
        if item.source_session_id == FRESH {
            assert_cleared(item);
        }
    }
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Fold-level state machine.

#[test]
fn verified_admission_stays_while_the_fence_is_closed_beside_the_member_waiver() {
    // SOURCE S4: an admitted revision keeps its scalars under a closed fence.
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-closed-fence");
    let (fresh_path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let (v1_path, v1) = parsed(&dir, V1_ROOT, &fresh_lines(V1_ROOT, 0));
    let (peer_path, peer) = parsed(
        &dir,
        PEER,
        &[
            user(PEER, "u_p0", &at(9, 0)),
            assistant(PEER, "req_p1", &at(9, 1), 50),
        ],
    );
    let mut index = indexed(&[&fresh_path, &v1_path, &peer_path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Emitted);
    let v1_rows = || {
        rows(
            &[
                (V1_ROOT, V1_ROOT, "req_d1"),
                (V1_ROOT, V1_ROOT, "req_d2"),
                (V1_ROOT, V1_ROOT, "req_d3"),
            ],
            &[
                (V1_ROOT, V1_ROOT, "req_d1", ""),
                (V1_ROOT, V1_ROOT, "req_d2", ""),
                (V1_ROOT, V1_ROOT, "req_d3", ""),
            ],
        )
    };
    // The pending cap (six) invalidates the unrelated third family, which
    // closes the global fence for this complete census.
    let mut items = vec![fresh.clone(), v1, peer];
    let disposition = fold(
        &mut items,
        &v1_rows(),
        &mut index,
        true,
        WINDOW,
        6,
        &[FRESH, V1_ROOT, PEER],
    );
    assert!(disposition.duplicate_census.census_invalid);
    assert!(index.claude_duplicate_request_witness_overflowed);
    assert_eq!(
        disposition.posture_admission(FRESH),
        Some("census_verified_fresh_start")
    );
    assert_fresh_scalars(&items[0]);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Emitted));
    // Slice 1 is unchanged for the telemetry-owned member.
    assert_eq!(
        disposition.posture_admission(V1_ROOT),
        Some("member_waiver")
    );

    // A full re-arm under the still closed fence re-parses it: still admitted.
    let mut items = vec![fresh.clone()];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        LATER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH],
    );
    assert!(index.claude_duplicate_request_witness_overflowed);
    assert_fresh_scalars(&items[0]);

    // A transient refusal (telemetry not settled this pass) withholds and
    // owes one corrective parse.
    let mut items = vec![fresh];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        LATER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[],
    );
    assert_cleared(&items[0]);
    assert_eq!(
        state(&index, FRESH),
        Some(ClaudeFreshStartState::ReparseOwed)
    );
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_transient_refusal_owes_exactly_one_corrective_parse() {
    // Every re-arm is spent by its transition, so repeated closed and open
    // windows cannot replay a revision (parent P2).
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-transient");
    let (path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut index = indexed(&[&path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Emitted);
    let rearmed = |index: &ScanIndex| indexed_fingerprint(index, &path).is_empty();
    // The re-parse that a re-arm causes restores the indexed fingerprint.
    let reparsed = |index: &mut ScanIndex| {
        index
            .files
            .get_mut(&local_index_key(&path))
            .expect("indexed")
            .source_file_fingerprint = format!("{FRESH}-fp");
    };
    let window_end = |index: &mut ScanIndex, census_complete: bool, window: &str| {
        fold(
            &mut [],
            &rows(&[], &[]),
            index,
            census_complete,
            window,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            &[],
        )
    };
    // An emitted revision re-parsed while its telemetry is unsettled loses
    // its numbers and is owed one corrective parse.
    let mut items = vec![fresh.clone()];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[],
    );
    assert_cleared(&items[0]);
    assert_eq!(
        state(&index, FRESH),
        Some(ClaudeFreshStartState::ReparseOwed)
    );
    // An incomplete census does not spend it.
    window_end(&mut index, false, WINDOW);
    assert!(!rearmed(&index));
    // The accepted window spends it: exactly one corrective parse.
    let disposition = window_end(&mut index, true, WINDOW);
    assert!(disposition.transcript_ownership_complete);
    assert!(rearmed(&index));
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Verified));

    // The corrective parse is refused again: nothing further is owed, so
    // alternating incomplete and accepted windows never re-arm it.
    reparsed(&mut index);
    let mut items = vec![fresh.clone()];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        LATER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[],
    );
    assert_cleared(&items[0]);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Verified));
    for census_complete in [false, true, false, true] {
        window_end(&mut index, census_complete, LATER_WINDOW);
        assert!(!rearmed(&index), "no replay loop");
        assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Verified));
    }

    // A later parse with settled telemetry admits it; nothing is re-armed.
    let mut items = vec![fresh];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        LATER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH],
    );
    assert_fresh_scalars(&items[0]);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Emitted));
    let disposition = window_end(&mut index, true, LATER_WINDOW);
    assert!(disposition.transcript_ownership_complete);
    assert!(!rearmed(&index));
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn repeated_windows_through_the_real_pipeline_parse_an_unsettled_root_once() {
    // Parent P2 through the scan loop: verification costs one corrective
    // parse; a root whose telemetry never settles is not parsed again.
    let fixture = Fixture::on(&[(FRESH, "2026-08-20T10:00:00Z")]);
    let dir = temp_dir("claude-2c-no-replay");
    write(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut machine = Machine::new(vec![dir.clone()], &[]);
    let (first, _) = machine.pass("2026-08-20T10:30:00Z");
    assert_cleared(item(&first, FRESH));
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Verified)
    );
    let (second, _) = machine.pass("2026-08-20T10:40:00Z");
    assert_cleared(item(&second, FRESH));
    for minute in [50, 55, 59] {
        let (later, _) = machine.pass(&format!("2026-08-20T10:{minute}:00Z"));
        assert!(later.is_empty(), "no replay loop");
    }
    assert_eq!(
        state(&machine.index, FRESH),
        Some(ClaudeFreshStartState::Verified)
    );
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn telemetry_verdicts_and_contradicting_rows_refuse_and_never_rearm() {
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-verdicts");
    let (path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let refused = |reports: (
        crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ),
                   prepare: &dyn Fn(&mut ScanIndex)| {
        let mut index = indexed(&[&path]);
        witness(&mut index, FRESH, ClaudeFreshStartState::Verified);
        prepare(&mut index);
        let mut items = vec![fresh.clone()];
        fold(
            &mut items,
            &reports,
            &mut index,
            false,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            &[FRESH],
        );
        (items.remove(0), index)
    };
    let none = |_: &mut ScanIndex| {};
    // Another root reports one of its requests.
    let (item, index) = refused(rows(&[(OTHER_ROOT, OTHER_ROOT, "req_f2")], &[]), &none);
    assert_cleared(&item);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Refused));
    // Its own root reports it under another session.
    let (item, _) = refused(rows(&[(FRESH, PEER, "req_f2")], &[]), &none);
    assert_cleared(&item);
    // A trace row maps one of its requests to a subagent.
    let (item, _) = refused(rows(&[], &[(FRESH, FRESH, "req_f1", "agent-9")]), &none);
    assert_cleared(&item);
    // A telemetry-refused root (authority quarantine) is never overridden.
    let (item, mut index) = refused(rows(&[], &[]), &|index: &mut ScanIndex| {
        index.claude_usage_authority_quarantine.insert(
            FRESH.to_string(),
            ClaudeUsageAuthorityQuarantineRecord {
                proof_correction: None,
                contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
                proven_witness_fingerprint: "w".to_string(),
                member_source_file_fingerprints: BTreeMap::new(),
                failed_reconstruction_count: 1,
                disposition: ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
                retry_after_unix_seconds: u64::MAX,
            },
        );
    });
    assert_cleared(&item);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Refused));
    // A refused revision is never re-armed by a later accepted window.
    index.claude_usage_authority_quarantine.clear();
    fold(
        &mut [item],
        &rows(&[], &[]),
        &mut index,
        true,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH],
    );
    assert!(!indexed_fingerprint(&index, &path).is_empty());

    // Two rows for one request are the reducer's duplicate refusal (S1).
    let (item, index) = refused(
        rows(&[(FRESH, FRESH, "req_f1"), (FRESH, FRESH, "req_f1")], &[]),
        &none,
    );
    assert_cleared(&item);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Refused));
    let (item, _) = refused(
        rows(
            &[],
            &[(FRESH, FRESH, "req_f1", ""), (FRESH, FRESH, "req_f1", "")],
        ),
        &none,
    );
    assert_cleared(&item);

    // Agreeing rows (this root and session, no agent) refuse nothing (S1).
    let (item, index) = refused(
        rows(&[(FRESH, FRESH, "req_f1")], &[(FRESH, FRESH, "req_f1", "")]),
        &none,
    );
    assert_fresh_scalars(&item);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Emitted));
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unsettled_telemetry_is_a_refusal_not_absence() {
    // SI I3: an unreadable, partial or unpaired sidecar is not "absent".
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-unsettled");
    let (path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut index = indexed(&[&path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Verified);
    let mut items = vec![fresh];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[],
    );
    assert_cleared(&items[0]);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Verified));
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_later_duplicate_revokes_and_rearms_exactly_once() {
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-revoke");
    let (fresh_path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let (copy_path, copy) = parsed(
        &dir,
        PEER,
        &[
            user(PEER, "u_p0", &at(9, 0)),
            assistant(PEER, "req_f2", &at(9, 1), 300),
        ],
    );
    let mut index = indexed(&[&fresh_path, &copy_path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Emitted);
    let mut first_page = vec![fresh.clone()];
    fold(
        &mut first_page,
        &rows(&[], &[]),
        &mut index,
        false,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH, PEER],
    );
    assert_fresh_scalars(&first_page[0]);
    let mut terminal_page = vec![copy];
    fold(
        &mut terminal_page,
        &rows(&[], &[]),
        &mut index,
        true,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH, PEER],
    );
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Revoked));
    assert!(indexed_fingerprint(&index, &fresh_path).is_empty());

    // The corrective body carries no numbers, and no later window re-arms.
    index
        .files
        .get_mut(&local_index_key(&fresh_path))
        .expect("indexed")
        .source_file_fingerprint = format!("{FRESH}-fp");
    let mut corrective = vec![fresh];
    fold(
        &mut corrective,
        &rows(&[], &[]),
        &mut index,
        true,
        LATER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH, PEER],
    );
    assert_cleared(&corrective[0]);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Revoked));
    assert!(!indexed_fingerprint(&index, &fresh_path).is_empty());
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn only_an_accepted_complete_window_verifies() {
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-window");
    let (fresh_path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let (unrelated_path, unrelated) = parsed(
        &dir,
        PEER,
        &[
            user(PEER, "u_p0", &at(9, 0)),
            assistant(PEER, "req_p1", &at(9, 1), 50),
        ],
    );
    let run = |census_complete: bool,
               max_pending: usize,
               prepare: &dyn Fn(&mut ScanIndex)|
     -> ScanIndex {
        let mut index = indexed(&[&fresh_path, &unrelated_path]);
        witness(&mut index, FRESH, ClaudeFreshStartState::Candidate);
        prepare(&mut index);
        let mut items = vec![fresh.clone(), unrelated.clone()];
        fold(
            &mut items,
            &rows(&[], &[]),
            &mut index,
            census_complete,
            WINDOW,
            max_pending,
            &[FRESH, PEER],
        );
        index
    };
    let none = |_: &mut ScanIndex| {};
    // Control: a complete, valid, fully observed window verifies.
    let index = run(true, MAX_CLAUDE_PENDING_USAGE_OCCURRENCES, &none);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Verified));
    // Census incomplete.
    let index = run(false, MAX_CLAUDE_PENDING_USAGE_OCCURRENCES, &none);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Candidate));
    // Complete but invalid: the cap invalidates a family.
    let index = run(true, 3, &none);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Candidate));
    // Complete but an indexed member was not observed this window.
    let index = run(true, MAX_CLAUDE_PENDING_USAGE_OCCURRENCES, &|index| {
        let ghost = dir.join(format!("{OTHER_ROOT}.jsonl"));
        index
            .files
            .insert(local_index_key(&ghost), manifest_index_entry(None));
    });
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Candidate));
    // Complete, but the fence stays closed after the update.
    let index = run(true, MAX_CLAUDE_PENDING_USAGE_OCCURRENCES, &|index| {
        index.claude_duplicate_request_witness_overflowed = true;
        let ghost = dir.join(format!("{OTHER_ROOT}.jsonl"));
        index
            .files
            .insert(local_index_key(&ghost), manifest_index_entry(None));
    });
    assert!(index.claude_duplicate_request_witness_overflowed);
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Candidate));
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_growing_session_restarts_at_candidate_and_waits_for_a_later_window() {
    let fixture = Fixture::on(&[(FRESH, "2026-08-20T10:00:00Z")]);
    let mut census = BTreeMap::new();
    let lines = fresh_lines(FRESH, 0);
    let path = PathBuf::from(format!("/fixture/{FRESH}.jsonl"));
    let dir = temp_dir("claude-2c-growing");
    let (_, item) = parsed(&dir, FRESH, &lines);
    let record = |census: &mut BTreeMap<_, _>, fingerprint: &str| {
        record_claude_fresh_start_candidate(
            census,
            &path,
            std::slice::from_ref(&item),
            &observation(&lines),
            true,
            || Some(ms("2026-08-20T10:00:00Z")),
            fingerprint,
            WINDOW,
        );
    };
    record(&mut census, "fp-1");
    census.get_mut(FRESH).expect("candidate").state = ClaudeFreshStartState::Emitted;
    // Same revision: the state is kept.
    record(&mut census, "fp-1");
    assert_eq!(census[FRESH].state, ClaudeFreshStartState::Emitted);
    // Appended bytes: a new revision restarts at Candidate (no numbers).
    record(&mut census, "fp-2");
    assert_eq!(census[FRESH].state, ClaudeFreshStartState::Candidate);
    assert_eq!(census[FRESH].candidate_source_file_fingerprint, "fp-2");
    // A parser or derivation upgrade is a new revision too (S4 condition 1).
    census.get_mut(FRESH).expect("candidate").state = ClaudeFreshStartState::Verified;
    census
        .get_mut(FRESH)
        .expect("candidate")
        .derivation_revision = "claude_code_jsonl:v39;census_verified_fresh_start:v1".to_string();
    record(&mut census, "fp-2");
    assert_eq!(census[FRESH].state, ClaudeFreshStartState::Candidate);
    // Unverified source bytes or a subagent path never become candidates.
    let mut unverified = census;
    record_claude_fresh_start_candidate(
        &mut unverified,
        &path,
        std::slice::from_ref(&item),
        &observation(&lines),
        false,
        || Some(ms("2026-08-20T10:00:00Z")),
        "fp-2",
        WINDOW,
    );
    assert!(unverified.is_empty());
    let mut subagent = BTreeMap::new();
    record_claude_fresh_start_candidate(
        &mut subagent,
        &PathBuf::from(format!("/fixture/{FRESH}/subagents/agent-x.jsonl")),
        std::slice::from_ref(&item),
        &observation(&lines),
        true,
        || Some(ms("2026-08-20T10:00:00Z")),
        "fp-3",
        WINDOW,
    );
    assert!(subagent.is_empty());
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_shed_corrective_upload_keeps_the_owed_parse() {
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-shed");
    let (path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut index = indexed(&[&path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Candidate);
    fold(
        &mut [fresh.clone()],
        &rows(&[], &[]),
        &mut index,
        true,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH],
    );
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Verified));
    assert!(indexed_fingerprint(&index, &path).is_empty());
    let durable_before_corrective_upload = index.clone();

    let entry = index
        .files
        .get_mut(&local_index_key(&path))
        .expect("indexed");
    entry.source_file_fingerprint = format!("{FRESH}-fp");
    entry.last_snapshot_fingerprint = Some("complete".to_string());
    fold(
        &mut [fresh],
        &rows(&[], &[]),
        &mut index,
        false,
        LATER_WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH],
    );
    assert_eq!(state(&index, FRESH), Some(ClaudeFreshStartState::Emitted));
    let shed = index.committable_subset(
        &durable_before_corrective_upload,
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert_eq!(state(&shed, FRESH), Some(ClaudeFreshStartState::Verified));
    assert!(indexed_fingerprint(&shed, &path).is_empty());
    let accepted = index.committable_subset(
        &durable_before_corrective_upload,
        &BTreeSet::from(["complete".to_string()]),
        &BTreeMap::new(),
    );
    assert_eq!(
        state(&accepted, FRESH),
        Some(ClaudeFreshStartState::Emitted)
    );
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Switch, persistence and identity neutrality.

#[test]
fn switched_off_writes_nothing_and_rearms_emitted_revisions_once() {
    let fixture = Fixture::with(false, &[(FRESH, "2026-08-20T09:59:30Z")]);
    let dir = temp_dir("claude-2c-off");
    write(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut machine = Machine::new(vec![dir.clone()], &[FRESH]);
    let (items, _) = machine.pass("2026-08-20T10:30:00Z");
    assert_cleared(item(&items, FRESH));
    assert!(machine.index.claude_fresh_start_census.is_empty());
    let saved = serde_json::to_value(&machine.index).expect("serialize index");
    assert!(saved.get("claude_fresh_start_census").is_none());
    drop(fixture);

    // SESSION C1: witnesses left by an earlier activation re-arm their
    // emitted revisions once (so the next body uploads without numbers) and
    // are dropped; nothing else is re-armed.
    let fixture = Fixture::with(false, &[]);
    let (fresh_path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let (peer_path, peer) = parsed(&dir, PEER, &fresh_lines(PEER, 0));
    let (other_path, other) = parsed(&dir, OTHER_ROOT, &fresh_lines(OTHER_ROOT, 0));
    let mut index = indexed(&[&fresh_path, &peer_path, &other_path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Emitted);
    witness(&mut index, PEER, ClaudeFreshStartState::Verified);
    witness(&mut index, OTHER_ROOT, ClaudeFreshStartState::Refused);
    let mut items = vec![fresh, peer, other];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        true,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH, PEER, OTHER_ROOT],
    );
    for item in &items {
        assert_cleared(item);
    }
    assert!(index.claude_fresh_start_census.is_empty());
    assert!(indexed_fingerprint(&index, &fresh_path).is_empty());
    assert!(!indexed_fingerprint(&index, &peer_path).is_empty());
    assert!(!indexed_fingerprint(&index, &other_path).is_empty());
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bodies_are_byte_identical_on_and_off_without_a_verified_root() {
    // No root here can be verified: a copy, a telemetry-proven root and a
    // root that shares a request with the copy.
    // One directory for both runs: paths and file times feed the bodies.
    let fork = "51000000-0000-4000-8000-000000000051";
    let dir = temp_dir("claude-2c-on-off");
    write(&dir, FRESH, &fresh_lines(FRESH, 0));
    let mut fork_lines = vec![metadata(fork, "custom-title", "2026-08-20T11:00:00Z")];
    fork_lines.extend(fresh_lines(fork, 0));
    fork_lines.push(assistant(fork, "req_f2", "2026-08-20T11:00:10Z", 1));
    write(&dir, fork, &fork_lines);
    write(&dir, V1_ROOT, &fresh_lines(V1_ROOT, 0));
    let run = |enabled: bool| {
        let fixture = Fixture::with(
            enabled,
            &[
                (FRESH, "2026-08-20T10:00:00Z"),
                (fork, "2026-08-20T11:00:00Z"),
                (V1_ROOT, "2026-08-20T10:00:00Z"),
            ],
        );
        let mut machine = Machine::new(vec![dir.clone()], &[FRESH, fork, V1_ROOT]);
        machine.reports = rows(
            &[
                (V1_ROOT, V1_ROOT, "req_d1"),
                (V1_ROOT, V1_ROOT, "req_d2"),
                (V1_ROOT, V1_ROOT, "req_d3"),
            ],
            &[
                (V1_ROOT, V1_ROOT, "req_d1", ""),
                (V1_ROOT, V1_ROOT, "req_d2", ""),
                (V1_ROOT, V1_ROOT, "req_d3", ""),
            ],
        );
        let mut bodies = Vec::new();
        let mut dispositions = Vec::new();
        for collected_at in ["2026-08-20T11:30:00Z", "2026-08-20T11:40:00Z"] {
            let (items, disposition) = machine.pass(collected_at);
            bodies.push(
                items
                    .iter()
                    .map(|item| serde_json::to_value(item).expect("body"))
                    .collect::<Vec<_>>(),
            );
            dispositions.push((
                disposition.transcript_ownership_complete,
                disposition.duplicate_census,
            ));
        }
        let mut saved = serde_json::to_value(&machine.index).expect("index");
        let witnesses = saved
            .as_object_mut()
            .expect("index object")
            .remove("claude_fresh_start_census");
        drop(fixture);
        (bodies, dispositions, witnesses)
    };
    let (on_bodies, on_census, _) = run(true);
    let (off_bodies, off_census, off_witnesses) = run(false);
    let _ = fs::remove_dir_all(dir);
    assert_eq!(on_bodies, off_bodies);
    // SI I2: census completeness and its settled inputs are unchanged.
    assert_eq!(on_census, off_census);
    assert_eq!(off_witnesses, None);
}

#[test]
fn malformed_or_over_bound_persisted_witnesses_read_as_not_admitted() {
    let mut saved = serde_json::to_value(ScanIndex::default()).expect("index");
    let object = saved.as_object_mut().expect("index object");
    object.insert(
        "claude_fresh_start_census".to_string(),
        serde_json::json!({
            FRESH: {
                "candidate_source_file_fingerprint": "fp",
                "derivation_revision": claude_fresh_start_current_revision(),
                "state": "emitted"
            },
            PEER: {"candidate_source_file_fingerprint": 7, "state": "emitted"},
            OTHER_ROOT: {
                "candidate_source_file_fingerprint": "fp",
                "derivation_revision": "r",
                "state": "from_the_future"
            }
        }),
    );
    let index = serde_json::from_value::<ScanIndex>(saved.clone()).expect("tolerant decode");
    assert_eq!(
        index.claude_fresh_start_census.keys().collect::<Vec<_>>(),
        vec![FRESH]
    );
    saved["claude_fresh_start_census"] = serde_json::json!("not a map");
    let index = serde_json::from_value::<ScanIndex>(saved.clone()).expect("tolerant decode");
    assert!(index.claude_fresh_start_census.is_empty());
    let over_bound = (0..=MAX_CLAUDE_FRESH_START_WITNESSES)
        .map(|n| {
            (
                format!("s{n}"),
                serde_json::json!({
                    "candidate_source_file_fingerprint": "fp",
                    "derivation_revision": "r",
                    "state": "emitted"
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    saved["claude_fresh_start_census"] = Value::Object(over_bound);
    let index = serde_json::from_value::<ScanIndex>(saved).expect("tolerant decode");
    assert!(index.claude_fresh_start_census.is_empty());
}

#[test]
fn admitted_body_differs_from_its_withheld_twin_only_in_context_scalars() {
    // SI I1: identity, attribution and naming inputs never depend on 2c,
    // across the Verified, Emitted, Verified and Refused transitions.
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-body-diff");
    let (path, fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    let fold_once = |state: ClaudeFreshStartState, settled: &[&str]| {
        let mut index = indexed(&[&path]);
        witness(&mut index, FRESH, state);
        let mut items = vec![fresh.clone()];
        fold(
            &mut items,
            &rows(&[], &[]),
            &mut index,
            false,
            WINDOW,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            settled,
        );
        items.remove(0)
    };
    let admitted = fold_once(ClaudeFreshStartState::Verified, &[FRESH]);
    assert_fresh_scalars(&admitted);
    for control in [
        fold_once(ClaudeFreshStartState::Emitted, &[]),
        fold_once(ClaudeFreshStartState::Refused, &[FRESH]),
        fold_once(ClaudeFreshStartState::Candidate, &[FRESH]),
    ] {
        assert_cleared(&control);
        let admitted_body = serde_json::to_value(&admitted).expect("admitted body");
        let control_body = serde_json::to_value(&control).expect("control body");
        let (admitted_body, control_body) = (
            admitted_body.as_object().expect("body object"),
            control_body.as_object().expect("body object"),
        );
        let differing = admitted_body
            .keys()
            .chain(control_body.keys())
            .filter(|key| admitted_body.get(*key) != control_body.get(*key))
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            differing,
            BTreeSet::from([
                "compaction_count",
                "compaction_timestamps",
                "compaction_total_cumulative_dropped_tokens",
                "compaction_total_duration_ms",
                "compaction_total_post_tokens",
                "compaction_total_pre_tokens",
                "first_turn_context_tokens",
                "last_turn_context_tokens",
                "peak_context_fill_tokens",
                // Derived: context posture participates in semantic identity.
                "snapshot_fingerprint",
            ])
        );
        // Naming inputs equal the non-admitted twin's.
        for naming_input in [
            "session_display_name",
            "session_display_name_source",
            "attribution_facts",
            "session_account_evidence",
            "request_evidence",
            "usage_accounting_contract",
            "session_start",
            "provenance",
            "origin",
        ] {
            assert_eq!(
                admitted_body.get(naming_input),
                control_body.get(naming_input),
                "{naming_input} must not depend on 2c"
            );
        }
        assert_eq!(
            admitted.claude_account_withheld_reason,
            control.claude_account_withheld_reason
        );
        assert_eq!(
            admitted.request_identity_refusals,
            control.request_identity_refusals
        );
    }
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Compaction boundaries on a verified root (SESSION Context C2).

#[test]
fn compactions_count_only_after_the_first_owned_response() {
    let fixture = Fixture::on(&[]);
    let dir = temp_dir("claude-2c-compactions");
    // C1 and C2 ride on `fresh_lines` (one boundary before the first
    // response, one after it); C6 pins ordinals that are neither zero nor
    // contiguous.
    let (path, mut fresh) = parsed(&dir, FRESH, &fresh_lines(FRESH, 0));
    for (request_id, sequence) in [("req_f1", 2), ("req_f2", 5), ("req_f3", 9)] {
        fresh
            .claude_usage_occurrences
            .get_mut(request_id)
            .expect("parsed occurrence")
            .sequence = sequence;
    }
    for (observation, response_count_before) in
        fresh.claude_context_curve_boundaries.iter_mut().zip([2, 6])
    {
        observation.response_count_before = response_count_before;
    }
    let mut index = indexed(&[&path]);
    witness(&mut index, FRESH, ClaudeFreshStartState::Verified);
    let mut items = vec![fresh];
    fold(
        &mut items,
        &rows(&[], &[]),
        &mut index,
        false,
        WINDOW,
        MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        &[FRESH],
    );
    // The boundary at the first owned ordinal (2) has no owned response
    // before it; the one at 6 does. Count, timestamps and totals agree.
    assert_eq!(items[0].compaction_count, Some(1));
    assert_eq!(items[0].compaction_total_pre_tokens, Some(20));
    assert_eq!(items[0].compaction_timestamps.len(), 1);
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn an_api_error_response_before_the_first_usage_response_borrows_no_compaction() {
    // C3: a zero-usage API-error response with a request id, then a boundary,
    // then the first usage response.
    let fixture = Fixture::on(&[(FRESH, "2026-08-20T10:00:00Z")]);
    let dir = temp_dir("claude-2c-api-error-first");
    let lines = vec![
        user(FRESH, "u_f0", &at(0, 0)),
        format!(
            "{{\"timestamp\":\"{}\",\"type\":\"assistant\",\"uuid\":\"u_e1\",\"sessionId\":\"{FRESH}\",\"requestId\":\"req_err\",\"isApiErrorMessage\":true,\"message\":{{\"id\":\"msg_err\",\"model\":\"<synthetic>\",\"usage\":{{\"input_tokens\":0,\"output_tokens\":0}}}}}}\n",
            at(0, 1)
        ),
        boundary(FRESH, &at(0, 2), 10),
        assistant(FRESH, "req_f1", &at(0, 3), 100),
        assistant(FRESH, "req_f2", &at(0, 4), 200),
    ];
    write(&dir, FRESH, &lines);
    let mut machine = Machine::new(vec![dir.clone()], &[FRESH]);
    let mut seen = Vec::new();
    for collected_at in ["2026-08-20T10:30:00Z", "2026-08-20T10:40:00Z"] {
        seen.extend(machine.pass(collected_at).0);
    }
    for item in &seen {
        assert!(
            matches!(item.compaction_count, None | Some(0)),
            "a boundary before the first usage response is never counted"
        );
    }
    drop(fixture);
    let _ = fs::remove_dir_all(dir);
}
