//! M1 codec controls on real parses of synthetic transcripts, per source:
//! the privacy canary, restore equality, Restore+Tail against a cold Full,
//! and the crash matrix after a checkpoint. No layout gate: these run on
//! every platform.
use super::*;
use crate::durable_tail_codec::take_l_spans;
use crate::transcript_acquisition::{birth_unix_nanos, FullReason, ReadMode, Scope};
use serde_json::json;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: u64 = 1_790_000_000;
const COLLECTED: &str = "2026-10-20T12:00:00Z";
const CLAUDE_SESSION: &str = "5f0c2a8e-1111-4222-8333-944445555666";
const CODEX_SESSION: &str = "0199f7a0-0000-7000-8000-0000000d7a11";

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ottto-dt-codec-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn write(&self, name: &str, lines: &[String]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scope() -> Scope {
    Scope("durable-codec-test".into())
}

fn apply_for(source: SnapshotSource) -> fn(&Value, &mut SnapshotAccumulator) {
    match source {
        SnapshotSource::Codex => apply_codex_line,
        SnapshotSource::ClaudeCode => apply_claude_code_line,
        SnapshotSource::Pi => apply_pi_line,
    }
}

fn parser(path: &Path, source: SnapshotSource) -> OwnedJsonlParser {
    OwnedJsonlParser::new(
        File::open(path).unwrap(),
        path,
        source,
        apply_for(source),
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap()
}

/// A cold positioned Full read: the retained copy and its checkpoint.
fn full_read(path: &Path, source: SnapshotSource) -> (CachedJsonlReduction, Checkpoint) {
    let mut parser = parser(path, source);
    let mode = parser
        .prepare_acquisition(None, &scope(), None, NOW)
        .unwrap();
    assert!(matches!(mode, ReadMode::Full(_)));
    while !parser.step().unwrap() {}
    let reduction = parser.reduction_copy();
    let checkpoint = match parser.certify_without_retention(&scope(), NOW).unwrap() {
        SideCertificate::Certified { completed, .. } => completed.checkpoint,
        _ => panic!("a clean fixture read is certified"),
    };
    (reduction, checkpoint)
}

/// The finished upload items of a parser that read to completion.
fn items(parser: OwnedJsonlParser, path: &Path, source: SnapshotSource) -> Value {
    let identity = opened_object_identity(source, &mut File::open(path).unwrap()).unwrap();
    let parsed = parser
        .finish(&identity, path, COLLECTED, "fp".into(), None, None, None)
        .unwrap();
    serde_json::to_value(&parsed.snapshots).unwrap()
}

/// The unsampled native oracle: a plain cold parse, no acquisition.
fn cold_items(path: &Path, source: SnapshotSource) -> Value {
    let mut parser = parser(path, source);
    while !parser.step().unwrap() {}
    items(parser, path, source)
}

/// Every encoded class and every content field, for exact equality.
fn full_digest(reduction: &CachedJsonlReduction) -> [u8; 32] {
    let mut e = Enc::hash("durable-codec-test:full");
    reduction.put(&mut e).expect("hash");
    e.finish_hash()
}

fn line_cap() -> u64 {
    jsonl_line_cap() as u64
}

fn restore(
    path: &Path,
    body: &[u8],
    source: SnapshotSource,
) -> Result<(CachedJsonlReduction, RederiveReceipt), Refuse> {
    let decoded = decode(body, source).expect("decode");
    let parser = rederive_parser(File::open(path).unwrap(), path, &decoded).unwrap();
    decoded.rederive(parser, &mut File::open(path).unwrap(), line_cap())
}

/// `pad` filler lines of about `width` bytes each.
fn claude_filler(from: usize, pad: usize, width: usize) -> Vec<String> {
    (from..from + pad)
        .map(|i| {
            json!({"type":"progress","sessionId":CLAUDE_SESSION,
                "timestamp":"2026-10-20T10:00:00Z","uuid":format!("pad-{i}"),
                "data":{"type":"hook_progress","pad":"p".repeat(width)}})
            .to_string()
        })
        .collect()
}

/// A Claude transcript whose first prompt sits between `before` and `after`
/// filler lines (outside both sample windows when each side exceeds 4 KiB).
fn claude_lines(before: usize, after: usize) -> Vec<String> {
    let mut lines = claude_filler(0, before, 512);
    lines.push(
        json!({"type":"user","sessionId":CLAUDE_SESSION,"uuid":"u-1","parentUuid":null,
            "timestamp":"2026-10-20T10:00:01Z","cwd":"/tmp/CANARY_CWD_dt","version":"2.1.0",
            "message":{"role":"user","content":"CANARY_PROMPT_dt please review"}})
        .to_string(),
    );
    lines.extend(claude_filler(before, after, 512));
    lines.push(
        json!({"type":"assistant","sessionId":CLAUDE_SESSION,"uuid":"u-2","parentUuid":"u-1",
            "timestamp":"2026-10-20T10:00:02Z","cwd":"/tmp/CANARY_CWD_dt",
            "requestId":"req_CANARYL1dt",
            "message":{"id":"msg_CANARYL2dt","type":"message","role":"assistant",
                "model":"claude-opus-4-1","stop_reason":"tool_use",
                "content":[{"type":"tool_use","id":"toolu_CANARYL3dt","name":"Bash",
                    "input":{"command":"echo CANARY_INPUT_dt"}}],
                "usage":{"input_tokens":10,"cache_creation_input_tokens":0,
                    "cache_read_input_tokens":0,"output_tokens":5}}})
        .to_string(),
    );
    lines.push(
        json!({"type":"user","sessionId":CLAUDE_SESSION,"uuid":"u-3","parentUuid":"u-2",
            "timestamp":"2026-10-20T10:00:03Z","cwd":"/tmp/CANARY_CWD_dt",
            "message":{"role":"user","content":[{"type":"tool_result",
                "tool_use_id":"toolu_CANARYL3dt","content":"CANARY_OUTPUT_dt"}]}})
        .to_string(),
    );
    lines.push(
        json!({"type":"ai-title","sessionId":CLAUDE_SESSION,"aiTitle":"CANARY_TITLE_dt"})
            .to_string(),
    );
    lines
}

fn claude_append() -> String {
    json!({"type":"assistant","sessionId":CLAUDE_SESSION,"uuid":"u-4","parentUuid":"u-3",
        "timestamp":"2026-10-20T10:00:04Z","cwd":"/tmp/CANARY_CWD_dt",
        "requestId":"req_CANARYL4dt",
        "message":{"id":"msg_CANARYL5dt","type":"message","role":"assistant",
            "model":"claude-opus-4-1","stop_reason":"end_turn",
            "content":[{"type":"text","text":"CANARY_ANSWER_dt"}],
            "usage":{"input_tokens":20,"cache_creation_input_tokens":0,
                "cache_read_input_tokens":10,"output_tokens":7}}})
    .to_string()
}

fn codex_usage(input: u64) -> Value {
    json!({"input_tokens":input,"cached_input_tokens":0,"output_tokens":3,
        "reasoning_output_tokens":0,"total_tokens":input + 3})
}

fn codex_lines() -> Vec<String> {
    let at = "2026-10-20T10:00:00Z";
    vec![
        json!({"type":"session_meta","timestamp":at,"payload":{"id":CODEX_SESSION,
            "timestamp":at,"cwd":"/tmp/CANARY_CWD_cx","originator":"codex_cli_rs",
            "cli_version":"0.50.0","source":"cli"}}),
        json!({"type":"turn_context","timestamp":at,
            "payload":{"turn_id":"turn-1","cwd":"/tmp/CANARY_CWD_cx","model":"gpt-5.2"}}),
        json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"task_started","turn_id":"turn-1"}}),
        json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"user_message","message":"CANARY_PROMPT_cx do it"}}),
        json!({"type":"response_item","timestamp":at,"payload":{"type":"function_call",
            "name":"shell","arguments":"{\"command\":[\"echo\",\"CANARY_ARGS_cx\"]}",
            "call_id":"call_CANARYL1cx"}}),
        json!({"type":"response_item","timestamp":at,"payload":{"type":"function_call_output",
            "call_id":"call_CANARYL1cx","output":"CANARY_OUT_cx"}}),
        json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"thread_name_updated","thread_name":"CANARY_TITLE_cx"}}),
        json!({"type":"event_msg","timestamp":"2026-10-20T10:00:01Z","payload":{"type":"token_count",
            "info":{"last_token_usage":codex_usage(100),"total_token_usage":codex_usage(100)}}}),
        json!({"type":"event_msg","timestamp":"2026-10-20T10:00:02Z",
            "payload":{"type":"task_complete","turn_id":"turn-1"}}),
    ]
    .into_iter()
    .map(|line| line.to_string())
    .collect()
}

fn codex_append() -> Vec<String> {
    let at = "2026-10-20T10:01:00Z";
    vec![
        json!({"type":"turn_context","timestamp":at,
            "payload":{"turn_id":"turn-2","cwd":"/tmp/CANARY_CWD_cx","model":"gpt-5.2"}}),
        json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"task_started","turn_id":"turn-2"}}),
        json!({"type":"event_msg","timestamp":at,"payload":{"type":"token_count",
            "info":{"last_token_usage":codex_usage(50),"total_token_usage":codex_usage(150)}}}),
        json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"task_complete","turn_id":"turn-2"}}),
    ]
    .into_iter()
    .map(|line| line.to_string())
    .collect()
}

struct Case {
    source: SnapshotSource,
    lines: Vec<String>,
    appended: Vec<String>,
    content: &'static [&'static str],
    provider_ids: &'static [&'static str],
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            source: SnapshotSource::ClaudeCode,
            lines: claude_lines(10, 10),
            appended: vec![claude_append()],
            content: &[
                "CANARY_PROMPT_dt",
                "CANARY_CWD_dt",
                "CANARY_INPUT_dt",
                "CANARY_OUTPUT_dt",
                "CANARY_TITLE_dt",
                "pppppppppppppppp",
            ],
            provider_ids: &["req_CANARYL1dt", "msg_CANARYL2dt", "toolu_CANARYL3dt"],
        },
        Case {
            source: SnapshotSource::Codex,
            lines: codex_lines(),
            appended: codex_append(),
            content: &[
                "CANARY_PROMPT_cx",
                "CANARY_CWD_cx",
                "CANARY_ARGS_cx",
                "CANARY_OUT_cx",
                "CANARY_TITLE_cx",
            ],
            provider_ids: &["call_CANARYL1cx"],
        },
    ]
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(at, _)| at)
        .collect()
}

/// Privacy canary (Amendment 1): no content of any kind is in the body; a
/// raw provider id (class `L`) appears only inside an `L` field's bytes.
#[test]
fn record_body_holds_no_content_and_provider_ids_only_in_l_fields() {
    for case in cases() {
        let scratch = Scratch::new("canary");
        let path = scratch.write("t.jsonl", &case.lines);
        let (reduction, _) = full_read(&path, case.source);
        take_l_spans();
        let body = encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        )
        .unwrap_or_else(|refuse| panic!("{:?} not persisted: {refuse:?}", case.source));
        let spans = take_l_spans();
        let path_text = path.to_string_lossy();
        for canary in case.content.iter().copied().chain([path_text.as_ref()]) {
            assert!(
                occurrences(&body, canary.as_bytes()).is_empty(),
                "{:?}: content {canary:?} reached the record body",
                case.source
            );
        }
        for id in case.provider_ids {
            for at in occurrences(&body, id.as_bytes()) {
                let end = at + id.len();
                assert!(
                    spans
                        .iter()
                        .any(|(start, stop, _)| *start <= at && end <= *stop),
                    "{:?}: provider id {id:?} at {at} outside every L field {spans:?}",
                    case.source
                );
            }
        }
    }
}

/// Decode plus bounded re-derivation gives back exactly the retained copy,
/// content fields included, within the head bound and named-line budget.
#[test]
fn restore_rederives_the_exact_retained_copy() {
    for case in cases() {
        let scratch = Scratch::new("exact");
        let path = scratch.write("t.jsonl", &case.lines);
        let (reduction, _) = full_read(&path, case.source);
        let body = encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        )
        .unwrap();
        let (restored, receipt) = restore(&path, &body, case.source).unwrap();
        assert_eq!(
            full_digest(&restored),
            full_digest(&reduction),
            "{:?}",
            case.source
        );
        assert!(restored.accumulator.title.is_some(), "{:?}", case.source);
        assert!(
            restored.accumulator.first_prompt_title.is_some(),
            "{:?}",
            case.source
        );
        assert!(receipt.head_bytes <= HEAD_BOUND);
        assert!(receipt.named_lines as usize <= NAMED_LINES);
        assert!(receipt.line_bytes <= line_cap());
    }
}

/// Full-equivalence control per source: a restored copy continued by Tail
/// finishes to the same upload items as a cold Full of the grown file.
#[test]
fn restore_then_tail_matches_cold_full() {
    for case in cases() {
        let scratch = Scratch::new("tail");
        let path = scratch.write("t.jsonl", &case.lines);
        let (reduction, checkpoint) = full_read(&path, case.source);
        let body = encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        )
        .unwrap();
        let birth = birth_unix_nanos(&fs::metadata(&path).unwrap());
        let certificate = checkpoint.durable_certificate(birth).unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        for line in &case.appended {
            writeln!(file, "{line}").unwrap();
        }
        drop(file);
        let mut held = File::open(&path).unwrap();
        let (checkpoint, _) = certificate.restore(&mut held, scope()).unwrap();
        let (restored, _) = restore(&path, &body, case.source).unwrap();
        let mut continued = parser(&path, case.source);
        let mode = continued
            .prepare_acquisition(
                Some(Retained {
                    checkpoint,
                    state: restored,
                }),
                &scope(),
                None,
                NOW,
            )
            .unwrap();
        assert_eq!(mode, ReadMode::Tail, "{:?}", case.source);
        while !continued.step().unwrap() {}
        assert_eq!(
            items(continued, &path, case.source),
            cold_items(&path, case.source),
            "{:?}",
            case.source
        );
    }
}

/// A metadata-only touch (ctime moves, bytes and mtime do not) still
/// restores, and the restored checkpoint reads as Unchanged.
#[test]
fn metadata_only_touch_restores_unchanged() {
    for case in cases() {
        let scratch = Scratch::new("touch");
        let path = scratch.write("t.jsonl", &case.lines);
        let (reduction, checkpoint) = full_read(&path, case.source);
        let body = encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        )
        .unwrap();
        let birth = birth_unix_nanos(&fs::metadata(&path).unwrap());
        let certificate = checkpoint.durable_certificate(birth).unwrap();
        let before = fs::metadata(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_ne!(
            (before.ctime(), before.ctime_nsec()),
            (after.ctime(), after.ctime_nsec())
        );
        let (checkpoint, admission) = certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .unwrap();
        assert!(admission.unchanged);
        let (restored, _) = restore(&path, &body, case.source).unwrap();
        let mut continued = parser(&path, case.source);
        let mode = continued
            .prepare_acquisition(
                Some(Retained {
                    checkpoint,
                    state: restored,
                }),
                &scope(),
                None,
                NOW,
            )
            .unwrap();
        assert_eq!(mode, ReadMode::Unchanged, "{:?}", case.source);
    }
}

/// Rewrites `[at, at + bytes.len())` in place and puts the mtime back: a
/// same-size edit only content can reveal.
fn edit_in_place(path: &Path, at: u64, bytes: &[u8]) {
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(bytes).unwrap();
    file.set_modified(modified).unwrap();
}

/// Crash matrix after a checkpoint, with real records: truncate, replace,
/// a same-size edit in a sample window, and a same-size edit of a
/// re-derived field outside both windows. Each ends in a Full read with
/// nothing restored.
#[test]
fn edits_after_the_checkpoint_refuse_restore() {
    let source = SnapshotSource::ClaudeCode;
    // The first prompt sits past the 4 KiB head window and before the
    // boundary window.
    let lines = claude_lines(12, 12);
    let prompt_at = lines[..12]
        .iter()
        .map(|line| line.len() as u64 + 1)
        .sum::<u64>();
    let record = |scratch: &Scratch| {
        let path = scratch.write("t.jsonl", &lines);
        let (reduction, checkpoint) = full_read(&path, source);
        let body = encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        )
        .unwrap();
        let birth = birth_unix_nanos(&fs::metadata(&path).unwrap());
        (path, body, checkpoint.durable_certificate(birth).unwrap())
    };

    let scratch = Scratch::new("truncate");
    let (path, _, certificate) = record(&scratch);
    let len = fs::metadata(&path).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len - 10)
        .unwrap();
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .err(),
        Some(FullReason::Shrunk)
    );

    let scratch = Scratch::new("replace");
    let (path, _, certificate) = record(&scratch);
    let replacement = scratch.write("next.jsonl", &lines);
    fs::rename(&replacement, &path).unwrap();
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .err(),
        Some(FullReason::Replaced)
    );

    let scratch = Scratch::new("head-edit");
    let (path, _, certificate) = record(&scratch);
    edit_in_place(&path, 100, b"q");
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .err(),
        Some(FullReason::HeadChanged)
    );

    let scratch = Scratch::new("prompt-edit");
    let (path, body, certificate) = record(&scratch);
    let line = fs::read(&path).unwrap();
    let offset =
        prompt_at + occurrences(&line[prompt_at as usize..], b"CANARY_PROMPT_dt")[0] as u64;
    edit_in_place(&path, offset, b"X");
    // Samples cannot see it: the certificate admits, re-derivation refuses.
    certificate
        .restore(&mut File::open(&path).unwrap(), scope())
        .unwrap();
    assert_eq!(
        restore(&path, &body, source).err(),
        Some(Refuse::NotRederivable(
            "SnapshotAccumulator.first_prompt_material"
        ))
    );
}

/// The allowlist digests, pinned: any field, class or type change in a
/// persisted type moves them. Review the classes with SOURCE, then repin.
const ALLOWLIST_PINS: [(SnapshotSource, &str); 2] = [
    (SnapshotSource::ClaudeCode, "unpinned"),
    (SnapshotSource::Codex, "unpinned"),
];

fn hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn allowlist_digests_are_pinned() {
    let actual = ALLOWLIST_PINS.map(|(source, _)| (source, hex(allowlist_digest(source))));
    assert_eq!(
        ALLOWLIST_PINS.map(|(source, pin)| (source, pin.to_string())),
        actual,
        "allowlist changed: review the field classes with SOURCE, then repin"
    );
}

/// The allowlist binds the source, the bounds and every persisted type's
/// field list and classes.
#[test]
fn allowlist_digest_binds_source_and_field_classes() {
    assert_ne!(
        allowlist_digest(SnapshotSource::ClaudeCode),
        allowlist_digest(SnapshotSource::Codex)
    );
    let text = shape_text();
    for line in [
        "D accumulator",
        "X title",
        "X first_prompt_material",
        "X workspace_path",
        "E provider_skills",
        "E activity_skills",
        "I codex_turn_traces",
        "L activity_call_tools",
        "L activity_mcp_call_ids",
        "D durable_marks",
        "H title",
    ] {
        assert!(
            text.split(';')
                .map(|part| part.trim_start_matches(['{', '}']))
                .any(|part| part == line || part.starts_with(&format!("{line}:"))),
            "{line:?} missing from the allowlist shape"
        );
    }
}
