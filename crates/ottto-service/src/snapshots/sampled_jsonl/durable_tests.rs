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

/// The finished upload items of a parser that read to completion. Claude
/// finishes with the money context the scan passes (the E2 fold's read
/// context over an index holding the file), so the money fold is compared
/// too.
fn items(parser: OwnedJsonlParser, path: &Path, source: SnapshotSource) -> Value {
    items_at(parser, path, source, None)
}

/// `items`, through the shared native body with an M3 PRE-finalization hook
/// (`None`: the legacy wrapper itself).
fn items_at(
    parser: OwnedJsonlParser,
    path: &Path,
    source: SnapshotSource,
    pre: Option<&mut dyn FnMut(crate::snapshots::PreFinalization<'_>)>,
) -> Value {
    let identity = opened_object_identity(source, &mut File::open(path).unwrap()).unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(
        local_index_key(path),
        serde_json::from_value(
            json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"}),
        )
        .unwrap(),
    );
    let twins = Default::default();
    let money =
        (source == SnapshotSource::ClaudeCode).then_some(claude_request_money::e2::ReadContext {
            index: &index,
            path,
            twins: &twins,
        });
    let parsed = match pre {
        None => parser.finish_with_repository_identity(
            &identity,
            path,
            COLLECTED,
            "fp".into(),
            None,
            None,
            None,
            None,
            money,
        ),
        Some(pre) => parser.finish_native(
            crate::snapshots::FinishRequest {
                expected_opened_object_identity: &identity,
                path,
                collected_at: COLLECTED,
                source_file_fingerprint: "fp".into(),
                codex_title_metadata: None,
                claude_title_metadata: None,
                attribution_context: None,
                repository_identity: None,
                money_context: money,
            },
            Some(pre),
        ),
    }
    .unwrap();
    // The fold is not serialized (`serde(skip)`): compare its entity body.
    let money = parsed
        .snapshots
        .iter()
        .map(|item| {
            item.claude_money
                .as_deref()
                .map(|fold| format!("{:?}", fold.entity))
        })
        .collect::<Vec<_>>();
    if source == SnapshotSource::ClaudeCode {
        assert!(money.iter().all(Option::is_some), "the money fold ran");
    }
    json!({"items": serde_json::to_value(&parsed.snapshots).unwrap(), "money": money})
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
        // Open at the seal: a call and an MCP call with no output yet, so
        // both call maps hold ids when the record is written.
        json!({"type":"response_item","timestamp":at,"payload":{"type":"function_call",
            "name":"shell","arguments":"{\"command\":[\"echo\",\"CANARY_OPEN_cx\"]}",
            "call_id":"call_CANARYL2cx"}}),
        json!({"type":"response_item","timestamp":at,"payload":{"type":"function_call",
            "namespace":"mcp__canarysrv","name":"mcp__canarysrv__lookup",
            "arguments":"{\"q\":\"CANARY_MCPARGS_cx\"}","call_id":"call_CANARYL3cx"}}),
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

/// Private instruction text (Claude instructions attachment and its
/// request-1 blob), around a plain session. The request-shape and blob keys
/// depend on the secret too, so a raw key reaching the body would show as
/// the secret (SOURCE P2-5).
fn claude_instruction_lines(secret: &str) -> Vec<String> {
    let mut lines = vec![
        json!({"type":"attachment","sessionId":CLAUDE_SESSION,"uuid":"a-1",
        "timestamp":"2026-10-20T10:00:00Z","attachment":{"type":"instructions","files":[
            {"type":"Project","content":format!("Project rules: {secret}")}]}})
        .to_string(),
    ];
    let mut session = claude_lines(2, 2);
    let request = [
        json!({"type":"api-request-shape","sessionId":CLAUDE_SESSION,"shapeHash":shape_key(secret),
            "shape":{"system":[{"type":"text","text":"You are Claude."}],"tools":[{"name":"Bash"}]}}),
        json!({"type":"api-request-blob","sessionId":CLAUDE_SESSION,"hash":blob_key(secret),
            "message":{"role":"user","content":[
                {"type":"text","text":format!(
                    "<system-reminder>\nCodebase and user instructions Project rules: {secret}")},
                {"type":"text","text":"CANARY_PROMPT_dt please review"}]}}),
        json!({"type":"api-request","sessionId":CLAUDE_SESSION,"shapeHash":shape_key(secret),
            "tail":[blob_key(secret)]}),
    ];
    // Before the first assistant line (two fillers, the prompt, two fillers).
    session.splice(5..5, request.iter().map(Value::to_string));
    lines.extend(session);
    lines
}

fn shape_key(secret: &str) -> String {
    format!("shape-{secret}")
}

fn blob_key(secret: &str) -> String {
    format!("blob-{secret}")
}

/// `claude_instruction_lines` cut before its `api-request`: the request-1
/// window still holds the shape and blob, keyed by the secret, at the seal.
fn claude_held_request_lines(secret: &str) -> Vec<String> {
    let mut lines = claude_instruction_lines(secret);
    let blob = lines
        .iter()
        .position(|line| line.contains("\"api-request-blob\""))
        .expect("blob line");
    lines.truncate(blob + 1);
    lines
}

/// Private AGENTS.md text, injected as a labeled request-1 user block.
fn codex_instruction_lines(secret: &str) -> Vec<String> {
    let mut lines = codex_lines();
    lines.insert(
        2,
        json!({"type":"response_item","timestamp":"2026-10-20T10:00:00Z","payload":{
            "type":"message","role":"user","content":[{"type":"input_text","text":format!(
                "# AGENTS.md instructions for /tmp/CANARY_CWD_cx\n\n<INSTRUCTIONS>\n{secret}\n</INSTRUCTIONS>")}],
            "internal_chat_message_metadata_passthrough":{
                "content_item_kinds":[crate::codex_prelude_footprint::AGENTS_MD_KIND]}}})
        .to_string(),
    );
    lines
}

const CANARY_EMAIL: &str = "canary.person@example-org.test";
const CANARY_ORG: &str = "6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

/// An email context and an org marker ahead of a plain session.
fn claude_org_lines() -> Vec<String> {
    let mut lines = vec![
        json!({"type":"attachment","sessionId":CLAUDE_SESSION,"uuid":"a-1",
            "timestamp":"2026-10-20T10:00:00Z",
            "attachment":{"type":"session_context","context":{"userEmail":CANARY_EMAIL}}})
        .to_string(),
        json!({"type":"attachment","sessionId":CLAUDE_SESSION,"uuid":"a-2",
            "timestamp":"2026-10-20T10:00:00Z",
            "attachment":{"type":"credential_org","organizationUuid":CANARY_ORG}})
        .to_string(),
    ];
    lines.extend(claude_lines(2, 2));
    lines
}

struct Case {
    source: SnapshotSource,
    lines: Vec<String>,
    appended: Vec<String>,
    content: &'static [&'static str],
    provider_ids: &'static [&'static str],
    /// Provider ids the sealed reduction still holds: each must be in the
    /// body, inside its own leaf `L` field.
    survivors: &'static [&'static str],
}

const CLAUDE_CONTENT: [&str; 6] = [
    "CANARY_PROMPT_dt",
    "CANARY_CWD_dt",
    "CANARY_INPUT_dt",
    "CANARY_OUTPUT_dt",
    "CANARY_TITLE_dt",
    "pppppppppppppppp",
];
const CLAUDE_IDS: [&str; 3] = ["req_CANARYL1dt", "msg_CANARYL2dt", "toolu_CANARYL3dt"];
const CODEX_IDS: [&str; 3] = ["call_CANARYL1cx", "call_CANARYL2cx", "call_CANARYL3cx"];

/// The canary matrix: plain sessions, private instruction text on both
/// sources (its reversible `ConfigDigest` included), and an email context
/// with an org marker. Artifacts and skill names are `E` (Full, never
/// stored): `e_class_canaries_never_persist`.
fn cases() -> Vec<Case> {
    const CODEX_CONTENT: &[&str] = &[
        "CANARY_PROMPT_cx",
        "CANARY_CWD_cx",
        "CANARY_ARGS_cx",
        "CANARY_OUT_cx",
        "CANARY_TITLE_cx",
        "CANARY_OPEN_cx",
        "CANARY_MCPARGS_cx",
    ];
    vec![
        Case {
            source: SnapshotSource::ClaudeCode,
            lines: claude_lines(10, 10),
            appended: vec![claude_append()],
            content: &CLAUDE_CONTENT,
            provider_ids: &CLAUDE_IDS,
            survivors: &["req_CANARYL1dt"],
        },
        Case {
            source: SnapshotSource::Codex,
            lines: codex_lines(),
            appended: codex_append(),
            content: CODEX_CONTENT,
            provider_ids: &CODEX_IDS,
            survivors: &["call_CANARYL2cx", "call_CANARYL3cx"],
        },
        Case {
            source: SnapshotSource::ClaudeCode,
            lines: claude_instruction_lines("CANARY_INSTR_A_dt"),
            appended: vec![claude_append()],
            content: &[
                "CANARY_INSTR_A_dt",
                "Project rules",
                "CANARY_PROMPT_dt",
                "CANARY_CWD_dt",
                "CANARY_TITLE_dt",
            ],
            provider_ids: &CLAUDE_IDS,
            survivors: &["req_CANARYL1dt"],
        },
        Case {
            source: SnapshotSource::Codex,
            lines: codex_instruction_lines("CANARY_INSTR_A_cx"),
            appended: codex_append(),
            content: &[
                "CANARY_INSTR_A_cx",
                "AGENTS.md",
                "CANARY_PROMPT_cx",
                "CANARY_CWD_cx",
            ],
            provider_ids: &CODEX_IDS,
            survivors: &["call_CANARYL2cx", "call_CANARYL3cx"],
        },
        Case {
            source: SnapshotSource::ClaudeCode,
            lines: claude_org_lines(),
            appended: vec![claude_append()],
            content: &[
                CANARY_EMAIL,
                "canary.person",
                "example-org",
                CANARY_ORG,
                "6a1b2c3d4e5f",
                "CANARY_PROMPT_dt",
                "CANARY_TITLE_dt",
            ],
            provider_ids: &CLAUDE_IDS,
            survivors: &["req_CANARYL1dt"],
        },
    ]
}

/// The leaf `L` fields each kind of provider id may sit in.
fn id_leaves(id: &str) -> &'static [&'static str] {
    if id.starts_with("toolu_") {
        &[
            "ClaudeToolUse.id",
            "SnapshotAccumulator.seen_claude_capability_tool_uses",
            "OpeningCallId.id",
        ]
    } else if id.starts_with("call_") {
        &[
            "ActivityCallId.id",
            "SnapshotAccumulator.activity_mcp_call_ids",
            "OpeningCallId.id",
            "SessionStartState.last_codex_call",
        ]
    } else {
        // Request and message ids.
        &[
            "CompactClaudeResponseRecord.request_id",
            "RequestSlot.request_ref",
            "ClaudeResponseBook.index",
        ]
    }
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(at, _)| at)
        .collect()
}

/// Privacy canary (Amendment 1, F4): no content of any kind is in the body;
/// every raw provider id (class `L`) sits inside the innermost `L` span of a
/// leaf field for its kind (`id_leaves`), never merely inside an enclosing
/// span; and the ids a sealed reduction still holds (open Codex call and MCP
/// maps, Claude request ids) do survive into the body.
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
            let found = occurrences(&body, id.as_bytes());
            if case.survivors.contains(id) {
                assert!(
                    !found.is_empty(),
                    "{:?}: provider id {id:?} held at the seal is missing from the body",
                    case.source
                );
            }
            for at in found {
                let end = at + id.len();
                let leaf = spans
                    .iter()
                    .filter(|(start, stop, _)| *start <= at && end <= *stop)
                    .min_by_key(|(start, stop, _)| stop - start)
                    .map(|(_, _, path)| *path);
                assert!(
                    leaf.is_some_and(|leaf| id_leaves(id).contains(&leaf)),
                    "{:?}: provider id {id:?} at {at} in {leaf:?}, not a leaf L field for it",
                    case.source
                );
            }
        }
    }
}

/// F1 instruction canary, per source: two sessions (one file rewritten in
/// place) differing only in private instruction text of equal length. Their retained copies differ
/// (the text and its reversible `ConfigDigest` are content), yet the
/// encoded reductions are byte-identical (nothing derived from the text is
/// stored; only the verified content hash in the re-derivation marks
/// differs), and each restores to its exact copy (the digest is re-derived
/// from the head).
#[test]
fn instruction_text_and_its_config_digest_never_reach_the_body() {
    type Build = fn(&str) -> Vec<String>;
    for (source, build, secrets) in [
        (
            SnapshotSource::ClaudeCode,
            claude_instruction_lines as Build,
            ["CANARY_INSTR_A_dt", "CANARY_INSTR_B_dt"],
        ),
        (
            SnapshotSource::Codex,
            codex_instruction_lines as Build,
            ["CANARY_INSTR_A_cx", "CANARY_INSTR_B_cx"],
        ),
    ] {
        let mut reductions = Vec::new();
        let mut retained = Vec::new();
        // One file rewritten in place: the same inode and birth, which the
        // Claude birth scope records.
        let scratch = Scratch::new("instructions");
        for secret in secrets {
            let path = scratch.write("t.jsonl", &build(secret));
            let (reduction, _) = full_read(&path, source);
            let body = encode(
                &reduction,
                crate::durable_tail_store::RECORD_BYTES,
                line_cap(),
            )
            .unwrap_or_else(|refuse| panic!("{source:?} not persisted: {refuse:?}"));
            assert!(
                occurrences(&body, secret.as_bytes()).is_empty(),
                "{source:?}"
            );
            let (restored, _) = restore(&path, &body, source).unwrap();
            assert_eq!(
                full_digest(&restored),
                full_digest(&reduction),
                "{source:?}"
            );
            let mut e = Enc::bytes(crate::durable_tail_store::RECORD_BYTES);
            reduction.put(&mut e).unwrap();
            reductions.push(e.into_bytes());
            retained.push(full_digest(&reduction));
        }
        assert_ne!(
            retained[0], retained[1],
            "{source:?}: the fixture must carry its instruction text"
        );
        assert_eq!(
            reductions[0], reductions[1],
            "{source:?}: something derived from instruction text reached the body"
        );
    }
}

/// F4: an email context is stored only as its domain-separated SHA-256 (32
/// bytes, once), never as the address or its plain SHA-256.
#[test]
fn org_marker_email_is_stored_only_as_a_domain_separated_digest() {
    use sha2::Digest as _;
    let scratch = Scratch::new("org");
    let path = scratch.write("t.jsonl", &claude_org_lines());
    let (reduction, _) = full_read(&path, SnapshotSource::ClaudeCode);
    let body = encode(
        &reduction,
        crate::durable_tail_store::RECORD_BYTES,
        line_cap(),
    )
    .unwrap();
    let plain: [u8; 32] = sha2::Sha256::digest(CANARY_EMAIL.as_bytes()).into();
    let separated: [u8; 32] = sha2::Sha256::new()
        .chain_update(b"ottto-claude-org-marker-context:v1\0")
        .chain_update(CANARY_EMAIL.as_bytes())
        .finalize()
        .into();
    assert!(occurrences(&body, &plain).is_empty());
    assert!(occurrences(&body, hex(plain).as_bytes()).is_empty());
    assert!(occurrences(&body, hex(separated).as_bytes()).is_empty());
    assert_eq!(occurrences(&body, &separated).len(), 1);
}

/// F4 matrix, `E` classes: an artifact or a skill name refuses the record
/// (the entry reads Full), so neither is ever stored.
#[test]
fn e_class_canaries_never_persist() {
    let scratch = Scratch::new("artifact");
    let path = scratch.write("t.jsonl", &claude_lines(1, 1));
    let (mut reduction, _) = full_read(&path, SnapshotSource::ClaudeCode);
    reduction.accumulator.artifacts.push(SessionArtifact {
        kind: "pull_request".into(),
        value: "https://example.test/CANARY_ARTIFACT/pull/1".into(),
    });
    assert_eq!(
        encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap()
        )
        .err(),
        Some(Refuse::NonEmpty("SnapshotAccumulator.artifacts"))
    );
    let mut skill = claude_lines(1, 1);
    skill.push(
        json!({"type":"assistant","sessionId":CLAUDE_SESSION,"uuid":"u-9","parentUuid":"u-3",
            "timestamp":"2026-10-20T10:00:09Z","requestId":"req_skill",
            "message":{"id":"msg_skill","type":"message","role":"assistant",
                "model":"claude-opus-4-1","stop_reason":"tool_use",
                "content":[{"type":"tool_use","id":"toolu_skill","name":"Bash",
                    "input":{"command":"cat ~/.claude/skills/canary-skill/SKILL.md"}}],
                "usage":{"input_tokens":1,"cache_creation_input_tokens":0,
                    "cache_read_input_tokens":0,"output_tokens":1}}})
        .to_string(),
    );
    let scratch = Scratch::new("skill");
    let path = scratch.write("t.jsonl", &skill);
    let (reduction, _) = full_read(&path, SnapshotSource::ClaudeCode);
    assert_eq!(
        encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap()
        )
        .err(),
        Some(Refuse::NonEmpty("SnapshotAccumulator.activity_skills"))
    );
}

/// SOURCE P2-5: request-shape and blob keys (client content hashes of
/// instruction text) are stored only as their domain-separated SHA-256 (`H`),
/// never raw, whatever the key holds. The fixture seals with the request-1
/// window still holding both, keyed by the secret, so a raw key would show as
/// the secret; the separated digests are each in the body exactly once, and
/// the copy restores exactly.
#[test]
fn request_shape_and_blob_keys_are_stored_only_as_domain_separated_digests() {
    use sha2::Digest as _;
    let secret = "CANARY_KEYSECRET_dt";
    let scratch = Scratch::new("request-keys");
    let path = scratch.write("t.jsonl", &claude_held_request_lines(secret));
    let (reduction, _) = full_read(&path, SnapshotSource::ClaudeCode);
    let body = encode(
        &reduction,
        crate::durable_tail_store::RECORD_BYTES,
        line_cap(),
    )
    .unwrap();
    assert!(occurrences(&body, secret.as_bytes()).is_empty());
    for (domain, raw) in [
        (&b"ottto-dt-claude-shape-key:v1\0"[..], shape_key(secret)),
        (&b"ottto-dt-claude-blob-key:v1\0"[..], blob_key(secret)),
    ] {
        let plain: [u8; 32] = sha2::Sha256::digest(raw.as_bytes()).into();
        let separated: [u8; 32] = sha2::Sha256::new()
            .chain_update(domain)
            .chain_update(raw.as_bytes())
            .finalize()
            .into();
        assert!(occurrences(&body, raw.as_bytes()).is_empty(), "{raw}");
        assert!(occurrences(&body, &plain).is_empty(), "{raw}");
        assert!(occurrences(&body, hex(separated).as_bytes()).is_empty());
        assert_eq!(occurrences(&body, &separated).len(), 1, "{raw}");
    }
    let (restored, _) = restore(&path, &body, SnapshotSource::ClaudeCode).unwrap();
    assert_eq!(full_digest(&restored), full_digest(&reduction));
}

/// SOURCE P2-5: an open Codex call is `{L id, U name}`. The encoded map's
/// only `L` span is the id, so an id copied into the name half would sit
/// outside every `L` span and fail the canary.
#[test]
fn open_call_l_span_is_the_id_alone() {
    use crate::snapshots::{ActivityCallId, ActivityCallTool};
    let map = BTreeMap::from([(
        ActivityCallId {
            id: "call_CANARYSPLITcx".into(),
        },
        ActivityCallTool {
            name: "call_NAMEHALFcx".into(),
        },
    )]);
    take_l_spans();
    let mut e = Enc::bytes(1 << 10);
    map.put(&mut e).unwrap();
    let body = e.into_bytes();
    let spans = take_l_spans();
    assert_eq!(spans.len(), 1, "{spans:?}");
    let (start, end, path) = spans[0];
    assert_eq!(path, "ActivityCallId.id");
    let id = occurrences(&body, b"call_CANARYSPLITcx")[0];
    assert!(start <= id && id + "call_CANARYSPLITcx".len() <= end);
    let name = occurrences(&body, b"call_NAMEHALFcx")[0];
    assert!(name >= end || name + "call_NAMEHALFcx".len() <= start);
}

/// P2-1 (SOURCE): a selector context holding any attribution capture key
/// (raw skill, plugin, MCP or subagent names) is `E`: the record is refused
/// under its own counted class and the entry reads Full. Any other context
/// key persists (`U`).
#[test]
fn attribution_selector_context_refuses_the_record() {
    let scratch = Scratch::new("attribution");
    let path = scratch.write("t.jsonl", &claude_lines(1, 1));
    let (plain, _) = full_read(&path, SnapshotSource::ClaudeCode);
    let mut kept = plain.clone();
    kept.accumulator.current_selector.insert(
        "service_tier",
        "priority".into(),
        "derived_from_logs_2",
    );
    encode(&kept, crate::durable_tail_store::RECORD_BYTES, line_cap())
        .expect("a non-attribution selector context persists");
    for key in crate::snapshots::CLAUDE_ATTRIBUTION_SELECTOR_KEYS {
        let mut captured = plain.clone();
        captured.accumulator.current_selector.insert(
            key,
            "CANARY_SKILL_dt".into(),
            "claude_code_attribution_field",
        );
        assert_eq!(
            encode(
                &captured,
                crate::durable_tail_store::RECORD_BYTES,
                line_cap()
            )
            .err(),
            Some(Refuse::NonEmpty("SelectorCapture.context.attribution")),
            "{key}"
        );
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
        Some(crate::transcript_acquisition::CertificateRefusal::Changed(
            FullReason::Shrunk
        ))
    );

    let scratch = Scratch::new("replace");
    let (path, _, certificate) = record(&scratch);
    let replacement = scratch.write("next.jsonl", &lines);
    fs::rename(&replacement, &path).unwrap();
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .err(),
        Some(crate::transcript_acquisition::CertificateRefusal::Changed(
            FullReason::Replaced
        ))
    );

    let scratch = Scratch::new("head-edit");
    let (path, _, certificate) = record(&scratch);
    edit_in_place(&path, 100, b"q");
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .err(),
        Some(crate::transcript_acquisition::CertificateRefusal::Changed(
            FullReason::HeadChanged
        ))
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
const ALLOWLIST_PINS: [(SnapshotSource, &str); 3] = [
    (
        SnapshotSource::ClaudeCode,
        "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c",
    ),
    (
        SnapshotSource::Codex,
        "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
    ),
    (
        SnapshotSource::Pi,
        "bd43c3d6197e6a6dfe339a486b0bbf4aaa121fc40022fcc8418f9d900baac4f7",
    ),
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
        "D activity_call_tools",
        "L activity_mcp_call_ids",
        "L id",
        "U name",
        "D tool_uses",
        "D claude_shape",
        "D claude_blobs",
        "D calls",
        "H digest",
        "E context.attribution",
        "D reducer",
        "D epoch",
        "D last_native",
        "D turn",
        "D closed_filter",
        "L claude_compaction_link_tip",
        "E claude_fork_parent",
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

/// Every `H` field, by persisted type, with what fills it. `HDigest` makes
/// `H` a fixed 32-byte type (a u64 word array, a rolling hash or a truncated
/// hash cannot compile as `H`); this table pins the algorithm per field, so
/// a new `H` field fails here until it is audited (F1).
const H_AUDIT: &[(&str, &str)] = &[
    (
        "Binding.context",
        "durable_tail_store::digest(\"ottto-dt-context:v1\", [namespace, upload context])",
    ),
    (
        "Binding.entry",
        "digest(\"ottto-dt-replay-entry:v1\", [digest(\"ottto-dt-entry:v1\", ..), ..])",
    ),
    (
        "Binding.key",
        "durable_tail_store::digest(\"ottto-dt-key:v1\", [source tag, index key])",
    ),
    (
        "Binding.scope",
        "digest(\"ottto-dt-replay-scope:v1\", [digest(\"ottto-dt-scope:v1\", ..), ..])",
    ),
    (
        "ClaudeRequestKey.digest",
        "SHA-256(\"ottto-dt-claude-shape-key:v1\\0\" || shapeHash) or \
         SHA-256(\"ottto-dt-claude-blob-key:v1\\0\" || blob hash)",
    ),
    (
        "DurableCertificate.boundary_sha256",
        "SHA-256(\"ottto-dt-sample:v1\\0\" || boundary window)",
    ),
    (
        "DurableCertificate.head_sha256",
        "SHA-256(\"ottto-dt-sample:v1\\0\" || head window)",
    ),
    (
        "Envelope.allowlist",
        "Shape::digest: SHA-256(\"ottto-durable-tail-shape:v1\" || shape text)",
    ),
    (
        "OrgMarkers.context_digest",
        "SHA-256(\"ottto-claude-org-marker-context:v1\\0\" || lowercased email)",
    ),
    (
        "OwnedRequest.configuration_witness",
        "SnapshotAccumulator.cache_configuration_witness, copied",
    ),
    (
        "PiSection.usage_keys",
        "H keys: pi_usage_hash(ottto-pi-usage-key:v1, response id); D values: PiUsageDedupState",
    ),
    (
        "PiUsageDedupState.message",
        "H keys: pi_usage_hash(ottto-pi-usage-occurrence:v1, normalized usage); N counts",
    ),
    (
        "PiUsageDedupState.message_end",
        "H keys: pi_usage_hash(ottto-pi-usage-occurrence:v1, normalized usage); N counts",
    ),
    (
        "PiUsageDedupState.paired_digests",
        "pi_usage_hash(ottto-pi-usage-occurrence:v1, normalized usage), copied",
    ),
    (
        "Rederive.agent_label",
        "Enc::hash(\"ottto-dt-rederive:agent_label:v1\")",
    ),
    (
        "Rederive.first_prompt",
        "Enc::hash(\"ottto-dt-rederive:first_prompt:v1\")",
    ),
    (
        "Rederive.session_start",
        "Enc::hash(\"ottto-dt-rederive:session_start:v2\")",
    ),
    (
        "Rederive.title",
        "Enc::hash(\"ottto-dt-rederive:title:v1\")",
    ),
    (
        "Rederive.workspace",
        "Enc::hash(\"ottto-dt-rederive:workspace:v1\")",
    ),
    (
        "SnapshotAccumulator.activity_changed_file_hashes",
        "sha256_hex([\"ottto-activity-changed-file:v1\", path])",
    ),
    (
        "SnapshotAccumulator.cache_configuration_witness",
        "sha256_hex([\"ottto-cache-configuration-witness:v1\", metadata json])",
    ),
    (
        "SnapshotAccumulator.codex_last_usage_event_identity",
        "sha256_hex([\"codex_usage_event:v1\", event])",
    ),
    (
        "SnapshotAccumulator.codex_parent_ledger_identity_used",
        "opened_object_identity_from: SHA-256, length-prefixed version domain",
    ),
    (
        "SnapshotAccumulator.codex_parent_prefix_digest",
        "SHA-256 chain seeded by SHA-256(CODEX_PARENT_PROOF_FORMAT)",
    ),
    (
        "SnapshotAccumulator.codex_physical_signatures",
        "codex_ownership_signature: sha256_hex with codex_parent_* domains",
    ),
    (
        "SnapshotAccumulator.codex_proof_ledger_row",
        "codex_ownership_signature: sha256_hex with codex_parent_* domains",
    ),
];

/// The `Type.field` path of every `H` field in the allowlist shape text.
fn h_paths(text: &str) -> BTreeSet<String> {
    let mut stack = Vec::new();
    let mut last = "";
    let mut out = BTreeSet::new();
    for token in text.split(';') {
        let mut rest = token;
        loop {
            if let Some(next) = rest.strip_prefix('{') {
                stack.push(last);
                rest = next;
            } else if let Some(next) = rest.strip_prefix('}') {
                stack.pop();
                rest = next;
            } else {
                break;
            }
        }
        if let Some(field) = rest.strip_prefix("H ") {
            out.insert(format!("{}.{field}", stack.last().copied().unwrap_or("?")));
        }
        if !rest.is_empty() {
            last = rest;
        }
    }
    out
}

#[test]
fn h_fields_are_audited() {
    let audited = H_AUDIT
        .iter()
        .map(|(path, _)| path.to_string())
        .collect::<BTreeSet<_>>();
    // The body's `H` fields and the envelope's digests (SOURCE P2-5).
    let mut paths = h_paths(&shape_text());
    for path in crate::durable_tail_store::ENVELOPE_H {
        assert!(paths.insert(path.to_string()), "{path} listed twice");
    }
    assert_eq!(paths, audited);
}

/// Full-fallback classes on a synthetic corpus, by the refusing field: a
/// skill reference (E) and a first prompt past the 1 MiB head bound (not
/// re-derivable) each read Full; plain sessions persist.
#[test]
fn fallback_classes_over_the_synthetic_corpus() {
    let mut skill = claude_lines(1, 1);
    skill.push(
        json!({"type":"assistant","sessionId":CLAUDE_SESSION,"uuid":"u-9","parentUuid":"u-3",
            "timestamp":"2026-10-20T10:00:09Z","requestId":"req_skill",
            "message":{"id":"msg_skill","type":"message","role":"assistant",
                "model":"claude-opus-4-1","stop_reason":"tool_use",
                "content":[{"type":"tool_use","id":"toolu_skill","name":"Bash",
                    "input":{"command":"cat ~/.claude/skills/pdf/SKILL.md"}}],
                "usage":{"input_tokens":1,"cache_creation_input_tokens":0,
                    "cache_read_input_tokens":0,"output_tokens":1}}})
        .to_string(),
    );
    let mut deep = claude_filler(0, 1100, 1024);
    deep.extend(claude_lines(0, 0));
    let corpus = [
        (SnapshotSource::ClaudeCode, claude_lines(1, 1)),
        (SnapshotSource::Codex, codex_lines()),
        (SnapshotSource::ClaudeCode, skill),
        (SnapshotSource::ClaudeCode, deep),
    ];
    let mut tally = BTreeMap::<&'static str, usize>::new();
    for (source, lines) in corpus {
        let scratch = Scratch::new("corpus");
        let path = scratch.write("t.jsonl", &lines);
        let (reduction, _) = full_read(&path, source);
        let class = match encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        ) {
            Ok(_) => "persisted",
            Err(
                Refuse::NonEmpty(field) | Refuse::NotRederivable(field) | Refuse::NotDigest(field),
            ) => field,
            Err(Refuse::TooLarge) => "record_bytes",
            Err(Refuse::UnknownLabel) => "static_label",
            Err(Refuse::WriteFailed) => "encode_io",
        };
        *tally.entry(class).or_default() += 1;
    }
    assert_eq!(
        tally,
        BTreeMap::from([
            ("persisted", 2),
            ("SnapshotAccumulator.activity_skills", 1),
            ("SnapshotAccumulator.first_prompt_material", 1),
        ])
    );
}

/// Budget receipt (static): the bounds every restore and write is held to.
#[test]
fn budget_bounds_hold() {
    use crate::durable_tail_store::{INVENTORY_BOUND, MAX_BATCH, MAX_RECORDS, RECORD_BYTES};
    // A restored copy is charged to the 31 MiB state budget like any
    // retained copy; one record never exceeds one cache entry.
    assert_eq!(RECORD_BYTES, crate::transcript_cache::ENTRY_BYTES);
    assert_eq!(MAX_RECORDS, crate::transcript_cache::CACHE_ENTRIES);
    // Disk admission is independent of memo precision; the old writer inventories 512 keys.
    assert_eq!(INVENTORY_BOUND, 512);
    // Per restore: one record read, two 4 KiB sample windows, a head
    // re-parse of at most 1 MiB and at most NAMED_LINES capped lines.
    assert_eq!(HEAD_BOUND, 1024 * 1024);
    assert_eq!(NAMED_LINES, 4);
    // Prepaid beside retained state: both stores' maps and the bounded
    // diagnostic set (512 full 440-byte nodes plus one retained root).
    assert_eq!(
        crate::snapshots::sampled_scan::durable_tail::STORES_RESIDENT_BOUND,
        1_978_368 + (2 * MAX_RECORDS + 1) * 440
    );
    // Per write pass: at most MAX_BATCH records of at most RECORD_BYTES.
    assert_eq!(MAX_BATCH, 32);
}

/// Budget receipt (measured) on the synthetic transcripts: body and record
/// bytes, the encode buffer, and one restore's re-derivation I/O.
#[test]
fn codec_budget_receipt() {
    for case in cases() {
        let scratch = Scratch::new("receipt");
        let path = scratch.write("t.jsonl", &case.lines);
        let (reduction, _) = full_read(&path, case.source);
        let mut e = Enc::bytes(crate::durable_tail_store::RECORD_BYTES);
        reduction.put(&mut e).unwrap();
        let encode_buffer = e.into_bytes().capacity();
        let body = encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap(),
        )
        .unwrap();
        let (_, receipt) = restore(&path, &body, case.source).unwrap();
        println!(
            "dt_codec_budget: source={} file_bytes={} body_bytes={} record_bytes={} \
             encode_buffer_bytes={} rederive_head_bytes={} rederive_named_lines={} \
             rederive_line_bytes={}",
            case.source.api_slug(),
            fs::metadata(&path).unwrap().len(),
            body.len(),
            body.len() + 356,
            encode_buffer,
            receipt.head_bytes,
            receipt.named_lines,
            receipt.line_bytes,
        );
        assert!(body.len() <= crate::durable_tail_store::RECORD_BYTES);
        assert!(receipt.head_bytes <= HEAD_BOUND);
    }
}

/// Decode all stored sections, excluding the caller's independent source
/// binding check. This is the structural acceptance oracle for `verify`.
fn structurally_decodes(body: &[u8]) -> bool {
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .any(|source| decode_body(body, source).is_ok())
}

fn verified_without_allocation(body: &[u8]) -> Result<(), Corrupt> {
    let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| verify(body));
    assert_eq!(stats.allocations, 0, "{stats:?}");
    result
}

#[test]
fn structural_verifier_real_records_truncations_tags_lengths_and_mutation_corpus() {
    let scratch = Scratch::new("structural-verifier");
    for (source, name, lines, min_present_options) in [
        (
            SnapshotSource::ClaudeCode,
            "claude.jsonl",
            claude_lines(2, 2),
            10,
        ),
        (SnapshotSource::Codex, "codex.jsonl", codex_lines(), 10),
        (
            SnapshotSource::ClaudeCode,
            "held-claude.jsonl",
            claude_held_request_lines("verify-canary"),
            10,
        ),
        (
            SnapshotSource::Codex,
            "instructions-codex.jsonl",
            codex_instruction_lines("verify-canary"),
            10,
        ),
    ] {
        let path = scratch.write(name, &lines);
        let (reduction, _) = full_read(&path, source);
        let body = encode(&reduction, 1 << 20, line_cap()).unwrap();
        assert_eq!(verified_without_allocation(&body), Ok(()));
        assert!(decode(&body, source).is_ok());
        // Byte/hash stability: re-encoding the same retained value is exact.
        assert_eq!(encode(&reduction, 1 << 20, line_cap()).unwrap(), body);
        for end in 0..body.len() {
            assert_eq!(
                verified_without_allocation(&body[..end]),
                Err(Corrupt),
                "{name} prefix {end}"
            );
        }
        let (mut visits, present_options) =
            crate::durable_tail_codec::trace_verify(|| assert_eq!(verify(&body), Ok(())));
        assert!(
            present_options >= min_present_options,
            "{name}: walked {present_options} populated optional sections, expected >= {min_present_options}"
        );
        println!("verifier fixture {name}: {present_options} populated optional sections");
        visits.sort_unstable();
        visits.dedup();
        assert!(visits.iter().any(|(_, varint)| *varint));
        assert!(visits.iter().any(|(_, varint)| !varint));
        for (at, varint) in visits {
            let mut corrupt = body.clone();
            if varint {
                // Every visited length/scalar/enum/H-option varint overflows.
                corrupt.splice(at..at, [0xff; 10]);
            } else {
                corrupt[at] = 2; // invalid bool / raw Option tag
            }
            assert!(
                !structurally_decodes(&corrupt),
                "{name} corrupt tag/length {at}"
            );
            assert_eq!(
                verified_without_allocation(&corrupt),
                Err(Corrupt),
                "{name} offset {at}"
            );
        }
        // Deterministic fuzz-style corpus, with a substitution/deletion at
        // every byte and every appended byte value. Valid mutations stay valid.
        for at in 0..body.len() {
            for byte in [0, 1, 2, 0x7f, 0x80, 0xff] {
                let mut mutated = body.clone();
                mutated[at] = byte;
                assert_eq!(
                    verified_without_allocation(&mutated).is_ok(),
                    structurally_decodes(&mutated),
                    "{name} mutation {at}/{byte}"
                );
            }
            let mut mutated = body.clone();
            mutated.remove(at);
            assert_eq!(
                verified_without_allocation(&mutated).is_ok(),
                structurally_decodes(&mutated),
                "{name} deletion {at}"
            );
        }
        for byte in 0..=255 {
            let mut mutated = body.clone();
            mutated.push(byte);
            assert_eq!(verified_without_allocation(&mutated), Err(Corrupt));
        }
    }
}

#[test]
fn structural_verifier_nonempty_selector_capture() {
    let mut capture = crate::snapshots::SelectorCapture::default();
    capture.insert("service_tier", "priority".into(), "derived_from_logs_2");
    assert!(!capture.context.is_empty());
    assert!(!capture.sources.is_empty());
    let mut e = Enc::bytes(1024);
    capture.put(&mut e).unwrap();
    let body = e.into_bytes();
    let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let mut d = Dec::new(&body);
        crate::snapshots::SelectorCapture::verify(&mut d).and_then(|()| d.finish())
    });
    assert_eq!(result, Ok(()));
    assert_eq!(stats.allocations, 0, "{stats:?}");
    let mut d = Dec::new(&body);
    let restored = crate::snapshots::SelectorCapture::take(&mut d).unwrap();
    d.finish().unwrap();
    assert_eq!(restored, capture);
    for end in 0..body.len() {
        let mut d = Dec::new(&body[..end]);
        assert!(crate::snapshots::SelectorCapture::verify(&mut d)
            .and_then(|()| d.finish())
            .is_err());
    }
}

#[test]
fn structural_verifier_large_body_still_allocates_nothing() {
    let scratch = Scratch::new("large-structural-verifier");
    let path = scratch.write("large.jsonl", &codex_lines());
    let (mut reduction, _) = full_read(&path, SnapshotSource::Codex);
    // Uploaded model/tool strings are stored U fields, so make the body large
    // without increasing transcript acquisition or test-probe bookkeeping.
    reduction.accumulator.latest_model = Some("m".repeat(256 * 1024));
    let body = encode(&reduction, 1 << 20, line_cap()).unwrap();
    assert!(body.len() > 256 * 1024);
    assert_eq!(verified_without_allocation(&body), Ok(()));
    assert_eq!(
        verified_without_allocation(&body[..body.len() - 1]),
        Err(Corrupt)
    );
}

fn assert_borrowed_count_identity(reduction: &CachedJsonlReduction) {
    take_l_spans();
    let rederive = rederive_digests(&reduction.accumulator, line_cap()).unwrap();
    let mut old = Enc::bytes(crate::durable_tail_store::RECORD_BYTES);
    reduction.put(&mut old).unwrap();
    rederive.put(&mut old).unwrap();
    let expected = old.into_bytes();
    take_l_spans();
    let (count, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let mut count = Enc::count(expected.len());
        reduction.put(&mut count).unwrap();
        rederive.put(&mut count).unwrap();
        count.counted()
    });
    assert_eq!(stats.allocations, 0, "count must not allocate: {stats:?}");
    assert_eq!(count, expected.len());
    let (refused, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
        let mut count = Enc::count(expected.len() - 1);
        reduction
            .put(&mut count)
            .and_then(|()| rederive.put(&mut count))
    });
    assert_eq!(refused, Err(Refuse::TooLarge));
    assert_eq!(stats.allocations, 0, "refusal precedes any body allocation");
    assert!(
        take_l_spans().is_empty(),
        "count is not a second L-span output"
    );
    let actual = encode(reduction, expected.len(), line_cap()).unwrap();
    assert_eq!(
        actual, expected,
        "borrowed parts preserve the original codec bytes"
    );
    assert_eq!(actual.capacity(), actual.len());
    assert_eq!(
        encode(reduction, expected.len() - 1, line_cap()),
        Err(Refuse::TooLarge)
    );
    let (_, options) = crate::durable_tail_codec::trace_verify(|| verify(&actual).unwrap());
    assert!(options >= 5, "fixture must populate nested optional state");
    take_l_spans();
}

#[test]
fn borrowed_count_exact_encoding_matches_populated_both_source_canaries() {
    let scratch = Scratch::new("borrowed-count-canaries");
    let mut covered = BTreeSet::new();
    for case in cases() {
        let path = scratch.write("nested.jsonl", &case.lines);
        let (reduction, _) = full_read(&path, case.source);
        covered.insert(case.source.api_slug());
        assert_borrowed_count_identity(&reduction);
    }
    assert_eq!(covered, BTreeSet::from(["claude_code", "codex"]));
}

#[test]
fn borrowed_count_identity_covers_codex_absent_legacy_and_v2_state() {
    use codex_counting_version::AckEvidence;
    let scratch = Scratch::new("borrowed-count-contract");
    let path = scratch.write("codex.jsonl", &codex_lines());
    for (evidence, version) in [
        (None, 0),
        (Some(AckEvidence::LegacyAcked), 1),
        (Some(AckEvidence::None), 2),
    ] {
        let mut parser = parser(&path, SnapshotSource::Codex);
        if let Some(evidence) = evidence {
            codex_counting_version::configure(&mut parser.accumulator, evidence, Some(0));
        }
        parser
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap();
        while !parser.step().unwrap() {}
        let reduction = parser.durable_test_reduction_copy();
        assert_eq!(reduction.durable_counting().map_or(0, |c| c.1), version);
        assert_borrowed_count_identity(&reduction);
    }
}

#[test]
fn compressed_rederive_refuses_before_seek_or_jsonl_parse() {
    let scratch = Scratch::new("zst-refusal");
    let plain = scratch.write(
        "plain.jsonl",
        &[format!(
            r#"{{"type":"session_meta","payload":{{"id":"{CODEX_SESSION}"}}}}"#
        )],
    );
    let (reduction, _) = full_read(&plain, SnapshotSource::Codex);
    let body = encode(&reduction, 8 * 1024 * 1024, jsonl_line_cap() as u64).unwrap();
    let decoded = decode(&body, SnapshotSource::Codex).unwrap();
    let archive = scratch.0.join("rollout.jsonl.zst");
    fs::write(&archive, b"synthetic archive bytes").unwrap();
    let mut file = File::open(&archive).unwrap();
    file.seek(SeekFrom::Start(3)).unwrap();
    codex_zst_refusal_tests::assert_refused(CodexZstCause::DurableTailUnsupported, || {
        assert!(rederive_parser(file.try_clone().unwrap(), &archive, &decoded).is_err());
        assert_eq!(
            file.stream_position().unwrap(),
            3,
            "refused before offset use"
        );
    });
}

#[test]
fn tail_reuse_allowance_cannot_block_an_independently_due_full() {
    use crate::transcript_cache::Retained;
    let scratch = Scratch::new("tail-admission");
    let path = scratch.write("native.jsonl", &["{}".into()]);
    let source = SnapshotSource::ClaudeCode;
    let (state, checkpoint) = full_read(&path, source);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{}\n")
        .unwrap();
    let mut due = parser(&path, source);
    let mode = due
        .prepare_acquisition_with_reuse_gate(
            Some(Retained {
                checkpoint: checkpoint.clone(),
                state: state.clone(),
            }),
            &scope(),
            Some(crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: NOW,
            }),
            NOW,
            |_, _| panic!("an owed Full never spends or checks a Tail allowance"),
        )
        .unwrap();
    assert_eq!(mode, ReadMode::Full(FullReason::AuditDue));
    let mut limited = parser(&path, source);
    let calls = std::cell::Cell::new(0);
    let mode = limited
        .prepare_acquisition_with_reuse_gate(
            Some(Retained { checkpoint, state }),
            &scope(),
            None,
            NOW,
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(false)
            },
        )
        .unwrap();
    assert_eq!(calls.get(), 1, "only the actual Tail asks for permission");
    assert_eq!(mode, ReadMode::Full(FullReason::StateMissing));
    while !limited.step().unwrap() {}
    let (cold, _) = full_read(&path, source);
    assert_eq!(
        encode(&limited.reduction_copy(), 1 << 20, 1 << 20).unwrap(),
        encode(&cold, 1 << 20, 1 << 20).unwrap(),
        "fallback uses the fresh native reduction"
    );
}

#[test]
fn no_input_completion_requires_every_rederive_digest_absent() {
    for field in 0..5 {
        let mut obligation = Rederive::default();
        let slot = match field {
            0 => &mut obligation.first_prompt,
            1 => &mut obligation.workspace,
            2 => &mut obligation.agent_label,
            3 => &mut obligation.session_start,
            _ => &mut obligation.title,
        };
        *slot = Some([1; 32]);
        let decoded = Decoded {
            reduction: CachedJsonlReduction {
                accumulator: SnapshotAccumulator::new(SnapshotSource::ClaudeCode),
                report: JsonlReadReport::default(),
                recognized_usage_drop_count: 0,
                positive_recognized_usage_count: 0,
                positive_usage_evidence: false,
            },
            rederive: obligation,
        };
        let (result, stats) =
            crate::retry_allocation_probe::measure_caller_thread(|| decoded.without_rederive());
        assert!(
            result.is_err(),
            "obligation{field} cannot use a zero/missing head mark as absence"
        );
        assert_eq!(stats.allocations, 0);
    }
    let decoded = Decoded {
        reduction: CachedJsonlReduction {
            accumulator: SnapshotAccumulator::new(SnapshotSource::ClaudeCode),
            report: JsonlReadReport::default(),
            recognized_usage_drop_count: 0,
            positive_recognized_usage_count: 0,
            positive_usage_evidence: false,
        },
        rederive: Rederive::default(),
    };
    let (result, stats) =
        crate::retry_allocation_probe::measure_caller_thread(|| decoded.without_rederive());
    let (_, receipt) = result.unwrap();
    assert_eq!(receipt, RederiveReceipt::default());
    assert_eq!(stats.allocations, 0);
}

/// Differential projection of the enabled workspace class from the actual
/// codec corpus. Other digest obligations are deliberately left unsupported;
/// this projection is NOT a claim that the complete rich records restore.
#[test]
fn bounded_workspace_matches_native_corpus_and_refuses_other_classes() {
    let scratch = Scratch::new("bounded-workspace");
    let cases = [
        (SnapshotSource::ClaudeCode, claude_lines(3, 3)),
        (SnapshotSource::Codex, codex_lines()),
    ];
    for (source, mut lines) in cases {
        // Compaction, title updates, later cwd and unknown nested payloads
        // cannot overwrite native first-write-wins workspace selection.
        lines.push(
            json!({"type":"system", "subtype":"compact_boundary",
            "cwd":"/later-workspace", "customTitle":"Later title",
            "payload":{"cwd":"/other-later"},
            "ignored":{"many":[{"content":"skip me"}]}})
            .to_string(),
        );
        let path = scratch.write(source.api_slug(), &lines);
        let (native, _) = full_read(&path, source);
        let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
        let decoded = decode(&body, source).unwrap();
        assert!(decoded.rederive.workspace.is_some());
        assert!(
            decoded.content_charge().is_err(),
            "rich record remains unsupported"
        );
        let oracle = restore(&path, &body, source).unwrap().0;
        let mut workspace = decode(&body, source).unwrap();
        workspace.rederive = Rederive {
            workspace: workspace.rederive.workspace,
            ..Default::default()
        };
        let charge = workspace.content_charge().unwrap();
        assert!(charge >= workspace.head_end().unwrap());
        let mut wrong = decode(&body, source).unwrap();
        wrong.rederive = Rederive {
            workspace: Some([0; 32]),
            ..Default::default()
        };
        wrong.content_charge().unwrap();
        assert!(matches!(
            wrong.rederive_content(&File::open(&path).unwrap()),
            Err(Refuse::NotRederivable("workspace_digest"))
        ));
        let (bounded, receipt) = workspace
            .rederive_content(&File::open(&path).unwrap())
            .unwrap();
        assert_eq!(
            bounded.accumulator.workspace_path,
            oracle.accumulator.workspace_path
        );
        assert_eq!(
            bounded.accumulator.workspace_path,
            native.accumulator.workspace_path
        );
        assert_eq!(receipt.named_lines, 0);
        assert_eq!(receipt.line_bytes, 0);
        assert_eq!(
            receipt.head_bytes,
            native.accumulator.durable_marks.workspace.unwrap()
        );
        // Every excluded class refuses before any I/O, independently.
        for class in 0..4 {
            let mut excluded = decode(&body, source).unwrap();
            excluded.rederive = Rederive::default();
            match class {
                0 => excluded.rederive.first_prompt = Some([1; 32]),
                1 => excluded.rederive.title = Some([1; 32]),
                2 => excluded.rederive.agent_label = Some([1; 32]),
                _ => excluded.rederive.session_start = Some([1; 32]),
            }
            assert!(excluded.content_charge().is_err());
        }
    }
}

#[test]
fn bounded_workspace_cap_and_escaped_text_keep_native_values_or_refuse() {
    let scratch = Scratch::new("workspace-cap");
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for length in [4095, 4096, 4097] {
            let cwd = "x".repeat(length);
            let line = match source {
                SnapshotSource::ClaudeCode => json!({"type":"progress", "cwd":cwd}),
                _ => json!({"type":"session_meta", "payload":{"id":CODEX_SESSION,
                    "cwd":cwd, "source":"cli"}}),
            };
            let path = scratch.write(
                &format!("{}-{length}", source.api_slug()),
                &[line.to_string()],
            );
            let (native, _) = full_read(&path, source);
            let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
            let mut decoded = decode(&body, source).unwrap();
            assert!(decoded.rederive.workspace.is_some());
            decoded.rederive = Rederive {
                workspace: decoded.rederive.workspace,
                ..Default::default()
            };
            decoded.content_charge().unwrap();
            let actual = decoded.rederive_content(&File::open(&path).unwrap());
            if length > 4096 {
                assert!(matches!(
                    actual,
                    Err(Refuse::NotRederivable("workspace_capture"))
                ));
            } else {
                assert_eq!(
                    actual.unwrap().0.accumulator.workspace_path,
                    native.accumulator.workspace_path
                );
            }
        }
    }
    let path = scratch.write("escaped", &[r#"{"type":"progress","cwd":"  /tmp/a\u0062\u0063  ","ignored":[{"key":"not captured"}]}"#.into()]);
    let (native, _) = full_read(&path, SnapshotSource::ClaudeCode);
    let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
    let mut decoded = decode(&body, SnapshotSource::ClaudeCode).unwrap();
    decoded.rederive = Rederive {
        workspace: decoded.rederive.workspace,
        ..Default::default()
    };
    decoded.content_charge().unwrap();
    assert_eq!(
        decoded
            .rederive_content(&File::open(&path).unwrap())
            .unwrap()
            .0
            .accumulator
            .workspace_path,
        Some(PathBuf::from("/tmp/abc"))
    );
}

#[test]
fn workspace_wrong_object_shapes_refuse_without_formatting_the_input() {
    let scratch = Scratch::new("workspace-shape-error");
    for field in ["payload", "session_meta", "turn_context"] {
        let path = scratch.write(
            "wrong-shape",
            &[json!({"type":"progress", "cwd":"/tmp/synthetic",
            field: "\u{0080}".repeat(100_000)})
            .to_string()],
        );
        let (native, _) = full_read(&path, SnapshotSource::ClaudeCode);
        let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
        let mut decoded = decode(&body, SnapshotSource::ClaudeCode).unwrap();
        decoded.rederive = Rederive {
            workspace: decoded.rederive.workspace,
            ..Default::default()
        };
        assert!(decoded.rederive.workspace.is_some());
        decoded.content_charge().unwrap();
        assert!(matches!(
            decoded.rederive_content(&File::open(&path).unwrap()),
            Err(Refuse::NotRederivable("workspace_capture"))
        ));
    }
}

// M3 G1 (r6 native): the one native finish body and its PRE-finalization
// seam. The seam is what `finish_with_repository_identity_prepared` stages
// from; these controls pin where it runs and what it sees, without a store.

/// The body bytes the seam's live view encodes to, and whether the
/// scan-shared live inputs were detached while it ran.
fn seam_body(live: crate::snapshots::PreFinalization<'_>) -> (Vec<u8>, bool) {
    let detached = live.accumulator.codex_turn_traces.is_none()
        && live.accumulator.codex_parent_ownership_ledgers.is_none();
    let body = encode_parts(
        live.accumulator,
        live.report,
        (
            live.recognized_usage_drop_count,
            live.positive_recognized_usage_count,
            live.positive_usage_evidence,
        ),
        usize::MAX,
        line_cap(),
    )
    .expect("a clean fixture encodes");
    (body, detached)
}

#[test]
fn m3_seam_live_bytes_equal_retained_copy_and_output_equals_legacy() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let scratch = Scratch::new("m3-seam");
        let lines = match source {
            SnapshotSource::Codex => codex_lines(),
            _ => claude_lines(2, 2),
        };
        let path = scratch.write("t.jsonl", &lines);
        let traces = || Some(std::sync::Arc::new(Default::default()));
        // Oracle: the copy a certified completion retains, then the legacy
        // wrapper's output over the same parser.
        let mut legacy = parser(&path, source);
        legacy
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap();
        while !legacy.step().unwrap() {}
        legacy.accumulator.codex_turn_traces = traces();
        // This fixture qualifies an encodable live state; first-prompt raw
        // material is deliberately outside the durable codec's allowlist.
        legacy.accumulator.first_prompt_material = None;
        legacy.accumulator.first_prompt_title = None;
        let retained = legacy.durable_test_reduction_copy();
        let legacy = items(legacy, &path, source);
        let mut live = parser(&path, source);
        live.prepare_acquisition(None, &scope(), None, NOW).unwrap();
        while !live.step().unwrap() {}
        live.accumulator.codex_turn_traces = traces();
        // This fixture qualifies an encodable live state; first-prompt raw
        // material is deliberately outside the durable codec's allowlist.
        live.accumulator.first_prompt_material = None;
        live.accumulator.first_prompt_title = None;
        let mut seen = Vec::new();
        let at_seam = items_at(
            live,
            &path,
            source,
            Some(&mut |view: crate::snapshots::PreFinalization<'_>| seen.push(seam_body(view))),
        );
        assert_eq!(seen.len(), 1, "{source:?}: the seam runs exactly once");
        let (body, detached) = &seen[0];
        assert!(
            detached,
            "{source:?}: live scan inputs are detached at the seam"
        );
        assert_eq!(
            body,
            &encode_body(&retained, usize::MAX, line_cap()).unwrap(),
            "{source:?}: PRE-finalization live bytes are the retained copy's bytes"
        );
        assert_eq!(
            at_seam, legacy,
            "{source:?}: the shared body publishes exactly the legacy output"
        );
    }
}

#[test]
fn m3_seam_never_runs_before_the_held_object_is_revalidated() {
    let scratch = Scratch::new("m3-seam-refused");
    let path = scratch.write("t.jsonl", &claude_lines(1, 1));
    let request = |expected: &'static str| crate::snapshots::FinishRequest {
        expected_opened_object_identity: expected,
        path: &path,
        collected_at: COLLECTED,
        source_file_fingerprint: "fp".into(),
        codex_title_metadata: None,
        claude_title_metadata: None,
        attribution_context: None,
        repository_identity: None,
        money_context: None,
    };
    let mut calls = 0;
    // An unfinished read and a changed opened object both fail before the
    // seam: nothing is staged, so nothing needs discarding.
    let unfinished = parser(&path, SnapshotSource::ClaudeCode);
    let mut count = |_: crate::snapshots::PreFinalization<'_>| calls += 1;
    assert!(unfinished
        .finish_native(request("unused"), Some(&mut count))
        .is_err());
    let mut changed = parser(&path, SnapshotSource::ClaudeCode);
    while !changed.step().unwrap() {}
    assert!(changed
        .finish_native(request("another opened object"), Some(&mut count))
        .is_err());
    assert_eq!(calls, 0);
}
