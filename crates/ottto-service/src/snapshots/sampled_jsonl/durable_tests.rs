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
pub(super) fn items(parser: OwnedJsonlParser, path: &Path, source: SnapshotSource) -> Value {
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

/// A later skill reference must not also create an unsupported opening-call
/// obligation: close the native opening window with three ordinary user turns.
fn skill_fixture_lines() -> Vec<String> {
    let mut lines = claude_lines(1, 1);
    for n in 4..7 {
        lines.push(json!({"type":"user","sessionId":CLAUDE_SESSION,"uuid":format!("skill-window-{n}"),"timestamp":format!("2026-10-20T10:00:0{n}Z"),"message":{"role":"user","content":"synthetic later turn"}}).to_string());
    }
    lines
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
/// with an org marker. Artifacts remain E; approved skill labels use PL-retained.
/// `e_content_refuses_and_approved_mid_file_skills_persist` covers both.
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

/// Other E content still refuses; the approved mid-file skill label now persists.
#[test]
fn e_content_refuses_and_approved_mid_file_skills_persist() {
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
    let mut skill = skill_fixture_lines();
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
    assert!(
        encode(
            &reduction,
            crate::durable_tail_store::RECORD_BYTES,
            line_cap()
        )
        .is_ok(),
        "a native mid-file SKILL.md label is now PL-retained"
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

/// A Pi session: header `cwd`, optionally a first user prompt, one turn.
fn pi_lines(first_prompt: bool) -> Vec<String> {
    let mut lines = vec![
        json!({"type":"session","version":3,"id":"synthetic-pi-restore",
        "timestamp":"2026-10-27T06:00:00Z","cwd":"/synthetic/pi-work"})
        .to_string(),
    ];
    if first_prompt {
        lines.push(
            json!({"type":"message","id":"a0000001","parentId":null,
            "message":{"role":"user","timestamp":1793080800000u64,
                "content":[{"type":"text","text":"Synthetic first prompt."}]}})
            .to_string(),
        );
    }
    lines.push(
        json!({"type":"message","id":"a0000002","parentId":"a0000001",
        "timestamp":"2026-10-27T07:00:01Z","message":{"role":"assistant",
            "provider":"openai","model":"gpt-5.4","api":"openai-responses",
            "timestamp":"2026-10-27T07:00:01Z","stopReason":"stop","responseId":"seed",
            "content":[{"type":"text","text":"Synthetic answer."}],
            "usage":{"input":10,"output":2,"cacheRead":0,"cacheWrite":0,
                "totalTokens":12,"cost":{"total":0.001}}}})
        .to_string(),
    );
    lines
}

/// The retained copy of a real Pi parse and its decoded body, before any
/// re-derivation. `decode` needs no native layout, unlike `decode_bounded`.
fn pi_decoded(path: &Path) -> (CachedJsonlReduction, Decoded) {
    let (reduction, _) = full_read(path, SnapshotSource::Pi);
    let body = encode(
        &reduction,
        crate::durable_tail_store::RECORD_BYTES,
        line_cap(),
    )
    .unwrap();
    let decoded = decode(&body, SnapshotSource::Pi).expect("decode");
    (reduction, decoded)
}

/// [format] Pi native accounting and restore contract.
/// Bounded replay restores Pi workspace, first prompt and fallback title.
/// These content steps are portable; durable bounded decode is layout-gated.
#[test]
fn pi_cwd_and_first_prompt_body_is_admitted_for_restore() {
    let scratch = Scratch::new("pi-admitted");
    let path = scratch.write("pi.jsonl", &pi_lines(true));
    let (reduction, decoded) = pi_decoded(&path);
    let cold = &reduction.accumulator;
    assert!(cold.workspace_path.is_some() && cold.first_prompt_material.is_some());
    decoded.content_charge().expect("no RederiveUnfunded");
    let (restored, _) = decoded
        .rederive_content(&File::open(&path).unwrap())
        .expect("restore admitted");
    let restored = restored.accumulator;
    assert_eq!(restored.workspace_path, cold.workspace_path);
    assert_eq!(restored.first_prompt_material, cold.first_prompt_material);
    assert_eq!(restored.first_prompt_title, cold.first_prompt_title);
}

/// [format] Pi native accounting and restore contract.
/// A physical first prompt after 1 MiB cannot obtain a bounded durable proof.
#[test]
fn pi_first_prompt_beyond_head_bound_refuses_persistence() {
    let scratch = Scratch::new("pi-head-bound");
    let mut lines = pi_lines(true);
    lines.insert(
        1,
        json!({"type":"progress", "padding":"x".repeat(HEAD_BOUND as usize)}).to_string(),
    );
    let path = scratch.write("pi.jsonl", &lines);
    let (native, _) = full_read(&path, SnapshotSource::Pi);
    assert!(native.accumulator.durable_marks.first_prompt.unwrap() > HEAD_BOUND);
    assert!(matches!(
        encode(&native, crate::durable_tail_store::RECORD_BYTES, line_cap()),
        Err(Refuse::NotRederivable(
            "SnapshotAccumulator.first_prompt_material"
        ))
    ));
}

const PI_MARKER: &str = "ZZsyntheticcanaryQQ";

/// A Pi body with a slash skill and the marker in its first prompt.
fn pi_marked_lines(cwd: bool) -> Vec<String> {
    let prompt = format!("/synthetic-skill review {PI_MARKER} before the release");
    pi_lines(true)
        .into_iter()
        .map(|line| {
            let mut value: Value = serde_json::from_str(&line).unwrap();
            if !cwd {
                value.as_object_mut().unwrap().remove("cwd");
            }
            value
                .to_string()
                .replace("Synthetic first prompt.", &prompt)
        })
        .collect()
}

/// A later prompt and turn: a Tail that must not re-assign the first prompt.
fn pi_tail_lines() -> Vec<String> {
    pi_lines(true)[1..]
        .iter()
        .map(|line| {
            line.replace("Synthetic first prompt.", "Synthetic later prompt.")
                .replace("a0000002", "a0000022")
                .replace("a0000001", "a0000021")
                .replace("\"seed\"", "\"tail\"")
        })
        .collect()
}

/// A synthetic upload key: one repeated byte.
fn pi_attribution(home: &Path) -> crate::session_attribution::SessionAttributionContext {
    use base64::Engine;
    crate::session_attribution::SessionAttributionContext::from_activity_hint(
        SnapshotSource::Pi,
        home,
        true,
        Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32])),
        Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
    )
    .unwrap()
}

fn pi_all_on() -> SnapshotUploadPolicy {
    SnapshotUploadPolicy {
        session_titles_enabled: true,
        session_attribution_enabled: true,
        session_attribution_labels_enabled: true,
        ..SnapshotUploadPolicy::default()
    }
}

/// The finished upload items after every upload setting, as the wire carries them.
fn pi_uploaded(
    parser: OwnedJsonlParser,
    path: &Path,
    context: &crate::session_attribution::SessionAttributionContext,
) -> Value {
    let identity = opened_object_identity(SnapshotSource::Pi, &mut File::open(path).unwrap());
    let mut parsed = parser
        .finish_native(
            crate::snapshots::FinishRequest {
                expected_opened_object_identity: &identity.unwrap(),
                path,
                collected_at: COLLECTED,
                source_file_fingerprint: "fp".into(),
                codex_title_metadata: None,
                claude_title_metadata: None,
                attribution_context: Some(context),
                repository_identity: None,
                money_context: None,
            },
            None,
        )
        .unwrap();
    apply_upload_policy(SnapshotSource::Pi, &mut parsed.snapshots, pi_all_on());
    serde_json::to_value(&parsed.snapshots).unwrap()
}

fn pi_cold_uploaded(
    path: &Path,
    context: &crate::session_attribution::SessionAttributionContext,
) -> Value {
    let mut parser = parser(path, SnapshotSource::Pi);
    while !parser.step().unwrap() {}
    pi_uploaded(parser, path, context)
}

/// Saves a real parse of `path`, restores it through the body, Tails `grow` and
/// hands the continued parser back. The Pi record carries no first-prompt
/// value, so `rederive_content` must fund and return it from the file's head.
fn pi_restored_tail(path: &Path, grow: &[String]) -> OwnedJsonlParser {
    let (reduction, checkpoint) = full_read(path, SnapshotSource::Pi);
    let body = encode(
        &reduction,
        crate::durable_tail_store::RECORD_BYTES,
        line_cap(),
    )
    .unwrap();
    let decoded = decode(&body, SnapshotSource::Pi).unwrap();
    decoded.content_charge().expect("no RederiveUnfunded");
    let (restored, _) = decoded
        .rederive_content(&File::open(path).unwrap())
        .expect("restored");
    let birth = birth_unix_nanos(&fs::metadata(path).unwrap());
    let certificate = checkpoint.durable_certificate(birth).unwrap();
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    for line in grow {
        writeln!(file, "{line}").unwrap();
    }
    drop(file);
    let mut held = File::open(path).unwrap();
    let (checkpoint, _) = certificate.restore(&mut held, scope()).unwrap();
    let mut continued = parser(path, SnapshotSource::Pi);
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
    assert_eq!(mode, ReadMode::Tail);
    while !continued.step().unwrap() {}
    continued
}

/// restore→Tail equals a cold Full: money and every uploaded field, byte-equal,
/// including the first-prompt and title fields, with no re-assignment from the
/// Tail's prompt.
fn pi_restore_tail_case(cwd: bool) {
    let scratch = Scratch::new("pi-marked-tail");
    let path = scratch.write("t.jsonl", &pi_marked_lines(cwd));
    let context = pi_attribution(&scratch.0);
    let parser = pi_restored_tail(&path, &pi_tail_lines());
    let tailed = pi_uploaded(parser, &path, &context);
    assert_eq!(tailed, pi_cold_uploaded(&path, &context));
    let text = tailed.to_string();
    for field in ["template_group_id", "skill_id", "session_display_name\":\""] {
        assert!(text.contains(field), "{field}");
    }
    assert!(text.contains(PI_MARKER), "the title and the label carry it");
}

/// [format] Pi native accounting and restore contract.
#[test]
fn pi_restored_tail_publishes_the_cold_first_prompt_and_title() {
    pi_restore_tail_case(false);
}

/// [format] Pi native accounting and restore contract.
/// The same with a header `cwd`, rederived from its marked header row.
#[test]
fn pi_restored_tail_with_header_cwd_publishes_the_cold_body() {
    pi_restore_tail_case(true);
}

/// [format] Pi native accounting and restore contract.
/// The title stays last-wins across a restore: a later title replaces the
/// first-prompt title, and the first-prompt grouping facts stay.
#[test]
fn pi_tail_title_follows_its_update_and_the_first_prompt_fields_stay() {
    let scratch = Scratch::new("pi-marked-title");
    let path = scratch.write("t.jsonl", &pi_marked_lines(false));
    let context = pi_attribution(&scratch.0);
    let cold = pi_cold_uploaded(&path, &context);
    let mut parser = pi_restored_tail(&path, &pi_tail_lines());
    // No Pi line sets a title today; this is the normal last-wins setter.
    parser
        .accumulator
        .set_title(Some("Synthetic later title".into()), "transcript_title");
    let tailed = pi_uploaded(parser, &path, &context);
    assert_eq!(tailed[0]["session_display_name"], "Synthetic later title");
    assert_eq!(tailed[0]["attribution_facts"], cold[0]["attribution_facts"]);
}

/// Full-equivalence control per source: a restored copy continued by Tail
/// finishes to the same upload items as a cold Full of the grown file.
#[test]
fn restore_then_tail_matches_cold_full() {
    let mut corpus = cases();
    let mut skill = skill_fixture_lines();
    skill.push(serde_json::json!({"type":"assistant","sessionId":CLAUDE_SESSION,"uuid":"skill-mid","timestamp":"2026-10-20T10:00:09Z","attributionSkill":"Review","message":{"id":"skill-mid","role":"assistant","model":"claude-opus-4-1","content":[{"type":"tool_use","id":"toolu-mid","name":"Read","input":{"file_path":"/synthetic/skills/Review/SKILL.md"}}],"usage":{"input_tokens":1,"output_tokens":1}}}).to_string());
    corpus.push(Case {
        source: SnapshotSource::ClaudeCode,
        lines: skill,
        appended: claude_lines(2, 2),
        content: &[],
        provider_ids: &[],
        survivors: &[],
    });
    for case in corpus {
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
        let (oracle, _) = restore(&path, &body, case.source).unwrap();
        let (restored, _) = decode(&body, case.source)
            .unwrap()
            .rederive_content(&File::open(&path).unwrap())
            .unwrap();
        assert_eq!(full_digest(&restored), full_digest(&oracle));
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
        let (cold_reduction, _) = full_read(&path, case.source);
        assert_eq!(
            serde_json::to_vec(&continued.accumulator.activity_summary()).unwrap(),
            serde_json::to_vec(&cold_reduction.accumulator.activity_summary()).unwrap()
        );
        if case.source == SnapshotSource::ClaudeCode {
            let attribution =
                crate::session_attribution::SessionAttributionContext::from_activity_hint(
                    case.source,
                    &scratch.0,
                    true,
                    Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                    Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
                )
                .unwrap();
            let grouping = |acc: &SnapshotAccumulator| {
                serde_json::to_vec(&attribution.grouping_facts(
                    crate::session_attribution::SessionAttributionGroupingInput {
                        source: case.source,
                        origin: Some(&acc.origin),
                        source_session_id: CLAUDE_SESSION,
                        observed_at: COLLECTED,
                        source_version: case.source.parser_version(),
                        first_prompt: acc.first_prompt_material.as_deref(),
                        provider_skills: &acc.provider_skills,
                        activity_skills: &acc.activity_skills,
                        repository_hash: None,
                        source_started_at: acc.started_at.as_deref(),
                        transcript_path: &path,
                    },
                ))
                .unwrap()
            };
            assert_eq!(
                grouping(&continued.accumulator),
                grouping(&cold_reduction.accumulator)
            );
        }
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
        let (mut reduction, checkpoint) = full_read(&path, source);
        reduction
            .accumulator
            .note_activity_skills("/synthetic/skills/HeadLabel/SKILL.md");
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
        "95c373175449b72f29d65ad493f5506f6980a338b57e59560a345b0ca0a02cd2",
    ),
    (
        SnapshotSource::Codex,
        "458f4632159f42471342573ed64a7071c7e3376a7ebcdbdec5eb603e8bb0b3d0",
    ),
    (
        SnapshotSource::Pi,
        // PROVISIONAL shared E→PL pin; final A_P awaits M-2 and SOURCE review.
        "2b5c22e9aaa50964dba5ea7e4f148a826a246fffa9efc4925895dd0a6d654260",
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
        "PL provider_skills",
        "PL activity_skills",
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
/// approved skill references persist alongside plain sessions; a first prompt
/// past the 1 MiB head bound still refuses toward native Full.
#[test]
fn fallback_classes_over_the_synthetic_corpus() {
    let mut skill = skill_fixture_lines();
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
            ("persisted", 3),
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
        2_179_072 + (2 * MAX_RECORDS + 1) * 440
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
    // The generic (Claude/Codex) layout `verify` checks; Pi's section layout
    // has its own verifier and is not part of this corpus.
    let mut d = Dec::new(body);
    CachedJsonlReduction::take(&mut d).is_ok()
        && Rederive::take(&mut d).is_ok()
        && d.finish().is_ok()
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
    // Since #870, audit debt alone never forces a Full on a checkpoint; an
    // independently owed Full (here a scope change) must not touch the gate.
    let mut due = parser(&path, source);
    // Since #870, audit debt alone never forces a Full on a checkpoint; an
    // independently owed Full (here a scope change) must not touch the gate.
    let mode = due
        .prepare_acquisition_with_reuse_gate(
            Some(Retained {
                checkpoint: checkpoint.clone(),
                state: state.clone(),
            }),
            &Scope("durable-codec-test-other-scope".into()),
            Some(crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: NOW,
            }),
            NOW,
            |_, _| panic!("an owed Full never spends or checks a Tail allowance"),
        )
        .unwrap();
    assert_eq!(mode, ReadMode::Full(FullReason::ScopeChanged));
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
fn bounded_content_matches_native_corpus_and_fences_every_class() {
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
        assert!(decoded.content_charge().is_ok());
        let (bounded, _) = decoded
            .rederive_content(&File::open(&path).unwrap())
            .unwrap();
        let oracle = restore(&path, &body, source).unwrap().0;
        assert_eq!(full_digest(&bounded), full_digest(&oracle));
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
            Err(Refuse::NotRederivable("content_fence"))
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
            assert!(excluded
                .rederive_content(&File::open(&path).unwrap())
                .is_err());
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
            assert_eq!(
                actual.unwrap().0.accumulator.workspace_path,
                native.accumulator.workspace_path
            );
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
fn workspace_unknown_object_shapes_match_native_without_formatting_the_input() {
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
        assert_eq!(
            decoded
                .rederive_content(&File::open(&path).unwrap())
                .unwrap()
                .0
                .accumulator
                .workspace_path,
            native.accumulator.workspace_path
        );
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

/// [format] Pi native accounting and restore contract.
/// Compare Pi header precedence with the native replay oracle.
#[test]
fn bounded_pi_workspace_matches_native_header_only_precedence() {
    let scratch = Scratch::new("pi-workspace-content");
    let source = SnapshotSource::Pi;
    let cases = [
        vec![json!({"type":"session","id":"synthetic-pi","cwd":"/synthetic/workspace"})],
        vec![
            json!({"type":"message","cwd":"/ignore-message","workspace":"/ignore"}),
            json!({"type":" session ","id":"synthetic-pi","cwd":"  /synthetic/a\u{e9}  ",
                "projectPath":"/ignore-project","workspace":"/ignore-workspace",
                "payload":{"cwd":"/ignore-payload"}}),
            json!({"type":"session","cwd":"/later-does-not-overwrite"}),
        ],
        vec![
            json!({"type":"session","id":"synthetic-pi","cwd":"  ","workspace":"/ignore"}),
            json!({"type":"session","cwd":"/first-nonempty"}),
        ],
    ];
    for (i, lines) in cases.into_iter().enumerate() {
        let lines = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        let path = scratch.write(&format!("pi-{i}"), &lines);
        let mut native = parser(&path, source);
        assert!(matches!(
            native
                .prepare_acquisition(None, &scope(), None, NOW)
                .unwrap(),
            ReadMode::Full(FullReason::StateMissing)
        ));
        while !native.step().unwrap() {}
        let native = native.reduction_copy();
        let make = || {
            let mut reduction = native.clone();
            reduction.accumulator.workspace_path = None;
            Decoded {
                reduction,
                rederive: Rederive {
                    workspace: Some(workspace_digest(&native.accumulator).unwrap()),
                    ..Default::default()
                },
            }
        };
        let expected = make()
            .rederive(
                parser(&path, source),
                &mut File::open(&path).unwrap(),
                line_cap(),
            )
            .unwrap();
        assert!(
            make().content_charge().unwrap() >= native.accumulator.durable_marks.workspace.unwrap()
        );
        let (actual, receipt) = make()
            .rederive_content(&File::open(&path).unwrap())
            .unwrap();
        assert_eq!(
            actual.accumulator.workspace_path,
            native.accumulator.workspace_path
        );
        assert_eq!(
            actual.accumulator.workspace_path,
            expected.0.accumulator.workspace_path
        );
        assert_eq!(receipt.head_bytes, expected.1.head_bytes);
        assert_eq!(receipt.line_bytes, 0);
        assert_eq!(receipt.named_lines, 0);
        let mut prompt = make();
        prompt.rederive.first_prompt = Some([1; 32]);
        assert!(
            prompt.content_charge().is_err(),
            "a fabricated prompt without a physical mark refuses"
        );
        prompt.reduction.accumulator.durable_marks.first_prompt = Some(1);
        assert!(
            prompt.content_charge().is_ok(),
            "a marked Pi prompt is funded"
        );
        let mut wrong = make();
        wrong.rederive.workspace = Some([0; 32]);
        assert!(matches!(
            wrong.rederive_content(&File::open(&path).unwrap()),
            Err(Refuse::NotRederivable("content_fence"))
        ));
    }
}

/// [format] Pi native accounting and restore contract.
#[test]
fn bounded_pi_workspace_enforces_cap_and_refuses_nonheader_cwd() {
    let scratch = Scratch::new("pi-workspace-caps");
    for size in [4096, 4097] {
        let path = scratch.write(
            &format!("pi-{size}"),
            &[json!({"type":"session","id":"synthetic-pi","cwd":"x".repeat(size)}).to_string()],
        );
        let mut native = parser(&path, SnapshotSource::Pi);
        assert!(matches!(
            native
                .prepare_acquisition(None, &scope(), None, NOW)
                .unwrap(),
            ReadMode::Full(FullReason::StateMissing)
        ));
        while !native.step().unwrap() {}
        let mut reduction = native.reduction_copy();
        let want = workspace_digest(&reduction.accumulator).unwrap();
        reduction.accumulator.workspace_path = None;
        let decoded = Decoded {
            reduction,
            rederive: Rederive {
                workspace: Some(want),
                ..Default::default()
            },
        };
        decoded.content_charge().unwrap();
        let result = decoded.rederive_content(&File::open(&path).unwrap());
        assert_eq!(
            result.unwrap().0.accumulator.workspace_path,
            Some(PathBuf::from("x".repeat(size)))
        );
    }
    let row = json!({"type":"message","cwd":"/synthetic/wrong-row"}).to_string();
    let path = scratch.write("not-header", std::slice::from_ref(&row));
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
    acc.workspace_path = Some(PathBuf::from("/synthetic/wrong-row"));
    acc.durable_marks.workspace = Some((row.len() + 1) as u64);
    let want = workspace_digest(&acc).unwrap();
    acc.workspace_path = None;
    let decoded = Decoded {
        reduction: CachedJsonlReduction {
            accumulator: acc,
            report: JsonlReadReport::default(),
            recognized_usage_drop_count: 0,
            positive_recognized_usage_count: 0,
            positive_usage_evidence: false,
        },
        rederive: Rederive {
            workspace: Some(want),
            ..Default::default()
        },
    };
    assert!(matches!(
        decoded.rederive_content(&File::open(&path).unwrap()),
        Err(Refuse::NotRederivable("content_fence"))
    ));
}

#[test]
fn skill_label_bounds_and_consent_preserve_the_whole_native_state() {
    let scratch = Scratch::new("label-bounds");
    let path = scratch.write("t.jsonl", &claude_lines(1, 1));
    let (base, _) = full_read(&path, SnapshotSource::ClaudeCode);
    for label in [
        "x".repeat(97),
        "é".into(),
        "a/b".into(),
        "a\\b".into(),
        "a\0b".into(),
    ] {
        let mut record = base.clone();
        record.accumulator.note_provider_skill(Some(label));
        let native = record.accumulator.provider_skills.clone();
        assert_eq!(
            encode_permitted(&record, usize::MAX, line_cap(), true).err(),
            Some(Refuse::NonEmpty("skill_label_out_of_bounds{set=provider}"))
        );
        assert_eq!(
            record.accumulator.provider_skills, native,
            "no filtering, truncation or recasing at persistence"
        );
    }
    let mut record = base.clone();
    record
        .accumulator
        .note_provider_skill(Some(format!("  {}  ", "A".repeat(96))));
    record.accumulator.note_activity_skills(
        "/synthetic/skills/FirstSpelling/SKILL.md /synthetic/skills/firstspelling/SKILL.md",
    );
    assert_eq!(
        record.accumulator.provider_skills,
        BTreeSet::from(["a".repeat(96)])
    );
    assert_eq!(
        record.accumulator.activity_skills,
        BTreeSet::from(["FirstSpelling".into()])
    );
    let body = encode_permitted(&record, usize::MAX, line_cap(), true).unwrap();
    assert!(body_has_skill_labels(&body).unwrap());
    let decoded = decode(&body, SnapshotSource::ClaudeCode).unwrap();
    assert!(
        !decoded.permits_skill_labels(false),
        "consent off never resurrects old labels"
    );
    assert!(decoded.permits_skill_labels(true));
    assert_eq!(
        encode_permitted(&record, usize::MAX, line_cap(), false).err(),
        Some(Refuse::NonEmpty("skill_label_consent_off"))
    );
    assert!(
        encode_permitted(&base, usize::MAX, line_cap(), false).is_ok(),
        "empty sets need no label permission"
    );
    assert!(
        encode_permitted(&record, usize::MAX, line_cap(), true).is_ok(),
        "turn-on permits the next native save without a forced read"
    );
    record.accumulator.activity_skills.insert("bad/path".into());
    assert_eq!(
        encode_permitted(&record, usize::MAX, line_cap(), true).err(),
        Some(Refuse::NonEmpty("skill_label_out_of_bounds{set=activity}"))
    );
}

#[test]
fn skill_labels_preserve_native_provider_and_activity_caps() {
    let scratch = Scratch::new("label-cap");
    let path = scratch.write("t.jsonl", &claude_lines(1, 1));
    let (mut record, _) = full_read(&path, SnapshotSource::ClaudeCode);
    for n in 0..33 {
        record
            .accumulator
            .note_provider_skill(Some(format!("Provider{n:02}")));
        record
            .accumulator
            .note_activity_skills(&format!("/synthetic/skills/Activity{n:02}/SKILL.md"));
    }
    record
        .accumulator
        .note_provider_skill(Some("Aardvark".into()));
    record
        .accumulator
        .note_activity_skills("/synthetic/skills/Aardvark/SKILL.md");
    assert!(!record.accumulator.provider_skills.contains("aardvark"));
    assert!(!record.accumulator.activity_skills.contains("Aardvark"));
    assert_eq!(
        record.accumulator.provider_skills.len(),
        crate::session_attribution::MAX_SKILL_FACTS + 1
    );
    assert_eq!(record.accumulator.activity_skills.len(), 33);
    assert!(record.accumulator.provider_skills.contains("provider08"));
    assert!(!record.accumulator.provider_skills.contains("provider09"));
    assert!(record.accumulator.activity_skills.contains("Activity32"));
    assert!(!record.accumulator.provider_skills.contains("provider33"));
    assert!(!record.accumulator.activity_skills.contains("Activity33"));
    let body = encode_permitted(&record, usize::MAX, line_cap(), true).unwrap();
    let decoded = decode(&body, SnapshotSource::ClaudeCode).unwrap();
    assert_eq!(
        decoded.reduction.accumulator.provider_skills,
        record.accumulator.provider_skills
    );
    assert_eq!(
        decoded.reduction.accumulator.activity_skills,
        record.accumulator.activity_skills
    );
    record.accumulator.activity_skills.insert("extra".into());
    assert_eq!(
        encode_permitted(&record, usize::MAX, line_cap(), true).err(),
        Some(Refuse::NonEmpty("skill_label_out_of_bounds{set=activity}"))
    );
    record.accumulator.activity_skills.remove("extra");
    // Native provider insertion stops at nine. Also pin the record codec's
    // approved <=33 bound independently of that narrower native cap.
    record.accumulator.provider_skills = (0..34).map(|n| format!("provider{n:02}")).collect();
    assert_eq!(
        encode_permitted(&record, usize::MAX, line_cap(), true).err(),
        Some(Refuse::NonEmpty("skill_label_out_of_bounds{set=provider}"))
    );
}

#[test]
fn pl_scope_is_closed_and_every_other_e_field_stays_refusing() {
    let shape = shape_text();
    let paths = |class: &str| {
        h_paths(&shape.replace("H ", "digest ").replace(class, "H "))
            .into_iter()
            .map(|path| path.split(':').next().unwrap().to_owned())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        paths("PL "),
        BTreeSet::from([
            "SnapshotAccumulator.activity_skills".into(),
            "SnapshotAccumulator.provider_skills".into()
        ])
    );
    assert_eq!(
        paths("E "),
        [
            "CodexPrelude.skills_body",
            "OpeningCall.files",
            "OrgMarkers.home",
            "SelectorCapture.context.attribution",
            "SnapshotAccumulator.codex_tier_replay",
            "SnapshotAccumulator.claude_desktop_identity",
            "SnapshotAccumulator.claude_desktop_spawn_lineage",
            "SnapshotAccumulator.codex_parent_signatures",
            "SnapshotAccumulator.codex_parent_prefix_proof",
            "SnapshotAccumulator.codex_parent_proof_used",
            "SnapshotAccumulator.codex_parent_proof_refusal",
            "SnapshotAccumulator.codex_legacy_bootstrap_buffer",
            "SnapshotAccumulator.artifacts",
            "SnapshotAccumulator.claude_usage_request_ids",
            "SnapshotAccumulator.claude_usage_occurrences",
            "SnapshotAccumulator.cache_observations",
            "SnapshotAccumulator.claude_fork_parent",
            "SnapshotAccumulator.claude_money",
            "SnapshotAccumulator.seen_pi_usage_keys",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
    );
}

/// [format] Pi native accounting and restore contract.
/// Exercise the registered Pi body through production decode and content replay.
#[test]
fn bounded_pi_prompt_workspace_tail_matches_cold_body_in_two_cycles() {
    let root = Scratch::new("pi-bounded-head-tail");
    let source = SnapshotSource::Pi;
    for cwd in [None, Some("/synthetic/pi-workspace")] {
        let lines = vec![
            json!({"type":"session","id":"synthetic-pi","cwd":cwd}).to_string(),
            json!({"type":"message","role":"user","content":"Synthetic first prompt"}).to_string(),
            json!({"type":"message","message":{"role":"assistant","model":"claude-sonnet-4-5","usage":{"input":20,"output":3},"timestamp":"2026-10-20T10:00:00Z"}}).to_string(),
        ];
        let path = root.write(if cwd.is_some() { "cwd" } else { "no-cwd" }, &lines);
        for cycle in 0..2 {
            let (native, checkpoint) = full_read(&path, source);
            let digests = rederive_digests(&native.accumulator, line_cap()).unwrap();
            assert!(digests.first_prompt.is_some());
            assert!(digests.session_start.is_none());
            assert!(digests.agent_label.is_none());
            let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
            let certificate = checkpoint
                .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
                .unwrap();
            let mut append = fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(append, "{}", json!({"type":"message","message":{"role":"user","content":format!("later prompt {cycle}")}})).unwrap();
            drop(append);
            let (checkpoint, _) = certificate
                .restore(&mut File::open(&path).unwrap(), scope())
                .unwrap();
            let decoded = decode_body(&body, source).unwrap();
            let (restored, receipt) = decoded
                .rederive_content(&File::open(&path).unwrap())
                .unwrap();
            assert!(receipt.head_bytes <= HEAD_BOUND);
            assert_eq!(
                restored.accumulator.first_prompt_material,
                native.accumulator.first_prompt_material
            );
            assert_eq!(
                restored.accumulator.first_prompt_title,
                native.accumulator.first_prompt_title
            );
            assert_eq!(restored.accumulator.workspace_path, cwd.map(PathBuf::from));
            let mut tail = parser(&path, source);
            assert_eq!(
                tail.prepare_acquisition(
                    Some(Retained {
                        checkpoint,
                        state: restored
                    }),
                    &scope(),
                    None,
                    NOW
                )
                .unwrap(),
                ReadMode::Tail
            );
            while !tail.step().unwrap() {}
            let actual = items(tail, &path, source);
            assert_eq!(actual, cold_items(&path, source));
            assert!(actual.to_string().contains("Synthetic first prompt"));
        }
    }
}

#[test]
fn bounded_plan_refuses_unsupported_codex_boundaries_and_oversized_marks_without_reads() {
    let root = Scratch::new("unsupported-bounded");
    let path = root.write("t", &codex_lines());
    let (native, _) = full_read(&path, SnapshotSource::Codex);
    let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
    for boundary in [
        CodexOwnershipBoundary::AwaitingLegacyTrigger,
        CodexOwnershipBoundary::AwaitingParentPrefix,
        CodexOwnershipBoundary::AmbiguousFork,
        CodexOwnershipBoundary::Undetermined,
    ] {
        let mut decoded = decode(&body, SnapshotSource::Codex).unwrap();
        decoded.reduction.accumulator.codex_ownership_boundary = boundary;
        assert!(decoded.rederive_plan().is_err());
    }
    let mut decoded = decode(&body, SnapshotSource::Codex).unwrap();
    decoded.rederive.first_prompt = Some([0; 32]);
    decoded.reduction.accumulator.durable_marks.first_prompt = Some(HEAD_BOUND + 1);
    assert_eq!(decoded.rederive_plan().err(), Some("mark"));
    let mut decoded = decode(&body, SnapshotSource::Codex).unwrap();
    decoded.rederive.title = Some([0; 32]);
    decoded.reduction.accumulator.durable_marks.title_line =
        Some((HEAD_BOUND + 1, TITLE_LINE_BOUND + 1));
    assert_eq!(decoded.rederive_plan().err(), Some("title"));
}

// F4: each H class fails atomically, and diagnostics identify only the class.
#[test]
fn bounded_fence_refuses_each_content_class_before_adoption() {
    let root = Scratch::new("all-content-fences");
    let source = SnapshotSource::Codex;
    let mut lines = codex_lines();
    let mut header: Value = serde_json::from_str(&lines[0]).unwrap();
    header["payload"]["source"] =
        json!({"subagent":{"thread_spawn":{"agent_path":"/agents/PRIVATE-AGENT-FENCE"}}});
    lines[0] = header.to_string();
    let path = root.write("source.jsonl", &lines);
    let (native, _) = full_read(&path, source);
    let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
    // Retain the ordinary corpus's supported plan; each injected digest is
    // deliberately impossible, including absent-class versus present mismatch.
    for class in 0..5 {
        let mut decoded = decode(&body, source).unwrap();
        let digest = match class {
            0 => &mut decoded.rederive.first_prompt,
            1 => &mut decoded.rederive.title,
            2 => &mut decoded.rederive.agent_label,
            3 => &mut decoded.rederive.session_start,
            4 => &mut decoded.rederive.workspace,
            _ => unreachable!(),
        };
        *digest = Some([0; 32]);
        let (result, rows) = crate::local_resource_diagnostics::capture(|| {
            decoded.rederive_content(&File::open(&path).unwrap())
        });
        assert!(matches!(
            result,
            Err(Refuse::NotRederivable("content_fence"))
        ));
        let counts = rows
            .iter()
            .find_map(|row| row["counts"].get("rederive_fence_mismatch"))
            .expect("fence alarm");
        assert_eq!(counts[class], 1);
        assert!(!serde_json::to_string(&rows)
            .unwrap()
            .contains("PRIVATE-AGENT-FENCE"));
    }
}

// F7: concurrent appends at the physical sample/head/title read boundaries
// preserve bounded replay and leave the appended suffix to ordinary Tail.
#[test]
fn bounded_restore_append_injection_at_samples_head_and_title_matches_cold_body() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for edge in [
            "before_samples",
            "between_samples",
            "after_samples",
            "head",
            "title",
        ] {
            let root = Scratch::new("bounded-append-stages");
            let lines = if source == SnapshotSource::ClaudeCode {
                claude_lines(20, 20)
            } else {
                let mut lines = codex_lines();
                let title = lines
                    .iter()
                    .position(|line| line.contains("thread_name_updated"))
                    .unwrap();
                let title = lines.remove(title);
                for n in 2..=3 {
                    let mut total = codex_usage(100 * n);
                    total["output_tokens"] = json!(3 * n);
                    total["total_tokens"] = json!(103 * n);
                    lines.push(json!({"type":"turn_context","payload":{"turn_id":format!("extra-{n}"),"model":"gpt-5.2"}}).to_string());
                    lines.push(json!({"type":"event_msg","payload":{"type":"task_started","turn_id":format!("extra-{n}")}}).to_string());
                    lines.push(json!({"type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":codex_usage(100),"total_token_usage":total}}}).to_string());
                    lines.push(json!({"type":"event_msg","payload":{"type":"task_complete","turn_id":format!("extra-{n}")}}).to_string());
                }
                lines.push(title);
                lines
            };
            let path = root.write("source.jsonl", &lines);
            let (native, checkpoint) = full_read(&path, source);
            let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
            let certificate = checkpoint
                .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
                .unwrap();
            let append = |path: &Path| {
                writeln!(
                    fs::OpenOptions::new().append(true).open(path).unwrap(),
                    "{{\"type\":\"progress\",\"data\":\"append-injection\"}}"
                )
                .unwrap();
            };
            append(&path); // scoped restore is growth-only
            if edge == "before_samples" {
                append(&path);
            }
            let hook_path = path.clone();
            let mut samples = 0;
            let target_sample = match edge {
                "between_samples" => 1,
                "after_samples" => 2,
                _ => 0,
            };
            let (checkpoint, _) = crate::transcript_acquisition::with_sample_read_hook(
                move || {
                    samples += 1;
                    if samples == target_sample {
                        append(&hook_path);
                    }
                },
                || certificate.restore_grown(&mut File::open(&path).unwrap(), scope()),
            )
            .unwrap();
            let decoded = decode(&body, source).unwrap();
            let plan = decoded.rederive_plan().unwrap();
            let title_offset = plan.title.map(|(offset, _)| offset);
            if edge == "title" {
                assert!(title_offset.is_some(), "fixture must read a named title");
            }
            let hook_path = path.clone();
            let mut fired = false;
            let (restored, receipt, _) = content::with_read_hook(
                move |offset| {
                    let target = (edge == "head" && offset == 0)
                        || (edge == "title" && Some(offset) == title_offset);
                    if target && !fired {
                        fired = true;
                        append(&hook_path);
                    }
                },
                || decoded.rederive_content_planned(&File::open(&path).unwrap(), &plan),
            )
            .unwrap();
            assert_eq!(receipt.head_bytes + receipt.line_bytes, plan.input_bytes());
            let mut tail = parser(&path, source);
            assert_eq!(
                tail.prepare_acquisition(
                    Some(Retained {
                        checkpoint,
                        state: restored
                    }),
                    &scope(),
                    None,
                    NOW
                )
                .unwrap(),
                ReadMode::Tail
            );
            while !tail.step().unwrap() {}
            assert_eq!(
                items(tail, &path, source),
                cold_items(&path, source),
                "{source:?}/{edge}"
            );
        }
    }
}

const PRIVACY_CANARIES: [&str; 4] = [
    "PRIVATE_LITERAL_DIAGNOSTICS_CANARY_20261030",
    "PRIVATE_REPLAY_HEAD_CANARY_20261030",
    "PRIVATE_REPLAY_PROMPT_CANARY_20261030",
    "PRIVATE_REPLAY_LABEL_CANARY_20261030",
];

/// The support tests consume the actual replay errors and diagnostic lines,
/// alongside the private input that must never be collected into a bundle.
pub(super) fn replay_privacy_artifacts(root: &Path) -> [&'static str; 4] {
    fs::create_dir_all(root).unwrap();
    let mut safe_log = String::new();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut lines = match source {
            SnapshotSource::ClaudeCode => claude_lines(2, 2),
            SnapshotSource::Codex => codex_lines(),
            SnapshotSource::Pi => vec![
                json!({"type":"session","id":"synthetic-pi","cwd":"/synthetic/privacy"})
                    .to_string(),
                json!({"type":"message","role":"user","content":"Synthetic Pi prompt"}).to_string(),
            ],
        };
        // Insert canaries in content, a head-only ignored field and an agent
        // label. A malformed selector and raw-value key are native inputs too.
        for line in &mut lines {
            let mut v: Value = serde_json::from_str(line).unwrap();
            v["private_head"] = json!(PRIVACY_CANARIES[1]);
            if let Some(content) = v.pointer_mut("/message/content") {
                if content.is_string() {
                    *content = json!(PRIVACY_CANARIES[2]);
                }
            }
            if source == SnapshotSource::Pi && v.get("role") == Some(&json!("user")) {
                v["content"] = json!(PRIVACY_CANARIES[2]);
            }
            if v.pointer("/payload/type") == Some(&json!("user_message")) {
                v["payload"]["message"] = json!(PRIVACY_CANARIES[2]);
            }
            if v.get("type") == Some(&json!("session_meta")) {
                v["payload"]["source"] = json!({"subagent":{"thread_spawn":{"agent_path":format!("/agents/{}", PRIVACY_CANARIES[3])}}});
            }
            *line = v.to_string();
        }
        lines.insert(
            0,
            json!({"selector":{"model":[PRIVACY_CANARIES[0]]}, "private_head":PRIVACY_CANARIES[1]})
                .to_string(),
        );
        let path = root.join(format!("{}-private.jsonl", source.api_slug()));
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        let (native, _) = full_read(&path, source);
        let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
        for class in 0..5 {
            let bad = decode_body(&body, source).unwrap().test_fence_body(class);
            // A real caught panic is a failed test, with a content-free failure
            // assertion. The subprocess test also inspects the panic hook sink.
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::local_resource_diagnostics::capture(|| {
                    decode_body(&bad, source)
                        .unwrap()
                        .rederive_content(&File::open(&path).unwrap())
                })
            }));
            assert!(
                caught.is_ok(),
                "replay must return a typed refusal without panicking"
            );
            let (result, rows) = caught.unwrap();
            let error = result.err().expect("inconsistent H refuses atomically");
            let text = format!("{error:?}\n{}\n", serde_json::to_string(&rows).unwrap());
            for canary in PRIVACY_CANARIES {
                assert!(!text.contains(canary));
            }
            safe_log.push_str(&text);
        }
        // Native raw-value handling accepts/reparses this physical input;
        // bounded replay must explicitly refuse the special key, without
        // reflecting either the input or serde's error payload.
        // Value's raw-value map consumes exactly one field. A second outer
        // field makes the native JSONL read lossy, so the certified full_read
        // premise would fail before bounded replay. Keep the canary inside the
        // raw JSON string; native parses it and bounded replay refuses the key.
        let raw = json!({
            "$serde_json::private::RawValue": json!({"ignored":PRIVACY_CANARIES[0]}).to_string()
        })
        .to_string()
            + "\n";
        fs::write(&path, raw + &lines.join("\n") + "\n").unwrap();
        let (native, _) = full_read(&path, source);
        let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
        let result = decode_body(&body, source)
            .unwrap()
            .rederive_content(&File::open(&path).unwrap());
        assert!(matches!(
            result,
            Err(Refuse::NotRederivable("raw_value_key"))
        ));
        safe_log.push_str(&format!("{:?}\n", result.err().unwrap()));
        // Corrupt persisted bytes and a descriptor error exercise both error
        // carriers without formatting a Value, prompt, title or label.
        assert!(decode_body(&body[..body.len() - 1], source).is_err());
        let fd = File::options().write(true).open(&path).unwrap();
        let err = decode_body(&body, source)
            .unwrap()
            .rederive_content(&fd)
            .err()
            .unwrap();
        safe_log.push_str(&format!("{err:?}\n"));
    }
    for canary in PRIVACY_CANARIES {
        assert!(!safe_log.contains(canary));
    }
    fs::write(root.join("replay-errors.log"), &safe_log).unwrap();
    eprintln!("{safe_log}");
    PRIVACY_CANARIES
}

#[test]
fn bounded_replay_errors_logs_and_panics_are_content_free() {
    const CHILD: &str = "OTTTO_BOUNDED_REPLAY_PRIVACY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let root = Scratch::new("privacy-child");
        replay_privacy_artifacts(&root.0);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "snapshots::sampled_jsonl::durable::tests::bounded_replay_errors_logs_and_panics_are_content_free", "--nocapture"])
        .env(CHILD, "1").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for canary in PRIVACY_CANARIES {
        assert!(
            !stdout.contains(canary),
            "content in stdout or panic payload"
        );
        assert!(!stderr.contains(canary), "content in log or panic payload");
    }
    assert!(
        stdout.contains("1 passed"),
        "child fixture must actually run"
    );
    assert!(
        output.status.success(),
        "privacy child must return typed errors without panic"
    );
}

/// [format] Pi native accounting and restore contract.
/// Exercise the production codec/acquisition/native-finish/finalizer interface with
/// actual A < C < B extents and a real complete native body (no hand-built item).
#[test]
fn codex_pi_restored_tail_race_below_accepted_publishes_complete_native_body() {
    let _on = RestartRestoreForTest::enabled();
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        let root = Scratch::new("pi-publication-race");
        let pi_lines = vec![
        json!({"type":"session","id":"synthetic-pi","cwd":"/synthetic/pi"}).to_string(),
        json!({"type":"message","role":"user","content":"Synthetic first Pi prompt"}).to_string(),
        json!({"type":"message","message":{"role":"assistant","model":"claude-sonnet-4-5","usage":{"input":20,"output":3},"timestamp":"2026-10-20T10:00:00Z"}}).to_string(),
    ];
        let lines = if source == SnapshotSource::Codex {
            codex_lines()
        } else {
            pi_lines
        };
        let path = root.write("source.jsonl", &lines);
        let (native, checkpoint) = full_read(&path, source);
        let a = fs::metadata(&path).unwrap().len();
        let body = encode(&native, crate::durable_tail_store::BODY_BYTES, line_cap()).unwrap();
        let certificate = checkpoint
            .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
            .unwrap();
        let total_input = std::cell::Cell::new(100);
        let total_output = std::cell::Cell::new(3);
        let append = |n| {
            let lines = if source == SnapshotSource::Codex {
                total_input.set(total_input.get() + n);
                total_output.set(total_output.get() + 3);
                let mut total = codex_usage(total_input.get());
                total["output_tokens"] = json!(total_output.get());
                total["total_tokens"] = json!(total_input.get() + total_output.get());
                vec![
                    json!({"type":"turn_context","timestamp":COLLECTED,"payload":{"turn_id":format!("race-{n}"),"model":"gpt-5.2"}}),
                    json!({"type":"event_msg","timestamp":COLLECTED,"payload":{"type":"task_started","turn_id":format!("race-{n}")}}),
                    json!({"type":"event_msg","timestamp":COLLECTED,"payload":{"type":"token_count","info":{"last_token_usage":codex_usage(n),"total_token_usage":total}}}),
                    json!({"type":"event_msg","timestamp":COLLECTED,"payload":{"type":"task_complete","turn_id":format!("race-{n}")}}),
                ]
            } else {
                vec![
                    json!({"type":"message","message":{"role":"assistant","model":"claude-sonnet-4-5","usage":{"input":n,"output":3},"timestamp":"2026-10-20T10:01:00Z"}}),
                ]
            };
            let mut fd = fs::OpenOptions::new().append(true).open(&path).unwrap();
            for line in lines {
                writeln!(fd, "{line}").unwrap();
            }
        };
        append(30);
        let c = fs::metadata(&path).unwrap().len();
        append(40);
        let b = fs::metadata(&path).unwrap().len();
        let finish = |parser: OwnedJsonlParser| {
            let identity = opened_object_identity(source, &mut File::open(&path).unwrap()).unwrap();
            parser
                .finish_with_repository_identity(
                    &identity,
                    &path,
                    COLLECTED,
                    "race-source".into(),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap()
        };
        let mut accepted = parser(&path, source);
        while !accepted.step().unwrap() {}
        let accepted = finish(accepted);
        assert!(accepted.report.complete());
        assert!(!accepted.snapshots.is_empty());
        let previous_entities: BTreeSet<String> = accepted
            .snapshots
            .iter()
            .map(|i| snapshot_fingerprint(source, i))
            .collect();
        let previous_bodies: BTreeSet<String> = accepted
            .snapshots
            .iter()
            .map(snapshot_upload_body_witness)
            .collect();
        let (checkpoint, _) = certificate
            .restore_grown(&mut File::open(&path).unwrap(), scope())
            .unwrap();
        let (restored, _) = decode_body(&body, source)
            .unwrap()
            .rederive_content(&File::open(&path).unwrap())
            .unwrap();
        // The accepted extent remains B while the actual plan freezes C.
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(c)
            .unwrap();
        assert!(a < c && c < b);
        let mut tail = parser(&path, source);
        let mode = tail
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
        assert_eq!(mode, ReadMode::Tail);
        let frozen = tail.reader.acquisition.as_ref().unwrap().frozen_length();
        while !tail.step().unwrap() {}
        let parsed = finish(tail);
        assert!(parsed.report.complete());
        let mut cold = parser(&path, source);
        while !cold.step().unwrap() {}
        assert_eq!(
            serde_json::to_value(&parsed.snapshots).unwrap(),
            serde_json::to_value(finish(cold).snapshots).unwrap()
        );
        let mut scan = SourceScanResult::empty(source);
        scan.snapshots = parsed.snapshots;
        scan.pending_finalization.push(PendingIndexFinalization {
            restored_behind_accepted: sampled_scan::durable_tail::restored_tail_below_accepted(
                source,
                true,
                mode,
                Some(frozen),
                Some(b),
            ),
            sampled_audit_verified: false,
            codex_pending_recovery: false,
            index_key: local_index_key(&path),
            source_file_fingerprint: "race-source".into(),
            previous_snapshot_fingerprint: Some(snapshot_file_entity_set_hex(&previous_entities)),
            previous_upload_body_witness: Some(snapshot_file_upload_body_set_hex(&previous_bodies)),
            parse_complete: parsed.report.complete(),
            diagnostic_reason: FileReason::Complete,
            parsed_snapshot_count: scan.snapshots.len(),
            effective_upload_body_witness_revision:
                crate::snapshot_sync::effective_upload_body_witness_revision(source),
        });
        let mut index = ScanIndex::default();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            finalize_scan_after_policy(source, &mut scan, &mut index)
        });
        assert!(!scan.snapshots.is_empty());
        assert_eq!(
            rows.iter()
                .filter_map(|r| r["counts"]["restored_behind_accepted"]["published"].as_u64())
                .sum::<u64>(),
            1
        );
    }
}

// E1 conditions (b)-(d) for M-2's labelled `E` field. (b) is the unchanged
// pins in durable_tail_store_tests.rs and released_decoders_tests.rs.

/// The label text the shape keeps for `SnapshotAccumulator.seen_pi_usage_keys`.
const PI_LEDGER_LABEL: &str = "BTreeMap<String, PiUsageDedupState>";

/// [format] Pi native accounting and restore contract.
/// E1 (c): the recorded label, the shape line it prints, and the real types
/// behind it. Fails if the label changes or the ledger's type drifts.
#[test]
fn pi_only_e_label_is_recorded_and_names_the_real_ledger_type() {
    use crate::durable_tail_codec::{PiOnlyDurable, PI_ONLY_E_LABELS};
    assert_eq!(
        PI_ONLY_E_LABELS,
        &[("SnapshotAccumulator.seen_pi_usage_keys", PI_LEDGER_LABEL)]
    );
    assert_eq!(<PiLedger as PiOnlyDurable>::FIELD, PI_ONLY_E_LABELS[0].0);
    assert!(
        shape_text().contains(&format!("E seen_pi_usage_keys: {PI_LEDGER_LABEL};")),
        "the shape keeps the recorded label text"
    );
    assert!(!crate::durable_tail_codec::pi_only_label_allowed(
        PI_ONLY_E_LABELS[0].0,
        PI_ONLY_E_LABELS[0].0,
        "DifferentType",
    ));
    let label = std::any::type_name::<BTreeMap<String, PiUsageDedupState>>();
    assert_eq!(
        std::any::type_name_of_val(&PiLedger::default().usage_keys),
        label
    );
    assert_eq!(
        std::any::type_name::<<PiLedger as PiOnlyDurable>::Label>(),
        label
    );
}

/// Same-named twins: the pre-M-2 unlabelled `E` field and the labelled one.
mod labelled_e_twins {
    use super::*;
    pub(super) mod legacy {
        use super::*;
        #[derive(Default)]
        pub(crate) struct SnapshotAccumulator {
            pub(crate) n: u64,
            pub(crate) seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState>,
        }
        crate::durable_tail_codec::durable_struct!(SnapshotAccumulator {
            N n: u64,
            E seen_pi_usage_keys: BTreeMap<String, PiUsageDedupState>,
        });
    }
    pub(super) mod labelled {
        use super::*;
        #[derive(Default)]
        pub(crate) struct SnapshotAccumulator {
            pub(crate) n: u64,
            pub(crate) seen_pi_usage_keys: PiLedger,
        }
        crate::durable_tail_codec::durable_struct!(SnapshotAccumulator {
            N n: u64,
            E seen_pi_usage_keys: PiLedger as BTreeMap<String, PiUsageDedupState>,
        });
    }
}

fn twin_shape<T: Durable>() -> (String, [u8; 32]) {
    let mut shape = Shape::default();
    T::shape(&mut shape);
    (shape.text().to_string(), shape.digest())
}

fn twin_bytes<T: Durable>(value: &T) -> Result<Vec<u8>, Refuse> {
    let mut e = Enc::bytes(1 << 20);
    value.put(&mut e)?;
    Ok(e.into_bytes())
}

/// [format] Pi native accounting and restore contract.
/// E1 (d), mechanism: the labelled arm is the unlabelled arm for its label
/// type. Same shape text and digest, same bytes, same refusal; bytes the old
/// type wrote decode into the new type and re-encode byte-identically.
#[test]
fn labelled_e_arm_is_wire_identical_to_the_unlabelled_arm() {
    use labelled_e_twins::{labelled, legacy};
    assert_eq!(
        twin_shape::<legacy::SnapshotAccumulator>(),
        twin_shape::<labelled::SnapshotAccumulator>()
    );
    let old = legacy::SnapshotAccumulator {
        n: 7,
        ..Default::default()
    };
    let old_bytes = twin_bytes(&old).unwrap();
    let new = labelled::SnapshotAccumulator {
        n: 7,
        ..Default::default()
    };
    assert_eq!(twin_bytes(&new).unwrap(), old_bytes);
    let mut d = Dec::new(&old_bytes);
    let decoded = <labelled::SnapshotAccumulator as Durable>::take(&mut d).unwrap();
    d.finish().unwrap();
    assert_eq!(decoded.n, 7);
    assert!(decoded.seen_pi_usage_keys.is_empty());
    assert_eq!(twin_bytes(&decoded).unwrap(), old_bytes);
    let refused = Err(Refuse::NonEmpty("SnapshotAccumulator.seen_pi_usage_keys"));
    let mut old = old;
    old.seen_pi_usage_keys
        .insert("k".into(), PiUsageDedupState::default());
    let mut new = new;
    new.seen_pi_usage_keys
        .insert("k".into(), PiUsageDedupState::default());
    assert_eq!(twin_bytes(&old), refused);
    assert_eq!(twin_bytes(&new), refused);
}

/// [format] Claude and Codex bodies with an empty ledger restore byte-identically.
#[test]
fn claude_and_codex_bodies_round_trip_byte_identical_through_the_pi_ledger() {
    let scratch = Scratch::new("pi-ledger-wire");
    for (source, name, lines) in [
        (
            SnapshotSource::ClaudeCode,
            "wire-claude.jsonl",
            claude_lines(2, 2),
        ),
        (SnapshotSource::Codex, "wire-codex.jsonl", codex_lines()),
    ] {
        let path = scratch.write(name, &lines);
        let (reduction, _) = full_read(&path, source);
        assert!(crate::durable_tail_codec::DurableEmpty::durable_empty(
            &reduction.accumulator.seen_pi_usage_keys
        ));
        let body = encode(&reduction, 1 << 20, line_cap()).unwrap();
        let decoded = decode_body(&body, source).unwrap();
        assert!(decoded.reduction.accumulator.seen_pi_usage_keys.is_empty());
        let (restored, _) = restore(&path, &body, source).unwrap();
        assert_eq!(
            encode(&restored, 1 << 20, line_cap()).unwrap(),
            body,
            "{name}"
        );
    }
}

/// [format] Pi native accounting and restore contract.
/// The codec/Tail rule runs on Linux too; the transition matrix additionally
/// checks native disk receipts, eviction and the shared money oracle on macOS.
#[test]
fn pi_fork_restore_tail_matches_cold_at_every_physical_line_cut() {
    let source = SnapshotSource::Pi;
    let header = json!({"type":"session","id":"synthetic-m2-cut",
        "timestamp":"2026-10-20T10:00:00Z","parentSession":"CANARY_M2_PARENT"})
    .to_string();
    let mut lines = vec![header];
    for (id, at) in [
        ("copied", "2026-10-20T09:59:59Z"),
        ("at", "2026-10-20T10:00:00Z"),
        ("after", "2026-10-20T10:00:01Z"),
    ] {
        for kind in ["message", "message_end"] {
            lines.push(
                json!({"type":kind,"timestamp":at,
                "message":{"role":"assistant","responseId":id,"timestamp":at,"model":"gpt-5.4",
                    "usage":{"input":100,"output":10}}})
                .to_string(),
            );
        }
        lines.push(
            json!({"type":"usage","id":id,"timestamp":at,"model":"gpt-5.4",
            "usage":{"input":20,"output":5}})
            .to_string(),
        );
    }
    for cut in 1..lines.len() {
        let scratch = Scratch::new("m2-cut");
        let path = scratch.write("fork.jsonl", &lines[..cut]);
        let (reduction, checkpoint) = full_read(&path, source);
        let bytes = encode(&reduction, 1 << 20, line_cap()).unwrap();
        let certificate = checkpoint
            .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
            .unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        for line in &lines[cut..] {
            writeln!(file, "{line}").unwrap();
        }
        drop(file);
        let (checkpoint, _) = certificate
            .restore(&mut File::open(&path).unwrap(), scope())
            .unwrap();
        let (restored, _) = restore(&path, &bytes, source).unwrap();
        assert!(restored.accumulator.seen_pi_usage_keys.fork_parts().0);
        let mut tail = parser(&path, source);
        assert_eq!(
            tail.prepare_acquisition(
                Some(Retained {
                    checkpoint,
                    state: restored
                }),
                &scope(),
                None,
                NOW
            )
            .unwrap(),
            ReadMode::Tail
        );
        while !tail.step().unwrap() {}
        assert_eq!(tail.accumulator.accepted_usage_totals.input_tokens, 240);
        assert_eq!(
            items(tail, &path, source),
            cold_items(&path, source),
            "cut {cut}"
        );
    }
}

/// [format] Pi native accounting and restore contract.
#[test]
fn copied_only_pi_fork_is_complete_emits_zero_and_restores_tail() {
    let scratch = Scratch::new("m2-only-copies");
    let at = "2026-10-20T09:59:59Z";
    let copy = json!({"type":"message","timestamp":at,"message":{"role":"assistant",
        "responseId":"copy","timestamp":at,"model":"gpt-5.4","usage":{"input":100,"output":10}}})
    .to_string();
    let path = scratch.write(
        "fork.jsonl",
        &[
            json!({"type":"session","id":"synthetic-copy-only","timestamp":"2026-10-20T10:00:00Z",
            "parentSession":"CANARY_M2_PARENT"})
            .to_string(),
            copy.clone(),
        ],
    );
    let source = SnapshotSource::Pi;
    let (reduction, checkpoint) = full_read(&path, source);
    assert_eq!(reduction.positive_recognized_usage_count, 0);
    assert!(
        !reduction.positive_usage_evidence,
        "known copied usage is not unexplained loss"
    );
    let bytes = encode(&reduction, 1 << 20, line_cap()).unwrap();
    let certificate = checkpoint
        .durable_certificate(birth_unix_nanos(&fs::metadata(&path).unwrap()))
        .unwrap();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(file, "{copy}").unwrap();
    drop(file);
    let (checkpoint, _) = certificate
        .restore(&mut File::open(&path).unwrap(), scope())
        .unwrap();
    let (restored, _) = restore(&path, &bytes, source).unwrap();
    let mut tail = parser(&path, source);
    assert_eq!(
        tail.prepare_acquisition(
            Some(Retained {
                checkpoint,
                state: restored
            }),
            &scope(),
            None,
            NOW
        )
        .unwrap(),
        ReadMode::Tail
    );
    while !tail.step().unwrap() {}
    let identity = opened_object_identity(source, tail.reader.reader.get_mut()).unwrap();
    let parsed = tail
        .finish(&identity, &path, COLLECTED, "fp".into(), None, None, None)
        .unwrap();
    assert!(parsed.complete(), "copied-only forks can be checkpointed");
    assert_eq!(
        parsed.snapshots.len(),
        1,
        "a zero correction must be publishable"
    );
    assert_eq!(parsed.snapshots[0].input_tokens, 0);
    assert_eq!(parsed.snapshots[0].request_count, 0);
    let cold = cold_items(&path, source);
    assert_eq!(
        serde_json::to_value(&parsed.snapshots).unwrap(),
        cold["items"]
    );
    // Unknown positive evidence or malformed owned usage still fails closed.
    fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(
        b"{\"type\":\"message\",\"timestamp\":\"bad\",\"message\":{\"role\":\"assistant\",\"usage\":{\"input\":50}}}\n"
    ).unwrap();
    let bad = cold_items(&path, source);
    assert!(
        bad["items"].as_array().unwrap().is_empty(),
        "invalid owned evidence cannot manufacture a zero carrier"
    );
}
