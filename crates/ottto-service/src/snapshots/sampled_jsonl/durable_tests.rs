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
    let parsed = parser
        .finish_with_repository_identity(
            &identity,
            path,
            COLLECTED,
            "fp".into(),
            None,
            None,
            None,
            None,
            money,
        )
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
const ALLOWLIST_PINS: [(SnapshotSource, &str); 2] = [
    (
        SnapshotSource::ClaudeCode,
        "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c",
    ),
    (
        SnapshotSource::Codex,
        "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
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
    use crate::durable_tail_store::{MAX_BATCH, MAX_RECORDS, RECORD_BYTES, STORE_BYTES};
    // A restored copy is charged to the 31 MiB state budget like any
    // retained copy; one record never exceeds one cache entry.
    assert_eq!(RECORD_BYTES, crate::transcript_cache::ENTRY_BYTES);
    assert_eq!(MAX_RECORDS, crate::transcript_cache::CACHE_ENTRIES);
    // Disk: at most 32 MiB per source store.
    assert_eq!(STORE_BYTES, 32 * 1024 * 1024);
    // Per restore: one record read, two 4 KiB sample windows, a head
    // re-parse of at most 1 MiB and at most NAMED_LINES capped lines.
    assert_eq!(HEAD_BOUND, 1024 * 1024);
    assert_eq!(NAMED_LINES, 4);
    // Beside the cache, outside its state budget: both stores' digest maps.
    assert_eq!(
        crate::snapshots::sampled_scan::durable_tail::STORES_RESIDENT_BOUND,
        64 * 1024
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
    .any(|source| decode(body, source).is_ok())
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

/// [format] One-shot CI recipe: retain untouched records from the real v1 writer.
#[test]
fn generate_53d05a43_v1_goldens() {
    use crate::durable_tail_store::{
        self as store, Binding, DurableSource, DurableTailStore, PendingRecord,
    };
    use crate::snapshots::codex_counting_version::{self, AckEvidence, TestCutover};
    use crate::snapshots::sampled_scan::durable_tail::Interpretation;
    use sha2::{Digest, Sha256};

    const SOURCE_SHA: &str = "53d05a4304f2e87effbaa48661e10286bff01c58";
    const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    const AT: &str = "2026-08-02T07:00:10Z";
    const CODEX_AT: &str = "2026-10-27T07:00:00Z";
    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn write_json(path: &Path, value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap();
        bytes.push(b'\n');
        fs::write(path, &bytes).unwrap();
        bytes
    }
    // Same physical rows as the native transition fixture, through its parser.
    fn codex_rows(turn: &str, tokens: u64) -> Vec<String> {
        let usage = json!({"input_tokens":tokens,"cached_input_tokens":0,"output_tokens":2,
            "reasoning_output_tokens":0,"total_tokens":tokens+2});
        [
            json!({"type":"event_msg","timestamp":"2026-10-27T07:00:01Z","payload":{"type":"task_started","turn_id":turn}}),
            json!({"type":"token_usage_record","timestamp":"2026-10-27T07:00:02Z","payload":{"thread_id":ROOT,"turn_id":turn,"response_id":turn,"usage":usage,"thread_token_usage":usage}}),
            json!({"type":"event_msg","timestamp":"2026-10-27T07:00:03Z","payload":{"type":"token_count","info":{"model":"gpt-5.2","last_token_usage":usage,"total_token_usage":usage}}}),
            json!({"type":"event_msg","timestamp":"2026-10-27T07:00:04Z","payload":{"type":"task_complete","turn_id":turn}}),
        ].iter().map(Value::to_string).collect()
    }

    let out = PathBuf::from(std::env::var_os("GOLDENS_OUT").expect("GOLDENS_OUT must be set"));
    let generator_commit = std::env::var("GENERATOR_COMMIT").expect("GENERATOR_COMMIT must be set");
    assert_eq!(generator_commit.len(), 40);
    assert!(generator_commit.bytes().all(|b| b.is_ascii_hexdigit()));
    fs::create_dir_all(out.join("inputs")).unwrap();
    fs::create_dir_all(out.join("expected")).unwrap();
    let mut cases = Vec::new();
    for (case, source) in [
        ("claude-three-request", SnapshotSource::ClaudeCode),
        ("claude-selector-unequal", SnapshotSource::ClaudeCode),
        ("codex-legacy-acked", SnapshotSource::Codex),
        ("codex-v2-24b", SnapshotSource::Codex),
    ] {
        let claude = source == SnapshotSource::ClaudeCode;
        let legacy = case == "codex-legacy-acked";
        let selector = case == "claude-selector-unequal";
        let scratch = Scratch::new(case);
        fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = crate::locked_state_dir::LockedStateDir::acquire(&scratch.0).unwrap();
        let index_path = scratch.0.join("index.json");
        let mut lines = if claude {
            [10, 20, 30].into_iter().enumerate().map(|(i, tokens)| {
                let request = format!("r{}", i + 1);
                json!({"type":"assistant","sessionId":ROOT,"version":"2.1.309",
                    "timestamp":AT,"requestId":request,
                    "message":{"id":format!("msg-{request}"),"model":"claude-haiku-4-5",
                        "usage":{"input_tokens":tokens,"output_tokens":tokens,
                            "cache_read_input_tokens":3,"cache_creation_input_tokens":7,
                            "cache_creation":{"ephemeral_5m_input_tokens":5,"ephemeral_1h_input_tokens":2}}}}).to_string()
            }).collect::<Vec<_>>()
        } else {
            let mut header = json!({"type":"session_meta","timestamp":CODEX_AT,
                "payload":{"id":ROOT,"timestamp":CODEX_AT}});
            if !legacy {
                header["payload"]["cli_version"] = json!("0.148.9");
            }
            let mut rows = vec![header.to_string()];
            rows.extend(codex_rows(if legacy { "turn-a" } else { "initial" }, 10));
            rows
        };
        let path = scratch.write(&format!("{ROOT}.jsonl"), &lines);
        let key = local_index_key(&path);
        let namespace = Scope("synthetic-v1-goldens".into());
        let mut index = ScanIndex::default();
        let mut prior_ack = Value::Null;
        let mut evidence_rows = Vec::new();
        // Legacy is first parsed and ACKed before cutover, then re-read with
        // the actual compiled cutover and that saved index's ACK evidence.
        for pass in 0..=usize::from(legacy) {
            let cutover = if legacy && pass == 0 {
                i64::MAX
            } else {
                codex_counting_version::CODEX_COUNTING_V2_CUTOVER_UNIX_MS.unwrap()
            };
            let _cutover = TestCutover::set(cutover);
            if pass == 1 {
                lines.extend(codex_rows("turn-b", 20));
                fs::write(&path, lines.join("\n") + "\n").unwrap();
            }
            let text = fs::read(&path).unwrap();
            let fingerprint = format!("sha256:{}", sha(&text));
            let ack = AckEvidence::of_view(index.files.values());
            if legacy && pass == 1 {
                assert_eq!(ack, AckEvidence::LegacyAcked);
            }
            let before = json!({"generation":index.generation,
                "entry":index.files.get(&key),"ack_evidence":ack});
            let (mut reduction, checkpoint, mut parsed) =
                claude_history_upgrade::with_staged_births_for_test(
                    BTreeMap::from([(key.clone(), 1_785_654_000_000_000_000)]),
                    || {
                        let mut p = parser(&path, source);
                        if !claude {
                            codex_counting_version::configure(
                                &mut p.accumulator,
                                ack,
                                Some(cutover),
                            );
                            let (previous, required) =
                                codex_file_join::receipt_state(index.files.get(&key));
                            p.accumulator.codex_tier_replay =
                                Some(codex_file_join::TierReplay::new(
                                    previous,
                                    required,
                                    namespace.0.clone(),
                                ));
                        }
                        assert!(matches!(
                            p.prepare_acquisition(None, &scope(), None, NOW).unwrap(),
                            ReadMode::Full(_)
                        ));
                        while !p.step().unwrap() {}
                        let reduction = p.reduction_copy();
                        let checkpoint = match p.certify_without_retention(&scope(), NOW).unwrap() {
                            SideCertificate::Certified { completed, .. } => completed.checkpoint,
                            _ => panic!("synthetic full read must certify"),
                        };
                        let identity =
                            opened_object_identity(source, &mut File::open(&path).unwrap())
                                .unwrap();
                        let parsed = p
                            .finish_with_repository_identity(
                                &identity,
                                &path,
                                COLLECTED,
                                fingerprint.clone(),
                                None,
                                None,
                                None,
                                None,
                                None,
                            )
                            .unwrap();
                        (reduction, checkpoint, parsed)
                    },
                );
            assert_eq!(parsed.snapshots.len(), 1);
            assert_eq!(parsed.recognized_usage_drop_count, 0);
            let v2 = !claude && !legacy;
            assert_eq!(reduction.accumulator.codex_counting_v2(), v2);
            let mut counting_receipts =
                crate::codex_scan_diagnostics::CountingV2Receipts::default();
            if let Some(counting) = &reduction.accumulator.codex_counting {
                counting.fold_receipts(&mut counting_receipts);
                if v2 {
                    assert_eq!(counting_receipts.native_counted, 1);
                } else {
                    assert_eq!(counting_receipts.v2_sessions, 0);
                }
            }
            if claude {
                let mut read = crate::claude_local_otel::ClaudeApiEvidenceRead::default();
                evidence_rows = [10, 20, 30]
                    .into_iter()
                    .enumerate()
                    .map(|(i, tokens)| {
                        let request = format!("r{}", i + 1);
                        let cost = (i as u64 + 1) * 100;
                        let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
                            capture_revision: "claude_api_request:v2".into(),
                            session_id: ROOT.into(),
                            request_id: request.clone(),
                            client_request_id: format!("client-{request}"),
                            observed_at: AT.into(),
                            model: "claude-haiku-4-5".into(),
                            effort: "high".into(),
                            query_source: "user".into(),
                            app_version: "2.1.309".into(),
                            event_sequence: Some(cost + 1),
                            cost_usd_micros: Some(cost),
                            input_tokens: tokens,
                            output_tokens: tokens,
                            cache_read_tokens: 3,
                            cache_creation_tokens: 7,
                            cache_creation_5m_tokens: 5,
                            cache_creation_1h_tokens: 2,
                            request_count: 1,
                            ..Default::default()
                        };
                        row.fingerprint =
                            format!("sha256:{}", sha(&serde_json::to_vec(&row).unwrap()));
                        row
                    })
                    .collect();
                read.evidence.insert(ROOT.into(), evidence_rows.clone());
                claude_request_money::e2::decide_page_copies(&mut parsed.snapshots, &index);
                claude_request_money::e2::attach_page(&mut parsed.snapshots, &read);
                let fold = parsed.snapshots[0]
                    .claude_money
                    .as_ref()
                    .expect("populated native fold");
                assert_eq!(
                    fold.entity
                        .grains
                        .values()
                        .map(|g| g.cost_micros)
                        .sum::<u64>(),
                    600
                );
            }
            let item = &mut parsed.snapshots[0];
            assert_eq!(item.source_session_id, ROOT);
            if claude {
                let start = item
                    .session_start
                    .as_ref()
                    .expect("closed three-request start window");
                assert_eq!(start.opening_request_count, Some(3));
                assert_eq!(start.request_2_context_tokens, Some(30));
                assert_eq!(start.request_3_context_tokens, Some(40));
                assert_eq!(start.opening_output_tokens, Some(30));
            } else if !legacy {
                assert_eq!(
                    item.session_start
                        .as_ref()
                        .unwrap()
                        .client_version
                        .as_deref(),
                    Some("0.148.9")
                );
            }
            let (input, output, requests) = if claude {
                (60, 60, 3)
            } else if legacy && pass == 1 {
                (30, 4, 2)
            } else {
                (10, 2, 1)
            };
            assert_eq!(
                (item.input_tokens, item.output_tokens, item.request_count),
                (input, output, requests)
            );
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
            let members = BTreeSet::from([item.snapshot_fingerprint.clone()]);
            let witnesses = BTreeSet::from([snapshot_upload_body_witness(item)]);
            let metadata = fs::metadata(&path).unwrap();
            let tier_receipt = reduction
                .accumulator
                .codex_tier_replay
                .clone()
                .and_then(|replay| replay.finish().unwrap());
            let entry: ScanIndexEntry = serde_json::from_value(json!({
                "size_bytes":metadata.len(),"modified_unix_seconds":metadata.mtime().max(0) as u64,
                "modified_unix_nanos":metadata.mtime_nsec(),"source_file_fingerprint":fingerprint,
                "last_snapshot_fingerprint":snapshot_file_entity_set_hex(&members),
                "last_upload_body_witness":snapshot_file_upload_body_set_hex(&witnesses),
                "effective_upload_body_witness_revision":crate::snapshot_sync::effective_upload_body_witness_revision(source),
                "codex_counting_v2":v2,"codex_counting_owner":if claude { None } else { Some(ROOT) },
                "codex_applied_tier_receipt":tier_receipt,"codex_captured_tier_receipt":tier_receipt
            })).unwrap();
            index.files.insert(key.clone(), entry);
            index
                .file_snapshot_fingerprints
                .insert(key.clone(), members.clone());
            index.record_accepted_snapshot_fingerprints(&members);
            assert!(index.accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
            if legacy && pass == 0 {
                index.save(&index_path).unwrap();
                prior_ack = json!({"cutover_unix_ms":cutover,"generation":index.generation,
                    "entry":index.files[&key],"accepted":members});
                continue;
            }
            let empty_body = encode(&reduction, store::RECORD_BYTES, line_cap()).unwrap();
            if selector {
                assert!(reduction.accumulator.current_selector.is_empty());
                reduction.accumulator.current_selector.insert(
                    "service_tier",
                    "priority".into(),
                    "derived_from_logs_2",
                );
            }
            let body = encode(&reduction, store::RECORD_BYTES, line_cap()).unwrap();
            verify(&body).unwrap();
            let decoded = decode(&body, source).unwrap();
            let selector_span = if selector {
                let capture = &reduction.accumulator.current_selector;
                assert_eq!(decoded.reduction.accumulator.current_selector, *capture);
                assert_eq!(
                    capture.context.get("service_tier").map(String::as_str),
                    Some("priority")
                );
                assert_eq!(
                    capture.sources.get("service_tier").map(String::as_str),
                    Some("derived_from_logs_2")
                );
                let mut e = Enc::bytes(1024);
                capture.put(&mut e).unwrap();
                let selected = e.into_bytes();
                let offsets = body
                    .windows(selected.len())
                    .enumerate()
                    .filter_map(|(at, window)| (window == selected).then_some(at))
                    .collect::<Vec<_>>();
                assert_eq!(
                    offsets.len(),
                    1,
                    "selected nonempty capture has one exact span"
                );
                let at = offsets[0];
                let mut e = Enc::bytes(1024);
                SelectorCapture::default().put(&mut e).unwrap();
                let mut replaced = body[..at].to_vec();
                replaced.extend(e.into_bytes());
                replaced.extend_from_slice(&body[at + selected.len()..]);
                assert_eq!(
                    replaced, empty_body,
                    "span is exactly current_selector's insertion"
                );
                let mut e = Enc::bytes(1024);
                capture.context.put(&mut e).unwrap();
                let context_len = e.position().unwrap();
                capture.sources.put(&mut e).unwrap();
                assert_eq!(e.into_bytes(), selected);
                let offset = store::HEADER_BYTES + at;
                json!({"offset":offset,"length":selected.len(),"body_offset":at,
                    "field":"SnapshotAccumulator.current_selector",
                    "context":{"offset":offset,"length":context_len},
                    "sources":{"offset":offset+context_len,"length":selected.len()-context_len}})
            } else {
                Value::Null
            };
            let pre_save =
                json!({"generation":index.generation,"entry":index.files[&key],"accepted":members});
            index.save(&index_path).unwrap();
            let entry = &index.files[&key];
            assert!(entry.last_upload_body_witness.is_some());
            let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
            let ds = if claude {
                DurableSource::ClaudeCode
            } else {
                DurableSource::Codex
            };
            let allowlist = allowlist_digest(source);
            assert_eq!(
                hex(&allowlist),
                if claude {
                    "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"
                } else {
                    "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1"
                }
            );
            let binding = Binding {
                source: ds,
                key: store::key_digest(ds, &key),
                context: store::context_digest(
                    &namespace.0,
                    index.active_upload_context_fingerprint.as_deref(),
                ),
                scope: store::replay_scope_digest(
                    &store::scope_digest(
                        &scope().0,
                        &allowlist,
                        &interpretation.identity_contract,
                        &interpretation.counting_view,
                    ),
                    crate::snapshot_sync::effective_upload_body_witness_revision(source),
                    index.active_effective_upload_body_witness_revision,
                    if claude {
                        index.claude_money_birth_store.money_rule_version()
                    } else {
                        0
                    },
                    claude && claude_request_money::e2::enabled(),
                ),
                entry: store::replay_entry_digest(
                    &store::entry_digest(
                        &entry.source_file_fingerprint,
                        entry.last_upload_body_witness.as_deref(),
                    ),
                    entry.effective_upload_body_witness_revision,
                    if claude {
                        index
                            .claude_money_birth_store
                            .money_marks(claude_money_birth_store::location_key(&key))
                    } else {
                        0
                    },
                ),
            };
            let certificate = checkpoint
                .durable_certificate(birth_unix_nanos(&metadata))
                .unwrap();
            let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
            assert_eq!(
                disk.write_after_save(
                    &lock,
                    index.generation,
                    vec![PendingRecord {
                        binding: binding.clone(),
                        certificate,
                        body: body.clone(),
                        allowlist,
                    }]
                )
                .unwrap()
                .written,
                1
            );
            let record = fs::read(disk.dir().join(format!("{}.rec", hex(&binding.key)))).unwrap();
            assert_eq!(&record[store::HEADER_BYTES..record.len() - 32], body);
            assert_eq!(u16::from_le_bytes(record[8..10].try_into().unwrap()), 1);
            assert_eq!(record[42], if claude { 1 } else { 2 });
            assert_eq!(
                u64::from_le_bytes(record[171..179].try_into().unwrap()),
                index.generation
            );
            let facts = json!({"source_session_id":ROOT,"input_tokens":input,"output_tokens":output,
                "request_count":requests,"counting_version":if claude { "not_applicable" } else if legacy { "Legacy" } else { "V2" },
                "cache_read_tokens":if claude { 9 } else { 0 },
                "cache_creation_5m_tokens":if claude { 15 } else { 0 },
                "cache_creation_1h_tokens":if claude { 6 } else { 0 },
                "telemetry_cost_micros":if claude { Some(600) } else { None },
                "opening_request_count":if claude { Some(3) } else { None },
                "request_2_context_tokens":if claude { Some(30) } else { None },
                "request_3_context_tokens":if claude { Some(40) } else { None },
                "opening_output_tokens":if claude { Some(30) } else { None },
                "cli_version":if !claude && !legacy { Some("0.148.9") } else { None },
                "selector_context":if selector { json!({"service_tier":"priority"}) } else { json!({}) },
                "selector_sources":if selector { json!({"service_tier":"derived_from_logs_2"}) } else { json!({}) },
                "accepted_body_witness":true,"tier_replay_present":!claude});
            assert_eq!(item.cache_read_tokens, if claude { 9 } else { 0 });
            assert_eq!(item.cache_creation_5m_tokens, if claude { 15 } else { 0 });
            assert_eq!(item.cache_creation_1h_tokens, if claude { 6 } else { 0 });
            if !claude {
                assert!(decoded.reduction.accumulator.codex_tier_replay.is_some());
            }
            let expected = json!({"schema_version":1,"case_id":case,"facts":facts,
                "scope_inputs":{"file_scope":scope().0,"namespace":namespace.0,
                    "identity_contract":interpretation.identity_contract,"counting_view":interpretation.counting_view,
                    "fixture_birth_unix_nanos":1_785_654_000_000_000_000u64,
                    "index_key_recipe":"local_index_key of the synthetic transcript in the CI scratch directory",
                    "fingerprint_recipe":"sha256 of inputs JSONL bytes"},
                "pre_read":before,"pre_save":pre_save,"post_save":{"generation":index.generation,"entry":entry,"accepted":members},
                "prior_legacy_ack":prior_ack,"api_evidence":evidence_rows,"counting_receipts":counting_receipts,
                "binding":{"key":hex(&binding.key),"context":hex(&binding.context),
                    "scope":hex(&binding.scope),"entry":hex(&binding.entry)},"selector_span":selector_span});
            let record_path = format!("{case}.rec");
            let input_path = format!("inputs/{case}.jsonl");
            let expected_path = format!("expected/{case}.json");
            fs::write(out.join(&record_path), &record).unwrap();
            fs::write(out.join(&input_path), &text).unwrap();
            let expected_bytes = write_json(&out.join(&expected_path), &expected);
            cases.push(json!({"case_id":case,"path":record_path,"byte_length":record.len(),"sha256":sha(&record),
                "envelope_version":1,"source_tag":if claude { 1 } else { 2 },"historical_allowlist":hex(&allowlist),
                "index_generation":index.generation,
                "input":{"path":input_path,"byte_length":text.len(),"sha256":sha(&text)},
                "expected":{"path":expected_path,"byte_length":expected_bytes.len(),"sha256":sha(&expected_bytes)},
                "expected_facts":facts,"selector_span":selector_span}));
        }
    }
    assert_eq!(cases.len(), 4);
    write_json(
        &out.join("MANIFEST.json"),
        &json!({"schema_version":1,"source_sha":SOURCE_SHA,
        "generator_commit":generator_commit,"repo":"ottto-ai/ottto","workflow_path":".github/workflows/linux-tests.yml",
        "run_id":null,"run_attempt":null,"run_url":null,"artifact":{"id":null,"name":null},
        "rustc":null,"toolchain":null,"runner_os":null,"runner_arch":null,"cases":cases}),
    );
}
