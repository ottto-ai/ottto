//! The Claude Tail codec on real parses of synthetic transcripts: every field
//! home round-trips, missing state is an incomplete reconstruction, skill
//! labels are data, and the head identity binds no delivery input.
use super::super::stage_full;
use super::*;
use crate::snapshots::sampled_jsonl::CachedJsonlReduction;
use crate::snapshots::sampled_scan::transition_fixture::native_cold as fixture;
use crate::snapshots::state_v2::StagedFile;
use crate::transcript_acquisition::{ReadMode, Scope};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: u64 = 1_790_000_000;
const SESSION: &str = "5f0c2a8e-1111-4222-8333-944445555777";
/// Non-ASCII, and longer than the record store's 96-byte label bound.
const SKILL: &str = "ünïcödé-skill-ünïcödé-skill-ünïcödé-skill-ünïcödé-skill-ünïcödé-skill-ünïcödé";

/// A user prompt, then `responses` assistant responses a minute apart, each
/// with a capability tool use, a compaction boundary after every fourth, and
/// a title. The first response also invokes the `SKILL` skill.
pub(in crate::snapshots) fn lines(responses: usize) -> Vec<String> {
    let at = |minute: usize| format!("2026-10-20T{:02}:{:02}:00Z", 10 + minute / 60, minute % 60);
    let mut lines = vec![json!({"type":"user","sessionId":SESSION,"uuid":"u-0",
        "parentUuid":null,"timestamp":at(0),"cwd":"/tmp/tail-claude","version":"2.1.0",
        "message":{"role":"user","content":"please review the change"}})
    .to_string()];
    for i in 0..responses {
        let mut content = vec![json!({"type":"tool_use","id":format!("toolu_{i:04}"),
            "name":"mcp__claude-in-chrome__navigate","input":{}})];
        if i == 0 {
            content.push(json!({"type":"tool_use","id":"toolu_skill","name":"Skill",
                "input":{"skill":SKILL}}));
        }
        lines.push(
            json!({"type":"assistant","sessionId":SESSION,"uuid":format!("a-{i}"),
                "timestamp":at(i),"cwd":"/tmp/tail-claude","requestId":format!("req_{i:04}"),
                "message":{"id":format!("msg_{i:04}"),"type":"message","role":"assistant",
                    "model":"claude-opus-4-1","stop_reason":"tool_use","content":content,
                    "usage":{"input_tokens":10 + i,"cache_creation_input_tokens":0,
                        "cache_read_input_tokens":0,"output_tokens":5}}})
            .to_string(),
        );
        if i % 4 == 3 {
            lines.push(
                json!({"type":"system","subtype":"compact_boundary","sessionId":SESSION,
                    "uuid":format!("c-{i}"),"timestamp":at(i),
                    "compactMetadata":{"trigger":"auto","preTokens":1000,"postTokens":100,
                        "durationMs":7}})
                .to_string(),
            );
        }
    }
    lines.push(
        json!({"type":"ai-title","sessionId":SESSION,"aiTitle":"Review the change"}).to_string(),
    );
    lines
}

/// A cold positioned Full read: the PRE-finalization reduction and the
/// checkpoint's certificate.
fn parse(lines: &[String]) -> (CachedJsonlReduction, DurableCertificate) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-tail-claude-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("session.jsonl");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let scope = Scope("tail-claude-codec".into());
    let mut parser = fixture::parser(
        SnapshotSource::ClaudeCode,
        &path,
        File::open(&path).unwrap(),
        apply_claude_code_line,
    );
    let mode = parser.prepare_acquisition(None, &scope, None, NOW).unwrap();
    assert!(matches!(mode, ReadMode::Full(_)));
    let (reduction, checkpoint) = fixture::finish_record(&mut parser, &scope, NOW);
    std::fs::remove_dir_all(&dir).unwrap();
    (reduction, checkpoint.durable_certificate(0).unwrap())
}

fn identity(file: &str, capture: bool) -> HeadIdentity {
    let root = Path::new("/home/projects");
    HeadIdentity::new(
        Path::new("/state/scan-index.json"),
        SnapshotSource::ClaudeCode,
        root,
        &root.join(file),
        capture,
    )
}

fn stage(reduction: &CachedJsonlReduction, certificate: &DurableCertificate) -> StagedFile {
    let (acc, report, scalars) = reduction.finish_view();
    let view = PreFinalization::new(acc, report, scalars);
    stage_full::<Claude>(&view, certificate, &identity("session.jsonl", false)).unwrap()
}

fn copy(staged: &StagedFile) -> StagedFile {
    StagedFile {
        revision: staged.revision,
        head: staged.head.clone(),
        collections: staged.collections.clone(),
        pages: staged.pages.clone(),
        obsolete: staged.obsolete.clone(),
        change: staged.change,
    }
}

/// Head first, then every page in key order, then the codec contract.
/// `into` is replaced whole by the head.
fn load(
    staged: &StagedFile,
    into: &mut SnapshotAccumulator,
) -> Result<DecodedHead, ReconstructCause> {
    let head = Claude::decode_head(staged.revision, &staged.head, into)?;
    for (&(collection, page), bytes) in &staged.pages {
        Claude::decode_page(collection, page, bytes, into)?;
    }
    Claude::validate_loaded(into, &staged.collections)?;
    Ok(head)
}

/// [format] Every Claude field home round-trips: head scalars and lineage,
/// paged collections across page boundaries, and content as session facts
/// only (opening-call files by call id). Finish and live fields stay out.
#[test]
fn every_claude_field_home_round_trips_through_head_and_pages() {
    let (mut reduction, certificate) = parse(&lines(300));
    let acc = reduction.accumulator_for_test();
    acc.activity_changed_file_hashes.extend(
        (0..3).map(|n| sha256_hex(&["ottto-activity-changed-file:v1", &format!("src/{n}.rs")])),
    );
    acc.claude_fork_parent = Some("4a1b2c3d-0000-4000-8000-000000000001".into());
    acc.artifacts.push(SessionArtifact {
        kind: "pull_request".into(),
        value: "https://example.invalid/pull/7".into(),
    });
    for (position, attachment) in [
        (
            1,
            json!({"type":"session_context","context":{"userEmail":"person@example.invalid"}}),
        ),
        (
            2,
            json!({"type":"credential_org","organizationUuid":"6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}),
        ),
    ] {
        claude_request_identity::note_marker_line(
            &mut acc.claude_org_markers,
            &json!({"type":"attachment","attachment":attachment}),
            position,
        );
    }
    acc.session_start
        .open_call_for_test("toolu_open", &["src/CANARY_OPEN_FILE.rs"]);
    let staged = stage(&reduction, &certificate);
    let (acc, _, _) = reduction.finish_view();
    assert_eq!(Claude::SOURCE, acc.source);
    assert_eq!(Claude::finish_field_nonempty(acc), None);
    let pages = |collection: Collection| {
        staged
            .pages
            .keys()
            .filter(|(stored, _)| *stored == collection)
            .count()
    };
    assert_eq!(
        [
            Collection::Responses,
            Collection::ToolUses,
            Collection::ChangedFiles,
            Collection::CapabilityHours,
            Collection::Compactions,
            Collection::SessionFacts,
        ]
        .map(pages),
        [2, 2, 1, 5, 2, 4]
    );
    let contents: [&[u8]; 4] = [
        b"please review",
        b"/tmp/tail-claude",
        b"Review the change",
        b"CANARY_OPEN_FILE",
    ];
    let holds =
        |value: &[u8], content: &[u8]| value.windows(content.len()).any(|window| window == content);
    for (key, value) in std::iter::once((None, &staged.head))
        .chain(staged.pages.iter().map(|(key, value)| (Some(key), value)))
    {
        if key.is_some_and(|(collection, _)| *collection == Collection::SessionFacts) {
            continue;
        }
        for content in contents {
            assert!(!holds(value, content), "content outside the session facts");
        }
    }
    // Title, first prompt, workspace, opening settings: each in its own slot.
    for (slot, content) in contents.into_iter().enumerate() {
        let slot = [1, 2, 0, 3][slot];
        assert!(holds(
            &staged.pages[&(Collection::SessionFacts, slot)],
            content
        ));
    }

    let mut loaded = acc.clone();
    let head = load(&staged, &mut loaded).unwrap();
    assert_eq!(head.certificate, certificate);
    assert_eq!(
        (&loaded.title, &loaded.workspace_path),
        (&acc.title, &acc.workspace_path)
    );
    assert_eq!(
        (&loaded.first_prompt_material, &loaded.first_prompt_title),
        (&acc.first_prompt_material, &acc.first_prompt_title)
    );
    assert_eq!(
        loaded.session_start.call_files_for_test("toolu_open"),
        acc.session_start.call_files_for_test("toolu_open")
    );
    assert_eq!(loaded.claude_fork_parent, acc.claude_fork_parent);
    assert!(loaded.provider_skills.contains(SKILL));

    // The loaded state encodes to exactly the stored head and pages.
    let view = PreFinalization::new(&loaded, &head.report, head.scalars);
    let again =
        stage_full::<Claude>(&view, &head.certificate, &identity("session.jsonl", false)).unwrap();
    assert_eq!(
        (
            again.revision,
            &again.head,
            &again.pages,
            &again.collections
        ),
        (
            staged.revision,
            &staged.head,
            &staged.pages,
            &staged.collections
        )
    );

    let mut live = acc.clone();
    live.account_identifier_hash = Some("a".repeat(64));
    assert_eq!(
        Claude::finish_field_nonempty(&live),
        Some("account_identifier_hash")
    );
}

/// [format] Missing or inconsistent stored state is a reconstruction cause,
/// never a default-empty success; an empty required collection is staged.
#[test]
fn missing_stored_state_is_an_incomplete_reconstruction() {
    let (reduction, certificate) = parse(&lines(300));
    let staged = stage(&reduction, &certificate);
    let (acc, _, _) = reduction.finish_view();
    let load_edited = |edit: &dyn Fn(&mut StagedFile)| {
        let mut edited = copy(&staged);
        edit(&mut edited);
        load(&edited, &mut acc.clone()).map(|_| ())
    };
    assert_eq!(load_edited(&|_| {}), Ok(()));
    assert_eq!(
        load_edited(&|staged| {
            staged.pages.remove(&(Collection::Responses, 1));
        }),
        Err(ReconstructCause::Incomplete)
    );
    assert_eq!(
        load_edited(&|staged| {
            staged.collections.remove(&Collection::ToolUses);
        }),
        Err(ReconstructCause::Incomplete)
    );
    assert_eq!(
        load_edited(&|staged| {
            if let Some(meta) = staged.collections.get_mut(&Collection::Responses) {
                meta.elements_per_page = 64;
            }
        }),
        Err(ReconstructCause::Incompatible)
    );
    assert_eq!(
        load_edited(&|staged| staged.revision = 0),
        Err(ReconstructCause::Revision)
    );
    let mut loaded = acc.clone();
    Claude::decode_head(staged.revision, &staged.head, &mut loaded).unwrap();
    assert_eq!(
        Claude::decode_page(
            Collection::Responses,
            1,
            &staged.pages[&(Collection::Responses, 1)],
            &mut loaded
        ),
        Err(ReconstructCause::Corrupt)
    );

    // No compactions: the collection is still staged, empty and without pages.
    let (small, certificate) = parse(&lines(2));
    let staged = stage(&small, &certificate);
    let (acc, _, _) = small.finish_view();
    assert_eq!(staged.collections[&Collection::Compactions].elements, 0);
    assert!(!staged
        .pages
        .keys()
        .any(|(collection, _)| *collection == Collection::Compactions));
    let mut edited = copy(&staged);
    load(&edited, &mut acc.clone()).unwrap();
    edited.collections.remove(&Collection::Compactions);
    assert_eq!(
        load(&edited, &mut acc.clone()).map(|_| ()),
        Err(ReconstructCause::Incomplete)
    );
}

/// [behaviour] Skill labels are data: non-ASCII, over-length, dot names, case
/// duplicates and more than 33 entries are stored as they are, never refused.
#[test]
fn skill_labels_round_trip_as_data() {
    let (mut reduction, certificate) = parse(&lines(2));
    let acc = reduction.accumulator_for_test();
    acc.activity_skills
        .extend(["Review", "review", ".", "..", SKILL].map(String::from));
    acc.activity_skills
        .extend((0..40).map(|n| format!("skill-{n:02}")));
    let staged = stage(&reduction, &certificate);
    let (acc, _, _) = reduction.finish_view();
    let mut loaded = acc.clone();
    load(&staged, &mut loaded).unwrap();
    assert!(acc.provider_skills.contains(SKILL) && acc.activity_skills.len() > 33);
    assert_eq!(loaded.provider_skills, acc.provider_skills);
    assert_eq!(loaded.activity_skills, acc.activity_skills);
}

/// [format] The head identity binds the route, the file and the capture mode.
/// A delivery-policy change (here the artifacts toggle) leaves it valid.
#[test]
fn head_identity_binds_route_file_and_capture_mode_only() {
    let (mut reduction, certificate) = parse(&lines(2));
    let before = stage(&reduction, &certificate);
    let acc = reduction.accumulator_for_test();
    acc.artifacts_enabled = !acc.artifacts_enabled;
    let after = stage(&reduction, &certificate);
    let id = identity("session.jsonl", false);
    assert_eq!(id.check(&before.head), Ok(()));
    assert_eq!(id.check(&after.head), Ok(()));
    assert_eq!(
        identity("other.jsonl", false).check(&before.head),
        Err(ReconstructCause::Identity)
    );
    assert_eq!(
        identity("session.jsonl", true).check(&before.head),
        Err(ReconstructCause::Incompatible)
    );
}
