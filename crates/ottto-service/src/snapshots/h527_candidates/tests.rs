use super::*;
use crate::snapshots::{
    claude_duplicate_request_owner, parse_claude_code_jsonl_file, snapshot_fingerprint,
    ClaudeUsageFamilyWitness,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const MACHINE: &str = "m4-fixture-machine";
const SESSION_EXCLUSIVE: &str = "session_exclusive_reported_usage:v1";
const SHARED_COPY_REQUEST: &str = "req-shared-copy";
const HELD_MIXED_FIXTURE: &str =
    include_str!("../../../../../fixtures/h527-candidates/held-mixed.v1.json");

fn session_id(ordinal: u64) -> String {
    format!("{ordinal:08x}-0000-4000-8000-{ordinal:012x}")
}

fn scope() -> OperatorScope {
    OperatorScope {
        operation_id: "00000000-0000-4000-8000-000000000527".to_string(),
        user_id: "10000000-0000-4000-8000-000000000001".to_string(),
        organization_id: "20000000-0000-4000-8000-000000000002".to_string(),
        device_id: "30000000-0000-4000-8000-000000000003".to_string(),
        machine_id: MACHINE.to_string(),
        producer_revision: "22f1d61acff69a705c03935aa2d591745569f4c8".to_string(),
    }
}

fn fixture_build() -> ProducerBuild {
    ProducerBuild {
        collector_version: "0.0.0-h527-fixture".to_string(),
        binary_sha256: sha256_hex(b"h527-fixture-binary"),
    }
}

fn member(ordinal: u64) -> ApprovedMember {
    let source_session_id = session_id(ordinal);
    ApprovedMember {
        session_key_sha256: session_key_sha256("claude_code", MACHINE, &source_session_id),
        prior_refusal_body_witness: sha256_hex(format!("refused-body-{ordinal}").as_bytes()),
        source_session_id,
    }
}

fn members() -> Vec<ApprovedMember> {
    (1..=18).map(member).collect()
}

/// One real parser item from a synthetic transcript. The parser leaves the
/// usage unproven; nothing here claims session-exclusive ownership.
fn parsed_item(source_session_id: &str, request_ids: &[&str]) -> SnapshotItem {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ottto-h527-{source_session_id}-{unique}.jsonl"));
    let mut lines = vec![json!({
        "timestamp": "2026-09-02T06:00:00Z",
        "type": "user",
        "sessionId": source_session_id,
        "message": {"role": "user", "content": "synthetic"},
    })];
    for (minute, request_id) in request_ids.iter().enumerate() {
        lines.push(json!({
            "timestamp": format!("2026-09-02T06:{:02}:00Z", minute + 1),
            "type": "assistant",
            "sessionId": source_session_id,
            "requestId": request_id,
            "message": {
                "id": format!("msg-{request_id}"),
                "role": "assistant",
                "model": "claude-opus-4-1",
                "usage": {"input_tokens": 10, "output_tokens": 2},
                "content": [{"type": "text", "text": "synthetic"}],
            },
        }));
    }
    fs::write(
        &path,
        lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write transcript");
    let item = parse_claude_code_jsonl_file(
        &path,
        "2026-09-02T07:00:00Z",
        "fixture-file-fingerprint".to_string(),
    )
    .expect("parse")
    .into_iter()
    .next()
    .expect("snapshot");
    let _ = fs::remove_file(path);
    item
}

/// The pipeline's own exclusive-usage promotion: contract then fingerprint.
fn exclusive(mut item: SnapshotItem) -> SnapshotItem {
    item.usage_accounting_contract = Some(SESSION_EXCLUSIVE.to_string());
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    item
}

fn complete_census() -> ClaudeUsageAuthorityDisposition {
    let mut disposition = ClaudeUsageAuthorityDisposition::default();
    disposition.duplicate_census.census_complete = true;
    disposition.duplicate_census.coverage_complete = true;
    disposition.transcript_ownership_complete = true;
    disposition
}

fn mark_duplicate(index: &mut ScanIndex, request_id: &str, owner_session_id: &str) {
    index
        .claude_duplicate_request_owners
        .entry(sha256_hex(request_id.as_bytes()))
        .or_default()
        .extend([
            claude_duplicate_request_owner(owner_session_id, owner_session_id),
            claude_duplicate_request_owner(
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
            ),
        ]);
}

fn run_export(
    snapshots: &[SnapshotItem],
    disposition: &ClaudeUsageAuthorityDisposition,
    index: &ScanIndex,
) -> CandidateExport {
    build_candidate_export(
        &scope(),
        &members(),
        &PipelineEvidence {
            upload_snapshots: snapshots,
            disposition,
            index,
        },
        &fixture_build(),
    )
    .expect("export")
}

fn packet_member(export: &CandidateExport, ordinal: u64) -> Value {
    let packet: Value = serde_json::from_str(&export.packet_json).expect("packet json");
    packet["members"][usize::try_from(ordinal - 1).expect("ordinal")].clone()
}

fn report(export: &CandidateExport, ordinal: u64) -> Value {
    let report = &export.qualification_reports[usize::try_from(ordinal - 1).expect("ordinal")];
    serde_json::from_slice(&report.canonical_json).expect("report json")
}

/// Held, conservation unknown, and no body field of any kind.
fn assert_held_without_body(member: &Value, reason: &str) {
    assert_eq!(member["disposition"], "held");
    assert_eq!(member["reason"], reason);
    assert_eq!(member["cross_session_conservation"], "unknown");
    let fields = member.as_object().expect("member object");
    assert!(!fields.contains_key("batch_request_json"));
    assert!(!fields.contains_key("batch_request_sha256"));
    assert!(!fields.contains_key("batch_request"));
}

#[test]
fn session_keys_match_backend_session_entity_key_vectors() {
    // Expected values come from the backend's session_entity_key over the
    // same tuples: escaped `session_key:v1`, not the unit-separated locator.
    for (machine_id, source_session_id, key, digest) in [
        (
            "m4-fixture-machine",
            "0b8f6a2e-1c4d-4e8a-9f3b-2d7c5a1e9b40",
            "claude_code|m4-fixture-machine|0b8f6a2e-1c4d-4e8a-9f3b-2d7c5a1e9b40",
            "bc527591455a6dfab337fcfeed880b1d454f55270eafcd67358aec7190c61ed2",
        ),
        (
            "machine|with|pipes",
            "11111111-2222-4333-8444-555555555555",
            "claude_code|machine\\pwith\\ppipes|11111111-2222-4333-8444-555555555555",
            "a7dc1c6cc0fbc6f204a13330e7eff5b887a8e6866700c8288f844726fbe0c9bb",
        ),
        (
            "machine\\back",
            "11111111-2222-4333-8444-555555555555_agent-a1|b\\c",
            "claude_code|machine\\\\back|11111111-2222-4333-8444-555555555555_agent-a1\\pb\\\\c",
            "7567bb0280ec06545b636389d1b2a13f268ce65c28088d978ef87c1646228f9c",
        ),
        (
            "\\z",
            "22222222-3333-4444-8555-666666666666",
            "claude_code|\\\\z|22222222-3333-4444-8555-666666666666",
            "0b729b7c5261012ab6ae2ac467305e74ca0760da594c353daa5a66774a5870f3",
        ),
    ] {
        assert_eq!(
            session_key_v1("claude_code", machine_id, source_session_id),
            key
        );
        assert_eq!(
            session_key_sha256("claude_code", machine_id, source_session_id),
            digest
        );
    }
}

#[test]
fn reason_vocabulary_is_closed() {
    assert_eq!(
        EligibleReason::ALL.map(EligibleReason::as_str),
        [
            "qualified_source_ownership",
            "exact_exclusion",
            "exact_previous_ack_membership",
        ]
    );
    assert_eq!(
        HeldReason::ALL.map(HeldReason::as_str),
        [
            "unknown_owner",
            "incomplete_census",
            "cap_overflow",
            "creator_hold",
            "missing_evidence",
            "money_decrease",
        ]
    );
}

/// Every hold class that member-scoped evidence can produce, in one packet.
#[test]
fn held_mixed_packet_matches_committed_fixture() {
    let mut disposition = complete_census();
    disposition.defer_sessions((4..=6).map(session_id).collect());
    disposition
        .quarantined_source_session_ids
        .extend((7..=9).map(session_id));
    let mut index = ScanIndex::default();
    let mut snapshots = Vec::new();
    for ordinal in 10..=12 {
        let request_a = format!("req-{ordinal}-a");
        let request_b = format!("req-{ordinal}-b");
        snapshots.push(parsed_item(
            &session_id(ordinal),
            &[request_a.as_str(), request_b.as_str()],
        ));
    }
    for ordinal in 13..=15 {
        let request_a = format!("req-{ordinal}-a");
        snapshots.push(exclusive(parsed_item(
            &session_id(ordinal),
            &[request_a.as_str(), SHARED_COPY_REQUEST],
        )));
        mark_duplicate(&mut index, SHARED_COPY_REQUEST, &session_id(ordinal));
    }
    for ordinal in 16..=18 {
        let request_a = format!("req-{ordinal}-a");
        let item = parsed_item(&session_id(ordinal), &[request_a.as_str()]);
        snapshots.push(item.clone());
        snapshots.push(item);
    }

    let export = run_export(&snapshots, &disposition, &index);

    let fixture = HELD_MIXED_FIXTURE.trim_end_matches('\n');
    assert_eq!(export.packet_json, fixture);
    assert_eq!(export.packet_sha256, sha256_hex(fixture.as_bytes()));
    for (ordinal, reason, local_checks_passed) in [
        (1, "missing_evidence", false),
        (4, "creator_hold", false),
        (7, "unknown_owner", false),
        (10, "incomplete_census", true),
        (13, "unknown_owner", false),
        (16, "unknown_owner", false),
    ] {
        assert_held_without_body(&packet_member(&export, ordinal), reason);
        assert_eq!(
            report(&export, ordinal)["local_checks_passed"],
            Value::Bool(local_checks_passed)
        );
    }
    for (report, member) in export.qualification_reports.iter().zip(members()) {
        assert_eq!(report.session_key_sha256, member.session_key_sha256);
        assert_eq!(report.sha256, sha256_hex(&report.canonical_json));
        let text = String::from_utf8(report.canonical_json.clone()).expect("utf8");
        assert!(!text.contains(&member.source_session_id));
        assert!(!text.contains("req-"));
    }
}

#[test]
fn unproven_usage_is_not_disqualifying_but_global_conservation_still_holds() {
    let unproven = parsed_item(&session_id(1), &["req-1-a", "req-1-b"]);
    let proven = exclusive(parsed_item(&session_id(2), &["req-2-a"]));
    let excluded = parsed_item(&session_id(3), &["req-3-a", SHARED_COPY_REQUEST]);
    let overlapping = parsed_item(&session_id(4), &["req-4-a", SHARED_COPY_REQUEST]);
    let mut index = ScanIndex::default();
    mark_duplicate(&mut index, SHARED_COPY_REQUEST, &session_id(3));
    index.claude_usage_family_witnesses.insert(
        claude_snapshot_family_root(&excluded),
        ClaudeUsageFamilyWitness {
            evidence_fingerprint: "fixture".to_string(),
            member_request_id_fingerprints: BTreeMap::new(),
            member_occurrence_fingerprints: BTreeMap::new(),
            assigned_request_id_fingerprints: BTreeMap::new(),
            legacy_excluded_request_id_hashes: BTreeMap::from([(
                session_id(3),
                BTreeSet::from([sha256_hex(SHARED_COPY_REQUEST.as_bytes())]),
            )]),
            legacy_exclusion_evidence_fingerprint: Some("fixture".to_string()),
            legacy_owner_roots: BTreeSet::new(),
        },
    );
    let before = serde_json::to_value(&unproven).expect("item json");
    let snapshots = vec![unproven, proven, excluded, overlapping];

    let export = run_export(&snapshots, &complete_census(), &index);

    // Unproven, proven and exactly excluded bodies all pass every local check,
    // and all stay held: no evidence covers historical accepted bodies.
    for ordinal in 1..=3 {
        assert_held_without_body(&packet_member(&export, ordinal), "incomplete_census");
        let report = report(&export, ordinal);
        assert_eq!(report["local_checks_passed"], Value::Bool(true));
        assert_eq!(report["global_conservation_evidence"], "unavailable");
    }
    assert_eq!(report(&export, 1)["usage_accounting_contract"], Value::Null);
    assert_eq!(
        report(&export, 2)["usage_accounting_contract"],
        SESSION_EXCLUSIVE
    );
    assert_eq!(report(&export, 3)["exactly_excluded_request_count"], 1);
    assert_held_without_body(&packet_member(&export, 4), "unknown_owner");
    assert_eq!(
        report(&export, 4)["local_checks_passed"],
        Value::Bool(false)
    );
    assert_eq!(report(&export, 4)["unresolved_duplicate_request_count"], 1);
    assert_eq!(
        serde_json::to_value(&snapshots[0]).expect("item json"),
        before
    );
}

#[test]
fn local_census_gaps_are_reported_as_local_failures() {
    let item = parsed_item(&session_id(1), &["req-1-a"]);
    let index = ScanIndex::default();
    let snapshots = vec![item];

    let mut incomplete = complete_census();
    incomplete.duplicate_census.census_complete = false;
    let mut invalid = complete_census();
    invalid.duplicate_census.census_invalid = true;
    let mut uncovered = complete_census();
    uncovered.duplicate_census.coverage_complete = false;
    let mut unobserved = complete_census();
    unobserved.transcript_ownership_complete = false;
    for disposition in [incomplete, invalid, uncovered, unobserved] {
        let export = run_export(&snapshots, &disposition, &index);
        assert_held_without_body(&packet_member(&export, 1), "incomplete_census");
        assert_eq!(
            report(&export, 1)["local_checks_passed"],
            Value::Bool(false)
        );
    }

    let mut fenced = complete_census();
    fenced.duplicate_census.fence_after = true;
    let mut capped = complete_census();
    capped.duplicate_census.page_invalidated_cap_count = 1;
    for disposition in [fenced, capped] {
        let export = run_export(&snapshots, &disposition, &index);
        assert_held_without_body(&packet_member(&export, 1), "cap_overflow");
        assert_eq!(
            report(&export, 1)["local_checks_passed"],
            Value::Bool(false)
        );
    }
    let overflowed = ScanIndex {
        claude_duplicate_request_witness_overflowed: true,
        ..ScanIndex::default()
    };
    let export = run_export(&snapshots, &complete_census(), &overflowed);
    assert_held_without_body(&packet_member(&export, 1), "cap_overflow");
}

#[test]
fn manifest_scope_must_be_exact() {
    let disposition = complete_census();
    let index = ScanIndex::default();
    let evidence = PipelineEvidence {
        upload_snapshots: &[],
        disposition: &disposition,
        index: &index,
    };
    let refuse = |scope: OperatorScope, members: Vec<ApprovedMember>, expected: &str| {
        let error = build_candidate_export(&scope, &members, &evidence, &fixture_build())
            .expect_err("refused");
        assert!(error.contains(expected), "{error}");
    };

    refuse(
        scope(),
        members().into_iter().take(17).collect(),
        "exactly 18",
    );
    let mut duplicated = members();
    duplicated[17] = duplicated[0].clone();
    refuse(scope(), duplicated, "distinct");
    let mut short = members();
    short[0].source_session_id = session_id(1)[..8].to_string();
    short[0].session_key_sha256 =
        session_key_sha256("claude_code", MACHINE, &short[0].source_session_id);
    refuse(scope(), short, "full Claude session id");
    let mut unbound = members();
    unbound[0].session_key_sha256 = members()[1].session_key_sha256.clone();
    refuse(scope(), unbound, "does not bind");
    let mut witness = members();
    witness[0].prior_refusal_body_witness = "abc".to_string();
    refuse(scope(), witness, "prior_refusal_body_witness");
    let mut operation = scope();
    operation.operation_id = "not-a-uuid".to_string();
    refuse(operation, members(), "operation_id");
    let mut revision = scope();
    revision.producer_revision = "22f1d61a".to_string();
    refuse(revision, members(), "producer_revision");
    let mut machine = scope();
    machine.machine_id = "short".to_string();
    refuse(machine, members(), "machine_id");
}

#[test]
fn export_binds_the_running_build_and_marks_unproven_fields() {
    let disposition = complete_census();
    let index = ScanIndex::default();
    let evidence = PipelineEvidence {
        upload_snapshots: &[],
        disposition: &disposition,
        index: &index,
    };

    let export = export_candidates(&scope(), &members(), &evidence).expect("export");

    let packet: Value = serde_json::from_str(&export.packet_json).expect("packet");
    let binary = fs::read(std::env::current_exe().expect("current exe")).expect("binary");
    assert_eq!(packet["collector_version"], collector_version());
    assert_eq!(packet["producer_binary_sha256"], sha256_hex(&binary));
    assert_eq!(
        packet["producer_revision_source"],
        "operator_supplied_unverified"
    );
    assert_eq!(
        packet["unresolved_fields"],
        json!(["prior_refusal_body_witness"])
    );
    assert_eq!(packet["contract_version"], CANDIDATES_CONTRACT_VERSION);
    assert_eq!(
        packet["scope_session_keys"],
        json!(members()
            .iter()
            .map(|member| member.session_key_sha256.clone())
            .collect::<Vec<_>>())
    );
    for ordinal in 1..=18 {
        assert_held_without_body(&packet_member(&export, ordinal), "missing_evidence");
    }
}
