use super::*;
use crate::snapshots::h527_candidates::session_key_sha256;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

const MACHINE: &str = "m4-fixture-machine";
const MODEL: &str = "claude-opus-4-1";
const PEER_SESSION: &str = "aaaaaaaa-0000-4000-8000-00000000peer";
const FORK_CHILD_SESSION: &str = "aaaaaaaa-0000-4000-8000-0000000fork";
const HELD_SESSION: &str = "aaaaaaaa-0000-4000-8000-0000000held";

fn session_id(ordinal: u64) -> String {
    format!("{ordinal:08x}-0000-4000-8000-{ordinal:012x}")
}

fn key(session: &str) -> String {
    session_key_sha256("claude_code", MACHINE, session)
}

fn fixture_build() -> ProducerBuild {
    ProducerBuild {
        collector_version: "0.0.0-h527-fixture".to_string(),
        binary_sha256: sha256_hex(b"h527-fixture-binary"),
    }
}

/// (request id, input, output, cache read)
type Request<'a> = (&'a str, u64, u64, u64);

fn assistant_line(session: &str, minute: usize, request: Request<'_>) -> Value {
    let (request_id, input, output, cache_read) = request;
    json!({
        "timestamp": format!("2026-09-02T06:{:02}:00Z", minute + 1),
        "type": "assistant",
        "sessionId": session,
        "requestId": request_id,
        "message": {
            "id": format!("msg-{request_id}"),
            "role": "assistant",
            "model": MODEL,
            "usage": {
                "input_tokens": input,
                "output_tokens": output,
                "cache_read_input_tokens": cache_read,
            },
            "content": [{"type": "text", "text": "synthetic"}],
        },
    })
}

fn write_lines(path: &Path, lines: &[Value]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    let text = lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, text + "\n").expect("write transcript");
}

fn write_transcript(path: &Path, session: &str, requests: &[Request<'_>]) {
    let mut lines = vec![json!({
        "timestamp": "2026-09-02T06:00:00Z",
        "type": "user",
        "sessionId": session,
        "message": {"role": "user", "content": "synthetic"},
    })];
    for (minute, request) in requests.iter().enumerate() {
        lines.push(assistant_line(session, minute, *request));
    }
    write_lines(path, &lines);
}

/// Requests per target ordinal. Overlaps:
/// - target 1 shares `req-shared-peer` with a non-target peer session;
/// - targets 2 and 3 share `req-b2-ack`; target 3 is first-ACKed;
/// - targets 4 and 5 share `req-b2-hash`; neither is ACK-ordered;
/// - a fork child copies target 6's `req-t06-a` with a fork marker;
/// - a peer under the held root shares target 7's `req-t07-b`;
/// - a replica of target 2 under the held root repeats its `req-b2-ack`.
fn target_requests(ordinal: u64) -> Vec<(String, u64, u64, u64)> {
    let own = |suffix: &str, input: u64| (format!("req-t{ordinal:02}-{suffix}"), input, 2, 100);
    match ordinal {
        1 => vec![
            own("a", 10),
            ("req-shared-peer".to_string(), 1000, 50, 5000),
        ],
        2 => vec![own("a", 20), ("req-b2-ack".to_string(), 300, 30, 0)],
        3 => vec![own("a", 30), ("req-b2-ack".to_string(), 300, 30, 0)],
        4 => vec![own("a", 40), ("req-b2-hash".to_string(), 400, 40, 0)],
        5 => vec![own("a", 50), ("req-b2-hash".to_string(), 400, 40, 0)],
        6 | 7 => vec![own("a", 60), own("b", 70)],
        _ => vec![own("a", 7 + ordinal)],
    }
}

struct Fixture {
    root: PathBuf,
    input: ProducerInput,
}

fn fixture() -> Fixture {
    let root = crate::test_scratch::private_dir("h527-producer");
    let projects = root.join("projects");
    let held = root.join("held");
    let mut targets = Vec::new();
    for ordinal in 1..=18_u64 {
        let session = session_id(ordinal);
        let path = projects.join("proj-a").join(format!("{session}.jsonl"));
        let requests = target_requests(ordinal);
        let borrowed = requests
            .iter()
            .map(|(id, input, output, cache)| (id.as_str(), *input, *output, *cache))
            .collect::<Vec<_>>();
        write_transcript(&path, &session, &borrowed);
        targets.push(InputTarget {
            source_session_id: session.clone(),
            session_key_sha256: key(&session),
            prior_refusal_body_witness: sha256_hex(format!("refused-{ordinal}").as_bytes()),
            transcript_path: path,
            b2_first_ack_order: (ordinal == 3).then_some(1),
        });
    }
    write_transcript(
        &projects
            .join("proj-b")
            .join(format!("{PEER_SESSION}.jsonl")),
        PEER_SESSION,
        &[
            ("req-shared-peer", 1000, 50, 5000),
            ("req-peer-own", 5, 1, 0),
        ],
    );
    let mut copied = assistant_line(FORK_CHILD_SESSION, 0, ("req-t06-a", 60, 2, 100));
    copied["forkedFrom"] = json!({"sessionId": session_id(6), "messageUuid": "original-a"});
    copied["uuid"] = json!("copied-a");
    write_lines(
        &projects
            .join("proj-b")
            .join(format!("{FORK_CHILD_SESSION}.jsonl")),
        &[
            copied,
            assistant_line(FORK_CHILD_SESSION, 1, ("req-fork-own", 9, 1, 0)),
        ],
    );
    // A replica of target 2 is that target's own copy, not a peer: the
    // `req-b2-ack` share stays between targets 2 and 3 and B2 allocates it.
    write_transcript(
        &held
            .join("replica")
            .join(format!("{}.jsonl", session_id(2))),
        &session_id(2),
        &[("req-t02-a", 20, 2, 100), ("req-b2-ack", 300, 30, 0)],
    );
    write_transcript(
        &held.join(format!("{HELD_SESSION}.jsonl")),
        HELD_SESSION,
        &[("req-t07-b", 70, 2, 100)],
    );
    fs::write(
        projects.join("proj-a").join("notes.txt"),
        "not a transcript",
    )
    .expect("write");
    let input = ProducerInput {
        contract_version: PRODUCER_INPUT_CONTRACT_VERSION.to_string(),
        scope: InputScope {
            operation_id: "00000000-0000-4000-8000-000000000527".to_string(),
            user_id: "10000000-0000-4000-8000-000000000001".to_string(),
            organization_id: "20000000-0000-4000-8000-000000000002".to_string(),
            device_id: "30000000-0000-4000-8000-000000000003".to_string(),
            machine_id: MACHINE.to_string(),
            producer_revision: "b6e2476e5bf9deea601e80f4a1b682cd485559a9".to_string(),
        },
        collected_at: "2026-10-18T00:00:00Z".to_string(),
        upload_policy: InputUploadPolicy {
            session_titles_enabled: false,
            workspace_labels_enabled: false,
            session_artifacts_enabled: false,
            session_attribution_enabled: false,
            session_attribution_labels_enabled: false,
        },
        context_curve_enabled: false,
        targets,
        peer_roots: vec![
            InputPeerRoot {
                class: "projects".to_string(),
                path: projects,
            },
            InputPeerRoot {
                class: "held".to_string(),
                path: held,
            },
        ],
        bounds: InputBounds {
            max_peer_files: 100,
            max_peer_total_bytes: 1 << 20,
            max_peer_file_bytes: 1 << 20,
            max_line_bytes: 1 << 16,
        },
        catalog_prices: Some(CatalogPrices {
            publication: CatalogPublication {
                source: "fixture catalog".to_string(),
                revision: "fixture-1".to_string(),
                sha256: sha256_hex(b"fixture catalog"),
            },
            rates_usd_per_mtok: BTreeMap::from([(
                format!("{MODEL}|short"),
                CatalogRates {
                    input: "15".to_string(),
                    output: "75".to_string(),
                    cache_read: "1.5".to_string(),
                    cache_creation_5m: "18.75".to_string(),
                    cache_creation_1h: "30".to_string(),
                },
            )]),
        }),
    };
    Fixture { root, input }
}

fn target_report(artifact: &Value, ordinal: u64) -> &Value {
    let session = session_id(ordinal);
    artifact["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .find(|target| target["source_session_id"] == session.as_str())
        .expect("target report")
}

fn excluded(report: &Value) -> &Vec<Value> {
    report["partition"]["excluded"]["witnesses"]
        .as_array()
        .expect("witnesses")
}

fn body_item(report: &Value) -> Value {
    let body: Value = serde_json::from_str(
        report["body"]["unqualified_batch_request_json"]
            .as_str()
            .expect("body"),
    )
    .expect("body json");
    assert_eq!(body["snapshots"].as_array().expect("snapshots").len(), 1);
    body["snapshots"][0].clone()
}

/// The exact-exclusion re-parse must equal parsing the transcript with the
/// excluded lines physically absent: same usage, rows and request set.
fn assert_matches_physical_removal(fixture: &Fixture, ordinal: u64, removed: &str) {
    let session = session_id(ordinal);
    let kept = target_requests(ordinal)
        .into_iter()
        .filter(|(id, ..)| id != removed)
        .collect::<Vec<_>>();
    let borrowed = kept
        .iter()
        .map(|(id, input, output, cache)| (id.as_str(), *input, *output, *cache))
        .collect::<Vec<_>>();
    let path = fixture
        .root
        .join("physical")
        .join(format!("{session}.jsonl"));
    write_transcript(&path, &session, &borrowed);
    let mut expected = parse_target_transcript(&path, "2026-10-18T00:00:00Z", false, false, None)
        .expect("parse")
        .snapshots;
    let mut actual = parse_target_transcript(
        &fixture.input.targets[(ordinal - 1) as usize].transcript_path,
        "2026-10-18T00:00:00Z",
        false,
        false,
        Some(BTreeSet::from([removed.to_string()])),
    )
    .expect("parse")
    .snapshots;
    let (expected, actual) = (expected.remove(0), actual.remove(0));
    assert_eq!(
        actual.claude_usage_request_ids,
        expected.claude_usage_request_ids
    );
    assert_eq!(Dims::of_item(&actual), Dims::of_item(&expected));
    assert_eq!(actual.model_usage, expected.model_usage);
    assert_eq!(actual.usage_buckets, expected.usage_buckets);
}

#[test]
fn producer_excludes_each_overlap_once_and_reconciles_ordinary_bodies() {
    let fixture = fixture();
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).expect("produce");
    let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
    assert_eq!(
        output.artifact_sha256,
        sha256_hex(output.artifact_json.as_bytes())
    );
    assert_eq!(artifact["global_coverage"]["complete"], true);
    assert_eq!(artifact["admission_authority"], "none");
    assert_eq!(output.summary["computed_unqualified_candidates"], 18);

    // Each overlap is excluded exactly once, from the right target.
    let mut total_excluded = 0;
    for ordinal in 1..=18 {
        let report = target_report(&artifact, ordinal);
        assert_eq!(
            report["candidate_status"], "computed_unqualified",
            "target {ordinal}"
        );
        total_excluded += excluded(report).len();
    }
    assert_eq!(total_excluded, 4);

    let target_1 = target_report(&artifact, 1);
    let [witness] = excluded(target_1).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["request_sha256"], sha256_hex(b"req-shared-peer"));
    assert_eq!(witness["cause"], "peer_overlap");
    assert_eq!(
        witness["peer_owner_session_sha256"],
        sha256_hex(PEER_SESSION.as_bytes())
    );
    // Kept totals rebuild from the retained request, not by subtraction alone.
    let item = body_item(target_1);
    assert_eq!(
        (
            item["input_tokens"].as_u64(),
            item["output_tokens"].as_u64()
        ),
        (Some(10), Some(2))
    );
    assert_eq!(item["cache_read_tokens"], 100);
    assert_eq!(item["request_count"], 1);
    assert_eq!(
        target_1["body"]["unqualified_batch_request_sha256"],
        sha256_hex(
            target_1["body"]["unqualified_batch_request_json"]
                .as_str()
                .expect("body")
                .as_bytes()
        )
    );
    assert_eq!(
        target_1["partition"]["excluded"]["totals"]["input_tokens"],
        1000
    );
    assert_eq!(
        target_1["partition"]["excluded"]["totals"]["cache_read_tokens"],
        5000
    );
    assert_matches_physical_removal(&fixture, 1, "req-shared-peer");

    // B2: first-ACKed target 3 keeps the shared request; target 2 drops it.
    let [witness] = excluded(target_report(&artifact, 2)).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["cause"], "b2_other_target");
    assert_eq!(witness["kept_by_session_key_sha256"], key(&session_id(3)));
    assert_eq!(
        target_report(&artifact, 2)["same_session_peer_line_count"],
        2
    );
    assert_eq!(
        artifact["input_manifest"]["shared_target_replica_line_count"],
        1
    );
    let receipt = &target_report(&artifact, 3)["identity_receipt"];
    assert_eq!(receipt["kept_shared_request_count"], 1);
    assert_eq!(receipt["untagged_count"], 1);
    assert_eq!(receipt["tagged_count"], 0);
    assert_eq!(receipt["allocation_identity_changes"], 0);
    assert_eq!(
        receipt["entries"][0]["keeping_root_session_key_sha256"],
        key(&session_id(3))
    );
    assert_eq!(receipt["entries"][0]["tag_state"], "untagged");
    assert!(excluded(target_report(&artifact, 3)).is_empty());

    // Without ACK order the smaller session key keeps; the other drops it once.
    let (keeper, dropper) = if key(&session_id(4)) < key(&session_id(5)) {
        (4, 5)
    } else {
        (5, 4)
    };
    assert!(excluded(target_report(&artifact, keeper)).is_empty());
    assert_eq!(excluded(target_report(&artifact, dropper)).len(), 1);

    // A fork-marked copy belongs to its named source session: no exclusion.
    let target_6 = target_report(&artifact, 6);
    assert!(excluded(target_6).is_empty());
    assert_eq!(target_6["same_session_peer_line_count"], 1);
    // A peer under the held root still excludes.
    let [witness] = excluded(target_report(&artifact, 7)).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["request_sha256"], sha256_hex(b"req-t07-b"));

    // The operator packet stays the frozen ten fields, every member held, no body.
    let packet: Value = serde_json::from_str(&output.candidate_bundle_json).expect("packet");
    assert_eq!(packet.as_object().expect("packet").len(), 10);
    assert!(!output.candidate_bundle_json.contains("batch_request"));
    for member in packet["members"].as_array().expect("members") {
        assert_eq!(member["disposition"], "held");
        assert_eq!(member["reason"], "missing_evidence");
        assert_eq!(member["cross_session_conservation"], "unknown");
    }

    // Disclosures pin this artifact and carry the exact catalog estimate.
    let disclosures: Value =
        serde_json::from_str(output.disclosures_json.as_deref().expect("disclosures"))
            .expect("disclosures json");
    assert_eq!(
        disclosures["exclusion_artifact_sha256"],
        output.artifact_sha256
    );
    let record = disclosures["records"]
        .as_array()
        .expect("records")
        .iter()
        .find(|record| record["session_key_sha256"] == key(&session_id(1)).as_str())
        .expect("target 1 disclosure");
    let record: Value =
        serde_json::from_str(record["disclosure_json"].as_str().expect("json")).expect("record");
    // 1000*15 + 50*75 + 5000*1.5 per million tokens.
    assert_eq!(record["excluded_catalog_cost_usd"], "0.02625");
    assert_eq!(record["excluded_request_count"], 1);
    assert_eq!(record["copy_screen_status"], "not_run");

    // Deterministic for the same immutable inputs.
    let again = produce(&fixture.input, &"0".repeat(64), &fixture_build()).expect("produce");
    assert_eq!(again.artifact_sha256, output.artifact_sha256);
    assert_eq!(
        again.candidate_bundle_sha256,
        output.candidate_bundle_sha256
    );

    let out_dir = fixture.root.join("out");
    write_outputs(&out_dir, &output).expect("write outputs");
    assert_eq!(
        fs::read_to_string(out_dir.join("artifact.json")).expect("artifact"),
        output.artifact_json
    );
    assert!(
        write_outputs(&out_dir, &output).is_err(),
        "existing directory refused"
    );
    let _ = fs::remove_dir_all(&fixture.root);
}

#[test]
fn producer_holds_every_target_without_a_body_on_unknown_or_capped_peers() {
    let fixture = fixture();
    let archive = fixture.root.join("archive");
    fs::create_dir_all(&archive).expect("mkdir");
    fs::write(archive.join("old-session.jsonl.zst"), b"compressed").expect("write");
    let mut unknown = fixture.input.clone();
    unknown.peer_roots.push(InputPeerRoot {
        class: "archive".to_string(),
        path: archive,
    });
    let mut capped = fixture.input.clone();
    capped.bounds.max_peer_files = 1;
    // A failed read still spends the byte budget.
    let broken = fixture.root.join("broken");
    fs::create_dir_all(&broken).expect("mkdir");
    let broken_line = b"{\"requestId\": \"req-t01-a\", truncated\n";
    fs::write(broken.join("broken.jsonl"), broken_line).expect("write");
    let mut failed = fixture.input.clone();
    failed.peer_roots = vec![InputPeerRoot {
        class: "other".to_string(),
        path: broken,
    }];
    let output = produce(&failed, &"0".repeat(64), &fixture_build()).expect("produce");
    let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
    assert_eq!(artifact["global_coverage"]["complete"], false);
    assert_eq!(
        artifact["input_manifest"]["cumulative_peer_bytes_read"],
        broken_line.len()
    );
    for (input, reason) in [(unknown, "incomplete_census"), (capped, "cap_overflow")] {
        let output = produce(&input, &"0".repeat(64), &fixture_build()).expect("produce");
        let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
        assert_eq!(artifact["global_coverage"]["complete"], false);
        assert_eq!(output.summary["computed_unqualified_candidates"], 0);
        for ordinal in 1..=18 {
            let report = target_report(&artifact, ordinal);
            assert_eq!(report["candidate_status"], "held");
            assert_eq!(report["held_reason"], reason);
            assert!(report.get("body").is_none() && report.get("partition").is_none());
        }
        assert!(!output
            .artifact_json
            .contains("unqualified_batch_request_json"));
    }
    let _ = fs::remove_dir_all(&fixture.root);
}
