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
const CHAIN_MIDDLE_SESSION: &str = "aaaaaaaa-0000-4000-8000-0000000mid1";
const CHAIN_TAIL_SESSION: &str = "aaaaaaaa-0000-4000-8000-0000000tail";
const ABSENT_SESSION: &str = "aaaaaaaa-0000-4000-8000-0000absent";
const COPY_HOLDER_SESSION: &str = "aaaaaaaa-0000-4000-8000-0000copier";

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
    let mut usage = json!({
        "input_tokens": input,
        "output_tokens": output,
        "cache_read_input_tokens": cache_read,
    });
    // Fast mode is premium-priced; the estimate must refuse it.
    if request_id == "req-b2-hash" {
        usage["speed"] = json!("fast");
    }
    json!({
        "timestamp": format!("2026-09-02T06:{:02}:00Z", minute + 1),
        "type": "assistant",
        "sessionId": session,
        "requestId": request_id,
        "message": {
            "id": format!("msg-{request_id}"),
            "role": "assistant",
            "model": MODEL,
            "usage": usage,
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
    write_lines(path, &transcript_lines(session, requests));
}

fn transcript_lines(session: &str, requests: &[Request<'_>]) -> Vec<Value> {
    let mut lines = vec![json!({
        "timestamp": "2026-09-02T06:00:00Z",
        "type": "user",
        "sessionId": session,
        "message": {"role": "user", "content": "synthetic"},
    })];
    for (minute, request) in requests.iter().enumerate() {
        lines.push(assistant_line(session, minute, *request));
    }
    lines
}

/// A provider fork copy: the holder's own session id, the source it names.
fn fork_copy(session: &str, named: &str, request: Request<'_>, uuid: &str) -> Value {
    let mut line = assistant_line(session, 0, request);
    line["forkedFrom"] = json!({"sessionId": named, "messageUuid": format!("src-{uuid}")});
    line["uuid"] = json!(uuid);
    line
}

/// Requests per target ordinal. Overlaps:
/// - target 1 shares `req-shared-peer` with a non-target peer session;
/// - targets 2 and 3 share `req-b2-ack`; target 3 is first-ACKed;
/// - targets 4 and 5 share `req-b2-hash`; neither is ACK-ordered;
/// - a fork child copies target 6's `req-t06-a` with a fork marker;
/// - a peer under the held root shares target 7's `req-t07-b`;
/// - a replica of target 2 under the held root repeats its `req-b2-ack`;
/// - a two-hop fork chain re-copies target 8's `req-t08-a` (no exclusion);
/// - a fork copy of target 9 carries a non-target id (no hold);
/// - a fork copy names an absent source for target 10's `req-t10-a`, the
///   conservative exclusion;
/// - a copy names a present peer that never counted target 11's `req-t11-a`
///   (excluded: presence is per line, not per file);
/// - target 12's own transcript holds a copy of target 13's `req-t13-a`
///   naming an absent source (excluded: target files are consulted);
/// - a copy names target 14, which does not count target 15's `req-t15-a`
///   (excluded);
/// - a copy names target 16, whose own copy of target 17's `req-t17-a` names
///   target 17 (resolved through the target file, no exclusion).
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
        // A second request keeps a body when the first one is excluded.
        6 | 7 | 10 | 11 | 13 | 15 => vec![own("a", 60), own("b", 70)],
        _ => vec![own("a", 7 + ordinal)],
    }
}

struct Fixture {
    root: PathBuf,
    input: ProducerInput,
}

fn fixture() -> Fixture {
    // Target paths must be canonical (macOS temp dirs resolve under /private).
    let root = fs::canonicalize(crate::test_scratch::private_dir("h527-producer"))
        .expect("canonical scratch");
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
        // Provider fork copies sit before a session's own records.
        let prefix = match ordinal {
            12 => vec![fork_copy(
                &session,
                ABSENT_SESSION,
                ("req-t13-a", 20, 2, 100),
                "target-12-copy",
            )],
            16 => vec![fork_copy(
                &session,
                &session_id(17),
                ("req-t17-a", 24, 2, 100),
                "target-16-copy",
            )],
            _ => Vec::new(),
        };
        write_lines(
            &path,
            &[prefix, transcript_lines(&session, &borrowed)].concat(),
        );
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
    // Target 8 -> middle -> tail: the tail's copy names the middle session.
    for (session, named) in [
        (CHAIN_MIDDLE_SESSION, session_id(8)),
        (CHAIN_TAIL_SESSION, CHAIN_MIDDLE_SESSION.to_string()),
    ] {
        write_lines(
            &projects.join("proj-c").join(format!("{session}.jsonl")),
            &[
                fork_copy(session, &named, ("req-t08-a", 15, 2, 100), session),
                assistant_line(session, 1, ("req-chain-own", 3, 1, 0)),
            ],
        );
    }
    // A copy, from a fork of target 9, of a record target 9 itself inherited.
    write_lines(
        &projects
            .join("proj-c")
            .join(format!("{COPY_HOLDER_SESSION}.jsonl")),
        &[
            fork_copy(
                COPY_HOLDER_SESSION,
                &session_id(9),
                ("req-not-a-target", 4, 1, 0),
                "copy-9",
            ),
            fork_copy(
                COPY_HOLDER_SESSION,
                ABSENT_SESSION,
                ("req-t10-a", 17, 2, 100),
                "copy-absent",
            ),
            fork_copy(
                COPY_HOLDER_SESSION,
                PEER_SESSION,
                ("req-t11-a", 18, 2, 100),
                "copy-present-peer",
            ),
            fork_copy(
                COPY_HOLDER_SESSION,
                &session_id(14),
                ("req-t15-a", 22, 2, 100),
                "copy-target-14",
            ),
            fork_copy(
                COPY_HOLDER_SESSION,
                &session_id(16),
                ("req-t17-a", 24, 2, 100),
                "copy-target-16",
            ),
        ],
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
            max_walk_entries: 1000,
            max_peer_files: 100,
            max_peer_total_bytes: 1 << 20,
            max_peer_file_bytes: 1 << 20,
            max_line_bytes: 1 << 16,
        },
        census_index_path: None,
        catalog_prices: Some(CatalogPrices {
            publication: CatalogPublication {
                source: "fixture catalog".to_string(),
                revision: "fixture-1".to_string(),
                sha256: sha256_hex(b"fixture catalog"),
            },
            // The fixture model has no provider price line, so the parser
            // stamps no context bucket.
            rates_usd_per_mtok: BTreeMap::from([(
                format!("{MODEL}|none"),
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
    assert_eq!(total_excluded, 8);
    let manifest = &artifact["input_manifest"];
    // Target 6's fork child, both chain copies, the copy naming target 16 and
    // target 16's own copy naming target 17. The copy naming target 9 carries
    // no target's id, so it never enters the census.
    assert_eq!(manifest["inherited_copy_resolved_line_count"], 5);
    assert_eq!(manifest["target_inherited_copy_line_count"], 2);
    assert_eq!(
        target_report(&artifact, 9)["candidate_status"],
        "computed_unqualified"
    );
    assert_eq!(manifest["inherited_copy_absent_source_line_count"], 4);
    assert!(excluded(target_report(&artifact, 8)).is_empty());
    assert!(excluded(target_report(&artifact, 17)).is_empty());
    // N1: the named peer is present but never counted the request.
    let [witness] = excluded(target_report(&artifact, 11)).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["cause"], "inherited_from_absent_source");
    assert_eq!(
        witness["peer_owner_session_sha256"],
        sha256_hex(PEER_SESSION.as_bytes())
    );
    // N1: a named target that does not count the request is no source either.
    let [witness] = excluded(target_report(&artifact, 15)).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["cause"], "inherited_from_absent_source");
    // N2: a copy inside target 12's own transcript, witnessed by that file.
    let [witness] = excluded(target_report(&artifact, 13)).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["cause"], "inherited_from_absent_source");
    assert_eq!(
        witness["peer_path_sha256"],
        target_report(&artifact, 12)["transcript_path_sha256"]
    );
    // Target 12's copy is skipped by its own parse: its body is untouched.
    assert!(excluded(target_report(&artifact, 12)).is_empty());
    // Walk breadth is counted; the whole plan was read.
    assert_eq!(manifest["over_cap_peer_file_count"], 0);
    assert_eq!(manifest["planned_peer_file_count"], 7);
    assert_eq!(manifest["peer_file_count"], 7);
    assert_eq!(
        manifest["planned_peer_bytes"],
        manifest["cumulative_peer_bytes_read"]
    );
    assert!(manifest["walk_entry_count"].as_u64().expect("entries") > 7);
    assert_eq!(manifest["peer_grown_during_read_count"], 0);
    let [witness] = excluded(target_report(&artifact, 10)).as_slice() else {
        panic!("one exclusion")
    };
    assert_eq!(witness["cause"], "inherited_from_absent_source");
    assert_eq!(
        witness["peer_owner_session_sha256"],
        sha256_hex(ABSENT_SESSION.as_bytes())
    );

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
    // The dropped request is fast mode, which the model|bucket rates cannot price.
    let estimate = &target_report(&artifact, dropper)["exclusion_estimate"];
    assert_eq!(estimate["excluded_catalog_cost_usd"], Value::Null);
    assert_eq!(estimate["unavailable_reason"], "unpriced_dimension");

    // A fork-marked copy belongs to its named source session: no exclusion.
    let target_6 = target_report(&artifact, 6);
    assert!(excluded(target_6).is_empty());
    // It is resolved after the census, not read as target 6's own replica.
    assert_eq!(target_6["same_session_peer_line_count"], 0);
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
    let mut narrow = fixture.input.clone();
    narrow.bounds.max_walk_entries = 3;
    let mut over_budget = fixture.input.clone();
    over_budget.bounds.max_peer_total_bytes = 10;
    let mut over_cap = fixture.input.clone();
    over_cap.bounds.max_peer_file_bytes = 1;
    // A failed read still spends the byte budget.
    let broken = fixture.root.join("broken");
    fs::create_dir_all(&broken).expect("mkdir");
    let broken_line = b"{\"requestId\": \"req-t01-a\", truncated\n";
    fs::write(broken.join("broken.jsonl"), broken_line).expect("write");
    let mut failed = fixture.input.clone();
    failed.peer_roots.push(InputPeerRoot {
        class: "other".to_string(),
        path: broken,
    });
    let output = produce(&failed, &"0".repeat(64), &fixture_build()).expect("produce");
    let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
    let unknown_causes = |artifact: &Value| {
        artifact["global_coverage"]["unknown"]
            .as_array()
            .expect("unknown")
            .iter()
            .map(|cause| cause.as_str().expect("cause").to_string())
            .collect::<Vec<_>>()
    };
    let [cause]: [String; 1] = unknown_causes(&artifact).try_into().expect("one cause");
    assert!(
        cause.ends_with("unparseable line with a request id key"),
        "{cause}"
    );
    let broken_bytes = artifact["input_manifest"]["peer_files"]
        .as_array()
        .expect("peer files")
        .iter()
        .find(|file| file.get("unknown").is_some())
        .expect("failed peer file");
    assert!(broken_bytes.get("size_bytes").is_none());
    let read_ok = artifact["input_manifest"]["peer_files"]
        .as_array()
        .expect("peer files")
        .iter()
        .filter_map(|file| file["size_bytes"].as_u64())
        .sum::<u64>();
    assert_eq!(
        artifact["input_manifest"]["cumulative_peer_bytes_read"],
        read_ok + broken_line.len() as u64
    );
    // One target outside every scanned root, with a projects root present.
    let mut outside = fixture.input.clone();
    let stray = fixture.root.join("stray").join("t18.jsonl");
    fs::create_dir_all(stray.parent().expect("parent")).expect("mkdir");
    fs::copy(&outside.targets[17].transcript_path, &stray).expect("copy");
    outside.targets[17].transcript_path = stray;
    let output = produce(&outside, &"0".repeat(64), &fixture_build()).expect("produce");
    let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
    let [cause]: [String; 1] = unknown_causes(&artifact).try_into().expect("one cause");
    assert!(cause.ends_with("is under no scanned peer root"), "{cause}");
    let mut unrooted = fixture.input.clone();
    unrooted.peer_roots.retain(|root| root.class != "projects");
    for (input, reason) in [
        (unknown, "incomplete_census"),
        (unrooted, "incomplete_census"),
        (capped, "cap_overflow"),
        (narrow, "cap_overflow"),
        (over_budget, "cap_overflow"),
        (over_cap, "cap_overflow"),
    ] {
        let output = produce(&input, &"0".repeat(64), &fixture_build()).expect("produce");
        let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
        assert_eq!(artifact["global_coverage"]["complete"], false);
        if reason == "cap_overflow" {
            // A budget overrun is found by the metadata walk: never a partial read.
            assert_eq!(artifact["input_manifest"]["cumulative_peer_bytes_read"], 0);
            assert_eq!(artifact["input_manifest"]["peer_file_count"], 0);
            if artifact["input_manifest"]["bounds"]["max_peer_file_bytes"] == 1 {
                // Every over-cap peer is counted, not only the first.
                assert_eq!(artifact["input_manifest"]["over_cap_peer_file_count"], 7);
            }
        }
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

/// Request-identity keys a body of this producer must never carry.
const IDENTITY_KEYS: [&str; 4] = [
    "evidence_ref",
    "identity_parts",
    "request_evidence",
    "request_identity_refusals",
];

/// Every identity key anywhere in `value`, including inside embedded JSON
/// text such as the body bytes, is null, empty or zero.
fn assert_identity_free(value: &Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if IDENTITY_KEYS.contains(&key.as_str()) {
                    assert!(
                        value.is_null()
                            || value.as_array().is_some_and(Vec::is_empty)
                            || value.as_u64() == Some(0),
                        "{key} carries identity"
                    );
                }
                assert_identity_free(value);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_identity_free),
        Value::String(text) if text.starts_with('{') => {
            if let Ok(embedded) = serde_json::from_str::<Value>(text) {
                assert_identity_free(&embedded);
            }
        }
        _ => {}
    }
}

#[test]
fn producer_bodies_stay_untagged_and_identity_never_reaches_the_artifact() {
    let fixture = fixture();
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).expect("produce");
    let artifact: Value = serde_json::from_str(&output.artifact_json).expect("artifact");
    assert_eq!(output.summary["computed_unqualified_candidates"], 18);
    assert_identity_free(&artifact);
    for ordinal in 1..=18 {
        let report = target_report(&artifact, ordinal);
        let body = report["body"]["unqualified_batch_request_json"]
            .as_str()
            .expect("body");
        assert!(serialized_request_identity(body)
            .expect("identity check")
            .untagged());
        let receipt = &report["identity_receipt"];
        assert_eq!(receipt["tagged_count"], 0);
        assert_eq!(receipt["body_request_evidence_count"], 0);
        assert_eq!(receipt["body_rows_with_identity"], 0);
        for entry in receipt["entries"].as_array().expect("entries") {
            assert_eq!(entry["tag_state"], "untagged");
        }
    }
    // A tagged body is refused, whatever produced it.
    let tagged = json!({"snapshots": [{
        "request_evidence": [{"evidence": "e"}],
        "request_identity_refusals": 1,
        "model_usage": [{"evidence_ref": 0}],
        "usage_buckets": [{"model_usage": [{"identity_parts": {"a": 1}}, {}]}],
    }]})
    .to_string();
    let identity = serialized_request_identity(&tagged).expect("identity check");
    assert!(!identity.untagged());
    assert_eq!(
        identity,
        BodyIdentity {
            request_evidence: 1,
            request_identity_refusals: 1,
            rows_with_identity: 2,
        }
    );
    let _ = fs::remove_dir_all(&fixture.root);
}

#[test]
fn producer_caps_are_pinned_apart_from_the_parser_cap() {
    let bounds = InputBounds {
        max_walk_entries: 1,
        max_peer_files: 1,
        max_peer_total_bytes: 1,
        max_peer_file_bytes: PEER_FILE_BYTES_CEILING,
        max_line_bytes: MAX_JSONL_LINE_BYTES as u64,
    };
    assert!(validate_bounds(&bounds).is_ok());
    // Peers stream line by line, so a peer over the parser's file cap is read.
    assert!(validate_bounds(&InputBounds {
        max_peer_file_bytes: MAX_JSONL_FILE_BYTES + 1,
        ..bounds
    })
    .is_ok());
    for invalid in [
        InputBounds {
            max_peer_file_bytes: PEER_FILE_BYTES_CEILING + 1,
            ..bounds
        },
        InputBounds {
            max_line_bytes: MAX_JSONL_LINE_BYTES as u64 + 1,
            ..bounds
        },
        InputBounds {
            max_walk_entries: 0,
            ..bounds
        },
    ] {
        assert!(validate_bounds(&invalid).is_err());
    }
    assert_eq!(TARGET_FILE_BYTES_CAP, 256 * 1024 * 1024);
}

#[test]
fn fork_copies_resolve_only_through_a_counting_source_and_cycles_stay_absent() {
    let copy = |holder: &str, named: &str, request_id: &str| CopyClaim {
        request_id: request_id.to_string(),
        named_session: Some(named.to_string()),
        holder_session: Some(holder.to_string()),
        path_sha256: format!("path-{holder}"),
    };
    let mut scan = PeerScan {
        hits: vec![BTreeMap::new()],
        copies: vec![
            // A cycle with no counting source anywhere.
            copy("cycle-a", "cycle-b", "req-cycle"),
            copy("cycle-b", "cycle-a", "req-cycle"),
            // A chain whose root owns the request.
            copy("chain-a", "chain-b", "req-chain"),
            copy("chain-b", "chain-c", "req-chain"),
            // A deleted middle: another session owns the request, but the
            // chain never reaches it.
            copy("gap-a", "gap-deleted", "req-gap"),
        ],
        ..PeerScan::default()
    };
    scan.owned_held_ids
        .entry("chain-c".to_string())
        .or_default()
        .insert("req-chain".to_string());
    scan.owned_held_ids
        .entry("gap-owner".to_string())
        .or_default()
        .insert("req-gap".to_string());
    let holders = BTreeMap::from([
        ("req-cycle", vec![0]),
        ("req-chain", vec![0]),
        ("req-gap", vec![0]),
    ]);
    resolve_fork_copies(&mut scan, &holders, &BTreeMap::new(), &[]);

    assert_eq!(scan.inherited_resolved_line_count, 2);
    assert_eq!(scan.inherited_absent_source_line_count, 3);
    assert_eq!(
        scan.hits[0].keys().map(String::as_str).collect::<Vec<_>>(),
        ["req-cycle", "req-gap"]
    );
    assert_eq!(scan.hits[0]["req-cycle"].line_count, 2);
    assert!(scan.hits[0]
        .values()
        .all(|hit| hit.inherited_from_absent_source));
    assert_eq!(scan.hits[0]["req-gap"].path_sha256, "path-gap-a");
}

#[test]
fn directory_listing_stops_at_the_walk_budget() {
    let directory = crate::test_scratch::private_dir("h527-producer-listing");
    for index in 0..5 {
        fs::write(directory.join(format!("{index}.jsonl")), b"").expect("entry");
    }
    let mut count = 0;
    assert!(list_directory_within(&directory, 3, &mut count)
        .expect("listing")
        .is_none());
    assert_eq!(count, 4);
    let mut count = 0;
    let entries = list_directory_within(&directory, 5, &mut count)
        .expect("listing")
        .expect("within budget");
    assert_eq!((entries.len(), count), (5, 5));
}

fn vanish_after_plan(path: PathBuf) {
    AFTER_PLAN_FOR_TEST.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(move || {
            fs::remove_file(path).expect("vanish planned peer");
        }))
    });
}

fn add_vanishing_peer(input: &ProducerInput, project: &str) -> PathBuf {
    let path = input.peer_roots[0]
        .path
        .join(project)
        .join(format!("{}.jsonl", session_id(900)));
    write_transcript(&path, &session_id(900), &[("req-t18-a", 25, 2, 100)]);
    path
}

#[test]
fn source_r4_vanished_census_excludes_shared_ids() {
    use crate::snapshots::claude_request_census::claude_request_census_record;
    let mut fixture = fixture();
    let peer = add_vanishing_peer(&fixture.input, "proj-other");
    let parsed =
        parse_target_transcript(&peer, &fixture.input.collected_at, false, false, None).unwrap();
    let record = claude_request_census_record(
        &(session_id(900), session_id(900)),
        &parsed.snapshots,
        vec![],
        &"a".repeat(64),
        1,
        true,
        false,
        false,
    )
    .expect("record");
    let mut census = ClaudeRequestCensus::default();
    census.insert_for_test(peer.to_str().unwrap(), record);
    let index_path = fixture.root.join("index.json");
    let bytes =
        serde_json::to_vec(&json!({"generation": 1, "claude_request_census": census})).unwrap();
    fs::write(&index_path, &bytes).unwrap();
    fixture.input.census_index_path = Some(index_path.clone());
    vanish_after_plan(peer);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    assert_eq!(artifact["input_manifest"]["vanished_census_used"], 1);
    assert_eq!(
        target_report(&artifact, 18)["partition"]["excluded"]["request_count"],
        1
    );
    assert_eq!(artifact["global_coverage"]["complete"], true);
    assert_eq!(
        fs::read(index_path).unwrap(),
        bytes,
        "producer cannot write census"
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_vanished_without_census_holds_only_lineage() {
    let mut fixture = fixture();
    // Put target 18 in a separate project, with its own unchanged bytes.
    let unrelated = fixture.input.peer_roots[0]
        .path
        .join("proj-unrelated")
        .join(format!("{}.jsonl", session_id(18)));
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::rename(&fixture.input.targets[17].transcript_path, &unrelated).unwrap();
    fixture.input.targets[17].transcript_path = unrelated;
    let peer = add_vanishing_peer(&fixture.input, "proj-a");
    vanish_after_plan(peer);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    assert_eq!(artifact["input_manifest"]["vanished_no_census"]["peers"], 1);
    assert_eq!(
        artifact["input_manifest"]["vanished_no_census"]["held_targets"],
        17
    );
    assert_eq!(
        target_report(&artifact, 1)["held_reason"],
        "incomplete_census"
    );
    assert_eq!(
        target_report(&artifact, 18)["candidate_status"],
        "computed_unqualified"
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_unrelated_target_proceeds_and_copy_lineage_is_transitive() {
    let mut fixture = fixture();
    let peer = add_vanishing_peer(&fixture.input, "proj-unrelated");
    let empty_index = fixture.root.join("index.json");
    fs::write(&empty_index, b"{\"generation\":1}").unwrap();
    fixture.input.census_index_path = Some(empty_index);
    vanish_after_plan(peer);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    assert_eq!(
        artifact["input_manifest"]["vanished_no_census"]["held_targets"],
        0
    );
    assert_eq!(
        target_report(&artifact, 18)["candidate_status"],
        "computed_unqualified"
    );
    let left = Path::new("/projects/a/root-a.jsonl");
    let right = Path::new("/projects/b/root-b.jsonl");
    assert!(same_lineage(
        left,
        right,
        &BTreeSet::from([
            ("root-a".into(), "middle".into()),
            ("middle".into(), "root-b".into())
        ])
    ));
    assert!(!same_lineage(left, right, &BTreeSet::new()));
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_census_rewrite_refuses_output_even_same_generation() {
    let mut fixture = fixture();
    let path = fixture.root.join("index.json");
    fs::write(&path, b"{\"generation\":1,\"claude_request_census\":{}}").unwrap();
    fixture.input.census_index_path = Some(path.clone());
    AFTER_PLAN_FOR_TEST.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(move || {
            fs::write(
                path,
                b"{\"generation\":1,\"claude_request_census\":{},\"changed\":true}",
            )
            .unwrap();
        }))
    });
    let error = produce(&fixture.input, &"0".repeat(64), &fixture_build())
        .err()
        .unwrap();
    assert!(error.contains("census index changed"), "{error}");
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_missing_evidence_counted_and_exact_tuple_copy_excluded() {
    for (peer_project, expect_match) in [
        (None, false),
        (Some("proj-a"), true),
        (Some("proj-unrelated"), false),
    ] {
        let fixture = fixture();
        let target = &fixture.input.targets[17];
        let mut missing = assistant_line(&target.source_session_id, 3, ("missing", 123, 7, 456));
        missing.as_object_mut().unwrap().remove("requestId");
        let mut lines = transcript_lines(&target.source_session_id, &[("req-t18-a", 25, 2, 100)]);
        lines.push(missing.clone());
        write_lines(&target.transcript_path, &lines);
        if let Some(project) = peer_project {
            missing["sessionId"] = json!(session_id(901));
            write_lines(
                &fixture.input.peer_roots[0]
                    .path
                    .join(project)
                    .join(format!("{}.jsonl", session_id(901))),
                &[missing],
            );
        }
        let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
        let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
        let report = target_report(&artifact, 18);
        assert_eq!(
            report["candidate_status"], "computed_unqualified",
            "{report}"
        );
        assert_eq!(
            report["missing_evidence_counted"]["lines"],
            u64::from(!expect_match)
        );
        assert_eq!(
            report["missing_evidence_matched_by_tuple"]["lines"],
            u64::from(expect_match)
        );
        assert_eq!(
            report["body"]["item_totals"]["input_tokens"],
            if expect_match { 25 } else { 148 }
        );
        assert!(report["missing_evidence_counted"]["usd"].is_null());
        fs::remove_dir_all(fixture.root).unwrap();
    }
}

#[test]
fn source_r4_tuple_guard_drops_whole_progressive_response() {
    let fixture = fixture();
    let target = &fixture.input.targets[17];
    let mut final_line = assistant_line(
        &target.source_session_id,
        4,
        ("missing-progressive", 123, 7, 456),
    );
    final_line.as_object_mut().unwrap().remove("requestId");
    let mut early = final_line.clone();
    early["timestamp"] = json!("2026-09-02T06:04:00Z");
    early["message"]["usage"]["output_tokens"] = json!(1);
    let mut lines = transcript_lines(&target.source_session_id, &[("req-t18-a", 25, 2, 100)]);
    lines.extend([early, final_line.clone()]);
    write_lines(&target.transcript_path, &lines);
    final_line["sessionId"] = json!(session_id(902));
    write_lines(
        &fixture.input.peer_roots[0]
            .path
            .join("proj-a")
            .join(format!("{}.jsonl", session_id(902))),
        &[final_line],
    );
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    let report = target_report(&artifact, 18);
    assert_eq!(
        report["candidate_status"], "computed_unqualified",
        "{report}"
    );
    assert_eq!(report["missing_evidence_matched_by_tuple"]["lines"], 1);
    assert_eq!(report["body"]["item_totals"]["input_tokens"], 25);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_all_idless_usage_stays_counted() {
    let fixture = fixture();
    let target = &fixture.input.targets[17];
    let mut line = assistant_line(&target.source_session_id, 5, ("only-missing", 123, 7, 456));
    line.as_object_mut().unwrap().remove("requestId");
    write_lines(&target.transcript_path, &[line]);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    let report = target_report(&artifact, 18);
    assert_eq!(
        report["candidate_status"], "computed_unqualified",
        "{report}"
    );
    assert_eq!(report["missing_evidence_counted"]["lines"], 1);
    assert_eq!(report["body"]["item_totals"]["input_tokens"], 123);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_vanished_target_replica_preserves_b2_money() {
    use crate::snapshots::claude_request_census::claude_request_census_record;
    let mut fixture = fixture();
    let replica = fixture.input.peer_roots[1]
        .path
        .join("replica")
        .join(format!("{}.jsonl", session_id(2)));
    let parsed =
        parse_target_transcript(&replica, &fixture.input.collected_at, false, false, None).unwrap();
    let record = claude_request_census_record(
        &(session_id(2), session_id(2)),
        &parsed.snapshots,
        vec![],
        &"a".repeat(64),
        1,
        true,
        false,
        false,
    )
    .unwrap();
    let mut census = ClaudeRequestCensus::default();
    census.insert_for_test(replica.to_str().unwrap(), record);
    let path = fixture.root.join("index.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({"generation":1,"claude_request_census":census})).unwrap(),
    )
    .unwrap();
    fixture.input.census_index_path = Some(path);
    vanish_after_plan(replica);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    assert_eq!(
        target_report(&artifact, 2)["body"]["item_totals"]["input_tokens"],
        20
    );
    assert_eq!(
        target_report(&artifact, 3)["body"]["item_totals"]["input_tokens"],
        330
    );
    assert_eq!(
        target_report(&artifact, 3)["partition"]["excluded"]["request_count"],
        0
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_live_idless_target_replica_is_own_counter() {
    let fixture = fixture();
    let target = &fixture.input.targets[17];
    let mut missing = assistant_line(
        &target.source_session_id,
        5,
        ("idless-replica", 123, 7, 456),
    );
    missing.as_object_mut().unwrap().remove("requestId");
    let mut lines = transcript_lines(&target.source_session_id, &[("req-t18-a", 25, 2, 100)]);
    lines.push(missing);
    write_lines(&target.transcript_path, &lines);
    let replica = fixture.input.peer_roots[1]
        .path
        .join("replica")
        .join(format!("{}.jsonl", session_id(18)));
    write_lines(&replica, &lines);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    let report = target_report(&artifact, 18);
    assert_eq!(
        report["candidate_status"], "computed_unqualified",
        "{report}"
    );
    assert_eq!(report["missing_evidence_counted"]["lines"], 1);
    assert_eq!(report["missing_evidence_matched_by_tuple"]["lines"], 0);
    assert_eq!(report["body"]["item_totals"]["input_tokens"], 148);
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_mixed_project_fork_lineage_holds_transitively() {
    let fixture = fixture();
    let peer = add_vanishing_peer(&fixture.input, "proj-vanished");
    // Q shares a project with all targets, but names P in a different project.
    let q = fixture.input.peer_roots[0]
        .path
        .join("proj-a")
        .join(format!("{}.jsonl", session_id(903)));
    write_lines(
        &q,
        &[fork_copy(
            &session_id(903),
            &session_id(900),
            ("not-target", 1, 1, 0),
            "mixed-edge",
        )],
    );
    vanish_after_plan(peer);
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    assert_eq!(
        artifact["input_manifest"]["vanished_no_census"]["held_targets"],
        18
    );
    assert_eq!(
        target_report(&artifact, 18)["held_reason"],
        "incomplete_census"
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_reappeared_peer_at_run_end_refuses_publication() {
    let fixture = fixture();
    let peer = add_vanishing_peer(&fixture.input, "proj-unrelated");
    vanish_after_plan(peer.clone());
    AFTER_BUILDS_FOR_TEST.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(move || {
            fs::write(peer, "reappeared").unwrap();
        }))
    });
    let error = produce(&fixture.input, &"0".repeat(64), &fixture_build())
        .err()
        .unwrap();
    assert!(error.contains("end-of-run stat"), "{error}");
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn source_r4_target_tuple_copy_keeps_one_b2_counter() {
    let mut fixture = fixture();
    // Even the largest known first-ACK sorts before an unknown first-ACK.
    // Pick the larger hash so a sentinel-only comparison would select wrongly.
    let known = if fixture.input.targets[16].session_key_sha256
        > fixture.input.targets[17].session_key_sha256
    {
        16
    } else {
        17
    };
    fixture.input.targets[known].b2_first_ack_order = Some(u64::MAX);
    let mut line = assistant_line(&session_id(17), 6, ("target-copy", 123, 7, 456));
    line.as_object_mut().unwrap().remove("requestId");
    for index in [16, 17] {
        let target = &fixture.input.targets[index];
        let requests = target_requests((index + 1) as u64);
        let borrowed = requests
            .iter()
            .map(|(id, a, b, c)| (id.as_str(), *a, *b, *c))
            .collect::<Vec<_>>();
        let mut lines = transcript_lines(&target.source_session_id, &borrowed);
        line["sessionId"] = json!(target.source_session_id);
        lines.push(line.clone());
        write_lines(&target.transcript_path, &lines);
        // A live replica of the losing target must not override B2.
        if index == 17 {
            write_lines(
                &fixture.input.peer_roots[1]
                    .path
                    .join("replica")
                    .join(format!("{}.jsonl", session_id(18))),
                &lines,
            );
        }
    }
    let output = produce(&fixture.input, &"0".repeat(64), &fixture_build()).unwrap();
    let artifact: Value = serde_json::from_str(&output.artifact_json).unwrap();
    let reports = [target_report(&artifact, 17), target_report(&artifact, 18)];
    assert!(
        reports
            .iter()
            .all(|report| report["candidate_status"] == "computed_unqualified"),
        "{reports:?}"
    );
    assert_eq!(
        reports
            .iter()
            .map(|report| report["missing_evidence_counted"]["lines"]
                .as_u64()
                .unwrap())
            .sum::<u64>(),
        1
    );
    assert_eq!(
        reports
            .iter()
            .map(
                |report| report["missing_evidence_matched_by_tuple"]["lines"]
                    .as_u64()
                    .unwrap()
            )
            .sum::<u64>(),
        1
    );
    assert_eq!(
        target_report(&artifact, (known + 1) as u64)["missing_evidence_counted"]["lines"],
        1
    );
    fs::remove_dir_all(fixture.root).unwrap();
}
