// Slice D1: durable Claude request-census records and the shadow predicate.
// Records are produced, persisted, pruned and measured; no decision reads
// them. All fixtures are synthetic and content-free.
use super::*;
use crate::snapshots::claude_request_census::{
    claude_census_disjointness_complete, claude_census_member_status, claude_request_hash,
    ClaudeCensusMemberStatus, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    CLAUDE_REQUEST_CENSUS_CANARY, CLAUDE_REQUEST_CENSUS_DERIVATION,
    MAX_CLAUDE_REQUEST_CENSUS_HASHES, MAX_RAW_BYTES, MAX_RECORD_BYTES,
};
use sha2::Sha256 as CanarySha256;

/// One canary fixture: (shape, sorted request hashes).
type CanaryRow = (String, Vec<u64>);

const FIRST_WINDOW: &str = "2026-08-02T09:00:00Z";
const SECOND_WINDOW: &str = "2026-08-03T09:00:00Z";

fn census_response(
    session: &str,
    request: Option<&str>,
    message: &str,
    second: u32,
    output_tokens: u64,
) -> String {
    let input_tokens = if output_tokens == 0 { 0 } else { 10 };
    let mut value = serde_json::json!({
        "timestamp": format!("2026-08-02T07:00:{second:02}Z"),
        "type": "assistant",
        "sessionId": session,
        "message": {
            "id": message,
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        },
    });
    if let Some(request) = request {
        value["requestId"] = serde_json::json!(request);
    }
    format!("{value}\n")
}

fn census_forked_response(session: &str, request: &str, message: &str, valid: bool) -> String {
    let forked_from = if valid {
        serde_json::json!({"sessionId": "census-parent", "messageUuid": "parent-message"})
    } else {
        serde_json::json!({"sessionId": "census-parent"})
    };
    let value = serde_json::json!({
        "timestamp": "2026-08-02T07:00:30Z",
        "type": "assistant",
        "sessionId": session,
        "forkedFrom": forked_from,
        "requestId": request,
        "message": {
            "id": message,
            "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 10, "output_tokens": 10},
        },
    });
    format!("{value}\n")
}

fn census_user_line(session: &str, content: &str) -> String {
    let value = serde_json::json!({
        "timestamp": "2026-08-02T07:00:00Z",
        "type": "user",
        "sessionId": session,
        "message": {"role": "user", "content": content},
    });
    format!("{value}\n")
}

fn census_write(root: &Path, name: &str, lines: &[String]) {
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture dir");
    std::fs::write(path, lines.concat()).expect("write census fixture");
}

/// The canary corpus (SOURCE S3(b)): every shape class the parser can give a
/// Claude record, under a fixed name each. Not covered (see the PR): the
/// 65,536 response-record cap (it drops through the same `note_dropped_usage`
/// as the invalid `forkedFrom` row here) and multi-item files (a Claude file
/// yields at most one item).
fn write_census_corpus(root: &Path) {
    census_write(
        root,
        "canary-exact.jsonl",
        &[
            census_response("canary-exact", Some("req_exact_1"), "msg_exact_1", 1, 10),
            census_response("canary-exact", Some("req_exact_2"), "msg_exact_2", 2, 10),
        ],
    );
    // Context row G: an API-error (zero-usage) response still counts its id.
    census_write(
        root,
        "canary-zero-usage.jsonl",
        &[
            census_response("canary-zero-usage", Some("req_zero_1"), "msg_zero_1", 1, 10),
            census_response(
                "canary-zero-usage",
                Some("req_zero_err"),
                "msg_zero_err",
                2,
                0,
            ),
        ],
    );
    // Row H: no responses at all.
    census_write(
        root,
        "canary-empty.jsonl",
        &[census_user_line("canary-empty", "census fixture")],
    );
    // Row I: an id-less usage response; the visible id is kept.
    census_write(
        root,
        "canary-id-less.jsonl",
        &[
            census_response(
                "canary-id-less",
                Some("req_idless_1"),
                "msg_idless_1",
                1,
                10,
            ),
            census_response("canary-id-less", None, "msg_idless_2", 2, 10),
        ],
    );
    // Row J: one request id on two responses.
    census_write(
        root,
        "canary-repeated.jsonl",
        &[
            census_response("canary-repeated", Some("req_rep"), "msg_rep_1", 1, 10),
            census_response("canary-repeated", Some("req_rep"), "msg_rep_2", 2, 10),
        ],
    );
    // A dropped response (malformed `forkedFrom`): non-progressing residue.
    census_write(
        root,
        "canary-invalid-fork.jsonl",
        &[
            census_response(
                "canary-invalid-fork",
                Some("req_badfork_1"),
                "msg_badfork_1",
                1,
                10,
            ),
            census_forked_response(
                "canary-invalid-fork",
                "req_badfork_2",
                "msg_badfork_2",
                false,
            ),
        ],
    );
    // Terminal line loss over the line cap.
    census_write(
        root,
        "canary-over-line-cap.jsonl",
        &[
            census_response(
                "canary-over-line-cap",
                Some("req_cap_1"),
                "msg_cap_1",
                1,
                10,
            ),
            census_user_line(
                "canary-over-line-cap",
                &"x".repeat(MAX_JSONL_LINE_BYTES + 1024),
            ),
        ],
    );
    // A provider-marked fork prefix is excluded from the child's ids.
    census_write(
        root,
        "canary-forked.jsonl",
        &[
            census_forked_response("canary-forked", "req_fork_parent", "msg_fork_parent", true),
            census_response(
                "canary-forked",
                Some("req_fork_own"),
                "msg_fork_own",
                40,
                10,
            ),
        ],
    );
    // Progressive records of one response merge into one id.
    census_write(
        root,
        "canary-progressive.jsonl",
        &[
            census_response("canary-progressive", Some("req_prog"), "msg_prog", 1, 5),
            census_response("canary-progressive", Some("req_prog"), "msg_prog", 2, 10),
        ],
    );
    // Provider time out of file order.
    census_write(
        root,
        "canary-provider-time.jsonl",
        &[
            census_response(
                "canary-provider-time",
                Some("req_time_late"),
                "msg_time_late",
                50,
                10,
            ),
            census_response(
                "canary-provider-time",
                Some("req_time_early"),
                "msg_time_early",
                10,
                10,
            ),
        ],
    );
    // A root and its subagent path.
    census_write(
        root,
        "canary-root.jsonl",
        &[census_response(
            "canary-root",
            Some("req_root_1"),
            "msg_root_1",
            1,
            10,
        )],
    );
    census_write(
        root,
        "canary-root/subagents/agent-canary.jsonl",
        &[census_response(
            "canary-root",
            Some("req_sub_1"),
            "msg_sub_1",
            3,
            10,
        )],
    );
    // Content session id differs from the path stem.
    census_write(
        root,
        "canary-path.jsonl",
        &[census_response(
            "canary-content",
            Some("req_alias_1"),
            "msg_alias_1",
            1,
            10,
        )],
    );
}

/// What the parser must yield for the canary corpus at the current
/// derivation: (shape, request ids) per fixture name.
fn expected_census_table() -> BTreeMap<String, CanaryRow> {
    [
        ("canary-empty.jsonl", "empty", vec![]),
        (
            "canary-exact.jsonl",
            "exact",
            vec!["req_exact_1", "req_exact_2"],
        ),
        ("canary-forked.jsonl", "exact", vec!["req_fork_own"]),
        (
            "canary-id-less.jsonl",
            "identity_incomplete",
            vec!["req_idless_1"],
        ),
        ("canary-invalid-fork.jsonl", "lossy", vec!["req_badfork_1"]),
        ("canary-over-line-cap.jsonl", "lossy", vec!["req_cap_1"]),
        ("canary-path.jsonl", "exact", vec!["req_alias_1"]),
        ("canary-progressive.jsonl", "exact", vec!["req_prog"]),
        (
            "canary-provider-time.jsonl",
            "exact",
            vec!["req_time_early", "req_time_late"],
        ),
        (
            "canary-repeated.jsonl",
            "identity_incomplete",
            vec!["req_rep"],
        ),
        ("canary-root.jsonl", "exact", vec!["req_root_1"]),
        (
            "canary-root/subagents/agent-canary.jsonl",
            "exact",
            vec!["req_sub_1"],
        ),
        (
            "canary-zero-usage.jsonl",
            "exact",
            vec!["req_zero_1", "req_zero_err"],
        ),
    ]
    .into_iter()
    .map(|(name, shape, ids)| {
        let mut hashes = ids.into_iter().map(claude_request_hash).collect::<Vec<_>>();
        hashes.sort_unstable();
        (name.to_string(), (shape.to_string(), hashes))
    })
    .collect()
}

fn census_relative(root: &Path, key: &str) -> String {
    let canonical = std::fs::canonicalize(root).unwrap_or_default();
    Path::new(key)
        .strip_prefix(root)
        .or_else(|_| Path::new(key).strip_prefix(&canonical))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| key.to_string())
}

fn census_key(index: &ScanIndex, root: &Path, name: &str) -> String {
    index
        .claude_request_census_for_test()
        .keys_for_test()
        .into_iter()
        .chain(index.files.keys().cloned())
        .find(|key| census_relative(root, key) == name)
        .unwrap_or_else(|| panic!("{name} has neither a record nor an entry"))
}

fn observed_census_table(index: &ScanIndex, root: &Path) -> BTreeMap<String, CanaryRow> {
    let census = index.claude_request_census_for_test();
    census
        .keys_for_test()
        .into_iter()
        .map(|key| {
            let record = census.get(&key).expect("listed record");
            (
                census_relative(root, &key),
                (
                    record.shape_for_test().wire().to_string(),
                    record.request_hashes_for_test().to_vec(),
                ),
            )
        })
        .collect()
}

fn canary_digest(table: &BTreeMap<String, CanaryRow>) -> String {
    let mut text = String::new();
    for (name, (shape, hashes)) in table {
        let hashes = hashes
            .iter()
            .map(|hash| format!("{hash:016x}"))
            .collect::<Vec<_>>()
            .join(",");
        text.push_str(&format!("{name}|{shape}|{hashes}\n"));
    }
    format!("{:x}", CanarySha256::digest(text.as_bytes()))
}

/// The canary's verdict for a table produced under `derivation`.
fn canary_verdict(derivation: u16, table: &BTreeMap<String, CanaryRow>) -> Result<(), String> {
    let (pinned_derivation, pinned_digest) = CLAUDE_REQUEST_CENSUS_CANARY;
    let digest = canary_digest(table);
    if derivation != pinned_derivation {
        return Err(format!(
            "derivation {derivation} has no pinned canary (pinned {pinned_derivation}); \
             pin {digest} with the bump"
        ));
    }
    if digest != pinned_digest {
        return Err(format!(
            "request-census extraction changed under derivation {derivation}: canary \
             {digest} != pinned {pinned_digest}; bump CLAUDE_REQUEST_CENSUS_DERIVATION"
        ));
    }
    Ok(())
}

fn census_scan(root: &Path, index: &mut ScanIndex, collected_at: &str) -> SourceScanResult {
    scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[root.to_path_buf()],
        index,
        collected_at,
        365,
        1_000,
        true,
    )
    .expect("scan synthetic Claude corpus")
}

fn census_window(scan: &SourceScanResult) -> u64 {
    rfc3339_unix_seconds(&scan.census_window_end).expect("census window")
}

fn hex_fingerprint(seed: char) -> String {
    seed.to_string().repeat(64)
}

/// Unchanged may carry authority, but it cannot create it or conceal a
/// different census. The reader separately fences identity/scope and debt.
#[test]
fn census_unchanged_preserves_only_matching_verified_records() {
    use crate::snapshots::claude_request_census::{
        record_claude_request_census, ClaudeRequestCensusParse,
    };
    let path = Path::new("/census/projects/quiet.jsonl");
    let key = local_index_key(path);
    let fingerprint = hex_fingerprint('a');
    let mut item = valid_v6_batch_request().snapshots.remove(0);
    item.source_session_id = "quiet".to_string();
    item.attribution_facts.clear();
    item.claude_context_curve_identity_complete = true;
    item.claude_usage_request_ids = BTreeSet::from(["req_quiet".to_string()]);
    for exact in [false, true] {
        for case in [
            "same",
            "full",
            "fingerprint",
            "derivation",
            "contents",
            "shape",
            "unverified",
            "retired",
            "tail",
            "debt",
            "lossy",
            "incomplete",
        ] {
            let mut index = ScanIndex::default();
            let mut old = ClaudeRequestCensusRecord::synthetic_for_test(
                &if case == "fingerprint" {
                    hex_fingerprint('b')
                } else {
                    fingerprint.clone()
                },
                1,
                if exact != (case == "shape") {
                    ClaudeRequestCensusShape::Exact
                } else {
                    ClaudeRequestCensusShape::Empty
                },
                if case == "contents" {
                    vec![1]
                } else if exact {
                    vec![claude_request_hash("req_quiet")]
                } else {
                    vec![]
                },
            )
            .with_derivation_for_test(if case == "derivation" {
                0
            } else {
                CLAUDE_REQUEST_CENSUS_DERIVATION
            })
            .with_unverified_for_test(matches!(case, "unverified" | "retired" | "full"));
            if case == "retired" {
                old.retire();
            }
            index
                .claude_request_census_mut_for_test()
                .insert_for_test(&key, old);
            record_claude_request_census(
                &mut index,
                ClaudeRequestCensusParse {
                    path,
                    index_key: &key,
                    source_file_fingerprint: &fingerprint,
                    census_window_end: SECOND_WINDOW,
                    complete: case != "incomplete",
                    lossy: case == "lossy",
                    source_verified: case == "full",
                    unchanged_source: !matches!(case, "tail" | "debt" | "full"),
                    itemless_request_hashes: vec![],
                    opened_birth: None,
                    modified_unix_seconds: 0,
                },
                if exact {
                    std::slice::from_ref(&item)
                } else {
                    &[]
                },
            );
            assert_eq!(
                index
                    .claude_request_census
                    .get(&key)
                    .unwrap()
                    .unverified_for_test(),
                !matches!(case, "same" | "full"),
                "{case}"
            );
        }
    }
}

/// TD1a: every finished Claude parse writes a record bound to the candidate
/// fingerprint and the census window, shaped by Context rows G-J and loss.
#[test]
fn census_records_bind_each_parse_to_its_revision_and_shape() {
    let scratch = crate::test_scratch::ScratchDir::new("census-records-shapes");
    let root = scratch.join("projects");
    write_census_corpus(&root);
    let mut index = ScanIndex::default();
    let scan = census_scan(&root, &mut index, FIRST_WINDOW);
    let window = census_window(&scan);

    assert_eq!(
        observed_census_table(&index, &root),
        expected_census_table()
    );
    for (key, entry) in &index.files {
        let Some(record) = index.claude_request_census_for_test().get(key) else {
            continue;
        };
        assert_eq!(record.window_for_test(), window, "{key}");
        assert_eq!(
            record.fingerprint_hex_for_test(),
            entry.source_file_fingerprint,
            "a recorded entry and its record name the same revision: {key}"
        );
    }
    // A residue parse records nothing in `files`, yet its record replaces
    // any older one and holds the ids it saw.
    let residue = census_key(&index, &root, "canary-invalid-fork.jsonl");
    assert!(!index.files.contains_key(&residue));
    let record = index
        .claude_request_census_for_test()
        .get(&residue)
        .expect("residue record");
    assert_eq!(record.shape_for_test(), ClaudeRequestCensusShape::Lossy);
    assert_eq!(record.window_for_test(), window);
    // Content (root, member) differing from the path pair is a twin.
    let alias = census_key(&index, &root, "canary-path.jsonl");
    assert!(index
        .claude_request_census_for_test()
        .get(&alias)
        .expect("alias record")
        .twin_for_test());
    let exact = census_key(&index, &root, "canary-exact.jsonl");
    assert!(!index
        .claude_request_census_for_test()
        .get(&exact)
        .expect("exact record")
        .twin_for_test());
}

/// TD1d: the derivation canary. The fixed corpus must yield exactly the
/// pinned table under `CLAUDE_REQUEST_CENSUS_DERIVATION`.
#[test]
fn census_derivation_canary_pins_ids_and_shapes() {
    let scratch = crate::test_scratch::ScratchDir::new("census-derivation-canary");
    let root = scratch.join("projects");
    write_census_corpus(&root);
    let mut index = ScanIndex::default();
    census_scan(&root, &mut index, FIRST_WINDOW);
    let observed = observed_census_table(&index, &root);
    assert_eq!(observed, expected_census_table());
    assert_eq!(
        canary_verdict(CLAUDE_REQUEST_CENSUS_DERIVATION, &observed),
        Ok(())
    );
}

/// TD1f (review F1, SOURCE S2(c)): a re-parse of a previously complete key
/// that ends as residue, with copied ids, replaces the old record. The key is
/// never covered by the old revision, and the copied ids join the census.
#[test]
fn census_residue_reparse_never_keeps_the_old_record() {
    let scratch = crate::test_scratch::ScratchDir::new("census-residue-reparse");
    let root = scratch.join("projects");
    census_write(
        &root,
        "census-original.jsonl",
        &[
            census_response("census-original", Some("req_orig_1"), "msg_orig_1", 1, 10),
            census_response("census-original", Some("req_orig_2"), "msg_orig_2", 2, 10),
        ],
    );
    census_write(
        &root,
        "census-copier.jsonl",
        &[census_response(
            "census-copier",
            Some("req_copier_1"),
            "msg_copier_1",
            1,
            10,
        )],
    );
    let mut index = ScanIndex::default();
    let first = census_scan(&root, &mut index, FIRST_WINDOW);
    assert!(first.census_complete);
    let copier = census_key(&index, &root, "census-copier.jsonl");
    let original = census_key(&index, &root, "census-original.jsonl");
    let old_record = index
        .claude_request_census_for_test()
        .get(&copier)
        .expect("first record")
        .clone();
    let old_fingerprint = index.files[&copier].source_file_fingerprint.clone();
    assert_eq!(old_record.fingerprint_hex_for_test(), old_fingerprint);
    assert_eq!(
        claude_census_member_status(&index, &original, &first.census_window_end, true),
        ClaudeCensusMemberStatus::Disjoint
    );

    // A takeover appends the original's request plus one dropped response.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(root.join("census-copier.jsonl"))
        .expect("open copier");
    file.write_all(
        census_response("census-copier", Some("req_orig_1"), "msg_copied_1", 5, 10).as_bytes(),
    )
    .expect("append copied response");
    file.write_all(
        census_forked_response("census-copier", "req_copier_2", "msg_copier_2", false).as_bytes(),
    )
    .expect("append dropped response");
    drop(file);

    let second = census_scan(&root, &mut index, SECOND_WINDOW);
    assert_ne!(second.census_window_end, first.census_window_end);
    // The entry keeps the old revision (residue is never recorded) ...
    assert_eq!(
        index.files[&copier].source_file_fingerprint,
        old_fingerprint
    );
    // ... but the record is the new parse's, bound to its candidate.
    let record = index
        .claude_request_census_for_test()
        .get(&copier)
        .expect("residue record");
    assert_ne!(record, &old_record);
    assert_ne!(record.fingerprint_hex_for_test(), old_fingerprint);
    assert_eq!(record.window_for_test(), census_window(&second));
    assert_eq!(record.shape_for_test(), ClaudeRequestCensusShape::Lossy);
    assert!(record
        .request_hashes_for_test()
        .contains(&claude_request_hash("req_orig_1")));
    // Neither side is Disjoint: the copier's family is unknown and the
    // original shares the copied id.
    for key in [&copier, &original] {
        assert_ne!(
            claude_census_member_status(&index, key, &second.census_window_end, true),
            ClaudeCensusMemberStatus::Disjoint,
            "{key}"
        );
    }
    assert_eq!(
        claude_census_member_status(&index, &original, &second.census_window_end, true),
        ClaudeCensusMemberStatus::SharesHash
    );
}

/// TD1e: the shadow reports that the record census would converge on a
/// corpus whose BASE census cannot (identity-invalid pending, and separately
/// a cap-exceeding occurrence total), while the real fence stays BASE.
#[test]
fn census_shadow_would_open_where_the_base_fence_closes() {
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::new(),
        health: Default::default(),
    };
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    for (case, id_less, max_pending) in [
        (
            "identity-invalid",
            true,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
        ),
        ("cap-exceeding", false, 1),
    ] {
        let scratch = crate::test_scratch::ScratchDir::new(&format!("census-shadow-{case}"));
        let root = scratch.join("projects");
        census_write(
            &root,
            "census-shadow-a.jsonl",
            &[
                census_response(
                    "census-shadow-a",
                    Some("req_shadow_a1"),
                    "msg_shadow_a1",
                    1,
                    10,
                ),
                census_response(
                    "census-shadow-a",
                    Some("req_shadow_a2"),
                    "msg_shadow_a2",
                    2,
                    10,
                ),
            ],
        );
        census_write(
            &root,
            "census-shadow-b.jsonl",
            &[census_response(
                "census-shadow-b",
                (!id_less).then_some("req_shadow_b1"),
                "msg_shadow_b1",
                1,
                10,
            )],
        );
        let mut index = ScanIndex::default();
        let mut scan = census_scan(&root, &mut index, FIRST_WINDOW);
        assert!(scan.census_complete, "{case}");
        let shadow = scan.claude_request_census_shadow.expect("terminal shadow");
        assert!(shadow.would_open, "{case}: {shadow:?}");
        assert_eq!(shadow.family_keys, 2, "{case}");
        assert_eq!(shadow.covered_by_fingerprint, 2, "{case}");
        assert_eq!(
            shadow.shape_identity_incomplete,
            usize::from(id_less),
            "{case}"
        );
        assert!(claude_census_disjointness_complete(
            &index,
            &scan.census_window_end,
            true
        ));
        let census_window_end = scan.census_window_end.clone();
        let disposition = apply_claude_reported_usage_with_index_and_limits(
            &mut scan.snapshots,
            &api,
            &trace,
            &mut index,
            true,
            &census_window_end,
            max_pending,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        );
        assert!(
            index.claude_duplicate_request_witness_overflowed,
            "{case}: the BASE fence closes"
        );
        assert!(disposition.duplicate_census.fence_after, "{case}");
        assert_eq!(disposition.duplicate_census.request_census, None);
    }
}

/// TD1b: census state follows the working index on a partial commit, never
/// `previous`: an unsettled key reverts its entry but keeps the record this
/// window parsed, and a never-committed key keeps its record until pruned.
#[test]
fn census_records_follow_the_working_index_through_committable_subset() {
    let key = "/census/projects/census-partial.jsonl".to_string();
    let new_key = "/census/projects/census-new.jsonl".to_string();
    let mut previous = ScanIndex::default();
    let mut old_entry = manifest_index_entry(Some("old-body"));
    old_entry.source_file_fingerprint = hex_fingerprint('a');
    previous.files.insert(key.clone(), old_entry.clone());
    previous
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["old-body".to_string()]));
    let old_record = ClaudeRequestCensusRecord::synthetic_for_test(
        &hex_fingerprint('a'),
        1,
        ClaudeRequestCensusShape::Exact,
        vec![1],
    );
    previous
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, old_record);

    let mut current = previous.clone();
    let mut new_entry = manifest_index_entry(Some("new-body"));
    new_entry.source_file_fingerprint = hex_fingerprint('b');
    current.files.insert(key.clone(), new_entry);
    current
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["new-body".to_string()]));
    let new_record = ClaudeRequestCensusRecord::synthetic_for_test(
        &hex_fingerprint('b'),
        2,
        ClaudeRequestCensusShape::Exact,
        vec![1, 2],
    );
    current
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, new_record.clone());
    let mut unseen_entry = manifest_index_entry(Some("unseen-body"));
    unseen_entry.source_file_fingerprint = hex_fingerprint('c');
    current.files.insert(new_key.clone(), unseen_entry);
    current
        .file_snapshot_fingerprints
        .insert(new_key.clone(), BTreeSet::from(["unseen-body".to_string()]));
    let unseen_record = ClaudeRequestCensusRecord::synthetic_for_test(
        &hex_fingerprint('c'),
        2,
        ClaudeRequestCensusShape::Exact,
        vec![3],
    );
    current
        .claude_request_census_mut_for_test()
        .insert_for_test(&new_key, unseen_record.clone());

    // Nothing accepted: both entries revert (BASE rule, unchanged).
    let committed = current.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        serde_json::to_value(&committed.files[&key]).expect("entry"),
        serde_json::to_value(&old_entry).expect("entry")
    );
    assert!(!committed.files.contains_key(&new_key));
    // Records follow `self`.
    let census = committed.claude_request_census_for_test();
    assert_eq!(census.get(&key), Some(&new_record));
    assert_eq!(census.get(&new_key), Some(&unseen_record));
    assert_eq!(census.hash_total_for_test(), 3);
    assert_eq!(
        committed.claude_request_census_shadow_for_test(),
        current.claude_request_census_shadow_for_test()
    );
}

/// Prune at the complete terminal: before any join, keep only keys that are
/// indexed or were walked this generation (review F9).
#[test]
fn census_terminal_prune_keeps_indexed_and_walked_keys_only() {
    let indexed = "/census/projects/census-indexed.jsonl".to_string();
    let walked = "/census/projects/census-walked.jsonl".to_string();
    let retired = "/census/projects/census-retired.jsonl".to_string();
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = hex_fingerprint('a');
    // Modified in this window: not due for transcript retirement.
    entry.modified_unix_seconds = rfc3339_unix_seconds(FIRST_WINDOW).expect("window");
    index.files.insert(indexed.clone(), entry);
    index
        .file_snapshot_fingerprints
        .insert(indexed.clone(), BTreeSet::from(["body".to_string()]));
    for (key, seed, hash) in [(&indexed, 'a', 1), (&walked, 'b', 2), (&retired, 'c', 2)] {
        index.claude_request_census_mut_for_test().insert_for_test(
            key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &hex_fingerprint(seed),
                1,
                ClaudeRequestCensusShape::Exact,
                vec![hash],
            ),
        );
    }
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::from([walked.clone()]),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    assert_eq!(
        index.claude_request_census_for_test().keys_for_test(),
        vec![indexed.clone(), walked.clone()]
    );
    assert_eq!(
        index.claude_request_census_for_test().hash_total_for_test(),
        2
    );
    // The retired record's copy of hash 2 no longer makes a duplicate.
    assert_eq!(counts.duplicate_hashes, 0);
    assert_eq!(counts.records, 2);
    assert_eq!(counts.family_keys, 1);
    assert_eq!(counts.covered_by_fingerprint, 1);
    assert!(counts.would_open);
    assert_eq!(
        index
            .claude_request_census_shadow_for_test()
            .would_open_for_test(),
        Some(true)
    );
}

/// The shadow predicate and per-member status on a synthetic index: coverage
/// by fingerprint or by this window, shared hashes, census-unknown families,
/// unverified records, and a missing record that keeps the predicate false.
#[test]
fn census_member_status_names_disjoint_shared_unknown_and_unobserved() {
    let window = rfc3339_unix_seconds(FIRST_WINDOW).expect("window");
    let key = |name: &str| format!("/census/projects/{name}.jsonl");
    let mut index = ScanIndex::default();
    let mut add = |name: &str, seed: char, record: Option<ClaudeRequestCensusRecord>| {
        let mut entry = manifest_index_entry(Some(name));
        entry.source_file_fingerprint = hex_fingerprint(seed);
        // Modified in this window: not due for transcript retirement.
        entry.modified_unix_seconds = window;
        index.files.insert(key(name), entry);
        index
            .file_snapshot_fingerprints
            .insert(key(name), BTreeSet::from([name.to_string()]));
        if let Some(record) = record {
            index
                .claude_request_census_mut_for_test()
                .insert_for_test(&key(name), record);
        }
    };
    let record = |seed: char, window: u64, shape, hashes: Vec<u64>| {
        ClaudeRequestCensusRecord::synthetic_for_test(&hex_fingerprint(seed), window, shape, hashes)
    };
    add(
        "disjoint",
        'a',
        Some(record('a', 1, ClaudeRequestCensusShape::Exact, vec![1, 2])),
    );
    add(
        "shared-1",
        'b',
        Some(record('b', 1, ClaudeRequestCensusShape::Exact, vec![3])),
    );
    add(
        "shared-2",
        'c',
        Some(record('c', 1, ClaudeRequestCensusShape::Exact, vec![3, 4])),
    );
    add(
        "id-less",
        'd',
        Some(record(
            'd',
            1,
            ClaudeRequestCensusShape::IdentityIncomplete,
            vec![5],
        )),
    );
    // Fingerprint moved on, but parsed in this window: covered by window.
    add(
        "held",
        'e',
        Some(record(
            'f',
            window,
            ClaudeRequestCensusShape::Exact,
            vec![6],
        )),
    );
    add(
        "unverified",
        '0',
        Some(
            record('0', 1, ClaudeRequestCensusShape::Exact, vec![7]).with_unverified_for_test(true),
        ),
    );
    // A record from another derivation is inert.
    add(
        "migrate",
        '1',
        Some(
            record('1', 1, ClaudeRequestCensusShape::Exact, vec![8])
                .with_derivation_for_test(CLAUDE_REQUEST_CENSUS_DERIVATION + 1),
        ),
    );
    assert!(!claude_census_disjointness_complete(
        &index,
        FIRST_WINDOW,
        true
    ));
    assert_eq!(
        claude_census_member_status(&index, &key("disjoint"), FIRST_WINDOW, true),
        ClaudeCensusMemberStatus::Unobserved
    );
    index.claude_request_census_mut_for_test().insert_for_test(
        &key("migrate"),
        record('1', 1, ClaudeRequestCensusShape::Empty, vec![]),
    );
    assert!(claude_census_disjointness_complete(
        &index,
        FIRST_WINDOW,
        true
    ));
    assert!(!claude_census_disjointness_complete(
        &index,
        FIRST_WINDOW,
        false
    ));
    // The window rule only covers this window.
    assert!(!claude_census_disjointness_complete(
        &index,
        SECOND_WINDOW,
        true
    ));
    let status = |name: &str| claude_census_member_status(&index, &key(name), FIRST_WINDOW, true);
    assert_eq!(status("disjoint"), ClaudeCensusMemberStatus::Disjoint);
    assert_eq!(status("shared-1"), ClaudeCensusMemberStatus::SharesHash);
    assert_eq!(status("shared-2"), ClaudeCensusMemberStatus::SharesHash);
    assert_eq!(status("id-less"), ClaudeCensusMemberStatus::FamilyUnknown);
    assert_eq!(status("held"), ClaudeCensusMemberStatus::Disjoint);
    assert_eq!(status("unverified"), ClaudeCensusMemberStatus::Unverified);
    assert_eq!(status("migrate"), ClaudeCensusMemberStatus::Disjoint);

    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    assert!(counts.would_open);
    assert_eq!(counts.family_keys, 7);
    assert_eq!(counts.covered_by_fingerprint, 6);
    assert_eq!(counts.covered_by_window, 1);
    assert_eq!(counts.shape_exact, 5);
    assert_eq!(counts.shape_empty, 1);
    assert_eq!(counts.shape_identity_incomplete, 1);
    assert_eq!(counts.unverified, 1);
    assert_eq!(counts.duplicate_hashes, 1);
    assert_eq!(counts.duplicate_owner_entries, 2);
    assert_eq!(counts.shared_keys, 2);
    assert_eq!(counts.family_unknown_roots, 1);
    assert_eq!(counts.hashes, 8);
    assert!(counts.json_bytes > 0);
}

/// S2(d), S8 and the review's cause list: every uncovered key is counted
/// once, under the first matching cause, and quarantine keys without a
/// record are counted on their own.
#[test]
fn census_shadow_counts_each_missing_record_by_cause() {
    let key = |name: &str| format!("/census/projects/{name}.jsonl");
    let mut index = ScanIndex::default();
    let mut add = |name: &str, seed: char, snapshot: bool| {
        let mut entry = manifest_index_entry(snapshot.then_some(name));
        entry.source_file_fingerprint = if seed == ' ' {
            String::new()
        } else {
            hex_fingerprint(seed)
        };
        index.files.insert(key(name), entry);
        if snapshot {
            index
                .file_snapshot_fingerprints
                .insert(key(name), BTreeSet::from([name.to_string()]));
        }
    };
    add("over-budget", 'a', true);
    add("account-hold", 'b', true);
    add("residue", 'c', true);
    add("placeholder", 'd', false);
    add("empty-fp", ' ', true);
    add("fp-mismatch", 'e', true);
    add("migrate", 'f', true);
    add("quarantined", '1', true);
    index.claude_request_census_mut_for_test().insert_for_test(
        &key("over-budget"),
        ClaudeRequestCensusRecord::synthetic_for_test(
            &hex_fingerprint('a'),
            1,
            ClaudeRequestCensusShape::OverBudget,
            vec![],
        ),
    );
    index.claude_request_census_mut_for_test().insert_for_test(
        &key("fp-mismatch"),
        ClaudeRequestCensusRecord::synthetic_for_test(
            &hex_fingerprint('9'),
            1,
            ClaudeRequestCensusShape::Exact,
            vec![1],
        ),
    );
    index
        .claude_account_deferred_holds
        .insert(key("account-hold"), "held-body".to_string());
    index.insert_retry_pending_claude_authority_for_test("quarantined");
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::new(),
        &BTreeSet::from([key("residue")]),
        FIRST_WINDOW,
    );
    assert!(!counts.would_open);
    assert_eq!(counts.family_keys, 8);
    assert_eq!(counts.missing_over_budget, 1);
    assert_eq!(counts.missing_account_hold, 1);
    assert_eq!(counts.missing_residue, 1);
    assert_eq!(counts.missing_placeholder, 1);
    assert_eq!(counts.missing_empty_fingerprint, 1);
    assert_eq!(counts.missing_fingerprint_mismatch, 1);
    assert_eq!(counts.missing_migrate, 2);
    assert_eq!(counts.quarantine_without_record, 1);
    assert_eq!(counts.covered_by_fingerprint + counts.covered_by_window, 0);
}

/// S3(d) tripwire: a verified complete re-parse at an unchanged fingerprint
/// and derivation that yields different ids is counted; the same ids are not.
#[test]
fn census_derivation_drift_tripwire_counts_changed_ids_at_one_revision() {
    let scratch = crate::test_scratch::ScratchDir::new("census-derivation-drift");
    let root = scratch.join("projects");
    census_write(
        &root,
        "census-drift.jsonl",
        &[census_response(
            "census-drift",
            Some("req_drift_1"),
            "msg_drift_1",
            1,
            10,
        )],
    );
    let mut index = ScanIndex::default();
    census_scan(&root, &mut index, FIRST_WINDOW);
    let key = census_key(&index, &root, "census-drift.jsonl");
    let record = index
        .claude_request_census_for_test()
        .get(&key)
        .expect("record")
        .clone();
    assert!(!record.unverified_for_test(), "a full loss-free read");
    assert_eq!(
        index
            .claude_request_census_shadow_for_test()
            .derivation_drift_for_test(),
        0
    );
    // As if an older parser had recorded other ids at this exact revision.
    index.claude_request_census_mut_for_test().insert_for_test(
        &key,
        ClaudeRequestCensusRecord::synthetic_for_test(
            &record.fingerprint_hex_for_test(),
            record.window_for_test(),
            ClaudeRequestCensusShape::Exact,
            vec![claude_request_hash("req_other")],
        ),
    );
    index
        .files
        .get_mut(&key)
        .expect("entry")
        .source_file_fingerprint
        .clear();
    census_scan(&root, &mut index, SECOND_WINDOW);
    let reparsed = index
        .claude_request_census_for_test()
        .get(&key)
        .expect("reparsed record");
    assert_eq!(
        reparsed.fingerprint_hex_for_test(),
        record.fingerprint_hex_for_test()
    );
    assert_eq!(
        index
            .claude_request_census_shadow_for_test()
            .derivation_drift_for_test(),
        1
    );
    // The same ids at the same revision are no drift.
    index
        .files
        .get_mut(&key)
        .expect("entry")
        .source_file_fingerprint
        .clear();
    census_scan(&root, &mut index, "2026-08-04T09:00:00Z");
    assert_eq!(
        index
            .claude_request_census_shadow_for_test()
            .derivation_drift_for_test(),
        1
    );
    // A budget tombstone at the same revision is no drift either: the budget,
    // not extraction, replaced its shape and hashes.
    index.claude_request_census_mut_for_test().insert_for_test(
        &key,
        ClaudeRequestCensusRecord::synthetic_for_test(
            &record.fingerprint_hex_for_test(),
            record.window_for_test(),
            ClaudeRequestCensusShape::OverBudget,
            vec![],
        ),
    );
    index
        .files
        .get_mut(&key)
        .expect("entry")
        .source_file_fingerprint
        .clear();
    census_scan(&root, &mut index, "2026-08-05T09:00:00Z");
    assert_eq!(
        index
            .claude_request_census_for_test()
            .get(&key)
            .expect("reparsed record")
            .shape_for_test(),
        ClaudeRequestCensusShape::Exact
    );
    assert_eq!(
        index
            .claude_request_census_shadow_for_test()
            .derivation_drift_for_test(),
        1
    );
}

/// StateMissing M1: an unchanged re-parse of a record retired at 35 days
/// (a backfill re-reading every file, a resume miss) is no derivation drift
/// and leaves the record retired: neither the hashes nor the index bytes
/// bounce back.
#[test]
fn census_retired_record_survives_an_unchanged_reparse() {
    let scratch = crate::test_scratch::ScratchDir::new("census-retired-reparse");
    let root = scratch.join("projects");
    census_write(
        &root,
        "census-retired.jsonl",
        &[census_response(
            "census-retired",
            Some("req_retired_1"),
            "msg_retired_1",
            1,
            10,
        )],
    );
    // Windows far enough past the file's mtime (now) to retire it.
    let mut index = ScanIndex::default();
    census_scan(&root, &mut index, "2027-03-01T09:00:00Z");
    let key = census_key(&index, &root, "census-retired.jsonl");
    let retired = index
        .claude_request_census_for_test()
        .record_for_test(&key)
        .expect("record")
        .clone();
    assert_eq!(
        retired.retired_for_test(),
        Some(1),
        "retired at the terminal"
    );
    let hashes = index.claude_request_census_for_test().totals_for_test().0;
    index
        .files
        .get_mut(&key)
        .expect("entry")
        .source_file_fingerprint
        .clear();
    census_scan(&root, &mut index, "2027-03-02T09:00:00Z");
    let reparsed = index
        .claude_request_census_for_test()
        .record_for_test(&key)
        .expect("reparsed record");
    assert_eq!(
        reparsed.fingerprint_hex_for_test(),
        retired.fingerprint_hex_for_test()
    );
    assert_eq!(reparsed.retired_for_test(), Some(1), "still retired");
    assert!(reparsed.request_hashes_for_test().is_empty());
    assert_eq!(
        index
            .claude_request_census_shadow_for_test()
            .derivation_drift_for_test(),
        0
    );
    assert_eq!(
        index.claude_request_census_for_test().totals_for_test().0,
        hashes
    );
}

/// A transcript of zero-usage responses only (API errors) yields no item, yet
/// its request ids still reach the census and meet a peer's copy.
#[test]
fn census_records_keep_ids_of_zero_usage_only_transcripts() {
    let scratch = crate::test_scratch::ScratchDir::new("census-zero-usage-only");
    let root = scratch.join("projects");
    census_write(
        &root,
        "census-api-errors.jsonl",
        &[census_response(
            "census-api-errors",
            Some("req_shared_err"),
            "msg_err_1",
            1,
            0,
        )],
    );
    census_write(
        &root,
        "census-peer.jsonl",
        &[census_response(
            "census-peer",
            Some("req_shared_err"),
            "msg_peer_1",
            2,
            10,
        )],
    );
    let mut index = ScanIndex::default();
    let scan = census_scan(&root, &mut index, FIRST_WINDOW);
    let errors = census_key(&index, &root, "census-api-errors.jsonl");
    let peer = census_key(&index, &root, "census-peer.jsonl");
    let record = index
        .claude_request_census_for_test()
        .get(&errors)
        .expect("zero-usage record");
    assert_eq!(
        record.request_hashes_for_test(),
        &[claude_request_hash("req_shared_err")]
    );
    assert_ne!(record.shape_for_test(), ClaudeRequestCensusShape::Empty);
    assert_ne!(record.shape_for_test(), ClaudeRequestCensusShape::Exact);
    assert_eq!(
        claude_census_member_status(&index, &peer, &scan.census_window_end, true),
        ClaudeCensusMemberStatus::SharesHash
    );
}

/// A lossy member that has no counted entry (a residue subagent never
/// indexed) still leaves its family census-unknown.
#[test]
fn census_unindexed_lossy_member_leaves_its_family_unknown() {
    let root_key = "/census/projects/census-clean.jsonl".to_string();
    let member_key = "/census/projects/census-clean/subagents/agent-residue.jsonl".to_string();
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("clean"));
    entry.source_file_fingerprint = hex_fingerprint('a');
    index.files.insert(root_key.clone(), entry);
    index
        .file_snapshot_fingerprints
        .insert(root_key.clone(), BTreeSet::from(["clean".to_string()]));
    for (key, seed, shape, hash) in [
        (&root_key, 'a', ClaudeRequestCensusShape::Exact, 1),
        (&member_key, 'b', ClaudeRequestCensusShape::Lossy, 2),
    ] {
        index.claude_request_census_mut_for_test().insert_for_test(
            key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &hex_fingerprint(seed),
                1,
                shape,
                vec![hash],
            ),
        );
    }
    assert_eq!(
        claude_census_member_status(&index, &root_key, FIRST_WINDOW, true),
        ClaudeCensusMemberStatus::FamilyUnknown
    );
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::from([member_key.clone()]),
        &BTreeSet::from([member_key.clone()]),
        FIRST_WINDOW,
    );
    assert!(counts.would_open);
    assert_eq!(counts.family_keys, 1);
    assert_eq!(counts.family_unknown_roots, 1);
    assert_eq!(counts.records, 2);
}

fn census_index_json(records: serde_json::Value) -> serde_json::Value {
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = hex_fingerprint('a');
    index
        .files
        .insert("/census/projects/census-a.jsonl".to_string(), entry);
    let mut value = serde_json::to_value(&index).expect("index value");
    value["claude_request_census"] = records;
    value
}

fn census_load(scratch: &Path, name: &str, json: &str) -> ScanIndex {
    let path = scratch.join(format!("{name}.json"));
    std::fs::write(&path, json).expect("write index");
    let loaded = ScanIndex::load(&path).expect("load index");
    assert!(path.exists(), "{name}: the index was never quarantined");
    assert_eq!(loaded.files.len(), 1, "{name}: the rest of the index loads");
    loaded
}

fn census_record_json(seed: char, shape: &str, hashes: &[u64]) -> serde_json::Value {
    let mut value = serde_json::json!({
        "v": CLAUDE_REQUEST_CENSUS_DERIVATION,
        "fp": hex_fingerprint(seed),
        "w": 7,
        "s": shape,
    });
    if !hashes.is_empty() {
        value["b"] = serde_json::json!(base64_hashes(hashes));
    }
    value
}

/// The `b` wire form: base64 of the big-endian hashes.
fn base64_hashes(hashes: &[u64]) -> String {
    use base64::Engine as _;
    let bytes = hashes
        .iter()
        .flat_map(|hash| hash.to_be_bytes())
        .collect::<Vec<_>>();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The legacy `h` wire form (#664): concatenated 16-digit lowercase hex.
fn legacy_hex_hashes(hashes: &[u64]) -> String {
    hashes.iter().map(|hash| format!("{hash:016x}")).collect()
}

/// TD1c: the decoder is per entry, tolerant and bounded. An old index has no
/// field; a wrong-type field is empty; malformed entries are dropped one by
/// one; nothing ever quarantines the index. Records round-trip exactly.
#[test]
fn census_decoder_drops_bad_entries_and_never_quarantines_the_index() {
    let scratch = crate::test_scratch::ScratchDir::new("census-decoder");
    // Old JSON: no field at all.
    let old = census_index_json(serde_json::Value::Null);
    let mut old = old.as_object().expect("object").clone();
    old.remove("claude_request_census");
    let loaded = census_load(
        &scratch,
        "old",
        &serde_json::to_string(&old).expect("old json"),
    );
    assert_eq!(loaded.claude_request_census_for_test().len_for_test(), 0);

    // Round trip through save and load.
    let mut index = ScanIndex::default();
    let mut entry = manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = hex_fingerprint('a');
    index
        .files
        .insert("/census/projects/census-a.jsonl".to_string(), entry);
    let record = ClaudeRequestCensusRecord::synthetic_for_test(
        &hex_fingerprint('a'),
        7,
        ClaudeRequestCensusShape::Exact,
        vec![1, u64::MAX],
    );
    index
        .claude_request_census_mut_for_test()
        .insert_for_test("/census/projects/census-a.jsonl", record.clone());
    let round_trip = census_load(
        &scratch,
        "round-trip",
        &serde_json::to_string(&index).expect("index json"),
    );
    assert_eq!(
        round_trip
            .claude_request_census_for_test()
            .get("/census/projects/census-a.jsonl"),
        Some(&record)
    );

    // Wrong type for the whole field: an empty census.
    for (name, field) in [
        ("string", serde_json::json!("records")),
        ("number", serde_json::json!(7)),
        ("array", serde_json::json!([1, {"v": 1}])),
        ("null", serde_json::Value::Null),
        ("bool", serde_json::json!(true)),
    ] {
        let loaded = census_load(
            &scratch,
            name,
            &serde_json::to_string(&census_index_json(field)).expect("json"),
        );
        assert_eq!(
            loaded.claude_request_census_for_test().len_for_test(),
            0,
            "{name}"
        );
    }

    // Malformed entries are dropped one by one; the good one survives.
    let good = census_record_json('a', "exact", &[1, 2]);
    let mut bad_fp = census_record_json('a', "exact", &[1]);
    bad_fp["fp"] = serde_json::json!("A".repeat(64));
    let mut short_fp = census_record_json('a', "exact", &[1]);
    short_fp["fp"] = serde_json::json!("a".repeat(63));
    let mut ragged = census_record_json('a', "lossy", &[]);
    ragged["h"] = serde_json::json!("0123");
    let mut descending = census_record_json('a', "lossy", &[]);
    descending["h"] = serde_json::json!(legacy_hex_hashes(&[2, 1]));
    let mut repeated = census_record_json('a', "lossy", &[]);
    repeated["h"] = serde_json::json!(legacy_hex_hashes(&[1, 1]));
    let unknown_shape = census_record_json('a', "multi_item", &[1]);
    let exact_without_ids = census_record_json('a', "exact", &[]);
    let empty_with_ids = census_record_json('a', "empty", &[1]);
    let mut negative_derivation = census_record_json('a', "exact", &[1]);
    negative_derivation["v"] = serde_json::json!(-1);
    let mut wide_derivation = census_record_json('a', "exact", &[1]);
    wide_derivation["v"] = serde_json::json!(70_000);
    let mut wrong_flag = census_record_json('a', "exact", &[1]);
    wrong_flag["tw"] = serde_json::json!("yes");
    let mut nested = census_record_json('a', "exact", &[]);
    nested["h"] = serde_json::json!({"a": [1, 2]});
    let mut missing_fp = census_record_json('a', "exact", &[1]);
    missing_fp.as_object_mut().expect("record").remove("fp");
    let mut forward = census_record_json('a', "exact", &[9]);
    forward["future"] = serde_json::json!({"anything": [1, "x"]});
    let mut records = serde_json::json!({
        "good": good,
        "bad-fp": bad_fp,
        "short-fp": short_fp,
        "ragged": ragged,
        "descending": descending,
        "repeated": repeated,
        "unknown-shape": unknown_shape,
        "exact-without-ids": exact_without_ids,
        "empty-with-ids": empty_with_ids,
        "negative-derivation": negative_derivation,
        "wide-derivation": wide_derivation,
        "wrong-flag": wrong_flag,
        "nested": nested,
        "missing-fp": missing_fp,
        "not-an-object": [1, 2, 3],
        "forward": forward,
    });
    records["k".repeat(5_000).as_str()] = census_record_json('a', "exact", &[1]);
    let mut json = serde_json::to_string(&census_index_json(records)).expect("json");
    // A duplicated field inside one record is malformed too.
    json = json.replacen(
        "\"good\":{",
        &format!(
            "\"duplicate-field\":{{\"v\":{CLAUDE_REQUEST_CENSUS_DERIVATION},\"v\":{CLAUDE_REQUEST_CENSUS_DERIVATION},\"fp\":\"{}\",\"s\":\"empty\"}},\"good\":{{",
            hex_fingerprint('a')
        ),
        1,
    );
    let loaded = census_load(&scratch, "malformed", &json);
    let census = loaded.claude_request_census_for_test();
    assert_eq!(
        census.keys_for_test(),
        vec!["forward".to_string(), "good".to_string()]
    );
    assert_eq!(census.hash_total_for_test(), 3);

    // The shadow memory is tolerant too.
    let mut value = census_index_json(serde_json::json!({}));
    value["claude_request_census_shadow"] = serde_json::json!({"o": true, "f": 3, "d": "x"});
    let loaded = census_load(
        &scratch,
        "shadow-state",
        &serde_json::to_string(&value).expect("json"),
    );
    assert_eq!(
        loaded
            .claude_request_census_shadow_for_test()
            .would_open_for_test(),
        Some(true)
    );
    assert_eq!(
        loaded
            .claude_request_census_shadow_for_test()
            .derivation_drift_for_test(),
        0
    );
    value["claude_request_census_shadow"] = serde_json::json!(["bad"]);
    let loaded = census_load(
        &scratch,
        "shadow-state-wrong-type",
        &serde_json::to_string(&value).expect("json"),
    );
    assert_eq!(
        loaded
            .claude_request_census_shadow_for_test()
            .would_open_for_test(),
        None
    );

    // An old decoder ignores fields it does not know: a later field never
    // quarantines this one either.
    let mut future = census_index_json(serde_json::json!({}));
    future["claude_request_census_v2"] = serde_json::json!({"x": {"y": 1}});
    census_load(
        &scratch,
        "future-field",
        &serde_json::to_string(&future).expect("json"),
    );
}

/// TD1c (bounds): the decoder keeps the running hash total within the budget,
/// refusing an over-budget entry before decoding its hex.
#[test]
fn census_decoder_keeps_the_hash_budget() {
    let scratch = crate::test_scratch::ScratchDir::new("census-decoder-budget");
    let full = (0..MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64).collect::<Vec<_>>();
    let records = serde_json::json!({
        "a-full": census_record_json('a', "lossy", &full),
        "b-one-more": census_record_json('b', "exact", &[1]),
        "c-empty": census_record_json('c', "empty", &[]),
    });
    let loaded = census_load(
        &scratch,
        "budget",
        &serde_json::to_string(&census_index_json(records)).expect("json"),
    );
    let census = loaded.claude_request_census_for_test();
    assert_eq!(
        census.keys_for_test(),
        vec!["a-full".to_string(), "c-empty".to_string()]
    );
    assert_eq!(
        census.hash_total_for_test(),
        MAX_CLAUDE_REQUEST_CENSUS_HASHES
    );
}

/// Production keeps the same budget by storing an `OverBudget` tombstone.
#[test]
fn census_records_past_the_budget_become_inert_tombstones() {
    let mut census = crate::snapshots::claude_request_census::ClaudeRequestCensus::default();
    census.insert_for_test(
        "a",
        ClaudeRequestCensusRecord::synthetic_for_test(
            &hex_fingerprint('a'),
            1,
            ClaudeRequestCensusShape::Lossy,
            (0..MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64).collect(),
        ),
    );
    census.insert_for_test(
        "b",
        ClaudeRequestCensusRecord::synthetic_for_test(
            &hex_fingerprint('b'),
            1,
            ClaudeRequestCensusShape::Exact,
            vec![1],
        ),
    );
    let tombstone = census.get("b").expect("tombstone");
    assert_eq!(
        tombstone.shape_for_test(),
        ClaudeRequestCensusShape::OverBudget
    );
    assert!(tombstone.request_hashes_for_test().is_empty());
    assert_eq!(
        census.hash_total_for_test(),
        MAX_CLAUDE_REQUEST_CENSUS_HASHES
    );
    census.remove("a");
    assert_eq!(census.hash_total_for_test(), 0);
}

/// Layout: census fields are charged through `fields!` without adding per-entry
/// data. Keep the exact current entry-size pin used by restore pricing.
#[test]
fn census_records_are_charged_with_the_scan_index_and_leave_entries_alone() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // CI layout: the hash-only Codex counting-owner Option<String> adds 24
    // inline bytes to the previous 440-byte entry. Census and Claude money
    // births add none: births live in the ScanIndex side table. The stored
    // opened-object ctime and file birth (`opened_changed_nanos`,
    // `opened_birth_nanos`, u64 each) add 16 bytes: Ron's content-only
    // re-read rule rebuilds the scan fingerprint from the ctime so a
    // ctime-only change never re-reads, and only for the same object
    // generation, bound by its exact birth (owner-approved 464 -> 472 -> 480).
    // #876's RAM fragment pointer adds 8; immutable counting-owner Box<str>
    // recovers 8 from Option<String>, preserving the pre-receipt layout contract.
    // Main's optional context receipt adds 80 inline bytes; its three H digests
    // are heap-charged. Keep main's exact combined layout pin.
    const SCAN_INDEX_ENTRY_BYTES: usize = 560;
    assert_eq!(
        std::mem::size_of::<ScanIndexEntry>(),
        SCAN_INDEX_ENTRY_BYTES
    );
    let mut index = ScanIndex::default();
    let before = crate::heap_layout_bound::completed_bound(&index, usize::MAX).expect("bound");
    index.claude_request_census_mut_for_test().insert_for_test(
        "/census/projects/census-a.jsonl",
        ClaudeRequestCensusRecord::synthetic_for_test(
            &hex_fingerprint('a'),
            1,
            ClaudeRequestCensusShape::Lossy,
            (0..1_000).collect(),
        ),
    );
    let after = crate::heap_layout_bound::completed_bound(&index, usize::MAX).expect("bound");
    assert!(after >= before + 8_000, "{before} -> {after}");
}

/// The shadow counters ride the duplicate-census counters, bounded.
#[test]
fn census_shadow_counts_encoding_is_bounded() {
    let shadow = ClaudeRequestCensusShadowCounts {
        would_open: false,
        would_open_flips: u64::MAX,
        family_keys: usize::MAX,
        covered_by_fingerprint: usize::MAX,
        covered_by_window: usize::MAX,
        missing_residue: usize::MAX,
        missing_account_hold: usize::MAX,
        missing_placeholder: usize::MAX,
        missing_empty_fingerprint: usize::MAX,
        missing_fingerprint_mismatch: usize::MAX,
        missing_migrate: usize::MAX,
        missing_over_budget: usize::MAX,
        quarantine_without_record: usize::MAX,
        shape_exact: usize::MAX,
        shape_empty: usize::MAX,
        shape_identity_incomplete: usize::MAX,
        shape_lossy: usize::MAX,
        unverified: usize::MAX,
        twin: usize::MAX,
        family_unknown_roots: usize::MAX,
        records: usize::MAX,
        hashes: usize::MAX,
        hash_budget_usage_percent: usize::MAX,
        hash_budget_warning: false,
        transient_limited: false,
        transient_peak_bytes: usize::MAX,
        duplicate_hashes: usize::MAX,
        duplicate_owner_entries: usize::MAX,
        shared_keys: usize::MAX,
        derivation_drift: u64::MAX,
        json_bytes: usize::MAX,
        heap_bytes: usize::MAX,
    };
    let encoded = serde_json::to_string(&shadow).expect("encode shadow");
    assert!(
        encoded.len() <= CENSUS_SHADOW_MAX_BYTES,
        "{} bytes",
        encoded.len()
    );
    assert_eq!(
        encoded.len(),
        CENSUS_SHADOW_MAX_BYTES,
        "longest scalar spellings"
    );
    let without = ClaudeDuplicateCensusCounts::default();
    let with = ClaudeDuplicateCensusCounts {
        request_census: Some(shadow),
        ..without
    };
    let grown = serde_json::to_string(&with).expect("encode counts").len()
        - serde_json::to_string(&without)
            .expect("encode counts")
            .len();
    assert!(
        grown <= CENSUS_SHADOW_MAX_BYTES + r#","request_census":"#.len(),
        "{grown} bytes"
    );
    // Absent (every non-terminal page and every other source), nothing is
    // added to the existing line.
    assert!(!serde_json::to_string(&without)
        .expect("encode counts")
        .contains("request_census"));
}

const CENSUS_SHADOW_MAX_BYTES: usize = 1_238;

/// Literal tokens matter: Value cannot represent the overflow that regressed
/// load and the compare-and-swap reader. Compare every other persisted field.
#[test]
fn census_numeric_overflow_is_isolated_from_load_and_cas() {
    let scratch = crate::test_scratch::ScratchDir::new("census-overflow");
    let mut base = census_index_json(serde_json::json!({}));
    base["generation"] = serde_json::json!(7);
    let mut expected = base.clone();
    // Every loaded index carries the tombstone marker (SOURCE Round 13 F1).
    expected["claude_retired_family_tombstones_initialized"] = serde_json::json!(true);
    for (name, field, raw) in [
        ("field", "claude_request_census", "1e400".to_owned()),
        (
            "record",
            "claude_request_census",
            format!(
                r#"{{"bad":{{"v":1,"fp":"{}","s":"empty","w":1e400}},"good":{}}}"#,
                hex_fingerprint('a'),
                census_record_json('a', "exact", &[1])
            ),
        ),
        (
            "shadow-field",
            "claude_request_census_shadow",
            "1e400".to_owned(),
        ),
        (
            "shadow-record",
            "claude_request_census_shadow",
            r#"{"o":true,"f":1e400}"#.to_owned(),
        ),
    ] {
        let marker = "overflow-token";
        let mut value = base.clone();
        value[field] = serde_json::json!(marker);
        let json = serde_json::to_string(&value)
            .unwrap()
            .replace(&format!("\"{marker}\""), &raw);
        let mut loaded = census_load(&scratch, name, &json);
        let mut actual = serde_json::to_value(&loaded).unwrap();
        let mut expected = expected.clone();
        for key in ["claude_request_census", "claude_request_census_shadow"] {
            actual.as_object_mut().unwrap().remove(key);
            expected.as_object_mut().unwrap().remove(key);
        }
        assert_eq!(actual, expected, "all other fields: {name}");
        if name == "record" {
            assert_eq!(
                loaded.claude_request_census_for_test().keys_for_test(),
                vec!["good"]
            );
        }
        let bounded_path = scratch.join(format!("{name}-bounded.json"));
        std::fs::write(&bounded_path, &json).unwrap();
        loaded
            .clone()
            .save_with_read_limit(&bounded_path, 128 * 1024)
            .expect("bounded CAS also isolates malformed evidence");
        loaded
            .save(&scratch.join(format!("{name}.json")))
            .expect("CAS accepts the same malformed shadow");
        assert_eq!(loaded.generation, 8);
    }
}

#[test]
fn census_oversized_hostile_field_is_drained_before_serde_buffers_it() {
    use std::io::Write;
    let scratch = crate::test_scratch::ScratchDir::new("census-hostile");
    let path = scratch.join("oversized.json");
    let base = census_index_json(serde_json::json!({}));
    let mut file = std::fs::File::create(&path).unwrap();
    let json = serde_json::to_string(&base).unwrap();
    // Write a hostile scalar without constructing it in the test process.
    let marker = "\"claude_request_census\":{}";
    let (before, after) = json.split_once(marker).expect("census field");
    write!(file, "{before}\"claude_request_census\":\"").unwrap();
    let block = [b'x'; 8192];
    for _ in 0..=MAX_RAW_BYTES / block.len() {
        file.write_all(&block).unwrap();
    }
    write!(file, "\"{after}").unwrap();
    drop(file);
    let mut loaded = ScanIndex::load(&path).expect("oversized evidence is optional");
    assert_eq!(loaded.files.len(), 1);
    assert!(loaded.claude_request_census_for_test().is_empty());
    loaded
        .save(&path)
        .expect("CAS also drains oversized evidence");
}

/// A pre-D1 shape has no census fields: IgnoredAny consumes their tokens,
/// including non-finite numbers, without trying to interpret them.
#[test]
fn census_old_shape_decoder_ignores_new_evidence() {
    #[derive(serde::Deserialize)]
    struct OldIndex {
        schema_version: u16,
        generation: u64,
        files: BTreeMap<String, ScanIndexEntry>,
    }
    let json = serde_json::to_string(&census_index_json(serde_json::json!({})))
        .unwrap()
        .replace(
            "\"claude_request_census\":{}",
            "\"claude_request_census\":1e400",
        );
    let old: OldIndex =
        serde_json::from_str(&json).expect("old shape skips the entire unknown field");
    assert_eq!(old.schema_version, SCAN_INDEX_SCHEMA_VERSION);
    assert_eq!(old.generation, 0);
    assert_eq!(old.files.len(), 1);
}

/// [money] A failed owned read invalidates the old census record; ordinary
/// in-progress continuations retain it. Other failure kinds use this same guard.
#[test]
#[cfg(unix)]
fn census_failed_read_invalidates_old_record() {
    use crate::transcript_acquisition::Scope;
    let scratch = crate::test_scratch::ScratchDir::new("census-abandoned");
    let root = scratch.join("projects");
    let session = "b2222222-2222-4222-8222-222222222222";
    let name = format!("{session}.jsonl");
    census_write(
        &root,
        &name,
        &[census_response(session, Some("old"), "old", 1, 10)],
    );
    let mut index = ScanIndex::default();
    census_scan(&root, &mut index, FIRST_WINDOW);
    let key = census_key(&index, &root, &name);
    let old = index
        .claude_request_census_for_test()
        .get(&key)
        .unwrap()
        .clone();
    census_write(
        &root,
        &name,
        &[
            census_response(session, Some("old"), "old", 1, 10),
            census_response(session, Some("new"), "new", 2, 10),
        ],
    );
    let mut state = OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        index,
        SECOND_WINDOW,
        365,
        100,
        true,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(
        std::sync::Arc::new(sampled_scan::SharedCache::default()),
        Scope("census-test".to_owned()),
    );
    // Stop at the actual selection/read boundary, without test hooks.
    for _ in 0..100 {
        if state.active_file.is_some() {
            break;
        }
        state = match state.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            OwnedSourceScanStep::Complete { .. } => panic!("parse must be selected"),
        };
    }
    assert_eq!(
        state.index.claude_request_census_for_test().get(&key),
        Some(&old)
    );
    let active = state.active_file.as_mut().expect("selected parser");
    assert!(active.sampling.is_some(), "exercise sampled revalidation");
    active.parser.reader.reader = OpenedInput::plain(File::open(&root).unwrap());
    for _ in 0..100 {
        state = match state.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            OwnedSourceScanStep::Complete { .. } => panic!("expected an abandoned parse"),
        };
        if state.census.unreadable_path_count != 0 {
            assert!(state.active_file.is_none(), "failure abandons the parser");
            assert!(
                state
                    .index
                    .claude_request_census_for_test()
                    .get(&key)
                    .is_none(),
                "an abandoned parse must invalidate its previous record"
            );
            return;
        }
        assert_eq!(
            state.index.claude_request_census_for_test().get(&key),
            Some(&old),
            "ordinary in-progress continuations keep their evidence"
        );
    }
    panic!("failure path was not reached");
}

#[test]
fn census_shadow_bounds_workspace_without_changing_the_index() {
    let mut index = ScanIndex::default();
    let key = format!("/census/projects/{}.jsonl", "x".repeat(5000));
    index.files.insert(key, manifest_index_entry(Some("body")));
    let before = serde_json::to_value(&index).unwrap();
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    assert!(counts.transient_limited);
    assert!(!counts.would_open);
    let mut after = serde_json::to_value(&index).unwrap();
    after
        .as_object_mut()
        .unwrap()
        .remove("claude_request_census_shadow");
    assert_eq!(after, before);
}

#[test]
fn census_decoder_stops_after_attempted_entries_even_when_all_are_rejected() {
    let scratch = crate::test_scratch::ScratchDir::new("census-attempt-budget");
    let mut records = String::from("{");
    for attempted in 0..65_536 {
        use std::fmt::Write;
        write!(records, "\"bad-{attempted}\":0,").unwrap();
    }
    use std::fmt::Write;
    write!(
        records,
        "\"after-budget\":{}}}",
        census_record_json('a', "exact", &[1])
    )
    .unwrap();
    let json = serde_json::to_string(&census_index_json(serde_json::json!({})))
        .unwrap()
        .replace(
            "\"claude_request_census\":{}",
            &format!("\"claude_request_census\":{records}"),
        );
    let loaded = census_load(&scratch, "attempts", &json);
    assert!(
        loaded.claude_request_census_for_test().is_empty(),
        "rejected records must consume interpretation work too"
    );
}

#[test]
fn census_decoder_stops_after_an_oversized_record() {
    use std::io::Write;
    let scratch = crate::test_scratch::ScratchDir::new("census-entry-budget");
    let path = scratch.join("record.json");
    let base = serde_json::to_string(&census_index_json(serde_json::json!({}))).unwrap();
    let (before, after) = base.split_once("\"claude_request_census\":{}").unwrap();
    let mut file = File::create(&path).unwrap();
    write!(
        file,
        "{before}\"claude_request_census\":{{\"hostile\":{{\"h\":\""
    )
    .unwrap();
    let block = [b'x'; 8192];
    for _ in 0..=MAX_RECORD_BYTES / block.len() {
        file.write_all(&block).unwrap();
    }
    write!(
        file,
        "\"}},\"after-budget\":{}}}{after}",
        census_record_json('a', "exact", &[1])
    )
    .unwrap();
    drop(file);
    let loaded = ScanIndex::load(&path).expect("entry is bounded optional evidence");
    assert_eq!(loaded.files.len(), 1);
    assert!(loaded.claude_request_census_for_test().is_empty());
}

#[test]
fn census_sequence_index_preserves_serde_compatibility_and_isolates_evidence() {
    let scratch = crate::test_scratch::ScratchDir::new("census-sequence");
    let base = census_index_json(serde_json::json!({}));
    // Pre-census ScanIndex fields, in the positional form accepted by Serde.
    // Keep a real positive record so a field-order change cannot silently
    // make the bound apply to a different slot.
    let mut fields = vec![
        serde_json::json!(SCAN_INDEX_SCHEMA_VERSION),
        serde_json::json!(0),
        serde_json::Value::Null,
        base["files"].clone(),
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::json!(false),
        serde_json::json!([]),
        serde_json::json!({}),
        // U1a-2a (#660): the side/proof fields after the parent ledgers
        // (`serde(skip)` RAM fields take no slot).
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!(0),
        serde_json::json!(0),
        serde_json::json!({}),
        serde_json::Value::Null,
        serde_json::Value::Null,
        serde_json::json!(0),
        serde_json::json!(""),
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
        serde_json::json!({}),
    ];
    fields.push(serde_json::json!({"good": census_record_json('a', "exact", &[1])}));
    fields.push(serde_json::json!("overflow-token"));
    let json = serde_json::to_string(&fields)
        .unwrap()
        .replace("\"overflow-token\"", "1e400");
    let control: ScanIndex = serde_json::from_str(&json).expect("Serde positional control");
    assert_eq!(
        control.claude_request_census_for_test().keys_for_test(),
        vec!["good"]
    );
    let mut loaded = census_load(&scratch, "sequence", &json);
    assert_eq!(
        loaded.claude_request_census_for_test(),
        control.claude_request_census_for_test()
    );
    loaded
        .save(&scratch.join("sequence.json"))
        .expect("positional CAS remains supported");
}

#[test]
fn census_escaped_shadow_field_name_cannot_bypass_the_reader_bound() {
    use std::io::Write;
    let scratch = crate::test_scratch::ScratchDir::new("census-escaped-bound");
    let path = scratch.join("escaped.json");
    let base = serde_json::to_string(&census_index_json(serde_json::json!({}))).unwrap();
    let escaped = "claude_request_census_shadow"
        .chars()
        .map(|ch| format!("\\u{:04x}", ch as u32))
        .collect::<String>();
    assert!(escaped.len() > 128, "exercise the longest field spelling");
    let mut file = File::create(&path).unwrap();
    write!(file, "{},\"{escaped}\":\"", base.strip_suffix('}').unwrap()).unwrap();
    let block = [b'x'; 8192];
    for _ in 0..=MAX_RAW_BYTES / block.len() {
        file.write_all(&block).unwrap();
    }
    write!(file, "\"}}").unwrap();
    drop(file);
    let mut loaded = ScanIndex::load(&path).expect("escaped field has the same bounded reader");
    assert_eq!(loaded.files.len(), 1);
    assert_eq!(
        loaded
            .claude_request_census_shadow_for_test()
            .would_open_for_test(),
        None
    );
    loaded
        .save(&path)
        .expect("CAS also bounds escaped field names");
}

/// The valid shadow state must survive load, CAS and reload byte-for-value,
/// independently of whether its previous predicate was open or closed.
#[test]
fn census_valid_shadow_state_round_trips_exactly() {
    let scratch = crate::test_scratch::ScratchDir::new("census-shadow-roundtrip");
    for open in [false, true] {
        for escaped in [false, true] {
            let expected = serde_json::json!({"o": open, "f": u64::MAX, "d": u64::MAX});
            let mut value = census_index_json(serde_json::json!({
                "good": census_record_json('a', "exact", &[1, 2])
            }));
            value["claude_request_census_shadow"] = expected.clone();
            let mut json = serde_json::to_string(&value).unwrap();
            if escaped {
                let field = "claude_request_census_shadow"
                    .chars()
                    .map(|ch| format!("\\u{:04x}", ch as u32))
                    .collect::<String>();
                json = json.replace("claude_request_census_shadow", &field);
            }
            let name = format!("shadow-{open}-{escaped}");
            let mut loaded = census_load(&scratch, &name, &json);
            assert_eq!(
                serde_json::to_value(&loaded).unwrap()["claude_request_census_shadow"],
                expected
            );
            assert_eq!(
                loaded
                    .claude_request_census_for_test()
                    .hash_total_for_test(),
                2
            );
            let path = scratch.join(format!("{name}.json"));
            loaded.save(&path).expect("CAS preserves shadow state");
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(
                serde_json::to_value(&reloaded).unwrap()["claude_request_census_shadow"],
                expected
            );
        }
    }
}

#[test]
fn census_duplicate_optional_fields_invalidate_only_the_ambiguous_evidence() {
    let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-root");
    for field in ["claude_request_census", "claude_request_census_shadow"] {
        let mut value = census_index_json(serde_json::json!({
            "good": census_record_json('a', "exact", &[1])
        }));
        value["claude_request_census_shadow"] = serde_json::json!({"o": true, "f": 3, "d": 4});
        let base = serde_json::to_string(&value).unwrap();
        let json = format!("{},\"{field}\":1e400}}", base.strip_suffix('}').unwrap());
        let mut loaded = census_load(&scratch, field, &json);
        if field == "claude_request_census" {
            assert!(loaded.claude_request_census_for_test().is_empty());
            assert_eq!(
                loaded
                    .claude_request_census_shadow_for_test()
                    .would_open_for_test(),
                Some(true)
            );
        } else {
            assert_eq!(
                loaded.claude_request_census_for_test().keys_for_test(),
                vec!["good"]
            );
            assert_eq!(
                loaded
                    .claude_request_census_shadow_for_test()
                    .would_open_for_test(),
                None
            );
        }
        loaded
            .save(&scratch.join(format!("{field}.json")))
            .expect("CAS isolates optional duplicates");
    }
    // Required duplicate fields are ambiguous. Refuse without replacing the
    // original witness; optional census duplicates above still invalidate only
    // their evidence.
    let base = serde_json::to_string(&census_index_json(serde_json::json!({}))).unwrap();
    let path = scratch.join("duplicate-files.json");
    std::fs::write(
        &path,
        format!("{},\"files\":{{}}}}", base.strip_suffix('}').unwrap()),
    )
    .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        ScanIndex::load(&path).is_err(),
        "ambiguous files field refuses"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "refusal preserves the original index"
    );
    assert!(
        !std::fs::read_dir(&scratch)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
        "refusal never quarantines"
    );
}

/// C3: a Held original keeps its census (and the copy's proof) while its
/// committed entry is unchanged, even when the file itself grew; a changed
/// committed entry, another physical object or an unknown birth invalidates.
#[cfg(unix)]
#[test]
fn held_original_keeps_dependent_copy_proof_only_while_committed_entry_unchanged() {
    use std::os::unix::fs::MetadataExt;
    let scratch = crate::test_scratch::ScratchDir::new("held-census-copy");
    let root = scratch.join("projects");
    for name in ["held-original", "dependent-copy"] {
        census_write(
            &root,
            &format!("{name}.jsonl"),
            &[census_response(
                name,
                Some("req_held_shared"),
                "msg_held_shared",
                1,
                100,
            )],
        );
    }
    let mut index = ScanIndex::default();
    let scan = census_scan(&root, &mut index, FIRST_WINDOW);
    let original = census_key(&index, &root, "held-original.jsonl");
    let copy = census_key(&index, &root, "dependent-copy.jsonl");
    let path = PathBuf::from(&original);
    let metadata = std::fs::metadata(&path).unwrap();
    let record = index
        .claude_request_census
        .get(&original)
        .unwrap()
        .clone()
        .with_birth_for_test(Some(claude_request_census::ClaudeRequestBirth {
            unix_seconds: 1,
            device: metadata.dev(),
            inode: metadata.ino(),
        }));
    index
        .claude_request_census
        .insert(original.clone(), record.clone());
    let mut candidate = candidate_from_traversal_path(
        SnapshotSource::ClaudeCode,
        ScanTraversalPath {
            scan_root: root.clone(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut ScanCensus::default(),
        None,
        365,
        &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
    )
    .unwrap();
    candidate.physical_identity = Some([metadata.dev(), metadata.ino()]);
    candidate.source_file_fingerprint = record.fingerprint_hex_for_test();
    assert_eq!(
        index.files[&original].source_file_fingerprint,
        record.fingerprint_hex_for_test(),
        "the committed entry is the recorded version"
    );
    for grown in [
        "unchanged",
        "file_fingerprint",
        "file_mtime",
        "entry_cleared",
    ] {
        let mut kept = index.clone();
        let mut file = candidate.clone();
        match grown {
            "file_fingerprint" => file.source_file_fingerprint = "a".repeat(64),
            "file_mtime" => file.modified_unix_seconds += 1,
            "entry_cleared" => kept
                .files
                .get_mut(&original)
                .unwrap()
                .source_file_fingerprint
                .clear(),
            _ => {}
        }
        assert!(
            claude_request_census::retain_held(&mut kept, &file),
            "{grown}"
        );
        assert_eq!(kept.claude_request_census.get(&original), Some(&record));
        assert_eq!(
            claude_census_member_status(&kept, &copy, &scan.census_window_end, true),
            ClaudeCensusMemberStatus::SharesHash,
            "{grown}"
        );
    }
    for change in [
        "entry_fingerprint",
        "entry_modified",
        "replaced_inode",
        "unknown_birth",
    ] {
        let mut control = index.clone();
        let mut changed = candidate.clone();
        let entry = control.files.get_mut(&original).unwrap();
        match change {
            "entry_fingerprint" => entry.source_file_fingerprint = "a".repeat(64),
            "entry_modified" => entry.modified_unix_seconds += 1,
            "replaced_inode" => {
                changed.physical_identity = Some([metadata.dev(), metadata.ino().wrapping_add(1)])
            }
            _ => {
                control
                    .claude_request_census
                    .insert(original.clone(), record.clone().with_birth_for_test(None));
            }
        }
        assert!(
            !claude_request_census::retain_held(&mut control, &changed),
            "{change}"
        );
        assert!(
            control
                .claude_request_census
                .get(&original)
                .map_or(true, |r| r.is_birth_stub_for_test()),
            "{change}"
        );
        assert_ne!(
            claude_census_member_status(&control, &copy, &scan.census_window_end, true),
            ClaudeCensusMemberStatus::SharesHash
        );
    }
}

/// Review F3 / L26 on the production path: a Held durable record for an
/// unchanged original takes the common-hold exit; the dependent copy (which
/// gained a request) is rescanned in the same pass. Its emitted envelopes,
/// witnesses and money equal the cold arm's (original read Full), and the
/// original's census record and last accepted body stay; a cold re-read of
/// the unchanged original emits nothing new either, so emitted money is
/// conserved. C3: the original then GROWS while held (its committed entry is
/// unchanged): the record, the copy's proof and the copy's emitted body stay
/// the same. Committed-entry-changed control: the same hold invalidates the
/// record (birth stub) and the copy loses its proof.
#[cfg(unix)]
#[test]
fn held_original_production_exit_conserves_copy_money_while_committed_entry_unchanged() {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let scratch = crate::test_scratch::ScratchDir::new("held-census-production");
    let root = scratch.join("projects");
    for name in ["held-original", "dependent-copy"] {
        census_write(
            &root,
            &format!("{name}.jsonl"),
            &[census_response(
                name,
                Some("req_held_shared"),
                "msg_held_shared",
                1,
                100,
            )],
        );
    }
    let accept = |index: &mut ScanIndex, scan: &SourceScanResult| {
        let mut projected = scan.clone();
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut projected.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut projected, index);
        let accepted = projected
            .snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&accepted);
        projected.snapshots
    };
    let mut seeded = ScanIndex::default();
    let seed = census_scan(&root, &mut seeded, FIRST_WINDOW);
    accept(&mut seeded, &seed);
    let original = census_key(&seeded, &root, "held-original.jsonl");
    let copy = census_key(&seeded, &root, "dependent-copy.jsonl");
    let record = seeded.claude_request_census.get(&original).unwrap().clone();
    let accepted = |index: &ScanIndex| {
        let entry = &index.files[&original];
        (
            entry.last_snapshot_fingerprint.clone(),
            entry.last_upload_body_witness.clone(),
        )
    };
    let last_accepted = accepted(&seeded);
    assert!(last_accepted.0.is_some());
    census_write(
        &root,
        "dependent-copy.jsonl",
        &[
            census_response(
                "dependent-copy",
                Some("req_held_shared"),
                "msg_held_shared",
                1,
                100,
            ),
            census_response(
                "dependent-copy",
                Some("req_copy_new"),
                "msg_copy_new",
                2,
                50,
            ),
        ],
    );
    let session = |snapshots: &[SnapshotItem], id: &str| {
        snapshots
            .iter()
            .filter(|snapshot| snapshot.source_session_id == id)
            .map(|snapshot| serde_json::to_value(snapshot).unwrap())
            .collect::<Vec<_>>()
    };
    let mut cold = None;
    for arm in ["cold", "held", "held_grown", "entry_changed"] {
        let state = scratch.join(arm);
        let index_path = state.join("index.json");
        let cache = std::sync::Arc::new(sampled_scan::SharedCache::default());
        let namespace = crate::transcript_acquisition::Scope("held-census-production".to_owned());
        cache.durable_begin_pass(SnapshotSource::ClaudeCode, &index_path, &namespace, false);
        // Reparse debt: the unchanged original is Parse; the copy changed.
        let mut index = seeded.clone();
        index
            .files
            .get_mut(&original)
            .unwrap()
            .source_file_fingerprint = String::new();
        if arm != "cold" {
            let dir = crate::durable_tail_store::store_dir_for_index(&index_path);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .unwrap();
            let key = crate::durable_tail_store::key_digest(
                crate::durable_tail_store::DurableSource::ClaudeCode,
                &original,
            );
            let name = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
            std::io::Write::write_all(
                &mut std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(dir.join(format!("{name}.rec")))
                    .unwrap(),
                b"opaque-newer-writer-record",
            )
            .unwrap();
        }
        if arm == "held_grown" {
            // The file grows in place (same object); the server still has
            // the committed version.
            census_write(
                &root,
                "held-original.jsonl",
                &[
                    census_response(
                        "held-original",
                        Some("req_held_shared"),
                        "msg_held_shared",
                        1,
                        100,
                    ),
                    census_response(
                        "held-original",
                        Some("req_original_new"),
                        "msg_original_new",
                        3,
                        70,
                    ),
                ],
            );
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&original)
                .unwrap();
            let modified = file.metadata().unwrap().modified().unwrap();
            file.set_modified(modified + std::time::Duration::from_secs(5))
                .unwrap();
        }
        if arm == "entry_changed" {
            index
                .files
                .get_mut(&original)
                .unwrap()
                .modified_unix_seconds += 5;
        }
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            FIRST_WINDOW,
            365,
            1_000,
            true,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache.clone(), namespace);
        let (mut index, result) = loop {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => break (index, scan),
            }
        };
        let emitted = accept(&mut index, &result);
        let (counts, _) = cache.durable_counters(SnapshotSource::ClaudeCode).unwrap();
        let copy_status =
            claude_census_member_status(&index, &copy, &result.census_window_end, true);
        let copy_entry = |index: &ScanIndex| {
            let entry = &index.files[&copy];
            (
                entry.last_snapshot_fingerprint.clone(),
                entry.last_upload_body_witness.clone(),
            )
        };
        match arm {
            "cold" => {
                assert_eq!(counts.durable_held, [0; 5]);
                assert_eq!(copy_status, ClaudeCensusMemberStatus::SharesHash);
                // Money conservation premise: a cold read of the unchanged
                // original emits nothing new; its accepted body stands.
                assert_eq!(accepted(&index), last_accepted);
                assert!(session(&emitted, "held-original").is_empty());
                assert!(!session(&emitted, "dependent-copy").is_empty());
                cold = Some((session(&emitted, "dependent-copy"), copy_entry(&index)));
            }
            "held" | "held_grown" => {
                assert_eq!(counts.durable_held.iter().sum::<u64>(), 1);
                assert!(session(&emitted, "held-original").is_empty(), "no POST");
                assert_eq!(accepted(&index), last_accepted, "last accepted body kept");
                if record.birth().is_some() {
                    assert_eq!(counts.held_census, [1, 0]);
                    assert_eq!(index.claude_request_census.get(&original), Some(&record));
                    assert_eq!(copy_status, ClaudeCensusMemberStatus::SharesHash);
                    let (copy_body, copy_witness) = cold.clone().unwrap();
                    assert!(!copy_body.is_empty());
                    assert_eq!(session(&emitted, "dependent-copy"), copy_body);
                    assert_eq!(copy_entry(&index), copy_witness);
                } else {
                    // No opened birth on this filesystem: the object cannot be
                    // proven the same, so the existing invalidator runs.
                    assert_eq!(counts.held_census, [0, 1]);
                }
            }
            _ => {
                assert_eq!(counts.durable_held.iter().sum::<u64>(), 1);
                assert_eq!(counts.held_census, [0, 1]);
                assert!(session(&emitted, "held-original").is_empty(), "no POST");
                assert_eq!(accepted(&index), last_accepted, "last accepted body kept");
                assert!(index
                    .claude_request_census
                    .get(&original)
                    .map_or(true, |r| r.is_birth_stub_for_test()));
                assert_ne!(copy_status, ClaudeCensusMemberStatus::SharesHash);
            }
        }
    }
    #[cfg(target_os = "macos")]
    assert!(
        record.birth().is_some(),
        "macOS records carry an opened birth"
    );
}
