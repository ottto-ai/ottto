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

/// TD1a: every finished Claude parse writes a record bound to the candidate
/// fingerprint and the census window, shaped by Context rows G-J and loss.
#[test]
fn census_records_bind_each_parse_to_its_revision_and_shape() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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

/// SOURCE early condition: the canary provably goes red when extraction
/// changes without a bump. Each mutation is what the parser would yield after
/// the named extraction change on the same fixture.
#[test]
fn census_derivation_canary_fails_on_a_missed_bump() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
    let scratch = crate::test_scratch::ScratchDir::new("census-derivation-canary-red");
    let root = scratch.join("projects");
    write_census_corpus(&root);
    let mut index = ScanIndex::default();
    census_scan(&root, &mut index, FIRST_WINDOW);
    let observed = observed_census_table(&index, &root);
    assert_eq!(
        canary_verdict(CLAUDE_REQUEST_CENSUS_DERIVATION, &observed),
        Ok(())
    );
    let mutate = |name: &str, change: &dyn Fn(&mut CanaryRow)| {
        let mut table = observed.clone();
        change(table.get_mut(name).expect("canary fixture"));
        table
    };
    let changes = [
        // Zero-usage (API error) ids no longer collected.
        mutate("canary-zero-usage.jsonl", &|entry| {
            entry
                .1
                .retain(|hash| *hash != claude_request_hash("req_zero_err"))
        }),
        // An id-less response starts reporting its message id.
        mutate("canary-id-less.jsonl", &|entry| {
            entry.1.push(claude_request_hash("msg_idless_2"));
            entry.1.sort_unstable();
        }),
        // A repeated id no longer marks the identity incomplete.
        mutate("canary-repeated.jsonl", &|entry| {
            entry.0 = "exact".to_string()
        }),
        // A provider-marked fork prefix is no longer excluded.
        mutate("canary-forked.jsonl", &|entry| {
            entry.1.push(claude_request_hash("req_fork_parent"));
            entry.1.sort_unstable();
        }),
        // A dropped response becomes loss-free.
        mutate("canary-invalid-fork.jsonl", &|entry| {
            entry.0 = "exact".to_string()
        }),
    ];
    for changed in &changes {
        assert_ne!(changed, &observed);
        let verdict = canary_verdict(CLAUDE_REQUEST_CENSUS_DERIVATION, changed);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|reason| reason.contains("bump CLAUDE_REQUEST_CENSUS_DERIVATION")),
            "{verdict:?}"
        );
    }
    // A bump without a re-pinned digest is red too.
    assert!(canary_verdict(CLAUDE_REQUEST_CENSUS_DERIVATION + 1, &observed).is_err());
}

/// TD1f (review F1, SOURCE S2(c)): a re-parse of a previously complete key
/// that ends as residue, with copied ids, replaces the old record. The key is
/// never covered by the old revision, and the copied ids join the census.
#[test]
fn census_residue_reparse_never_keeps_the_old_record() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
                    if key == &walked {
                        rfc3339_unix_seconds(FIRST_WINDOW).unwrap()
                    } else {
                        1
                    },
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
}

/// The shadow predicate and per-member status on a synthetic index: coverage
/// by fingerprint or by this window, shared hashes, census-unknown families,
/// unverified records, and a missing record that keeps the predicate false.
#[test]
fn census_member_status_names_disjoint_shared_unknown_and_unobserved() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    // An already-retired record from before this capability stays retired
    // while its next ordinary parse rebuilds safety; no new work is scheduled.
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, retired.clone().without_safety_for_test());
    assert!(!claude_census_disjointness_complete(
        &index,
        "2027-03-01T09:00:00Z",
        true
    ));
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
                rfc3339_unix_seconds(FIRST_WINDOW).unwrap(),
                shape,
                vec![hash],
            )
            .with_acquired_eof_for_test(true),
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
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

/// TD1c (bounds): the decoder keeps the running hash total within the budget,
/// refusing an over-budget entry before decoding its hex.
#[test]
fn census_decoder_keeps_the_hash_budget() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

/// Production keeps the same budget by storing an `OverBudget` tombstone.
#[test]
fn census_records_past_the_budget_become_inert_tombstones() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

/// Layout: both new `ScanIndex` fields are charged through `fields!`, and the
/// per-entry layout `#588` restore pricing reads is unchanged by D1.
#[test]
fn census_records_are_charged_with_the_scan_index_and_leave_entries_alone() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Measured on the tests-first head (CI layout), before D1 changed anything.
    const SCAN_INDEX_ENTRY_BYTES_BEFORE_D1: usize = 440;
    assert_eq!(
        std::mem::size_of::<ScanIndexEntry>(),
        SCAN_INDEX_ENTRY_BYTES_BEFORE_D1
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
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
    let shadow = ClaudeRequestCensusShadowCounts {
        safety_metadata_reclaimed_active: u64::MAX,
        unread_due_to_growth: usize::MAX,
        dirty_unparsed_keys_known: false,
        shadow_decision_taps_known: false,
        safety_compact_decode_recovered: usize::MAX,

        shadow_peak_measured: false,
        shadow_workspace_peak_measured: false,
        safety_resource_refused_keys: usize::MAX,
        confirmed_empty_keys: usize::MAX,
        missing_confirmed_empty_records: usize::MAX,
        strong_comparison_complete: false,
        safety_incomplete: false,
        safety_incomplete_overflow: false,
        safety_incomplete_overflow_cause: Some(
            crate::snapshots::claude_request_census::SafetyIncompleteOverflowCause::MalformedMarker,
        ),
        unread_alarm_emitted_keys: usize::MAX,
        safety_incomplete_alarm: false,
        d2_hash_budget_alarm: false,
        legacy_compare_ready: false,
        legacy_compare_generation_mismatch: false,
        legacy_compare_budget_refused: false,
        shadow_post_save_equality_checked: false,
        shadow_post_save_qualified: false,
        shadow_projected_dependent_known: false,
        shadow_refusal_rate_known: false,
        migration_estimate_known: false,
        d2_active: false,
        debt_scheduler_active: false,
        safety_reclaimed: u64::MAX,
        safety_incomplete_since: u64::MAX,
        unread_oldest_age_seconds: u64::MAX,
        unread_last_progress_age_seconds: u64::MAX,
        unread_max_complete_terminals: u64::MAX,
        shadow_elapsed_us: u64::MAX,
        shadow_work_units: u64::MAX,
        shadow_healthy_terminals_attempted: u64::MAX,
        shadow_healthy_terminals_memory_refused: u64::MAX,
        shadow_healthy_terminal_refusal_rate_ppm: u64::MAX,
        census_read_bytes: u64::MAX,
        census_evidence_bytes: u64::MAX,
        shadow_spec_version: usize::MAX,
        safety_reclaimed_keys: usize::MAX,
        shape_lossy_unread: usize::MAX,
        shape_lossy_dropped: usize::MAX,
        shape_multi_item: usize::MAX,
        shape_lossy_classification_unknown: usize::MAX,
        shape_all_read_residue: usize::MAX,
        unread_age_alarm_keys: usize::MAX,
        unread_terminal_alarm_keys: usize::MAX,
        unread_liveness_unknown_keys: usize::MAX,
        retired_records: usize::MAX,
        active_hash_total: usize::MAX,
        retired_hash_total: usize::MAX,
        retired_safety_missing: usize::MAX,
        alias_migrate_keys: usize::MAX,
        content_owner_pairs: usize::MAX,
        content_owner_overflow_keys: usize::MAX,
        shares_hash_with_retired_owner_keys: usize::MAX,
        strong_admissions_via_excusal: usize::MAX,
        dirty_unparsed_keys: usize::MAX,
        decode_ambiguous_keys: usize::MAX,
        decode_duplicate_keys_dropped: u64::MAX,
        census_duplicate_rebuild_exhausted: u64::MAX,
        census_duplicate_rebuild_orphaned: u64::MAX,
        census_rebuild_priors_decode_refused: u64::MAX,
        census_duplicate_rebuild_identity_revoked: u64::MAX,
        producer_refused_keys: usize::MAX,
        shadow_post_save_mismatch_keys: usize::MAX,
        legacy_compare_families: usize::MAX,
        legacy_compare_keys: usize::MAX,
        legacy_uncomparable_families: usize::MAX,
        legacy_dup_not_d2_shared: usize::MAX,
        legacy_dup_not_d2_shared_families: usize::MAX,
        d2_shared_not_legacy: usize::MAX,
        d2_shared_not_legacy_families: usize::MAX,
        shadow_diff_old_families: usize::MAX,
        shadow_diff_inert_families: usize::MAX,
        shadow_diff_retired_families: usize::MAX,
        shadow_diff_alias_families: usize::MAX,
        shadow_diff_unclassified_families: usize::MAX,
        d2_settled_pending_invalid_families: usize::MAX,
        d2_settled_pending_cap_families: usize::MAX,
        d2_settled_pending_identity_families: usize::MAX,
        d2_settled_pending_member_changed_families: usize::MAX,
        d2_settled_pending_occurrence_mismatch_families: usize::MAX,
        d2_settled_pending_other_families: usize::MAX,
        shadow_unexplained_positive_admissions: usize::MAX,
        shadow_protected_contract_violations: usize::MAX,
        shadow_d2_protected_offers: usize::MAX,
        shadow_cutover_history_offers: usize::MAX,
        shadow_cutover_newfile_offers: usize::MAX,
        shadow_projected_dependent_keys: usize::MAX,
        shadow_projected_dependent_bytes: usize::MAX,
        shadow_projected_dependent_protected: usize::MAX,
        shadow_join_builds: usize::MAX,
        shadow_keys_visited: usize::MAX,
        shadow_hashes_visited: usize::MAX,
        shadow_work_limited: usize::MAX,
        shadow_compare_heap_bytes: usize::MAX,
        shadow_peak_heap_bytes: usize::MAX,
        shadow_workspace_peak_bytes: usize::MAX,
        migration_keys_estimated: usize::MAX,
        migration_input_bytes_estimated: usize::MAX,
        would_open: false,
        would_open_flips: u64::MAX,
        unindexed_required_keys: usize::MAX,
        missing_unindexed_records: usize::MAX,
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
        CENSUS_SHADOW_WORST_BYTES,
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

const CENSUS_SHADOW_MAX_BYTES: usize = 8 * 1024;
const CENSUS_SHADOW_WORST_BYTES: usize = 6178;

/// Literal tokens matter: Value cannot represent the overflow that regressed
/// load and the compare-and-swap reader. Compare every other persisted field.
#[test]
fn census_numeric_overflow_is_isolated_from_load_and_cas() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
            // SI-724-B3b: the "N3 initialized" marker is the rebuild guard's,
            // saved beside the shadow state it backs. Only a damaged shadow
            // state, which closes the guard, writes it here.
            if actual
                .as_object_mut()
                .unwrap()
                .remove("claude_census_rebuild_initialized")
                .is_some()
            {
                assert!(name.starts_with("shadow"), "{name}: marker");
                assert!(
                    crate::snapshots::claude_request_census::duplicate_rebuild_test_support::closed(
                        &loaded
                    ),
                    "{name}: the marker backs a closed guard"
                );
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
}

#[test]
fn census_oversized_hostile_field_is_drained_before_serde_buffers_it() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

#[test]
fn census_hash_budget_warning_starts_at_eighty_percent() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
    // 80% of the hash cap, rounded up: the first count that warns.
    let threshold = (MAX_CLAUDE_REQUEST_CENSUS_HASHES * 4).div_ceil(5) as u64;
    for hashes in [threshold - 1, threshold] {
        let mut index = ScanIndex::default();
        index.claude_request_census_mut_for_test().insert_for_test(
            "key",
            ClaudeRequestCensusRecord::synthetic_for_test(
                &hex_fingerprint('a'),
                1,
                ClaudeRequestCensusShape::Lossy,
                (0..hashes).collect(),
            ),
        );
        let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
            &mut index,
            &BTreeSet::from(["key".to_owned()]),
            &BTreeSet::new(),
            FIRST_WINDOW,
        );
        assert_eq!(counts.hash_budget_warning, hashes == threshold);
        assert_eq!(
            counts.hash_budget_usage_percent,
            if hashes == threshold { 80 } else { 79 }
        );
    }
}

/// A pre-D1 shape has no census fields: IgnoredAny consumes their tokens,
/// including non-finite numbers, without trying to interpret them.
#[test]
fn census_old_shape_decoder_ignores_new_evidence() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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

#[cfg(unix)]
#[derive(Clone, Copy)]
enum CensusAbandonedParse {
    Read,
    Attribution,
    Scope,
    Object,
    Reopen,
    Reduction,
}

/// Real owned-reader continuations, with synthetic filesystem/acquisition
/// failures. Every case starts with an older valid record and changed bytes.
#[cfg(unix)]
fn census_assert_abandoned_parse_invalidates_record(failure: CensusAbandonedParse) {
    use crate::transcript_acquisition::{ReadPlan, Scope};
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
    let mut context = None;
    match failure {
        CensusAbandonedParse::Read => {
            active.parser.reader.reader = OpenedInput::plain(File::open(&root).unwrap());
        }
        CensusAbandonedParse::Attribution => {
            let home = scratch.join("home");
            let events = home.join(".ottto/launch-events");
            std::fs::create_dir_all(&events).unwrap();
            // Listing this regular file as the pending directory fails.
            std::fs::write(events.join("pending"), b"unavailable").unwrap();
            context = crate::session_attribution::SessionAttributionContext::from_activity_hint(
                SnapshotSource::ClaudeCode,
                &home,
                true,
                Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
            );
            assert!(context.is_some());
        }
        CensusAbandonedParse::Scope => {
            active.sampling.as_mut().unwrap().scope = Scope("changed-scope".to_owned());
        }
        CensusAbandonedParse::Object => {
            let path = &active.candidate.path;
            let bytes = std::fs::read(path).unwrap();
            std::fs::rename(path, scratch.join("old-object")).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        CensusAbandonedParse::Reopen => {
            std::fs::remove_file(&active.candidate.path).unwrap();
        }
        CensusAbandonedParse::Reduction => {
            // The selected scope is still current, but the acquisition's
            // certificate belongs to another interpretation. EOF commit fails.
            active.parser.reader.acquisition = Some(
                ReadPlan::prepare(
                    active.parser.reader.reader.get_mut(),
                    None,
                    &Scope("wrong-certificate".to_owned()),
                    None,
                    1,
                )
                .unwrap(),
            );
        }
    }
    for _ in 0..100 {
        state = match state.step(context.as_ref()) {
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
#[cfg(unix)]
fn census_failed_read_invalidates_old_record() {
    census_assert_abandoned_parse_invalidates_record(CensusAbandonedParse::Read);
}
#[test]
#[cfg(unix)]
fn census_failed_attribution_invalidates_old_record() {
    census_assert_abandoned_parse_invalidates_record(CensusAbandonedParse::Attribution);
}
#[test]
#[cfg(unix)]
fn census_failed_scope_revalidation_invalidates_old_record() {
    census_assert_abandoned_parse_invalidates_record(CensusAbandonedParse::Scope);
}
#[test]
#[cfg(unix)]
fn census_failed_object_revalidation_invalidates_old_record() {
    census_assert_abandoned_parse_invalidates_record(CensusAbandonedParse::Object);
}
#[test]
#[cfg(unix)]
fn census_failed_reopen_invalidates_old_record() {
    census_assert_abandoned_parse_invalidates_record(CensusAbandonedParse::Reopen);
}
#[test]
#[cfg(unix)]
fn census_failed_reduction_invalidates_old_record() {
    census_assert_abandoned_parse_invalidates_record(CensusAbandonedParse::Reduction);
}

#[test]
fn census_shadow_bounds_workspace_without_changing_the_index() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

#[test]
fn census_decoder_stops_after_an_oversized_record() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

#[test]
fn census_sequence_index_preserves_serde_compatibility_and_isolates_evidence() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

#[test]
fn census_escaped_shadow_field_name_cannot_bypass_the_reader_bound() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

/// The valid shadow state must survive load, CAS and reload byte-for-value,
/// independently of whether its previous predicate was open or closed.
#[test]
fn census_valid_shadow_state_round_trips_exactly() {
    for enabled in [false, true] {
        let _shadow_mode =
            crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
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
}

#[test]
fn census_duplicate_optional_fields_invalidate_only_the_ambiguous_evidence() {
    let _shadow_mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(true);
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

/// MONEY N3: corruption is counted durably and the next ordinary scan rebuilds
/// the affected transcript record, even when source bytes never change.
#[test]
fn census_duplicate_key_counts_and_rearms_only_its_file_until_rebuilt() {
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild");
        let root = scratch.join("projects");
        for name in ["duplicate", "healthy"] {
            census_write(
                &root,
                &format!("{name}.jsonl"),
                &[census_response(
                    name,
                    Some(&format!("req-{name}")),
                    &format!("msg-{name}"),
                    1,
                    10,
                )],
            );
        }
        let mut original = ScanIndex::default();
        census_scan(&root, &mut original, FIRST_WINDOW);
        let key = census_key(&original, &root, "duplicate.jsonl");
        let healthy = census_key(&original, &root, "healthy.jsonl");
        let healthy_fp = original.files[&healthy].source_file_fingerprint.clone();
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let expected = original
            .claude_request_census_for_test()
            .get(&key)
            .unwrap()
            .request_hashes_for_test()
            .to_vec();
        let mut value = serde_json::to_value(&original).unwrap();
        let row = serde_json::to_string(&value["claude_request_census"][&key]).unwrap();
        let healthy_row = serde_json::to_string(&value["claude_request_census"][&healthy]).unwrap();
        let quoted_key = serde_json::to_string(&key).unwrap();
        let quoted_healthy = serde_json::to_string(&healthy).unwrap();
        value["claude_request_census"] = serde_json::json!("DUPLICATE_CENSUS_FIXTURE");
        let duplicate_map =
            format!("{{{quoted_key}:{row},{quoted_key}:{row},{quoted_healthy}:{healthy_row}}}");
        let raw = serde_json::to_string(&value)
            .unwrap()
            .replace("\"DUPLICATE_CENSUS_FIXTURE\"", &duplicate_map);
        for bounded in [false, true] {
            let path = scratch.join(format!("index-{bounded}.json"));
            std::fs::write(&path, &raw).unwrap();
            let mut index = if bounded {
                crate::snapshots::claude_request_census::decode_bounded_index(raw.as_bytes())
                    .unwrap()
            } else {
                ScanIndex::load(&path).unwrap()
            };
            assert!(index.claude_request_census_for_test().get(&key).is_none());
            assert!(
                census_rebuild_rearms(&index, &key, &fingerprint),
                "next pass must parse Rearmed"
            );
            assert_eq!(index.files[&healthy].source_file_fingerprint, healthy_fp);
            assert!(!census_rebuild_rearms(&index, &healthy, &healthy_fp));
            let counts =
                crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                    &mut index,
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    FIRST_WINDOW,
                );
            assert_eq!(counts.decode_duplicate_keys_dropped, 1);
            let line = serde_json::to_value(ClaudeDuplicateCensusCounts {
                request_census: Some(counts),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(line["request_census"]["decode_duplicate_keys_dropped"], 1);
            index
                .save(&path)
                .expect("corruption counter and rearm debt survive CAS");
            let mut restarted = ScanIndex::load(&path).unwrap();
            assert!(census_rebuild_rearms(&restarted, &key, &fingerprint));
            assert_eq!(
                serde_json::to_value(&restarted).unwrap()["claude_request_census_shadow"]["a"],
                1
            );
            census_scan(&root, &mut restarted, SECOND_WINDOW);
            let rebuilt = restarted
                .claude_request_census_for_test()
                .get(&key)
                .expect("next scan rebuilds missing census");
            assert_eq!(rebuilt.request_hashes_for_test(), expected);
            assert!(!restarted.files[&key].source_file_fingerprint.is_empty());
            assert_eq!(
                serde_json::to_value(&restarted).unwrap()["claude_request_census_shadow"]["a"],
                1
            );
        }
    }
}

/// `duplicate.jsonl` and `healthy.jsonl`, scanned once into an index.
fn census_duplicate_rebuild_fixture(scratch: &Path) -> (PathBuf, ScanIndex, String) {
    let root = scratch.join("projects");
    for name in ["duplicate", "healthy"] {
        census_write(
            &root,
            &format!("{name}.jsonl"),
            &[census_response(
                name,
                Some(&format!("req-{name}")),
                &format!("msg-{name}"),
                1,
                10,
            )],
        );
    }
    let mut index = ScanIndex::default();
    census_scan(&root, &mut index, FIRST_WINDOW);
    let key = census_key(&index, &root, "duplicate.jsonl");
    (root, index, key)
}

/// `index` persisted with `key`'s census row written twice and, optionally,
/// a persisted rebuild guard (`"n"`) in the shadow state.
fn census_duplicate_rebuild_raw(
    index: &ScanIndex,
    key: &str,
    guard: Option<serde_json::Value>,
) -> String {
    let mut value = serde_json::to_value(index).unwrap();
    let rows = census_duplicate_rows(&value, key);
    value["claude_request_census"] = serde_json::json!("DUPLICATE_CENSUS_FIXTURE");
    if let Some(guard) = guard {
        value["claude_request_census_shadow"] = serde_json::json!({ "n": guard });
    }
    serde_json::to_string(&value)
        .unwrap()
        .replace("\"DUPLICATE_CENSUS_FIXTURE\"", &rows)
}

/// The census map of the serialized `index` as raw JSON, `key`'s row twice.
/// Raw text: a parsed `Value` would keep only one copy.
fn census_duplicate_rows(index: &serde_json::Value, key: &str) -> String {
    let rows = index["claude_request_census"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, row)| {
            let entry = format!(
                "{}:{}",
                serde_json::to_string(name).unwrap(),
                serde_json::to_string(row).unwrap()
            );
            if name == key {
                format!("{entry},{entry}")
            } else {
                entry
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{rows}}}")
}

const N3_T0: u64 = 1_790_000_000;
const N3_DAY: u64 = 86_400;
/// MONEY 724h P2: a grant's read span, and how long a rearm stamp counts
/// toward the bound (one window plus the span).
const N3_SPAN: u64 =
    crate::snapshots::claude_request_census::duplicate_rebuild_test_support::N3_GRANT_MAX_LOAD_TO_READ;
const N3_ATTEMPT_WINDOW: u64 = 7 * N3_DAY + N3_SPAN;

fn census_exhausted_counter(index: &mut ScanIndex) -> u64 {
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    let line = serde_json::to_value(ClaudeDuplicateCensusCounts {
        request_census: Some(counts),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        line["request_census"]["census_duplicate_rebuild_exhausted"],
        counts.census_duplicate_rebuild_exhausted
    );
    assert_eq!(counts.decode_duplicate_keys_dropped, 1, "still corruption");
    counts.census_duplicate_rebuild_exhausted
}

fn census_rebuild_alarms(key: &str, cause: &str) -> usize {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    let hash8 = &bound::key_id(key)[..8];
    bound::alarm_lines()
        .iter()
        .filter(|line| {
            line.contains("duplicate rebuild exhausted alarm")
                && line.contains(&format!("key_hash8={hash8} "))
                && line.contains(&format!("cause={cause} "))
        })
        .count()
}

/// MONEY N3 lightness: an affected key is rearmed at most twice per seven
/// days, across restarts, then stays visibly exhausted until the window passes.
#[test]
fn census_duplicate_rebuild_is_bounded_per_key_per_seven_days() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-bound");
        let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        assert!(!fingerprint.is_empty());
        let path = scratch.join("index.json");
        std::fs::write(&path, census_duplicate_rebuild_raw(&original, &key, None)).unwrap();

        // First rebuild: rearmed, and durable before any scan can read.
        let clock = bound::set_now(N3_T0);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(bound::attempts(&index, &key), vec![N3_T0]);
        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(persisted["claude_request_census_shadow"]["n"].is_object());
        assert_eq!(
            persisted["files"][&key]["source_file_fingerprint"],
            serde_json::json!(fingerprint),
            "a rearm is never written"
        );
        // The same process reloading before its scan reached the key spends nothing.
        let index = ScanIndex::load(&path).unwrap();
        assert!(census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(bound::attempts(&index, &key), vec![N3_T0]);
        drop(clock);

        // Second rebuild: a restart (crash) before the first one finished.
        bound::restart();
        let clock = bound::set_now(N3_T0 + N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(
            bound::attempts(&index, &key),
            vec![N3_T0, N3_T0 + N3_DAY],
            "restart keeps the first stamp"
        );
        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        drop(clock);

        // Third within seven days: refused, counted and alarmed once.
        bound::restart();
        let clock = bound::set_now(N3_T0 + 2 * N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(
            !census_rebuild_rearms(&index, &key, &fingerprint),
            "not rearmed"
        );
        assert!(bound::exhausted(&index, &key));
        assert_eq!(bound::attempts(&index, &key).len(), 2);
        assert!(index.claude_request_census_for_test().get(&key).is_none());
        assert_eq!(census_exhausted_counter(&mut index), 1);
        assert_eq!(census_rebuild_alarms(&key, "rebuild_bound_7d"), 1);
        assert_eq!(census_exhausted_counter(&mut index), 1);
        assert_eq!(
            census_rebuild_alarms(&key, "rebuild_bound_7d"),
            1,
            "rate-limited"
        );
        // No grant to save. Candidate selection (asserted above) has no
        // Rearmed reason for the unchanged transcript.
        // This fixture never uploads, so its scans re-read every file for
        // legacy activity; that is not an N3 rearm and is not scanned here.
        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        assert_eq!(bound::attempts(&index, &key).len(), 2);
        index.save(&path).unwrap();
        drop(clock);

        // Still exhausted after a restart inside the window.
        bound::restart();
        let clock = bound::set_now(N3_T0 + 6 * N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(bound::exhausted(&index, &key));
        assert!(!census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(census_exhausted_counter(&mut index), 1);
        drop(clock);

        // MONEY 724h P2: a stamp counts for one window plus the read span,
        // so seven days and one second still refuse.
        bound::restart();
        let clock = bound::set_now(N3_T0 + 7 * N3_DAY + 1);
        let index = ScanIndex::load(&path).unwrap();
        assert!(bound::exhausted(&index, &key), "counted past seven days");
        assert!(!census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(bound::attempts(&index, &key), vec![N3_T0, N3_T0 + N3_DAY]);
        drop(clock);

        // Window expiry re-allows one rebuild, which then decodes clean.
        bound::restart();
        let clock = bound::set_now(N3_T0 + N3_ATTEMPT_WINDOW + 1);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(!bound::exhausted(&index, &key));
        assert!(census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(
            bound::attempts(&index, &key),
            vec![N3_T0 + N3_DAY, N3_T0 + N3_ATTEMPT_WINDOW + 1]
        );
        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        census_scan(&root, &mut index, SECOND_WINDOW);
        assert!(index.claude_request_census_for_test().get(&key).is_some());
        index.save(&path).unwrap();
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(!bound::pending(&index, &key), "clean decode clears");
        assert_eq!(census_exhausted_counter(&mut index), 0);
        drop(clock);
    }
}

/// A future stamp counts as recent (clock rollback fails closed), and a
/// clean decode of the key's record clears the exhausted state.
#[test]
fn census_duplicate_rebuild_future_stamp_refuses_until_a_clean_decode() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-future");
        let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let future = N3_T0 + 30 * N3_DAY;
        let guard =
            serde_json::json!({ "k": { (bound::key_id(&key)): format!("0:{future},{future}") } });
        let path = scratch.join("index.json");
        std::fs::write(
            &path,
            census_duplicate_rebuild_raw(&original, &key, Some(guard)),
        )
        .unwrap();
        let _clock = bound::set_now(N3_T0);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(!census_rebuild_rearms(&index, &key, &fingerprint));
        assert!(bound::exhausted(&index, &key));
        assert_eq!(
            bound::attempts(&index, &key),
            vec![N3_T0, N3_T0],
            "clamped to now"
        );
        assert_eq!(census_exhausted_counter(&mut index), 1);
        assert_eq!(census_rebuild_alarms(&key, "rebuild_bound_7d"), 1);
        index.save(&path).unwrap();

        // New transcript content is ordinary SourceChanged work, not a rearm;
        // its clean record clears the terminal state.
        census_write(
            &root,
            "duplicate.jsonl",
            &[
                census_response("duplicate", Some("req-duplicate"), "msg-duplicate", 1, 10),
                census_response(
                    "duplicate",
                    Some("req-duplicate-2"),
                    "msg-duplicate-2",
                    2,
                    10,
                ),
            ],
        );
        let mut index = ScanIndex::load(&path).unwrap();
        census_scan(&root, &mut index, SECOND_WINDOW);
        assert!(index.claude_request_census_for_test().get(&key).is_some());
        index.save(&path).unwrap();
        bound::restart();
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(!bound::exhausted(&index, &key));
        assert!(!bound::pending(&index, &key));
        assert_eq!(census_exhausted_counter(&mut index), 0);
    }
}

/// Past the tracked-key cap a new duplicate is refused, not rearmed, and the
/// refusal stays counted for one window.
#[test]
fn census_duplicate_rebuild_key_cap_fails_closed() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-cap");
        let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let tracked = (0..bound::MAX_TRACKED_KEYS)
            .map(|slot| {
                // Full entries: the saved (pretty) guard must still decode.
                let entry = format!("0:{N3_T0},{N3_T0}");
                (format!("{slot:016x}"), serde_json::json!(entry))
            })
            .collect::<serde_json::Map<_, _>>();
        assert!(!tracked.contains_key(&bound::key_id(&key)));
        let path = scratch.join("index.json");
        std::fs::write(
            &path,
            census_duplicate_rebuild_raw(
                &original,
                &key,
                Some(serde_json::json!({ "k": tracked })),
            ),
        )
        .unwrap();
        let _clock = bound::set_now(N3_T0 + N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(
            !census_rebuild_rearms(&index, &key, &fingerprint),
            "not rearmed past the cap"
        );
        assert!(bound::attempts(&index, &key).is_empty());
        assert!(index.claude_request_census_for_test().get(&key).is_none());
        assert_eq!(census_exhausted_counter(&mut index), 1);
        assert_eq!(census_rebuild_alarms(&key, "tracked_key_cap"), 1);
        index.save(&path).unwrap();
        bound::restart();
        let mut index = ScanIndex::load(&path).unwrap();
        assert_eq!(
            bound::tracked_open(&index),
            Some(bound::MAX_TRACKED_KEYS),
            "a full saved guard decodes"
        );
        assert_eq!(index.files[&key].source_file_fingerprint, fingerprint);
        assert_eq!(
            census_exhausted_counter(&mut index),
            1,
            "counted for one window"
        );
    }
}

/// A read that starts and then fails before any checkpoint spends its grant,
/// even inside one daemon process whose working index is discarded.
#[test]
fn census_duplicate_rebuild_same_process_failure_spends_an_attempt() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-failure");
        let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let path = scratch.join("index.json");
        std::fs::write(&path, census_duplicate_rebuild_raw(&original, &key, None)).unwrap();
        for (second, attempts) in [(0, 1), (60, 2)] {
            let _clock = bound::set_now(N3_T0 + second);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(census_rebuild_rearms(&index, &key, &fingerprint));
            assert_eq!(bound::attempts(&index, &key).len(), attempts);
            persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
            let mut working = ScanIndex::load(&path).unwrap();
            assert_eq!(bound::attempts(&working, &key).len(), attempts);
            assert!(census_rebuild_rearms(&working, &key, &fingerprint));
            note_duplicate_rebuild_started(&mut working, Path::new(&key));
            assert!(
                !census_rebuild_rearms(&working, &key, &fingerprint),
                "a started read spends the in-process rearm"
            );
            drop(working);
        }
        let _clock = bound::set_now(N3_T0 + 120);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(bound::exhausted(&index, &key));
        assert!(!census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(census_exhausted_counter(&mut index), 1);
    }
}

/// Both rebuild counters, as the census line reports them.
fn census_rebuild_counters(index: &mut ScanIndex) -> (u64, u64) {
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    let line = serde_json::to_value(ClaudeDuplicateCensusCounts {
        request_census: Some(counts),
        ..Default::default()
    })
    .unwrap();
    let counters = (
        counts.census_duplicate_rebuild_exhausted,
        counts.census_duplicate_rebuild_orphaned,
    );
    assert_eq!(
        (
            line["request_census"]["census_duplicate_rebuild_exhausted"].as_u64(),
            line["request_census"]["census_duplicate_rebuild_orphaned"].as_u64(),
        ),
        (Some(counters.0), Some(counters.1))
    );
    counters
}

/// `value` serialized with its shadow state's guard lost or made ambiguous.
fn census_rebuild_corrupt_guard(
    mut value: serde_json::Value,
    corruption: &str,
    id: &str,
) -> String {
    let guard = value["claude_request_census_shadow"]["n"].clone();
    assert!(guard.is_object(), "{corruption}: the fixture holds a guard");
    let placeholder = |value: &mut serde_json::Value, at: &str| {
        value["claude_request_census_shadow"][at] = serde_json::json!("GUARD_PLACEHOLDER");
        serde_json::to_string(value).unwrap()
    };
    match corruption {
        "malformed_shadow" => {
            value["claude_request_census_shadow"] = serde_json::json!("corrupt");
            serde_json::to_string(&value).unwrap()
        }
        "duplicated_shadow" => {
            let shadow = serde_json::to_string(&value["claude_request_census_shadow"]).unwrap();
            value["claude_request_census_shadow"] = serde_json::json!("DUPLICATE_SHADOW");
            serde_json::to_string(&value).unwrap().replace(
                "\"DUPLICATE_SHADOW\"",
                &format!("{shadow},\"claude_request_census_shadow\":{shadow}"),
            )
        }
        // The legacy numeric shadow scalar still reads as absent diagnostics.
        "nonfinite_shadow" => {
            value["claude_request_census_shadow"] = serde_json::json!("NONFINITE");
            serde_json::to_string(&value)
                .unwrap()
                .replace("\"NONFINITE\"", "1e400")
        }
        "malformed_guard" => {
            value["claude_request_census_shadow"]["n"] = serde_json::json!("corrupt");
            serde_json::to_string(&value).unwrap()
        }
        // A stale copy with no stamps after the real one: last-wins would
        // replenish both attempts.
        "duplicated_guard" => placeholder(&mut value, "n")
            .replace("\"GUARD_PLACEHOLDER\"", &format!("{guard},\"n\":{{}}")),
        "duplicated_key_id" => {
            let tracked = serde_json::to_string(&guard["k"][id]).unwrap();
            placeholder(&mut value, "n").replace(
                "\"GUARD_PLACEHOLDER\"",
                &format!("{{\"k\":{{\"{id}\":{tracked},\"{id}\":\"0:\"}}}}"),
            )
        }
        other => panic!("{other}"),
    }
}

const N3_GUARD_CORRUPTIONS: [&str; 6] = [
    "malformed_shadow",
    "nonfinite_shadow",
    "duplicated_shadow",
    "malformed_guard",
    "duplicated_guard",
    "duplicated_key_id",
];

/// SI-724-B3: two rebuilds completed inside the window (the guard keeps only
/// their stamps). A renewed duplicate whose guard is lost or ambiguous is
/// refused, never granted a third rebuild: admission closes for one window,
/// counted and alarmed, across restarts. The intact guard refuses it too.
/// After that window a new counted attempt is allowed.
#[test]
fn census_duplicate_rebuild_lost_or_ambiguous_guard_never_replenishes() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for corruption in std::iter::once("intact").chain(N3_GUARD_CORRUPTIONS) {
            bound::restart();
            let scratch =
                crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-lost-guard");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let id = bound::key_id(&key);
            // Two completed rebuilds: stamps only, nothing pending.
            let completed = serde_json::json!({
                "k": { (id.clone()): format!("0:{N3_T0},{}", N3_T0 + N3_DAY) }
            });
            let raw = if corruption == "intact" {
                census_duplicate_rebuild_raw(&original, &key, Some(completed))
            } else {
                let mut value = serde_json::to_value(&original).unwrap();
                let rows = census_duplicate_rows(&value, &key);
                value["claude_request_census"] = serde_json::json!("DUPLICATE_CENSUS_FIXTURE");
                value["claude_request_census_shadow"] = serde_json::json!({ "n": completed });
                census_rebuild_corrupt_guard(value, corruption, &id)
                    .replace("\"DUPLICATE_CENSUS_FIXTURE\"", &rows)
            };
            let path = scratch.join("index.json");
            std::fs::write(&path, raw).unwrap();
            let refused_at = N3_T0 + 2 * N3_DAY;
            // Inside both the stamps' window and the closure's.
            for (cycle, at) in [refused_at, refused_at + N3_DAY, refused_at + 4 * N3_DAY]
                .into_iter()
                .enumerate()
            {
                bound::restart();
                let _clock = bound::set_now(at);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(
                    !census_rebuild_rearms(&index, &key, &fingerprint),
                    "{corruption} cycle {cycle}: no third rebuild"
                );
                assert!(index.claude_request_census_for_test().get(&key).is_none());
                if corruption == "intact" {
                    assert!(bound::exhausted(&index, &key), "{corruption}");
                    assert_eq!(bound::attempts(&index, &key).len(), 2);
                } else {
                    assert_eq!(
                        bound::tracked_open(&index),
                        None,
                        "{corruption}: admission closed"
                    );
                    assert!(bound::attempts(&index, &key).is_empty());
                }
                // Each renewed duplicate refused while closed counts once more.
                let refusals = if corruption == "intact" {
                    1
                } else {
                    cycle as u64 + 1
                };
                assert_eq!(
                    census_exhausted_counter(&mut index),
                    refusals,
                    "{corruption}"
                );
                let cause = if corruption == "intact" {
                    "rebuild_bound_7d"
                } else {
                    "guard_state_closed"
                };
                assert_eq!(
                    census_rebuild_alarms(&key, cause),
                    cycle + 1,
                    "{corruption}"
                );
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                index.save(&path).unwrap();
                // The duplicate renews for the next process: the original
                // rows doubled again, with the saved shadow state (its guard)
                // minus the corruption counter, so the line still counts one.
                let saved: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                let mut shadow = saved["claude_request_census_shadow"].clone();
                shadow
                    .as_object_mut()
                    .expect("the guard is saved")
                    .remove("a");
                let mut value = serde_json::to_value(&original).unwrap();
                let rows = census_duplicate_rows(&value, &key);
                value["claude_request_census"] = serde_json::json!("DUPLICATE_CENSUS_FIXTURE");
                value["claude_request_census_shadow"] = shadow;
                let raw = serde_json::to_string(&value)
                    .unwrap()
                    .replace("\"DUPLICATE_CENSUS_FIXTURE\"", &rows);
                std::fs::write(&path, raw).unwrap();
            }
            // One window after the refusal: one new counted attempt.
            bound::restart();
            let _clock = bound::set_now(refused_at + 7 * N3_DAY + 1);
            let index = ScanIndex::load(&path).unwrap();
            assert!(
                census_rebuild_rearms(&index, &key, &fingerprint),
                "{corruption}: a counted attempt after the window"
            );
            assert_eq!(
                bound::attempts(&index, &key),
                vec![refused_at + 7 * N3_DAY + 1],
                "{corruption}"
            );
        }
    }
}

/// An earlier checkpoint's rearm (entry saved empty, its prior in the root
/// field) whose guard is then lost is an orphan. Unknown provenance takes the
/// ordinary path (SI B2 condition 2): it is re-offered, never restored or
/// held, and admission closes for one window, counted and alarmed. Once the
/// read rebuilt the record nothing rearms it again.
#[test]
fn census_duplicate_rebuild_legacy_orphan_is_re_offered_and_closes_admission() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for corruption in N3_GUARD_CORRUPTIONS {
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-orphan");
            let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let id = bound::key_id(&key);
            // An earlier checkpoint: one grant saved empty with its prior.
            let mut saved: serde_json::Value = serde_json::from_str(&census_duplicate_rebuild_raw(
                &original,
                &key,
                Some(serde_json::json!({ "k": { (id.clone()): format!("1:{N3_T0}") } })),
            ))
            .unwrap();
            let census = saved["claude_request_census"].as_object_mut().unwrap();
            census.remove(&key);
            saved["files"][&key]["source_file_fingerprint"] = serde_json::json!("");
            saved["claude_census_rebuild_priors"] =
                serde_json::json!({ (id.clone()): fingerprint });
            let raw = census_rebuild_corrupt_guard(saved, corruption, &id);
            let path = scratch.join("index.json");
            std::fs::write(&path, raw).unwrap();

            bound::restart();
            let clock = bound::set_now(N3_T0 + 60);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(
                index.files[&key].source_file_fingerprint.is_empty(),
                "{corruption}: never restored"
            );
            assert!(!bound::held(&index, &key), "{corruption}: never held");
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::Rearmed)
                ),
                "{corruption}: re-offered"
            );
            assert_eq!(bound::prior(&index, &key), None, "{corruption}");
            assert_eq!(bound::tracked_open(&index), None, "{corruption}: closed");
            let orphaned = census_rebuild_counters(&mut index).1;
            assert_eq!(orphaned, 1, "{corruption}");
            assert_eq!(census_rebuild_alarms(&key, "orphaned_rearm"), 1);
            index.save(&path).unwrap();

            // The ordinary read rebuilds the record; nothing rearms it again.
            let mut index = ScanIndex::load(&path).unwrap();
            census_scan(&root, &mut index, SECOND_WINDOW);
            assert!(index.claude_request_census_for_test().get(&key).is_some());
            index.save(&path).unwrap();
            drop(clock);
            bound::restart();
            let _clock = bound::set_now(N3_T0 + 120);
            let index = ScanIndex::load(&path).unwrap();
            let rebuilt = index.files[&key].source_file_fingerprint.clone();
            assert!(!rebuilt.is_empty(), "{corruption}");
            assert!(
                !census_rebuild_rearms(&index, &key, &rebuilt),
                "{corruption}"
            );
            assert!(!bound::pending(&index, &key));
            assert_eq!(bound::tracked_open(&index), None, "still closed in window");
        }
    }
}

/// SOURCE hardening: duplicate corruption, then exhaustion, then a clean
/// decode, then expiry. The checkpoint then carries no `n` and no priors, and
/// its shadow field is the bytes main's serializer writes for that state.
#[test]
fn census_duplicate_rebuild_expiry_after_a_clean_decode_leaves_main_shadow_bytes() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-expiry");
        let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let path = scratch.join("index.json");
        std::fs::write(&path, census_duplicate_rebuild_raw(&original, &key, None)).unwrap();
        for day in [0, 1] {
            bound::restart();
            let _clock = bound::set_now(N3_T0 + day * N3_DAY);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(census_rebuild_rearms(&index, &key, &fingerprint));
            persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        }
        bound::restart();
        let clock = bound::set_now(N3_T0 + 2 * N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(bound::exhausted(&index, &key));
        assert!(!census_rebuild_rearms(&index, &key, &fingerprint));
        assert_eq!(census_exhausted_counter(&mut index), 1);
        index.save(&path).unwrap();

        // New content rebuilds the record (SourceChanged); it decodes clean.
        census_write(
            &root,
            "duplicate.jsonl",
            &[
                census_response("duplicate", Some("req-duplicate"), "msg-duplicate", 1, 10),
                census_response(
                    "duplicate",
                    Some("req-duplicate-2"),
                    "msg-duplicate-2",
                    2,
                    10,
                ),
            ],
        );
        let mut index = ScanIndex::load(&path).unwrap();
        census_scan(&root, &mut index, SECOND_WINDOW);
        assert!(index.claude_request_census_for_test().get(&key).is_some());
        index.save(&path).unwrap();
        drop(clock);
        bound::restart();
        let clock = bound::set_now(N3_T0 + 3 * N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(!bound::pending(&index, &key));
        assert_eq!(
            bound::attempts(&index, &key).len(),
            2,
            "stamps kept in window"
        );
        index.save(&path).unwrap();
        drop(clock);

        // MONEY 724h P2: one window plus the read span after it, the second
        // stamp still counts.
        bound::restart();
        let clock = bound::set_now(N3_T0 + 8 * N3_DAY + 1);
        let index = ScanIndex::load(&path).unwrap();
        assert_eq!(bound::attempts(&index, &key), vec![N3_T0 + N3_DAY]);
        drop(clock);

        // Both stamps expire: the guard is empty and leaves the checkpoint.
        bound::restart();
        let _clock = bound::set_now(N3_T0 + N3_DAY + N3_ATTEMPT_WINDOW + 1);
        let mut index = ScanIndex::load(&path).unwrap();
        index.save(&path).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(saved["claude_request_census_shadow"].get("n").is_none());
        assert!(saved.get("claude_census_rebuild_priors").is_none());
        let index = ScanIndex::load(&path).unwrap();
        let (written, main) = bound::shadow_bytes(&index);
        assert_eq!(written, main);
        assert_eq!(
            saved["claude_request_census_shadow"],
            serde_json::from_str::<serde_json::Value>(&main).unwrap()
        );
    }
}

/// MONEY P2: a fingerprint not in the real format (here 128 control bytes) is
/// refused at insert and never saved, so a nearly full guard plus the
/// adversarial duplicate saves and reloads intact.
#[test]
fn census_duplicate_rebuild_refuses_malformed_fingerprints_at_insert() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-format");
        let (_root, mut original, key) = census_duplicate_rebuild_fixture(&scratch);
        let adversarial = "\u{1}".repeat(128);
        original
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clone_from(&adversarial);
        let tracked = (0..bound::MAX_TRACKED_KEYS - 1)
            .map(|slot| {
                (
                    format!("{slot:016x}"),
                    serde_json::json!(format!("0:{N3_T0},{N3_T0}")),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let path = scratch.join("index.json");
        std::fs::write(
            &path,
            census_duplicate_rebuild_raw(
                &original,
                &key,
                Some(serde_json::json!({ "k": tracked })),
            ),
        )
        .unwrap();
        let _clock = bound::set_now(N3_T0 + N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert_eq!(
            index.files[&key].source_file_fingerprint, adversarial,
            "not rearmed"
        );
        assert_eq!(bound::prior(&index, &key), None);
        assert!(bound::attempts(&index, &key).is_empty());
        assert_eq!(census_exhausted_counter(&mut index), 1);
        assert_eq!(census_rebuild_alarms(&key, "fingerprint_format"), 1);
        index.save(&path).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(saved.get("claude_census_rebuild_priors").is_none());
        bound::restart();
        let mut index = ScanIndex::load(&path).unwrap();
        assert_eq!(
            bound::tracked_open(&index),
            Some(bound::MAX_TRACKED_KEYS - 1),
            "the saved guard decodes intact"
        );
        assert_eq!(index.files[&key].source_file_fingerprint, adversarial);
        assert_eq!(census_exhausted_counter(&mut index), 1);
    }
}

/// A checkpoint from the earlier guard form (`"<flags>:<stamps>:<prior>"`,
/// no root priors, the rearmed entry saved empty) keeps its outstanding grant
/// bounded: the prior moves into the saved priors and marks the empty entry
/// as this bound's own, the second rebuild is the last, and the third holds
/// the entry (skipped, never restored: SI B2 condition 2).
#[test]
fn census_duplicate_rebuild_migrates_a_guard_saved_in_the_earlier_form() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-legacy");
        let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let path = scratch.join("index.json");
        std::fs::write(&path, census_duplicate_rebuild_raw(&original, &key, None)).unwrap();
        let clock = bound::set_now(N3_T0);
        let mut index = ScanIndex::load(&path).unwrap();
        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        drop(clock);
        // Rewrite the saved grant in the earlier form.
        let mut saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let id = bound::key_id(&key);
        assert!(
            saved.get("claude_census_rebuild_priors").is_none(),
            "a current grant saves no prior"
        );
        saved["claude_request_census_shadow"]["n"]["k"][&id] =
            serde_json::json!(format!("1:{N3_T0}:{fingerprint}"));
        // The earlier form saved the rearmed entry empty.
        saved["files"][&key]["source_file_fingerprint"] = serde_json::json!("");
        std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();

        bound::restart();
        let clock = bound::set_now(N3_T0 + N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(
            bound::tracked_open(&index).is_some(),
            "earlier form decodes"
        );
        assert!(index.files[&key].source_file_fingerprint.is_empty());
        assert_eq!(
            census_rebuild_decision(&index, &key, &fingerprint),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::Rearmed)
            ),
            "the counted attempt reads the marked entry"
        );
        assert_eq!(bound::attempts(&index, &key), vec![N3_T0, N3_T0 + N3_DAY]);
        assert_eq!(
            bound::prior(&index, &key).as_deref(),
            Some(fingerprint.as_str()),
            "prior migrated"
        );
        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            saved["claude_request_census_shadow"]["n"]["k"][&id],
            serde_json::json!(format!("1:{N3_T0},{}", N3_T0 + N3_DAY)),
            "written back in the current form"
        );
        drop(clock);

        bound::restart();
        let _clock = bound::set_now(N3_T0 + 2 * N3_DAY);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(bound::exhausted(&index, &key));
        assert!(bound::held(&index, &key));
        assert!(
            index.files[&key].source_file_fingerprint.is_empty(),
            "never restored"
        );
        assert_eq!(
            census_rebuild_decision(&index, &key, &fingerprint),
            (CandidateDecision::Skip, None),
            "held, not re-read"
        );
        assert_eq!(census_exhausted_counter(&mut index), 1);
        assert_eq!(census_rebuild_alarms(&key, "legacy_rearm_held"), 1);
        index.save(&path).unwrap();

        // MONEY 724h P2: the second stamp counts for one window plus the
        // read span, so a day past seven days later one attempt is left.
        bound::restart();
        let clock = bound::set_now(N3_T0 + 8 * N3_DAY + 1);
        let index = ScanIndex::load(&path).unwrap();
        assert!(!bound::held(&index, &key));
        assert_eq!(
            bound::attempts(&index, &key),
            vec![N3_T0 + N3_DAY, N3_T0 + 8 * N3_DAY + 1]
        );
        drop(clock);

        // The window allows one new counted attempt, which reads it.
        bound::restart();
        let _clock = bound::set_now(N3_T0 + N3_DAY + N3_ATTEMPT_WINDOW + 1);
        let index = ScanIndex::load(&path).unwrap();
        assert!(!bound::held(&index, &key));
        assert_eq!(
            bound::attempts(&index, &key),
            vec![N3_T0 + N3_DAY + N3_ATTEMPT_WINDOW + 1]
        );
        assert_eq!(
            census_rebuild_decision(&index, &key, &fingerprint),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::Rearmed)
            )
        );
    }
}

/// What candidate selection decides for `key`'s unchanged transcript at its
/// original `fingerprint` (the last gate, after every non-N3 reason).
fn census_rebuild_decision(
    index: &ScanIndex,
    key: &str,
    fingerprint: &str,
) -> (CandidateDecision, Option<CandidateParseReason>) {
    index.source_fingerprint_decision(key, &index.files[key], fingerprint)
}

/// MONEY N3 (SI-724-B1): a grant never writes the fingerprint; candidate
/// selection alone re-reads the unchanged transcript. True when it does.
fn census_rebuild_rearms(index: &ScanIndex, key: &str, fingerprint: &str) -> bool {
    assert_eq!(
        index.files[key].source_file_fingerprint, fingerprint,
        "a rearm never writes the fingerprint"
    );
    match census_rebuild_decision(index, key, fingerprint) {
        (CandidateDecision::Parse, Some(CandidateParseReason::Rearmed)) => true,
        (CandidateDecision::Skip, None) => false,
        other => panic!("unexpected decision {other:?}"),
    }
}

/// All three rebuild counters, as the census line reports them.
fn census_rebuild_counters_all(index: &mut ScanIndex) -> (u64, u64, u64) {
    let (exhausted, orphaned) = census_rebuild_counters(index);
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    let line = serde_json::to_value(ClaudeDuplicateCensusCounts {
        request_census: Some(counts),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        line["request_census"]["census_rebuild_priors_decode_refused"].as_u64(),
        Some(counts.census_rebuild_priors_decode_refused)
    );
    (
        exhausted,
        orphaned,
        counts.census_rebuild_priors_decode_refused,
    )
}

/// One saved grant: the fixture's duplicate loaded at `N3_T0`, its grant
/// persisted. Returns the saved checkpoint as JSON.
fn census_rebuild_saved_grant(path: &Path, original: &ScanIndex, key: &str) -> serde_json::Value {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    std::fs::write(path, census_duplicate_rebuild_raw(original, key, None)).unwrap();
    let _clock = bound::set_now(N3_T0);
    let mut index = ScanIndex::load(path).unwrap();
    assert!(
        census_rebuild_rearms(&index, key, &original.files[key].source_file_fingerprint),
        "the grant rearms in memory"
    );
    persist_duplicate_rebuild_grants(&mut index, path).unwrap();
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// MONEY P1a: a rearm is never written. The saved grant's entry keeps its
/// real fingerprint and no prior is saved, so a downgrade or an external save
/// that erases the guard (main ignores it and its witness; a save dropping
/// `n` alone leaves the witness, which closes the guard; round 7 rejects the
/// current guard form and closes it) leaves no rearm: repeated failed or
/// discarded scans never re-read the transcript.
#[test]
fn census_duplicate_rebuild_erased_witnesses_never_leave_a_free_rearm() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for erasure in ["main_save", "n_dropped", "round7_closed_guard"] {
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-erased");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            let mut saved = census_rebuild_saved_grant(&path, &original, &key);
            assert_eq!(
                saved["files"][&key]["source_file_fingerprint"],
                serde_json::json!(fingerprint),
                "a grant is saved with its real fingerprint, never empty"
            );
            assert!(
                saved.get("claude_census_rebuild_priors").is_none(),
                "a current grant saves no prior"
            );
            assert_eq!(
                saved["claude_request_census_shadow"]["nw"],
                serde_json::json!(N3_T0),
                "the window witness is saved beside the guard"
            );
            if erasure != "round7_closed_guard" {
                let shadow = saved["claude_request_census_shadow"]
                    .as_object_mut()
                    .unwrap();
                shadow.remove("n").expect("guard saved");
                if erasure == "main_save" {
                    shadow.remove("nw").expect("witness saved");
                }
            } else {
                saved["claude_request_census_shadow"]["n"] = serde_json::json!({ "c": N3_T0 });
            }
            std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();

            for cycle in 1..=4_u64 {
                bound::restart();
                let _clock = bound::set_now(N3_T0 + 60 * cycle);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(
                    !census_rebuild_rearms(&index, &key, &fingerprint),
                    "{erasure}: no rearm outlives its guard, not re-read"
                );
                assert!(bound::attempts(&index, &key).is_empty());
                if erasure != "main_save" {
                    assert_eq!(bound::tracked_open(&index), None, "{erasure}: closed");
                }
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                let mut working = ScanIndex::load(&path).unwrap();
                assert_eq!(working.files[&key].source_file_fingerprint, fingerprint);
                note_duplicate_rebuild_started(&mut working, Path::new(&key));
                drop(working);
                index.save(&path).unwrap();
            }
        }
    }
}

/// MONEY P1a with SI-724-B1 and B2 condition 2: the priors field removed,
/// emptied or refused after a current-form grant. The grant never saved one,
/// so its key is still bounded: at most the remaining attempt, then refused
/// (a refused field admits none). This bound never empties a current-form
/// key's fingerprint (the key is tracked as seen intact), so an entry saved
/// empty here is another mechanism's rearm, exactly SI's identity case: it
/// takes the ordinary path, re-offered, never held or restored, spends no N3
/// attempt and holds no N3 grant, and once a read rebuilt the record nothing
/// re-reads it again (no loop). The same state saved by an earlier
/// checkpoint is this bound's own and held:
/// `census_duplicate_rebuild_earlier_empty_without_prior_is_held`.
#[test]
fn census_duplicate_rebuild_missing_prior_never_holds_or_frees_a_rearm() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for (priors, saved_empty) in [
            ("removed", false),
            ("emptied", false),
            ("refused", false),
            ("removed", true),
            ("emptied", true),
            ("refused", true),
        ] {
            let case = format!("{priors}, saved_empty={saved_empty}");
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-no-prior");
            let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            census_rebuild_saved_grant(&path, &original, &key);
            let erase = |path: &Path| {
                let mut saved: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                census_rebuild_erase_priors(&mut saved, priors, &key);
                if saved_empty {
                    saved["files"][&key]["source_file_fingerprint"] = serde_json::json!("");
                }
                std::fs::write(path, serde_json::to_string(&saved).unwrap()).unwrap();
            };
            erase(&path);

            let mut grants = 1;
            for cycle in 1..=4_u64 {
                bound::restart();
                let _clock = bound::set_now(N3_T0 + 60 * cycle);
                let mut index = ScanIndex::load(&path).unwrap();
                if saved_empty {
                    assert!(
                        index.files[&key].source_file_fingerprint.is_empty(),
                        "{case}: never restored"
                    );
                    assert!(!bound::held(&index, &key), "{case}: never held");
                    assert!(bound::current_form(&index, &key), "{case}: seen intact");
                    assert_eq!(
                        census_rebuild_decision(&index, &key, &fingerprint),
                        (
                            CandidateDecision::Parse,
                            Some(CandidateParseReason::Rearmed)
                        ),
                        "{case}: the ordinary rearm is re-offered"
                    );
                    assert!(
                        !crate::snapshots::claude_request_census::duplicate_rebuild_rearmed(
                            &index, &key
                        ),
                        "{case}: identity's own read, never an N3 grant"
                    );
                    assert_eq!(
                        bound::attempts(&index, &key),
                        vec![N3_T0],
                        "{case}: no N3 attempt spent on it"
                    );
                    assert_eq!(census_rebuild_alarms(&key, "legacy_rearm_held"), 0);
                } else if census_rebuild_rearms(&index, &key, &fingerprint) {
                    grants += 1;
                } else {
                    assert!(bound::exhausted(&index, &key), "{case}");
                }
                assert!(
                    grants <= MAX_N3_REARMS_PER_WINDOW,
                    "{case}: {grants} rearms within one window"
                );
                assert!(bound::attempts(&index, &key).len() <= MAX_N3_REARMS_PER_WINDOW);
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                let mut working = ScanIndex::load(&path).unwrap();
                note_duplicate_rebuild_started(&mut working, Path::new(&key));
                drop(working);
                index.save(&path).unwrap();
                erase(&path);
            }
            // A refused field closes admission on every load: no new grant.
            assert_eq!(
                grants,
                if saved_empty || priors == "refused" {
                    1
                } else {
                    2
                },
                "{case}"
            );

            // A completed read rebuilds the record and stops every rearm.
            bound::restart();
            let clock = bound::set_now(N3_T0 + N3_DAY);
            let mut index = ScanIndex::load(&path).unwrap();
            census_scan(&root, &mut index, SECOND_WINDOW);
            assert!(index.claude_request_census_for_test().get(&key).is_some());
            let rebuilt = index.files[&key].source_file_fingerprint.clone();
            assert!(!rebuilt.is_empty());
            index.save(&path).unwrap();
            for cycle in 1..=2_u64 {
                bound::restart();
                let _clock = bound::set_now(N3_T0 + N3_DAY + 60 * cycle);
                let index = ScanIndex::load(&path).unwrap();
                assert!(!bound::pending(&index, &key), "{case}: released");
                assert!(!census_rebuild_rearms(&index, &key, &rebuilt), "{case}");
            }
            drop(clock);
        }
    }
}

/// MONEY P1a (724f), the round-9 assertions restored for the state they
/// describe: an earlier checkpoint's rearm, saved empty, whose priors field is
/// then removed, emptied or refused. The guard positively records it as this
/// bound's own (pending, earlier form), so it is held: candidate selection
/// skips it, it stays counted and alarmed in every process, failed or
/// discarded scans never re-read it, and it is never restored. Only a counted
/// attempt, saved before the scan, reads it: the one left in the window
/// (`spent` 1), none once both are spent or while a refused field keeps
/// admission closed, one per new window. New transcript content releases it.
#[test]
fn census_duplicate_rebuild_earlier_empty_without_prior_is_held() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_grants,
    };
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for priors in ["removed", "emptied", "refused"] {
            for spent in [1_u64, 2] {
                let case = format!("{priors}, spent={spent}");
                bound::restart();
                let scratch =
                    crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-earlier-held");
                let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
                let fingerprint = original.files[&key].source_file_fingerprint.clone();
                let path = scratch.join("index.json");
                let id = bound::key_id(&key);
                let mut saved = census_rebuild_saved_grant(&path, &original, &key);
                // The earlier form: pending without the current-form flag,
                // its entry saved empty.
                let stamps = (0..spent)
                    .map(|slot| (N3_T0 + 30 * slot).to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                saved["claude_request_census_shadow"]["n"]["k"][&id] =
                    serde_json::json!(format!("1:{stamps}"));
                saved["files"][&key]["source_file_fingerprint"] = serde_json::json!("");
                std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();
                let erase = |path: &Path| {
                    let mut saved: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    census_rebuild_erase_priors(&mut saved, priors, &key);
                    std::fs::write(path, serde_json::to_string(&saved).unwrap()).unwrap();
                };
                erase(&path);
                // A closed guard alarms an unspent key as closed; a key with
                // both attempts spent as held.
                let cause = if priors == "refused" && spent == 1 {
                    "guard_state_closed"
                } else {
                    "legacy_rearm_held"
                };

                let mut reads = 0;
                let mut held = 0;
                for cycle in 1..=4_u64 {
                    bound::restart();
                    let at = N3_T0 + 60 * cycle;
                    let _clock = bound::set_now(at);
                    let mut index = ScanIndex::load(&path).unwrap();
                    assert!(
                        index.files[&key].source_file_fingerprint.is_empty(),
                        "{case}: the saved emptiness stays, never restored"
                    );
                    assert!(!bound::current_form(&index, &key), "{case}");
                    if census_rebuild_decision(&index, &key, &fingerprint) == rearmed {
                        reads += 1;
                        assert!(!bound::held(&index, &key), "{case}");
                        assert_eq!(
                            bound::attempts(&index, &key).last(),
                            Some(&at),
                            "{case}: a counted attempt authorizes the read"
                        );
                        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                        assert!(
                            bound::saved_stamps(&path, &key).contains(&at),
                            "{case}: stamped before the scan"
                        );
                    } else {
                        held += 1;
                        assert!(bound::held(&index, &key), "{case}: held");
                        assert_eq!(
                            census_rebuild_decision(&index, &key, &fingerprint),
                            (CandidateDecision::Skip, None),
                            "{case}: a held rearm is never read"
                        );
                        assert_eq!(census_rebuild_counters(&mut index), (1, 0), "{case}");
                        assert_eq!(
                            census_rebuild_alarms(&key, cause),
                            held,
                            "{case}: one alarm per process"
                        );
                        persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                    }
                    assert!(bound::attempts(&index, &key).len() <= MAX_N3_REARMS_PER_WINDOW);
                    // A failed scan: its read starts, its working index is
                    // discarded; the cycle's own index is then saved.
                    let mut working = ScanIndex::load(&path).unwrap();
                    note_duplicate_rebuild_started(&mut working, Path::new(&key));
                    drop(working);
                    index.save(&path).unwrap();
                    erase(&path);
                }
                let left = if priors == "refused" { 0 } else { 2 - spent };
                assert_eq!(reads, left, "{case}: only the attempt left in the window");
                assert_eq!(held, 4 - left as usize, "{case}");
                assert!(spent + reads <= MAX_N3_REARMS_PER_WINDOW as u64, "{case}");

                // The window passing allows one new counted attempt, saved
                // before its scan; a refused field keeps it closed and held.
                bound::restart();
                let at = N3_T0 + 8 * N3_DAY;
                let clock = bound::set_now(at);
                let mut index = ScanIndex::load(&path).unwrap();
                if priors == "refused" {
                    assert!(bound::held(&index, &key), "{case}: still held");
                    assert_eq!(
                        census_rebuild_decision(&index, &key, &fingerprint),
                        (CandidateDecision::Skip, None),
                        "{case}"
                    );
                } else {
                    assert_eq!(
                        census_rebuild_decision(&index, &key, &fingerprint),
                        rearmed,
                        "{case}: one counted attempt"
                    );
                    assert_eq!(bound::attempts(&index, &key), vec![at], "{case}");
                    persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                    assert_eq!(bound::saved_stamps(&path, &key), vec![at], "{case}");
                }

                // New transcript content is ordinary changed-file work; its
                // clean record releases the key.
                census_write(
                    &root,
                    "duplicate.jsonl",
                    &[
                        census_response("duplicate", Some("req-duplicate"), "msg-duplicate", 1, 10),
                        census_response(
                            "duplicate",
                            Some("req-duplicate-2"),
                            "msg-duplicate-2",
                            2,
                            10,
                        ),
                    ],
                );
                census_scan(&root, &mut index, SECOND_WINDOW);
                assert!(
                    index.claude_request_census_for_test().get(&key).is_some(),
                    "{case}"
                );
                assert!(!index.files[&key].source_file_fingerprint.is_empty());
                index.save(&path).unwrap();
                bound::restart();
                let index = ScanIndex::load(&path).unwrap();
                assert!(!bound::pending(&index, &key), "{case}: released");
                assert!(!bound::held(&index, &key), "{case}");
                drop(clock);
            }
        }
    }
}

/// MONEY 724f P1a: total re-reads of one duplicate key over three windows of
/// failed and discarded scans (restarts and same-process reloads, saved and
/// unsaved) stay within the bound in every rolling window, and every read is
/// covered by a counted stamp saved before it. Cases: a current-form grant,
/// an earlier checkpoint's marked empty with and without its prior, and with
/// its priors field refused on every load (no read at all).
///
/// MONEY 724g P2: a `delayed` schedule also leaves a saved, unspent grant
/// unread in one process for most of a window, or past it, before the same
/// process reloads and reads. The bound holds for the actual read times too:
/// at most two reads in any rolling seven days, not only two authorizing
/// stamps.
#[test]
fn census_duplicate_rebuild_total_re_reads_stay_within_the_bound_across_windows() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_grants,
    };
    const WINDOW: u64 = 7 * N3_DAY;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for (case, schedule) in [
            "current",
            "earlier_with_prior",
            "earlier_without_prior",
            "earlier_priors_refused",
        ]
        .into_iter()
        .flat_map(|case| [(case, "regular"), (case, "delayed")])
        {
            bound::restart();
            let scratch =
                crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-multi-window");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            let id = bound::key_id(&key);
            let mut saved = census_rebuild_saved_grant(&path, &original, &key);
            if case != "current" {
                saved["claude_request_census_shadow"]["n"]["k"][&id] =
                    serde_json::json!(format!("1:{N3_T0}"));
                saved["files"][&key]["source_file_fingerprint"] = serde_json::json!("");
                if case == "earlier_with_prior" {
                    saved["claude_census_rebuild_priors"] =
                        serde_json::json!({ (id.clone()): fingerprint });
                }
            }
            std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();
            let refuse = |path: &Path| {
                if case == "earlier_priors_refused" {
                    let mut saved: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    census_rebuild_erase_priors(&mut saved, "refused", &key);
                    std::fs::write(path, serde_json::to_string(&saved).unwrap()).unwrap();
                }
            };
            // The saved grant's own read, at `N3_T0`, and the counted stamp
            // that authorized each read.
            let mut reads = vec![N3_T0];
            let mut authorized = vec![N3_T0];
            let mut delay = 0;
            let mut at = N3_T0;
            for step in 0..42_u64 {
                at = N3_T0 + 3_600 + step * N3_DAY / 2 + delay;
                // 0: restart, read, unsaved. 1: same process, discarded before
                // the read. 2: same process, read, saved. 3: restart,
                // discarded before the read, saved.
                let kind = step % 4;
                if schedule == "delayed" && kind == 1 {
                    // This process's saved grant stays unread until the next
                    // step's reload: most of a window, then past one.
                    delay += if step % 8 == 1 {
                        6 * N3_DAY
                    } else {
                        7 * N3_DAY
                    };
                }
                if kind == 0 || kind == 3 {
                    bound::restart();
                }
                refuse(&path);
                let _clock = bound::set_now(at);
                let mut index = ScanIndex::load(&path).unwrap();
                let offered = census_rebuild_decision(&index, &key, &fingerprint)
                    == (
                        CandidateDecision::Parse,
                        Some(CandidateParseReason::Rearmed),
                    );
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                if offered && (kind == 0 || kind == 2) {
                    // Its stamp: saved this step, or by the unread grant of
                    // the step before (same process).
                    let stamp = bound::saved_stamps(&path, &key)
                        .into_iter()
                        .filter(|stamp| *stamp <= at && at - *stamp <= N3_DAY / 2)
                        .max()
                        .unwrap_or_else(|| {
                            panic!("{case} at {at}: a read without a saved counted stamp")
                        });
                    assert!(
                        !authorized.contains(&stamp),
                        "{case} at {at}: stamp {stamp} authorizes a second read"
                    );
                    authorized.push(stamp);
                    let in_window = authorized
                        .iter()
                        .filter(|earlier| stamp.saturating_sub(**earlier) <= WINDOW)
                        .count();
                    assert!(
                        in_window <= MAX_N3_REARMS_PER_WINDOW,
                        "{case} {schedule} at {at}: {in_window} authorizations in one window"
                    );
                    reads.push(at);
                    // MONEY 724g P2: the actual reads, in any rolling window.
                    let read_in_window = reads
                        .iter()
                        .filter(|earlier| at - **earlier <= WINDOW)
                        .count();
                    assert!(
                        read_in_window <= MAX_N3_REARMS_PER_WINDOW,
                        "{case} {schedule} at {at}: {read_in_window} reads in seven days: {reads:?}"
                    );
                    note_duplicate_rebuild_started(&mut index, Path::new(&key));
                }
                if kind >= 2 {
                    index.save(&path).unwrap();
                }
            }
            let span = at - N3_T0;
            let windows = span.div_ceil(WINDOW) as usize + 1;
            assert!(
                reads.len() <= MAX_N3_REARMS_PER_WINDOW * windows,
                "{case}: {} reads over {windows} windows",
                reads.len()
            );
            if case == "earlier_priors_refused" {
                assert_eq!(reads, vec![N3_T0], "{case}: closed on every load");
            } else {
                // Not vacuous: each later window still allows a counted read.
                assert!(reads.len() >= 4, "{case}: {reads:?}");
            }
        }
    }
}

/// `original` saved with its duplicate `key` fresh (`current`), or in an
/// earlier checkpoint's form (`earlier`): pending without `CURRENT`, no
/// stamps, the entry saved empty (this bound's own marked rearm).
fn census_rebuild_form_raw(original: &ScanIndex, key: &str, form: &str) -> String {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    if form != "earlier" {
        return census_duplicate_rebuild_raw(original, key, None);
    }
    let mut earlier = original.clone();
    earlier
        .files
        .get_mut(key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    census_duplicate_rebuild_raw(
        &earlier,
        key,
        Some(serde_json::json!({ "k": { (bound::key_id(key)): "1:" } })),
    )
}

/// MONEY 724h P2: MONEY's counterexample with independent load and read
/// clocks. Each cycle loads (a counted attempt is stamped and saved before
/// its scan), reads later, and discards its failed working scan. Loads and
/// reads at (0, 60 s), (1 d, 1 d + 60 s), (7 d + 1 s, 7 d + 2 s): the first
/// stamp still counts at the third load (one window plus the read span), so
/// the third read is refused. The schedule continues with a long scan (a
/// read 11 h after its load is admitted) and the attempt window's inclusive
/// boundary. Every read is covered by a saved
/// stamp at most the span before it, and any rolling seven days hold at most
/// two actual reads, in one process and with a restart before every cycle.
/// Current and earlier-checkpoint forms; OFF and ON.
#[test]
fn census_duplicate_rebuild_actual_reads_stay_bounded_with_independent_load_and_read_clocks() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_grants,
    };
    const WINDOW: u64 = 7 * N3_DAY;
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    // (load, read), offsets from N3_T0.
    let schedule = [
        (0, 60),
        (N3_DAY, N3_DAY + 60),
        (7 * N3_DAY + 1, 7 * N3_DAY + 2),
        (N3_ATTEMPT_WINDOW + 1, N3_ATTEMPT_WINDOW + 2),
        (8 * N3_DAY, 8 * N3_DAY + 11 * 3_600),
        (N3_DAY + N3_ATTEMPT_WINDOW + 1, 8 * N3_DAY + 23 * 3_600),
        (16 * N3_DAY, 16 * N3_DAY + 60),
        // The stamp of `N3_DAY + N3_ATTEMPT_WINDOW + 1` still counts at
        // exactly one attempt window after it (refused), not a second later.
        (16 * N3_DAY + 1, 16 * N3_DAY + 61),
        (16 * N3_DAY + 2, 16 * N3_DAY + 62),
    ];
    let expected = [
        60,
        N3_DAY + 60,
        N3_ATTEMPT_WINDOW + 2,
        8 * N3_DAY + 23 * 3_600,
        16 * N3_DAY + 60,
        16 * N3_DAY + 62,
    ]
    .map(|offset| N3_T0 + offset);
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for form in ["current", "earlier"] {
            for restarts in [false, true] {
                let case = format!("shadow={enabled} {form} restarts={restarts}");
                bound::restart();
                let scratch =
                    crate::test_scratch::ScratchDir::new("census-rebuild-independent-clocks");
                let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
                let fingerprint = original.files[&key].source_file_fingerprint.clone();
                let path = scratch.join("index.json");
                std::fs::write(&path, census_rebuild_form_raw(&original, &key, form)).unwrap();
                let mut reads: Vec<u64> = Vec::new();
                for (load, read) in schedule {
                    let (load, read) = (N3_T0 + load, N3_T0 + read);
                    if restarts {
                        bound::restart();
                    }
                    let clock = bound::set_now(load);
                    let mut index = ScanIndex::load(&path).unwrap();
                    persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                    drop(clock);
                    let _clock = bound::set_now(read);
                    if census_rebuild_decision(&index, &key, &fingerprint) != rearmed {
                        assert_eq!(
                            census_rebuild_decision(&index, &key, &fingerprint),
                            (CandidateDecision::Skip, None),
                            "{case} read at {read}"
                        );
                        continue;
                    }
                    let stamp = bound::saved_stamps(&path, &key)
                        .into_iter()
                        .filter(|stamp| *stamp <= read && read - *stamp <= N3_SPAN)
                        .max();
                    assert!(
                        stamp.is_some(),
                        "{case}: the read at {read} has no saved stamp within the span"
                    );
                    reads.push(read);
                    let in_window = reads.iter().filter(|earlier| read - **earlier <= WINDOW);
                    assert!(
                        in_window.count() <= MAX_N3_REARMS_PER_WINDOW,
                        "{case}: more than two reads in seven days: {reads:?}"
                    );
                    // The read starts; its failed working scan is discarded.
                    note_duplicate_rebuild_started(&mut index, Path::new(&key));
                }
                assert_eq!(reads, expected, "{case}");
                assert!(
                    !reads.contains(&(N3_T0 + 7 * N3_DAY + 2)),
                    "{case}: MONEY's third read refused"
                );
            }
        }
    }
}

/// MONEY 724h P2: a grant authorizes a read only within
/// `N3_GRANT_MAX_LOAD_TO_READ` of its stamp, checked when candidate selection
/// admits the read. A long scan reaching the key later is refused: the key is
/// skipped (an earlier checkpoint's marked empty is held), nothing is read,
/// and the census line counts it as exhausted with its own cause, alarmed
/// once. The same process reloading finds its saved grant spent, never
/// moved forward: only a new counted attempt from the same budget, saved
/// before its scan, reads the key, and with the budget spent it stays
/// refused (also after a restart). An identity-armed empty fingerprint still
/// takes the identity path past the span: never held, never counted. OFF and
/// ON.
#[test]
fn census_duplicate_rebuild_read_past_the_grant_span_needs_a_new_counted_attempt() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants, SourceRearm,
    };
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    let refused = (CandidateDecision::Skip, None);
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for form in ["current", "earlier", "identity"] {
            let case = format!("shadow={enabled} {form}");
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-grant-span");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            std::fs::write(&path, census_rebuild_form_raw(&original, &key, form)).unwrap();
            let load = N3_T0;
            let clock = bound::set_now(load);
            let mut index = ScanIndex::load(&path).unwrap();
            persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
            assert_eq!(
                bound::saved_stamps(&path, &key),
                vec![load],
                "{case}: stamped and saved before the scan"
            );
            if form == "identity" {
                // Identity work's re-arm of the current-form key.
                census_identity_clear(
                    &mut index,
                    &key,
                    SourceRearm::Identity("identity_contract:grant-span"),
                );
                assert!(index.files[&key].source_file_fingerprint.is_empty());
            }
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                rearmed,
                "{case}: at the load"
            );
            drop(clock);
            {
                let _clock = bound::set_now(load + N3_SPAN);
                assert_eq!(
                    census_rebuild_decision(&index, &key, &fingerprint),
                    rearmed,
                    "{case}: the span's last second still admits the read"
                );
            }

            // A long scan reaches the key one second past the span.
            let clock = bound::set_now(load + N3_SPAN + 1);
            if form == "identity" {
                assert!(!bound::held(&index, &key), "{case}: never held");
                assert_eq!(
                    census_rebuild_decision(&index, &key, &fingerprint),
                    rearmed,
                    "{case}: the identity path reads it"
                );
                assert_eq!(
                    census_rebuild_counters(&mut index),
                    (0, 0),
                    "{case}: never counted"
                );
                assert_eq!(census_rebuild_alarms(&key, "grant_read_span_expired"), 0);
                continue;
            }
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                refused,
                "{case}: refused past the span, nothing read"
            );
            assert_eq!(bound::held(&index, &key), form == "earlier", "{case}");
            for _ in 0..2 {
                assert_eq!(
                    census_rebuild_counters(&mut index),
                    (1, 0),
                    "{case}: counted as exhausted"
                );
            }
            assert_eq!(
                census_rebuild_alarms(&key, "grant_read_span_expired"),
                1,
                "{case}: alarmed once"
            );
            drop(clock);

            // The same process reloads (the working scan discarded): its
            // saved grant is spent. A new counted attempt reads the key.
            let again = load + N3_SPAN + 2;
            let clock = bound::set_now(again);
            let mut index = ScanIndex::load(&path).unwrap();
            assert_eq!(
                bound::attempts(&index, &key),
                vec![load, again],
                "{case}: a new counted attempt, never the old stamp moved"
            );
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                rearmed,
                "{case}"
            );
            persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
            assert_eq!(
                bound::saved_stamps(&path, &key),
                vec![load, again],
                "{case}: saved before the scan"
            );
            drop(clock);

            // Late again: refused, and both attempts are spent.
            let late = again + N3_SPAN + 1;
            {
                let _clock = bound::set_now(late);
                assert_eq!(
                    census_rebuild_decision(&index, &key, &fingerprint),
                    refused,
                    "{case}: late again"
                );
            }
            for restart in [false, true] {
                if restart {
                    bound::restart();
                }
                let _clock = bound::set_now(late + 1);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(bound::exhausted(&index, &key), "{case} restart={restart}");
                assert_eq!(bound::attempts(&index, &key), vec![load, again]);
                assert_eq!(
                    census_rebuild_decision(&index, &key, &fingerprint),
                    refused,
                    "{case} restart={restart}: no free read"
                );
                assert_eq!(census_rebuild_counters(&mut index), (1, 0), "{case}");
            }
        }
    }
}

/// MONEY 724g P2 with SI's ruling: closing this process's stale, unspent
/// grant never holds an identity-armed empty fingerprint. The grant's key is
/// current-form; identity work then clears its fingerprint (saved). The same
/// process reloads within the grant's window and past it: the identity path
/// wins either way (re-offered, never held, no N3 attempt charged or saved).
/// OFF and ON.
#[test]
fn census_duplicate_rebuild_stale_grant_never_holds_an_identity_rearm() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for delay in [6 * N3_DAY, 8 * N3_DAY] {
            let case = format!("shadow={enabled} delay={delay}");
            bound::restart();
            let scratch =
                crate::test_scratch::ScratchDir::new("census-rebuild-stale-grant-identity");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            // This process's saved grant at N3_T0, never started.
            let mut saved = census_rebuild_saved_grant(&path, &original, &key);
            // Identity work's saved re-arm of the current-form key.
            saved["files"][&key]["source_file_fingerprint"] = serde_json::json!("");
            std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();

            let _clock = bound::set_now(N3_T0 + delay);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(bound::current_form(&index, &key), "{case}");
            assert!(!bound::held(&index, &key), "{case}: never held");
            assert!(!bound::exhausted(&index, &key), "{case}");
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                rearmed,
                "{case}: identity re-offers it"
            );
            let before = std::fs::read(&path).unwrap();
            persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
            assert_eq!(
                std::fs::read(&path).unwrap(),
                before,
                "{case}: no N3 attempt charged"
            );
        }
    }
}

/// MONEY 724f P1: two rebuilds spent inside the window, then a save drops `n`
/// alone (an external or older save) and the duplicate renews. The window
/// witness saved beside it, or a priors field present, is evidence of earlier
/// activity: the guard is lost, not fresh. Admission closes for one window
/// (no replenished attempt), counted and alarmed, across restarts; after it a
/// new counted attempt is allowed. Only a checkpoint with no evidence at all
/// (main's own save drops the witness too) starts a fresh guard.
#[test]
fn census_duplicate_rebuild_missing_guard_with_evidence_never_replenishes() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for evidence in ["witness", "priors_field", "none"] {
            bound::restart();
            let scratch =
                crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-missing-guard");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            // Two real grants, both saved, with the witness beside the guard.
            std::fs::write(&path, census_duplicate_rebuild_raw(&original, &key, None)).unwrap();
            for day in [0, 1] {
                bound::restart();
                let _clock = bound::set_now(N3_T0 + day * N3_DAY);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(census_rebuild_rearms(&index, &key, &fingerprint));
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                assert_eq!(bound::witness(&index), N3_T0 + day * N3_DAY);
            }
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                saved["claude_request_census_shadow"]["nw"],
                serde_json::json!(N3_T0 + N3_DAY)
            );
            // The save that drops `n`, then the renewed duplicate.
            let renew = |shadow: serde_json::Value, priors_field: bool| {
                let mut value = serde_json::to_value(&original).unwrap();
                let rows = census_duplicate_rows(&value, &key);
                value["claude_request_census"] = serde_json::json!("DUPLICATE_CENSUS_FIXTURE");
                value["claude_request_census_shadow"] = shadow;
                if priors_field {
                    value["claude_census_rebuild_priors"] = serde_json::json!({});
                }
                let raw = serde_json::to_string(&value)
                    .unwrap()
                    .replace("\"DUPLICATE_CENSUS_FIXTURE\"", &rows);
                std::fs::write(&path, raw).unwrap();
            };
            let mut shadow = saved["claude_request_census_shadow"].clone();
            let shadow_map = shadow.as_object_mut().unwrap();
            shadow_map.remove("n").expect("guard saved");
            // Without the corruption counter, so the line still counts one.
            shadow_map.remove("a");
            if evidence != "witness" {
                shadow_map.remove("nw").expect("witness saved");
            }
            renew(shadow, evidence == "priors_field");

            let refused_at = N3_T0 + 2 * N3_DAY;
            if evidence == "none" {
                // Indistinguishable from a key never tracked: a fresh guard.
                bound::restart();
                let _clock = bound::set_now(refused_at);
                let index = ScanIndex::load(&path).unwrap();
                assert!(census_rebuild_rearms(&index, &key, &fingerprint));
                assert_eq!(bound::attempts(&index, &key), vec![refused_at]);
                continue;
            }
            for (cycle, at) in [refused_at, refused_at + N3_DAY, refused_at + 4 * N3_DAY]
                .into_iter()
                .enumerate()
            {
                bound::restart();
                let _clock = bound::set_now(at);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(
                    !census_rebuild_rearms(&index, &key, &fingerprint),
                    "{evidence} cycle {cycle}: no replenished rebuild"
                );
                assert_eq!(
                    bound::tracked_open(&index),
                    None,
                    "{evidence}: admission closed"
                );
                assert!(bound::attempts(&index, &key).is_empty());
                assert_eq!(
                    census_exhausted_counter(&mut index),
                    cycle as u64 + 1,
                    "{evidence}: each renewed duplicate refused"
                );
                assert_eq!(
                    census_rebuild_counters(&mut index).1,
                    1,
                    "{evidence}: the lost guard counted once in the window"
                );
                assert_eq!(census_rebuild_alarms(&key, "guard_lost"), 1, "{evidence}");
                assert_eq!(
                    census_rebuild_alarms(&key, "guard_state_closed"),
                    cycle,
                    "{evidence}"
                );
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                index.save(&path).unwrap();
                let saved: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                let mut shadow = saved["claude_request_census_shadow"].clone();
                assert!(shadow["n"].is_object(), "{evidence}: the closure is saved");
                shadow.as_object_mut().unwrap().remove("a");
                renew(shadow, false);
            }
            // One window after the closure: one new counted attempt.
            bound::restart();
            let _clock = bound::set_now(refused_at + 7 * N3_DAY + 1);
            let index = ScanIndex::load(&path).unwrap();
            assert!(
                census_rebuild_rearms(&index, &key, &fingerprint),
                "{evidence}: a counted attempt after the window"
            );
            assert_eq!(
                bound::attempts(&index, &key),
                vec![refused_at + 7 * N3_DAY + 1],
                "{evidence}"
            );
        }
    }
}

const MAX_N3_REARMS_PER_WINDOW: usize = 2;

/// Autoreview r9 P1: once the grant's parse rebuilt the record, a later
/// independent rearm (other work clearing the fingerprint) is saved as it is,
/// never overwritten with the prior, and still reads after the reload.
#[test]
fn census_duplicate_rebuild_save_keeps_an_independent_rearm_after_the_rebuild() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-independent");
        let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let path = scratch.join("index.json");
        census_rebuild_saved_grant(&path, &original, &key);
        let _clock = bound::set_now(N3_T0 + 60);
        let mut index = ScanIndex::load(&path).unwrap();
        assert!(census_rebuild_rearms(
            &index,
            &key,
            &original.files[&key].source_file_fingerprint
        ));
        census_scan(&root, &mut index, SECOND_WINDOW);
        assert!(index.claude_request_census_for_test().get(&key).is_some());
        let rebuilt = index.files[&key].source_file_fingerprint.clone();
        assert!(!rebuilt.is_empty());
        // Independent reparse debt on the same file after the rebuild.
        index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        index.save(&path).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            saved["files"][&key]["source_file_fingerprint"],
            serde_json::json!(""),
            "the independent rearm is saved, not the prior"
        );
        bound::restart();
        let index = ScanIndex::load(&path).unwrap();
        assert!(
            !bound::pending(&index, &key),
            "the rebuild cleared the bound"
        );
        assert!(index.files[&key].source_file_fingerprint.is_empty());
        assert_eq!(
            census_rebuild_decision(&index, &key, &rebuilt),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::Rearmed)
            ),
            "the independent debt still reads"
        );
    }
}

/// MONEY P1b, SI B2: a malformed, truncated or overflowing priors field is
/// decoded in isolation and refused. Every index entry and the key's attempt
/// history are kept (no whole-index reset), no rebuild is admitted for one
/// window, and the refusal is counted on the census line for that window.
/// The refused field marks nothing, so nothing is held or restored. A
/// duplicated field name is not a value defect: it refuses the whole read
/// (SI-724-B3b item 3,
/// `census_rebuild_duplicated_root_fields_refuse_and_keep_the_index`).
#[test]
fn census_rebuild_priors_decode_refusal_keeps_the_index() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for corruption in ["malformed", "truncated", "overflow"] {
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-priors-refused");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            let mut saved = census_rebuild_saved_grant(&path, &original, &key);
            let id = bound::key_id(&key);
            let entries = saved["files"].as_object().unwrap().len();
            assert_eq!(entries, original.files.len());
            // A well-formed field first, then its corruption.
            saved["claude_census_rebuild_priors"] =
                serde_json::json!({ (id.clone()): fingerprint });
            let raw = census_rebuild_corrupt_priors(&mut saved, corruption, &id, &fingerprint);
            std::fs::write(&path, raw).unwrap();

            // The same process, its saved grant not yet started: refused too.
            {
                let _clock = bound::set_now(N3_T0 + 30);
                let index = ScanIndex::load(&path).unwrap();
                assert!(
                    !census_rebuild_rearms(&index, &key, &fingerprint),
                    "{corruption}: a closed guard refuses an unstarted grant"
                );
                assert!(bound::exhausted(&index, &key), "{corruption}");
                assert_eq!(bound::attempts(&index, &key), vec![N3_T0]);
            }

            bound::restart();
            let clock = bound::set_now(N3_T0 + 60);
            let mut index = ScanIndex::load(&path).unwrap();
            assert_eq!(
                index.files.len(),
                entries,
                "{corruption}: every index entry kept"
            );
            assert_eq!(
                bound::attempts(&index, &key),
                vec![N3_T0],
                "{corruption}: attempt history kept"
            );
            assert!(bound::exhausted(&index, &key), "{corruption}: no grant");
            assert!(!bound::held(&index, &key), "{corruption}");
            assert!(
                !census_rebuild_rearms(&index, &key, &fingerprint),
                "{corruption}: not rearmed, not re-read"
            );
            assert_eq!(bound::tracked_open(&index), None, "{corruption}: closed");
            assert_eq!(
                census_rebuild_counters_all(&mut index),
                (1, 0, 1),
                "{corruption}"
            );
            assert_eq!(
                census_rebuild_alarms(&key, "priors_decode_refused"),
                1,
                "{corruption}"
            );
            index.save(&path).unwrap();
            drop(clock);
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert!(
                saved.get("claude_census_rebuild_priors").is_none(),
                "{corruption}: nothing marked"
            );

            // Still closed and counted inside the window.
            bound::restart();
            let clock = bound::set_now(N3_T0 + 120);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(!census_rebuild_rearms(&index, &key, &fingerprint));
            assert_eq!(
                census_rebuild_counters_all(&mut index).2,
                1,
                "{corruption}: counted for one window"
            );
            drop(clock);

            // The closure's window passing reopens admission; MONEY 724h P2:
            // the saved grant's stamp still counts (one window plus the read
            // span), so one counted attempt is left.
            bound::restart();
            let clock = bound::set_now(N3_T0 + 60 + 7 * N3_DAY + 1);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(census_rebuild_rearms(&index, &key, &fingerprint));
            assert_eq!(
                bound::attempts(&index, &key),
                vec![N3_T0, N3_T0 + 60 + 7 * N3_DAY + 1]
            );
            assert_eq!(census_rebuild_counters_all(&mut index).2, 0, "expired");
            drop(clock);

            // The window passing allows one new counted attempt.
            bound::restart();
            let _clock = bound::set_now(N3_T0 + 60 + N3_ATTEMPT_WINDOW + 1);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(census_rebuild_rearms(&index, &key, &fingerprint));
            assert_eq!(
                bound::attempts(&index, &key),
                vec![N3_T0 + 60 + N3_ATTEMPT_WINDOW + 1]
            );
            assert_eq!(census_rebuild_counters_all(&mut index).2, 0, "expired");
        }
    }
}

/// `saved` with its priors field removed, emptied or refused (a malformed
/// value for `key`).
fn census_rebuild_erase_priors(saved: &mut serde_json::Value, priors: &str, key: &str) {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    match priors {
        "removed" => {
            saved
                .as_object_mut()
                .unwrap()
                .remove("claude_census_rebuild_priors");
        }
        "emptied" => saved["claude_census_rebuild_priors"] = serde_json::json!({}),
        "refused" => {
            saved["claude_census_rebuild_priors"] = serde_json::json!({ (bound::key_id(key)): 7 });
        }
        other => panic!("{other}"),
    }
}

/// `saved` with a corrupted `claude_census_rebuild_priors`, as raw JSON.
fn census_rebuild_corrupt_priors(
    saved: &mut serde_json::Value,
    corruption: &str,
    id: &str,
    fingerprint: &str,
) -> String {
    match corruption {
        "malformed" => {
            saved["claude_census_rebuild_priors"][id] = serde_json::json!(7);
            serde_json::to_string(saved).unwrap()
        }
        "truncated" => {
            saved["claude_census_rebuild_priors"][id] =
                serde_json::json!(&fingerprint[..fingerprint.len() - 1]);
            serde_json::to_string(saved).unwrap()
        }
        "wrong_type" => {
            saved["claude_census_rebuild_priors"] = serde_json::json!(["x"]);
            serde_json::to_string(saved).unwrap()
        }
        // A literal overflowing number (it has no `Value` form): as the
        // key's prior, and as the whole field.
        "overflow" => {
            saved["claude_census_rebuild_priors"][id] = serde_json::json!("PRIORS_OVERFLOW");
            serde_json::to_string(saved)
                .unwrap()
                .replace("\"PRIORS_OVERFLOW\"", "1e400")
        }
        "overflow_field" => {
            saved["claude_census_rebuild_priors"] = serde_json::json!("PRIORS_OVERFLOW");
            serde_json::to_string(saved)
                .unwrap()
                .replace("\"PRIORS_OVERFLOW\"", "1e400")
        }
        other => panic!("{other}"),
    }
}

/// SI B2 conditions 1 and 3, MONEY 724f P2: a real load and the bounded
/// decoder, with session-account bindings, ACKs and the contract-5 latch
/// present, and a malformed, truncated, wrong-type or literally overflowing
/// (`1e400`) priors field. (A duplicated field name refuses the whole read:
/// `census_rebuild_duplicated_root_fields_refuse_and_keep_the_index`.) Every identity field is kept exactly
/// as without the field, through a bounded CAS save (`save_with_read_limit`,
/// whose compare-and-swap read decodes the corrupt checkpoint) and a plain
/// one, and their reloads; only the priors are refused, counted once.
#[test]
fn census_rebuild_priors_refusal_keeps_bindings_acks_and_latch() {
    use crate::snapshots::claude_request_census::{
        decode_bounded_index, duplicate_rebuild_test_support as bound,
    };
    const KEPT: [&str; 7] = [
        "files",
        "session_account_bindings",
        "accepted_snapshot_fingerprints",
        "accepted_snapshot_fingerprint_ledger_version",
        "claude_request_identity_contract",
        "claude_request_identity_contract_changed",
        "claude_request_census",
    ];
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-priors-identity");
        let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let id = bound::key_id(&key);
        let mut value = serde_json::to_value(&original).unwrap();
        let acks = serde_json::json!(["c".repeat(64), "d".repeat(64)]);
        value["accepted_snapshot_fingerprints"] = acks.clone();
        let bindings = serde_json::json!({
            ("f".repeat(64)): { "account_identifier_hash": "a".repeat(64) }
        });
        value["session_account_bindings"] = bindings.clone();
        let contract = serde_json::json!(crate::snapshots::claude_request_identity::COLLECTOR);
        value["claude_request_identity_contract"] = contract.clone();
        value["claude_request_identity_contract_changed"] = serde_json::json!(true);
        let kept = |index: &ScanIndex| {
            let value = serde_json::to_value(index).unwrap();
            KEPT.map(|field| value[field].clone())
        };
        let control_raw = serde_json::to_string(&value).unwrap();
        let control_path = scratch.join("control.json");
        std::fs::write(&control_path, &control_raw).unwrap();
        let control = kept(&ScanIndex::load(&control_path).unwrap());
        assert_eq!(control[1], bindings, "the binding decodes");
        assert_eq!(control[4], contract, "the contract decodes");
        assert_eq!(control[5], serde_json::json!(true), "the latch decodes");
        assert_eq!(control[2], acks, "the ACKs decode");
        assert_eq!(
            kept(&decode_bounded_index(control_raw.as_bytes()).unwrap()),
            control
        );

        for corruption in [
            "malformed",
            "truncated",
            "wrong_type",
            "overflow",
            "overflow_field",
        ] {
            let mut corrupt = value.clone();
            corrupt["claude_census_rebuild_priors"] =
                serde_json::json!({ (id.clone()): fingerprint });
            let raw = census_rebuild_corrupt_priors(&mut corrupt, corruption, &id, &fingerprint);
            let path = scratch.join(format!("{corruption}-{enabled}.json"));
            std::fs::write(&path, &raw).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert!(path.exists(), "{corruption}: never quarantined");
            let mut bounded = decode_bounded_index(raw.as_bytes()).unwrap();
            for index in [&mut loaded, &mut bounded] {
                assert_eq!(kept(index), control, "{corruption}: identity kept");
                assert!(index.claude_census_rebuild_priors.is_empty());
                assert_eq!(census_rebuild_counters_all(index).2, 1, "{corruption}");
            }
            if corruption.starts_with("overflow") {
                assert!(raw.contains("1e400"), "{corruption}: literal overflow");
            }
            let mut plain = loaded.clone();
            loaded
                .save_with_read_limit(&path, 64 * 1024 * 1024)
                .expect("bounded CAS keeps the identity fields");
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(kept(&reloaded), control, "{corruption}: after bounded CAS");
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                kept(&decode_bounded_index(&bytes).unwrap()),
                control,
                "{corruption}: bounded reload"
            );
            // The plain CAS over the same corrupt checkpoint.
            std::fs::write(&path, &raw).unwrap();
            plain.save(&path).expect("CAS keeps the identity fields");
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(kept(&reloaded), control, "{corruption}: after CAS");
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                kept(&decode_bounded_index(&bytes).unwrap()),
                control,
                "{corruption}: bounded reload after CAS"
            );
        }
    }
}

/// SI-724-F2: guard-loss alarm lines (count-only, no key identity) with
/// `cause` emitted since `from`.
fn census_rebuild_guard_alarms(from: usize, cause: &str) -> usize {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    bound::alarm_lines()[from..]
        .iter()
        .filter(|line| {
            line.contains("duplicate rebuild guard lost alarm")
                && line.contains(&format!("cause={cause} "))
        })
        .inspect(|line| assert!(!line.contains("key_hash8"), "count-only: {line}"))
        .count()
}

/// SI-724-F1-B: a deep (70 nested arrays) or wide (more than the bounded
/// shape gate's node cap) "N3 initialized" marker value is refused in
/// isolation by every reader alike. A real load, the bounded decoder, a
/// bounded CAS save (whose compare-and-swap read decodes the corrupt
/// checkpoint) and a plain one, and their reloads keep every binding, ACK and
/// the contract-5 latch exactly as without the marker; only N3 closes (the
/// guard lost for one window, the marker rewritten present), and the
/// guard-loss alarm (SI-724-F2) fires once, count-only. OFF and ON.
#[test]
fn census_rebuild_deep_or_wide_marker_closes_only_n3_on_every_reader() {
    use crate::snapshots::claude_request_census::{
        decode_bounded_index, duplicate_rebuild_test_support as bound,
    };
    const KEPT: [&str; 7] = [
        "files",
        "session_account_bindings",
        "accepted_snapshot_fingerprints",
        "accepted_snapshot_fingerprint_ledger_version",
        "claude_request_identity_contract",
        "claude_request_identity_contract_changed",
        "claude_request_census",
    ];
    let deep = format!("{}1{}", "[".repeat(70), "]".repeat(70));
    let wide = format!("[{}1]", "1,".repeat(crate::snapshot_retry::STATE_NODES + 8));
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        let _clock = bound::set_now(N3_T0);
        let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-marker-shape");
        let (_root, original, _key) = census_duplicate_rebuild_fixture(&scratch);
        let mut value = serde_json::to_value(&original).unwrap();
        let acks = serde_json::json!(["c".repeat(64), "d".repeat(64)]);
        value["accepted_snapshot_fingerprints"] = acks.clone();
        let bindings = serde_json::json!({
            ("f".repeat(64)): { "account_identifier_hash": "a".repeat(64) }
        });
        value["session_account_bindings"] = bindings.clone();
        let contract = serde_json::json!(crate::snapshots::claude_request_identity::COLLECTOR);
        value["claude_request_identity_contract"] = contract.clone();
        value["claude_request_identity_contract_changed"] = serde_json::json!(true);
        let kept = |index: &ScanIndex| {
            let value = serde_json::to_value(index).unwrap();
            KEPT.map(|field| value[field].clone())
        };
        let control_raw = serde_json::to_string(&value).unwrap();
        let control_path = scratch.join("control.json");
        std::fs::write(&control_path, &control_raw).unwrap();
        let control_index = ScanIndex::load(&control_path).unwrap();
        assert!(!bound::closed(&control_index), "control: N3 open");
        let control = kept(&control_index);
        assert_eq!(control[1], bindings, "the binding decodes");
        assert_eq!(control[2], acks, "the ACKs decode");
        assert_eq!(control[4], contract, "the contract decodes");
        assert_eq!(control[5], serde_json::json!(true), "the latch decodes");
        assert_eq!(
            kept(&decode_bounded_index(control_raw.as_bytes()).unwrap()),
            control
        );

        for (shape, marker) in [("deep", &deep), ("wide", &wide)] {
            let case = format!("shadow={enabled} {shape}");
            bound::restart();
            let alarms = bound::alarm_lines().len();
            let mut corrupt = value.clone();
            corrupt["claude_census_rebuild_initialized"] = serde_json::json!("MARKER_VALUE");
            let raw = serde_json::to_string(&corrupt)
                .unwrap()
                .replace("\"MARKER_VALUE\"", marker);
            let path = scratch.join(format!("{shape}-{enabled}.json"));
            std::fs::write(&path, &raw).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert!(path.exists(), "{case}: never quarantined");
            let mut bounded = decode_bounded_index(raw.as_bytes())
                .unwrap_or_else(|error| panic!("{case}: bounded decode refused: {error:#}"));
            for index in [&mut loaded, &mut bounded] {
                assert_eq!(kept(index), control, "{case}: identity kept");
                assert!(bound::closed(index), "{case}: only N3 closes");
                assert_eq!(bound::tracked_open(index), None, "{case}");
                assert_eq!(bound::marker(index), N3_T0, "{case}: rewritten present");
                assert_eq!(census_rebuild_counters(index).1, 1, "{case}: counted once");
            }
            assert_eq!(
                census_rebuild_guard_alarms(alarms, "marker_refused"),
                1,
                "{case}: one rate-limited guard-loss alarm"
            );
            let mut plain = loaded.clone();
            loaded
                .save_with_read_limit(&path, 64 * 1024 * 1024)
                .unwrap_or_else(|error| panic!("{case}: bounded CAS refused: {error:#}"));
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                saved["claude_census_rebuild_initialized"],
                serde_json::json!(N3_T0),
                "{case}: saved well-formed"
            );
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(kept(&reloaded), control, "{case}: after bounded CAS");
            assert!(
                bound::closed(&reloaded),
                "{case}: still closed for the window"
            );
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                kept(&decode_bounded_index(&bytes).unwrap()),
                control,
                "{case}: bounded reload"
            );
            // The plain CAS over the same corrupt checkpoint.
            std::fs::write(&path, &raw).unwrap();
            plain
                .save(&path)
                .unwrap_or_else(|error| panic!("{case}: CAS refused: {error:#}"));
            let reloaded = ScanIndex::load(&path).unwrap();
            assert_eq!(kept(&reloaded), control, "{case}: after CAS");
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                kept(&decode_bounded_index(&bytes).unwrap()),
                control,
                "{case}: bounded reload after CAS"
            );
        }
    }
}

/// SI-724-F2: losing the guard or its marker while no key is pending (a
/// healthy index: no duplicate, nothing tracked) closes admission for one
/// window and raises a count-only, rate-limited guard-loss alarm: `n` dropped
/// with the marker left (guard missing), a malformed marker, or a malformed
/// `n` (undecodable). Once per cause per process, again after a restart,
/// even with the per-key alarm budget spent. OFF and ON.
#[test]
fn census_rebuild_guard_loss_alarms_with_no_key_pending() {
    use crate::snapshots::claude_request_census::duplicate_rebuild_test_support as bound;
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        let _clock = bound::set_now(N3_T0 + N3_DAY);
        let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-guard-loss-alarm");
        let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        // The orphaned counter each loss reports (a guard decoded closed
        // brings none; the census line omits a zero counter).
        for (loss, cause, orphaned) in [
            ("n_dropped", "guard_missing", 1),
            ("marker_malformed", "marker_refused", 1),
            ("n_malformed", "guard_undecodable", 0),
        ] {
            let case = format!("shadow={enabled} {loss}");
            let mut value = serde_json::to_value(&original).unwrap();
            value["claude_census_rebuild_initialized"] = serde_json::json!(N3_T0);
            match loss {
                "marker_malformed" => {
                    value["claude_census_rebuild_initialized"] = serde_json::json!("x");
                }
                "n_malformed" => {
                    value["claude_request_census_shadow"]["n"] = serde_json::json!("corrupt");
                }
                _ => {}
            }
            let path = scratch.join(format!("{loss}-{enabled}.json"));
            std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
            for process in 0..2 {
                let case = format!("{case} process={process}");
                bound::restart();
                if process == 1 {
                    bound::saturate_key_alarms();
                }
                let alarms = bound::alarm_lines().len();
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(!bound::pending(&index, &key), "{case}: no key pending");
                assert!(bound::closed(&index), "{case}: closed for one window");
                for _ in 0..2 {
                    let counts =
                        crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                            &mut index,
                            &BTreeSet::new(),
                            &BTreeSet::new(),
                            FIRST_WINDOW,
                        );
                    assert_eq!(counts.census_duplicate_rebuild_orphaned, orphaned, "{case}");
                }
                assert_eq!(
                    census_rebuild_guard_alarms(alarms, cause),
                    1,
                    "{case}: one alarm per process"
                );
            }
        }
    }
}

/// The census line's identity-revoke counter (SI-724-B1b).
fn census_rebuild_identity_revoked_line(index: &mut ScanIndex) -> u64 {
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        index,
        &BTreeSet::new(),
        &BTreeSet::new(),
        FIRST_WINDOW,
    );
    let line = serde_json::to_value(ClaudeDuplicateCensusCounts {
        request_census: Some(counts),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        line["request_census"]["census_duplicate_rebuild_identity_revoked"]
            .as_u64()
            .unwrap_or(0),
        counts.census_duplicate_rebuild_identity_revoked
    );
    counts.census_duplicate_rebuild_identity_revoked
}

/// `key`'s fingerprint cleared through the shared identity-clear path.
fn census_identity_clear(
    index: &mut ScanIndex,
    key: &str,
    why: crate::snapshots::claude_request_census::SourceRearm<'_>,
) -> bool {
    let entry = index.files.get_mut(key).unwrap();
    crate::snapshots::claude_request_census::rearm_source_fingerprint(
        &mut index.claude_request_census_shadow,
        key,
        entry,
        why,
    )
}

/// SI-724-B1b with MONEY's conditions, through the shared identity-clear path
/// itself. An earlier checkpoint's held key is revoked once per arming: one
/// revoke, one re-offer, recorded in the guard and saved with the clear.
/// Repeated cycles (restarts, a failed scan's discarded working index, an
/// unsaved cycle, the same arming re-derived) never revoke it again: the key
/// is out of the bound's control. Corruption never revokes: no evidence,
/// oversized evidence, or a repair instead of identity work keep it held, and
/// a malformed or duplicated contract-5 latch refuses the whole read (no
/// arming at all). An earlier form re-entering (an older binary's save) is
/// not revoked again by the same arming, only by a new one. OFF and ON.
#[test]
fn census_duplicate_rebuild_identity_revoke_is_one_shot_per_arming() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_revokes, SourceRearm,
    };
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    let oversized = "x".repeat(8192);
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        bound::restart();
        let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-identity-revoke");
        let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
        let fingerprint = original.files[&key].source_file_fingerprint.clone();
        let path = scratch.join("index.json");
        let mut saved = census_rebuild_saved_grant(&path, &original, &key);
        bound::hold_earlier_form(&mut saved, &key, [N3_T0, N3_T0 + 30]);
        std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();

        // A malformed or duplicated latch cannot arm anything: the read refuses.
        for latch in ["malformed", "duplicated"] {
            let mut value = saved.clone();
            value["claude_request_identity_contract_changed"] = serde_json::json!("LATCH");
            let raw = serde_json::to_string(&value).unwrap().replace(
                "\"LATCH\"",
                if latch == "malformed" {
                    "\"yes\""
                } else {
                    "true,\"claude_request_identity_contract_changed\":true"
                },
            );
            let latch_path = scratch.join(format!("latch-{latch}.json"));
            std::fs::write(&latch_path, &raw).unwrap();
            assert!(ScanIndex::load(&latch_path).is_err(), "{latch}: refused");
            assert_eq!(
                std::fs::read_to_string(&latch_path).unwrap(),
                raw,
                "{latch}: kept"
            );
        }

        bound::restart();
        let clock = bound::set_now(N3_T0 + 60);
        let mut index = ScanIndex::load(&path).unwrap();
        let mut committed = index.clone();
        assert!(bound::held(&index, &key), "shadow={enabled}: held");
        assert_eq!(
            census_rebuild_decision(&index, &key, &fingerprint),
            (CandidateDecision::Skip, None)
        );
        for why in [
            SourceRearm::Identity(""),
            SourceRearm::Identity(&oversized),
            SourceRearm::Other("unbound_authority_repair"),
        ] {
            census_identity_clear(&mut index, &key, why);
            assert!(bound::held(&index, &key), "{why:?}: still held");
            assert_eq!(bound::identity_revoked(&index), 0, "{why:?}");
        }
        // One arming: one revoke, one re-offer.
        census_identity_clear(
            &mut index,
            &key,
            SourceRearm::Identity("identity_contract:test-5"),
        );
        // MONEY 724g P1: never selected before the revoke is saved.
        assert!(bound::revoke_unsaved(&index, &key));
        assert!(bound::held(&index, &key), "shadow={enabled}: until saved");
        assert_eq!(
            census_rebuild_decision(&index, &key, &fingerprint),
            (CandidateDecision::Skip, None)
        );
        persist_duplicate_rebuild_revokes(&mut index, &mut committed, &path).unwrap();
        assert!(!bound::revoke_unsaved(&index, &key));
        assert!(!bound::held(&index, &key));
        assert!(bound::revoked(&index, &key));
        assert!(!bound::pending(&index, &key), "out of the bound's control");
        assert_eq!(census_rebuild_decision(&index, &key, &fingerprint), rearmed);
        // The same arming again, and another one: the identity path's now.
        census_identity_clear(
            &mut index,
            &key,
            SourceRearm::Identity("identity_contract:test-5"),
        );
        census_identity_clear(
            &mut index,
            &key,
            SourceRearm::Identity("family_correction:test"),
        );
        assert_eq!(bound::identity_revoked(&index), 1);
        assert_eq!(census_rebuild_identity_revoked_line(&mut index), 1);
        index.save(&path).unwrap();
        drop(clock);

        for cycle in 1..=3_u64 {
            let case = format!("shadow={enabled} cycle={cycle}");
            bound::restart();
            let _clock = bound::set_now(N3_T0 + 60 + 60 * cycle);
            let mut index = ScanIndex::load(&path).unwrap();
            assert!(!bound::held(&index, &key), "{case}: never held again");
            assert!(bound::revoked(&index, &key), "{case}: durable");
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                rearmed,
                "{case}: re-offered"
            );
            census_identity_clear(
                &mut index,
                &key,
                SourceRearm::Identity("identity_contract:test-5"),
            );
            assert_eq!(bound::identity_revoked(&index), 1, "{case}: no second");
            // A failed scan: its read starts, its working index is discarded.
            let mut working = ScanIndex::load(&path).unwrap();
            note_duplicate_rebuild_started(&mut working, Path::new(&key));
            drop(working);
            if cycle != 2 {
                index.save(&path).unwrap();
            }
        }

        // The earlier form re-entering: the same arming keeps it held, a new
        // arming revokes it once more.
        let mut saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        bound::hold_earlier_form(&mut saved, &key, [N3_T0, N3_T0 + 30]);
        std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();
        bound::restart();
        let _clock = bound::set_now(N3_T0 + 600);
        let mut index = ScanIndex::load(&path).unwrap();
        let mut committed = index.clone();
        assert!(bound::held(&index, &key), "shadow={enabled}: re-entered");
        census_identity_clear(
            &mut index,
            &key,
            SourceRearm::Identity("identity_contract:test-5"),
        );
        assert!(bound::held(&index, &key), "shadow={enabled}: same arming");
        assert_eq!(bound::identity_revoked(&index), 1);
        census_identity_clear(
            &mut index,
            &key,
            SourceRearm::Identity("identity_contract:test-6"),
        );
        assert!(bound::held(&index, &key), "shadow={enabled}: until saved");
        persist_duplicate_rebuild_revokes(&mut index, &mut committed, &path).unwrap();
        assert!(!bound::held(&index, &key), "shadow={enabled}: a new arming");
        assert_eq!(bound::identity_revoked(&index), 2);
        assert_eq!(census_rebuild_decision(&index, &key, &fingerprint), rearmed);
    }
}

/// MONEY 724g P1 with SI's rulings: identity work revoking an earlier
/// checkpoint's N3 hold while the scan is built is durable before the key is
/// selected (`persist_duplicate_rebuild_revokes`, the daemon's save on the
/// cycle's committed state, right after the scan is built). Unsaved, the key
/// stays held and is never selected; a revoke lost to a crash before its save
/// only repeats as a revoke, which re-offers the key once saved. A crash or a
/// discarded working index after that save, before the cycle's post-scan
/// save, never revokes the same arming again: the token stays consumed, the
/// counter counts one revoke in total, and the key is re-offered once per
/// selection until its read is saved, then never again. Restarts and
/// same-process reloads; OFF and ON.
#[test]
fn census_duplicate_rebuild_identity_revoke_is_saved_before_selection() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, note_duplicate_rebuild_started,
        persist_duplicate_rebuild_revokes, SourceRearm,
    };
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    let skipped = (CandidateDecision::Skip, None);
    let arming = SourceRearm::Identity("identity_contract:test-5");
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for reload in ["restart", "same_process"] {
            let case = format!("shadow={enabled} reload={reload}");
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new(
                "census-rebuild-revoke-saved-before-selection",
            );
            let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            let id = bound::key_id(&key);
            let mut saved = census_rebuild_saved_grant(&path, &original, &key);
            bound::hold_earlier_form(&mut saved, &key, [N3_T0, N3_T0 + 30]);
            std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();
            let load = || {
                if reload == "restart" {
                    bound::restart();
                }
                ScanIndex::load(&path).unwrap()
            };
            let on_disk = || -> serde_json::Value {
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
            };

            // The revoke lost before any save: never selected, nothing read.
            let clock = bound::set_now(N3_T0 + 60);
            let mut index = load();
            let held_bytes = std::fs::read(&path).unwrap();
            assert!(bound::held(&index, &key), "{case}: held");
            census_identity_clear(&mut index, &key, arming);
            assert!(bound::revoked(&index, &key), "{case}");
            assert!(bound::revoke_unsaved(&index, &key), "{case}");
            assert!(bound::held(&index, &key), "{case}: held until saved");
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                skipped,
                "{case}: never selected before the save"
            );
            drop(index);
            assert_eq!(std::fs::read(&path).unwrap(), held_bytes, "{case}");
            drop(clock);

            // The daemon's order: load, the arming while the scan is built,
            // the revoke saved, then selection.
            let clock = bound::set_now(N3_T0 + 120);
            let mut index = load();
            let mut committed = index.clone();
            assert!(
                bound::held(&index, &key),
                "{case}: the lost revoke left it held"
            );
            assert_eq!(bound::identity_revoked(&index), 0, "{case}");
            census_identity_clear(&mut index, &key, arming);
            assert!(bound::held(&index, &key), "{case}: held until saved");
            assert_eq!(bound::identity_revoked(&index), 1, "{case}");
            persist_duplicate_rebuild_revokes(&mut index, &mut committed, &path).unwrap();
            assert!(!bound::revoke_unsaved(&index, &key), "{case}");
            assert!(!bound::held(&index, &key), "{case}: saved, then released");
            assert_eq!(
                index.generation, committed.generation,
                "{case}: one CAS line"
            );
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                rearmed,
                "{case}: re-offered"
            );
            let saved = on_disk();
            let guard = &saved["claude_request_census_shadow"]["n"];
            assert!(
                guard["k"].get(&id).is_none(),
                "{case}: out of the bound's control"
            );
            assert!(guard["r"][&id].is_string(), "{case}: token saved");
            assert_eq!(guard["i"], serde_json::json!(1), "{case}: counted once");
            assert_eq!(
                saved["files"][&key]["source_file_fingerprint"],
                serde_json::json!(""),
                "{case}: the clear is saved"
            );
            // The read starts; the working index is then lost (a crash, or a
            // failed scan discarding it) before the post-scan save.
            note_duplicate_rebuild_started(&mut index, Path::new(&key));
            drop(index);
            drop(committed);
            drop(clock);

            for cycle in 1..=3_u64 {
                let case = format!("{case} cycle={cycle}");
                let _clock = bound::set_now(N3_T0 + 120 + 60 * cycle);
                let mut index = load();
                let mut committed = index.clone();
                assert!(!bound::held(&index, &key), "{case}: never held again");
                assert!(bound::revoked(&index, &key), "{case}: durable");
                assert_eq!(bound::identity_revoked(&index), 1, "{case}");
                // The same arming re-derived: no second revoke.
                let before = std::fs::read(&path).unwrap();
                census_identity_clear(&mut index, &key, arming);
                assert!(
                    !bound::revoke_unsaved(&index, &key),
                    "{case}: token consumed"
                );
                assert_eq!(bound::identity_revoked(&index), 1, "{case}: no second");
                assert_eq!(
                    census_rebuild_identity_revoked_line(&mut index),
                    1,
                    "{case}"
                );
                persist_duplicate_rebuild_revokes(&mut index, &mut committed, &path).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), before, "{case}: nothing new");
                assert_eq!(
                    census_rebuild_decision(&index, &key, &fingerprint),
                    rearmed,
                    "{case}: re-offered, still unread"
                );
                if cycle == 2 {
                    note_duplicate_rebuild_started(&mut index, Path::new(&key));
                }
            }

            // The read completes and is saved: never re-offered again.
            let _clock = bound::set_now(N3_T0 + 600);
            let mut index = load();
            census_scan(&root, &mut index, SECOND_WINDOW);
            assert_eq!(
                index.files[&key].source_file_fingerprint, fingerprint,
                "{case}: read once"
            );
            index.save(&path).unwrap();
            let index = load();
            assert_eq!(
                census_rebuild_decision(&index, &key, &fingerprint),
                skipped,
                "{case}: exactly one re-offer"
            );
            assert_eq!(bound::identity_revoked(&index), 1, "{case}: one in total");
        }
    }
}

/// SI-724-B3b: the "N3 initialized" marker, saved at the root beside the
/// shadow state from the first grant on, outlives a dropped guard. With `n`
/// and its witness, or the whole root shadow state, missing, or the marker
/// itself malformed (an isolated value defect), the guard is lost, never
/// fresh: recurring duplicates get no new grant, admission stays closed for
/// the window, counted and alarmed, the index kept. With no marker and no
/// other evidence the guard is fresh (control). After the window one counted
/// attempt is allowed. OFF and ON.
#[test]
fn census_duplicate_rebuild_marker_without_its_guard_is_lost() {
    use crate::snapshots::claude_request_census::{
        duplicate_rebuild_test_support as bound, persist_duplicate_rebuild_grants,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for loss in [
            "n_dropped",
            "root_shadow_dropped",
            "marker_malformed",
            "marker_overflow",
            "no_marker_control",
        ] {
            let case = format!("shadow={enabled} {loss}");
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-duplicate-rebuild-marker");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let path = scratch.join("index.json");
            std::fs::write(&path, census_duplicate_rebuild_raw(&original, &key, None)).unwrap();
            {
                bound::restart();
                let _clock = bound::set_now(N3_T0);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(census_rebuild_rearms(&index, &key, &fingerprint), "{case}");
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                assert_eq!(bound::marker(&index), N3_T0, "{case}: written by the grant");
            }
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                saved["claude_census_rebuild_initialized"],
                serde_json::json!(N3_T0),
                "{case}: saved"
            );
            // The recurring duplicate over a checkpoint with `shadow` (none:
            // the root field missing) and the raw marker `marker`.
            let renew = |shadow: Option<serde_json::Value>, marker: Option<&str>| {
                let mut value = serde_json::to_value(&original).unwrap();
                let rows = census_duplicate_rows(&value, &key);
                value["claude_request_census"] = serde_json::json!("DUPLICATE_CENSUS_FIXTURE");
                match shadow {
                    Some(shadow) => value["claude_request_census_shadow"] = shadow,
                    None => {
                        value
                            .as_object_mut()
                            .unwrap()
                            .remove("claude_request_census_shadow");
                    }
                }
                if marker.is_some() {
                    value["claude_census_rebuild_initialized"] = serde_json::json!("MARKER");
                }
                let raw = serde_json::to_string(&value)
                    .unwrap()
                    .replace("\"DUPLICATE_CENSUS_FIXTURE\"", &rows)
                    .replace("\"MARKER\"", marker.unwrap_or_default());
                std::fs::write(&path, raw).unwrap();
            };
            let mut shadow = saved["claude_request_census_shadow"].clone();
            shadow.as_object_mut().unwrap().remove("a");
            let marker = N3_T0.to_string();
            match loss {
                "n_dropped" | "no_marker_control" => {
                    let map = shadow.as_object_mut().unwrap();
                    map.remove("n").expect("guard saved");
                    map.remove("nw").expect("witness saved");
                    renew(
                        Some(shadow),
                        (loss == "n_dropped").then_some(marker.as_str()),
                    );
                }
                "root_shadow_dropped" => renew(None, Some(&marker)),
                "marker_malformed" => renew(Some(shadow), Some("\"x\"")),
                _ => renew(Some(shadow), Some("1e400")),
            }

            let refused_at = N3_T0 + 2 * N3_DAY;
            if loss == "no_marker_control" {
                bound::restart();
                let _clock = bound::set_now(refused_at);
                let index = ScanIndex::load(&path).unwrap();
                assert!(
                    census_rebuild_rearms(&index, &key, &fingerprint),
                    "{case}: fresh"
                );
                assert_eq!(bound::attempts(&index, &key), vec![refused_at]);
                continue;
            }
            let lost = !loss.starts_with("marker_");
            for (cycle, at) in [refused_at, refused_at + N3_DAY, refused_at + 4 * N3_DAY]
                .into_iter()
                .enumerate()
            {
                bound::restart();
                let _clock = bound::set_now(at);
                let mut index = ScanIndex::load(&path).unwrap();
                assert!(path.exists(), "{case}: never quarantined");
                assert!(
                    !census_rebuild_rearms(&index, &key, &fingerprint),
                    "{case} cycle {cycle}: no new grant"
                );
                assert!(bound::closed(&index), "{case}: closed, never fresh");
                assert_ne!(bound::marker(&index), u64::MAX, "{case}: rewritten present");
                assert_ne!(bound::marker(&index), 0, "{case}");
                if lost {
                    assert!(bound::attempts(&index, &key).is_empty(), "{case}");
                } else {
                    // The guard itself is intact; its one attempt stays.
                    assert_eq!(bound::attempts(&index, &key), vec![N3_T0], "{case}");
                }
                // The terminal emits the alarms the load queued.
                assert_eq!(
                    census_exhausted_counter(&mut index),
                    // Each renewed duplicate of the untracked key is refused;
                    // the tracked key is one exhausted key.
                    if lost { cycle as u64 + 1 } else { 1 },
                    "{case}"
                );
                if lost {
                    assert_eq!(census_rebuild_alarms(&key, "guard_lost"), 1, "{case}");
                    assert_eq!(
                        census_rebuild_alarms(&key, "guard_state_closed"),
                        cycle,
                        "{case}"
                    );
                } else {
                    assert_eq!(
                        census_rebuild_alarms(&key, "guard_state_closed"),
                        cycle + 1,
                        "{case}"
                    );
                }
                persist_duplicate_rebuild_grants(&mut index, &path).unwrap();
                index.save(&path).unwrap();
                let saved: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                let mut shadow = saved["claude_request_census_shadow"].clone();
                assert!(shadow["n"].is_object(), "{case}: the closure is saved");
                shadow.as_object_mut().unwrap().remove("a");
                let marker = saved["claude_census_rebuild_initialized"].to_string();
                renew(Some(shadow), Some(&marker));
            }
            bound::restart();
            let at = refused_at + 7 * N3_DAY + 1;
            let _clock = bound::set_now(at);
            let index = ScanIndex::load(&path).unwrap();
            assert!(
                census_rebuild_rearms(&index, &key, &fingerprint),
                "{case}: one counted attempt after the window"
            );
            assert_eq!(bound::attempts(&index, &key), vec![at], "{case}");
        }
    }
}

/// SI-724-B3b, item 3: a duplicated root field name follows the index-wide
/// policy (#718): every reader refuses, the index is kept byte for byte and
/// its source pauses; never a quarantine, never a default. The rebuild priors
/// and the "N3 initialized" marker, with bindings, ACKs and the contract-5
/// latch present, through a load, the bounded reader, a bounded CAS save
/// (`save_with_read_limit`) and a plain CAS save. Their value-level defects
/// stay isolated (`census_rebuild_priors_refusal_keeps_bindings_acks_and_latch`,
/// `census_duplicate_rebuild_marker_without_its_guard_is_lost`).
#[test]
fn census_rebuild_duplicated_root_fields_refuse_and_keep_the_index() {
    use crate::snapshots::claude_request_census::{
        decode_bounded_index, duplicate_rebuild_test_support as bound,
    };
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for field in [
            "claude_census_rebuild_priors",
            "claude_census_rebuild_initialized",
        ] {
            let case = format!("shadow={enabled} {field}");
            bound::restart();
            let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-duplicated-root");
            let (_root, original, key) = census_duplicate_rebuild_fixture(&scratch);
            let fingerprint = original.files[&key].source_file_fingerprint.clone();
            let mut value = serde_json::to_value(&original).unwrap();
            value["accepted_snapshot_fingerprints"] =
                serde_json::json!(["c".repeat(64), "d".repeat(64)]);
            value["session_account_bindings"] = serde_json::json!({
                ("f".repeat(64)): { "account_identifier_hash": "a".repeat(64) }
            });
            value["claude_request_identity_contract"] =
                serde_json::json!(crate::snapshots::claude_request_identity::COLLECTOR);
            value["claude_request_identity_contract_changed"] = serde_json::json!(true);
            let control_path = scratch.join("control.json");
            std::fs::write(&control_path, serde_json::to_string(&value).unwrap()).unwrap();
            let plain = ScanIndex::load(&control_path).unwrap();
            assert_eq!(plain.session_account_bindings.len(), 1, "{case}");
            assert!(plain.claude_request_identity_contract_changed, "{case}");
            let copy = if field == "claude_census_rebuild_priors" {
                serde_json::json!({ (bound::key_id(&key)): fingerprint }).to_string()
            } else {
                N3_T0.to_string()
            };
            value[field] = serde_json::json!("DUPLICATE_ROOT_FIELD");
            let raw = serde_json::to_string(&value).unwrap().replace(
                "\"DUPLICATE_ROOT_FIELD\"",
                &format!("{copy},\"{field}\":{copy}"),
            );
            let path = scratch.join("index.json");
            std::fs::write(&path, &raw).unwrap();
            // A quarantine would leave a `.corrupt.` sibling.
            let quarantined = || {
                std::fs::read_dir(scratch.as_ref())
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
                    .count()
            };
            assert!(ScanIndex::load(&path).is_err(), "{case}: load refused");
            assert!(
                decode_bounded_index(raw.as_bytes()).is_err(),
                "{case}: bounded reader refused"
            );
            assert!(
                plain
                    .clone()
                    .save_with_read_limit(&path, 64 * 1024 * 1024)
                    .is_err(),
                "{case}: bounded CAS refused"
            );
            assert!(plain.clone().save(&path).is_err(), "{case}: CAS refused");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), raw, "{case}: kept");
            assert_eq!(quarantined(), 0, "{case}: never quarantined");
        }
    }
}

/// #718 composition: the N3 state (a current grant, or identity's revoke of an
/// earlier checkpoint's hold; the witness and marker) reads the same through
/// a load and the bounded CAS reader, and persists through a plain and a
/// bounded CAS save; a duplicated shadow state closes the guard in both
/// readers (never a fresh default) and stays closed through both saves. An
/// independent rearm of another key stays visible throughout. OFF and ON.
#[test]
fn census_duplicate_rebuild_state_reads_alike_through_load_and_bounded_cas() {
    use crate::snapshots::claude_request_census::{
        decode_bounded_index, duplicate_rebuild_test_support as bound, SourceRearm,
    };
    let rearmed = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::Rearmed),
    );
    for enabled in [false, true] {
        let _mode = crate::snapshots::claude_request_census::d2_shadow_mode_for_test(enabled);
        for state in ["grant", "revoked", "duplicated_shadow"] {
            for save in ["plain", "bounded"] {
                let case = format!("shadow={enabled} {state} {save}");
                bound::restart();
                let scratch = crate::test_scratch::ScratchDir::new("census-rebuild-cas-alike");
                let (root, original, key) = census_duplicate_rebuild_fixture(&scratch);
                let healthy = census_key(&original, &root, "healthy.jsonl");
                let healthy_fp = original.files[&healthy].source_file_fingerprint.clone();
                let fingerprint = original.files[&key].source_file_fingerprint.clone();
                let path = scratch.join("index.json");
                let mut saved = census_rebuild_saved_grant(&path, &original, &key);
                if state == "revoked" {
                    bound::hold_earlier_form(&mut saved, &key, [N3_T0, N3_T0 + 30]);
                }
                let mut raw = serde_json::to_string(&saved).unwrap();
                if state == "duplicated_shadow" {
                    let shadow =
                        serde_json::to_string(&saved["claude_request_census_shadow"]).unwrap();
                    saved["claude_request_census_shadow"] = serde_json::json!("DUPLICATE_SHADOW");
                    raw = serde_json::to_string(&saved).unwrap().replace(
                        "\"DUPLICATE_SHADOW\"",
                        &format!("{shadow},\"claude_request_census_shadow\":{shadow}"),
                    );
                }
                std::fs::write(&path, &raw).unwrap();
                bound::restart();
                let _clock = bound::set_now(N3_T0 + 60);
                let mut index = ScanIndex::load(&path).unwrap();
                if state == "revoked" {
                    assert!(bound::held(&index, &key), "{case}");
                    census_identity_clear(
                        &mut index,
                        &key,
                        SourceRearm::Identity("identity_contract:test"),
                    );
                }
                // The independent control.
                census_identity_clear(
                    &mut index,
                    &healthy,
                    SourceRearm::Other("independent_rearm_control"),
                );
                let first = serde_json::to_value(&index.claude_request_census_shadow).unwrap();
                let bounded_first = decode_bounded_index(raw.as_bytes()).unwrap();
                if state != "revoked" {
                    assert_eq!(
                        serde_json::to_value(&bounded_first.claude_request_census_shadow).unwrap(),
                        first,
                        "{case}: one decode of the same bytes"
                    );
                }
                match save {
                    "plain" => index.save(&path).unwrap(),
                    _ => index.save_with_read_limit(&path, 64 * 1024 * 1024).unwrap(),
                }
                let bytes = std::fs::read(&path).unwrap();
                bound::restart();
                let loaded = ScanIndex::load(&path).unwrap();
                let bounded = decode_bounded_index(&bytes).unwrap();
                for (reader, index) in [("load", &loaded), ("bounded", &bounded)] {
                    let case = format!("{case} {reader}");
                    assert_eq!(
                        index.source_fingerprint_decision(
                            &healthy,
                            &index.files[&healthy],
                            &healthy_fp
                        ),
                        rearmed,
                        "{case}: the independent rearm stays"
                    );
                    match state {
                        "grant" => {
                            assert_eq!(
                                bound::attempts(index, &key).first(),
                                Some(&N3_T0),
                                "{case}"
                            );
                            assert_eq!(bound::marker(index), N3_T0, "{case}");
                            assert!(bound::witness(index) >= N3_T0, "{case}");
                            assert!(!bound::closed(index), "{case}");
                        }
                        "revoked" => {
                            assert!(!bound::held(index, &key), "{case}");
                            assert!(bound::revoked(index, &key), "{case}");
                            assert_eq!(bound::identity_revoked(index), 1, "{case}");
                            assert_eq!(
                                census_rebuild_decision(index, &key, &fingerprint),
                                rearmed,
                                "{case}"
                            );
                        }
                        _ => {
                            assert!(bound::closed(index), "{case}: closed, never default");
                            assert!(bound::attempts(index, &key).is_empty(), "{case}");
                            assert!(!census_rebuild_rearms(index, &key, &fingerprint), "{case}");
                        }
                    }
                }
                assert_eq!(
                    serde_json::to_value(&loaded.claude_request_census_shadow).unwrap(),
                    serde_json::to_value(&bounded.claude_request_census_shadow).unwrap(),
                    "{case}: both readers agree"
                );
                assert_eq!(
                    loaded.claude_census_rebuild_initialized,
                    bounded.claude_census_rebuild_initialized,
                    "{case}"
                );
            }
        }
    }
}

/// SI-724-B1b: the shared identity-clear path is the only place that clears
/// a source fingerprint outside tests. A new clear fails here until it routes
/// through `rearm_source_fingerprint` and is classified below: identity work
/// (revokes an earlier checkpoint's N3 hold, once per arming) or not.
#[test]
fn every_source_fingerprint_clear_uses_the_identity_path() {
    fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    let mut clears = BTreeMap::new();
    let mut identity = BTreeMap::new();
    let mut other = BTreeMap::new();
    for path in files {
        let name = path
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // Inline unit tests follow the production code.
        let production = text
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap_or_default();
        for (map, needle) in [
            (&mut clears, ".source_file_fingerprint.clear()"),
            (&mut identity, "SourceRearm::Identity("),
            (&mut other, "SourceRearm::Other("),
        ] {
            let count = production.matches(needle).count();
            if count > 0 {
                map.insert(name.clone(), count);
            }
        }
    }
    assert_eq!(
        clears,
        BTreeMap::from([
            // The shared path itself.
            ("snapshots/claude_request_census.rs".to_string(), 1),
            // A `#[cfg(test)]` experiment module, absent from builds.
            ("snapshots/envelope_selection_experiment.rs".to_string(), 2),
        ]),
        "a source fingerprint clear outside rearm_source_fingerprint"
    );
    assert_eq!(
        identity,
        BTreeMap::from([
            // Contract-5/family proof re-arm, family correction, legacy
            // witness, owned start, stale-family uncarry, cancel, rewind
            // (two) and stale-pending re-arm.
            ("snapshots.rs".to_string(), 9),
            // The shared path's own dispatch.
            ("snapshots/claude_request_census.rs".to_string(), 1),
        ]),
        "classify the new identity-clear site"
    );
    assert_eq!(
        other,
        BTreeMap::from([
            // Carried re-parse debt through local-hold reverts (two) and the
            // settled-subset save.
            ("snapshots.rs".to_string(), 3),
            // A repair of damaged authority state.
            ("snapshots/authority_proof_correction.rs".to_string(), 1),
            // A native comparison recovery re-read.
            (
                "snapshots/claude_native_comparison/settlement.rs".to_string(),
                1
            ),
        ]),
        "classify the new non-identity clear site"
    );
}
