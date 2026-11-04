// Durable Claude request-census records and the shadow predicate.
// Records are produced, persisted and measured; no decision reads
// them. All fixtures are synthetic and content-free.
use super::*;
use crate::snapshots::claude_request_census::{
    claude_census_member_status, claude_request_hash, ClaudeCensusMemberStatus,
    ClaudeRequestCensusRecord, ClaudeRequestCensusShape, CLAUDE_REQUEST_CENSUS_CANARY,
    CLAUDE_REQUEST_CENSUS_DERIVATION,
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

/// The canary corpus: every shape class the parser can give a
/// Claude record, under a fixed name each. Not covered (see the PR):
/// multi-item files (a Claude file yields at most one item).
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
    // A large valid line must preserve census completeness.
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
            census_user_line("canary-over-line-cap", &"x".repeat(16_777_216 + 1024)),
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
        ("canary-over-line-cap.jsonl", "exact", vec!["req_cap_1"]),
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

/// TD1f: a re-parse of a previously complete key
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

/// A transcript of zero-usage responses only (API errors) yields no item, yet
/// its request ids still reach the census and meet a peer's copy.
#[test]
fn census_records_keep_ids_of_zero_usage_only_transcripts() {
    let scratch = crate::test_scratch::ScratchDir::new("census-zero-usage-only");
    let root = scratch.join("projects");
    // [money] Observed shape: one ID-bearing zero and eight unflagged,
    // synthetic ID-less zeros. The available overlap ID must survive.
    let mut errors = vec![census_response(
        "census-api-errors",
        Some("req_shared_err"),
        "msg_err_1",
        1,
        0,
    )];
    for second in 2..=9 {
        let mut row: serde_json::Value = serde_json::from_str(&census_response(
            "census-api-errors",
            None,
            &format!("msg_err_{second}"),
            second,
            0,
        ))
        .unwrap();
        row["message"]["model"] = serde_json::json!("<synthetic>");
        errors.push(format!("{row}\n"));
    }
    census_write(&root, "census-api-errors.jsonl", &errors);
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

/// Literal tokens matter: Value cannot represent the overflow that regressed
/// load and the compare-and-swap reader. Compare every other persisted field.
#[test]
fn census_numeric_overflow_is_isolated_from_load_and_cas() {
    let scratch = crate::test_scratch::ScratchDir::new("census-overflow");
    let mut base = census_index_json(serde_json::json!({}));
    base["generation"] = serde_json::json!(7);
    let expected = base.clone();
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

/// [money] The v1 reader never refuses a census for its size: a census field
/// past the old 49 MiB raw-evidence limit (here one record padded with an
/// unknown field) loads whole, and the CAS save reads it again.
#[test]
fn census_past_the_old_raw_byte_limit_loads_whole() {
    use std::io::Write;
    const OLD_RAW_LIMIT: usize = 49 * 1024 * 1024;
    let scratch = crate::test_scratch::ScratchDir::new("census-past-raw-limit");
    let path = scratch.join("large.json");
    let base = census_index_json(serde_json::json!({}));
    let mut file = std::fs::File::create(&path).unwrap();
    let json = serde_json::to_string(&base).unwrap();
    let marker = "\"claude_request_census\":{}";
    let (before, after) = json.split_once(marker).expect("census field");
    let small = census_record_json('b', "exact", &[2]);
    let big = census_record_json('a', "exact", &[1]).to_string();
    let open = big.strip_suffix('}').expect("record object");
    write!(
        file,
        "{before}\"claude_request_census\":{{\"big\":{open},\"pad\":\""
    )
    .unwrap();
    // Write the padding without constructing it in the test process.
    let block = [b'x'; 8192];
    for _ in 0..=OLD_RAW_LIMIT / block.len() {
        file.write_all(&block).unwrap();
    }
    write!(file, "\"}},\"small\":{small}}}{after}").unwrap();
    drop(file);
    let mut loaded = ScanIndex::load(&path).expect("a large census loads");
    assert_eq!(loaded.files.len(), 1);
    let census = loaded.claude_request_census_for_test();
    assert_eq!(
        census.keys_for_test(),
        vec!["big".to_string(), "small".to_string()]
    );
    assert_eq!(census.get("big").unwrap().request_hashes_for_test(), &[1]);
    assert_eq!(census.hash_total_for_test(), 2);
    loaded
        .save(&path)
        .expect("the CAS reads the large census too");
}

/// A pre-census shape has no census fields: IgnoredAny consumes their tokens,
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
        None,
        &[],
        false,
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
