// E2 (I1): the real evidence stage (`apply_claude_local_evidence_to_scan_*`)
// with the gate on. Emission runs before contract 5 and D1, so the existing
// identity owners tag the final request-owned rows; a failed telemetry read
// never yields a complete body and withholds nothing. Fixtures are synthetic.
use super::*;

const E2_CHILD: &str = "a4d1585d310070d0f";

fn e2_account() -> String {
    "a".repeat(64)
}

fn e2_write_rows<T: Serialize>(support: &Path, dir: &str, root: &str, rows: &[T]) {
    let path = support
        .join(dir)
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}

/// The family fixture's API rows (req_5 is the child's) and trace rows.
fn e2_family_evidence(
    root: &str,
) -> (
    Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>,
    Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>,
) {
    let api = (1..=5)
        .map(|i| {
            complete_api_row(
                root,
                &format!("req_{i}"),
                i,
                10,
                if i == 5 { 1 } else { 10 },
                0,
            )
        })
        .collect();
    let trace = (1..=5)
        .map(|i| {
            complete_trace_row(
                root,
                &format!("req_{i}"),
                if i == 5 { E2_CHILD } else { "" },
            )
        })
        .collect();
    (api, trace)
}

/// One real scan of `dirs` plus the evidence stage, all under the gate.
fn e2_page(
    dirs: &[PathBuf],
    support: &Path,
    index: &mut ScanIndex,
) -> (Vec<SnapshotItem>, ClaudeUsageAuthorityDisposition, bool) {
    let (items, disposition, failed, _) = e2_page_counted(dirs, support, index);
    (items, disposition, failed)
}

/// `e2_page` plus the page identity counters `finish_page` recorded (read
/// before the emitted folds they derive from are released).
fn e2_page_counted(
    dirs: &[PathBuf],
    support: &Path,
    index: &mut ScanIndex,
) -> (
    Vec<SnapshotItem>,
    ClaudeUsageAuthorityDisposition,
    bool,
    serde_json::Value,
) {
    claude_request_money::e2::with_enabled(|| {
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            dirs,
            index,
            "2026-08-02T07:10:00Z",
            7,
            100,
            false,
        )
        .unwrap();
        claude_request_identity::retain_root_accounts(
            &mut scan.snapshots,
            index,
            "e2-identity-machine",
        );
        let ((disposition, _, stats), counts) =
            claude_request_money::e2::pipeline_test_observer::capture_identity_counts(|| {
                crate::snapshot_sync::apply_claude_local_evidence_to_scan(support, &mut scan, index)
            });
        (
            scan.snapshots,
            disposition,
            stats.effort_evidence_load_failed,
            counts,
        )
    })
}

fn e2_rows(item: &SnapshotItem) -> impl Iterator<Item = &SnapshotModelUsage> {
    item.model_usage.iter().chain(
        item.usage_buckets
            .iter()
            .flat_map(|bucket| &bucket.model_usage),
    )
}

fn e2_is_literal(item: &SnapshotItem) -> bool {
    item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_USAGE_CONTRACT)
}

/// Every evidence ref names an entry the item carries, and no row names an
/// account other than the one login of the fixture.
fn e2_assert_identity_consistent(item: &SnapshotItem, label: &str) {
    let account = e2_account();
    for row in e2_rows(item) {
        assert!(
            row.account_identifier_hash
                .as_deref()
                .map_or(true, |hash| hash == account),
            "{label}: facts never move to another account"
        );
        if let Some(evidence_ref) = row.evidence_ref {
            assert!(
                (evidence_ref as usize) < item.request_evidence.len(),
                "{label}: every evidence ref stays resolvable"
            );
        }
    }
}

#[test]
fn e2_pipeline_tags_the_final_root_and_agent_rows() {
    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (api, trace) = e2_family_evidence(&root);
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    {
        let mut index = ScanIndex::default();
        let (items, disposition, read_failed) =
            e2_page(std::slice::from_ref(&dir), &support, &mut index);
        assert!(!read_failed);
        let root_item = items
            .iter()
            .find(|item| item.source_session_id == root)
            .expect("root body");
        let child = items
            .iter()
            .find(|item| item.source_session_id != root)
            .expect("child body");
        for (item, requests, label) in [(root_item, 4, "root"), (child, 1, "agent")] {
            // Tagging after emission: an item tagged first would be refused.
            assert!(e2_is_literal(item), "{label}");
            assert_eq!(item.request_count, requests, "{label}: own requests only");
            e2_assert_identity_consistent(item, label);
            assert!(
                e2_rows(item).all(|row| row.account_identifier_hash == Some(e2_account())),
                "{label}: the one proven login tags every final row"
            );
        }
        assert_eq!(disposition.quarantined_entity_count(), 0);
        let mut uploadable = items.clone();
        disposition.retain_uploadable(&mut uploadable);
        assert_eq!(uploadable.len(), items.len(), "nothing is withheld");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_e2_pipeline_tags_the_final_root_and_agent_rows() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (api, trace) = e2_family_evidence(&root);
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    {
        let mut index = ScanIndex::default();
        let (items, disposition, read_failed) =
            e2_page(std::slice::from_ref(&dir), &support, &mut index);
        assert!(!read_failed);
        let root_item = items
            .iter()
            .find(|item| item.source_session_id == root)
            .expect("root body");
        let child = items
            .iter()
            .find(|item| item.source_session_id != root)
            .expect("child body");
        for (item, requests, label) in [(root_item, 4, "root"), (child, 1, "agent")] {
            // Tagging after emission: an item tagged first would be refused.
            assert!(e2_is_literal(item), "{label}");
            assert_eq!(item.request_count, requests, "{label}: own requests only");
            e2_assert_identity_consistent(item, label);
            assert!(
                e2_rows(item).all(|row| row.account_identifier_hash == Some(e2_account())),
                "{label}: the one proven login tags every final row"
            );
        }
        assert_eq!(disposition.quarantined_entity_count(), 0);
        let mut uploadable = items.clone();
        disposition.retain_uploadable(&mut uploadable);
        assert_eq!(uploadable.len(), items.len(), "nothing is withheld");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn e2_pipeline_tags_a_copied_transcript_once() {
    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (api, trace) = e2_family_evidence(&root);
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    // The copy lives under another project directory and is born later.
    let original = dir.join(format!("{root}.jsonl"));
    let copy_dir = temp_dir("e2-identity-copy");
    let copy = copy_dir.join(format!("{root}.jsonl"));
    std::thread::sleep(std::time::Duration::from_millis(20));
    // APFS copy/clone may preserve the original birth. Write a new file:
    // this fixture specifically requires a physically later-born twin.
    fs::write(&copy, fs::read(&original).unwrap()).unwrap();
    let births_known = match (
        fs::metadata(&original).and_then(|m| m.created()),
        fs::metadata(&copy).and_then(|m| m.created()),
    ) {
        (Ok(original_birth), Ok(copy_birth)) => {
            assert!(
                copy_birth > original_birth,
                "the copy fixture must be born later"
            );
            true
        }
        _ => false,
    };
    let dirs = [dir.clone(), copy_dir.clone()];
    let mut index = ScanIndex::default();
    // The first page may meet the twins in either order (disclosed residual).
    e2_page(&dirs, &support, &mut index);
    // The copy continues on its own (one known writer): the twin family is
    // re-read together and the copied history is skipped.
    let mut own: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&copy).unwrap().lines().next().unwrap()).unwrap();
    own["requestId"] = json!("req_own");
    own["version"] = json!("2.1.309");
    own["timestamp"] = json!(OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap());
    let mut file = fs::OpenOptions::new().append(true).open(&copy).unwrap();
    writeln!(file, "{own}").unwrap();
    drop(file);
    let (items, disposition, _) = e2_page(&dirs, &support, &mut index);
    let roots = items
        .iter()
        .filter(|item| item.source_session_id == root)
        .collect::<Vec<_>>();
    for item in &roots {
        e2_assert_identity_consistent(item, "copy");
    }
    if births_known {
        assert_eq!(roots.len(), 1, "one summed body per session");
        let body = roots[0];
        assert!(e2_is_literal(body));
        assert_eq!(body.request_count, 5, "original four plus the copy's own");
        assert_eq!(body.removed_request_count, Some(4), "copied history once");
        assert_eq!(disposition.quarantined_entity_count(), 0);
    } else {
        writeln!(
            std::io::stderr().lock(),
            "e2_pipeline_copy: file birth unavailable on this filesystem; copy rule UNEXECUTED"
        )
        .unwrap();
    }
    fs::remove_dir_all(copy_dir).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_e2_pipeline_tags_a_copied_transcript_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (api, trace) = e2_family_evidence(&root);
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    // The copy lives under another project directory and is born later.
    let original = dir.join(format!("{root}.jsonl"));
    let copy_dir = temp_dir("e2-identity-copy");
    let copy = copy_dir.join(format!("{root}.jsonl"));
    std::thread::sleep(std::time::Duration::from_millis(20));
    // APFS copy/clone may preserve the original birth. Write a new file:
    // this fixture specifically requires a physically later-born twin.
    fs::write(&copy, fs::read(&original).unwrap()).unwrap();
    let births_known = match (
        fs::metadata(&original).and_then(|m| m.created()),
        fs::metadata(&copy).and_then(|m| m.created()),
    ) {
        (Ok(original_birth), Ok(copy_birth)) => {
            assert!(
                copy_birth > original_birth,
                "the copy fixture must be born later"
            );
            true
        }
        _ => false,
    };
    let dirs = [dir.clone(), copy_dir.clone()];
    let mut index = ScanIndex::default();
    // The first page may meet the twins in either order (disclosed residual).
    e2_page(&dirs, &support, &mut index);
    // The copy continues on its own (one known writer): the twin family is
    // re-read together and the copied history is skipped.
    let mut own: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&copy).unwrap().lines().next().unwrap()).unwrap();
    own["requestId"] = json!("req_own");
    own["version"] = json!("2.1.309");
    own["timestamp"] = json!(OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap());
    let mut file = fs::OpenOptions::new().append(true).open(&copy).unwrap();
    writeln!(file, "{own}").unwrap();
    drop(file);
    // Explicitly service discovery of the copy append at this fixed clock.
    expire_terminal_off_discovery_for_test(&index);
    let (items, disposition, _) = e2_page(&dirs, &support, &mut index);
    let roots = items
        .iter()
        .filter(|item| item.source_session_id == root)
        .collect::<Vec<_>>();
    for item in &roots {
        e2_assert_identity_consistent(item, "copy");
    }
    if births_known {
        assert_eq!(roots.len(), 1, "one summed body per session");
        let body = roots[0];
        assert!(e2_is_literal(body));
        assert_eq!(body.request_count, 5, "original four plus the copy's own");
        assert_eq!(body.removed_request_count, Some(4), "copied history once");
        assert_eq!(disposition.quarantined_entity_count(), 0);
    } else {
        writeln!(
            std::io::stderr().lock(),
            "e2_pipeline_copy: file birth unavailable on this filesystem; copy rule UNEXECUTED"
        )
        .unwrap();
    }
    fs::remove_dir_all(copy_dir).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn e2_pipeline_telemetry_read_failure_is_never_complete_and_withholds_nothing() {
    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (_, trace) = e2_family_evidence(&root);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    // A directory where the API sidecar should be: the read fails as a whole.
    fs::create_dir_all(
        support
            .join(crate::claude_local_otel::STORE_DIR)
            .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes()))),
    )
    .unwrap();
    let mut index = ScanIndex::default();
    let (items, disposition, read_failed) =
        e2_page(std::slice::from_ref(&dir), &support, &mut index);
    assert!(read_failed, "the fixture really fails the telemetry read");
    let literal = items.iter().filter(|item| e2_is_literal(item)).count();
    assert_eq!(literal, 2, "live bodies still emit, as estimates");
    for item in &items {
        assert_eq!(item.telemetry_owned_complete, Some(false));
        assert!(item.cost.is_none(), "no telemetry cost without a read");
        e2_assert_identity_consistent(item, "failed read");
    }
    assert_eq!(
        items.iter().map(|item| item.request_count).sum::<u64>(),
        5,
        "transcript requests still count"
    );
    let mut uploadable = items.clone();
    disposition.retain_uploadable(&mut uploadable);
    assert_eq!(
        uploadable.len(),
        items.len(),
        "live bodies are not withheld"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_e2_pipeline_telemetry_read_failure_is_never_complete_and_withholds_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (_, trace) = e2_family_evidence(&root);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    // A directory where the API sidecar should be: the read fails as a whole.
    fs::create_dir_all(
        support
            .join(crate::claude_local_otel::STORE_DIR)
            .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes()))),
    )
    .unwrap();
    let mut index = ScanIndex::default();
    let (items, disposition, read_failed) =
        e2_page(std::slice::from_ref(&dir), &support, &mut index);
    assert!(read_failed, "the fixture really fails the telemetry read");
    let literal = items.iter().filter(|item| e2_is_literal(item)).count();
    assert_eq!(literal, 2, "live bodies still emit, as estimates");
    for item in &items {
        assert_eq!(item.telemetry_owned_complete, Some(false));
        assert!(item.cost.is_none(), "no telemetry cost without a read");
        e2_assert_identity_consistent(item, "failed read");
    }
    assert_eq!(
        items.iter().map(|item| item.request_count).sum::<u64>(),
        5,
        "transcript requests still count"
    );
    let mut uploadable = items.clone();
    disposition.retain_uploadable(&mut uploadable);
    assert_eq!(
        uploadable.len(),
        items.len(),
        "live bodies are not withheld"
    );
    fs::remove_dir_all(dir).unwrap();
}

fn e2_resign(row: &mut crate::claude_local_otel::ClaudeLocalOtelEvidence) {
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(row).unwrap())
    );
}

fn e2_login_counts(item: &SnapshotItem) -> BTreeMap<Option<String>, u64> {
    let mut counts = BTreeMap::new();
    for row in item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
    {
        if let Some(parts) = &row.identity_parts {
            for part in parts {
                *counts
                    .entry(part.account_identifier_hash.clone())
                    .or_default() += part.request_count;
            }
        } else {
            *counts
                .entry(row.account_identifier_hash.clone())
                .or_default() += row.request_count;
        }
    }
    counts
}

#[test]
fn e2_pipeline_root_and_child_keep_independent_own_telemetry_logins() {
    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (mut api, trace) = e2_family_evidence(&root);
    api[4].account_identifier_hash = Some("b".repeat(64));
    e2_resign(&mut api[4]);
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    let (items, disposition, failed) = e2_page(
        std::slice::from_ref(&dir),
        &support,
        &mut ScanIndex::default(),
    );
    assert!(!failed);
    assert_eq!(items.len(), 2);
    for item in &items {
        assert!(e2_is_literal(item));
        let (login, requests) = if item.source_session_id == root {
            ("a", 4)
        } else {
            ("b", 1)
        };
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(Some(login.repeat(64)), requests)])
        );
    }
    assert_eq!(disposition.quarantined_entity_count(), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_e2_pipeline_root_and_child_keep_independent_own_telemetry_logins() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (mut api, trace) = e2_family_evidence(&root);
    api[4].account_identifier_hash = Some("b".repeat(64));
    e2_resign(&mut api[4]);
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    let (items, disposition, failed) = e2_page(
        std::slice::from_ref(&dir),
        &support,
        &mut ScanIndex::default(),
    );
    assert!(!failed);
    assert_eq!(items.len(), 2);
    for item in &items {
        assert!(e2_is_literal(item));
        let (login, requests) = if item.source_session_id == root {
            ("a", 4)
        } else {
            ("b", 1)
        };
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(Some(login.repeat(64)), requests)])
        );
    }
    assert_eq!(disposition.quarantined_entity_count(), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn e2_pipeline_markerless_a_to_b_keeps_own_logins_with_and_without_a_binding() {
    for (bound, partial) in [(false, false), (true, false), (false, true), (true, true)] {
        let (dir, root, _) = claude_account_family_fixture();
        let support = dir.join("support");
        let (mut api, trace) = e2_family_evidence(&root);
        for row in &mut api[2..4] {
            row.account_identifier_hash = Some("b".repeat(64));
            e2_resign(row);
        }
        if partial {
            api.retain(|row| row.request_id != "req_2" && row.request_id != "req_4");
        }
        e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
        e2_write_rows(
            &support,
            "local-otel/claude-code-trace-ownership",
            &root,
            &trace,
        );
        let mut index = ScanIndex::default();
        if bound {
            index.session_account_bindings.insert(
                sha256_hex(&["session_owner:v1", "e2-identity-machine", &root]),
                SessionAccountBinding {
                    account_identifier_hash: e2_account(),
                    workspace_identifier_hash: None,
                },
            );
        }
        let (items, disposition, failed, counts) =
            e2_page_counted(std::slice::from_ref(&dir), &support, &mut index);
        assert!(!failed);
        let item = items
            .iter()
            .find(|item| item.source_session_id == root)
            .unwrap();
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(Some(e2_account()), 2), (Some("b".repeat(64)), 2)]),
            "bound={bound}"
        );
        assert_eq!(item.request_count, 4);
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some(if partial { "0.0002" } else { "0.0004" })
        );
        if partial {
            assert_eq!(
                counts["claude_inherited_org_requests"], 2,
                "missing requests inherit A then B, counted"
            );
        } else {
            assert!(
                counts.get("claude_inherited_org_requests").is_none(),
                "own evidence needs no fill: {counts}"
            );
        }
        assert!(
            counts.get("claude_identity_conflict_fallbacks").is_none(),
            "no conflict: {counts}"
        );
        assert_eq!(disposition.quarantined_entity_count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn terminal_off_on_e2_pipeline_markerless_a_to_b_keeps_own_logins_with_and_without_a_binding() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for (bound, partial) in [(false, false), (true, false), (false, true), (true, true)] {
        let (dir, root, _) = claude_account_family_fixture();
        let support = dir.join("support");
        let (mut api, trace) = e2_family_evidence(&root);
        for row in &mut api[2..4] {
            row.account_identifier_hash = Some("b".repeat(64));
            e2_resign(row);
        }
        if partial {
            api.retain(|row| row.request_id != "req_2" && row.request_id != "req_4");
        }
        e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
        e2_write_rows(
            &support,
            "local-otel/claude-code-trace-ownership",
            &root,
            &trace,
        );
        let mut index = ScanIndex::default();
        if bound {
            index.session_account_bindings.insert(
                sha256_hex(&["session_owner:v1", "e2-identity-machine", &root]),
                SessionAccountBinding {
                    account_identifier_hash: e2_account(),
                    workspace_identifier_hash: None,
                },
            );
        }
        let (items, disposition, failed, counts) =
            e2_page_counted(std::slice::from_ref(&dir), &support, &mut index);
        assert!(!failed);
        let item = items
            .iter()
            .find(|item| item.source_session_id == root)
            .unwrap();
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(Some(e2_account()), 2), (Some("b".repeat(64)), 2)]),
            "bound={bound}"
        );
        assert_eq!(item.request_count, 4);
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some(if partial { "0.0002" } else { "0.0004" })
        );
        if partial {
            assert_eq!(
                counts["claude_inherited_org_requests"], 2,
                "missing requests inherit A then B, counted"
            );
        } else {
            assert!(
                counts.get("claude_inherited_org_requests").is_none(),
                "own evidence needs no fill: {counts}"
            );
        }
        assert!(
            counts.get("claude_identity_conflict_fallbacks").is_none(),
            "no conflict: {counts}"
        );
        assert_eq!(disposition.quarantined_entity_count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn e2_pipeline_exact_telemetry_over_cap_refuses_upstream_lost_proof() {
    let dir = temp_dir("e2-identity-telemetry-cap");
    let root = "1449b91b-f36e-4cbc-a5bb-50fc66430ba5";
    let support = dir.join("support");
    let mut lines = String::new();
    let mut api = Vec::new();
    let mut trace = Vec::new();
    for n in 1..=17 {
        let request = format!("req_{n}");
        lines.push_str(&format!("{}\n", json!({
            "timestamp": format!("2026-08-02T07:00:{n:02}Z"), "type": "assistant",
            "sessionId": root, "requestId": request,
            "message": {"id": format!("msg_{n}"), "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 10}}
        })));
        let mut row = complete_api_row(root, &request, n, 10, 10, 0);
        row.account_identifier_hash = Some(format!("{n:064x}"));
        e2_resign(&mut row);
        api.push(row);
        trace.push(complete_trace_row(root, &request, ""));
    }
    fs::write(dir.join(format!("{root}.jsonl")), lines).unwrap();
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        root,
        &trace,
    );
    let (items, disposition, failed, counts) = e2_page_counted(
        std::slice::from_ref(&dir),
        &support,
        &mut ScanIndex::default(),
    );
    assert!(!failed);
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert!(e2_is_literal(item));
    assert_eq!(item.request_count, 17);
    assert_eq!(
        e2_login_counts(item),
        BTreeMap::from([(None, 17)]),
        "SOURCE: lost seventeenth-key proof cannot borrow the starting or sixteenth login"
    );
    assert_eq!(
        item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("0.0017")
    );
    let display = item.claude_account_display.as_deref().unwrap();
    assert_eq!(display.current.status, "unknown");
    assert_eq!(display.current.account_identifier_hash, None);
    assert_eq!(display.current.unknown_reason.as_deref(), Some("identity_withheld"));
    assert_eq!(item.request_identity_refusals, 1);
    assert_eq!(counts["claude_identity_conflict_fallbacks"], 1);
    assert_eq!(disposition.quarantined_entity_count(), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn terminal_off_on_e2_pipeline_exact_telemetry_over_cap_uses_the_existing_counted_start_fallback() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let dir = temp_dir("e2-identity-telemetry-cap");
    let root = "1449b91b-f36e-4cbc-a5bb-50fc66430ba5";
    let support = dir.join("support");
    let mut lines = String::new();
    let mut api = Vec::new();
    let mut trace = Vec::new();
    for n in 1..=17 {
        let request = format!("req_{n}");
        lines.push_str(&format!("{}\n", json!({
            "timestamp": format!("2026-08-02T07:00:{n:02}Z"), "type": "assistant",
            "sessionId": root, "requestId": request,
            "message": {"id": format!("msg_{n}"), "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 10}}
        })));
        let mut row = complete_api_row(root, &request, n, 10, 10, 0);
        row.account_identifier_hash = Some(format!("{n:064x}"));
        e2_resign(&mut row);
        api.push(row);
        trace.push(complete_trace_row(root, &request, ""));
    }
    fs::write(dir.join(format!("{root}.jsonl")), lines).unwrap();
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        root,
        &trace,
    );
    let (items, disposition, failed, counts) = e2_page_counted(
        std::slice::from_ref(&dir),
        &support,
        &mut ScanIndex::default(),
    );
    assert!(!failed);
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert!(e2_is_literal(item));
    assert_eq!(item.request_count, 17);
    assert_eq!(
        e2_login_counts(item),
        BTreeMap::from([(Some(format!("{:064x}", 1)), 17)]),
        "bounded fallback uses the start, never the sixteenth login"
    );
    assert_eq!(
        item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("0.0017")
    );
    let display = item.claude_account_display.as_deref().unwrap();
    assert_eq!(display.current.status, "known");
    assert_eq!(
        display.current.account_identifier_hash,
        Some(format!("{:064x}", 1))
    );
    assert_eq!(counts["claude_identity_conflict_fallbacks"], 1);
    assert_eq!(disposition.quarantined_entity_count(), 0);
    fs::remove_dir_all(dir).unwrap();
}

/// The real evidence stage with the gate on, returning its evidence counters.
fn e2_page_with_stats(
    dir: &Path,
    support: &Path,
) -> (
    Vec<SnapshotItem>,
    ClaudeUsageAuthorityDisposition,
    crate::snapshot_sync::ClaudeLocalEvidenceStats,
) {
    claude_request_money::e2::with_enabled(|| {
        let mut index = ScanIndex::default();
        let mut scan = scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &[dir.to_path_buf()],
            &mut index,
            "2026-08-02T07:10:00Z",
            7,
            100,
            false,
        )
        .unwrap();
        claude_request_identity::retain_root_accounts(
            &mut scan.snapshots,
            &index,
            "e2-identity-machine",
        );
        let (disposition, _, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(support, &mut scan, &mut index);
        (scan.snapshots, disposition, stats)
    })
}

/// A discard defers the whole family: its items stay on the page withheld
/// and held, so the production upload filter sends nothing of it.
fn e2_assert_family_deferred(items: &[SnapshotItem], disposition: &ClaudeUsageAuthorityDisposition) {
    assert_eq!(items.len(), 2, "root and child stay on the page for the hold");
    for item in items {
        assert!(!e2_is_literal(item), "no body is emitted for a deferred item");
        assert!(
            disposition
                .quarantined_source_session_ids
                .contains(&item.source_session_id),
            "the deferred item is held"
        );
    }
    let mut uploadable = items.to_vec();
    disposition.retain_uploadable(&mut uploadable);
    assert!(uploadable.is_empty(), "nothing of the family uploads this page");
}

/// A strict trace read dropped because the sidecar grew mid-read leaves every
/// request of the family unbound (no login), never bound to the other login.
#[test]
fn e2_pipeline_discarded_trace_read_leaves_requests_unbound_never_another_account() {
    for discard in [false, true] {
        let (dir, root, _) = claude_account_family_fixture();
        let support = dir.join("support");
        let (mut api, trace) = e2_family_evidence(&root);
        api[4].account_identifier_hash = Some("b".repeat(64));
        e2_resign(&mut api[4]);
        e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
        e2_write_rows(
            &support,
            "local-otel/claude-code-trace-ownership",
            &root,
            &trace,
        );
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        if discard {
            let expected = support
                .join("local-otel/claude-code-trace-ownership")
                .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
            let extra = serde_json::to_string(&complete_trace_row(&root, "req_6", "")).unwrap();
            let fired = fired.clone();
            crate::claude_local_otel::before_next_trace_read_for_test(move |path| {
                assert_eq!(path, expected, "the family root's strict trace read");
                // A concurrent exporter appends one more valid row.
                fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .unwrap()
                    .write_all(format!("{extra}\n").as_bytes())
                    .unwrap();
                fired.set(true);
            });
        }
        let (items, disposition, stats) = e2_page_with_stats(&dir, &support);
        assert_eq!(fired.get(), discard, "discard={discard}");
        assert_eq!(items.len(), 2);
        if discard {
            // Deferred, not sent untagged: no other account can receive it.
            e2_assert_family_deferred(&items, &disposition);
            assert_eq!(stats.trace_discard_deferred_items, 2);
        } else {
            assert_eq!(stats.trace_discard_deferred_items, 0);
        }
        for item in items.iter().filter(|_| !discard) {
            let (login, requests) = if item.source_session_id == root {
                ("a", 4)
            } else {
                ("b", 1)
            };
            // Only this item's own login.
            let allowed = Some(login.repeat(64));
            for row in e2_rows(item) {
                assert!(
                    row.account_identifier_hash.is_none()
                        || row.account_identifier_hash == allowed,
                    "never another item's account"
                );
            }
            let expected = BTreeMap::from([(allowed, requests)]);
            assert_eq!(e2_login_counts(item), expected);
        }
        if discard {
            assert_eq!(stats.trace_incomplete_root_count, 1);
            assert_eq!(
                stats.trace_rows_discarded,
                crate::claude_local_otel::ClaudeTraceRowsDiscarded {
                    cap: 1,
                    cap_rows: 5,
                    ..Default::default()
                }
            );
            let line = serde_json::to_value(&stats).unwrap();
            assert_eq!(line["trace_rows_discarded"]["cap"], 1);
            assert_eq!(line["trace_rows_discarded"]["generation"], 0);
            assert_eq!(line["trace_discard_deferred_items"], 2);
        } else {
            assert_eq!(stats.trace_incomplete_root_count, 0);
            assert!(stats.trace_rows_discarded.is_empty());
            let line = serde_json::to_value(&stats).unwrap();
            assert!(line.get("trace_rows_discarded").is_none());
            assert!(line.get("trace_discard_deferred_items").is_none());
        }
        fs::remove_dir_all(dir).unwrap();
    }
}

/// Retained creator A, complete own telemetry B, and permitted history custody.
/// Scan and evidence application are production stages; only custody is seeded.
fn e2_bound_trace_page(
    dir: &Path,
    support: &Path,
    root: &str,
    index: &mut ScanIndex,
    unhealthy: bool,
    accepted: Option<&claude_request_identity::AcceptedBuckets>,
) -> (
    Vec<SnapshotItem>,
    ClaudeUsageAuthorityDisposition,
    crate::snapshot_sync::ClaudeLocalEvidenceStats,
) {
    claude_request_money::e2::with_enabled(|| {
        // Sidecar changes must select the root and child even when their
        // transcript bytes are unchanged (notably malformed -> clean).
        let mut scan = scan_source_roots_with_test_limit_and_claude_support(
            &[dir.to_path_buf()],
            index,
            "2026-08-02T07:10:00Z",
            7,
            100,
            support,
        )
        .unwrap();
        claude_request_identity::retain_root_accounts(
            &mut scan.snapshots,
            index,
            "e2-identity-machine",
        );
        let previous = claude_history_upgrade::HeldUploadTuple {
            last_snapshot_fingerprint: Some("owed-snapshot".into()),
            last_upload_body_witness: Some("owed-witness".into()),
            file_snapshot_fingerprints: Some(BTreeSet::from(["owed-member".into()])),
            confirmed_empty: false,
        };
        index.claude_history_emission.files.clear();
        for item in &scan.snapshots {
            let path = if item.source_session_id == root {
                dir.join(format!("{root}.jsonl"))
            } else {
                dir.join(root)
                    .join("subagents")
                    .join(format!("agent-{E2_CHILD}.jsonl"))
            };
            index.claude_history_emission.files.insert(
                item.source_file_fingerprint.clone().unwrap(),
                claude_history_upgrade::GatedHistory {
                    index_key: local_index_key(&path),
                    permitted: true,
                    previous: Some(previous.clone()),
                    ..Default::default()
                },
            );
        }
        assert_eq!(index.claude_history_emission.files.len(), 2);
        let ((disposition, _, stats), counts) =
            claude_request_money::e2::pipeline_test_observer::capture_identity_counts(|| {
                crate::snapshot_sync::apply_claude_local_evidence_to_scan_with_accepted_for_test(
                    support, &mut scan, index, accepted,
                )
            });
        if unhealthy && stats.trace_rows_discarded.is_empty() {
            assert_eq!(counts["claude_inherited_org_requests"], 5,
                "non-discard E2 fallback still fills every request from retained A");
        }
        for gated in index.claude_history_emission.files.values() {
            assert!(gated.permitted, "owed permission is retained");
            assert_eq!(gated.previous.as_ref(), Some(&previous), "custody is kept");
            assert_eq!(
                gated.held,
                unhealthy.then_some(HistoryHold::TelemetryUnread),
                "root and child history use the existing hold"
            );
        }
        assert_eq!(
            index.session_account_bindings
                [&sha256_hex(&["session_owner:v1", "e2-identity-machine", root])]
                .account_identifier_hash,
            e2_account(),
            "the durable creator binding A is untouched"
        );
        (scan.snapshots, disposition, stats)
    })
}

fn e2_bound_trace_assert_logins(items: &[SnapshotItem], root: &str, root_login: Option<String>, child_login: Option<String>) {
    assert_eq!(items.len(), 2, "root and child both emit");
    for item in items {
        let login = if item.source_session_id == root { root_login.clone() } else { child_login.clone() };
        let requests = if item.source_session_id == root { 4 } else { 1 };
        assert!(e2_is_literal(item));
        assert_eq!(item.request_count, requests);
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(login.clone(), requests)]),
            "every request share, including child inheritance"
        );
        for row in e2_rows(item) {
            assert_eq!(row.account_identifier_hash, login);
            if let Some(parts) = &row.identity_parts {
                for part in parts {
                    assert_eq!(part.account_identifier_hash, login, "identity_parts");
                }
            }
        }
    }
}

fn e2_bound_trace_totals(items: &[SnapshotItem]) -> BTreeMap<String, serde_json::Value> {
    items
        .iter()
        .map(|item| {
            (
                item.source_session_id.clone(),
                json!({
                    "requests": item.request_count,
                    "input": item.input_tokens, "output": item.output_tokens,
                    "cache_read": item.cache_read_tokens,
                    "cache_5m": item.cache_creation_5m_tokens,
                    "cache_1h": item.cache_creation_1h_tokens,
                    "reasoning": item.reasoning_output_tokens,
                    "unattributed": item.unattributed_total_tokens,
                    "cost": item.cost,
                }),
            )
        })
        .collect()
}

fn e2_bound_trace_regression(mode: &str, split_logins: bool) {
    e2_bound_trace_billing_regression(mode, split_logins, false);
}

fn e2_bound_trace_billing_regression(mode: &str, split_logins: bool, external: bool) {
    e2_bound_trace_case(mode, split_logins, external, false);
}

/// `accepted_ledger`: the clean page's bodies enter the accepted-identity
/// ledger exactly as a stored ACK records them, and every later page reads it.
fn e2_bound_trace_case(mode: &str, split_logins: bool, external: bool, accepted_ledger: bool) {
    let (dir, root, _) = claude_account_family_fixture();
    if external {
        for path in [
            dir.join(format!("{root}.jsonl")),
            dir.join(&root).join("subagents").join(format!("agent-{E2_CHILD}.jsonl")),
        ] {
            let lines = fs::read_to_string(&path).unwrap().lines().map(|line| {
                let mut row: serde_json::Value = serde_json::from_str(line).unwrap();
                row["auth_mode"] = json!("api_key");
                format!("{row}\n")
            }).collect::<String>();
            fs::write(path, lines).unwrap();
        }
    }
    let support = dir.join("support");
    let (mut api, trace) = e2_family_evidence(&root);
    for row in &mut api {
        row.account_identifier_hash = Some("b".repeat(64));
        e2_resign(row);
    }
    if split_logins {
        api[4].account_identifier_hash = Some("c".repeat(64));
        e2_resign(&mut api[4]);
    }
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(&support, "local-otel/claude-code-trace-ownership", &root, &trace);
    let path = support
        .join("local-otel/claude-code-trace-ownership")
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    let mut index = ScanIndex::default();
    index.session_account_bindings.insert(
        sha256_hex(&["session_owner:v1", "e2-identity-machine", &root]),
        SessionAccountBinding {
            account_identifier_hash: e2_account(),
            workspace_identifier_hash: None,
        },
    );
    let (clean, _, stats) = e2_bound_trace_page(&dir, &support, &root, &mut index, false, None);
    let child_login = if split_logins { "c" } else { "b" }.repeat(64);
    e2_bound_trace_assert_logins(&clean, &root, Some("b".repeat(64)), Some(child_login.clone()));
    let mut accepted = claude_request_identity::AcceptedBuckets::for_test();
    if accepted_ledger {
        // The same ledger write `record_cache_state` makes for a stored ACK.
        for item in &clean {
            accepted.record(&serde_json::to_value(item).unwrap());
        }
        assert!(
            clean.iter().any(|item| accepted.get(&item.source_session_id).is_some()),
            "a tagged contract-5 body was accepted"
        );
    }
    let accepted = accepted_ledger.then_some(&accepted);
    if external {
        for item in &clean {
            for row in e2_rows(item) {
                assert_eq!(row.auth_mode.as_deref(), Some("api_key"));
                assert!(!claude_request_accounts::local_subscription(row),
                    "this fixture bypasses contract-5 identity grouping");
            }
        }
    }
    assert_eq!(stats.trace_discard_no_fallback_requests, 0);
    assert_eq!(stats.trace_discard_deferred_items, 0);
    let line = serde_json::to_value(&stats).unwrap();
    assert!(line.get("trace_discard_no_fallback_requests").is_none());
    assert!(line.get("trace_discard_deferred_items").is_none());
    let totals = e2_bound_trace_totals(&clean);
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    if mode == "malformed" {
        fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"malformed\n").unwrap();
        // Stable malformed input is truly unhealthy, even with all valid rows
        // retained. The reader's frozen-main equality test covers this state.
        let report = crate::claude_local_otel::load_claude_trace_ownership_evidence(
            &support, [root.clone()],
        );
        assert_eq!(report.malformed_lines, 1);
        assert!(!report.is_complete(), "the control must take the unhealthy path");
        assert_eq!(report.evidence[&root], trace);
        assert!(report.rows_discarded.is_empty());
    } else {
        let expected = path.clone();
        let duplicate = serde_json::to_string(&trace[0]).unwrap();
        let fired = fired.clone();
        let generation = mode == "generation";
        crate::claude_local_otel::before_next_trace_read_for_test(move |path| {
            assert_eq!(path, expected);
            if generation {
                let replacement = path.with_extension("replacement");
                fs::copy(path, &replacement).unwrap();
                fs::rename(replacement, path).unwrap();
            } else {
                fs::OpenOptions::new().append(true).open(path).unwrap()
                    .write_all(format!("{duplicate}\n").as_bytes()).unwrap();
            }
            fired.set(true);
        });
    }
    let (items, disposition, stats) =
        e2_bound_trace_page(&dir, &support, &root, &mut index, true, accepted);
    assert_eq!(fired.get(), mode != "malformed");
    assert_eq!(stats.trace_incomplete_root_count, 1);
    let discarded = mode != "malformed";
    assert_eq!(stats.trace_discard_no_fallback_requests, if discarded { 5 } else { 0 });
    if discarded {
        // Deferred: no revision replaces the accepted body, so the server
        // keeps its tags and no other account (A or None) receives this hour.
        e2_assert_family_deferred(&items, &disposition);
        assert_eq!(stats.trace_discard_deferred_items, 2);
        let line = serde_json::to_value(&stats).unwrap();
        assert_eq!(line["trace_discard_no_fallback_requests"], 5);
        assert_eq!(line["trace_discard_deferred_items"], 2);
        assert_eq!(stats.trace_rows_discarded.cap, u64::from(mode == "cap"));
        assert_eq!(stats.trace_rows_discarded.generation, u64::from(mode == "generation"));
    } else {
        assert_eq!(e2_bound_trace_totals(&items), totals, "per-session money is unchanged");
        // Main preserves uniform API-qualified B on markerless wire rows despite
        // internal A partitions. Split B/C evidence cannot take that shortcut:
        // the non-discard control then emits the retained A partitions instead.
        let control_login = if split_logins { e2_account() } else { "b".repeat(64) };
        e2_bound_trace_assert_logins(&items, &root, Some(control_login.clone()), Some(control_login));
        assert_eq!(stats.trace_discard_deferred_items, 0);
        assert!(stats.trace_rows_discarded.is_empty(), "malformed is not a discard");
        let line = serde_json::to_value(&stats).unwrap();
        assert!(line.get("trace_discard_no_fallback_requests").is_none());
        assert!(line.get("trace_discard_deferred_items").is_none());
        assert_eq!(stats.complete_sidecar_root_count, 0);
        assert_eq!(stats.api_incomplete_root_count, 0);
        assert_eq!(stats.api_evidence_row_count, 0);
        assert_eq!(stats.trace_evidence_row_count, 0);
        for item in &items {
            assert_eq!(item.telemetry_owned_complete, Some(false));
        }
    }
    // Settle the sidecar; the next page must use B despite the retained A.
    // Only a discard owes this recovery. The malformed control stops at
    // main's unhealthy page: re-selection after its repair is main's scanner.
    if discarded {
        e2_write_rows(&support, "local-otel/claude-code-trace-ownership", &root, &trace);
        let (recovered, _, stats) =
            e2_bound_trace_page(&dir, &support, &root, &mut index, false, accepted);
        e2_bound_trace_assert_logins(&recovered, &root, Some("b".repeat(64)), Some(child_login));
        assert_eq!(e2_bound_trace_totals(&recovered), totals, "the deferred usage is not dropped");
        assert_eq!(stats.trace_discard_no_fallback_requests, 0);
        assert_eq!(stats.trace_discard_deferred_items, 0);
        assert!(stats.trace_rows_discarded.is_empty());
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn e2_pipeline_bound_a_own_b_cap_discard_has_no_fallback_then_recovers() {
    e2_bound_trace_regression("cap", false);
}

#[cfg(unix)]
#[test]
fn e2_pipeline_bound_a_own_b_generation_discard_has_no_fallback_then_recovers() {
    e2_bound_trace_regression("generation", false);
}

#[test]
fn e2_pipeline_bound_a_malformed_trace_keeps_main_fallback() {
    e2_bound_trace_regression("malformed", false);
}

// With no uniform API account, main's markerless shortcut cannot preserve B.
// The malformed control takes the same unhealthy/no-accepted-rows path as a
// discard with the new rule disabled, and actually emits retained A.
#[test]
fn e2_pipeline_bound_a_split_logins_malformed_trace_matches_main_a() {
    e2_bound_trace_regression("malformed", true);
}

#[test]
fn e2_pipeline_bound_a_split_logins_cap_discard_blocks_retained_a() {
    e2_bound_trace_regression("cap", true);
}

#[cfg(unix)]
#[test]
fn e2_pipeline_bound_a_split_logins_generation_discard_blocks_retained_a() {
    e2_bound_trace_regression("generation", true);
}

#[test]
fn e2_pipeline_external_billing_cap_discard_clears_wire_account_then_recovers() {
    e2_bound_trace_billing_regression("cap", false, true);
}

#[cfg(unix)]
#[test]
fn e2_pipeline_external_billing_generation_discard_clears_wire_account_then_recovers() {
    e2_bound_trace_billing_regression("generation", false, true);
}

#[test]
fn e2_pipeline_external_billing_malformed_trace_keeps_main_account() {
    e2_bound_trace_billing_regression("malformed", false, true);
}

// A bucket already accepted tagged (B root, C child) is never replaced by an
// untagged revision: the discard page uploads nothing for the family, and the
// next clean page uploads B/C again with unchanged totals.
#[test]
fn e2_pipeline_accepted_b_cap_discard_defers_upload_then_recovers() {
    e2_bound_trace_case("cap", true, false, true);
}

#[cfg(unix)]
#[test]
fn e2_pipeline_accepted_b_generation_discard_defers_upload_then_recovers() {
    e2_bound_trace_case("generation", true, false, true);
}
