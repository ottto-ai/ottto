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
fn e2_pipeline_exact_telemetry_over_cap_uses_the_existing_counted_start_fallback() {
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
) -> (Vec<SnapshotItem>, crate::snapshot_sync::ClaudeLocalEvidenceStats) {
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
        let (_, _, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(support, &mut scan, &mut index);
        (scan.snapshots, stats)
    })
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
        let (items, stats) = e2_page_with_stats(&dir, &support);
        assert_eq!(fired.get(), discard, "discard={discard}");
        assert_eq!(items.len(), 2);
        for item in &items {
            e2_assert_identity_consistent(item, &format!("discard={discard}"));
            let (login, requests) = if item.source_session_id == root {
                ("a", 4)
            } else {
                ("b", 1)
            };
            let expected = if discard {
                BTreeMap::from([(None, requests)])
            } else {
                BTreeMap::from([(Some(login.repeat(64)), requests)])
            };
            assert_eq!(e2_login_counts(item), expected, "discard={discard}");
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
        } else {
            assert_eq!(stats.trace_incomplete_root_count, 0);
            assert!(stats.trace_rows_discarded.is_empty());
            assert!(serde_json::to_value(&stats)
                .unwrap()
                .get("trace_rows_discarded")
                .is_none());
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
