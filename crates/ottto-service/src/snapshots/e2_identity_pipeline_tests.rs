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
        if unhealthy {
            assert_eq!(counts.get("claude_inherited_org_requests"), None,
                "no request is filled from the retained, start or root account: {counts}");
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

/// Mark transcript lines API-key billed: `external` marks root and child,
/// `mixed` only the root's req_3 and req_4. Either way the item leaves final
/// identity grouping and keeps the emission's uniform row account.
fn e2_set_billing(dir: &Path, root: &str, billing: &str) {
    if billing == "subscription" {
        return;
    }
    for path in [
        dir.join(format!("{root}.jsonl")),
        dir.join(root).join("subagents").join(format!("agent-{E2_CHILD}.jsonl")),
    ] {
        let lines = fs::read_to_string(&path).unwrap().lines().map(|line| {
            let mut row: serde_json::Value = serde_json::from_str(line).unwrap();
            if billing == "external" || matches!(row["requestId"].as_str(), Some("req_3" | "req_4")) {
                row["auth_mode"] = json!("api_key");
            }
            format!("{row}\n")
        }).collect::<String>();
        fs::write(path, lines).unwrap();
    }
}

/// Rows of `item`'s buckets that carry at least one tagged share.
fn e2_tagged_bucket_rows(item: &SnapshotItem) -> u64 {
    item.usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .filter(|row| match &row.identity_parts {
            Some(parts) => parts.iter().any(|part| part.account_identifier_hash.is_some()),
            None => row.account_identifier_hash.is_some(),
        })
        .count() as u64
}

/// Bound A, own B (child C when `split_logins`), then one unhealthy page and
/// one clean page. `mode` is a discard (`cap`, `generation`) or another
/// unhealthy read (`malformed`, `unreadable`, `oversized` at open, or
/// `incomplete`: the trace member is missing). SOURCE: no unhealthy request
/// takes an account; a discard also withholds the family.
/// `billing`: `subscription`, `external` or `mixed` (see `e2_set_billing`).
/// `accepted_ledger`: the clean page's bodies enter the accepted-identity
/// ledger exactly as a stored ACK records them, and every later page reads it.
/// `listed`: the family is on the re-emission list (no E2 fold).
fn e2_bound_trace_case(
    mode: &str,
    split_logins: bool,
    billing: &str,
    accepted_ledger: bool,
    listed: bool,
) {
    let (dir, root, _) = claude_account_family_fixture();
    e2_set_billing(&dir, &root, billing);
    let support = dir.join("support");
    let (mut api, trace) = e2_family_evidence(&root);
    // Own login B, except the mixed arm: own A == the bound owner, which main
    // uploads and only #947's clear would hold (Lead B Addendum 4).
    let own = if billing == "mixed" { "a" } else { "b" };
    for row in &mut api {
        row.account_identifier_hash = Some(own.repeat(64));
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
    if listed {
        let list = crate::snapshots::claude_reemission_exclusions::ReemissionExclusions::path(&support);
        fs::create_dir_all(list.parent().unwrap()).unwrap();
        fs::write(list, format!("{:x}\n", Sha256::digest(root.as_bytes()))).unwrap();
    }
    // Only the durable creator binding A (and the real list) carries over.
    let bound_index = || {
        let mut index = ScanIndex::default();
        index.session_account_bindings.insert(
            sha256_hex(&["session_owner:v1", "e2-identity-machine", &root]),
            SessionAccountBinding {
                account_identifier_hash: e2_account(),
                workspace_identifier_hash: None,
            },
        );
        index.load_claude_reemission_exclusions(&support);
        index
    };
    let discarded = matches!(mode, "cap" | "generation");
    let mut index = bound_index();
    let (clean, _, stats) = e2_bound_trace_page(&dir, &support, &root, &mut index, false, None);
    let b = Some(own.repeat(64));
    let child_login = Some(if split_logins { "c" } else { own }.repeat(64));
    if listed {
        assert!(clean.iter().all(|item| item.claude_money.is_none()), "listed: no E2 fold");
    } else {
        e2_bound_trace_assert_logins(&clean, &root, b.clone(), child_login.clone());
    }
    let mut accepted = claude_request_identity::AcceptedBuckets::for_test();
    // Refusals each item owes once its accepted shares change: one per row.
    let mut refusals = BTreeMap::<String, u64>::new();
    if accepted_ledger {
        // The same ledger write `record_cache_state` makes for a stored ACK.
        for item in &clean {
            accepted.record(&serde_json::to_value(item).unwrap());
            if accepted.get(&item.source_session_id).is_some() {
                refusals.insert(item.source_session_id.clone(), e2_tagged_bucket_rows(item));
            }
        }
        assert!(refusals.values().any(|rows| *rows > 0), "a tagged body was accepted: {refusals:?}");
    }
    let accepted = accepted_ledger.then_some(&accepted);
    if billing != "subscription" {
        let root_item = clean.iter().find(|item| item.source_session_id == root).unwrap();
        assert!(
            e2_rows(root_item).any(|row| !claude_request_accounts::local_subscription(row)),
            "this arm bypasses contract-5 identity grouping"
        );
    }
    assert_eq!(stats.trace_discard_no_fallback_requests, 0);
    assert_eq!(stats.trace_discard_deferred_items, 0);
    assert!(stats.unhealthy_root_no_fallback_requests.is_empty());
    let line = serde_json::to_value(&stats).unwrap();
    for key in [
        "trace_discard_no_fallback_requests",
        "trace_discard_deferred_items",
        "unhealthy_root_no_fallback_requests",
    ] {
        assert!(line.get(key).is_none(), "{key} is absent while zero");
    }
    let totals = e2_bound_trace_totals(&clean);
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    match mode {
        "malformed" => {
            fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"malformed\n").unwrap();
            // Stable malformed input is truly unhealthy, even with all valid
            // rows retained.
            let report = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                &support, [root.clone()],
            );
            assert_eq!(report.malformed_lines, 1);
            assert!(!report.is_complete(), "the case must take the unhealthy path");
            assert_eq!(report.evidence[&root], trace);
            assert!(report.rows_discarded.is_empty());
        }
        "unreadable" => {
            fs::remove_file(&path).unwrap();
            fs::create_dir_all(&path).unwrap();
        }
        // The API sidecar stays: a missing pair member is failed evidence.
        "incomplete" => fs::remove_file(&path).unwrap(),
        // Sparse NUL padding is malformed evidence; size alone no longer
        // refuses pairing or the strict read.
        "oversized" => fs::OpenOptions::new().write(true).open(&path).unwrap()
            .set_len(64 * 1024 * 1024).unwrap(),
        "cap" | "generation" => {
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
        other => panic!("unknown mode {other}"),
    }
    // A family the page did not withhold is selected again only by a fresh
    // index: the scanner's own change detection is not under test here.
    if !discarded {
        index = bound_index();
    }
    let (items, disposition, stats) =
        e2_bound_trace_page(&dir, &support, &root, &mut index, true, accepted);
    assert_eq!(fired.get(), discarded);
    assert_eq!(
        stats.trace_incomplete_root_count,
        usize::from(discarded || matches!(mode, "malformed" | "oversized")),
        "only unreadable and incomplete pairs skip the strict read"
    );
    // Root 4 + child 1 requests, under this cause only; a listed family has
    // no E2 fold to count.
    let reason = if discarded { "discarded" } else { mode };
    let requests = if listed { 0 } else { 5 };
    let expected = if listed { json!({}) } else { json!({ reason: requests }) };
    assert_eq!(serde_json::to_value(stats.unhealthy_root_no_fallback_requests).unwrap(), expected);
    assert_eq!(stats.trace_discard_no_fallback_requests, if discarded { requests } else { 0 },
        "#932's scalar equals the discarded reason");
    // The production account owner after this page: a body with no login on
    // the session bound to A is held unless this scan admitted it.
    let mut bound = items.clone();
    let held = index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        "e2-identity-machine",
        &mut bound,
        &[],
        &disposition.mixed_uploads,
    );
    if discarded {
        // Deferred: no revision replaces the accepted body, so the server
        // keeps its tags and no other account (A or None) receives this hour.
        e2_assert_family_deferred(&items, &disposition);
        if billing != "subscription" {
            // Only the root is bound (to A).
            assert_eq!(held, BTreeSet::from([root.clone()]), "#932's discard keeps main's account hold");
        }
        assert_eq!(stats.trace_discard_deferred_items, 2);
        let line = serde_json::to_value(&stats).unwrap();
        assert_eq!(line["trace_discard_deferred_items"], 2);
        assert_eq!(
            line.get("unhealthy_root_no_fallback_requests"),
            (!listed).then_some(&expected),
            "absent while empty"
        );
        assert_eq!(stats.trace_rows_discarded.cap, u64::from(mode == "cap"));
        assert_eq!(stats.trace_rows_discarded.generation, u64::from(mode == "generation"));
    } else {
        // Never A, never B/C: every request share is Unknown, uploaded now.
        e2_bound_trace_assert_logins(&items, &root, None, None);
        if billing == "mixed" {
            // Lead B Addendum 4 (option 1): the cleared owner login A is not
            // held; the body uploads Unknown on this page.
            assert!(held.is_empty(), "0 holds: {held:?}");
            e2_bound_trace_assert_logins(&bound, &root, None, None);
        } else if billing == "external" {
            // Main's hold for a login other than A (B) stays.
            assert_eq!(held, BTreeSet::from([root.clone()]), "main's B != A hold");
        }
        assert_eq!(disposition.quarantined_entity_count(), 0, "Unknown, not deferred");
        assert_eq!(stats.trace_discard_deferred_items, 0);
        assert!(stats.trace_rows_discarded.is_empty(), "{mode} is not a discard");
        let line = serde_json::to_value(&stats).unwrap();
        assert_eq!(line["unhealthy_root_no_fallback_requests"], expected);
        if mode == "malformed" {
            // The same paired read: money is unchanged, only the account moves.
            assert_eq!(e2_bound_trace_totals(&items), totals, "per-session money is unchanged");
        }
        for item in &items {
            assert_eq!(item.telemetry_owned_complete, Some(false));
            // #909: one refusal per changed accepted row; none if never accepted.
            assert_eq!(
                item.request_identity_refusals,
                refusals.get(&item.source_session_id).copied().unwrap_or(0),
                "{}", item.source_session_id
            );
        }
    }
    // The sidecar reads clean again: the family's own proof returns.
    if mode == "unreadable" {
        fs::remove_dir(&path).unwrap();
    }
    e2_write_rows(&support, "local-otel/claude-code-trace-ownership", &root, &trace);
    if !discarded {
        index = bound_index();
    }
    let (recovered, _, stats) =
        e2_bound_trace_page(&dir, &support, &root, &mut index, false, accepted);
    if listed {
        // Addendum 3: the accepted tags are kept, nothing is refused.
        for item in &recovered {
            let logins = e2_login_counts(item);
            assert!(logins.keys().all(|login| login.is_some() && *login != Some(e2_account())),
                "{logins:?}");
            assert_eq!(item.request_identity_refusals, 0);
        }
    } else {
        e2_bound_trace_assert_logins(&recovered, &root, b, child_login);
        assert!(recovered.iter().all(|item| item.request_identity_refusals == 0));
    }
    assert_eq!(e2_bound_trace_totals(&recovered), totals, "no usage is dropped");
    assert!(stats.unhealthy_root_no_fallback_requests.is_empty());
    assert_eq!(stats.trace_discard_deferred_items, 0);
    assert!(stats.trace_rows_discarded.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

/// [money] #932: a discard withholds, never another account.
#[test]
fn e2_pipeline_bound_a_own_b_cap_discard_has_no_fallback_then_recovers() {
    e2_bound_trace_case("cap", false, "subscription", false, false);
}

/// [money] #932: a replaced trace is a discard too.
#[cfg(unix)]
#[test]
fn e2_pipeline_bound_a_own_b_generation_discard_has_no_fallback_then_recovers() {
    e2_bound_trace_case("generation", false, "subscription", false, false);
}

/// [money] Uniform B on a malformed trace is Unknown until a clean read,
/// never B through the D1 shortcut.
/// guard: unseen on M4 (0 of 3,614 evidence pages); code-derived from #932 review P2-1
#[test]
fn e2_pipeline_bound_a_uniform_b_malformed_trace_is_unknown_not_a() {
    e2_bound_trace_case("malformed", false, "subscription", false, false);
}

/// [money] Split B/C on a malformed trace is Unknown, never retained A.
/// Never accepted, so no refusal.
/// guard: unseen on M4 (0 of 3,614 evidence pages); code-derived from #932 review P2-1
#[test]
fn e2_pipeline_bound_a_split_logins_malformed_trace_is_unknown_not_a() {
    e2_bound_trace_case("malformed", true, "subscription", false, false);
}

/// [money] SOURCE reason counts: split B/C on every other unhealthy read is
/// Unknown, never retained A, and counted under its own reason.
/// guard: unseen on M4 (0 of 3,614 evidence pages)
#[test]
fn e2_pipeline_bound_a_split_logins_unhealthy_trace_reasons_are_unknown_not_a() {
    for (case, mode) in [
        ("unreadable: the trace path is a directory", "unreadable"),
        ("oversized: refused at open from metadata", "oversized"),
        ("incomplete: the trace pair member is missing", "incomplete"),
    ] {
        let row = std::panic::catch_unwind(|| {
            e2_bound_trace_case(mode, true, "subscription", false, false)
        });
        assert!(row.is_ok(), "{case}");
    }
}

/// [money] #932: the discard withholds the split family too.
#[test]
fn e2_pipeline_bound_a_split_logins_cap_discard_blocks_retained_a() {
    e2_bound_trace_case("cap", true, "subscription", false, false);
}

/// [money] #932: the same for a replaced trace.
#[cfg(unix)]
#[test]
fn e2_pipeline_bound_a_split_logins_generation_discard_blocks_retained_a() {
    e2_bound_trace_case("generation", true, "subscription", false, false);
}

/// [money] #932: external billing bypasses grouping; the discard clears it.
#[test]
fn e2_pipeline_external_billing_cap_discard_clears_wire_account_then_recovers() {
    e2_bound_trace_case("cap", false, "external", false, false);
}

/// [money] #932: the same for a replaced trace.
#[cfg(unix)]
#[test]
fn e2_pipeline_external_billing_generation_discard_clears_wire_account_then_recovers() {
    e2_bound_trace_case("generation", false, "external", false, false);
}

/// [money] Lead B C2: the uniform wire account is cleared for every
/// unhealthy reason, not only discards. One family login B: with two, the
/// account owner already withholds a D1-shaped body. B != bound A: main's
/// account hold stays (Lead B Addendum 4).
#[test]
fn e2_pipeline_external_billing_malformed_trace_clears_wire_account() {
    e2_bound_trace_case("malformed", false, "external", false, false);
}

/// [money] Lead B C2 + Addendum 4 (option 1), mixed billing (only req_3/req_4
/// API-key billed), own login A == bound owner: the body uploads Unknown on
/// the same page with 0 account holds, decision-2 refusals (none here: this
/// body never enters the #909 ledger) and unchanged totals.
#[test]
fn e2_pipeline_mixed_billing_malformed_trace_clears_wire_account() {
    e2_bound_trace_case("malformed", false, "mixed", false, false);
}

/// [money] #932 x #909: a bucket already accepted tagged (B root, C child) is
/// never replaced by an untagged revision: the discard page uploads nothing
/// for the family, and the next clean page uploads B/C again.
#[test]
fn e2_pipeline_accepted_b_cap_discard_defers_upload_then_recovers() {
    e2_bound_trace_case("cap", true, "subscription", true, false);
}

/// [money] #932 x #909: the same for a replaced trace.
#[cfg(unix)]
#[test]
fn e2_pipeline_accepted_b_generation_discard_defers_upload_then_recovers() {
    e2_bound_trace_case("generation", true, "subscription", true, false);
}

/// [money] #947 x #909 (Lead B Q2): an accepted bucket made Unknown by a
/// malformed trace keeps #909's refusal, one per changed accepted row.
#[test]
fn e2_pipeline_accepted_bucket_unhealthy_root_keeps_909_refusal() {
    e2_bound_trace_case("malformed", true, "subscription", true, false);
}

/// [money] Lead B Addendum 3 (#932 x #909 F2): a listed family (real
/// re-emission list, no E2 fold) whose accepted trace grows mid-read is held
/// like a folded one: nothing untagged or refused uploads, its history stays
/// owed, and the next clean read keeps the tags.
#[test]
fn e2_pipeline_listed_family_accepted_cap_discard_is_held_then_keeps_tags() {
    e2_bound_trace_case("cap", true, "subscription", true, true);
}
