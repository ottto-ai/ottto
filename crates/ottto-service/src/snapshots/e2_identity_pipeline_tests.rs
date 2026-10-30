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

// SOURCE 2026-10-30 (unhealthy root): a family whose strict sidecar read failed
// gets no account. Requests stay Unknown and are counted per reason, never
// bound to the retained creator A. Bindings, custody and holds are untouched.

const E2_SIBLING: &str = "2449b91b-f36e-4cbc-a5bb-50fc66430ba5";

fn e2_owner_key(root: &str) -> String {
    sha256_hex(&["session_owner:v1", "e2-identity-machine", root])
}

/// A healthy markerless sibling session under its own root: two requests,
/// own login D, also bound A. Its directory is scanned on the same page.
fn e2_healthy_sibling(support: &Path) -> PathBuf {
    let dir = temp_dir("e2-unhealthy-sibling");
    let lines = (1..=2)
        .map(|n| {
            format!("{}\n", json!({
                "timestamp": format!("2026-08-02T07:00:{n:02}Z"), "type": "assistant",
                "sessionId": E2_SIBLING, "requestId": format!("req_sib_{n}"),
                "message": {"id": format!("msg_sib_{n}"), "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 10}}
            }))
        })
        .collect::<String>();
    fs::write(dir.join(format!("{E2_SIBLING}.jsonl")), lines).unwrap();
    e2_sibling_evidence(support);
    dir
}

/// (Re)write the sibling's clean sidecars, so a later page selects it again.
fn e2_sibling_evidence(support: &Path) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut api = Vec::new();
    let mut trace = Vec::new();
    for n in 1..=2 {
        let request = format!("req_sib_{n}");
        let mut row = complete_api_row(E2_SIBLING, &request, n, 10, 10, 0);
        row.account_identifier_hash = Some("d".repeat(64));
        e2_resign(&mut row);
        api.push(row);
        trace.push(complete_trace_row(E2_SIBLING, &request, ""));
    }
    e2_write_rows(support, crate::claude_local_otel::STORE_DIR, E2_SIBLING, &api);
    e2_write_rows(
        support,
        "local-otel/claude-code-trace-ownership",
        E2_SIBLING,
        &trace,
    );
}

/// One real page over the family and its sibling, with the family's owed
/// history custody seeded. Asserts the durable bindings and custody survive.
fn e2_unhealthy_root_page(
    dirs: &[PathBuf],
    support: &Path,
    root: &str,
    index: &mut ScanIndex,
    unhealthy: bool,
    accepted: Option<&claude_request_identity::AcceptedBuckets>,
) -> (
    Vec<SnapshotItem>,
    ClaudeUsageAuthorityDisposition,
    crate::snapshot_sync::ClaudeLocalEvidenceStats,
    serde_json::Value,
) {
    claude_request_money::e2::with_enabled(|| {
        // Sidecar changes must select the family even when its transcript
        // bytes are unchanged (unhealthy -> clean).
        let mut scan = scan_source_roots_with_test_limit_and_claude_support(
            dirs,
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
        for item in scan
            .snapshots
            .iter()
            .filter(|item| claude_snapshot_family_root_ref(item) == root)
        {
            let path = if item.source_session_id == root {
                dirs[0].join(format!("{root}.jsonl"))
            } else {
                dirs[0]
                    .join(root)
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
        for gated in index.claude_history_emission.files.values() {
            assert!(gated.permitted, "owed permission is retained");
            assert_eq!(gated.previous.as_ref(), Some(&previous), "custody is kept");
            assert_eq!(
                gated.held,
                unhealthy.then_some(HistoryHold::TelemetryUnread),
                "root and child history keep the existing hold"
            );
        }
        for bound in [root, E2_SIBLING] {
            assert_eq!(
                index.session_account_bindings[&e2_owner_key(bound)].account_identifier_hash,
                e2_account(),
                "the durable creator binding A is untouched"
            );
        }
        (scan.snapshots, disposition, stats, counts)
    })
}

/// Each family item's request shares, rows and identity parts carry `login`;
/// the sibling keeps its own D.
fn e2_unhealthy_assert_logins(
    items: &[SnapshotItem],
    root: &str,
    root_login: Option<String>,
    child_login: Option<String>,
) {
    assert_eq!(items.len(), 3, "root, child and sibling all emit");
    for item in items {
        let (login, requests) = if item.source_session_id == E2_SIBLING {
            (Some("d".repeat(64)), 2)
        } else if item.source_session_id == root {
            (root_login.clone(), 4)
        } else {
            (child_login.clone(), 1)
        };
        assert!(e2_is_literal(item));
        assert_eq!(item.request_count, requests);
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(login.clone(), requests)]),
            "{}: every request share, including child inheritance",
            item.source_session_id
        );
        for row in e2_rows(item) {
            assert_eq!(row.account_identifier_hash, login);
            for part in row.identity_parts.iter().flatten() {
                assert_eq!(part.account_identifier_hash, login, "identity_parts");
            }
        }
    }
}

fn e2_unhealthy_totals(items: &[SnapshotItem]) -> BTreeMap<String, serde_json::Value> {
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
/// `mixed` marks only the root's req_3 and req_4. Either way the item leaves
/// final identity grouping and keeps the emission's uniform row account.
fn e2_set_billing(dir: &Path, root: &str, billing: &str) {
    if billing == "subscription" {
        return;
    }
    for path in [
        dir.join(format!("{root}.jsonl")),
        dir.join(root)
            .join("subagents")
            .join(format!("agent-{E2_CHILD}.jsonl")),
    ] {
        let lines = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| {
                let mut row: serde_json::Value = serde_json::from_str(line).unwrap();
                if billing == "external"
                    || matches!(row["requestId"].as_str(), Some("req_3" | "req_4"))
                {
                    row["auth_mode"] = json!("api_key");
                }
                format!("{row}\n")
            })
            .collect::<String>();
        fs::write(path, lines).unwrap();
    }
}

/// Bound A, own B (child C when `split_logins`), then a trace that is
/// `malformed`, `unreadable` (a directory) or `oversized` at open.
fn e2_unhealthy_root_case(mode: &str, split_logins: bool) {
    e2_unhealthy_root_billing_case(mode, split_logins, "subscription");
}

fn e2_unhealthy_root_billing_case(mode: &str, split_logins: bool, billing: &str) {
    let (dir, root, _) = claude_account_family_fixture();
    e2_set_billing(&dir, &root, billing);
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
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    let sibling = e2_healthy_sibling(&support);
    let dirs = [dir.clone(), sibling.clone()];
    let path = support
        .join("local-otel/claude-code-trace-ownership")
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    // Each page starts from the durable bindings alone, so every page selects
    // the whole family regardless of the scanner's change detection.
    let bound_index = || {
        let mut index = ScanIndex::default();
        for bound in [root.as_str(), E2_SIBLING] {
            index.session_account_bindings.insert(
                e2_owner_key(bound),
                SessionAccountBinding {
                    account_identifier_hash: e2_account(),
                    workspace_identifier_hash: None,
                },
            );
        }
        index
    };
    let b = Some("b".repeat(64));
    let child = Some(if split_logins { "c" } else { "b" }.repeat(64));

    let (clean, _, stats, _) =
        e2_unhealthy_root_page(&dirs, &support, &root, &mut bound_index(), false, None);
    e2_unhealthy_assert_logins(&clean, &root, b.clone(), child.clone());
    if billing != "subscription" {
        let root_item = clean.iter().find(|item| item.source_session_id == root).unwrap();
        assert!(
            e2_rows(root_item).any(|row| !claude_request_accounts::local_subscription(row)),
            "this arm bypasses contract-5 identity grouping"
        );
    }
    assert!(stats.unhealthy_root_no_fallback_requests.is_empty());
    let line = serde_json::to_value(&stats).unwrap();
    assert!(line.get("unhealthy_root_no_fallback_requests").is_none(), "absent while empty");
    let totals = e2_unhealthy_totals(&clean);

    match mode {
        "malformed" => {
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"malformed\n")
                .unwrap();
        }
        "unreadable" => {
            fs::remove_file(&path).unwrap();
            fs::create_dir_all(&path).unwrap();
        }
        "incomplete" => {
            // The API sidecar stays: a missing pair member is failed evidence.
            fs::remove_file(&path).unwrap();
        }
        "oversized" => {
            // Sparse: the strict reader refuses at open from metadata alone.
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(64 * 1024 * 1024)
                .unwrap();
        }
        other => panic!("unknown mode {other}"),
    }
    e2_sibling_evidence(&support);
    let (items, disposition, stats, counts) =
        e2_unhealthy_root_page(&dirs, &support, &root, &mut bound_index(), true, None);
    // Never A, never another login: every family share is Unknown. The
    // sibling's own clean evidence keeps D on the same page.
    e2_unhealthy_assert_logins(&items, &root, None, None);
    assert_eq!(
        counts.get("claude_inherited_org_requests"),
        None,
        "no request is filled from the retained, start or root account: {counts}"
    );
    let expected = json!({ mode: 5 });
    assert_eq!(
        serde_json::to_value(stats.unhealthy_root_no_fallback_requests).unwrap(),
        expected,
        "root 4 + child 1, under this cause only"
    );
    let line = serde_json::to_value(&stats).unwrap();
    assert_eq!(line["unhealthy_root_no_fallback_requests"], expected);
    assert_eq!(disposition.quarantined_entity_count(), 0, "Unknown, not deferred");
    if mode == "malformed" {
        // The same paired read: money is unchanged, only the account moves.
        assert_eq!(e2_unhealthy_totals(&items), totals, "per-session money is unchanged");
    }
    for item in items.iter().filter(|item| item.source_session_id != E2_SIBLING) {
        assert_eq!(item.telemetry_owned_complete, Some(false));
        assert!(item.request_count > 0, "never $0 by dropping requests");
    }

    // The sidecar reads clean again: its own proof replaces Unknown.
    if mode == "unreadable" {
        fs::remove_dir(&path).unwrap();
    }
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    e2_sibling_evidence(&support);
    let (recovered, _, stats, _) =
        e2_unhealthy_root_page(&dirs, &support, &root, &mut bound_index(), false, None);
    e2_unhealthy_assert_logins(&recovered, &root, b, child);
    assert_eq!(e2_unhealthy_totals(&recovered), totals, "no usage is dropped");
    assert!(stats.unhealthy_root_no_fallback_requests.is_empty());
    fs::remove_dir_all(sibling).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

/// A fresh index carrying only the durable creator binding A for the family
/// root and the sibling.
fn e2_unhealthy_bound_index(root: &str) -> ScanIndex {
    let mut index = ScanIndex::default();
    for bound in [root, E2_SIBLING] {
        index.session_account_bindings.insert(
            e2_owner_key(bound),
            SessionAccountBinding {
                account_identifier_hash: e2_account(),
                workspace_identifier_hash: None,
            },
        );
    }
    index
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

/// #909 x SOURCE (Lead B pin): a bucket ACCEPTED tagged and then made Unknown
/// by an unhealthy (malformed) trace still carries #909's per-share refusal,
/// one per changed accepted row, so the server can keep the retained proof.
/// A never-accepted body made Unknown carries none. The root holds two own
/// logins (B, C), so contract-5 grouping, not the D1 shortcut, tags the clean
/// body and the ledger freezes its tagged shares.
fn e2_unhealthy_root_accepted_case(accepted_ledger: bool) {
    let (dir, root, _) = claude_account_family_fixture();
    let support = dir.join("support");
    let (mut api, trace) = e2_family_evidence(&root);
    for (n, row) in api.iter_mut().enumerate() {
        row.account_identifier_hash = Some(if n < 2 { "b" } else { "c" }.repeat(64));
        e2_resign(row);
    }
    e2_write_rows(&support, crate::claude_local_otel::STORE_DIR, &root, &api);
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    let sibling = e2_healthy_sibling(&support);
    let dirs = [dir.clone(), sibling.clone()];
    let path = support
        .join("local-otel/claude-code-trace-ownership")
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    let mut ledger = claude_request_identity::AcceptedBuckets::for_test();
    let in_family = |item: &&SnapshotItem| item.source_session_id != E2_SIBLING;

    let (clean, _, _, _) = e2_unhealthy_root_page(
        &dirs,
        &support,
        &root,
        &mut e2_unhealthy_bound_index(&root),
        false,
        Some(&ledger),
    );
    let root_item = clean
        .iter()
        .find(|item| item.source_session_id == root)
        .unwrap();
    assert_eq!(
        e2_login_counts(root_item),
        BTreeMap::from([(Some("b".repeat(64)), 2), (Some("c".repeat(64)), 2)]),
        "the clean root body is grouped per request"
    );
    // Expected refusals per item: its accepted rows that carried a tag.
    let mut expected = BTreeMap::<String, u64>::new();
    if accepted_ledger {
        // The same ledger write `record_cache_state` makes for a stored ACK.
        for item in &clean {
            ledger.record(&serde_json::to_value(item).unwrap());
        }
        for item in clean.iter().filter(in_family) {
            if ledger.get(&item.source_session_id).is_some() {
                expected.insert(item.source_session_id.clone(), e2_tagged_bucket_rows(item));
            }
        }
        assert!(
            expected.get(&root).is_some_and(|rows| *rows > 0),
            "the root bucket was accepted with tagged shares: {expected:?}"
        );
    }

    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"malformed\n")
        .unwrap();
    e2_sibling_evidence(&support);
    let (items, _, stats, _) = e2_unhealthy_root_page(
        &dirs,
        &support,
        &root,
        &mut e2_unhealthy_bound_index(&root),
        true,
        Some(&ledger),
    );
    assert_eq!(
        serde_json::to_value(stats.unhealthy_root_no_fallback_requests).unwrap(),
        json!({"malformed": 5})
    );
    for item in &items {
        if item.source_session_id == E2_SIBLING {
            assert_eq!(item.request_identity_refusals, 0, "the clean sibling is unchanged");
            continue;
        }
        let requests = if item.source_session_id == root { 4 } else { 1 };
        assert_eq!(
            e2_login_counts(item),
            BTreeMap::from([(None, requests)]),
            "never A, never the accepted B/C"
        );
        let want = expected.get(&item.source_session_id).copied().unwrap_or(0);
        assert_eq!(
            item.request_identity_refusals, want,
            "{}: one refusal per changed accepted row; none for a never-accepted body",
            item.source_session_id
        );
    }
    if !accepted_ledger {
        assert!(items.iter().all(|item| item.request_identity_refusals == 0));
    }

    // Clean again: the accepted shares are re-proven, so nothing is refused.
    e2_write_rows(
        &support,
        "local-otel/claude-code-trace-ownership",
        &root,
        &trace,
    );
    e2_sibling_evidence(&support);
    let (recovered, _, _, _) = e2_unhealthy_root_page(
        &dirs,
        &support,
        &root,
        &mut e2_unhealthy_bound_index(&root),
        false,
        Some(&ledger),
    );
    let root_item = recovered
        .iter()
        .find(|item| item.source_session_id == root)
        .unwrap();
    assert_eq!(
        e2_login_counts(root_item),
        BTreeMap::from([(Some("b".repeat(64)), 2), (Some("c".repeat(64)), 2)])
    );
    assert_eq!(root_item.request_identity_refusals, 0);
    fs::remove_dir_all(sibling).unwrap();
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn e2_pipeline_accepted_bucket_unhealthy_root_keeps_909_refusal() {
    e2_unhealthy_root_accepted_case(true);
}

#[test]
fn e2_pipeline_never_accepted_unhealthy_root_has_no_refusal() {
    e2_unhealthy_root_accepted_case(false);
}

#[test]
fn e2_pipeline_bound_a_split_logins_malformed_trace_is_unknown_not_a() {
    e2_unhealthy_root_case("malformed", true);
}

#[test]
fn e2_pipeline_bound_a_uniform_b_malformed_trace_is_unknown_not_a() {
    e2_unhealthy_root_case("malformed", false);
}

// C2 (Lead B): rows that bypass final identity grouping lose the uniform
// account the emission would carry, for every unhealthy reason. One family
// login B: with two, the account owner already withholds a D1-shaped body.
#[test]
fn e2_pipeline_bound_a_external_billing_malformed_trace_clears_wire_account() {
    e2_unhealthy_root_billing_case("malformed", false, "external");
}

#[test]
fn e2_pipeline_bound_a_mixed_billing_malformed_trace_clears_wire_account() {
    e2_unhealthy_root_billing_case("malformed", false, "mixed");
}

#[test]
fn e2_pipeline_bound_a_external_billing_oversized_trace_clears_wire_account() {
    e2_unhealthy_root_billing_case("oversized", false, "external");
}

#[test]
fn e2_pipeline_bound_a_split_logins_unreadable_trace_is_unknown_not_a() {
    e2_unhealthy_root_case("unreadable", true);
}

#[test]
fn e2_pipeline_bound_a_split_logins_oversized_trace_is_unknown_not_a() {
    e2_unhealthy_root_case("oversized", true);
}

#[test]
fn e2_pipeline_bound_a_split_logins_missing_trace_member_is_unknown_not_a() {
    e2_unhealthy_root_case("incomplete", true);
}

#[test]
fn e2_unhealthy_root_reason_precedence_and_counter_shape() {
    use claude_request_identity::UnhealthyRootReason as Reason;
    assert_eq!(Reason::of(1, 1, 1), Reason::Oversized);
    assert_eq!(Reason::of(0, 1, 1), Reason::Unreadable);
    assert_eq!(Reason::of(0, 0, 1), Reason::Malformed);
    assert_eq!(Reason::of(0, 0, 0), Reason::Incomplete);
    assert!(Reason::Oversized < Reason::Unreadable && Reason::Malformed < Reason::Incomplete);
    let mut counts = ClaudeUnhealthyRootNoFallbackCounts::default();
    assert!(counts.is_empty());
    assert_eq!(serde_json::to_value(counts).unwrap(), json!({}));
    counts.add(Reason::Malformed, 3);
    counts.add(Reason::Incomplete, 2);
    counts.add(Reason::Malformed, 1);
    assert_eq!(
        serde_json::to_value(counts).unwrap(),
        json!({"malformed": 4, "incomplete": 2})
    );
}
