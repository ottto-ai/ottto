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
    permitted: bool,
) -> (Vec<SnapshotItem>, ClaudeUsageAuthorityDisposition, bool) {
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
        let permit = permitted
            .then(|| {
                claude_request_identity::permit_when(
                    true,
                    SnapshotSource::ClaudeCode,
                    Some(claude_request_identity::COHORT_HINT_TOKEN),
                )
                .ok()
            })
            .flatten();
        assert_eq!(permit.is_some(), permitted);
        let (disposition, _, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan_with_permit(
                support, &mut scan, index, permit,
            );
        (
            scan.snapshots,
            disposition,
            stats.effort_evidence_load_failed,
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
    for permitted in [true, false] {
        let mut index = ScanIndex::default();
        let (items, disposition, read_failed) =
            e2_page(std::slice::from_ref(&dir), &support, &mut index, permitted);
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
            assert!(e2_is_literal(item), "{label} (permitted={permitted})");
            assert_eq!(item.request_count, requests, "{label}: own requests only");
            e2_assert_identity_consistent(item, label);
            assert!(
                e2_rows(item).all(|row| row.account_identifier_hash == Some(e2_account())),
                "{label}: the one proven login tags every final row (permitted={permitted})"
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
    fs::copy(&original, &copy).unwrap();
    let births_known = [&original, &copy]
        .iter()
        .all(|path| fs::metadata(path).and_then(|m| m.created()).is_ok());
    let dirs = [dir.clone(), copy_dir.clone()];
    let mut index = ScanIndex::default();
    // The first page may meet the twins in either order (disclosed residual).
    e2_page(&dirs, &support, &mut index, true);
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
    let (items, disposition, _) = e2_page(&dirs, &support, &mut index, true);
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
        e2_page(std::slice::from_ref(&dir), &support, &mut index, true);
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
