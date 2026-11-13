// Late Task members use native selection, evidence folding, upload and durable
// settlement. The file is deliberately separate from shared money fixtures.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};

const SWITCH: &str = "2026-08-02T07:00:20Z";
const MEMBER: &str = "2026-08-02T07:00:30Z";
const SIDE: &str = "2026-08-02T07:00:40Z";
const GAP: &str = "2026-08-02T07:00:50Z";

fn login(
    request: &str,
    tokens: u64,
    account: char,
    org: char,
    at: &str,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = api_login(ROOT, request, tokens, account, Some(org));
    row.observed_at = at.into();
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn evidence(c: &Corpus, late: bool, agent: &str) {
    let mut rows = vec![
        login("a", 10, '1', '8', AT),
        login("b", 20, '2', '9', SWITCH),
    ];
    let mut traces = vec![trace("a", ""), trace("b", "")];
    if late {
        rows.extend([
            login("m", 30, '2', '9', MEMBER),
            login("s", 5, '2', '9', SIDE),
        ]);
        traces.extend([trace("m", agent), trace("s", agent)]);
    }
    c.evidence(&rows, &traces);
}
fn corpus() -> (Corpus, PathBuf) {
    let mut c = Corpus::new("late-member-side-calls");
    let root = c.root(
        ROOT,
        &(line(ROOT, "a", AT, 10) + &line(ROOT, "b", SWITCH, 20)),
    );
    std::fs::create_dir_all(c.root.join(ROOT).join("subagents")).unwrap();
    evidence(&c, false, "000");
    (c, root)
}
fn enrich(c: &Corpus, page: &mut Page, progress: &mut SnapshotUploadProgress) {
    page.enrich_with(c, Some(&mut progress.accepted_identity_buckets));
    let hints = std::mem::take(&mut page.disposition.side_call_hints);
    if !hints.is_empty() {
        page.scan.enqueue_claude_discovery_hints(
            &mut page.index,
            std::slice::from_ref(&c.root),
            183,
            &hints,
        );
        page.scan.census_complete = false;
    }
}
fn new_progress() -> SnapshotUploadProgress {
    let mut progress = e2_progress();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    progress
}
fn pending(index: &ScanIndex, path: &Path) -> bool {
    let state = serde_json::to_value(index).unwrap();
    state["traversal"]["pending_candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|candidate| {
            candidate["path"] == json!(path)
                && candidate["census_member"] == true
                && candidate["watcher_hint"] == true
        })
}
fn restart(c: &Corpus, page: &mut Page, progress: &mut SnapshotUploadProgress) -> E2ScanFixture {
    page.index = c.reload(&mut page.index);
    let path = c.base.join("late-progress.json");
    progress.save(&path).unwrap();
    *progress = SnapshotUploadProgress::load(
        &path,
        &format!("{:064x}", 99),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let scanner = E2ScanFixture::capturing_identity();
    if let Some(route) = crate::snapshots::e2_pipeline_scan_fixture::route_of(&page.index) {
        scanner.on_committed_route(&route);
    }
    scanner
}
fn route(items: &[SnapshotItem], progress: &mut SnapshotUploadProgress, mode: Mode) -> RouteResult {
    let (status, batches, _) = upload(items, progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    // Validate actual wire first; final comparisons collapse only page framing.
    let sent = if batches.is_empty() {
        for item in items {
            assert_eq!(
                progress
                    .accepted_body_witnesses
                    .get(&item.snapshot_fingerprint),
                Some(&snapshot_upload_body_witness(item)),
                "final body has an exact stored ACK"
            );
        }
        vec![canonical(&request(items))]
    } else {
        batches
    };
    let mut result = RouteResult::emitted(mode, SnapshotSource::ClaudeCode, sent, items);
    result.normalized = json!([{"source":"claude_code",
        "snapshots":result.snapshots.values().collect::<Vec<_>>() }]);
    result.accepted_identity_buckets = Some(json!(result
        .snapshots
        .keys()
        .map(|id| (id.clone(), progress.accepted_identity_buckets.get(id)))
        .collect::<BTreeMap<_, _>>()));
    result
}
fn settle_page(c: &Corpus, page: &mut Page, progress: &mut SnapshotUploadProgress) {
    let holds = page.finish();
    upload(&page.scan.snapshots, progress, ack).0.unwrap();
    let mut settled =
        settle_completed_upload(page.index.clone(), &page.committed, progress, &holds);
    settle_index_after_upload(&mut settled.index, &page.committed, progress);
    accept_upload_context_acks_for_test(
        &mut settled.index,
        &page.scan.snapshots,
        &progress.fresh_context_body_acks,
    );
    page.index = c.reload(&mut settled.index);
}

fn root_unchanged(stable: &[SnapshotItem], actual: &[SnapshotItem]) {
    assert_eq!(actual.len(), 1);
    assert_eq!(
        snapshot_upload_body_witness(&actual[0]),
        snapshot_upload_body_witness(&stable[0])
    );
    let wire = |items: &[SnapshotItem]| {
        RouteResult::emitted(
            Mode::Ram,
            SnapshotSource::ClaudeCode,
            vec![canonical(&request(items))],
            items,
        )
    };
    // The shared oracle owns source-witness normalization; every money,
    // placement and remaining envelope field still compares exactly.
    money_oracle::assert_equivalent(&wire(stable), &wire(actual));
}

/// [regress] A Task member born after the final native listing reserves m/s
/// off the unchanged root. Exact hinted discovery survives save/restart, with
/// the root's original two-account placement and member's explicit B evidence.
#[test]
fn late_member_native_pages_match_cold_money_and_placement() {
    for mode in [Mode::Ram, Mode::Restart] {
        with_e2(|| {
            let (mut c, root) = corpus();
            let root_bytes = std::fs::read(&root).unwrap();
            let mut scanner = E2ScanFixture::capturing_identity();
            let mut progress = new_progress();
            let mut first = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
            enrich(&c, &mut first, &mut progress);
            first.finish();
            let stable = first.scan.snapshots.clone();
            assert_eq!(stable.len(), 1);
            upload(&stable, &mut progress, ack).0.unwrap();
            first
                .index
                .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
            let prior = c.reload(&mut first.index);
            // Changed sidecars select the same unchanged root transcript.
            evidence(&c, true, "agent-000");
            let mut page = c.raw(&scanner, prior, 100, true, std::slice::from_ref(&root));
            assert!(page.scan.census_complete);
            assert!(serde_json::to_value(&page.index).unwrap()["traversal"].is_null());
            let member = c.agent(
                0,
                &(line(ROOT, "m", MEMBER, 30) + &line(ROOT, "gap", GAP, 7)),
            );
            assert_eq!(
                std::fs::read(&root).unwrap(),
                root_bytes,
                "same root file/revision"
            );
            e2::take_diag();
            enrich(&c, &mut page, &mut progress);
            let diag = e2::take_diag();
            assert_eq!(diag.get("side_call_member_hints"), Some(&1));
            assert!(!diag.contains_key("held_side_call_undiscovered"));
            assert!(!page.scan.census_complete);
            assert!(pending(&page.index, &member));
            page.finish();
            root_unchanged(&stable, &page.scan.snapshots);
            if mode == Mode::Restart {
                // This is the sole proof that a root refusal's partial
                // checkpoint preserves the newly queued member.
                let mut refused = new_progress();
                let (status, _, _) = upload(&page.scan.snapshots, &mut refused, |batch| {
                    let mut response = ack(batch)?;
                    response.rejected_entities = std::mem::take(&mut response.accepted_entities)
                        .into_iter()
                        .map(|r| crate::snapshot_client::SnapshotEntityRejection {
                            source_session_id: r.source_session_id,
                            snapshot_fingerprint: r.snapshot_fingerprint,
                            occurrence_count: r.occurrence_count,
                            reason: "usage_accounting_authority_downgrade".into(),
                            detail: "synthetic root refusal".into(),
                            permanent: true,
                        })
                        .collect();
                    response.accepted = 0;
                    response.sessions_reconciled = 0;
                    Ok(response)
                });
                assert!(matches!(
                    status.unwrap(),
                    ResumableUploadResult::Rejected { .. }
                ));
                page.index = checkpoint_partial_snapshot_index(
                    &page.index,
                    &page.committed,
                    &refused,
                    &page.scan.snapshots,
                    Some(&page.scan),
                    &BTreeSet::new(),
                    &c.base.join("refused-index.json"),
                    &c.base.join("refused-progress.json"),
                    || Ok(()),
                )
                .unwrap();
                scanner = restart(&c, &mut page, &mut progress);
            } else {
                let (_, batches, _) = upload(&page.scan.snapshots, &mut progress, ack);
                assert!(batches.is_empty(), "root no-op");
                page.index = c.reload(&mut page.index);
            }
            assert!(
                pending(&page.index, &member),
                "exact hint survives save and root outcome"
            );
            let mut latest = BTreeMap::from([(ROOT.to_owned(), stable[0].clone())]);
            let mut index = page.index;
            let mut member_read = false;
            for _ in 0..8 {
                let mut next = c.raw(&scanner, index, 1, true, &[]);
                enrich(&c, &mut next, &mut progress);
                next.finish();
                for item in &next.scan.snapshots {
                    if item.source_session_id == ROOT {
                        root_unchanged(&stable, std::slice::from_ref(item));
                    } else {
                        assert_eq!(
                            (item.request_count, item.input_tokens),
                            (3, 42),
                            "m, gap, s once"
                        );
                        member_read = true;
                    }
                    latest.insert(item.source_session_id.clone(), item.clone());
                }
                settle_page(&c, &mut next, &mut progress);
                let complete = next.scan.census_complete;
                index = next.index;
                if member_read && complete {
                    break;
                }
            }
            assert!(member_read, "hint eventually reaches native acquisition");
            let mut cold = c.raw(
                &E2ScanFixture::capturing_identity(),
                ScanIndex::default(),
                100,
                false,
                &[],
            );
            let mut cold_progress = new_progress();
            enrich(&c, &mut cold, &mut cold_progress);
            cold.finish();
            let cold_route = route(&cold.scan.snapshots, &mut cold_progress, Mode::ColdFull);
            let items = latest.into_values().collect::<Vec<_>>();
            let actual = route(&items, &mut progress, mode);
            money_oracle::assert_equivalent(&cold_route, &actual);
            money_oracle::assert_placement_equivalent(&cold_route, &actual);
            money_oracle::assert_no_smaller_reemit(ROOT, &cold_route, &actual, &cold_route, false);
            let root = serde_json::to_string(&actual.snapshots[ROOT]).unwrap();
            assert!(
                root.contains(&"1".repeat(64)) && root.contains(&"2".repeat(64)),
                "two accounts"
            );
            let child = &actual.snapshots[&format!("{ROOT}_agent-000")];
            assert!(
                serde_json::to_string(child)
                    .unwrap()
                    .contains(&"9".repeat(64)),
                "member organization B"
            );
            assert_eq!(child["request_count"], 3);
        });
    }
}

/// No transcript exists for the same valid trace owner: preserve the old
/// root fallback, including placement, through an ordinary durable restart.
#[test]
fn late_member_absence_keeps_root_fallback() {
    with_e2(|| {
        let (c, _) = corpus();
        let scanner = E2ScanFixture::capturing_identity();
        evidence(&c, true, "000");
        let mut p = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
        let mut progress = new_progress();
        e2::take_diag();
        enrich(&c, &mut p, &mut progress);
        assert!(!e2::take_diag().contains_key("side_call_member_hints"));
        assert!(p.scan.census_complete);
        p.finish();
        assert_eq!(
            (
                p.scan.snapshots[0].request_count,
                p.scan.snapshots[0].input_tokens
            ),
            (4, 65)
        );
        let expected = route(&p.scan.snapshots, &mut progress, Mode::ColdFull);
        settle_page(&c, &mut p, &mut progress);
        let owner = restart(&c, &mut p, &mut progress);
        let mut again = c.raw(&owner, p.index, 100, true, &[]);
        enrich(&c, &mut again, &mut progress);
        again.finish();
        let items = if again.scan.snapshots.is_empty() {
            p.scan.snapshots
        } else {
            again.scan.snapshots
        };
        let actual = route(&items, &mut progress, Mode::Restart);
        money_oracle::assert_equivalent(&expected, &actual);
    });
}
