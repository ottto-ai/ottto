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
    let ((disposition, _, stats), released) = e2::pipeline_test_observer::capture_released(|| {
        apply_claude_local_evidence_to_scan_in_context(
            &c.support,
            &mut page.scan,
            &mut page.index,
            Some(&progress.accepted_identity_buckets),
            Default::default(),
            std::slice::from_ref(&c.root),
            183,
        )
    });
    page.disposition = disposition;
    page.stats = stats;
    page.released = released;
    page.index
        .veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut page.scan.snapshots);
    let deferred = page.index.bind_session_accounts_with_mixed(
        SnapshotSource::ClaudeCode,
        "e2-synthetic-machine",
        &mut page.scan.snapshots,
        &[],
        (&[], &mut [0; 9]),
        &page.disposition.mixed_uploads,
    );
    page.disposition.defer_sessions(deferred);
    crate::snapshots::apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut page.scan.snapshots,
        page.upload_policy,
    );
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

fn member_ack_controls(child: &SnapshotItem) {
    for fault in ["refused", "not_stored", "partial"] {
        let mut progress = new_progress();
        let items = std::slice::from_ref(child);
        let (_, sent, _) = upload(items, &mut progress, |batch| {
            let mut response = ack(batch)?;
            let mut reference = response.accepted_entities.pop().unwrap();
            response.accepted = 0;
            response.sessions_reconciled = 0;
            match fault {
                "refused" => response.rejected_entities.push(
                    crate::snapshot_client::SnapshotEntityRejection {
                        source_session_id: reference.source_session_id,
                        snapshot_fingerprint: reference.snapshot_fingerprint,
                        occurrence_count: reference.occurrence_count,
                        reason: "usage_accounting_authority_downgrade".into(),
                        detail: "synthetic refusal".into(),
                        permanent: true,
                    },
                ),
                "not_stored" => {
                    reference.unchanged_basis = Some("usage_identical".into());
                    response.accepted = reference.occurrence_count;
                    response.sessions_reconciled = response.accepted;
                    response.unchanged_entities.push(reference);
                }
                _ => {} // the partial response omitted this member's ACK
            }
            Ok(response)
        });
        assert!(!sent.is_empty());
        assert!(
            progress.accepted_body_witnesses.is_empty(),
            "{fault}: no stored-body credit"
        );
        assert!(
            progress
                .accepted_identity_buckets
                .get(&child.source_session_id)
                .is_none(),
            "{fault}: no accepted member placement"
        );
        // Retry from durable progress, without a captured refusal's quarantine,
        // has the identical literal body and exact witness.
        let mut retry = new_progress();
        let (_, resent, _) = upload(items, &mut retry, ack);
        assert_eq!(resent, sent);
        assert_eq!(
            retry
                .accepted_body_witnesses
                .get(&child.snapshot_fingerprint),
            Some(&snapshot_upload_body_witness(child))
        );
    }
}

/// [regress] A member created after its family listing keeps both its matching
/// request and true side call off the root, without holding the root. Native
/// final-page retirement, root no-op/refusal, both crash boundaries and placement
/// are one matrix over the same stable final corpus.
#[test]
fn late_member_native_pages_match_cold_money_and_placement() {
    for (mode, refuse_root, crash_ack) in [
        (Mode::Ram, false, false),
        (Mode::DiskRestore, false, false),
        (Mode::Restart, false, true),
        (Mode::Restart, true, true),
    ] {
        with_e2(|| {
            let (mut c, root) = corpus();
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
            // ACKed body, before its file receipt save: the next unchanged
            // native read is still owed, so it really carries the root fold.
            let prior = c.reload(&mut first.index);
            let mut page = c.raw(&scanner, prior, 100, true, std::slice::from_ref(&root));
            assert!(page.scan.census_complete);
            assert!(serde_json::to_value(&page.index).unwrap()["traversal"].is_null());
            assert!(page
                .scan
                .snapshots
                .iter()
                .any(|item| item.source_session_id == ROOT));
            let member = c.agent(
                0,
                &(line(ROOT, "m", MEMBER, 30) + &line(ROOT, "gap", GAP, 7)),
            );
            evidence(&c, true, "agent-000"); // already-prefixed id must round-trip
            e2::take_diag();
            enrich(&c, &mut page, &mut progress);
            let diag = e2::take_diag();
            assert_eq!(diag.get("side_call_member_probes"), Some(&1));
            assert_eq!(diag.get("side_call_member_hints"), Some(&1));
            assert!(!diag.contains_key("held_side_call_undiscovered"));
            assert!(!page.scan.census_complete);
            assert!(pending(&page.index, &member));
            page.finish();
            assert_eq!(
                canonical(&page.scan.snapshots),
                canonical(&stable),
                "P1 root body, money, buckets and witness stay unchanged"
            );
            let accepted_root = progress.accepted_identity_buckets.get(ROOT).cloned();
            if refuse_root {
                let mut refusal = new_progress();
                let (status, _, _) = upload(&page.scan.snapshots, &mut refusal, |batch| {
                    let mut response = ack(batch)?;
                    response.rejected_entities = std::mem::take(&mut response.accepted_entities)
                        .into_iter()
                        .map(|entity| crate::snapshot_client::SnapshotEntityRejection {
                            source_session_id: entity.source_session_id,
                            snapshot_fingerprint: entity.snapshot_fingerprint,
                            occurrence_count: entity.occurrence_count,
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
                assert!(refusal.accepted_fingerprints.is_empty());
                let checkpoint = checkpoint_partial_snapshot_index(
                    &page.index,
                    &page.committed,
                    &refusal,
                    &page.scan.snapshots,
                    Some(&page.scan),
                    &BTreeSet::new(),
                    &c.base.join("root-refused-index.json"),
                    &c.base.join("root-refused-progress.json"),
                    || Ok(()),
                )
                .unwrap();
                page.index = checkpoint;
            } else {
                let (_, batches, _) = upload(&page.scan.snapshots, &mut progress, ack);
                assert!(batches.is_empty(), "accepted root is a real upload no-op");
            }
            assert_eq!(
                progress.accepted_identity_buckets.get(ROOT).cloned(),
                accepted_root
            );
            if mode != Mode::Ram {
                scanner = restart(&c, &mut page, &mut progress);
            } else {
                page.index = c.reload(&mut page.index);
            }
            assert!(
                pending(&page.index, &member),
                "hint survives settlement and save"
            );
            let mut latest = BTreeMap::from([(ROOT.to_owned(), stable[0].clone())]);
            let mut index = page.index;
            let mut member_read = false;
            let mut ack_crashed = false;
            for _ in 0..8 {
                let mut next = c.raw(&scanner, index, 1, true, &[]);
                enrich(&c, &mut next, &mut progress);
                next.finish();
                for item in &next.scan.snapshots {
                    if item.source_session_id == ROOT {
                        assert_eq!(
                            canonical(item),
                            canonical(&stable[0]),
                            "root never rises or drops"
                        );
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
                if !ack_crashed
                    && next
                        .scan
                        .snapshots
                        .iter()
                        .any(|item| item.source_session_id != ROOT)
                {
                    let child = next
                        .scan
                        .snapshots
                        .iter()
                        .find(|item| item.source_session_id != ROOT)
                        .unwrap();
                    member_ack_controls(child);
                }
                if member_read && crash_ack && !ack_crashed {
                    ack_crashed = true;
                    upload(&next.scan.snapshots, &mut progress, ack).0.unwrap();
                    // Crash after exact body ACK, before saving file receipts.
                    scanner = restart(&c, &mut next, &mut progress);
                    let before = next.scan.snapshots.clone();
                    next = c.raw(&scanner, next.index, 100, true, &[]);
                    enrich(&c, &mut next, &mut progress);
                    next.finish();
                    for child in before.iter().filter(|item| item.source_session_id != ROOT) {
                        let replayed = next
                            .scan
                            .snapshots
                            .iter()
                            .find(|item| item.source_session_id == child.source_session_id)
                            .expect("ACK without receipt save leaves member owed");
                        assert_eq!(
                            canonical(replayed),
                            canonical(child),
                            "post-ACK restart is exact"
                        );
                    }
                }
                settle_page(&c, &mut next, &mut progress);
                let complete = next.scan.census_complete;
                index = next.index;
                if member_read && complete {
                    break;
                }
            }
            assert!(
                member_read,
                "exact hinted member eventually reaches native acquisition"
            );
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
            // The ledger already accepted these bytes; a fresh wire proof only
            // supplies the same final entity framing to the shared oracle.
            let actual = route(&items, &mut progress, mode);
            money_oracle::assert_equivalent(&cold_route, &actual);
            money_oracle::assert_placement_equivalent(&cold_route, &actual);
            money_oracle::assert_no_smaller_reemit(ROOT, &cold_route, &actual, &cold_route, false);
            let root_json = &actual.snapshots[ROOT];
            assert!(!root_json["request_evidence"].as_array().unwrap().is_empty());
            let serialized = serde_json::to_string(root_json).unwrap();
            assert!(
                serialized.contains(&"1".repeat(64)) && serialized.contains(&"2".repeat(64)),
                "root has both accounts across its switch"
            );
            let child = &actual.snapshots[&format!("{ROOT}_agent-000")];
            assert!(
                serde_json::to_string(child)
                    .unwrap()
                    .contains(&"9".repeat(64)),
                "member side-call placement retains its own organization"
            );
            assert_eq!(child["request_count"], 3);
            let mut saved = index;
            let prior = c.reload(&mut saved);
            let quiet_owner = E2ScanFixture::capturing_identity();
            if let Some(path) = crate::snapshots::e2_pipeline_scan_fixture::route_of(&prior) {
                quiet_owner.on_committed_route(&path);
            }
            let (mut quiet, io) =
                crate::snapshots::sampled_scan::transition_fixture::observe_codex_quiet(|| {
                    let mut page = c.raw(&quiet_owner, prior, 100, true, &[]);
                    enrich(&c, &mut page, &mut progress);
                    page.finish();
                    page
                });
            let (_, batches, _) = upload(&quiet.scan.snapshots, &mut progress, ack);
            assert!(batches.is_empty());
            let mut quiet_result =
                RouteResult::emitted(Mode::Restart, SnapshotSource::ClaudeCode, batches, &[]);
            quiet_result.modes = quiet.modes;
            quiet_result.io = io;
            money_oracle::assert_quiet_restart_zero_bytes(&quiet_result);
            // The save still contains no newly owed late-member work.
            settle_page(&c, &mut quiet, &mut progress);
        });
    }
}

/// Absence preserves the old fallback; unusable trace filenames cannot escape
/// the family anchor. A metadata error reserves ownership, never proves absence.
#[test]
fn late_member_absence_and_metadata_error_controls() {
    for (kind, agent, fallback, hints) in [
        ("absent", "000", 2, 0),
        ("invalid", "../escape", 2, 0),
        ("error", "000", 0, 1),
    ] {
        with_e2(|| {
            let (c, _) = corpus();
            let scanner = E2ScanFixture::capturing_identity();
            let mut p = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
            assert!(p.scan.census_complete);
            #[cfg(unix)]
            if kind == "error" {
                let directory = c.root.join(ROOT).join("subagents");
                std::fs::remove_dir(&directory).unwrap();
                std::os::unix::fs::symlink("subagents", &directory).unwrap(); // ELOOP
            }
            #[cfg(not(unix))]
            if kind == "error" {
                return;
            }
            evidence(&c, true, agent);
            e2::take_diag();
            enrich(&c, &mut p, &mut new_progress());
            let diag = e2::take_diag();
            p.finish();
            assert_eq!(p.scan.snapshots[0].request_count, 2 + fallback);
            assert_eq!(
                diag.get("side_call_member_hints").copied().unwrap_or(0),
                hints
            );
            assert_eq!(p.scan.census_complete, hints == 0);
            assert!(!diag.contains_key("held_side_call_undiscovered"));
            assert!(p.scan.snapshots[0].telemetry_owned_complete.is_some());
            if kind == "absent" {
                let expected = route(&p.scan.snapshots, &mut new_progress(), Mode::ColdFull);
                let mut progress = new_progress();
                settle_page(&c, &mut p, &mut progress);
                let prior = p.index;
                let owner = E2ScanFixture::capturing_identity();
                let mut again = c.raw(&owner, prior, 100, true, &[]);
                enrich(&c, &mut again, &mut progress);
                again.finish();
                // A saved exact body may suppress emission; the accepted body
                // remains the old root fallback, with no hint or member entity.
                let items = if again.scan.snapshots.is_empty() {
                    p.scan.snapshots
                } else {
                    again.scan.snapshots
                };
                let actual = route(&items, &mut progress, Mode::Restart);
                money_oracle::assert_equivalent(&expected, &actual);
            }
        });
    }
}
