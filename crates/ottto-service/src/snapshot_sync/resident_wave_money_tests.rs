// The same native corpus, one page versus resident-paced pages. Actual upload
// batches may differ: the oracle receives final ACKed entities, never a claim
// that the two transport histories are identical.
use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::with_resident_budget;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle, Accepted, Mode, RouteResult,
};

struct Wave {
    route: RouteResult,
    progress: SnapshotUploadProgress,
    index: ScanIndex,
    pages: usize,
    reads: usize,
    deferred: usize,
    chunked_deferrals: usize,
    complete: bool,
    receipts: BTreeMap<String, Value>,
}

fn final_view(
    mut routes: Vec<RouteResult>,
    progress: &SnapshotUploadProgress,
    prior: Option<&RouteResult>,
) -> RouteResult {
    let mut result = if routes.is_empty() {
        let mut result = prior
            .expect("a quiet update needs prior accepted proof")
            .clone();
        result.batches.clear();
        result.snapshots.clear();
        result
    } else {
        routes.remove(0)
    };
    for route in routes {
        for (entity, body) in route.snapshots {
            assert!(
                result.snapshots.insert(entity, body).is_none(),
                "no extra copy of unchanged entity"
            );
        }
        result.batches.extend(route.batches);
    }
    if let Some(prior) = prior {
        for (entity, body) in &prior.snapshots {
            if !result.snapshots.contains_key(entity) {
                let accepted = &prior.accepted[entity];
                let fp = body["snapshot_fingerprint"].as_str().unwrap();
                assert_eq!(
                    progress.accepted_body_witnesses.get(fp),
                    Some(&accepted.witness)
                );
                result.snapshots.insert(entity.clone(), body.clone());
            }
        }
    }
    // Canonicalize only batch framing/order, after every original envelope was
    // validated against its actual typed item by RouteResult::emitted.
    canonical_entities(&mut result);
    result.accepted = result
        .snapshots
        .iter()
        .map(|(entity, body)| {
            let fp = body["snapshot_fingerprint"].as_str().unwrap();
            let witness = progress
                .accepted_body_witnesses
                .get(fp)
                .expect("exact stored-body ACK")
                .clone();
            (
                entity.clone(),
                Accepted {
                    body: body.clone(),
                    witness,
                },
            )
        })
        .collect();
    result.accepted_identity_buckets = Some(json!(result
        .snapshots
        .keys()
        .map(|id| (id.clone(), progress.accepted_identity_buckets.get(id)))
        .collect::<BTreeMap<_, _>>()));
    result
}

fn canonical_entities(result: &mut RouteResult) {
    result.normalized = json!([{"source": result.source.api_slug(),
        "snapshots": result.snapshots.values().collect::<Vec<_>>() }]);
}

fn drain(c: &Corpus, budget: f64, restart: bool) -> Wave {
    drain_from(
        c,
        budget,
        restart,
        ScanIndex::default(),
        e2_progress(),
        None,
    )
}

fn drain_from(
    c: &Corpus,
    budget: f64,
    restart: bool,
    mut index: ScanIndex,
    mut progress: SnapshotUploadProgress,
    prior: Option<&RouteResult>,
) -> Wave {
    let mut scanner = E2ScanFixture::capturing_identity();
    if let Some(route) = crate::snapshots::e2_pipeline_scan_fixture::route_of(&index) {
        scanner.on_committed_route(&route);
    }
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let mut routes = Vec::new();
    let mut deferred = 0;
    let mut chunked_deferrals = 0;
    let mut reads = 0;
    let mut pages = 0;
    let mut complete = false;
    for _ in 0..32 {
        let mut page = with_resident_budget(budget, || c.raw(&scanner, index, 100, true, &[]));
        pages += 1;
        reads += page.scan.scanned_file_count;
        deferred += usize::from(page.scan.charge_deferred);
        complete = page.scan.census_complete;
        let chunks_before = crate::snapshot_sync::evidence_chunks_for_test();
        page.enrich(c);
        chunked_deferrals += usize::from(
            page.scan.charge_deferred
                && crate::snapshot_sync::evidence_chunks_for_test() - chunks_before > 1,
        );
        page.finish();
        let sent = under_required_cas(&page.scan.snapshots, &progress);
        let (status, batches, _) = upload(&sent, &mut progress, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let posted = batches
            .iter()
            .flat_map(|bytes| {
                let wire: Value = serde_json::from_slice(bytes).unwrap();
                wire["snapshots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| item["snapshot_fingerprint"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>();
        for item in sent
            .iter()
            .filter(|item| !posted.contains(&item.snapshot_fingerprint))
        {
            assert_eq!(
                progress
                    .accepted_body_witnesses
                    .get(&item.snapshot_fingerprint),
                Some(&snapshot_upload_body_witness(item)),
                "unchanged body must already have exact ACK proof"
            );
        }
        let posted_items = sent
            .iter()
            .filter(|item| posted.contains(&item.snapshot_fingerprint))
            .cloned()
            .collect::<Vec<_>>();
        if !posted_items.is_empty() {
            routes.push(RouteResult::emitted(
                if budget.is_infinite() {
                    Mode::ColdFull
                } else if restart {
                    Mode::Restart
                } else {
                    Mode::Ram
                },
                SnapshotSource::ClaudeCode,
                batches,
                &posted_items,
            ));
        }
        settle_index_after_upload(&mut page.index, &page.committed, &progress);
        accept_upload_context_acks_for_test(
            &mut page.index,
            &page.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        // Save every deferral; a new owner must drain it, not assume zero IO.
        index = c.reload(&mut page.index);
        if complete && !page.scan.charge_deferred {
            break;
        }
        assert!(page.scan.charge_deferred);
        if restart {
            let progress_path = c.base.join("resident-progress.json");
            progress.save(&progress_path).unwrap();
            progress = SnapshotUploadProgress::load(
                &progress_path,
                &format!("{:064x}", 99),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap();
            progress
                .accepted_identity_buckets
                .bind_test_key(Some([0x42; 32]));
            scanner = E2ScanFixture::capturing_identity();
            scanner.on_committed_route(
                &crate::snapshots::e2_pipeline_scan_fixture::route_of(&index).unwrap(),
            );
        }
    }
    assert!(complete, "eventual drain for finite stable work");
    assert!(!routes.is_empty() || prior.is_some());
    let route = final_view(routes, &progress, prior);
    let receipts = index
        .files
        .iter()
        .map(|(key, entry)| {
            (
                key.clone(),
                serde_json::to_value(&entry.upload_context_receipt).unwrap(),
            )
        })
        .collect();
    Wave {
        route,
        progress,
        index,
        pages,
        reads,
        deferred,
        chunked_deferrals,
        complete,
        receipts,
    }
}

/// [money] A resident-deferred page also packs its admitted families into
/// evidence chunks. Its saved drain equals one wide page enriched as one chunk.
#[test]
fn resident_deferred_packed_evidence_matches_one_page_one_chunk() {
    if !supported("resident-packed-evidence") {
        return;
    }
    with_e2(|| {
        let (c, _) = evidence_chunk_tests::three_family_page("resident-packed-evidence");
        for path in c.births.keys() {
            input_clock(path);
        }
        let wide = evidence_chunk_tests::isolated(|| {
            crate::snapshot_sync::ONE_EVIDENCE_CHUNK.with(|one| {
                let previous = one.replace(true);
                let wide = drain(&c, f64::INFINITY, false);
                one.set(previous);
                wide
            })
        });
        let small = evidence_chunk_tests::isolated(|| drain(&c, 0.15, true));
        assert_eq!(wide.pages, 1);
        assert!(small.pages > 1 && small.deferred > 0);
        assert!(
            small.chunked_deferrals > 0,
            "the same page must be both resident-deferred and packed into multiple chunks"
        );
        assert_eq!(wide.reads, 3);
        assert_eq!(small.reads, wide.reads, "no extra physical read");
        money_oracle::assert_equivalent(&wide.route, &small.route);
        money_oracle::assert_no_smaller_reemit(
            wide.route.snapshots.keys().next().unwrap(),
            &wide.route,
            &small.route,
            &wide.route,
            false,
        );
        assert_eq!(small.receipts, wide.receipts);
        assert_eq!(small.route.accepted, wide.route.accepted);
        assert_eq!(
            small.progress.accepted_identity_buckets,
            wide.progress.accepted_identity_buckets
        );
        assert!(wide.complete && small.complete);
    });
}

fn corpus_with_family(name: &str) -> Corpus {
    let mut c = corpus(name);
    for n in 0..5 {
        let id = format!("{}338a80a-f36e-4cbc-a5bb-50fc66430ba5", n + 1);
        let body = if n == 0 {
            line(ROOT, "r1", AT, 10)
                + &line(ROOT, "r2", "2026-08-02T07:00:20Z", 20)
                + &line(ROOT, "gap", "2026-08-02T07:00:25Z", 12)
        } else {
            line(&id, &format!("request-{n}"), AT, 5 + n)
        };
        let path = c.root(&id, &body);
        input_clock(&path);
    }
    let agent = c.agent(0, &line(ROOT, "child", "2026-08-02T07:00:30Z", 7));
    input_clock(&agent);
    // A real account switch, a gap, and a side call owned by the child.
    // Native enrichment also runs inherit_root_accounts on the split family.
    c.evidence(
        &[
            api_login(ROOT, "r1", 10, '1', Some('7')),
            api_login(ROOT, "r2", 20, '2', Some('8')),
            api_login(ROOT, "child", 7, '2', Some('8')),
            api_login(ROOT, "side", 3, '2', Some('8')),
        ],
        &[
            trace_for(ROOT, "r1", ""),
            trace_for(ROOT, "r2", ""),
            trace_for(ROOT, "child", "000"),
            trace_for(ROOT, "side", "000"),
        ],
    );
    c
}

/// [money] One page and at least three paced pages have identical final
/// ACKed bodies, receipts, accepted placement buckets and census completion.
/// Restart-between-pages drains owed files, then a quiet restart reads zero.
#[test]
fn resident_wave_final_acked_money_and_saved_deferral_restart_are_equal() {
    if !supported("resident-wave") {
        return;
    }
    with_e2(|| {
        let c = corpus_with_family("resident-wave-final");
        let wide = drain(&c, f64::INFINITY, false);
        let small = drain(&c, 0.05, false);
        let restarted = drain(&c, 0.05, true);
        assert_eq!(wide.pages, 1);
        assert!(small.pages >= 3 && restarted.pages >= 3);
        assert!(small.deferred > 0 && restarted.deferred > 0);
        assert_eq!(wide.reads, 6);
        for other in [&small, &restarted] {
            money_oracle::assert_equivalent(&wide.route, &other.route);
            money_oracle::assert_no_smaller_reemit(
                ROOT,
                &wide.route,
                &other.route,
                &wide.route,
                false,
            );
            assert_eq!(
                other.reads, wide.reads,
                "each forced/split member is read exactly once"
            );
            assert_eq!(other.receipts, wide.receipts);
            assert_eq!(other.complete, wide.complete);
            assert_eq!(other.route.accepted, wide.route.accepted);
            assert_eq!(
                other.progress.accepted_identity_buckets,
                wide.progress.accepted_identity_buckets
            );
        }
        assert!(
            wide.route.snapshots[ROOT]["request_count"]
                .as_u64()
                .unwrap()
                >= 3
        );
        let placement = serde_json::to_string(&wide.route.snapshots[ROOT]["model_usage"]).unwrap();
        assert!(
            placement.contains(&"1".repeat(64)) && placement.contains(&"2".repeat(64)),
            "two tagged accounts and a switch"
        );
        assert!(
            wide.route.snapshots[&format!("{ROOT}_agent-000")]["request_count"]
                .as_u64()
                .unwrap()
                >= 2,
            "the split child owns its native response and side call"
        );
        // Existing quiet-roster fixture: every saved deferral has drained first.
        // Save the metadata-only settled roster, then restart from that save.
        let mut quiet_index = restarted.index;
        quiet_index.activate_upload_context("e2-synthetic-destination".into());
        quiet_index.activate_effective_upload_body_witness_revision(3);
        quiet_index.adopt_effective_upload_body_witness_revision_monotonically();
        quiet_index.load_claude_reemission_exclusions(&c.support);
        crate::snapshots::e2_pipeline_scan_fixture::retain_indexed_walk_for_test(
            &mut quiet_index,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&c.root),
            "2026-08-02T08:00:00Z",
            183,
        );
        let quiet_index = c.reload(&mut quiet_index);
        let scanner = E2ScanFixture::capturing_identity();
        scanner.on_committed_route(
            &crate::snapshots::e2_pipeline_scan_fixture::route_of(&quiet_index).unwrap(),
        );
        // Plain Claude files use the same observed object/parser byte seams.
        let ((quiet, batches), io) =
            crate::snapshots::sampled_scan::transition_fixture::observe_codex_quiet(|| {
                let mut quiet = c.raw(&scanner, quiet_index, 100, true, &[]);
                quiet.enrich(&c);
                quiet.finish();
                let (status, batches, _) =
                    upload(&quiet.scan.snapshots, &mut restarted.progress.clone(), ack);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                assert!(batches.is_empty());
                (quiet, batches)
            });
        let mut result =
            RouteResult::emitted(Mode::Restart, SnapshotSource::ClaudeCode, batches, &[]);
        result.io = io;
        result.modes = quiet.modes;
        money_oracle::assert_quiet_restart_zero_bytes(&result);
    });
}

/// [money] Deferred units retain nonempty accepted proof and never settle an
/// unaccepted successor; an exact ACK receipt survives a process reopen.
#[test]
fn resident_wave_held_money_survives_refusal_not_stored_partial_and_ack_crash() {
    if !supported("resident-wave-held") {
        return;
    }
    with_e2(|| {
        let c = corpus_with_family("resident-wave-held");
        let wide = drain(&c, f64::INFINITY, false);
        // Every successor comes from a real native append, not edited totals.
        for path in c.births.keys() {
            let session = path.file_stem().unwrap().to_str().unwrap();
            let session = if session.starts_with("agent-") {
                ROOT
            } else {
                session
            };
            append(
                path,
                &line(session, "successor", "2026-08-02T07:00:40Z", 13),
            );
        }
        let mut cold_page = c.raw(
            &E2ScanFixture::capturing_identity(),
            wide.index.clone(),
            100,
            true,
            &[],
        );
        assert!(
            cold_page.modes.0 > 0,
            "cold Full keeps the same prior receipt context"
        );
        cold_page.enrich(&c);
        cold_page.finish();
        let mut cold = mixed_route_acked(&cold_page, &wide.progress, Mode::ColdFull, ack).0;
        canonical_entities(&mut cold);
        for refusal in ["refused", "not_stored", "partial", "crash_after_ack"] {
            let mut progress = wide.progress.clone();
            let scanner = E2ScanFixture::capturing_identity();
            scanner.on_committed_route(
                &crate::snapshots::e2_pipeline_scan_fixture::route_of(&wide.index).unwrap(),
            );
            let mut page =
                with_resident_budget(if refusal == "partial" { 0.25 } else { 0.05 }, || {
                    c.raw(&scanner, wide.index.clone(), 100, true, &[])
                });
            assert!(page.scan.charge_deferred);
            page.enrich(&c);
            page.finish();
            let offered = under_required_cas(&page.scan.snapshots, &progress);
            assert!(
                !offered.is_empty(),
                "the ACK control must send a native body"
            );
            if refusal == "partial" {
                assert!(offered.len() >= 2);
            }
            let refused_entity = offered.last().unwrap().source_session_id.clone();
            let before = progress.accepted_body_witnesses.clone();
            let (_, wire, _) = upload(&offered, &mut progress, |batch| {
                let mut response = ack_with_disposition(batch, refusal)?;
                if refusal == "partial" {
                    if let Some(at) = response
                        .accepted_entities
                        .iter()
                        .position(|e| e.source_session_id == refused_entity)
                    {
                        let mut refused = response.accepted_entities.remove(at);
                        response.accepted -= 1;
                        response.sessions_reconciled -= 1;
                        refused.head_challenge = refused.head_etag.take().map(|_| "c".repeat(64));
                        response.conflict_entities.push(refused);
                    }
                }
                Ok(response)
            });
            if refusal == "crash_after_ack" {
                let path = c.base.join("ack-crash-progress.json");
                progress.save(&path).unwrap();
                progress = SnapshotUploadProgress::load(
                    &path,
                    &format!("{:064x}", 99),
                    snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
                )
                .unwrap();
                let before = progress.accepted_body_witnesses.clone();
                let (status, batches, _) = upload(&offered, &mut progress, ack);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                assert!(
                    batches.is_empty(),
                    "exact receipt suppresses duplicate after ACK"
                );
                assert_eq!(progress.accepted_body_witnesses, before);
            } else if refusal == "partial" {
                for item in &offered {
                    let observed = progress
                        .accepted_body_witnesses
                        .get(&item.snapshot_fingerprint);
                    if item.source_session_id == refused_entity {
                        assert_eq!(observed, before.get(&item.snapshot_fingerprint));
                    } else {
                        assert_eq!(observed, Some(&snapshot_upload_body_witness(item)));
                    }
                }
            } else {
                assert_eq!(
                    progress.accepted_body_witnesses, before,
                    "no settlement without exact stored-body ACK"
                );
            }
            // Observe a deferred entity's accepted proof from the real prior ACK.
            let held = wide
                .route
                .snapshots
                .keys()
                .find(|entity| !offered.iter().any(|i| &i.source_session_id == *entity))
                .unwrap();
            let mut actual =
                RouteResult::emitted(Mode::Ram, SnapshotSource::ClaudeCode, wire, &offered);
            let body = &wide.route.snapshots[held];
            let fp = body["snapshot_fingerprint"].as_str().unwrap();
            actual.accepted.insert(
                held.clone(),
                Accepted {
                    body: body.clone(),
                    witness: progress.accepted_body_witnesses[fp].clone(),
                },
            );
            canonical_entities(&mut actual);
            let mut expected = cold.clone();
            expected
                .snapshots
                .retain(|id, _| actual.snapshots.contains_key(id) || id == held);
            expected.accepted_identity_buckets = None;
            actual.accepted_identity_buckets = None;
            canonical_entities(&mut expected);
            money_oracle::assert_held(held, &wide.route, &actual, &expected);
            money_oracle::assert_no_smaller_reemit(held, &wide.route, &actual, &expected, true);
        }
    });
}

/// [money] Path twins force their complete family. A tiny allowance still
/// admits that unit whole and reads each physical member once across pages.
#[test]
fn resident_wave_twins_and_forced_family_are_read_once() {
    if !supported("resident-wave-twins") {
        return;
    }
    with_e2(|| {
        let mut c = corpus_with_family("resident-wave-twins");
        let body = std::fs::read_to_string(c.root.join(format!("{ROOT}.jsonl"))).unwrap();
        let twin = c.write_at(&format!("copy/{ROOT}.jsonl"), &body, "2026-08-02T07:00:00Z");
        input_clock(&twin);
        let wide = drain(&c, f64::INFINITY, false);
        let paced = drain(&c, 0.05, true);
        assert_eq!(wide.reads, 7);
        assert_eq!(paced.reads, wide.reads);
        assert!(paced.deferred > 0);
        money_oracle::assert_equivalent(&wide.route, &paced.route);
        assert_eq!(wide.receipts, paced.receipts);
    });
}

/// [money] The mass late-evidence wave re-folds committed Tails with no native
/// transcript read. Page saves and a new owner retain exact final ACK money.
#[test]
fn resident_wave_source_changed_tail_refolds_match_one_page() {
    if !supported("resident-wave-refolds") {
        return;
    }
    with_e2(|| {
        let c = corpus_with_family("resident-wave-refolds");
        let wide_seed = drain(&c, f64::INFINITY, false);
        let small_seed = drain(&c, f64::INFINITY, false);
        // New finish evidence for every root; native transcripts stay fixed.
        for n in 1..5 {
            let id = format!("{}338a80a-f36e-4cbc-a5bb-50fc66430ba5", n + 1);
            let request = format!("request-{n}");
            c.evidence_for(
                &id,
                &[api_for(&id, &request, 5 + n, 90)],
                &[trace_for(&id, &request, "")],
            );
        }
        c.evidence(
            &[
                api_login(ROOT, "r1", 10, '1', Some('7')),
                api_login(ROOT, "r2", 20, '2', Some('8')),
                api_login(ROOT, "child", 7, '2', Some('8')),
                api_login(ROOT, "side", 3, '2', Some('8')),
                api_login(ROOT, "late", 2, '2', Some('8')),
            ],
            &[
                trace_for(ROOT, "r1", ""),
                trace_for(ROOT, "r2", ""),
                trace_for(ROOT, "child", "000"),
                trace_for(ROOT, "side", "000"),
                trace_for(ROOT, "late", "000"),
            ],
        );
        let (wide, w_bytes) =
            crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
                drain_from(
                    &c,
                    f64::INFINITY,
                    false,
                    wide_seed.index,
                    wide_seed.progress,
                    Some(&wide_seed.route),
                )
            });
        let (small, s_bytes) =
            crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
                drain_from(
                    &c,
                    0.087_100_1,
                    true,
                    small_seed.index,
                    small_seed.progress,
                    Some(&small_seed.route),
                )
            });
        assert_eq!((w_bytes, s_bytes), (0, 0));
        assert_eq!(wide.pages, 1);
        assert!(
            small.pages >= 5 && small.deferred > 0,
            "Tail reduction pages must charge beyond c_f"
        );
        money_oracle::assert_equivalent(&wide.route, &small.route);
        money_oracle::assert_no_smaller_reemit(
            ROOT,
            &wide_seed.route,
            &small.route,
            &wide.route,
            false,
        );
        assert_eq!(wide.receipts, small.receipts);
        assert_eq!(wide.route.accepted, small.route.accepted);
    });
}
