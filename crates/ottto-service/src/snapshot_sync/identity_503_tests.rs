// Identity-503 settlement guarantees; reuse the existing finish and oracle fixtures.
use super::*;
use crate::local_resource_diagnostics::capture;
use crate::snapshots::{scan_source_roots, BACKFILL_WINDOW_DAYS};
use serde_json::json;
const T1: &str = "2026-08-01T00:01:00Z";

/// [money] Real pages: an earlier 503, a grown main-body ACK on a later
/// page, then the scanner's actual retirement. A new terminal-page 503
/// survives that retirement as successor custody; no census flag is forced.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn identity_503_paged_ack_terminal_and_successor_custody() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let project = home.fixture.home.join(".claude/projects/-synthetic-repo");
    let transcript = project.join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let original = std::fs::read_to_string(&transcript).unwrap();
    for n in 2..6 {
        let session = format!("{n}338a80a-f36e-4cbc-a5bb-50fc66430ba5");
        std::fs::write(
            project.join(format!("{session}.jsonl")),
            original
                .replace(IDENTITY_PIPELINE_ROOT, &session)
                .replace("req_", &format!("req_{n}_"))
                .replace("\"id\":\"m", &format!("\"id\":\"m{n}")),
        )
        .unwrap();
    }
    let destination = snapshot_upload_destination_namespace(&home.device, "device-secret");
    let prepare = |home: &mut AckFinishHome| {
        crate::snapshots::OwnedSourceScan::with_oracle_schedule(Some((1, false)), || {
            home.prepare_raw()
        })
    };
    let (preparation, index, scan) = prepare(&mut home);
    assert!(!scan.census_complete);
    assert!(
        index.scan_traversal_in_progress_for_test(),
        "the earlier page is not terminal"
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].source_session_id, IDENTITY_PIPELINE_ROOT);
    let initial_fp = scan.snapshots[0].snapshot_fingerprint.clone();
    let progress_path = preparation.upload_progress_path.clone();
    let index_path = preparation.index_path.clone();
    let reload = |path: &Path| {
        SnapshotUploadProgress::load_for_index(
            &ScanIndex::load(&index_path).unwrap(),
            &index_path,
            path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap()
    };
    server
        .script
        .lock()
        .unwrap()
        .push_back(AckScriptedPost::Identity("503 Service Unavailable"));
    home.finish(preparation, index, scan).unwrap();
    let key = cache_session_key(IDENTITY_PIPELINE_ROOT);
    assert_eq!(
        reload(&progress_path).identity_503_pending,
        Some(BTreeSet::from([key.clone()]))
    );
    let grown = json!({"timestamp": current_rfc3339(), "type": "assistant",
        "sessionId": IDENTITY_PIPELINE_ROOT, "requestId": "req_3", "message": {"id": "m3",
        "model": "claude-haiku-4-5", "usage": {"input_tokens": 30, "output_tokens": 3}}});
    std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap()
        .write_all(format!("{grown}\n").as_bytes())
        .unwrap();
    let _clock =
        prior_index_lifetime_tests::Guard::new(false, None, Some(current_unix_seconds() + 120));
    let mut acked = false;
    for _ in 0..16 {
        let ((preparation, index, scan), rows) = capture(|| prepare(&mut home));
        let retired = rows.iter().find(|row| row["counts"]["event"] == "retiring");
        if let Some(retired) = retired {
            assert!(
                acked,
                "the grown main-upload ACK precedes the terminal verdict"
            );
            assert_eq!(retired["counts"]["raw_census_complete"], true);
            // The page after the ACK reconciles its empty custody before scanning.
            assert!(scan.census_complete, "the actual terminal verdict is clean");
            assert!(
                !scan.snapshots.is_empty(),
                "the terminal page has a successor body"
            );
            let successor = scan
                .snapshots
                .iter()
                .map(|item| cache_session_key(&item.source_session_id))
                .collect::<BTreeSet<_>>();
            server
                .script
                .lock()
                .unwrap()
                .push_back(AckScriptedPost::Identity("503 Service Unavailable"));
            home.finish(preparation, index, scan).unwrap();
            assert_eq!(
                reload(&progress_path).identity_503_pending,
                Some(successor),
                "retirement keeps this pass's new deferrals"
            );
            assert!(
                !crate::backfill::load_backfill_state(&home.support)
                    .destination_completed("claude_code", &destination),
                "the deferred terminal page never switches"
            );
            return;
        }
        let grown_ack = scan.snapshots.iter().any(|item| {
            item.source_session_id == IDENTITY_PIPELINE_ROOT
                && item.snapshot_fingerprint != initial_fp
        });
        home.finish(preparation, index, scan).unwrap();
        if grown_ack {
            assert!(!reload(&progress_path)
                .identity_503_pending
                .as_ref()
                .unwrap()
                .contains(&key));
            acked = true;
        }
    }
    panic!("the finite paged walk must retire");
}

/// [money] Custody classes at the upload seam. Only an identity-unavailable
/// 503 in main-upload mode records the session; only a main-upload stored
/// ACK of it drains. Probe and retry mode, a not-stored ACK and a conflict
/// leave it owed. Serde keeps an empty set distinct from absent, decodes
/// malformed custody as absent, and an older daemon's save drops it.
#[test]
fn identity_503_custody_records_and_drains_only_from_the_main_upload() {
    use crate::snapshot_client::{ShedSnapshotIndexes, UploadShed, UploadShedCode};
    const SESSION: &str = "custody-session";
    let key = cache_session_key(SESSION);
    let items = [format!("{:064x}", 7)];
    let reply = |kind: &str| -> Result<crate::snapshot_client::SnapshotBatchResponse> {
        let shed = |status: u16| -> Result<crate::snapshot_client::SnapshotBatchResponse> {
            Err(anyhow::Error::new(UploadShed {
                status,
                retry_after: Some(Duration::from_secs(60)),
                code: (kind != "ordinary503")
                    .then_some(UploadShedCode::OriginalIdentityUnavailable),
            })
            .context(ShedSnapshotIndexes(vec![0])))
        };
        let entity = serde_json::json!([{"source_session_id": SESSION,
            "snapshot_fingerprint": &items[0], "occurrence_count": 1,
            "unchanged_basis": (kind == "usage_identical").then_some("usage_identical")}]);
        match kind {
            "503" | "ordinary503" => shed(503),
            "429" => shed(429),
            _ => Ok(serde_json::from_value(serde_json::json!({"accepted": 1,
                "sessions_reconciled": 1, "session_ids": [], "disabled": false,
                "disabled_reason": null, "entity_ack_contract": crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
                "accepted_entities": if kind == "stored" { entity.clone() } else { serde_json::json!([]) },
                "unchanged_entities": if kind == "usage_identical" { entity.clone() } else { serde_json::json!([]) },
                "conflict_entities": if kind == "conflict" { entity } else { serde_json::json!([]) }}))
            .unwrap()),
        }
    };
    let owed = Some(BTreeSet::from([key.clone()]));
    for (row, main, kind, before, after, identity_503) in [
        ("503 to a probe or retry", false, "503", None, None, 1),
        ("429 in the main upload", true, "429", None, None, 0),
        ("ordinary 503", true, "ordinary503", None, None, 0),
        (
            "probe or retry ACK",
            false,
            "stored",
            owed.clone(),
            owed.clone(),
            0,
        ),
        (
            "usage_identical, not stored",
            true,
            "usage_identical",
            owed.clone(),
            owed.clone(),
            0,
        ),
        ("conflict", true, "conflict", owed.clone(), owed.clone(), 0),
    ] {
        let mut progress = SnapshotUploadProgress::new(
            format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        );
        progress.identity_503_pending = before;
        progress.identity_503_pass = main.then(BTreeSet::new);
        let mut accepted = 0;
        let result = upload_resumable_batches_with_literal_families(
            &items,
            "identity-503-custody",
            &mut progress,
            &mut accepted,
            String::as_str,
            String::clone,
            |_| Some(SESSION),
            |_| 0,
            |_| None,
            &mut InplaceRetryBudget::default(),
            |_| reply(kind),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(progress.identity_503_pending, after, "{row}");
        if let ResumableUploadResult::Deferred {
            identity_503: n, ..
        } = result
        {
            assert_eq!(n, identity_503, "{row}");
        } else {
            assert_eq!(identity_503, 0, "{row}: {result:?}");
        }
    }
    // A retired walk: earlier keys end with it (one blocked walk), this
    // pass's keys hold the next walk, an owed or unknown cause becomes
    // explicit so the next reconcile settles it, a no-503 walk stays absent.
    let other = "b".repeat(64);
    let both = Some(BTreeSet::from([key.clone(), other.clone()]));
    for (row, before, this_pass, owed, after) in [
        (
            "earlier key, never ACKed",
            owed.clone(),
            BTreeSet::new(),
            true,
            Some(BTreeSet::new()),
        ),
        (
            "this pass's key",
            both,
            BTreeSet::from([other.clone()]),
            true,
            Some(BTreeSet::from([other])),
        ),
    ] {
        let mut progress = SnapshotUploadProgress::new(
            format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        );
        progress.identity_503_pending = before;
        progress.retire_identity_503_custody(this_pass, owed);
        assert_eq!(progress.identity_503_pending, after, "{row}");
    }
    let mut progress = SnapshotUploadProgress::new(
        format!("{:064x}", 99),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    progress.identity_503_pending = Some(BTreeSet::new());
    let saved = serde_json::to_value(&progress).unwrap();
    assert_eq!(saved["identity_503_pending"], serde_json::json!([]));
    let decode = |value: &serde_json::Value| {
        serde_json::from_value::<SnapshotUploadProgress>(value.clone())
            .unwrap()
            .identity_503_pending
    };
    assert_eq!(
        decode(&saved),
        Some(BTreeSet::new()),
        "empty is proof, not absent"
    );
    for malformed in [serde_json::json!(7), serde_json::json!(["not-a-key"])] {
        let mut value = saved.clone();
        value["identity_503_pending"] = malformed;
        assert_eq!(decode(&value), None, "malformed custody is unknown");
    }
    let older: head_conflict_released_progress_fixture::SnapshotUploadProgress =
        serde_json::from_value(saved).unwrap();
    assert_eq!(decode(&serde_json::to_value(older).unwrap()), None);
}

/// [money] Oracle row: the placement positive control (two accounts, a
/// mid-session switch, a side call, an evidence gap, a tagged row) through
/// the real upload ledger. `main` has an accepted revision; its next body
/// meets an identity 503 while `side-call` is stored, and the held page keeps
/// the prior ACK. After a restart the main upload ACKs the grown `main` body
/// and drains the custody: the reassembled route equals cold, and a quiet
/// pass re-sends nothing.
#[test]
fn identity_503_deferral_then_ack_keeps_cold_money_and_placement() {
    use crate::snapshot_client::{ShedSnapshotIndexes, UploadShed, UploadShedCode};
    use crate::snapshots::sampled_scan::transition_fixture::{
        money_oracle, Accepted, IoBytes, Mode,
    };
    use serde_json::{json, Value};
    fn fp(item: &Value) -> &str {
        item["snapshot_fingerprint"].as_str().unwrap()
    }
    fn session(item: &Value) -> Option<&str> {
        item["source_session_id"].as_str()
    }
    let cold = money_oracle::placement_tests::placement_fixture();
    let scratch = crate::test_scratch::ScratchDir::new("identity-503-oracle");
    let namespace = format!("{:064x}", 99);
    let witness = || snapshot_quarantine_witness(SnapshotSource::ClaudeCode);
    // The progress lives on this install's native route.
    let mut owner = ScanIndex::default();
    let index_path = crate::snapshots::e2_pipeline_scan_fixture::bind_fixture_route(
        SnapshotSource::ClaudeCode,
        &mut owner,
        &scratch,
        &namespace,
    );
    owner.save_fixture(&index_path).unwrap();
    let path = snapshot_upload_progress_path(&index_path);
    let mut items = cold.snapshots.values().cloned().collect::<Vec<_>>();
    for (n, item) in items.iter_mut().enumerate() {
        item["snapshot_fingerprint"] = format!("{:064x}", n + 1).into();
    }
    assert_eq!(session(&items[0]), Some("main"));
    let mut prior_main = items[0].clone();
    prior_main["snapshot_fingerprint"] = format!("{:064x}", 9).into();
    prior_main["request_count"] = 1.into();
    let mut deferred_main = items[0].clone();
    deferred_main["snapshot_fingerprint"] = format!("{:064x}", 8).into();
    let send = |progress: &mut SnapshotUploadProgress, items: &[Value], defer: Option<&str>| {
        progress.identity_503_pass = Some(BTreeSet::new());
        let mut emitted = Vec::new();
        let result = upload_resumable_batches_with_literal_families(
            items,
            "identity-503-oracle",
            progress,
            &mut 0,
            fp,
            |item| fp(item).to_string(),
            session,
            |_| 0,
            |_| None,
            &mut InplaceRetryBudget::default(),
            |batch: &[&Value]| {
                if let Some(index) = batch.iter().position(|item| session(item) == defer) {
                    return Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                        code: Some(UploadShedCode::OriginalIdentityUnavailable),
                    })
                    .context(ShedSnapshotIndexes(vec![index])));
                }
                emitted.extend(batch.iter().map(|item| (*item).clone()));
                let refs = batch
                    .iter()
                    .map(|item| {
                        json!({"source_session_id": session(item),
                        "snapshot_fingerprint": fp(item), "occurrence_count": 1})
                    })
                    .collect::<Vec<_>>();
                Ok(serde_json::from_value(json!({"accepted": batch.len(),
                    "sessions_reconciled": batch.len(), "session_ids": [], "disabled": false,
                    "disabled_reason": null,
                    "entity_ack_contract": crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
                    "accepted_entities": refs}))
                .unwrap())
            },
            |state| state.save(&path),
        )
        .unwrap();
        progress.identity_503_pass = None;
        (result, emitted)
    };
    let route =
        |mode, emitted: &[Value], accepted: &[&Value], progress: &SnapshotUploadProgress| {
            let mut route = cold.clone();
            route.mode = mode;
            route.snapshots = emitted
                .iter()
                .map(|body| {
                    let mut body = body.clone();
                    body.as_object_mut().unwrap().remove("snapshot_fingerprint");
                    (session(&body).unwrap().to_owned(), body)
                })
                .collect();
            route.accepted = accepted
                .iter()
                .filter_map(|body| {
                    let witness = progress.accepted_body_witnesses.get(fp(body))?;
                    Some((
                        session(body).unwrap().to_owned(),
                        Accepted {
                            body: (*body).clone(),
                            witness: witness.clone(),
                        },
                    ))
                })
                .collect();
            let ledger = cold
                .snapshots
                .keys()
                .filter_map(|entity| {
                    let state = progress.accepted_identity_buckets.get(entity)?;
                    Some((entity.clone(), serde_json::to_value(state).unwrap()))
                })
                .collect::<BTreeMap<_, _>>();
            route.accepted_identity_buckets = Some(json!(ledger));
            route
        };
    let mut progress = SnapshotUploadProgress::new(namespace.clone(), witness());
    progress.accepted_identity_buckets =
        crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
    let (routed, mut progress) =
        crate::snapshot_sync::tests::routed_progress(&owner, &index_path, progress);
    assert_eq!(routed, path);
    // Stored identity rows are read before each placement comparison.
    let entities = || cold.snapshots.keys().map(String::as_str);
    let (_, _) = send(&mut progress, std::slice::from_ref(&prior_main), None);
    progress.load_identity(entities()).unwrap();
    let prior = route(Mode::Ram, &[], &[&prior_main], &progress);
    let (result, emitted) = send(
        &mut progress,
        &[deferred_main, items[1].clone()],
        Some("main"),
    );
    assert!(matches!(
        result,
        ResumableUploadResult::Deferred {
            count: 1,
            identity_503: 1,
            ..
        }
    ));
    let owed = Some(BTreeSet::from([cache_session_key("main")]));
    assert_eq!(progress.identity_503_pending, owed);
    progress.load_identity(entities()).unwrap();
    let held = route(Mode::Ram, &emitted, &[&prior_main], &progress);
    money_oracle::assert_held("main", &prior, &held, &cold);
    let reload = || {
        let mut restored = crate::snapshot_sync::tests::load_routed_progress(
            &owner,
            &index_path,
            &namespace,
            witness(),
        );
        restored
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        restored
    };
    let mut restored = reload();
    assert_eq!(
        restored.identity_503_pending, owed,
        "custody survives a restart"
    );
    let (_, resent) = send(&mut restored, &items, None);
    assert_eq!(resent.len(), 1, "only the grown main body is sent");
    assert_eq!(reload().identity_503_pending, Some(BTreeSet::new()));
    restored.load_identity(entities()).unwrap();
    let drained = route(
        Mode::Restart,
        &[emitted, resent].concat(),
        &items.iter().collect::<Vec<_>>(),
        &restored,
    );
    money_oracle::assert_equivalent(&cold, &drained);
    money_oracle::assert_no_smaller_reemit("main", &prior, &drained, &cold, false);
    let mut quiet_progress = reload();
    let (_, quiet_emitted) = send(&mut quiet_progress, &items, None);
    quiet_progress.load_identity(entities()).unwrap();
    let mut quiet = route(Mode::Restart, &quiet_emitted, &[], &quiet_progress);
    quiet.batches = quiet_emitted
        .iter()
        .map(|body| serde_json::to_vec(body).unwrap())
        .collect();
    // An upload-only route reads no transcript; its proof is the empty resend.
    quiet.io = IoBytes {
        cheap_checks: Some(0),
        anchor_reads: Some(0),
        other_reads: Some(0),
        ..IoBytes::default()
    };
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
}

/// [money] An identity-503 deferral on an earlier page blocks its walk
/// until custody proves every deferred session ACKed. Real conflicts,
/// unknown custody and an older daemon's save keep it unsettled. Each row
/// runs the real pre-scanner reconcile, then the walk's terminal page.
#[test]
fn isolated_503_custody_decides_the_walk_terminal() {
    use std::collections::BTreeSet;
    use UnsettledUploadCause::{DeferredConflict, Isolated503};
    // An older daemon knows 9 causes: this bit is `unknown` there, and
    // the authoritative flag keeps the walk unsettled.

    let owed = BTreeSet::from(["a".repeat(64)]);
    let drained = BTreeSet::new();
    type Row<'a> = (
        &'a str,
        &'a [UnsettledUploadCause],
        bool,
        Option<&'a BTreeSet<String>>,
        bool,
    );
    let rows: [Row; 6] = [
        (
            "deferred, later ACKed",
            &[Isolated503],
            false,
            Some(&drained),
            true,
        ),
        (
            "unACKed, vanished or never retried",
            &[Isolated503],
            false,
            Some(&owed),
            false,
        ),
        (
            "custody absent or malformed",
            &[Isolated503],
            false,
            None,
            false,
        ),
        ("older daemon saved the bit", &[], true, None, false),
        (
            "503 beside a real conflict",
            &[Isolated503, DeferredConflict],
            false,
            Some(&drained),
            false,
        ),
        ("no 503: absent custody", &[], false, None, true),
    ];
    for (row, causes, older_save, custody, complete) in rows {
        let scratch = crate::test_scratch::ScratchDir::new("isolated-503-walk");
        let roots = [scratch.to_path_buf()];
        let mut index = ScanIndex::default();
        capture(|| index.start_identity_custody_walk_for_test(&roots, T1));
        for cause in causes {
            index.mark_bounded_sweep_unsettled_by(*cause);
        }
        if older_save {
            // The flag and the raw bit, as an older daemon saves them.
            let mut saved = serde_json::to_value(&index).unwrap();
            saved["bounded_sweep_had_unsettled_upload"] = true.into();
            saved["bounded_sweep_unsettled_causes"] = (1 << 9).into();
            index = serde_json::from_value(saved).unwrap();
        }
        let before = index.bounded_sweep_unsettled_cause_names();
        index.reconcile_isolated_503(&mut custody.cloned());
        let (scan, rows) = capture(|| {
            scan_source_roots(
                SnapshotSource::Pi,
                &roots,
                &mut index,
                T1,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap()
        });
        assert!(
            !index.scan_traversal_in_progress_for_test(),
            "{row}: the walk retired"
        );
        let retired = rows
            .iter()
            .find(|row| row["counts"]["event"] == "retiring")
            .unwrap();
        assert_eq!(scan.census_complete, complete, "{row}");
        assert_eq!(retired["counts"]["raw_census_complete"], true, "{row}");
        assert_eq!(
            retired["counts"]["reason"],
            if complete {
                "complete"
            } else {
                "complete_needs_clean_followup"
            },
            "{row}"
        );
        let expected = match row {
            "503 beside a real conflict" => vec!["deferred_conflict"],
            _ if complete => Vec::new(),
            _ => before,
        };
        assert_eq!(
            retired["counts"]["unsettled_causes"],
            json!(expected),
            "{row}"
        );
    }
}

/// A terminal-page 503 leaves custody owed with no walk: the next walk
/// starts held (only that cause survives the start), so even a
/// single-pass walk retires unsettled. After it retires, the ledger
/// makes custody explicit and empty; the next reconcile settles.
#[test]
fn owed_isolated_503_holds_the_next_walk_from_its_start() {
    use std::collections::BTreeSet;
    let scratch = crate::test_scratch::ScratchDir::new("isolated-503-next-walk");
    let roots = [scratch.to_path_buf()];
    let mut index = ScanIndex::default();
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::Isolated503);
    index.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::DeferredConflict);
    index.prepare_historical_replay("identity-custody-replay".into());
    assert_eq!(
        index.bounded_sweep_unsettled_cause_names(),
        ["isolated_503"]
    );
    for (row, mut custody, complete) in [
        (
            "owed session vanished",
            Some(BTreeSet::from(["a".repeat(64)])),
            false,
        ),
        ("custody absent: unknown", None, false),
        ("next walk after retirement", Some(BTreeSet::new()), true),
    ] {
        index.reconcile_isolated_503(&mut custody);
        assert!(!index.scan_traversal_in_progress_for_test(), "{row}");
        let (scan, rows) = capture(|| {
            scan_source_roots(
                SnapshotSource::Pi,
                &roots,
                &mut index,
                T1,
                BACKFILL_WINDOW_DAYS,
            )
            .unwrap()
        });
        let retired = rows.iter().find(|row| row["counts"]["event"] == "retiring");
        assert_eq!(scan.census_complete, complete, "{row}");
        assert_eq!(
            retired.unwrap()["counts"]["unsettled_causes"],
            if complete {
                json!([])
            } else {
                json!(["isolated_503"])
            },
            "{row}"
        );
        assert_ne!(
            custody,
            Some(BTreeSet::new()),
            "{row}: settled custody clears"
        );
    }
}
