// Every way a pass can end: the exits of `finish_sync_source`, driven through
// the real function after a real prepare, on the scripted (`AckScriptedServer`,
// `AckFinishHome`) and oracle (`OracleServer`, `OracleHome`) fixtures. Every
// transcript, credential and HTTP answer is synthetic and local.
//
// "Receipt" is the terminal status report. "Withdrawn" means the receipt
// carries no census manifest. An exit pinned elsewhere names its test and file.
//
//  1. A continuation preparation reaches finish. Writes nothing, sends
//     nothing, returns an error. Not pinned here: plain error propagation
//     before any upload.
//  2. The recovery guard cannot be built, or the entry checks fail (recovery
//     validation, destination authority, the Codex fenced census write).
//     Nothing sent; only the Codex fenced census may be written. Not pinned
//     here: plain error propagation before any upload.
//  3. Idle pass (nothing read, no walk started). Advisory maintenance only;
//     sends no receipt; records a success cadence with zero accepted; re-arms
//     the walk gate; Ok. Pinned by `idle_pass_emits_no_body` and
//     `clean_source_idles_without_a_receipt` (walk_gate_oracle_tests.rs). The
//     zero-accepted cadence is not pinned here: the cadence exposes no
//     reading that tells it from any other quiet success.
//  4. A local save before the upload fails (telemetry seed, identity load,
//     copy-derived invalidation, tracking confirmation, quarantine prune,
//     manifest window, cache-head debt, re-offer deadline, reprojected
//     refusal, held quarantine retry, telemetry-only binding). Earlier saves
//     stand; nothing sent; error. Not pinned here: plain error propagation
//     before any upload.
//  5. Recovery-only pass whose local checkpoint fails. Nothing sent; error.
//     Not pinned here, as row 6.
//  6. Recovery-only pass whose local checkpoint succeeds. Saves the index
//     locally, uploads nothing, sends nothing, returns
//     "state_v2_save_recovered_retry". Not pinned here: it needs a state-store
//     save hold set before finish, which no finish fixture builds today.
//  7. The cache-head probe fails with an error that is neither a capacity
//     stop nor an outage, or applying its results fails. Probe pages already
//     acknowledged stay saved; no receipt, no cadence; the raw error. Not
//     pinned here: it needs the negotiated cache contract and a malformed
//     probe answer, which only the re-offer pipeline drives.
//  8. Shed upload. Saves outage custody and the partial checkpoint; sends
//     `server_error`, withdrawn, counts from the partial index (or the
//     committed one if that save failed); notes the shed and defers the
//     source; Ok. `shed_and_disabled_receipts_withdraw_the_manifest` pins the
//     receipt, the deferral and the return, not the saves or the counts; the
//     next pass walks: `unsettled_upload_never_arms`
//     (walk_gate_oracle_tests.rs).
//  9. Shed upload whose receipt cannot be sent: error.
//     `receipt_send_failure_at_each_exit`.
// 10. Upload disabled by the backend. Skips the selected save and the
//     markers; sends Disabled with the server's reason, withdrawn; defers
//     nothing; Ok. `shed_and_disabled_receipts_withdraw_the_manifest` pins the
//     receipt, the missing deferral and the return.
// 11. Disabled upload whose receipt cannot be sent: error.
//     `receipt_send_failure_at_each_exit`.
// 12. Shed or failed upload whose ACK release after a good partial save
//     fails. Index saved; no receipt; error. Not pinned here: it needs a
//     ledger save that fails only after the partial index save.
// 13. Failed upload, local state failure during the page. No partial index
//     save; sends `scan_error`, withdrawn; error "local snapshot state
//     failed". `failed_upload_receipt_names_each_failure_class` pins the
//     receipt, the error and that no ACK is durable. The skipped partial
//     save is not pinned: the fixture's held ledger lock would stop that save
//     as well.
// 14. Failed upload, capacity stop (ACK settlement pending). Partial
//     checkpoint; keeps the census-wait count; sends `scan_error`; error
//     "local snapshot ACK settlement pending".
//     `failed_upload_receipt_names_each_failure_class` (not the checkpoint);
//     the count's reset:
//     `ack_census_wait_count_resets_on_a_disabled_finish_between_capacity_stops`
//     (permanent_finish_pipeline_tests.rs).
// 15. Failed upload, an acknowledgement that does not match the request.
//     Sends `server_error`; error "backend snapshot response was invalid".
//     `failed_upload_receipt_names_each_failure_class`.
// 16. Failed upload, local contract preflight. Sends
//     `backend_validation_error`. Not pinned here: it needs a body over the
//     identity item cap, a much larger fixture.
// 17. Failed upload, backend authorization rejected. Sends `auth_error`.
//     `failed_upload_receipt_names_each_failure_class`.
// 18. Failed upload, backend payload rejection that names no item. Sends
//     `backend_validation_error`.
//     `failed_upload_receipt_names_each_failure_class`.
// 19. Failed upload, anything else (a dropped connection, an outage). Saves
//     outage custody and the partial checkpoint; records the loss; sends
//     `network_error`; error "upload local snapshots".
//     `failed_upload_receipt_names_each_failure_class` pins the receipt, the
//     error and the partial checkpoint; custody, restart and replay:
//     `c06_crash_windows_preserve_placement_and_durable_suppression`
//     (once_credit_oracle_tests.rs).
// 20. Failed upload whose receipt cannot be sent: the upload's own error
//     text, not the receipt's. `receipt_send_failure_at_each_exit`.
// 21. Staging the selected ACK retirement fails. Page saves only; no
//     receipt; error. Not pinned here: no fixture makes staging fail.
// 22. Authority lost or the Codex checkpoint invalid before the selected
//     save, or the selected save fails. Page saves only; no receipt; error.
//     `e2_real_caller_parity_at_tight_allowances`
//     (prior_index_lifetime_tests.rs), with a competing save; which of the
//     two checks fires is not pinned.
// 23. Failure right after the selected save. Index saved and manifest
//     published; no receipt; error.
//     `c02_durable_ack_suppresses_replay_of_the_prior_index`
//     (once_credit_oracle_tests.rs), `hint_loss_failed_finish_walks_next`
//     (walk_gate_oracle_tests.rs).
// 24. The unverified-history marker clear fails. Index saved, success
//     cadence recorded; no receipt; error.
//     `failure_after_the_selected_save_leaves_the_rest_to_the_next_pass`,
//     with the failure injected just before the clear; the cadence is not
//     pinned.
// 25. The backfill completion write fails. As row 24, and the unverified
//     marker may already be cleared.
//     `failure_after_the_selected_save_leaves_the_rest_to_the_next_pass`,
//     with the failure injected just before the write.
// 26. Retiring the pass's progress fails. Index and both markers written; no
//     receipt; error.
//     `failure_after_the_selected_save_leaves_the_rest_to_the_next_pass`
//     (the markers are already written), `hint_loss_deleted_file_walks_next`
//     (walk_gate_oracle_tests.rs). That the ledger itself is left unretired
//     is not pinned: a reload adopts what the saved index already holds.
// 27. Disclosed refusal (a rejected page, or a permanent refusal retained on
//     a quiet pass). Everything saved; sends the refusal state, with the
//     manifest exactly when the census is complete; a failed send is
//     ignored; Ok. `permanent_finish_real_pipeline_preserves_refusal_and_status_failures`
//     (permanent_finish_pipeline_tests.rs).
// 28. Deferred page whose holds are all isolated. As row 27; Ok.
//     `markers_and_manifest_on_a_finished_pass` (manifest and markers),
//     `identity_503_paged_ack_terminal_and_successor_custody`
//     (identity_503_tests.rs).
// 29. Deferred page with a hold that is not isolated. As row 27, then the
//     error `snapshot_entity_deferred`.
//     `validation_and_witness_finish_still_defer`
//     (permanent_finish_pipeline_tests.rs; it checks only that it fails).
// 30. Success whose receipt cannot be sent. Everything saved; error; the
//     walk gate is not armed and the next pass walks.
//     `success_receipt_send_failure_fails_the_pass_and_leaves_the_walk_gate_unarmed`
//     pins the tried receipt, the error, the empty gate and the next walk.
// 31. Success. Writes the markers (the unverified marker cleared on a gated,
//     complete, settled Claude census; destination completion with this
//     pass's scan start after a successful backfill); sends Success with the
//     manifest exactly when the census is complete; arms the walk gate when
//     nothing is owed; Ok. `markers_and_manifest_on_a_finished_pass`; Pi
//     completion is relied on by `owner_return_preserves_all_source_carry`
//     (relogin_pipeline_tests.rs). The completion write does not branch by
//     source, so Codex has no row of its own.

use super::*;

const SCAN_START: &str = "2026-11-02T03:04:05Z";

fn receipt_count(server: &AckScriptedServer) -> usize {
    server.statuses.lock().unwrap().len()
}

fn last_receipt(server: &AckScriptedServer) -> Value {
    let statuses = server.statuses.lock().unwrap();
    statuses.last().cloned().expect("a terminal receipt")
}

fn saved_generation(index_path: &Path) -> u64 {
    ScanIndex::load(index_path).map_or(0, |index| index.generation)
}

/// The saved ledger, reloaded from disk as the next pass would.
fn reload_progress(
    home: &AckFinishHome,
    index_path: &Path,
    progress_path: &Path,
) -> SnapshotUploadProgress {
    SnapshotUploadProgress::load_for_index(
        &ScanIndex::load(index_path).unwrap(),
        index_path,
        progress_path,
        &snapshot_upload_destination_namespace(&home.device, "device-secret"),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap()
}

/// The status endpoint refused the receipt itself (the fixtures answer 500).
fn is_receipt_send_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::snapshot_client::UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| {
            diagnostics
                .safe_message()
                .contains("endpoint=snapshot_status")
        })
}

fn mark_history_unverified(home: &AckFinishHome) {
    crate::backfill::update_backfill_state(&home.support, |state| {
        state.prior_history_unverified = true;
    })
    .unwrap();
}

fn completion_written(home: &AckFinishHome) -> bool {
    crate::backfill::load_backfill_state(&home.support).destination_completed(
        SnapshotSource::ClaudeCode.api_slug(),
        &snapshot_upload_destination_namespace(&home.device, "device-secret"),
    )
}

fn reset_shed_state(source: SnapshotSource) {
    crate::snapshot_sync::retry::clear_source_upload_deadlines_for_test();
    crate::snapshot_sync::retry::clear_shed_streak(source);
}

/// Shed and disabled passes fail when their receipt cannot be sent. A failed
/// upload returns its own error whatever the receipt does. The disclosed
/// refusal is pinned by `PermanentStatusFailure`, the success exit below.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
#[serial(source_upload_deadlines)]
fn receipt_send_failure_at_each_exit() {
    let source = SnapshotSource::ClaudeCode;
    for (post, propagated) in [
        (AckScriptedPost::Shed, true),
        (AckScriptedPost::Disabled, true),
        (AckScriptedPost::Drop, false),
    ] {
        reset_shed_state(source);
        let server = AckScriptedServer::new();
        let mut home = AckFinishHome::new(&server);
        let (preparation, index, scan) = home.prepare(&format!("{post:?}"));
        server.script.lock().unwrap().push_back(post);
        server
            .status_fails
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let error = home.finish(preparation, index, scan).unwrap_err();
        assert_eq!(server.offered.lock().unwrap().len(), 1, "{post:?}");
        assert_eq!(receipt_count(&server), 1, "{post:?}: the receipt was tried");
        let tried = last_receipt(&server);
        match post {
            AckScriptedPost::Shed => assert_eq!(tried["last_error_code"], "server_error"),
            AckScriptedPost::Disabled => assert_eq!(tried["enabled"], false),
            _ => assert_eq!(tried["last_error_code"], "network_error"),
        }
        if propagated {
            assert!(is_receipt_send_failure(&error), "{post:?}: {error:#}");
        } else {
            assert_eq!(error.to_string(), "upload local snapshots", "{error:#}");
        }
    }
    reset_shed_state(source);
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    Post(AckScriptedPost),
    /// Another owner holds the progress ledger's lock during the POST, so the
    /// page's own save of its ACK fails.
    LocalState,
    /// Retained ACK debt over the admission capacity: no page is sent.
    CapacityStop,
}

/// Six failure classes through the failed-upload exit: the receipt's code and
/// message, the returned error's context and that no ACK is durable. The pass
/// after each reports again with another code; what it serves is not pinned.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn failed_upload_receipt_names_each_failure_class() {
    use crate::snapshot_sync::ack_retention;
    let source = SnapshotSource::ClaudeCode;
    ack_retention::note_capacity_stop_census(source, false, true);
    let debt = ack_followup_debt(5000);
    for (fault, code, message, context) in [
        (
            Fault::Post(AckScriptedPost::Drop),
            "network_error",
            "local snapshot upload failed",
            "upload local snapshots",
        ),
        (
            Fault::Post(AckScriptedPost::Unauthorized),
            "auth_error",
            "backend rejected snapshot batch authorization",
            "backend rejected snapshot batch authorization",
        ),
        (
            Fault::Post(AckScriptedPost::UnnamedRejection),
            "backend_validation_error",
            "backend rejected snapshot batch payload validation",
            "backend rejected snapshot batch payload validation",
        ),
        (
            Fault::Post(AckScriptedPost::ForeignAck),
            "server_error",
            "backend snapshot response did not match the request",
            "backend snapshot response was invalid",
        ),
        (
            Fault::LocalState,
            "scan_error",
            "local snapshot checkpoint or destination state failed",
            "local snapshot state failed",
        ),
        (
            Fault::CapacityStop,
            "scan_error",
            "local snapshot ACK settlement pending",
            "local snapshot ACK settlement pending",
        ),
    ] {
        let server = AckScriptedServer::new();
        let mut home = AckFinishHome::new(&server);
        let (mut preparation, index, scan) = home.prepare(&format!("{fault:?}"));
        let index_path = preparation.index_path.clone();
        let progress_path = preparation.upload_progress_path.clone();
        match fault {
            Fault::Post(post) => server.script.lock().unwrap().push_back(post),
            Fault::LocalState => {
                *server.lock_progress_on_post.lock().unwrap() = Some(progress_path.clone());
            }
            Fault::CapacityStop => ack_followup_set_debt(&mut preparation, &debt, true),
        }
        let generation = saved_generation(&index_path);
        let error = home.finish(preparation, index, scan).unwrap_err();
        drop(server.held_progress_lock.lock().unwrap().take());
        assert_eq!(error.to_string(), context, "{fault:?}: {error:#}");
        assert_eq!(receipt_count(&server), 1, "{fault:?}");
        let sent = last_receipt(&server);
        assert_eq!(sent["last_error_code"], code, "{fault:?}");
        assert_eq!(sent["last_error_message"], message, "{fault:?}");
        assert_eq!(sent["enabled"], true, "{fault:?}");
        assert_eq!(sent["consecutive_failures"], 1, "{fault:?}");
        assert!(sent.get("manifest").is_none(), "{fault:?}: withdrawn");
        let offered = server.offered.lock().unwrap().clone();
        if let Fault::CapacityStop = fault {
            assert!(error
                .downcast_ref::<ack_retention::AckSettlementRequired>()
                .is_some());
            assert!(offered.is_empty(), "a capacity stop sends no page");
            assert_eq!(ack_retention::incomplete_census_capacity_stops(source), 1);
        } else {
            assert_eq!(offered.len(), 1, "{fault:?}: one real POST");
            let fingerprint = offered[0]["snapshot_fingerprint"].as_str().unwrap();
            let progress = reload_progress(&home, &index_path, &progress_path);
            assert!(
                !progress.accepted_fingerprints.contains(fingerprint),
                "{fault:?}: no ACK is durable"
            );
        }
        if let Fault::Post(AckScriptedPost::Drop) = fault {
            assert!(
                saved_generation(&index_path) > generation,
                "the outage's partial checkpoint commits the read"
            );
        }
        let (mut preparation, index, scan) = home.prepare_raw();
        if let Fault::CapacityStop = fault {
            ack_followup_set_debt(&mut preparation, &debt, false);
        }
        home.finish(preparation, index, scan)
            .unwrap_or_else(|error| panic!("{fault:?}: the next pass: {error:#}"));
        assert_eq!(receipt_count(&server), 2, "{fault:?}");
        assert_ne!(last_receipt(&server)["last_error_code"], code, "{fault:?}");
    }
    ack_retention::note_capacity_stop_census(source, false, true);
}

/// Shed and disabled receipts carry no manifest even after a complete census,
/// and both passes return Ok. Only the shed defers the source.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
#[serial(source_upload_deadlines)]
fn shed_and_disabled_receipts_withdraw_the_manifest() {
    let source = SnapshotSource::ClaudeCode;
    for post in [AckScriptedPost::Shed, AckScriptedPost::Disabled] {
        reset_shed_state(source);
        let server = AckScriptedServer::new();
        let mut home = AckFinishHome::new(&server);
        let (preparation, index, scan) = home.prepare_raw();
        assert!(
            scan.census_complete,
            "{post:?}: a manifest would be publishable"
        );
        server.script.lock().unwrap().push_back(post);
        home.finish(preparation, index, scan)
            .unwrap_or_else(|error| panic!("{post:?}: {error:#}"));
        assert_eq!(receipt_count(&server), 1, "{post:?}");
        let sent = last_receipt(&server);
        assert!(sent.get("manifest").is_none(), "{post:?}: {sent}");
        let backoff = crate::snapshot_sync::retry::source_upload_backoff_remaining(source);
        let streak = crate::snapshot_sync::retry::source_shed_streaks()
            .lock()
            .unwrap()
            .get(source.api_slug())
            .copied();
        if let AckScriptedPost::Shed = post {
            assert_eq!(sent["enabled"], true);
            assert_eq!(sent["last_error_code"], "server_error");
            assert_eq!(
                sent["last_error_message"],
                "backend shed the snapshot upload; honouring backoff"
            );
            assert!(
                backoff.is_some_and(|left| left > Duration::from_secs(50)),
                "the server's Retry-After is honoured: {backoff:?}"
            );
            assert_eq!(streak, Some(1));
        } else {
            assert_eq!(sent["enabled"], false);
            assert_eq!(sent["disabled_reason"], "synthetic_disabled");
            assert_eq!(sent.get("last_error_code"), Some(&Value::Null));
            assert_eq!(backoff, None);
            assert_eq!(streak, None);
        }
    }
    reset_shed_state(source);
}

/// The three failure points after the selected save. Each leaves the index
/// saved, sends no receipt, and leaves what follows it to the next pass. The
/// `unverified_marker` and `backfill_completion` points fire before their
/// markers' conditions are checked, so these rows pin only where each failure
/// falls in the order; `markers_and_manifest_on_a_finished_pass` pins the
/// conditions.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn failure_after_the_selected_save_leaves_the_rest_to_the_next_pass() {
    for (stage, gated, completion_at_failure) in [
        ("unverified_marker", true, false),
        ("backfill_completion", false, false),
        ("finish_cycle", false, true),
    ] {
        let server = AckScriptedServer::new();
        let mut home = AckFinishHome::new(&server);
        if gated {
            mark_history_unverified(&home);
        }
        let (preparation, index, scan) = home.prepare_raw();
        assert!(scan.census_complete, "{stage}");
        let index_path = preparation.index_path.clone();
        let generation = saved_generation(&index_path);
        let failure = SaveFailure::at(stage);
        let error = home.finish(preparation, index, scan).unwrap_err();
        drop(failure);
        assert_eq!(
            error.to_string(),
            format!("synthetic post-index-save failure: {stage}")
        );
        assert!(saved_generation(&index_path) > generation, "{stage}: saved");
        assert_eq!(receipt_count(&server), 0, "{stage}: no receipt");
        let state = crate::backfill::load_backfill_state(&home.support);
        assert_eq!(state.prior_history_unverified, gated, "{stage}");
        assert_eq!(completion_written(&home), completion_at_failure, "{stage}");
        if !gated {
            let offered = server.offered.lock().unwrap().clone();
            let fingerprint = offered[0]["snapshot_fingerprint"].as_str().unwrap();
            assert!(ScanIndex::load(&index_path)
                .unwrap()
                .accepted_snapshot_fingerprint_recorded(fingerprint));
        }
        let (preparation, index, scan) = home.prepare_raw();
        home.finish(preparation, index, scan)
            .unwrap_or_else(|error| panic!("{stage}: the next pass: {error:#}"));
        assert_eq!(receipt_count(&server), 1, "{stage}");
        if !gated {
            let sent = last_receipt(&server);
            assert_eq!(sent.get("last_error_code"), Some(&Value::Null), "{stage}");
        }
        let state = crate::backfill::load_backfill_state(&home.support);
        assert!(
            !state.prior_history_unverified,
            "{stage}: cleared next pass"
        );
        // A gated destination owes no bootstrap, so it records no completion.
        assert_eq!(completion_written(&home), !gated, "{stage}");
    }
}

/// The two markers and the manifest on passes that reach the end. The scan
/// start is set apart from the census window end, which the receipt binds,
/// so the completion timestamp cannot be confused with it.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn markers_and_manifest_on_a_finished_pass() {
    use AckScriptedPost::{Accept, Conflict};
    // (row, gated, census complete, answer, marker still set, completion)
    for (row, gated, complete, post, unverified_after, completion) in [
        ("settled walk", false, true, Accept, false, true),
        ("gated history", true, true, Accept, false, false),
        ("gated, census incomplete", true, false, Accept, true, false),
        ("census incomplete", false, false, Accept, false, false),
        ("held conflict", false, true, Conflict, false, false),
        (
            "conflict, census incomplete",
            false,
            false,
            Conflict,
            false,
            false,
        ),
    ] {
        let server = AckScriptedServer::new();
        let mut home = AckFinishHome::new(&server);
        if gated {
            mark_history_unverified(&home);
        }
        let (mut preparation, index, mut scan) = home.prepare_raw();
        assert!(scan.census_complete, "{row}: the real scan is clean");
        scan.census_complete = complete;
        preparation.scan_started_at = SCAN_START.into();
        server.script.lock().unwrap().push_back(post);
        home.finish(preparation, index, scan)
            .unwrap_or_else(|error| panic!("{row}: {error:#}"));
        assert_eq!(receipt_count(&server), 1, "{row}");
        let sent = last_receipt(&server);
        assert_eq!(sent.get("manifest").is_some(), complete, "{row}: {sent}");
        let code = sent["last_error_code"].as_str();
        match (post, gated, complete) {
            (Conflict, ..) => assert_eq!(code, Some("server_error"), "{row}: {sent}"),
            (_, false, true) => assert_eq!(code, None, "{row}: {sent}"),
            (_, false, false) => assert!(
                code.is_some_and(|code| code.starts_with("census_")),
                "{row}: an incomplete census is reported as one: {sent}"
            ),
            // A gated destination's own census status is not pinned here.
            (_, true, _) => assert_ne!(code, Some("server_error"), "{row}: {sent}"),
        }
        assert_ne!(sent["last_scan_started_at"], SCAN_START, "{row}");
        let state = crate::backfill::load_backfill_state(&home.support);
        assert_eq!(state.prior_history_unverified, unverified_after, "{row}");
        assert_eq!(completion_written(&home), completion, "{row}");
        assert_eq!(
            state.last_completed_at.as_deref(),
            completion.then_some(SCAN_START),
            "{row}: this pass's scan start"
        );
    }
}

/// The success receipt is the last step before the walk gate arms. When it
/// cannot be sent the pass fails with everything before it saved, the gate
/// stays unarmed, and the next pass walks.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn success_receipt_send_failure_fails_the_pass_and_leaves_the_walk_gate_unarmed() {
    use crate::snapshot_watcher::{simulate_transcript_events, with_simulated_watch};
    use crate::snapshots::walk_idle;
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "this row needs the supported scan layout; it must not pass unrun"
    );
    let recording = Recording::start();
    let source = SnapshotSource::ClaudeCode;
    let server = OracleServer::new(source, recording.handle());
    let mut home = OracleHome::new(source, &server);
    home.row = "finish_success_receipt";
    let watched = source.default_roots(&home.fixture.home);
    let scan_statuses = |server: &OracleServer| {
        let statuses = server.statuses.lock().unwrap();
        statuses
            .iter()
            .filter(|status| status["report_kind"] == "scan_status")
            .cloned()
            .collect::<Vec<_>>()
    };
    with_simulated_watch(&watched, || {
        walk_idle::restart_for_test();
        // Control: clean passes settle the walk and arm the gate.
        let armed = (0..4).any(|_| {
            let cycle = home.cycle(&server, &recording);
            assert!(cycle.finish.is_ok(), "{:?}", cycle.finish);
            walk_idle::armed_for_test(source).is_some()
        });
        assert!(armed, "control: a clean walk arms the gate");
        let line = json!({"timestamp":"2026-11-01T07:03:00Z","type":"assistant",
            "sessionId":IDENTITY_PIPELINE_ROOT,"requestId":"req_3","message":{"id":"m3",
            "model":"claude-haiku-4-5","usage":{"input_tokens":5,"output_tokens":1}}});
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(home.transcript())
            .unwrap();
        writeln!(file, "{line}").unwrap();
        drop(file);
        simulate_transcript_events(source, &watched, &[home.transcript()]);
        walk_idle::age_for_test(source, 1800);
        let receipts = scan_statuses(&server).len();
        server
            .status_fails
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = home.cycle(&server, &recording);
        server
            .status_fails
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(
            !failed.acknowledged.concat().is_empty(),
            "the change is ACKed"
        );
        let statuses = scan_statuses(&server);
        assert_eq!(statuses.len(), receipts + 1, "the receipt was tried");
        let tried = statuses.last().unwrap();
        assert_eq!(tried.get("last_error_code"), Some(&Value::Null), "{tried}");
        assert!(tried.get("manifest").is_some(), "complete census: {tried}");
        let error = failed.finish.unwrap_err();
        assert!(is_receipt_send_failure(&error), "{error:#}");
        assert_eq!(walk_idle::armed_for_test(source), None, "never armed");
        walk_idle::age_for_test(source, 1800);
        let next = home.cycle(&server, &recording);
        assert!(next.finish.is_ok(), "{:?}", next.finish);
        assert_eq!(next.gate["census_complete"], true, "walks: {}", next.gate);
        assert_eq!(scan_statuses(&server).len(), receipts + 2, "and reports");
    });
}
