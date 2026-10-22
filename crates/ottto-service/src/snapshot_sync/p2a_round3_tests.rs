// Live P2a through the actual prepare -> rotation -> finish -> selected save.
// Sibling conservation fixtures remain independently owned and unchanged.
thread_local! {
    static P2A_ACK_SAVE_FAILURE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static P2A_INDEX_CONFLICT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}
pub(crate) fn p2a_conflict_index_for_test(path: &Path) {
    P2A_INDEX_CONFLICT.with(|state| {
        if state.borrow().as_deref() == Some(path) {
            state.borrow_mut().take();
            let mut competing = ScanIndex::load(path).unwrap();
            competing.save(path).unwrap();
        }
    });
}
pub(crate) fn p2a_before_ack_save_for_test(path: &Path) {
    P2A_ACK_SAVE_FAILURE.with(|state| {
        if state.borrow().as_deref() == Some(path) {
            state.borrow_mut().take();
            std::fs::create_dir_all(
                path.with_extension(format!("json.{}.tmp", std::process::id())),
            )
            .unwrap();
        }
    });
}
struct P2aConflictReset;
impl Drop for P2aConflictReset {
    fn drop(&mut self) {
        P2A_INDEX_CONFLICT.with(|state| state.borrow_mut().take());
        P2A_ACK_SAVE_FAILURE.with(|state| state.borrow_mut().take());
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_real_prepare_finish_ack_refusal_hold_and_failed_cas_restart() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for (outcome, conflict, ledger_fault, ack_save_fault) in [
        (FinishOutcome::Accept, false, false, false),
        (FinishOutcome::Accept, false, false, true),
        (FinishOutcome::Accept, true, false, false),
        (FinishOutcome::Accept, false, true, false),
        (
            FinishOutcome::Dominated {
                reason: "accepted_log_stale_older_upload",
                admit_residue: true,
            },
            false,
            false,
            false,
        ),
        (FinishOutcome::MoneyHeld, false, false, false),
        (FinishOutcome::Retryable, false, false, false),
    ] {
        let fixture = IdentityPipelineHome::new();
        let cadence = IdentityPipelineCadence::new();
        let support = fixture.base.join("p2a-live-support");
        let secrets = fixture.base.join("p2a-live-secrets");
        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            b"",
        )
        .unwrap();
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
        let _live = money::LiveForTest::new(&support);
        money::store::reload_for_test(&support).unwrap();
        let server = FinishServer::new(outcome);
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
        let device = LocalDeviceBinding {
            device_id: "p2a-live-device".into(),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .unwrap();
        let daemon = test_daemon("otm_test");
        let client = SnapshotApiClient::new(server.url.clone());
        let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
        let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&support, SnapshotSource::ClaudeCode),
            &namespace,
        ));
        ScanIndex::default().save(&index_path).unwrap();
        let transcript = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
            .canonicalize()
            .unwrap();
        let dirty = format!(
            "dirty:{:x}",
            Sha256::digest(transcript.to_string_lossy().as_bytes())
        );
        let blocked =
            money::store::shard_path_for_test(&support, &dirty).with_extension("json.tmp");
        if ledger_fault {
            std::fs::create_dir_all(&blocked).unwrap();
        }
        let collection = || AgentStatusCollection {
            snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
            source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        };
        let cycles = if conflict {
            3 // First adopt, then fail a due-only save, then retry unchanged bytes.
        } else if ledger_fault || ack_save_fault {
            2
        } else {
            1
        };
        let _reset = P2aConflictReset;
        for cycle in 0..cycles {
            if conflict && cycle == 1 {
                let saved = ScanIndex::load(&index_path).unwrap();
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision == 3));
                // No physical change or adoption remains: only this durable
                // external-evidence obligation can select the file again.
                money::store::with_ledger_for_test(&support, |ledger| {
                    ledger.insert(dirty.clone(), crate::snapshots::claude_request_census::ClaudeRequestCensusRecord::money_debt([9; 32], 0));
                    let mut writer = money::store::WriterState::default();
                    while ledger.dirty_shards() > 0 {
                        money::store::save_page_for_test(&support, ledger, &mut writer).unwrap();
                    }
                }).unwrap();
            }
            let mut attempts = 0;
            let (result, progress_path) = loop {
                attempts += 1;
                assert!(attempts <= 24, "resumable writer must converge");
                cadence.next_due_cycle();
                let mut transport = crate::net_resilience::TransportCycleOutcome::default();
                let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
                let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
                    prepare_sync_source(
                        &client,
                        &device,
                        "device-secret",
                        SnapshotSource::ClaudeCode,
                        "otm_test",
                        &fixture.home,
                        &support,
                        &daemon,
                        &mut transport,
                        daemon.snapshot_scan_account_witness().unwrap(),
                        false,
                    )
                })
                .unwrap()
                .expect("real due preparation");
                let (preparation, index, scan) =
                    collect_native_preparation_with_rotation(frame, false);
                assert!(index.request_money_live_revision());
                assert!(
                    !scan.snapshots.is_empty(),
                    "actual selector must re-read the owed revision"
                );
                let progress_path = preparation.upload_progress_path.clone();
                if ack_save_fault && cycle == 0 {
                    P2A_ACK_SAVE_FAILURE
                        .with(|state| *state.borrow_mut() = Some(progress_path.clone()));
                }
                if conflict && cycle == 1 {
                    P2A_INDEX_CONFLICT
                        .with(|state| *state.borrow_mut() = Some(preparation.index_path.clone()));
                }
                let result =
                    crate::agent_status_refresh::with_test_collection(collection(), || {
                        finish_sync_source(
                            preparation,
                            index,
                            scan,
                            &client,
                            &device,
                            "device-secret",
                            SnapshotSource::ClaudeCode,
                            "otm_test",
                            &fixture.home,
                            &support,
                            &daemon,
                            &mut transport,
                            &mut retry,
                        )
                    });
                money::store::flush();
                if result.as_ref().err().is_some_and(|error| {
                    error
                        .to_string()
                        .contains("request money scheduling checkpoint pending")
                }) {
                    continue;
                }
                break (result, progress_path);
            };
            let saved = ScanIndex::load(&index_path).unwrap();
            if conflict && cycle == 1 {
                assert!(result.is_err(), "competing selected save must reject CAS");
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision == 3));
                let progress = SnapshotUploadProgress::load(
                    &progress_path,
                    &namespace,
                    snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
                )
                .unwrap();
                assert!(
                    !progress.accepted_fingerprints.is_empty(),
                    "covering ACK was durable before failed CAS"
                );
                assert!(
                    money::money_due(&support, &transcript.to_string_lossy(), u64::MAX),
                    "failed selected-index CAS must retain due-only debt on an adopted file"
                );
            } else if ack_save_fault && cycle == 0 {
                assert!(result.is_err());
                assert!(
                    !server.offered.lock().unwrap().is_empty(),
                    "server ACK preceded failed local save"
                );
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3));
                assert!(
                    money::money_due(&support, &transcript.to_string_lossy(), u64::MAX),
                    "uncertain ACK must preserve durable selection debt"
                );
                std::fs::remove_dir(
                    progress_path.with_extension(format!("json.{}.tmp", std::process::id())),
                )
                .unwrap();
            } else if ledger_fault && cycle == 0 {
                assert!(
                    server.offered.lock().unwrap().is_empty(),
                    "failed dirty barrier forbids POST"
                );
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3));
                std::fs::remove_dir(&blocked).unwrap();
            } else if matches!(
                outcome,
                FinishOutcome::Accept | FinishOutcome::Dominated { .. }
            ) {
                assert!(result.is_ok(), "{outcome:?}: {result:?}");
                assert!(!saved.files.is_empty());
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision == 3));
                let offered = server.offered.lock().unwrap();
                assert!(!offered.is_empty());
                assert!(
                    offered
                        .iter()
                        .all(|item| item["usage_accounting_contract"]
                            == money::REQUEST_OWNED_CONTRACT)
                );
                assert!(
                    !money::money_due(&support, &transcript.to_string_lossy(), u64::MAX),
                    "saved covering body retires its selection obligation"
                );
                if matches!(outcome, FinishOutcome::Dominated { .. }) {
                    let fp = offered[0]["snapshot_fingerprint"].as_str().unwrap();
                    assert!(
                        !saved.accepted_snapshot_fingerprint_recorded(fp),
                        "settled-refused is never accepted"
                    );
                }
            } else {
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3));
                let progress = SnapshotUploadProgress::load(
                    &progress_path,
                    &namespace,
                    snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
                )
                .unwrap();
                assert!(
                    progress.permanent_rejections.is_empty(),
                    "retryable hold/conflict never becomes permanent"
                );
                if matches!(outcome, FinishOutcome::MoneyHeld) {
                    assert!(saved
                        .quarantined_snapshot_fingerprints
                        .values()
                        .any(|record| record.hold.is_some()));
                    assert_eq!(
                        server.terminal.lock().unwrap().last().unwrap()["consecutive_failures"],
                        0
                    );
                }
            }
            // All evidence/index/progress for the next cycle comes from disk.
            money::store::reload_for_test(&support).unwrap();
        }
    }
}

#[test]
#[serial]
#[serial(claude_request_money_shadow)]
fn p2a_status_projection_clears_acceptance_and_fences_idle_scopes() {
    use crate::snapshots::claude_request_money as money;
    let support = test_dir("p2a-menu");
    let _live = money::LiveForTest::new(&support);
    let account = [7; 32];
    scope_request_money_menu(&support, "destination-a".into(), account);
    *REQUEST_MONEY_MENU.lock().unwrap() = Some(RequestMoneyMenuStatus {
        held: 1,
        refused: 0,
        adoption: "running".into(),
        protected: "loaded".into(),
    });
    assert_eq!(request_money_menu_status(account).unwrap().held, 1);
    // Persisted projection replaces the final hold after its acceptance.
    let mut index = ScanIndex::default();
    crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        "2026-10-22T10:00:00Z",
        183,
        16,
        false,
    )
    .unwrap();
    index.activate_effective_upload_body_witness_revision(3);
    let path = support.join("index.json");
    index.save(&path).unwrap();
    let mut restarted = ScanIndex::load(&path).unwrap();
    crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[],
        &mut restarted,
        "2026-10-22T10:00:00Z",
        183,
        16,
        false,
    )
    .unwrap();
    restarted.activate_effective_upload_body_witness_revision(3);
    SyncCounts::default().with_snapshot_terminal_counts(&restarted);
    assert_eq!(request_money_menu_status(account).unwrap().held, 0);
    // Kill-switch polling works even on an idle cycle with no projection.
    std::fs::write(support.join("claude-request-owned-live.off"), b"").unwrap();
    assert!(request_money_menu_status(account).is_none());
    std::fs::remove_file(support.join("claude-request-owned-live.off")).unwrap();
    *REQUEST_MONEY_MENU.lock().unwrap() = Some(RequestMoneyMenuStatus {
        held: 2,
        refused: 0,
        adoption: "running".into(),
        protected: "loaded".into(),
    });
    assert!(request_money_menu_status([8; 32]).is_none());
    scope_request_money_menu(&support, "destination-b".into(), account);
    assert!(request_money_menu_status(account).is_none());
    scope_request_money_menu(
        &support.join("other-support"),
        "destination-b".into(),
        account,
    );
    assert!(request_money_menu_status(account).is_none());
    let _ = std::fs::remove_dir_all(support);
}
